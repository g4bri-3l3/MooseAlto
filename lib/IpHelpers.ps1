# --------------------------------------------------------------------------
# IPv4/CIDR helpers
# --------------------------------------------------------------------------

# The pairwise checks see the same address strings over and over, so each
# string is parsed once and cached. This was the biggest cost in those loops.
$script:CidrPartsCache = @{}
$script:Int64IPCache = @{}
$script:IsPlainIPCache = @{}
$script:IsIpRangeCache = @{}
$script:AddressBoundsCache = @{}

function ConvertTo-Int64IP {
    param([string]$IPAddress)
    if ($script:Int64IPCache.ContainsKey($IPAddress)) { return $script:Int64IPCache[$IPAddress] }
    $bytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $result = [Int64][BitConverter]::ToUInt32($bytes, 0)
    $script:Int64IPCache[$IPAddress] = $result
    return $result
}

function Get-CidrParts {
    param([string]$Cidr)
    if ($script:CidrPartsCache.ContainsKey($Cidr)) { return $script:CidrPartsCache[$Cidr] }
    $result = if ($Cidr -match '^(.+)/(\d+)$') {
        [PSCustomObject]@{ IP = $Matches[1]; Prefix = [int]$Matches[2] }
    }
    else {
        [PSCustomObject]@{ IP = $Cidr; Prefix = 32 }
    }
    $script:CidrPartsCache[$Cidr] = $result
    return $result
}

function Test-IsPlainIP {
    param([string]$Token)
    if ($script:IsPlainIPCache.ContainsKey($Token)) { return $script:IsPlainIPCache[$Token] }
    $ipPart = (Get-CidrParts $Token).IP
    $parsed = $null
    # Dotted IPv4 only: TryParse alone takes "2001:db8::1" as 0.0.0.1 and
    # "10" as 0.0.0.10. Anything else is matched by name.
    $result = ($ipPart -match '^\d{1,3}(\.\d{1,3}){3}$') -and [System.Net.IPAddress]::TryParse($ipPart, [ref]$parsed)
    $script:IsPlainIPCache[$Token] = $result
    return $result
}

function Test-CidrContains {
    param([string]$Broader, [string]$Narrower)
    $b = Get-CidrParts $Broader
    $n = Get-CidrParts $Narrower
    if ($b.Prefix -gt $n.Prefix) { return $false }
    $bIP = ConvertTo-Int64IP $b.IP
    $nIP = ConvertTo-Int64IP $n.IP
    $mask = (([Int64]0xFFFFFFFF) -shl (32 - $b.Prefix)) -band ([Int64]0xFFFFFFFF)
    return (($bIP -band $mask) -eq ($nIP -band $mask))
}

function Test-PrivateOrSpecialIP {
    param([string]$Cidr)
    $parts = Get-CidrParts $Cidr
    $privRanges = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
    foreach ($r in $privRanges) {
        if (Test-CidrContains -Broader $r -Narrower "$($parts.IP)/32") { return $true }
    }
    return $false
}

function Test-IsRfc1918Range {
    # CIDR or range entirely inside one RFC1918 block.
    param([string]$Token)
    $rfc1918Blocks = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    if ($Token -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
        $startIp = $Matches[1]
        $endIp = $Matches[2]
        foreach ($block in $rfc1918Blocks) {
            if ((Test-CidrContains -Broader $block -Narrower "$startIp/32") -and
                (Test-CidrContains -Broader $block -Narrower "$endIp/32")) {
                return $true
            }
        }
        return $false
    }
    if (Test-IsPlainIP $Token) {
        foreach ($block in $rfc1918Blocks) {
            if (Test-CidrContains -Broader $block -Narrower $Token) { return $true }
        }
    }
    return $false
}

function Test-IsNegatedPublicPattern {
    # Only negated private ranges: "anything not private", i.e. any public
    # address, without saying "any". -Strict also wants all three blocks
    # negated; part of them is still broad, but not "any public".
    param([array]$RawTokens, [switch]$Strict)
    if (-not $RawTokens -or $RawTokens.Count -eq 0) { return $false }
    $inners = @()
    foreach ($tok in $RawTokens) {
        if ($tok -notmatch '^\[Negate\]\s*') { return $false }
        $inner = $tok -replace '^\[Negate\]\s*', ''
        if (-not (Test-IsRfc1918Range $inner)) { return $false }
        $inners += $inner
    }
    if ($Strict) {
        foreach ($block in @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")) {
            $bb = Get-AddressBounds $block
            $covered = $false
            foreach ($i in $inners) {
                $ib = Get-AddressBounds $i
                if ($ib -and $ib.Start -le $bb.Start -and $ib.End -ge $bb.End) { $covered = $true; break }
            }
            if (-not $covered) { return $false }
        }
    }
    return $true
}

function Test-IsAllRfc1918Pattern {
    # The opposite: all three private blocks listed, i.e. any private
    # address. Each block must sit inside one token (no piecing fragments
    # together). -Strict: every token must be private, so 0.0.0.0/0 isn't it.
    param([array]$RawTokens, [switch]$Strict)
    if (-not $RawTokens -or $RawTokens.Count -eq 0) { return $false }
    foreach ($tok in $RawTokens) {
        if ($tok -match '^\[Negate\]') { return $false }
        if ($Strict -and -not (Test-IsRfc1918Range $tok)) { return $false }
    }
    $rfc1918Blocks = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    foreach ($block in $rfc1918Blocks) {
        $covered = $false
        foreach ($tok in $RawTokens) {
            if ((Test-IsPlainIP $tok) -and (Test-CidrContains -Broader $tok -Narrower $block)) {
                $covered = $true
                break
            }
        }
        if (-not $covered) { return $false }
    }
    return $true
}

function Test-AddressFieldEffectivelyAny {
    # "any", or one of the two RFC1918 tricks above, which are just as open.
    param($RawTokens)
    if ($null -eq $RawTokens) { return $true }
    if (Test-IsNegatedPublicPattern -RawTokens $RawTokens) { return $true }
    if (Test-IsAllRfc1918Pattern -RawTokens $RawTokens) { return $true }
    return $false
}

function Test-IsIpRange {
    # "10.5.5.10-10.5.5.50".
    param([string]$Token)
    if ($script:IsIpRangeCache.ContainsKey($Token)) { return $script:IsIpRangeCache[$Token] }
    $result = [bool]($Token -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    $script:IsIpRangeCache[$Token] = $result
    return $result
}

function Get-AddressBounds {
    # Start/End integers for a CIDR or a range. $null for anything else (a
    # negation isn't one interval, a name has none); callers then compare
    # the text.
    param([string]$Token)
    if ($script:AddressBoundsCache.ContainsKey($Token)) { return $script:AddressBoundsCache[$Token] }
    $result = $null
    if (Test-IsPlainIP $Token) {
        $parts = Get-CidrParts $Token
        $baseInt = ConvertTo-Int64IP $parts.IP
        $hostBits = 32 - $parts.Prefix
        $mask = (([Int64]0xFFFFFFFF) -shl $hostBits) -band ([Int64]0xFFFFFFFF)
        $networkInt = $baseInt -band $mask
        $blockSize = if ($hostBits -ge 32) { [Int64]0xFFFFFFFF } else { ([Int64]1 -shl $hostBits) - 1 }
        $result = [PSCustomObject]@{ Start = $networkInt; End = $networkInt + $blockSize }
    }
    elseif (Test-IsIpRange $Token) {
        $ipParts = $Token -split '\s*-\s*'
        $startInt = $null; $endInt = $null
        $startOk = $false; $endOk = $false
        try { $startInt = ConvertTo-Int64IP $ipParts[0].Trim(); $startOk = $true } catch {}
        try { $endInt = ConvertTo-Int64IP $ipParts[1].Trim(); $endOk = $true } catch {}
        if ($startOk -and $endOk -and $startInt -le $endInt) {
            $result = [PSCustomObject]@{ Start = $startInt; End = $endInt }
        }
    }
    $script:AddressBoundsCache[$Token] = $result
    return $result
}

function Test-IntervalsOverlap {
    param($A, $B)
    return -not ($A.End -lt $B.Start -or $B.End -lt $A.Start)
}

function Test-NarrowerAvoidsNegatedSet {
    # Negations combine with AND: the narrower interval is covered if it
    # touches none of the excluded ranges. A negated narrower side isn't
    # handled (rare).
    param([array]$NegatedBroaderRawTokens, $NarrowerBounds)
    foreach ($bTok in $NegatedBroaderRawTokens) {
        $inner = $bTok -replace '^\[Negate\]\s*', ''
        $exclBounds = Get-AddressBounds $inner
        if ($null -eq $exclBounds) { return $false }
        if (Test-IntervalsOverlap $NarrowerBounds $exclBounds) { return $false }
    }
    return $true
}

function Test-NetworksContain {
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }

    # All negations means AND, not the usual OR of a list.
    $allNegated = $Broader.Count -gt 0 -and (@($Broader | Where-Object { $_ -notmatch '^\[Negate\]' })).Count -eq 0
    if ($allNegated) {
        foreach ($nTok in $Narrower) {
            if ($Broader -contains $nTok) { continue }
            $nBounds = Get-AddressBounds $nTok
            if ($null -eq $nBounds) { return $false }
            if (-not (Test-NarrowerAvoidsNegatedSet -NegatedBroaderRawTokens $Broader -NarrowerBounds $nBounds)) { return $false }
        }
        return $true
    }

    foreach ($nTok in $Narrower) {
        $covered = $false
        foreach ($bTok in $Broader) {
            $bBounds = Get-AddressBounds $bTok
            $nBounds = Get-AddressBounds $nTok
            if ($bBounds -and $nBounds) {
                if ($bBounds.Start -le $nBounds.Start -and $nBounds.End -le $bBounds.End) { $covered = $true; break }
            }
            elseif ($bTok -eq $nTok) { $covered = $true; break }
        }
        if (-not $covered) { return $false }
    }
    return $true
}

function ConvertTo-ParsedAddressList {
    # Parse once, so the pairwise loops only compare integers.
    param($AddrTokens)
    if ($null -eq $AddrTokens) { return $null }
    $parsed = foreach ($tok in $AddrTokens) {
        $bounds = Get-AddressBounds $tok
        if ($bounds) {
            [PSCustomObject]@{ HasBounds = $true; Start = $bounds.Start; End = $bounds.End; Raw = $tok }
        }
        else {
            [PSCustomObject]@{ HasBounds = $false; Start = 0; End = 0; Raw = $tok }
        }
    }
    return @($parsed)
}

function Test-NetworksContainFast {
    # Test-NetworksContain on pre-parsed lists.
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }

    # All negations means AND, not the usual OR of a list.
    $allNegated = $Broader.Count -gt 0 -and (@($Broader | Where-Object { $_.Raw -notmatch '^\[Negate\]' })).Count -eq 0
    if ($allNegated) {
        $negatedRaw = $Broader | ForEach-Object { $_.Raw }
        foreach ($n in $Narrower) {
            # The same negation on both sides is the same address.
            if ($negatedRaw -contains $n.Raw) { continue }
            if (-not $n.HasBounds) { return $false }
            $nBounds = [PSCustomObject]@{ Start = $n.Start; End = $n.End }
            if (-not (Test-NarrowerAvoidsNegatedSet -NegatedBroaderRawTokens $negatedRaw -NarrowerBounds $nBounds)) { return $false }
        }
        return $true
    }

    foreach ($n in $Narrower) {
        $covered = $false
        foreach ($b in $Broader) {
            if ($b.HasBounds -and $n.HasBounds) {
                if ($b.Start -le $n.Start -and $n.End -le $b.End) { $covered = $true; break }
            }
            elseif ($b.Raw -eq $n.Raw) { $covered = $true; break }
        }
        if (-not $covered) { return $false }
    }
    return $true
}

function Test-ListContains {
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }
    foreach ($item in $Narrower) {
        if ($Broader -notcontains $item) { return $false }
    }
    return $true
}

function Test-NetworksOverlapFast {
    # Any overlap at all (for the correlation check). A list of negations
    # is assumed to overlap everything: it may over-report a Low finding,
    # which beats missing one.
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $true }
    if ($A.Count -eq 0 -or $B.Count -eq 0) { return $true }

    $aAllNegated = (@($A | Where-Object { $_.Raw -notmatch '^\[Negate\]' })).Count -eq 0
    $bAllNegated = (@($B | Where-Object { $_.Raw -notmatch '^\[Negate\]' })).Count -eq 0
    if ($aAllNegated -or $bAllNegated) { return $true }

    foreach ($a in $A) {
        foreach ($b in $B) {
            if ($a.HasBounds -and $b.HasBounds) {
                if ($a.Start -le $b.End -and $b.Start -le $a.End) { return $true }
            }
            elseif ($a.Raw -eq $b.Raw) { return $true }
        }
    }
    return $false
}

function Test-ListsOverlap {
    # Applications / services: one value in common, or either side any.
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $true }
    foreach ($item in $A) {
        if ($B -contains $item) { return $true }
    }
    return $false
}

