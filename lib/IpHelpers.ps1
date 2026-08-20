# --------------------------------------------------------------------------
# IPv4/CIDR helpers
# --------------------------------------------------------------------------

# The shadow/duplicate detection loops compare every rule against every
# earlier one (O(n^2)), so the same address string gets parsed again and
# again across many comparisons. These three caches turn that into "parse
# once per unique string, then instant lookups" - the single biggest cost
# in that loop was repeatedly re-running regex matching and
# System.Net.IPAddress parsing on strings already parsed moments before.
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
    $result = [System.Net.IPAddress]::TryParse($ipPart, [ref]$parsed)
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
    # True if a plain CIDR or "start-end" range token falls entirely within
    # one of the three standard RFC1918 blocks.
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
    # True if an address field is made ENTIRELY of "[Negate] <RFC1918 range>"
    # tokens, meaning "match anything that is NOT private", which is
    # functionally equivalent to "any public IP" even though no single token
    # literally says "any" or names a public CIDR. Seen in real PAN-OS
    # exports (e.g. negating 10/8, 172.16/12, and 192.168/16 together on a
    # rule effectively opens it to the whole internet). Easy to miss in a
    # manual review since the field never shows "any".
    param([array]$RawTokens)
    if (-not $RawTokens -or $RawTokens.Count -eq 0) { return $false }
    foreach ($tok in $RawTokens) {
        if ($tok -notmatch '^\[Negate\]\s*') { return $false }
        $inner = $tok -replace '^\[Negate\]\s*', ''
        if (-not (Test-IsRfc1918Range $inner)) { return $false }
    }
    return $true
}

function Test-IsIpRange {
    # An "IP-IP" range, e.g. "10.5.5.10-10.5.5.50". Distinct from a plain
    # CIDR/IP (which uses "/", never "-"), so there's no ambiguity between
    # the two syntaxes.
    param([string]$Token)
    if ($script:IsIpRangeCache.ContainsKey($Token)) { return $script:IsIpRangeCache[$Token] }
    $result = [bool]($Token -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    $script:IsIpRangeCache[$Token] = $result
    return $result
}

function Get-AddressBounds {
    # Returns a Start/End Int64 pair for any token expressible as one
    # contiguous numeric interval: a plain CIDR/IP (network address to
    # broadcast address) or an "IP-IP" range (both ends parsed directly).
    # Returns $null for anything else - a "[Negate] X" expression isn't a
    # single contiguous interval in general (it's everything EXCEPT X,
    # which splits into zero, one, or two remaining intervals depending on
    # where X sits), and an unresolved address-object name has no interval
    # at all without its definition. Both still fall back to exact string
    # matching in the callers below, same as before this function existed.
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
    # For a Broader address list made ENTIRELY of "[Negate] X" tokens -
    # which combine with AND semantics (matches only if it avoids EVERY
    # excluded X, same assumption Test-IsNegatedPublicPattern above
    # already makes for the all-RFC1918 case), a single-interval Narrower
    # token is covered if it has zero overlap with each excluded X. Only
    # handles a Narrower with computable bounds (a plain CIDR/range): a
    # Narrower that's itself a "[Negate]" expression isn't attempted here,
    # since that combination is rare enough in practice not to be worth
    # the added complexity right now.
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

    # Broader made entirely of "[Negate] X" tokens combines with AND
    # semantics, unlike the OR semantics that governs a normal multi-value
    # list, so it can't go through the same per-token "any one match is
    # enough" loop below.
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
    # Pre-parses an address token list ONCE into a fast-comparison form.
    # The shadow/duplicate detection loops compare every rule against every
    # earlier one, so the same rule's own address gets looked at again on
    # every comparison it takes part in - up to n-1 times. Parsing it once
    # up front and comparing pre-parsed Start/End integers in the loop
    # itself (see Test-NetworksContainFast) avoids re-running regex
    # matching and IPAddress parsing that many times over.
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
    # Same semantics as Test-NetworksContain, but takes address lists
    # already pre-parsed by ConvertTo-ParsedAddressList, so no parsing
    # happens inside the O(n^2) comparison loop itself, just integer
    # comparisons. Covers plain CIDR/IP and "IP-IP" ranges uniformly
    # (both reduce to a Start/End interval); anything else falls back to
    # exact string matching, same as it always has.
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }

    # Broader made entirely of "[Negate] X" tokens combines with AND
    # semantics (matches only if it avoids EVERY excluded X), unlike the
    # OR semantics of a normal multi-value list, so it needs handling
    # separately from the per-token loop below, which assumes OR.
    $allNegated = $Broader.Count -gt 0 -and (@($Broader | Where-Object { $_.Raw -notmatch '^\[Negate\]' })).Count -eq 0
    if ($allNegated) {
        $negatedRaw = $Broader | ForEach-Object { $_.Raw }
        foreach ($n in $Narrower) {
            # Exact match first: two rules using the identical negation
            # expression are still "the same address" for duplicate/shadow
            # purposes, regardless of the interval math below (which only
            # handles a Narrower with its own computable bounds).
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
