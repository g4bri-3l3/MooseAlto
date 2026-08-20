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

function Test-NetworksContain {
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }
    foreach ($nTok in $Narrower) {
        $covered = $false
        foreach ($bTok in $Broader) {
            if ((Test-IsPlainIP $bTok) -and (Test-IsPlainIP $nTok)) {
                if (Test-CidrContains -Broader $bTok -Narrower $nTok) { $covered = $true; break }
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
    # up front and comparing pre-parsed integers/prefixes in the loop
    # itself (see Test-NetworksContainFast) avoids re-running regex
    # matching and IPAddress parsing that many times over.
    param($AddrTokens)
    if ($null -eq $AddrTokens) { return $null }
    $parsed = foreach ($tok in $AddrTokens) {
        if (Test-IsPlainIP $tok) {
            $parts = Get-CidrParts $tok
            [PSCustomObject]@{ IsIP = $true; Int64 = (ConvertTo-Int64IP $parts.IP); Prefix = $parts.Prefix; Raw = $tok }
        }
        else {
            [PSCustomObject]@{ IsIP = $false; Int64 = 0; Prefix = 0; Raw = $tok }
        }
    }
    return @($parsed)
}

function Test-NetworksContainFast {
    # Same semantics as Test-NetworksContain, but takes address lists
    # already pre-parsed by ConvertTo-ParsedAddressList, so no parsing
    # happens inside the O(n^2) comparison loop itself, just integer
    # bitmask arithmetic.
    param($Broader, $Narrower)
    if ($null -eq $Broader) { return $true }
    if ($null -eq $Narrower) { return $false }
    foreach ($n in $Narrower) {
        $covered = $false
        foreach ($b in $Broader) {
            if ($b.IsIP -and $n.IsIP) {
                if ($b.Prefix -le $n.Prefix) {
                    $mask = (([Int64]0xFFFFFFFF) -shl (32 - $b.Prefix)) -band ([Int64]0xFFFFFFFF)
                    if (($b.Int64 -band $mask) -eq ($n.Int64 -band $mask)) { $covered = $true; break }
                }
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

