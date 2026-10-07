# --------------------------------------------------------------------------
# Shared pieces of the cloud importers (Azure NSG, AWS SG, GCP firewall)
# --------------------------------------------------------------------------
#
# Cloud rules have no zones. Each rule has a "local" side (the NSG, security
# group or VPC network it protects) and a "remote" side (where the traffic
# comes from, or goes to). The model gets:
#   local side   zone = the NSG / SG / network name, addresses as written
#   remote side  zone 'any', addresses as written, the whole internet
#                (*, 0.0.0.0/0, ::/0, the Internet service tag) as any
# The remote zone is always 'any' so the pairwise checks compare remote
# sides by address alone: 0.0.0.0/0 on port 22 must cover 10.0.0.0/16 on
# port 22. Whether the remote side is the internet can't then come from the
# zone, so the importer decides it and stores it in SrcIsInternet /
# DstIsInternet (see Test-RuleSideIsInternet): any address, a public IP,
# or a tag covering public cloud space is internet; private ranges and
# references (asg:, sg:, pl:, tag:, sa:, other service tags) are not.
#
# Scope is "<container>/<direction>": inbound and outbound lists are
# evaluated separately, and rules of different NSGs never meet.

$script:CloudVendors = @('azure', 'aws', 'gcp')

# What "everything" looks like in the three exports.
$script:CloudWideTokens = @('*', 'any', 'internet', '0.0.0.0/0', '0.0.0.0', '::/0', '0::/0')

function Test-CloudWideToken {
    param([string]$Token)
    return ($script:CloudWideTokens -contains $Token.Trim().ToLower())
}

function Test-CloudIpv6Public {
    # Global unicast (2000::/3), the only IPv6 space that is internet. ULA
    # (fc00::/7) and link local (fe80::/10) are not. MooseAlto has no IPv6
    # math, so this only decides the zone; the token itself stays opaque.
    param([string]$Token)
    $t = $Token.Trim().ToLower()
    if ($t -notmatch ':') { return $false }
    return ($t -match '^[23][0-9a-f]{0,3}:')
}

function Test-CloudIpv4Public {
    # A literal IPv4 address or CIDR outside the private and special ranges.
    param([string]$Token)
    if ($Token -notmatch '^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}(/\d{1,2})?$') { return $false }
    $a = [int]$Matches[1]; $b = [int]$Matches[2]
    if ($a -eq 10 -or $a -eq 127 -or $a -eq 0) { return $false }
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $false }
    if ($a -eq 192 -and $b -eq 168) { return $false }
    if ($a -eq 169 -and $b -eq 254) { return $false }
    # 100.64.0.0/10, carrier-grade NAT, is used inside cloud networks too.
    if ($a -eq 100 -and $b -ge 64 -and $b -le 127) { return $false }
    return $true
}

function Get-CloudRemoteSide {
    # Zone, addresses and internet flag for the remote side of a rule.
    # $Tokens are already prefixed when they are references (asg:, sg:,
    # pl:, tag:, sa:). $InternetTags: names (lowercase) the platform uses for
    # "public cloud address space", read as internet with the token kept.
    # $PublicTags: names (lowercase) meaning "every public address" (Azure's
    # Internet). They become "not RFC1918" (negated private ranges), which
    # the address math handles exactly: it covers any public range but not
    # 10.0.0.0/8, and a deny-all below it is not dead. Shown under the
    # tag's own name.
    param($Model, [string]$RuleName, [string[]]$Tokens, [string[]]$InternetTags = @(), [string[]]$PublicTags = @())
    $toks = @($Tokens | Where-Object { $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($toks.Count -eq 0) { return @{ Zone = 'any'; Addrs = @(); Internet = $true } }
    if ($toks.Count -eq 1 -and $PublicTags -contains $toks[0].ToLower()) {
        return @{ Zone = 'any'; Addrs = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'); Negate = $true; Display = $toks[0]; Internet = $true }
    }
    foreach ($t in $toks) {
        if (Test-CloudWideToken $t) { return @{ Zone = 'any'; Addrs = @(); Internet = $true } }
    }

    $internet = $false
    foreach ($t in $toks) {
        $tl = $t.ToLower()
        if (Test-CloudIpv4Public $t) { $internet = $true }
        if (Test-CloudIpv6Public $t) {
            $internet = $true
            Add-NormDiagnostic $Model 'info' $RuleName "IPv6 address '$t' is public: read as internet (IPv6 ranges are compared by name only)"
        }
        foreach ($it in $InternetTags) {
            if ($tl -eq $it -or $tl.StartsWith("$it.")) {
                $internet = $true
                Add-NormDiagnostic $Model 'info' $RuleName "service tag '$t' covers public cloud address space shared with other customers: read as internet"
            }
        }
    }
    return @{ Zone = 'any'; Addrs = $toks; Internet = $internet }
}

function Get-CloudLocalAddrs {
    # The protected side: "everything behind it" is any.
    param([string[]]$Tokens)
    $toks = @($Tokens | Where-Object { $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
    foreach ($t in $toks) {
        if ((Test-CloudWideToken $t) -or $t.ToLower() -eq 'virtualnetwork') { return @() }
    }
    return $toks
}

function ConvertTo-CloudProtocol {
    # tcp, udp, icmp, icmpv6, any, or ip-proto-N.
    param([string]$Proto)
    $p = "$Proto".Trim().ToLower()
    switch ($p) {
        { $_ -in @('', '*', '-1', 'all', 'any') } { return 'any' }
        { $_ -in @('tcp', '6') } { return 'tcp' }
        { $_ -in @('udp', '17') } { return 'udp' }
        { $_ -in @('icmp', '1') } { return 'icmp' }
        { $_ -in @('icmpv6', 'ipv6-icmp', '58') } { return 'icmpv6' }
        'esp' { return 'ip-proto-50' }
        'ah' { return 'ip-proto-51' }
        'sctp' { return 'ip-proto-132' }
        'ipip' { return 'ip-proto-4' }
        'gre' { return 'ip-proto-47' }
    }
    if ($p -match '^\d+$') { return "ip-proto-$p" }
    return $p
}

function ConvertTo-CloudServiceTokens {
    # Protocol plus port specs ('22', '1000-2000', '*'), to the model's
    # service tokens. Empty result = any service. Ports only mean something
    # for TCP/UDP; "any protocol, port 22" is TCP and UDP 22.
    param([string]$Proto, [string[]]$Ports)
    $p = ConvertTo-CloudProtocol $Proto
    $specs = @($Ports | Where-Object { $_ -ne $null -and "$_".Trim() -ne '' } | ForEach-Object { "$_".Trim() })
    $allPorts = ($specs.Count -eq 0) -or (@($specs | Where-Object { $_ -in @('*', 'any', '0-65535', '1-65535') }).Count -gt 0)

    if ($p -eq 'any') {
        if ($allPorts) { return @() }
        $out = @()
        foreach ($proto in @('tcp', 'udp')) { $out += ConvertTo-CloudPortTokens -Proto $proto -Specs $specs }
        return @($out | Select-Object -Unique)
    }
    if ($p -in @('tcp', 'udp')) {
        if ($allPorts) { return @("$p-1-65535") }
        return @(ConvertTo-CloudPortTokens -Proto $p -Specs $specs | Select-Object -Unique)
    }
    if ($p -eq 'icmp') { return @('icmp') }
    if ($p -eq 'icmpv6') { return @('ipv6-icmp') }
    return @($p)
}

function ConvertTo-CloudPortTokens {
    param([string]$Proto, [string[]]$Specs)
    $out = @()
    foreach ($s in $Specs) {
        if ($s -match '^(\d+)\s*-\s*(\d+)$') {
            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
            if ($lo -lt 1) { $lo = 1 }
            $out += ConvertTo-PortTokens -Proto $Proto -Low $lo -High $hi
        }
        elseif ($s -match '^\d+$') { $out += "$Proto-$([int]$s)" }
    }
    return $out
}

function Get-CloudServiceLabel {
    # Short text for rule names that have none (AWS): "tcp/22", "all".
    param([string[]]$Services)
    if ($null -eq $Services -or $Services.Count -eq 0) { return 'all' }
    $labels = @($Services | Select-Object -First 3 | ForEach-Object { $_ -replace '^(tcp|udp)-', '$1/' })
    $more = if ($Services.Count -gt 3) { " +$($Services.Count - 3)" } else { '' }
    return (($labels -join ',') + $more)
}

function Read-CloudJson {
    # BOM, and a CLI warning line printed before the JSON, are both tolerated.
    param([string]$Path)
    $raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path).Path)
    $raw = $raw.TrimStart([char]0xFEFF)
    $start = $raw.IndexOfAny([char[]]@('[', '{'))
    if ($start -lt 0) { throw "no JSON content in $Path" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}

function Get-CloudProp {
    # A property whatever its case (az prints camelCase, ARM REST nests it
    # under "properties", AWS uses PascalCase).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    foreach ($q in $Object.PSObject.Properties) { if ($q.Name -ieq $Name) { return $q.Value } }
    return $null
}

function New-CloudRule {
    # A model rule laid out for a direction: inbound means remote -> local.
    param(
        [string]$Name, [string]$LocalName, [string]$Scope, [string]$Vendor,
        [ValidateSet('inbound', 'outbound')][string]$Direction,
        [string]$LocalZone, [string[]]$LocalAddrs, $Remote,
        [string[]]$Services, [string]$Action, [string]$Tags = ''
    )
    $r = New-NormRule
    $r.Name = $Name
    $r.LocalName = $LocalName
    $r.Id = $Name
    $r.Scope = $Scope
    $r | Add-Member -NotePropertyName Vendor -NotePropertyValue $Vendor
    # The protected side is never the internet, even with a public IP on it
    # (an NSG in front of a VM's public address).
    $remoteNegate = [bool]$Remote.Negate
    $remoteDisplay = if ($Remote.Display) { "$($Remote.Display)" } else { '' }
    # An empty list returned by a function arrives as $null, and @($null)
    # is one empty address, not any.
    $LocalAddrs = @($LocalAddrs | Where-Object { $_ })
    $Remote = @{ Zone = $Remote.Zone; Addrs = @($Remote.Addrs | Where-Object { $_ }); Internet = $Remote.Internet }
    if ($Direction -eq 'inbound') {
        $r.SrcZones = @($Remote.Zone); $r.SrcAddrs = @($Remote.Addrs); $r.SrcNegate = $remoteNegate
        $r.DstZones = @($LocalZone); $r.DstAddrs = @($LocalAddrs)
        $r | Add-Member -NotePropertyName SrcIsInternet -NotePropertyValue ([bool]$Remote.Internet)
        $r | Add-Member -NotePropertyName DstIsInternet -NotePropertyValue $false
        $r | Add-Member -NotePropertyName SrcDisplay -NotePropertyValue $remoteDisplay
        $r | Add-Member -NotePropertyName DstDisplay -NotePropertyValue ''
    }
    else {
        $r.SrcZones = @($LocalZone); $r.SrcAddrs = @($LocalAddrs)
        $r.DstZones = @($Remote.Zone); $r.DstAddrs = @($Remote.Addrs); $r.DstNegate = $remoteNegate
        $r | Add-Member -NotePropertyName SrcIsInternet -NotePropertyValue $false
        $r | Add-Member -NotePropertyName DstIsInternet -NotePropertyValue ([bool]$Remote.Internet)
        $r | Add-Member -NotePropertyName SrcDisplay -NotePropertyValue ''
        $r | Add-Member -NotePropertyName DstDisplay -NotePropertyValue $remoteDisplay
    }
    $r.Services = @($Services)
    $r.Action = $Action
    # Cloud rules do no content inspection, and none can be added to
    # them: the security profile check would only repeat itself on every
    # exposed rule.
    $r.Profile = 'n/a (cloud firewall rule)'
    $r.Tags = $Tags
    return $r
}

function Get-CloudZoneLabels {
    # Container name as the zone, "<parent>/<name>" when the same name is
    # used in more than one parent (resource group, VPC). The plain name
    # still matches -CriticalZones (Test-ZoneNameInSet).
    param([object[]]$Items)  # each: @{ Key; Name; Parent }
    $counts = @{}
    foreach ($i in $Items) { $k = $i.Name.ToLower(); $counts[$k] = 1 + [int]$counts[$k] }
    $labels = @{}
    foreach ($i in $Items) {
        $labels[$i.Key] = $(if ($counts[$i.Name.ToLower()] -gt 1 -and $i.Parent) { "$($i.Parent)/$($i.Name)" } else { $i.Name })
    }
    return $labels
}
