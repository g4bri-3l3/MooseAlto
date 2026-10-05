# --------------------------------------------------------------------------
# Vendor-neutral model shared by all importers
# --------------------------------------------------------------------------
#
# Every importer (fortios, junos, tufin) fills the same model, and Import.ps1
# turns it into the rule objects Import-PaloAltoRules builds. Keep it close
# to those fields: the point is to reuse the checks, not write new ones.
#
# Rule fields worth knowing:
#   Rules order        evaluation order
#   empty Addrs/Apps/Services   any
#   Services           tcp-22, udp-53, tcp-1000-2000 (a range), icmp-8, ip-proto-47
#   Action             'allow' or 'deny'
#   HitCount/LastHit   '' unknown, LastHit '-' never hit
#   Log                $null = the source has no logging info; '' = not logged

$script:ExpandRangeLimit = 16

function New-NormModel {
    param([string]$Vendor, [string]$Source)
    return [PSCustomObject]@{
        Vendor      = $Vendor
        Source      = $Source
        Rules       = New-Object System.Collections.Generic.List[object]
        Objects     = @{}
        Groups      = @{}
        ZoneHints   = [ordered]@{}
        # Zones where same-zone traffic passes with no rule.
        IntrazoneAllowZones = New-Object System.Collections.Generic.List[string]
        Diagnostics = New-Object System.Collections.Generic.List[object]
    }
}

function Add-NormDiagnostic {
    param($Model, [ValidateSet('info', 'warn', 'lossy', 'error')][string]$Level, [string]$Rule, [string]$Message)
    $Model.Diagnostics.Add([PSCustomObject]@{ Level = $Level; Rule = $Rule; Message = $Message })
}

function New-NormRule {
    return [PSCustomObject]@{
        Id = ''; Name = ''; LocalName = ''; Scope = ''; Enabled = $true
        SrcZones = @('any'); DstZones = @('any')
        SrcAddrs = @(); DstAddrs = @(); SrcNegate = $false; DstNegate = $false
        Applications = @(); Services = @()
        Action = 'allow'; Profile = 'none'; Tags = ''; Comment = ''
        HitCount = ''; LastHit = ''
        Log = $null; Created = ''; Modified = ''
    }
}

function Add-NormObject {
    param($Model, [string]$Name, [string]$Type, [string]$Value)
    $Model.Objects[$Name.ToLower()] = [PSCustomObject]@{ Name = $Name; Type = $Type; Value = $Value }
}

function Add-NormGroup {
    param($Model, [string]$Name, [string[]]$Members)
    $Model.Groups[$Name.ToLower()] = [PSCustomObject]@{ Name = $Name; Members = @($Members) }
}

# --------------------------------------------------------------------------
# Port helpers shared by all vendor parsers
# --------------------------------------------------------------------------

function ConvertTo-PortTokens {
    # Small ranges are expanded so the risky port checks see every port;
    # big ones stay a single range token.
    param([string]$Proto, [int]$Low, [int]$High)
    $Proto = $Proto.ToLower()
    if ($High -lt $Low) { $High = $Low }
    if ($Low -eq $High) { return @("$Proto-$Low") }
    if (($High - $Low + 1) -le $script:ExpandRangeLimit) {
        return @($Low..$High | ForEach-Object { "$Proto-$_" })
    }
    return @("$Proto-$Low-$High")
}

# Apps whose risk you can't see from the port.
$script:AppHintKeywords = @('anydesk', 'teamviewer', 'logmein', 'gotomypc', 'logmein-gotomypc', 'splashtop', 'chrome-remote-desktop', 'dns-over-https')
# Sometimes a service name like "AnyDesk-Support" is the only clue. Return
# the name so the service-name check can still catch it.
function Get-NormAppHintToken {
    param([string]$Name)
    $sub = @($Name.ToLower() -split '[-_\s\.]+') + @($Name.ToLower())
    # Our risky list calls it "logmein-gotomypc".
    if ($sub -contains 'gotomypc' -and $sub -notcontains 'logmein') { return 'logmein-gotomypc' }
    if (@($sub | Where-Object { $script:AppHintKeywords -contains $_ }).Count -gt 0) { return $Name.ToLower() }
    return $null
}

function Test-NormServiceIsAny {
    # "any", IP protocol 0, or all of TCP plus all of UDP.
    param([string[]]$Tokens)
    if ($null -eq $Tokens -or $Tokens.Count -eq 0) { return $true }
    if ($Tokens -contains 'application-default') { return $false }
    if ($Tokens -contains 'any' -or $Tokens -contains 'ip-proto-0') { return $true }
    return ($Tokens -contains 'tcp-1-65535') -and ($Tokens -contains 'udp-1-65535')
}

# --------------------------------------------------------------------------
# Export to MooseAlto input files
# --------------------------------------------------------------------------

function Format-NormAddressField {
    param($Model, [string[]]$Addrs, [bool]$Negate)
    if ($null -eq $Addrs -or $Addrs.Count -eq 0) { return 'any' }
    if (-not $Negate) { return ($Addrs -join ';') }
    # Negated members are written as literal addresses where possible.
    $out = @()
    foreach ($a in $Addrs) {
        foreach ($lit in (Resolve-NormAddressLiterals -Model $Model -Token $a)) { $out += "[Negate] $lit" }
    }
    return ($out -join ';')
}

function Resolve-NormAddressLiterals {
    param($Model, [string]$Token, [System.Collections.Generic.HashSet[string]]$Visited)
    if ($null -eq $Visited) { $Visited = New-Object System.Collections.Generic.HashSet[string] }
    $key = $Token.ToLower()
    if (-not $Visited.Add($key)) { return @($Token) }
    if ($Model.Objects.ContainsKey($key)) {
        $o = $Model.Objects[$key]
        if ($o.Type -in @('ip-netmask', 'ip-range')) { return @($o.Value) }
        return @($Token)
    }
    if ($Model.Groups.ContainsKey($key)) {
        $r = @()
        foreach ($m in $Model.Groups[$key].Members) { $r += Resolve-NormAddressLiterals -Model $Model -Token $m -Visited $Visited }
        return $r
    }
    return @($Token)
}

function Export-MooseAltoInput {
    # -ExportNormalized: writes <prefix>_rules.csv, _address_objects.csv and
    # _address_groups.csv in PAN-OS layout. Returns the three paths.
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$OutDir, [string]$Prefix = 'normalized')
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

    $rows = foreach ($r in $Model.Rules) {
        # Rule Usage is a Panorama-only verdict; leave it empty here too.
        $usage = ''
        [PSCustomObject][ordered]@{
            'Name'                = $r.Name
            'Location'            = $r.Scope
            'Source Zone'         = ($r.SrcZones -join ';')
            'Source Address'      = Format-NormAddressField -Model $Model -Addrs $r.SrcAddrs -Negate $r.SrcNegate
            'Destination Zone'    = ($r.DstZones -join ';')
            'Destination Address' = Format-NormAddressField -Model $Model -Addrs $r.DstAddrs -Negate $r.DstNegate
            'Application'         = $(if ($r.Applications.Count -eq 0) { 'any' } else { $r.Applications -join ';' })
            'Service'             = $(if (Test-NormServiceIsAny $r.Services) { 'any' } else { $r.Services -join ';' })
            'Action'              = $r.Action
            'Profile'             = $r.Profile
            'Tags'                = $r.Tags
            'Disabled'            = $(if ($r.Enabled) { 'no' } else { 'yes' })
            'Hit Count'           = $r.HitCount
            'Last Hit'            = $r.LastHit
            'Rule Usage'          = $usage
            'Vendor'              = $Model.Vendor
            'Vendor Rule ID'      = $r.Id
        }
    }
    $objRows = foreach ($o in ($Model.Objects.Values | Sort-Object Name)) {
        [PSCustomObject][ordered]@{ Name = $o.Name; Location = $Model.Vendor; Type = $o.Type; Address = $o.Value; Tags = '' }
    }
    $grpRows = foreach ($g in ($Model.Groups.Values | Sort-Object Name)) {
        [PSCustomObject][ordered]@{ Name = $g.Name; Location = $Model.Vendor; 'Members Count' = $g.Members.Count; Addresses = ($g.Members -join ';'); Tags = '' }
    }

    $paths = @{
        Rules   = Join-Path $OutDir "${Prefix}_rules.csv"
        Objects = Join-Path $OutDir "${Prefix}_address_objects.csv"
        Groups  = Join-Path $OutDir "${Prefix}_address_groups.csv"
    }
    $rows | Export-Csv -Path $paths.Rules -NoTypeInformation -Encoding UTF8
    if ($objRows) { $objRows | Export-Csv -Path $paths.Objects -NoTypeInformation -Encoding UTF8 }
    else { 'Name,Location,Type,Address,Tags' | Set-Content -Path $paths.Objects -Encoding UTF8 }
    if ($grpRows) { $grpRows | Export-Csv -Path $paths.Groups -NoTypeInformation -Encoding UTF8 }
    else { 'Name,Location,Members Count,Addresses,Tags' | Set-Content -Path $paths.Groups -Encoding UTF8 }
    return $paths
}

function Export-NormReport {
    # The <report>_normalization.txt file.
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$Path)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("MooseAlto normalization report")
    [void]$sb.AppendLine("Vendor : $($Model.Vendor)")
    [void]$sb.AppendLine("Source : $($Model.Source)")
    [void]$sb.AppendLine("Rules  : $($Model.Rules.Count)   Address objects: $($Model.Objects.Count)   Address groups: $($Model.Groups.Count)")
    $inet = @($Model.ZoneHints.Keys | Where-Object { $Model.ZoneHints[$_] -eq 'internet' })
    if ($inet.Count -gt 0) {
        [void]$sb.AppendLine("Internet facing zones from the configuration (added automatically): `"$($inet -join ',')`"")
    }
    [void]$sb.AppendLine('')
    foreach ($lvl in @('error', 'lossy', 'warn', 'info')) {
        $items = @($Model.Diagnostics | Where-Object { $_.Level -eq $lvl })
        if ($items.Count -eq 0) { continue }
        [void]$sb.AppendLine("[$($lvl.ToUpper())] $($items.Count)")
        foreach ($d in $items) {
            $prefix = if ($d.Rule) { "  $($d.Rule): " } else { '  ' }
            [void]$sb.AppendLine("$prefix$($d.Message)")
        }
        [void]$sb.AppendLine('')
    }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}
