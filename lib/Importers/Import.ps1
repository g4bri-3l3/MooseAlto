# --------------------------------------------------------------------------
# Input dispatcher: vendor detection and conversion to MooseAlto rules
# --------------------------------------------------------------------------
#
# PAN-OS CSVs go straight to Import-PaloAltoRules. Everything else is
# imported into the Common.ps1 model, rendered back to PAN-OS-style cell
# text and parsed with the same Parse-* helpers, so the checks can't tell
# the difference.
#
# New vendor: an importer returning the model, plus a line in
# Get-InputVendor and in Import-FirewallConfig.

. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'FortiOS.ps1')
. (Join-Path $PSScriptRoot 'Junos.ps1')
. (Join-Path $PSScriptRoot 'PanUsage.ps1')
. (Join-Path $PSScriptRoot 'Tufin.ps1')
. (Join-Path $PSScriptRoot 'CloudCommon.ps1')
. (Join-Path $PSScriptRoot 'AzureNsg.ps1')
. (Join-Path $PSScriptRoot 'AwsSg.ps1')
. (Join-Path $PSScriptRoot 'GcpFirewall.ps1')

function Get-InputVendor {
    # Looks at the content, not the extension (exports get renamed a lot).
    # Also spots hit counter files, so we can explain the mix-up when one is
    # passed as the main input. Returns '' when it can't tell.
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -Path $Path -PathType Container) { return '' }
    $head = (Get-Content -Path $Path -TotalCount 200 -ErrorAction SilentlyContinue) -join "`n"
    if ($head -match '(?m)^#config-version=FG' -or $head -match '(?m)^\s*config (system|firewall|vdom|global)\b') { return 'fortios' }
    if ($head -match '(?m)^\s*(set|deactivate) (security|system|interfaces|applications|routing-options|logical-systems|groups|version|snmp|policy-options|firewall|protocols|routing-instances) ' -or
        $head -match '(?m)^\s*(security|system|interfaces|applications) \{' -or $head -match '(?m)^## Last (commit|changed)') { return 'junos' }
    # Tufin: any line naming Device Name, Rule Name, Source and Destination,
    # in any order. PAN-OS never has "Device Name" or "Rule Name".
    foreach ($ln in ($head -split "`n")) {
        if ($ln -match '(?i)Device\s*Name' -and $ln -match '(?i)Rule\s*Name' -and $ln -match '(?i)(^|[,;"])\s*Source\s*([,;"]|$)' -and $ln -match '(?i)(^|[,;"])\s*Destination\s*([,;"]|$)') { return 'tufin' }
    }
    # PAN-OS: the header names the zone and address columns.
    $firstLine = (($head -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    if ($firstLine -match '(?i)Source Zone' -and $firstLine -match '(?i)Destination Address' -and $firstLine -match ',') { return 'paloalto-csv' }
    # Cloud exports (JSON from the az / aws / gcloud CLIs). A CLI warning
    # line may come before the JSON. A line opening a JSON array or object,
    # not a Markdown link ("[![...").
    if ($head -match '(?m)^\s*(\[\s*$|\{\s*$|\[\s*\{|\{\s*")') {
        if (Test-AwsSgJson $head) { return 'aws' }
        if (Test-GcpFirewallJson $head) { return 'gcp' }
        if (Test-AzureNsgJson $head) { return 'azure' }
    }
    if ($head.TrimStart() -match '^[\[{]' -and $head -match '"policyid"') { return 'fortios-hitcount' }
    if ($head -match '(?m)^\s*Index\s+From zone\s+To zone\s+Name') { return 'junos-hitcount' }
    if ($firstLine -match '(?i)Hit Count|Rule Usage' -and $firstLine -match '(?i)(^|[,"])Name([,"]|$)') { return 'paloalto-usage' }
    return ''
}

function Get-HitCountFileNote {
    # What to tell the user when they pass a hit counter file as the input.
    param([string]$Vendor)
    switch ($Vendor) {
        'fortios-hitcount' { return 'a FortiGate hit counter file (monitor API JSON), not a configuration. The configuration to analyze is the .conf backup (or "show full-configuration" output)' }
        'junos-hitcount' { return "a Juniper SRX hit counter file ('show security policies hit-count' output), not a configuration. The configuration to analyze is 'show configuration | display set' (or the hierarchical text)" }
        'paloalto-usage' { return 'a Palo Alto rule usage file (Name plus Hit Count / Last Hit / Rule Usage), not a rulebase export. The file to analyze is the security rulebase CSV export' }
    }
    return $null
}

function Import-FirewallConfig {
    # Returns rules plus objects and groups in the same shape the PAN-OS
    # object CSVs produce.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Vendor,
        [string]$HitCountFile,
        [string]$AppMapCsv
    )
    switch ($Vendor) {
        'fortios' { $model = ConvertFrom-FortiOS -Path $Path -UsageJson $HitCountFile -AppMapCsv $AppMapCsv }
        'junos' { $model = ConvertFrom-Junos -Path $Path -HitCountFile $HitCountFile -AppMapCsv $AppMapCsv }
        'tufin' { $model = ConvertFrom-Tufin -Path $Path }
        'azure' { $model = ConvertFrom-AzureNsg -Path $Path }
        'aws' { $model = ConvertFrom-AwsSg -Path $Path }
        'gcp' { $model = ConvertFrom-GcpFirewall -Path $Path }
        default { throw "No importer for vendor '$Vendor'." }
    }
    $objects = @{}
    foreach ($o in $model.Objects.Values) {
        $objects[$o.Name.ToLower()] = [PSCustomObject]@{ Name = $o.Name; Type = $o.Type; Value = $o.Value }
    }
    $groups = @{}
    foreach ($g in $model.Groups.Values) {
        $groups[$g.Name.ToLower()] = [PSCustomObject]@{ Name = $g.Name; IsDynamic = $false; Members = @($g.Members) }
    }
    return @{
        Rules         = ConvertTo-MooseAltoRules -Model $model
        Objects       = $objects
        Groups        = $groups
        Model         = $model
        VendorContext = @{ Vendor = $model.Vendor; IntrazoneAllowZones = @($model.IntrazoneAllowZones) }
    }
}

function ConvertTo-MooseAltoRules {
    # Field list must stay in step with Import-PaloAltoRules (Parsing.ps1).
    param([Parameter(Mandatory)]$Model)
    $hasLog = @($Model.Rules | Where-Object { $null -ne $_.Log }).Count -gt 0
    $hasCreated = @($Model.Rules | Where-Object { $_.Created }).Count -gt 0
    $hasModified = @($Model.Rules | Where-Object { $_.Modified }).Count -gt 0
    $seenNames = @{}
    $rules = @()
    $i = 0
    foreach ($r in $Model.Rules) {
        $name = $r.Name
        if ($seenNames.ContainsKey($name)) { $seenNames[$name]++; $name = "$name (duplicate name #$($seenNames[$name]))" }
        else { $seenNames[$name] = 1 }

        $srcZone = ($r.SrcZones -join ';')
        $dstZone = ($r.DstZones -join ';')
        $srcRaw = Format-NormAddressField -Model $Model -Addrs $r.SrcAddrs -Negate $r.SrcNegate
        $dstRaw = Format-NormAddressField -Model $Model -Addrs $r.DstAddrs -Negate $r.DstNegate
        $appRaw = if ($r.Applications.Count -eq 0) { 'any' } else { $r.Applications -join ';' }
        $svcRaw = if (Test-NormServiceIsAny $r.Services) { 'any' } else { $r.Services -join ';' }
        # Panorama-only verdict; zero hits are covered by zero_hit_count.
        $usage = ''

        $obj = [PSCustomObject]@{
            Index             = $i
            Name              = $name
            LocalName         = "$($r.LocalName)"
            SrcZone           = Parse-ZoneField $srcZone
            SrcAddrRaw        = $srcRaw
            SrcAddr           = Parse-AddressField $srcRaw
            DstZone           = Parse-ZoneField $dstZone
            DstAddrRaw        = $dstRaw
            DstAddr           = Parse-AddressField $dstRaw
            Application       = Parse-ListField $appRaw
            ServiceRaw        = $svcRaw
            Service           = Parse-ListField $svcRaw
            Action            = $r.Action
            Profile           = $r.Profile
            Tags              = $r.Tags
            Disabled          = -not $r.Enabled
            HitCount          = $r.HitCount
            UsageStatus       = $usage
            LastHit           = $r.LastHit
            Options           = $(if ($null -ne $r.Log) { $r.Log } else { '' })
            HasOptionsColumn  = $hasLog
            Created           = $r.Created
            Modified          = $r.Modified
            HasCreatedColumn  = $hasCreated
            HasModifiedColumn = $hasModified
            # A multi-vendor export (Tufin) gives each rule its own vendor.
            Vendor            = $(if ($r.PSObject.Properties['Vendor'] -and $r.Vendor) { $r.Vendor } else { $Model.Vendor })
            VendorRuleId      = $r.Id
            Scope             = $r.Scope
            LastHitMeansHit   = [bool]($r.PSObject.Properties['LastHitMeansHit'] -and $r.LastHitMeansHit)
        }
        # Cloud importers decide internet exposure themselves (see
        # Test-RuleSideIsInternet). Other rules don't get the fields at all.
        if ($r.PSObject.Properties['SrcIsInternet']) {
            $obj | Add-Member -NotePropertyName SrcIsInternet -NotePropertyValue ([bool]$r.SrcIsInternet)
            $obj | Add-Member -NotePropertyName DstIsInternet -NotePropertyValue ([bool]$r.DstIsInternet)
        }
        # A service tag modeled as addresses (Azure Internet) keeps its own
        # name in the report text.
        if ($r.PSObject.Properties['SrcDisplay'] -and $r.SrcDisplay) { $obj.SrcAddrRaw = $r.SrcDisplay }
        if ($r.PSObject.Properties['DstDisplay'] -and $r.DstDisplay) { $obj.DstAddrRaw = $r.DstDisplay }
        $rules += $obj
        $i++
    }
    return $rules
}

function Write-ImportSummary {
    # Console summary, and the normalization file next to the HTML report.
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$ReportPath, [string]$HitCountFile = '')
    Export-NormReport -Model $Model -Path $ReportPath
    $byLevel = @($Model.Diagnostics | Group-Object Level | ForEach-Object { "$($_.Count) $($_.Name)" })
    Write-Host "Imported $($Model.Vendor) config: $($Model.Rules.Count) rule(s), $($Model.Objects.Count) address object(s), $($Model.Groups.Count) group(s)." -ForegroundColor Green
    if ($HitCountFile) {
        $withHits = @($Model.Rules | Where-Object { $_.HitCount -ne '' }).Count
        $color = if ($withHits -eq 0) { 'Red' } elseif ($withHits -lt $Model.Rules.Count) { 'Yellow' } else { 'Green' }
        Write-Host "Hit counters from ${HitCountFile}: found for $withHits of $($Model.Rules.Count) rule(s)." -ForegroundColor $color
        foreach ($d in @($Model.Diagnostics | Where-Object { $_.Message -like 'hit counter file*' })) { Write-Host "  $($d.Message)" -ForegroundColor $color }
    }
    if ($byLevel.Count -gt 0) {
        Write-Host "Normalization notes: $($byLevel -join ', '). Details in $ReportPath" -ForegroundColor Yellow
    }
    return $ReportPath
}
