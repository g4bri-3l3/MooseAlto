# --------------------------------------------------------------------------
# Tufin SecureTrack Rule Viewer CSV export
# --------------------------------------------------------------------------
#
# One file can hold many devices and vendors. A few report lines come first,
# then the table; columns are matched by name and the rest are ignored (the
# mapping is in the README). Rules are named "<device>/<rule>" and only
# compared inside the same device and policy. Object names stay names:
# Tufin doesn't export what's in them.

$script:TufinVendorMap = [ordered]@{
    'palo alto' = 'paloalto'; 'fortinet' = 'fortios'; 'fortigate' = 'fortios'; 'juniper' = 'junos'
    'check point' = 'checkpoint'; 'checkpoint' = 'checkpoint'; 'cisco' = 'cisco'; 'azure' = 'azure'
    'amazon' = 'aws'; 'aws' = 'aws'; 'google' = 'gcp'; 'zscaler' = 'zscaler'; 'f5' = 'f5'
}

# Common service names the FortiOS and Junos tables don't already cover.
$script:TufinServiceNames = @{
    'service-http' = @('tcp-80', 'tcp-8080'); 'service-https' = @('tcp-443')
    'http' = @('tcp-80'); 'https' = @('tcp-443'); 'ssh' = @('tcp-22'); 'telnet' = @('tcp-23'); 'ftp' = @('tcp-21')
    'smtp' = @('tcp-25'); 'domain-udp' = @('udp-53'); 'domain-tcp' = @('tcp-53'); 'dns' = @('tcp-53', 'udp-53')
    'ntp' = @('udp-123'); 'ntp-udp' = @('udp-123'); 'snmp' = @('udp-161'); 'ldap' = @('tcp-389'); 'ldap-ssl' = @('tcp-636')
    'microsoft-ds' = @('tcp-445'); 'smb' = @('tcp-445'); 'remote_desktop_protocol' = @('tcp-3389'); 'rdp' = @('tcp-3389')
    'ms-sql-server' = @('tcp-1433'); 'mysql' = @('tcp-3306'); 'pop-3' = @('tcp-110'); 'pop3' = @('tcp-110')
    'imap' = @('tcp-143'); 'tftp' = @('udp-69'); 'syslog' = @('udp-514'); 'echo-request' = @('icmp-8'); 'icmp' = @('icmp')
    'icmp-proto' = @('icmp'); 'ping' = @('icmp-8')
}

function ConvertTo-TufinVendor {
    param([string]$Text)
    $t = $Text.Trim().ToLower()
    foreach ($k in $script:TufinVendorMap.Keys) { if ($t.Contains($k)) { return $script:TufinVendorMap[$k] } }
    return $(if ($t) { ($t -replace '[^a-z0-9]+', '-') } else { 'unknown' })
}

function Split-TufinCell {
    param([string]$Text)
    if (-not $Text) { return @() }
    return @($Text -split '\r?\n|;|,(?![^()\[\]]*[\)\]])' | ForEach-Object { $_.Trim().Trim('"').Trim() } | Where-Object { $_ })
}

function Test-TufinAny {
    param([string]$Text)
    # Also "ANY SERVICE", "ANY APPLICATION" and friends.
    return $Text -match '^(?i)(any|all|\*|any4|any-ipv4|0\.0\.0\.0/0|0\.0\.0\.0/0\.0\.0\.0|any( [a-z]+)+)$'
}

function ConvertFrom-TufinMask {
    # 10.1.1.0/255.255.255.0 -> 10.1.1.0/24
    param([string]$Ip, [string]$Mask)
    $bits = 0
    foreach ($o in ($Mask -split '\.')) { $bits += ([Convert]::ToString([int]$o, 2).ToCharArray() | Where-Object { $_ -eq '1' }).Count }
    return "$Ip/$bits"
}

function ConvertTo-TufinAddress {
    # An address we can do math on, or else the name.
    param([string]$Item)
    $v = $Item.Trim()
    $ipRe = '\d{1,3}(?:\.\d{1,3}){3}'
    # "name (value)": use the value.
    if ($v -match "^(.+?)\s*[\(\[]\s*(.+?)\s*[\)\]]$") {
        $inner = ConvertTo-TufinAddress $Matches[2]
        if ($inner -match "^$ipRe") { return $inner }
        $v = $Matches[1].Trim()
    }
    if ($v -match "^($ipRe)\s*(?:/|\s)\s*($ipRe)$") { return (ConvertFrom-TufinMask $Matches[1] $Matches[2]) }
    if ($v -match "^($ipRe)\s*-\s*($ipRe)$") { return "$($Matches[1])-$($Matches[2])" }
    if ($v -match "^$ipRe(/\d{1,2})?$") { return $v }
    return $v
}

function ConvertTo-TufinServiceTokens {
    param([string]$Item)
    $v = $Item.Trim()
    $lv = $v.ToLower()
    if ($lv -eq 'application-default') { return @('application-default') }
    # "https (tcp/443)", "tcp 443", "TCP/443", "tcp:8000-8010", "udp_53"
    if ($lv -match '(tcp|udp|sctp)\s*[/:_ -]\s*(\d+)(?:\s*-\s*(\d+))?') {
        $lo = [int]$Matches[2]; $hi = if ($Matches[3]) { [int]$Matches[3] } else { $lo }
        return @(ConvertTo-PortTokens -Proto $Matches[1] -Low $lo -High $hi)
    }
    # "tcp/https" (Cisco style): protocol plus a named port
    if ($lv -match '^(tcp|udp)\s*[/:]\s*([a-z][a-z0-9-]*)$' -and $script:JunosNamedPorts.ContainsKey($Matches[2])) {
        return @("$($Matches[1])-$($script:JunosNamedPorts[$Matches[2]])")
    }
    if ($lv -match '^icmp') { return @('icmp') }
    if ($script:TufinServiceNames.ContainsKey($lv)) { return $script:TufinServiceNames[$lv] }
    if ($script:FgtPredefinedServices.ContainsKey($v.ToUpper())) { return $script:FgtPredefinedServices[$v.ToUpper()] }
    if ($script:JunosPredefinedApps.ContainsKey($lv)) { return $script:JunosPredefinedApps[$lv] }
    return @($lv)
}

function ConvertTo-TufinApplication {
    param([string]$Item, [string]$Vendor)
    switch ($Vendor) {
        'fortios' { return (ConvertTo-FgtCanonicalApp $Item) }
        'junos' { return (ConvertTo-JunosCanonicalApp -DynamicApp $Item -UserMap @{}) }
    }
    return ($Item.Trim().ToLower() -replace '\s+', '-')
}

function ConvertTo-TufinDate {
    # To yyyy-MM-dd; $DayFirst picks dd/MM or MM/dd.
    param([string]$Text, [bool]$DayFirst)
    $t = $Text.Trim()
    if ($t -match '^(\d{4})-(\d{2})-(\d{2})') { return "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    if ($t -match '^(\d{1,2})[/.](\d{1,2})[/.](\d{4})') {
        $a = [int]$Matches[1]; $b = [int]$Matches[2]; $y = [int]$Matches[3]
        $d = if ($DayFirst) { $a } else { $b }; $m = if ($DayFirst) { $b } else { $a }
        if ($m -ge 1 -and $m -le 12 -and $d -ge 1 -and $d -le 31) { return ('{0:D4}-{1:D2}-{2:D2}' -f $y, $m, $d) }
    }
    $parsed = [datetime]::MinValue
    $formats = @('MMM d, yyyy h:mm:ss tt', 'MMM d, yyyy', 'd MMM yyyy', 'd MMM yyyy HH:mm:ss', 'ddd MMM dd HH:mm:ss yyyy')
    if ([datetime]::TryParseExact($t, [string[]]$formats, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$parsed)) {
        return $parsed.ToString('yyyy-MM-dd')
    }
    return ''
}

function Read-TufinTable {
    # The header is the first line with the device and rule columns. The
    # lines above it are kept: they help guess the date format.
    param([string]$Path)
    $raw = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path)
    $lines = $raw -split "`r?`n"
    $hdrIdx = -1
    for ($i = 0; $i -lt [math]::Min($lines.Count, 100); $i++) {
        if ($lines[$i] -match '(?i)Device\s*Name' -and $lines[$i] -match '(?i)Rule\s*Name' -and $lines[$i] -match '(?i)Source' -and $lines[$i] -match '(?i)Destination') { $hdrIdx = $i; break }
    }
    if ($hdrIdx -lt 0) { throw "no Tufin rule table header (Device Name / Rule Name / Source columns) in the first 100 lines" }
    $hdrLine = $lines[$hdrIdx]
    $delim = if (([regex]::Matches($hdrLine, ';')).Count -gt ([regex]::Matches($hdrLine, ',')).Count) { ';' } else { ',' }
    $names = @(($hdrLine.TrimStart([char]0xFEFF) | ConvertFrom-Csv -Delimiter $delim -Header (1..200 | ForEach-Object { "c$_" })).PSObject.Properties |
        Where-Object { $null -ne $_.Value } | ForEach-Object { $_.Value.Trim() })
    $seen = @{}
    for ($k = 0; $k -lt $names.Count; $k++) {
        if (-not $names[$k]) { $names[$k] = "Column$($k + 1)" }
        if ($seen.ContainsKey($names[$k].ToLower())) { $names[$k] = "$($names[$k])_$($k + 1)" }
        $seen[$names[$k].ToLower()] = $true
    }
    $body = ($lines[($hdrIdx + 1)..($lines.Count - 1)] -join "`n")
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText($tmp, $body, [System.Text.UTF8Encoding]::new($false))
        $rows = @(Import-Csv -Path $tmp -Delimiter $delim -Header $names -Encoding UTF8)
    }
    finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
    return @{ Rows = $rows; Preamble = @($lines[0..([math]::Max($hdrIdx - 1, 0))]); Columns = $names }
}

function Get-TufinField {
    # Ignores case and spaces in the column name.
    param($Row, [string]$Name)
    $key = ($Name -replace '\s+', '').ToLower()
    foreach ($p in $Row.PSObject.Properties) {
        if (($p.Name -replace '\s+', '').ToLower() -eq $key) { return "$($p.Value)".Trim() }
    }
    return ''
}

function Test-TufinTrue {
    param([string]$Text)
    return $Text -match '^(?i)(true|yes|y|1|enabled?|negated)$'
}

function ConvertFrom-Tufin {
    param([Parameter(Mandatory)][string]$Path)
    $model = New-NormModel -Vendor 'tufin' -Source $Path
    $table = Read-TufinTable -Path $Path
    $rows = $table.Rows
    # No Tufin report lines on top: still go ahead, but mention it.
    if (-not (($table.Preamble -join "`n") -match '(?i)Report creation time|rule-viewer|SecureTrack')) {
        Add-NormDiagnostic $model 'info' '' "read as a Tufin Rule Viewer export from its column names only (no Tufin report lines above the table)"
        Write-Host "Note: $Path read as a Tufin Rule Viewer export from its column names (Device Name, Rule Name, Source, Destination); the Tufin report lines above the table are not there." -ForegroundColor Yellow
    }

    # The export only has the columns that were on screen. A missing one
    # must be reported: read as empty it would turn rules into allow / any.
    $have = @($table.Columns | ForEach-Object { ($_ -replace '\s+', '').ToLower() })
    $required = @('Device Name', 'Rule Name', 'Source', 'Destination', 'Service', 'Action')
    $missingReq = @($required | Where-Object { $have -notcontains ($_ -replace '\s+', '').ToLower() })
    if ($missingReq.Count -gt 0) {
        throw "the Tufin export lacks column(s) $($missingReq -join ', '). Add them to the Rule Viewer columns and export again"
    }
    $optional = [ordered]@{
        'Vendor' = 'finding wording and application names fall back to generic'
        'Policy Name' = 'rules of different policies on one device are compared with each other'
        'From Zone' = 'no zones: internet exposure judged on addresses only'
        'To Zone' = 'no zones: internet exposure judged on addresses only'
        'Disabled' = 'every rule treated as enabled'
        'Source Negated' = 'negated sources read as positive (rule looks narrower than it is)'
        'Destination Negated' = 'negated destinations read as positive (rule looks narrower than it is)'
        'Service Negated' = 'negated services read as positive'
        'Application' = 'no application checks'
        'Security Profiles' = 'every rule reported without security profile'
        'Logged' = 'logging checks not run'
        'Last Hit' = 'usage checks (zero hits, stale) not run'
    }
    $missingOpt = @($optional.Keys | Where-Object { $have -notcontains ($_ -replace '\s+', '').ToLower() })
    foreach ($c in $missingOpt) {
        Add-NormDiagnostic $model 'warn' '' "column '$c' not in the export: $($optional[$c])"
    }
    if ($missingOpt.Count -gt 0) {
        Write-Host "WARNING: the Tufin export lacks column(s) $($missingOpt -join ', '); see the normalization notes for what that changes. Add them to the Rule Viewer columns for a complete analysis." -ForegroundColor Yellow
    }
    # Without the column, every rule would get flagged for missing profiles.
    $noProfileColumn = $missingOpt -contains 'Security Profiles'

    # dd/MM or MM/dd? Look for a number above 12 in the dates, then in the
    # report header; otherwise assume day first.
    $dayFirst = $null
    foreach ($r in $rows) {
        foreach ($c in @((Get-TufinField $r 'Last Hit'), (Get-TufinField $r 'Last Modified'))) {
            if ($c -match '^(\d{1,2})[/.](\d{1,2})[/.]\d{4}') {
                if ([int]$Matches[1] -gt 12) { $dayFirst = $true; break }
                if ([int]$Matches[2] -gt 12) { $dayFirst = $false; break }
            }
        }
        if ($null -ne $dayFirst) { break }
    }
    if ($null -eq $dayFirst) {
        $pre = $table.Preamble -join ' '
        if ($pre -match '(\d{1,2})[/.](\d{1,2})[/.]\d{4}') { $dayFirst = -not ([int]$Matches[2] -gt 12) }
        else { $dayFirst = $true }
    }

    $devices = @{}
    $skipped = @{}
    foreach ($row in $rows) {
        $device = Get-TufinField $row 'Device Name'
        $src = Get-TufinField $row 'Source'
        $dst = Get-TufinField $row 'Destination'
        $actionRaw = Get-TufinField $row 'Action'
        # Section titles and separators.
        if (-not $device -or (-not $src -and -not $dst -and -not $actionRaw)) { continue }

        $vendor = ConvertTo-TufinVendor (Get-TufinField $row 'Vendor')
        $policy = Get-TufinField $row 'Policy Name'
        $ruleset = Get-TufinField $row 'Ruleset'
        $ruleType = Get-TufinField $row 'Rule Type'
        $ruleName = Get-TufinField $row 'Rule Name'
        $localName = $ruleName
        $idOnDevice = Get-TufinField $row 'ID on Device'
        if (-not $ruleName) { $ruleName = if ($idOnDevice) { "rule $idOnDevice" } else { "seq $(Get-TufinField $row 'Seq No.')" } }

        # NAT, decryption, PBF and QoS aren't security rules.
        if ($ruleType -match '(?i)\bnat\b|decrypt|pbf|forward|qos|tunnel') {
            $skipped["rule type '$ruleType'"] = 1 + [int]$skipped["rule type '$ruleType'"]
            continue
        }
        # PAN-OS default rules; the intrazone check already covers them.
        if ($ruleName -match '^(?i)(intrazone|interzone)-default$') {
            $skipped['PAN-OS intrazone/interzone default rules'] = 1 + [int]$skipped['PAN-OS intrazone/interzone default rules']
            continue
        }

        $r = New-NormRule
        $scopeParts = @($device, $policy, $ruleset) | Where-Object { $_ }
        $r.Scope = ($scopeParts -join '/')
        $r.Name = "$device/$ruleName"
        $r.LocalName = $localName
        $r | Add-Member -NotePropertyName TufinDevice -NotePropertyValue $device
        $r.Id = $(if ($idOnDevice) { "$device#$idOnDevice" } else { $r.Name })
        $r.Enabled = -not (Test-TufinTrue (Get-TufinField $row 'Disabled'))
        $r | Add-Member -NotePropertyName Vendor -NotePropertyValue $vendor

        $fz = @(Split-TufinCell (Get-TufinField $row 'From Zone') | Where-Object { -not (Test-TufinAny $_) })
        $tz = @(Split-TufinCell (Get-TufinField $row 'To Zone') | Where-Object { -not (Test-TufinAny $_) })
        $r.SrcZones = $(if ($fz.Count) { $fz } else { @('any') })
        $r.DstZones = $(if ($tz.Count) { $tz } else { @('any') })

        $sItems = @(Split-TufinCell $src); $dItems = @(Split-TufinCell $dst)
        $r.SrcAddrs = $(if (@($sItems | Where-Object { Test-TufinAny $_ }).Count -gt 0 -or $sItems.Count -eq 0) { @() } else { @($sItems | ForEach-Object { ConvertTo-TufinAddress $_ }) })
        $r.DstAddrs = $(if (@($dItems | Where-Object { Test-TufinAny $_ }).Count -gt 0 -or $dItems.Count -eq 0) { @() } else { @($dItems | ForEach-Object { ConvertTo-TufinAddress $_ }) })
        # No zones at all (Check Point): a zone of "any" would make every rule
        # look internet facing, so use "(no zone)" unless the address is any
        # too, and let the addresses decide.
        if ($fz.Count -eq 0 -and $tz.Count -eq 0) {
            $r.SrcZones = $(if ($r.SrcAddrs.Count -eq 0) { @('any') } else { @('(no zone)') })
            $r.DstZones = $(if ($r.DstAddrs.Count -eq 0) { @('any') } else { @('(no zone)') })
        }
        $r.SrcNegate = (Test-TufinTrue (Get-TufinField $row 'Source Negated')) -and $r.SrcAddrs.Count -gt 0
        $r.DstNegate = (Test-TufinTrue (Get-TufinField $row 'Destination Negated')) -and $r.DstAddrs.Count -gt 0

        $apps = @(Split-TufinCell (Get-TufinField $row 'Application') | Where-Object { -not (Test-TufinAny $_) })
        $r.Applications = @($apps | ForEach-Object { ConvertTo-TufinApplication $_ $vendor } | Select-Object -Unique)

        $svcItems = @(Split-TufinCell (Get-TufinField $row 'Service'))
        $tokens = @()
        if (@($svcItems | Where-Object { Test-TufinAny $_ }).Count -eq 0) {
            foreach ($s in $svcItems) { $tokens += ConvertTo-TufinServiceTokens $s }
        }
        $tokens = @($tokens | Select-Object -Unique)
        if (Test-TufinTrue (Get-TufinField $row 'Service Negated')) {
            Add-NormDiagnostic $model 'lossy' $r.Name "service negated ($($svcItems -join ', ')); treated as any service (WIDER than the rule)"
            $tokens = @()
        }
        $r.Services = $(if ($tokens -contains 'application-default') { @('application-default') } elseif (Test-NormServiceIsAny $tokens) { @() } else { $tokens })

        $r.Action = $(if ($actionRaw -match '(?i)deny|drop|reject|reset|block') { 'deny' } else { 'allow' })
        if ($actionRaw -and $actionRaw -notmatch '(?i)allow|accept|permit|pass|deny|drop|reject|reset|block') {
            Add-NormDiagnostic $model 'lossy' $r.Name "action '$actionRaw' read as allow"
        }
        elseif (-not $actionRaw) {
            Add-NormDiagnostic $model 'lossy' $r.Name "empty Action cell, read as allow"
        }

        $prof = Get-TufinField $row 'Security Profiles'
        $r.Profile = $(if ($noProfileColumn) { '(not exported)' } elseif (-not $prof -or $prof -match '^(?i)(none|n/a|-)$') { 'none' } else { ((Split-TufinCell $prof) -join ';') })
        # FortiGate app control in the profiles counts as app inspection.
        if ($vendor -eq 'fortios' -and $prof -match '(?i)application') { $r.Profile += ';app:tufin' }

        $logged = Get-TufinField $row 'Logged'
        $r.Log = $(if (Test-TufinTrue $logged) { 'Log at Session End' } elseif ($logged) { '' } else { $null })
        $r.Tags = ((Split-TufinCell (Get-TufinField $row 'Tags')) -join ';')
        $r.Modified = ConvertTo-TufinDate (Get-TufinField $row 'Last Modified') $dayFirst

        $lh = Get-TufinField $row 'Last Hit'
        $lhDate = if ($lh) { ConvertTo-TufinDate $lh $dayFirst } else { '' }
        if ($lhDate) {
            # A date but no counter: we know it was hit, not how often.
            $r.LastHit = $lhDate
            $r | Add-Member -NotePropertyName LastHitMeansHit -NotePropertyValue $true
        }
        elseif ($lh -match '(?i)^(no hits?|never|none|0)$') { $r.HitCount = '0'; $r.LastHit = '-' }
        elseif (-not $lh) {
            # Empty means "no hits" or "not collected on this device". Sorted
            # out after the loop: zero hits only if the device has dates.
            $r | Add-Member -NotePropertyName TufinNoLastHit -NotePropertyValue $true
        }

        foreach ($pair in @(@('Source User', 'restricted to users; MooseAlto has no identity dimension, rule may look broader than it is'),
                @('URL Category', 'URL category restricts destinations; not represented'),
                @('Time', 'time limited rule (schedule)'))) {
            $val = Get-TufinField $row $pair[0]
            if ($val -and -not (Test-TufinAny $val) -and $val -notmatch '^(?i)(always|n/a|-)$') {
                Add-NormDiagnostic $model $(if ($pair[0] -eq 'Time') { 'info' } else { 'lossy' }) $r.Name "$($pair[0]) '$val': $($pair[1])"
            }
        }
        $model.Rules.Add($r)
        $devices["$device ($vendor)"] = 1 + [int]$devices["$device ($vendor)"]
    }

    $devicesWithHits = @{}
    foreach ($r in $model.Rules) { if ($r.LastHit -and $r.LastHit -ne '-') { $devicesWithHits[$r.TufinDevice] = $true } }
    $noTracking = @{}
    foreach ($r in $model.Rules) {
        if (-not ($r.PSObject.Properties['TufinNoLastHit'] -and $r.TufinNoLastHit)) { continue }
        $dev = $r.TufinDevice
        if ($devicesWithHits.ContainsKey($dev)) { $r.HitCount = '0'; $r.LastHit = '-' }
        else { $noTracking[$dev] = $true }
    }
    if ($noTracking.Count -gt 0) {
        Add-NormDiagnostic $model 'info' '' "no Last Hit on any rule of $(@($noTracking.Keys | Sort-Object) -join ', '): hit data not collected there, usage checks skipped for those devices"
    }
    foreach ($k in $skipped.Keys) { Add-NormDiagnostic $model 'info' '' "$($skipped[$k]) row(s) skipped: $k" }
    Add-NormDiagnostic $model 'info' '' "devices: $(($devices.Keys | Sort-Object | ForEach-Object { "$_ $($devices[$_])" }) -join ', ')"
    Add-NormDiagnostic $model 'info' '' "dates read as $(if ($dayFirst) { 'day/month/year' } else { 'month/day/year' })"
    $withNames = @($model.Rules | Where-Object { @($_.SrcAddrs + $_.DstAddrs | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}' }).Count -gt 0 }).Count
    if ($withNames -gt 0) {
        Add-NormDiagnostic $model 'lossy' '' "$withNames rule(s) reference address objects or groups by name: Tufin exports only the name, so they are compared by name, not by address (see Known limitations)"
    }
    # Only PAN-OS allows intrazone traffic by default.
    foreach ($z in @($model.Rules | Where-Object { $_.Vendor -eq 'paloalto' } | ForEach-Object { $_.SrcZones + $_.DstZones } | Where-Object { $_ -ne 'any' } | ForEach-Object { $_.ToLower() } | Select-Object -Unique)) {
        $model.IntrazoneAllowZones.Add($z)
    }
    if ($model.Rules.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no security rule found in the Tufin export' }
    return $model
}
