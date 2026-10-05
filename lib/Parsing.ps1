# --------------------------------------------------------------------------
# CSV / field parsing (rules, address objects, address groups)
# --------------------------------------------------------------------------

function Parse-ZoneField {
    # Zones can be multi-valued. Exports normally use ";" but we've seen ","
    # too, so accept both. Blank means "any"; never returns $null.
    param([string]$Field)
    $Field = $Field.Trim()
    if ($Field -eq "") { return @("any") }
    $vals = @($Field -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    if ($vals.Count -eq 0) { return @("any") }
    return $vals
}

function Parse-AddressField {
    # Same ";" or "," split as the zones. Returns $null for any. Tokens are
    # kept as written; IpHelpers decides later what it can do math on.
    param([string]$Field)
    $Field = $Field.Trim()
    if ($Field -eq "" -or $Field.ToLower() -eq "any") { return $null }
    $tokens = @()
    foreach ($part in ($Field -split '[;,]')) {
        $part = $part.Trim()
        if ($part -eq "") { continue }
        $tokens += $part
    }
    if ($tokens.Count -eq 0) { return $null }
    return $tokens
}

function Parse-ListField {
    # Applications and services: same split, lowercased. $null means any.
    param([string]$Field)
    $Field = $Field.Trim()
    if ($Field -eq "" -or $Field.ToLower() -eq "any") { return $null }
    return @($Field -split '[;,]' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" })
}

function Get-ServicePorts {
    # Ports from "tcp/23" or from service objects named "tcp-23". Only a
    # tcp/udp prefix counts, so "web-8080" isn't mistaken for a port.
    param($ServiceTokens)
    $ports = @()
    if (-not $ServiceTokens) { return $ports }
    foreach ($tok in $ServiceTokens) {
        if ($tok -match '(?i)^(tcp|udp)[/-](\d+)$') { $ports += [int]$Matches[2] }
    }
    return $ports
}

function Get-ServiceUdpPorts {
    # UDP ports only, for the amplification check (spoofed reflection needs
    # UDP; the same port over TCP isn't a risk there).
    param($ServiceTokens)
    $ports = @()
    if (-not $ServiceTokens) { return $ports }
    foreach ($tok in $ServiceTokens) {
        if ($tok -match '(?i)^udp[/-](\d+)$') { $ports += [int]$Matches[1] }
    }
    return $ports
}

function Repair-DoubleWrappedCsvLine {
    # Some exports (Panorama 11.1, PAN-OS 10/11.1) wrap the whole line in
    # quotes and double every quote inside. Undo that, or the CSV parser
    # sees the line as a single field.
    param([string]$Line)
    if (-not $Line.StartsWith('"')) { return $Line }
    $trimmed = $Line
    if ($trimmed.StartsWith('"')) { $trimmed = $trimmed.Substring(1) }
    if ($trimmed.Length -gt 0 -and $trimmed.EndsWith('"')) { $trimmed = $trimmed.Substring(0, $trimmed.Length - 1) }
    return ($trimmed -replace '""', '"')
}

function Remove-BomNoise {
    # Strips a real BOM and the mojibake one ("ï»¿", the BOM bytes read as
    # CP1252 and saved again). Char codes instead of literal glyphs so the
    # .ps1 file's own encoding can't break the comparison.
    param([string]$Text)
    $Text = $Text.TrimStart([char]0xFEFF)
    $mojibakeBom = [string]([char]0xEF) + [string]([char]0xBB) + [string]([char]0xBF)
    if ($Text.StartsWith($mojibakeBom)) { $Text = $Text.Substring(3) }
    return $Text
}

function Get-CsvFileContent {
    # Reads the file, drops BOM noise and unwraps double-wrapped lines.
    # It loops because we've seen a header wrapped twice, with a mojibake
    # BOM between the layers; one pass left garbage column names and a
    # silently wrong report.
    param([string]$Path)
    $rawContent = Get-Content -Path $Path -Raw
    $rawContent = Remove-BomNoise -Text $rawContent
    $lines = $rawContent -split "`r?`n"
    if ($lines.Count -gt 0) {
        # The prefix alone would also match a normal line like "ID",Name,...
        # so we also want several "" pairs before calling it wrapped.
        $wrapPrefix = '^"[^,]{0,10}?,'
        $passes = 0
        while ($passes -lt 5) {
            $probe = Remove-BomNoise -Text $lines[0]
            $looksWrapped = ($probe -match $wrapPrefix) -and (([regex]::Matches($probe, '""')).Count -ge 5)
            if (-not $looksWrapped) { break }
            $lines = $lines | ForEach-Object { Repair-DoubleWrappedCsvLine -Line (Remove-BomNoise -Text $_) }
            $passes++
        }
    }
    return ($lines -join "`r`n")
}

function Get-DummyCsvHeaders {
    # Placeholder names to read the header line as a data row: one per
    # comma plus one, at least $Minimum. A fixed count used to drop columns
    # (rule usage exports have more than 20). Extra names come back $null.
    param([string]$HeaderLine, [int]$Minimum = 20)
    $n = [Math]::Max($Minimum, ([regex]::Matches("$HeaderLine", ',')).Count + 1)
    return @(1..$n | ForEach-Object { "Col$_" })
}

function Import-PaloAltoRules {
    param([string]$Path)

    # Exports often start with an unnamed row-number column, and a blank
    # header makes Import-Csv rename every column H1, H2... So we read the
    # header ourselves, name the blank one, and parse with that list.
    $fileContent = Get-CsvFileContent -Path $Path
    $fileLines = $fileContent -split "`r?`n"

    $headerLineRaw = $fileLines[0]
    $dummyHeaders = Get-DummyCsvHeaders -HeaderLine $headerLineRaw -Minimum 40
    $headerParsed = $headerLineRaw | ConvertFrom-Csv -Header $dummyHeaders
    $realHeaderNames = @($headerParsed.PSObject.Properties.Value | Where-Object { $null -ne $_ } | ForEach-Object { $_.Trim() })
    if ($realHeaderNames.Count -gt 0 -and $realHeaderNames[0] -eq "") {
        $realHeaderNames[0] = "RowNum"
    }

    $rows = $fileContent | ConvertFrom-Csv -Header $realHeaderNames | Select-Object -Skip 1

    # A renamed column doesn't error, it just reads as blank (= any) on
    # every rule. Say so loudly instead of producing a clean-looking report.
    $expectedColumns = @("Name", "Source Zone", "Source Address", "Destination Zone", "Destination Address", "Application", "Service", "Action")
    $missingColumns = @($expectedColumns | Where-Object { $realHeaderNames -notcontains $_ })
    if ($missingColumns.Count -gt 0) {
        Write-Host "ERROR: This CSV is missing expected column(s): $($missingColumns -join ', '). The parser expects the security rulebase export of PAN-OS 10, 11 or 12 (see README). If your PAN-OS/Panorama version uses different column names, results will be silently incomplete rather than erroring out. Compare this file's header row against the README's documented schema before trusting the report." -ForegroundColor Red
    }

    $hasDisabledColumn = $realHeaderNames -contains "Disabled"
    $hasOptionsColumn = $realHeaderNames -contains "Options"
    $hasCreatedColumn = $realHeaderNames -contains "Created"
    $hasModifiedColumn = $realHeaderNames -contains "Modified"

    # The wording changes between versions ("Rule Usage: Hit Count",
    # "Rule Usage Hit Count"...), so match on the substring.
    $hitCountColumnName = $realHeaderNames | Where-Object { $_ -match "Hit Count" } | Select-Object -First 1
    $hasHitCountColumn = $null -ne $hitCountColumnName

    $lastHitColumnName = $realHeaderNames | Where-Object { $_ -match "Last Hit" } | Select-Object -First 1
    $hasLastHitColumn = $null -ne $lastHitColumnName

    # The used/unused/partially used column has odd names ("Rule Usage Rule
    # Usage"), so find it by its values instead, looking at the first 50 rows.
    $usageStatusValues = @("used", "unused", "partially used")
    $usageStatusColumnName = $null
    $sampleRows = $rows | Select-Object -First 50
    foreach ($colName in $realHeaderNames) {
        if ($colName -in @("", "Name", "Location", "Tags", "Type")) { continue }
        $observed = @($sampleRows | ForEach-Object { $_.$colName } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() } | Select-Object -Unique)
        if ($observed.Count -gt 0 -and -not ($observed | Where-Object { $usageStatusValues -notcontains $_ })) {
            $usageStatusColumnName = $colName
            break
        }
    }
    $hasUsageStatusColumn = $null -ne $usageStatusColumnName

    $rules = @()
    $i = 0
    $namePrefixDisabledSeen = $false
    $seenNames = @{}
    $duplicateNamesSeen = $false
    $lastColumn = $realHeaderNames[$realHeaderNames.Count - 1]
    $shortRows = @()
    $blankActionRows = @()
    foreach ($row in $rows) {
        $rawName = $(if ($row.Name) { $row.Name } else { "rule_$i" })

        # Panorama 11 may have no Disabled column and put "[Disabled] " in
        # front of the name instead. Either signal disables the rule.
        $disabledFromNamePrefix = $rawName -match '^\[Disabled\]\s*'
        if ($disabledFromNamePrefix) { $namePrefixDisabledSeen = $true }
        $cleanName = $rawName -replace '^\[Disabled\]\s*', ''

        # The name is the rule's only identifier downstream, so a repeated
        # name gets a suffix here rather than mixing up two rules later.
        if ($seenNames.ContainsKey($cleanName)) {
            $seenNames[$cleanName]++
            $duplicateNamesSeen = $true
            $uniqueName = "$cleanName (duplicate name #$($seenNames[$cleanName]))"
        }
        else {
            $seenNames[$cleanName] = 1
            $uniqueName = $cleanName
        }

        # A row with fewer fields than the header gets $null in the missing
        # cells: read them as empty and say so, never drop the rule.
        if ($null -eq $row.$lastColumn) { $shortRows += $uniqueName }
        if (-not "$($row.Action)".Trim()) { $blankActionRows += $uniqueName }
        $disabledFromColumn = if ($hasDisabledColumn) { "$($row.Disabled)".Trim().ToLower() -eq "yes" } else { $false }

        $rules += [PSCustomObject]@{
            Index       = $i
            Name        = $uniqueName
            LocalName   = $(if ($row.Name) { $cleanName } else { "" })
            SrcZone     = Parse-ZoneField $row.'Source Zone'
            SrcAddrRaw  = $row.'Source Address'
            SrcAddr     = Parse-AddressField $row.'Source Address'
            DstZone     = Parse-ZoneField $row.'Destination Zone'
            DstAddrRaw  = $row.'Destination Address'
            DstAddr     = Parse-AddressField $row.'Destination Address'
            Application = Parse-ListField $row.Application
            ServiceRaw  = $row.Service
            Service     = Parse-ListField $row.Service
            Action      = $(if ($row.Action) { $row.Action.Trim().ToLower() } else { "allow" })
            Profile     = $(if ($row.Profile) { $row.Profile.Trim() } else { "" })
            Tags        = $(if ($row.Tags) { $row.Tags.Trim() } else { "" })
            Disabled    = $disabledFromColumn -or $disabledFromNamePrefix
            HitCount    = if ($hasHitCountColumn) { $row.$hitCountColumnName } else { "" }
            UsageStatus = if ($hasUsageStatusColumn -and $row.$usageStatusColumnName) { $row.$usageStatusColumnName.Trim().ToLower() } else { "" }
            LastHit     = if ($hasLastHitColumn) { $row.$lastHitColumnName } else { "" }
            Options     = if ($hasOptionsColumn) { $row.Options } else { "" }
            HasOptionsColumn = $hasOptionsColumn
            Created     = if ($hasCreatedColumn) { $row.Created } else { "" }
            Modified    = if ($hasModifiedColumn) { $row.Modified } else { "" }
            HasCreatedColumn = $hasCreatedColumn
            HasModifiedColumn = $hasModifiedColumn
        }
        $i++
    }

    if (-not $hasDisabledColumn -and $namePrefixDisabledSeen) {
        Write-Host "Note: no 'Disabled' column in this export, but a '[Disabled] ' prefix was found in the Name field. Using that instead (seen on Panorama 11 exports)." -ForegroundColor Yellow
    }
    elseif (-not $hasDisabledColumn) {
        Write-Host "Note: 'Disabled' column not present in this export. All rules treated as enabled." -ForegroundColor Yellow
    }
    if (-not $hasHitCountColumn) {
        Write-Host "Note: no column containing 'Hit Count' found in this export. The zero_hit_count check will never trigger." -ForegroundColor Yellow
    }
    else {
        Write-Host "Note: using '$hitCountColumnName' as the hit-count column." -ForegroundColor Yellow
    }
    if (-not $hasUsageStatusColumn) {
        Write-Host "Note: no used/unused/partially-used Rule Usage column detected in this export. The rule_usage_unused and rule_usage_partially_used checks will never trigger." -ForegroundColor Yellow
    }
    else {
        Write-Host "Note: using '$usageStatusColumnName' as the Rule Usage status column." -ForegroundColor Yellow
    }
    if (-not $hasLastHitColumn) {
        Write-Host "Note: no column containing 'Last Hit' found in this export. The stale_last_hit check will never trigger." -ForegroundColor Yellow
    }
    else {
        Write-Host "Note: using '$lastHitColumnName' as the last-hit column." -ForegroundColor Yellow
    }
    if ($duplicateNamesSeen) {
        Write-Host "Note: this export has multiple rules sharing the same Name. Duplicates were renamed with a '(duplicate name #N)' suffix so each rule's findings and report row are attributed correctly." -ForegroundColor Yellow
    }
    if ($shortRows.Count -gt 0) {
        Write-Host "WARNING: $($shortRows.Count) row(s) have fewer fields than the header; the missing cells were read as empty (e.g. $(($shortRows | Select-Object -First 5) -join ', ')). Check the export for truncated lines." -ForegroundColor Yellow
    }
    if ($blankActionRows.Count -gt 0) {
        Write-Host "WARNING: $($blankActionRows.Count) rule(s) have an empty Action and were analyzed as allow (e.g. $(($blankActionRows | Select-Object -First 5) -join ', '))." -ForegroundColor Yellow
    }

    return $rules
}

# --------------------------------------------------------------------------
# Address object / group resolution (optional, only if the CSVs are given)
# --------------------------------------------------------------------------
#
# Objects CSV: Name, Location, Type, Address, Tags
# Groups CSV:  Name, Location, Members Count, Addresses, Tags
# Groups have no Type column, so a dynamic group just doesn't resolve and
# stays an opaque name. Members Count is only a cross-check on the ";" split.

function Read-HeaderFixedCsv {
    # Same blank-first-column fix as Import-PaloAltoRules.
    param([string]$Path)
    $fileContent = Get-CsvFileContent -Path $Path
    $fileLines = $fileContent -split "`r?`n"

    $headerLineRaw = $fileLines[0]
    $dummyHeaders = Get-DummyCsvHeaders -HeaderLine $headerLineRaw -Minimum 20
    $headerParsed = $headerLineRaw | ConvertFrom-Csv -Header $dummyHeaders
    $realHeaderNames = @($headerParsed.PSObject.Properties.Value | Where-Object { $null -ne $_ } | ForEach-Object { $_.Trim() })
    # Empty file: ConvertFrom-Csv won't take an empty -Header.
    if ($realHeaderNames.Count -eq 0) { return @() }
    if ($realHeaderNames[0] -eq "") {
        $realHeaderNames[0] = "RowNum"
    }
    return $fileContent | ConvertFrom-Csv -Header $realHeaderNames | Select-Object -Skip 1
}

function Import-AddressObjects {
    param([string]$Path)
    $objects = @{}
    if (-not $Path -or -not (Test-Path $Path)) { return $objects }

    foreach ($row in (Read-HeaderFixedCsv -Path $Path)) {
        if (-not $row.Name) { continue }
        $valueField = $(if ($row.Address) { $row.Address } elseif ($row.Value) { $row.Value } else { "" })
        $objects[$row.Name.Trim().ToLower()] = [PSCustomObject]@{
            Name  = $row.Name.Trim()
            Type  = $(if ($row.Type) { $row.Type.Trim().ToLower() } else { "" })
            Value = $valueField.Trim()
        }
    }
    return $objects
}

function Import-AddressGroups {
    param([string]$Path)
    $groups = @{}
    if (-not $Path -or -not (Test-Path $Path)) { return $groups }

    foreach ($row in (Read-HeaderFixedCsv -Path $Path)) {
        if (-not $row.Name) { continue }
        $memberField = $(if ($row.Addresses) { $row.Addresses } elseif ($row.Address) { $row.Address } elseif ($row.Members) { $row.Members } else { "" })
        $members = @()
        if ($memberField) {
            $members = @($memberField -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        }
        $groups[$row.Name.Trim().ToLower()] = [PSCustomObject]@{
            Name      = $row.Name.Trim()
            IsDynamic = $false
            Members   = $members
        }

        if ($row.'Members Count' -and $row.'Members Count' -match '^\d+$') {
            $expectedCount = [int]$row.'Members Count'
            if ($members.Count -ne $expectedCount) {
                Write-Host "Note: group '$($row.Name)' declares $expectedCount member(s) but $($members.Count) were extracted from the Addresses field. Check the separator used in your export." -ForegroundColor Yellow
            }
        }
    }
    return $groups
}

function Resolve-AddressToken {
    # Object or group name -> its IPs, CIDRs or ranges, recursively. Names
    # we can't turn into IPv4 (fqdn, wildcard, unknown) stay labeled tokens.
    param(
        [string]$Token,
        [hashtable]$Objects,
        [hashtable]$Groups,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    if (Test-IsPlainIP $Token) { return @($Token) }

    $key = $Token.Trim().ToLower()
    if ($Visited.Contains($key)) { return @($Token) }  # circular-reference guard
    [void]$Visited.Add($key)

    if ($Objects.ContainsKey($key)) {
        $obj = $Objects[$key]
        # "ip-netmask" vs "IP Netmask" depending on the export.
        $normalizedType = ($obj.Type -replace '\s+', '-').ToLower()
        if ($normalizedType -eq "ip-netmask" -and (Test-IsPlainIP $obj.Value)) {
            return @($obj.Value)
        }
        # A range object becomes "a-b", same as a range typed in the rule.
        if ($normalizedType -eq "ip-range" -and (Test-IsIpRange $obj.Value.Trim())) {
            return @($obj.Value.Trim())
        }
        return @("$($obj.Name)[$($obj.Type)]=$($obj.Value)")
    }

    if ($Groups.ContainsKey($key)) {
        $grp = $Groups[$key]
        if ($grp.IsDynamic) {
            return @("$($grp.Name)[dynamic-group,unresolved]")
        }
        $resolved = @()
        foreach ($member in $grp.Members) {
            $resolved += Resolve-AddressToken -Token $member -Objects $Objects -Groups $Groups -Visited $Visited
        }
        # An empty group matches nothing; an empty list would read as any.
        if ($resolved.Count -eq 0) { return @("$($grp.Name)[empty-group]") }
        return $resolved
    }

    return @($Token)
}

function Resolve-AddressList {
    param($AddrTokens, [hashtable]$Objects, [hashtable]$Groups)
    if ($null -eq $AddrTokens) { return $null }
    if ($Objects.Count -eq 0 -and $Groups.Count -eq 0) { return $AddrTokens }

    $resolved = @()
    foreach ($tok in $AddrTokens) {
        $visited = [System.Collections.Generic.HashSet[string]]::new()
        # "[Negate] NAME": resolve the name, keep the prefix on each member.
        if ($tok -match '^\[Negate\]\s*(.+)$') {
            foreach ($m in (Resolve-AddressToken -Token $Matches[1].Trim() -Objects $Objects -Groups $Groups -Visited $visited)) { $resolved += "[Negate] $m" }
            continue
        }
        $resolved += Resolve-AddressToken -Token $tok -Objects $Objects -Groups $Groups -Visited $visited
    }
    return @($resolved | Select-Object -Unique)
}

