# --------------------------------------------------------------------------
# CSV / field parsing (rules, address objects, address groups)
# --------------------------------------------------------------------------

function Parse-ZoneField {
    # Zones can be multi-valued in real exports (e.g. "outside;zone-to-hub").
    # The documented/most commonly confirmed separator is ";", but at least
    # one real row has been seen using "," instead for this same field
    # (e.g. "outside,voip") - possibly a different export tool/version, or
    # inconsistent hand-editing. Splitting on either avoids silently
    # treating "outside,voip" as one bogus zone name that matches nothing.
    # Returns an array of zone name strings. Never returns $null; "any" is used if blank.
    param([string]$Field)
    $Field = $Field.Trim()
    if ($Field -eq "") { return @("any") }
    $vals = @($Field -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
    if ($vals.Count -eq 0) { return @("any") }
    return $vals
}

function Parse-AddressField {
    # Multi-value separator is normally ";" (not ",", since "," is the CSV
    # delimiter), but at least one real row has been seen using "," for a
    # different multi-value field (Service) instead, so both are accepted
    # here too, for consistency and safety, rather than assuming this field
    # is immune to the same inconsistency.
    # IP ranges, "[Negate] ..." entries, and address-object names are kept
    # as opaque tokens (exact-match only). Only plain CIDR/IP gets real
    # containment logic.
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
    # Same dual-separator reasoning as Parse-ZoneField/Parse-AddressField
    # above: a real row has been seen with Service values comma-separated
    # ("tcp-5444,udp-53") instead of the more commonly confirmed ";".
    # Splitting on either avoids silently treating the whole string as one
    # unrecognized token, which would make every port in it invisible to
    # the risky-port checks.
    param([string]$Field)
    $Field = $Field.Trim()
    if ($Field -eq "" -or $Field.ToLower() -eq "any") { return $null }
    return @($Field -split '[;,]' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" })
}

function Get-ServicePorts {
    # PAN-OS represents a port two different ways depending on context: the
    # raw "tcp/23" protocol/port syntax, or a named custom Service object
    # following the common "tcp-23" / "udp-23" naming convention (the name
    # itself encodes the port). Both are matched here so a rule using a
    # named service object like "tcp-23" is checked the same as one using
    # "tcp/23" directly. Anchored to a tcp/udp prefix specifically, rather
    # than any name ending in "-<number>", so an unrelated custom object
    # name that happens to end in digits isn't misread as a port.
    param($ServiceTokens)
    $ports = @()
    if (-not $ServiceTokens) { return $ports }
    foreach ($tok in $ServiceTokens) {
        if ($tok -match '(?i)^(tcp|udp)[/-](\d+)$') { $ports += [int]$Matches[2] }
    }
    return $ports
}

function Repair-DoubleWrappedCsvLine {
    # Some real PAN-OS/Panorama exports wrap the ENTIRE CSV line in an
    # extra outer pair of quotes, doubling every original quote character
    # in the process (seen across a Panorama 11.1 export and direct
    # firewall PAN-OS 10/11.1 exports, so this looks tied to export method
    # rather than PAN-OS version specifically). A standards-compliant CSV
    # parser reads such a line as ONE giant field instead of the intended
    # columns, so this needs undoing before normal parsing.
    param([string]$Line)
    if (-not $Line.StartsWith('"')) { return $Line }
    $trimmed = $Line
    if ($trimmed.StartsWith('"')) { $trimmed = $trimmed.Substring(1) }
    if ($trimmed.Length -gt 0 -and $trimmed.EndsWith('"')) { $trimmed = $trimmed.Substring(0, $trimmed.Length - 1) }
    return ($trimmed -replace '""', '"')
}

function Get-CsvFileContent {
    # Reads a CSV file's full text, strips the UTF-8 BOM if present, and
    # transparently repairs the double-quote-wrapping issue above when
    # detected on the first line (its signature: starting with '",', the
    # same "blank leading column" pattern already expected, just wrapped
    # in one more layer of quoting).
    param([string]$Path)
    $rawContent = (Get-Content -Path $Path -Raw) -replace [char]0xFEFF, ''
    $lines = $rawContent -split "`r?`n"
    if ($lines.Count -gt 0 -and $lines[0].StartsWith('",')) {
        $lines = $lines | ForEach-Object { Repair-DoubleWrappedCsvLine -Line $_ }
    }
    return ($lines -join "`r`n")
}

function Import-PaloAltoRules {
    param([string]$Path)

    # PAN-OS exports often have an unnamed leading row-number column.
    # Import-Csv's header auto-detection falls back to H1/H2/H3... for ALL
    # columns when it hits a blank header, misaligning every named property.
    # Read and repair the header explicitly: parse the header line as a data
    # row with dummy column names, recover the real header text, patch the
    # blank first entry, then re-parse using that fixed header list
    # (skipping the original header row since we supply our own).
    $fileContent = Get-CsvFileContent -Path $Path
    $fileLines = $fileContent -split "`r?`n"

    $dummyHeaders = 1..40 | ForEach-Object { "Col$_" }
    $headerLineRaw = $fileLines[0]
    $headerParsed = $headerLineRaw | ConvertFrom-Csv -Header $dummyHeaders
    $realHeaderNames = @($headerParsed.PSObject.Properties.Value | Where-Object { $null -ne $_ } | ForEach-Object { $_.Trim() })
    if ($realHeaderNames.Count -gt 0 -and $realHeaderNames[0] -eq "") {
        $realHeaderNames[0] = "RowNum"
    }

    $rows = $fileContent | ConvertFrom-Csv -Header $realHeaderNames | Select-Object -Skip 1

    # If a different PAN-OS/Panorama version (or export type) uses different
    # column names, a property lookup like $row.'Source Address' returns
    # $null WITHOUT erroring. The script would keep running and silently
    # treat that field as blank/any for every rule, producing a report that
    # looks complete but is built on wrong data. Warn loudly here instead,
    # so a schema mismatch is obvious immediately rather than discovered
    # later from a suspiciously "clean" report.
    $expectedColumns = @("Name", "Source Zone", "Source Address", "Destination Zone", "Destination Address", "Application", "Service", "Action")
    $missingColumns = @($expectedColumns | Where-Object { $realHeaderNames -notcontains $_ })
    if ($missingColumns.Count -gt 0) {
        Write-Host "ERROR: This CSV is missing expected column(s): $($missingColumns -join ', '). This script's parser was built against one real PAN-OS export (see README). If your PAN-OS/Panorama version uses different column names, results will be silently incomplete rather than erroring out. Compare this file's header row against the README's documented schema before trusting the report." -ForegroundColor Red
    }

    $hasDisabledColumn = $realHeaderNames -contains "Disabled"
    $hasOptionsColumn = $realHeaderNames -contains "Options"

    # Match by substring rather than the exact "Rule Usage: Hit Count" -
    # different PAN-OS/Panorama versions and export types have been seen to
    # word this differently (with or without the colon, different prefix).
    # Whichever real column contains "Hit Count" is used, so this doesn't
    # need to be re-taught the exact wording per version.
    $hitCountColumnName = $realHeaderNames | Where-Object { $_ -match "Hit Count" } | Select-Object -First 1
    $hasHitCountColumn = $null -ne $hitCountColumnName

    # Same reasoning as Hit Count above: match by substring so exact
    # wording differences across exports don't matter.
    $lastHitColumnName = $realHeaderNames | Where-Object { $_ -match "Last Hit" } | Select-Object -First 1
    $hasLastHitColumn = $null -ne $lastHitColumnName

    # The Rule Usage status column (used/unused/partially used, see
    # https://docs.paloaltonetworks.com/ngfw/administration/monitoring/view-policy-rule-usage)
    # has been seen with an unpredictable, even duplicated, header name
    # ("Rule Usage Rule Usage" in one real export). Rather than guess yet
    # another exact string, detect it by its DATA: whichever column's
    # observed values are entirely drawn from that fixed 3-value set is the
    # one, regardless of what it's named. Sampling the first 50 rows keeps
    # this cheap on large rulesets.
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
    foreach ($row in $rows) {
        $rawName = $(if ($row.Name) { $row.Name } else { "rule_$i" })

        # Some real Panorama exports (seen on version 11) don't have a
        # separate Disabled column at all. Instead the Name field itself is
        # prefixed with "[Disabled] " for disabled rules. Detected here as
        # an independent signal, combined with the column-based one below,
        # since either could be present depending on export type/version.
        $disabledFromNamePrefix = $rawName -match '^\[Disabled\]\s*'
        if ($disabledFromNamePrefix) { $namePrefixDisabledSeen = $true }
        $cleanName = $rawName -replace '^\[Disabled\]\s*', ''

        # Rule names are used as the sole identifier everywhere downstream:
        # a finding stores RuleName (not a rule ID), the report table looks
        # up Source/Destination/Action/Profile by name, and shadow/duplicate
        # findings reference "earlier rule 'X'" by name. If two rules
        # genuinely share a name, every one of those becomes ambiguous - a
        # finding for one rule could display with the other's fields. Fixed
        # at the source here, once, rather than in each of those places
        # separately: a repeated name gets a disambiguating suffix, so every
        # later reference is automatically unique and correctly attributed.
        if ($seenNames.ContainsKey($cleanName)) {
            $seenNames[$cleanName]++
            $duplicateNamesSeen = $true
            $uniqueName = "$cleanName (duplicate name #$($seenNames[$cleanName]))"
        }
        else {
            $seenNames[$cleanName] = 1
            $uniqueName = $cleanName
        }

        $disabledFromColumn = if ($hasDisabledColumn) { $row.Disabled.Trim().ToLower() -eq "yes" } else { $false }

        $rules += [PSCustomObject]@{
            Index       = $i
            Name        = $uniqueName
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

    return $rules
}

# --------------------------------------------------------------------------
# Address object / group resolution (optional, only if the CSVs are given)
# --------------------------------------------------------------------------
#
# Schema below is confirmed against real exports.
#
#   Address Objects CSV: Name, Location, Type, Address, Tags
#     * Type: ip-netmask | ip-range | fqdn | ip-wildcard
#     * Address: the actual value (10.1.2.0/24, an IP range, or a hostname)
#
#   Address Groups CSV: Name, Location, Members Count, Addresses, Tags
#     * No "Type" column is present in this export, so static vs. dynamic
#       cannot be determined directly. Dynamic groups (tag-match
#       expressions) are handled gracefully anyway: their "Addresses" value
#       won't match any known object/group name, so it just falls through
#       to the existing "unknown name, stays opaque" behavior below. No
#       explicit Type check needed.
#     * "Addresses": member object/group names, ";"-separated (same
#       convention as multi-value fields elsewhere in these exports)
#     * "Members Count" is used as a cross-check only: if the number of
#       resolved members doesn't match this count, a warning is printed.
#       This is the most likely sign that the real separator differs from
#       ";" for your PAN-OS version.
#
# If your export uses different column names, this is the first place to fix.

function Read-HeaderFixedCsv {
    # Shared helper: repairs the same "blank leading column" issue handled
    # in Import-PaloAltoRules, reused here for the objects/groups exports.
    param([string]$Path)
    $fileContent = Get-CsvFileContent -Path $Path
    $fileLines = $fileContent -split "`r?`n"

    $dummyHeaders = 1..20 | ForEach-Object { "Col$_" }
    $headerLineRaw = $fileLines[0]
    $headerParsed = $headerLineRaw | ConvertFrom-Csv -Header $dummyHeaders
    $realHeaderNames = @($headerParsed.PSObject.Properties.Value | Where-Object { $null -ne $_ } | ForEach-Object { $_.Trim() })
    if ($realHeaderNames.Count -gt 0 -and $realHeaderNames[0] -eq "") {
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
        # Real exports use "Addresses" (plural) and have no "Type" column at
        # all. Static vs. dynamic can't be determined directly, so we don't
        # try; see the module-level note above for why that's fine.
        $memberField = $(if ($row.Addresses) { $row.Addresses } elseif ($row.Address) { $row.Address } elseif ($row.Members) { $row.Members } else { "" })
        $members = @()
        if ($memberField) {
            $members = @($memberField -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
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
    # Recursively resolves an address-object or (static) address-group name
    # to its real member IP(s)/CIDR(s). Plain IPs pass through unchanged.
    # Unknown names, FQDNs, IP ranges, and dynamic groups stay as opaque
    # (clearly labeled) tokens, exact-match only downstream, same as before.
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
        if ($obj.Type -eq "ip-netmask" -and (Test-IsPlainIP $obj.Value)) {
            return @($obj.Value)
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
        $resolved += Resolve-AddressToken -Token $tok -Objects $Objects -Groups $Groups -Visited $visited
    }
    return @($resolved | Select-Object -Unique)
}
