# --------------------------------------------------------------------------
# Report rendering (Markdown/HTML) and the optional Gemini AI summary
# --------------------------------------------------------------------------

function Protect-IPAddresses {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][System.Collections.Hashtable]$Map
    )
    $pattern = '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?'
    $found = [regex]::Matches($Text, $pattern) | ForEach-Object { $_.Value } | Select-Object -Unique
    foreach ($ip in $found) {
        if (-not $Map.ContainsKey($ip)) {
            $Map[$ip] = "IP-MASKED-$($Map.Count + 1)"
        }
    }
    $result = $Text
    foreach ($ip in $found) {
        $result = $result -replace [regex]::Escape($ip), $Map[$ip]
    }
    return $result
}

# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------

$SeverityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }

function Get-SvgPieChart {
    # Dependency-free donut chart: plain SVG.
    param([string[]]$Labels, [int[]]$Values, [string[]]$Colors, [int]$Size = 130, [string]$CenterLabel = "")

    $total = ($Values | Measure-Object -Sum).Sum
    if ($total -le 0) { return "<p style='color:#888;font-size:12px;'>No data.</p>" }

    $cx = $Size / 2
    $cy = $Size / 2
    $strokeWidth = [Math]::Round($Size * 0.13, 1)
    $r = ($Size / 2) - ($strokeWidth / 2) - 1
    $circumference = [Math]::Round(2 * [Math]::PI * $r, 2)

    $rings = "<circle cx='$cx' cy='$cy' r='$r' fill='none' stroke='#ECE9E4' stroke-width='$strokeWidth' />"
    $legend = ""
    $cumulative = 0
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $value = $Values[$i]
        if ($value -le 0) { continue }
        $color = $Colors[$i]
        $segLen = [Math]::Round(($value / $total) * $circumference, 2)
        $offset = [Math]::Round(-1 * $cumulative, 2)
        $rings += "<circle cx='$cx' cy='$cy' r='$r' fill='none' stroke='$color' stroke-width='$strokeWidth' stroke-dasharray='$segLen $circumference' stroke-dashoffset='$offset' />"
        $cumulative += $segLen
        $pct = [Math]::Round(($value / $total) * 100, 1)
        $legend += "<div class='pie-legend-item'><span class='pie-legend-swatch' style='background:$color'></span>$($Labels[$i]) ($value, $pct%)</div>"
    }
    # Rotated so the first segment starts at 12 o'clock instead of 3
    # o'clock, matching where a reader's eye naturally lands first.
    $donut = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size'><g transform='rotate(-90 $cx $cy)'>$rings</g><text x='$cx' y='$($cy - 2)' text-anchor='middle' font-size='20' font-weight='600' fill='#2B2A28'>$total</text><text x='$cx' y='$($cy + 14)' text-anchor='middle' font-size='9' fill='#6B655C'>$CenterLabel</text></svg>"
    return "<div class='pie-chart-wrap'>$donut<div class='pie-legend'>$legend</div></div>"
}

function Import-PreviousFindings {
    # Reads a findings CSV from a prior MooseAlto run for -CompareTo.
    # Deliberately tolerant of a different/older schema: an export from an
    # earlier MooseAlto version won't have every column this version does,
    # and that's fine here, since only Rule/Type/Severity are actually
    # used for comparison. Returns $null (not an error) on anything that
    # goes wrong reading the file, so the caller can skip the comparison
    # section cleanly rather than letting a bad path crash the whole run.
    param([string]$Path)
    if (-not $Path) { return $null }
    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        Write-Host "Note: -CompareTo file not found ($Path). Skipping comparison." -ForegroundColor Yellow
        return $null
    }
    try {
        $rows = Import-Csv -Path $Path
    }
    catch {
        Write-Host "Note: -CompareTo file couldn't be read as CSV ($Path). Skipping comparison." -ForegroundColor Yellow
        return $null
    }
    if (-not $rows -or -not ($rows | Get-Member -Name "Rule" -MemberType NoteProperty) -or -not ($rows | Get-Member -Name "Type" -MemberType NoteProperty)) {
        Write-Host "Note: -CompareTo file doesn't look like a MooseAlto findings CSV (missing Rule/Type columns). Skipping comparison." -ForegroundColor Yellow
        return $null
    }
    return @($rows)
}

function Get-FindingsComparison {
    # Matches findings between runs by (Rule name, Type) - the simplest
    # key that works without needing the previous run's underlying rule
    # data, only its findings CSV. The real limitation: renaming a rule
    # between runs makes its findings look "resolved" in the old name and
    # "new" in the new name, even though nothing about the underlying
    # issue changed. Matching on rule content (zone/address/app) instead
    # of name would handle that, but also raises its own ambiguity when
    # content legitimately changes between runs, so this starts with the
    # simpler name-based key and that known tradeoff stated plainly rather
    # than guessing at a fuzzier match.
    param([array]$CurrentFindings, [array]$PreviousFindings)

    $previousKeys = @{}
    foreach ($p in $PreviousFindings) {
        $key = "$($p.Rule)|$($p.Type)"
        $previousKeys[$key] = $p
    }

    $currentKeys = @{}
    foreach ($f in $CurrentFindings) {
        $key = "$($f.RuleName)|$($f.Type)"
        $currentKeys[$key] = $f
    }

    $newFindings = @()
    $persistentFindings = @()
    foreach ($key in $currentKeys.Keys) {
        if ($previousKeys.ContainsKey($key)) { $persistentFindings += $currentKeys[$key] }
        else { $newFindings += $currentKeys[$key] }
    }

    $resolvedFindings = @()
    foreach ($key in $previousKeys.Keys) {
        if (-not $currentKeys.ContainsKey($key)) { $resolvedFindings += $previousKeys[$key] }
    }

    return [PSCustomObject]@{
        New        = @($newFindings | Sort-Object { $SeverityOrder[$_.Severity] })
        Resolved   = @($resolvedFindings | Sort-Object { $SeverityOrder[$_.Severity] })
        Persistent = @($persistentFindings | Sort-Object { $SeverityOrder[$_.Severity] })
    }
}

function Get-ReportLines {
    param([array]$Findings, [array]$Inventory, [string]$InputCsvPath, [array]$Rules, [string]$ElapsedText = "", [array]$InternetZoneSet = @(), [string]$CompareToPath = "", [string]$AddressObjectsCsvPath = "", [string]$AddressGroupsCsvPath = "", [array]$CriticalZoneSet = @(), [int]$StaleHitDays = 365, [int]$MaxAddressListSize = 25, [switch]$SkipLLM)

    # Look up Source/Destination/Action/Profile by rule name at render time,
    # rather than attaching them to every finding at creation. This avoids
    # touching the ~25 places in DetectionRules.ps1 that build a finding.
    $ruleLookup = @{}
    foreach ($r in $Rules) {
        $ruleLookup[$r.Name] = [PSCustomObject]@{
            Src         = "$($r.SrcZone -join ';') / $($r.SrcAddrRaw)"
            Dst         = "$($r.DstZone -join ';') / $($r.DstAddrRaw)"
            Application = if ($r.Application) { $r.Application -join "," } else { "any" }
            Service     = $r.ServiceRaw
            Action      = $r.Action
            Profile     = if ($r.Profile) { $r.Profile } else { "none" }
            Created     = $r.Created
            Modified    = $r.Modified
        }
    }

    # Created/Modified are shown as extra columns only when the export
    # actually has them - most don't, and an empty column on every single
    # row would just be noise.
    $showCreatedModified = @($Rules | Where-Object { $_.HasCreatedColumn -or $_.HasModifiedColumn }).Count -gt 0

    # The any_any_any_allow finding itself is the broadest possible rule in
    # the ruleset. Pin just that row to the top, not every other finding
    # for the same rule (those still sort by severity normally).
    $anyAnyAnyRuleNames = @($Findings | Where-Object { $_.Type -eq "any_any_any_allow" } | Select-Object -ExpandProperty RuleName -Unique)

    $sorted = $Findings | Sort-Object { $SeverityOrder[$_.Severity] }
    $pinned = @($sorted | Where-Object { $_.Type -eq "any_any_any_allow" })
    $rest = @($sorted | Where-Object { $_.Type -ne "any_any_any_allow" })
    $sorted = $pinned + $rest

    $lines = @("# MooseAlto: Palo Alto Firewall Rule Hygiene Report", "")
    $lines += "**Input file:** $InputCsvPath  "
    $lines += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')  "
    if ($ElapsedText) {
        $lines += "**Processing time:** $ElapsedText  "
    }

    # Only non-default/actually-supplied run settings show up here, not
    # every parameter with its default value - the point is telling the
    # reader what made THIS run different from a plain default run, not
    # repeating the full parameter list.
    $runInfoLines = @()
    if ($AddressObjectsCsvPath) { $runInfoLines += "**Address objects:** $AddressObjectsCsvPath  " }
    if ($AddressGroupsCsvPath) { $runInfoLines += "**Address groups:** $AddressGroupsCsvPath  " }
    if ($CriticalZoneSet.Count -gt 0) { $runInfoLines += "**Critical zones:** $($CriticalZoneSet -join ', ')  " }
    if ($InternetZoneSet.Count -gt 0 -and ($InternetZoneSet -join ',') -ne "untrust,internet,outside,external") {
        $runInfoLines += "**Internet-facing zones:** $($InternetZoneSet -join ', ')  "
    }
    if ($StaleHitDays -ne 365) { $runInfoLines += "**Stale threshold:** $StaleHitDays days  " }
    if ($MaxAddressListSize -ne 25) { $runInfoLines += "**Max address list size:** $MaxAddressListSize  " }
    if ($SkipLLM) { $runInfoLines += "**AI analysis:** skipped (-SkipLLM)  " }
    $lines += $runInfoLines
    $lines += ""

    $critCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $lines += "## Summary"
    $lines += ""
    $lines += "| Metric | Value |"
    $lines += "|---|---|"
    $lines += "| Rules analyzed | $($Rules.Count) |"
    $lines += "| Total findings | $($Findings.Count) |"
    $lines += "| Critical | $critCount |"
    $lines += "| High | $highCount |"
    $lines += "| Medium | $medCount |"
    $lines += "| Low | $lowCount |"
    $lines += ""

    # -------- Rule Statistics --------
    # A quick visual overview before the detailed findings table: how the
    # ruleset breaks down by action, direction, and profile coverage, plus
    # where the findings severity actually lands. Uses the same
    # zone/address "touches internet" signals as the algorithmic checks,
    # but a simpler direction classification than the Inventory's.
    $enabledRules = @($Rules | Where-Object { -not $_.Disabled })
    $disabledCount = @($Rules | Where-Object { $_.Disabled }).Count
    $allowRules = @($enabledRules | Where-Object { $_.Action -eq "allow" })
    $denyDropCount = @($enabledRules | Where-Object { $_.Action -eq "deny" -or $_.Action -eq "drop" }).Count
    $noProfileCount = @($allowRules | Where-Object { $_.Profile.ToLower() -eq "" -or $_.Profile.ToLower() -eq "none" }).Count
    $permissiveCount = @($allowRules | Where-Object { $null -eq $_.Application -and ($null -eq $_.SrcAddr -or $null -eq $_.DstAddr) }).Count

    $inboundCount = 0; $outboundCount = 0; $bothCount = 0; $internalCount = 0
    foreach ($r in $allowRules) {
        $srcInet = (Test-ZoneTouchesInternet -Zones $r.SrcZone -InternetZoneSet $InternetZoneSet) -or (Test-AddressTouchesInternet -AddrTokens $r.SrcAddr)
        $dstInet = (Test-ZoneTouchesInternet -Zones $r.DstZone -InternetZoneSet $InternetZoneSet) -or (Test-AddressTouchesInternet -AddrTokens $r.DstAddr)
        if ($srcInet -and $dstInet) { $bothCount++ }
        elseif ($srcInet) { $inboundCount++ }
        elseif ($dstInet) { $outboundCount++ }
        else { $internalCount++ }
    }

    $appFrequency = @{}
    foreach ($r in $allowRules) {
        if ($null -eq $r.Application) { continue }
        foreach ($app in $r.Application) {
            if (-not $appFrequency.ContainsKey($app)) { $appFrequency[$app] = 0 }
            $appFrequency[$app]++
        }
    }
    $topApps = $appFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Rules with Application left as "any" but a specific Service/port are
    # completely invisible in the applications table above (they have no
    # App-ID at all, that's the whole point of port_based_rule_missing_app_id).
    # A large chunk of a legacy ruleset can be exactly this pattern, so it
    # deserves its own visibility rather than silently not showing up
    # anywhere in the statistics.
    $serviceFrequency = @{}
    foreach ($r in $allowRules) {
        if ($null -ne $r.Application -or $null -eq $r.Service) { continue }
        foreach ($svc in $r.Service) {
            # "application-default" without an App-ID isn't a concrete port,
            # it just means no port restriction either, so it belongs with
            # the fully-open-rule stats above, not a "which ports are being
            # used instead of App-ID" table.
            if ($svc -eq "application-default") { continue }
            if (-not $serviceFrequency.ContainsKey($svc)) { $serviceFrequency[$svc] = 0 }
            $serviceFrequency[$svc]++
        }
    }
    $topServices = $serviceFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Which check types fire most often, across the whole findings list
    # (not scoped to allow rules only, unlike the app/service stats above -
    # a finding is a finding regardless of the rule's action). Tells you
    # AT A GLANCE whether the ruleset has one systemic problem repeated
    # many times (e.g. most High findings are all
    # no_security_profile_on_exposed_rule) versus many different distinct
    # issues, which severity counts alone don't distinguish.
    $typeFrequency = @{}
    foreach ($f in $Findings) {
        if (-not $typeFrequency.ContainsKey($f.Type)) { $typeFrequency[$f.Type] = 0 }
        $typeFrequency[$f.Type]++
    }
    $topTypes = $typeFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Which specific rules generate the most findings, so review effort
    # can start with the rule causing the most noise rather than scanning
    # the whole table for repeat offenders.
    $ruleFrequency = @{}
    foreach ($f in $Findings) {
        if ($f.RuleName -eq "(ruleset-wide)") { continue }
        if (-not $ruleFrequency.ContainsKey($f.RuleName)) { $ruleFrequency[$f.RuleName] = 0 }
        $ruleFrequency[$f.RuleName]++
    }
    $topRulesByFindings = $ruleFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Tags follow the same multi-value convention as addresses/services
    # elsewhere in this file (";" normally, "," seen on at least one real
    # export), so split the same way rather than counting the whole
    # field as one tag.
    $tagFrequency = @{}
    $noTagCount = 0
    foreach ($r in $Rules) {
        if (-not $r.Tags -or $r.Tags.Trim() -eq "" -or $r.Tags.Trim().ToLower() -eq "none") {
            $noTagCount++
            continue
        }
        foreach ($tag in ($r.Tags -split '[;,]')) {
            $tagTrimmed = $tag.Trim()
            if ($tagTrimmed -eq "") { continue }
            if (-not $tagFrequency.ContainsKey($tagTrimmed)) { $tagFrequency[$tagTrimmed] = 0 }
            $tagFrequency[$tagTrimmed]++
        }
    }
    $topTags = $tagFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # App-ID vs port-based split: a quick indicator of how modernized the
    # ruleset's matching is. Three-way rather than two-way, since "neither
    # restricts anything" (any/any) is a meaningfully different case from
    # "restricted, but by port instead of App-ID" - collapsing them would
    # overstate how port-based the ruleset actually is.
    $appIdBasedCount = @($allowRules | Where-Object { $null -ne $_.Application }).Count
    $portBasedCount = @($allowRules | Where-Object { $null -eq $_.Application -and $_.Service -and ($_.Service -notcontains "application-default") }).Count
    $fullyOpenBothCount = $allowRules.Count - $appIdBasedCount - $portBasedCount

    $lines += "## Rule Statistics"
    $lines += ""

    $statCardsHtml = "<div class='stat-grid'>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$($Rules.Count)</div><div class='stat-label'>Total rules</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$($enabledRules.Count)</div><div class='stat-label'>Enabled</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$disabledCount</div><div class='stat-label'>Disabled</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$($allowRules.Count)</div><div class='stat-label'>Allow</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$denyDropCount</div><div class='stat-label'>Deny / drop</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$permissiveCount</div><div class='stat-label'>Permissive allow rules</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$noProfileCount</div><div class='stat-label'>Allow rules, no profile</div></div>"
    $statCardsHtml += "<div class='stat-card'><div class='stat-value'>$noTagCount</div><div class='stat-label'>Rules with no tags</div></div>"
    $statCardsHtml += "</div>"

    $severityPie = Get-SvgPieChart -Labels @("Critical", "High", "Medium", "Low") -Values @($critCount, $highCount, $medCount, $lowCount) -Colors @("#B33A3A", "#C1793A", "#D4A017", "#ADA79C") -CenterLabel "findings"
    $directionPie = Get-SvgPieChart -Labels @("Inbound", "Outbound", "Both sides", "Internal only") -Values @($inboundCount, $outboundCount, $bothCount, $internalCount) -Colors @("#A6720F", "#6B8F5E", "#8A6BAE", "#ADA79C") -CenterLabel "allow rules"
    $appIdPie = Get-SvgPieChart -Labels @("App-ID based", "Port-based (no App-ID)", "Fully open (any/any)") -Values @($appIdBasedCount, $portBasedCount, $fullyOpenBothCount) -Colors @("#A6720F", "#C1793A", "#B33A3A") -CenterLabel "allow rules"

    # Small hand-drawn inline icons (shield / exchange / lock), not an
    # icon font: MooseAlto's whole pitch is "no network calls unless you
    # opt into the Gemini step," so a webfont/CDN icon set would
    # contradict that even for something this cosmetic.
    $iconShield = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><path d='M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z'/></svg>"
    $iconExchange = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><path d='M7 3l4 4-4 4M3 7h8M17 21l-4-4 4-4M21 17h-8'/></svg>"
    $iconLock = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><rect x='4' y='11' width='16' height='9' rx='1'/><path d='M8 11V7a4 4 0 018 0v4'/></svg>"

    # All three pies together in one row rather than splitting the
    # App-ID/port one off into its own row further down: three distribution
    # charts belong next to each other, and a lone chart in its own
    # full-width row was wasting most of that row's horizontal space.
    $chartsHtml = "<div class='chart-row'>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconShield}Findings by severity</div>$severityPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconExchange}Allow rules by direction</div>$directionPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconLock}Allow rules: App-ID vs port-based matching</div>$appIdPie</div>"
    $chartsHtml += "</div>"

    # Each of these is its own self-contained block, built independently
    # and only if it actually has data. Rather than hard-pairing specific
    # ones together (which breaks visually whenever one side happens to be
    # empty on a given ruleset, leaving its partner stranded alone with
    # empty space next to it), they're collected into one list and packed
    # two-per-row in whatever order they come, so a report is never left
    # with an orphaned single table next to blank space unless there's
    # truly an odd number of blocks with data.
    $tableBlocks = New-Object System.Collections.Generic.List[string]

    if ($topApps) {
        $html = "<div><div class='pie-chart-title'>Most common applications (allow rules)</div><div class='table-wrap'><table><tr><th>Application</th><th>Rule count</th></tr>"
        foreach ($entry in $topApps) { $html += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>" }
        $tableBlocks.Add("$html</table></div></div>")
    }
    if ($topServices) {
        $html = "<div><div class='pie-chart-title'>Most common services (allow rules, no App-ID)</div><div class='table-wrap'><table><tr><th>Service</th><th>Rule count</th></tr>"
        foreach ($entry in $topServices) { $html += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>" }
        $tableBlocks.Add("$html</table></div></div>")
    }
    if ($topTypes) {
        $html = "<div><div class='pie-chart-title'>Most common finding types</div><div class='table-wrap'><table><tr><th>Type</th><th>Count</th></tr>"
        foreach ($entry in $topTypes) { $html += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>" }
        $tableBlocks.Add("$html</table></div></div>")
    }
    if ($topRulesByFindings) {
        $html = "<div><div class='pie-chart-title'>Rules with the most findings</div><div class='table-wrap'><table><tr><th>Rule</th><th>Finding count</th></tr>"
        foreach ($entry in $topRulesByFindings) { $html += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>" }
        $tableBlocks.Add("$html</table></div></div>")
    }
    if ($topTags) {
        $html = "<div><div class='pie-chart-title'>Most common tags</div><div class='table-wrap'><table><tr><th>Tag</th><th>Rule count</th></tr>"
        foreach ($entry in $topTags) { $html += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>" }
        $tableBlocks.Add("$html</table></div></div>")
    }

    $tableRowsHtml = ""
    $tablesPerRow = 5
    for ($i = 0; $i -lt $tableBlocks.Count; $i += $tablesPerRow) {
        $rowContent = ""
        for ($j = $i; $j -lt [Math]::Min($i + $tablesPerRow, $tableBlocks.Count); $j++) {
            $rowContent += $tableBlocks[$j]
        }
        $tableRowsHtml += "<div class='chart-row'>$rowContent</div>"
    }

    $statsHtmlBlock = $statCardsHtml + $chartsHtml + $tableRowsHtml
    $statsBytes = [System.Text.Encoding]::UTF8.GetBytes($statsHtmlBlock)
    $lines += "%%RAWHTML_BASE64%%$([System.Convert]::ToBase64String($statsBytes))"
    $lines += ""

    # -------- Comparison with Previous Report (optional) --------
    $comparison = $null
    if ($CompareToPath) {
        $previousFindings = Import-PreviousFindings -Path $CompareToPath
        if ($previousFindings) {
            $comparison = Get-FindingsComparison -CurrentFindings $Findings -PreviousFindings $previousFindings

            $lines += "## Comparison with Previous Report"
            $lines += ""
            $lines += "Compared against: ``$CompareToPath``"
            $lines += ""

            $compareCardsHtml = "<div class='stat-grid'>"
            $compareCardsHtml += "<div class='stat-card'><div class='stat-value'>$($comparison.New.Count)</div><div class='stat-label'>New findings</div></div>"
            $compareCardsHtml += "<div class='stat-card'><div class='stat-value'>$($comparison.Resolved.Count)</div><div class='stat-label'>Resolved findings</div></div>"
            $compareCardsHtml += "<div class='stat-card'><div class='stat-value'>$($comparison.Persistent.Count)</div><div class='stat-label'>Still present</div></div>"
            $compareCardsHtml += "</div>"
            $compareBytes = [System.Text.Encoding]::UTF8.GetBytes($compareCardsHtml)
            $lines += "%%RAWHTML_BASE64%%$([System.Convert]::ToBase64String($compareBytes))"
            $lines += ""
            $lines += "New, resolved, and still-present findings are marked in the Comparison column of the table below."
            $lines += ""
        }
    }

    # Build one unified, render-ready row list rather than keeping the
    # comparison as separate New/Resolved tables: a finding that's
    # "Resolved" no longer has a row in $Findings at all (the rule that
    # caused it may not even exist anymore), so its columns come straight
    # from the previous run's CSV instead of $ruleLookup, which only
    # knows about this run's rules. Both shapes get normalized into the
    # same row structure here so one table and one sort can cover all of
    # it, keeping severity order intact across current AND resolved rows
    # together instead of dumping resolved ones at the end regardless of
    # how severe they were.
    $newKeys = @{}
    if ($comparison) {
        foreach ($f in $comparison.New) { $newKeys["$($f.RuleName)|$($f.Type)"] = $true }
    }
    $renderRows = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($f in $sorted) {
        $ctx = $ruleLookup[$f.RuleName]
        $compareTag = ""
        if ($comparison) {
            $key = "$($f.RuleName)|$($f.Type)"
            $compareTag = if ($newKeys.ContainsKey($key)) { "New" } else { "Still present" }
        }
        $renderRows.Add([PSCustomObject]@{
            Severity = $f.Severity; Rule = $f.RuleName
            Src      = if ($ctx) { $ctx.Src } else { "" }
            Dst      = if ($ctx) { $ctx.Dst } else { "" }
            App      = if ($ctx) { $ctx.Application } else { "" }
            Svc      = if ($ctx) { $ctx.Service } else { "" }
            Action   = if ($ctx) { $ctx.Action } else { "" }
            Profile  = if ($ctx) { $ctx.Profile } else { "" }
            Created  = if ($ctx) { $ctx.Created } else { "" }
            Modified = if ($ctx) { $ctx.Modified } else { "" }
            Type     = $f.Type; Detail = $f.Detail; Compare = $compareTag
        })
    }
    if ($comparison) {
        foreach ($f in $comparison.Resolved) {
            $renderRows.Add([PSCustomObject]@{
                Severity = $f.Severity; Rule = $f.Rule
                Src      = $f.Source; Dst = $f.Destination; App = $f.Application; Svc = $f.Service
                Action   = $f.Action; Profile = $f.Profile
                Created  = $f.Created; Modified = $f.Modified
                Type     = $f.Type; Detail = $f.Detail; Compare = "Resolved"
            })
        }
        # Stable sort: within the same severity, current-run rows (already
        # in their existing order, any_any_any_allow pinned first among
        # them) stay ahead of resolved ones added just above, rather than
        # shuffling the whole table.
        $renderRows = [System.Collections.Generic.List[PSCustomObject]]@($renderRows | Sort-Object { $SeverityOrder[$_.Severity] })
    }

    # Header/separator/rows are built once, with the two optional column
    # groups (Created/Modified, Comparison) spliced in conditionally,
    # rather than four near-duplicate hardcoded branches for every
    # combination of "has compare data" x "has created/modified data".
    $lines += "## Algorithmic-based Findings"
    $lines += ""
    $extraHeader = if ($showCreatedModified) { " Created | Modified |" } else { "" }
    $compareHeader = if ($comparison) { " Comparison |" } else { "" }
    $lines += "| Severity | Rule | Source | Destination | Application | Service | Action | Profile |$extraHeader Type | Detail |$compareHeader"
    $sep = "|---|---|---|---|---|---|---|---|"
    if ($showCreatedModified) { $sep += "---|---|" }
    $sep += "---|---|"
    if ($comparison) { $sep += "---|" }
    $lines += $sep
    foreach ($r in $renderRows) {
        $extraVals = if ($showCreatedModified) { " $($r.Created) | $($r.Modified) |" } else { "" }
        $compareVal = if ($comparison) { " $($r.Compare) |" } else { "" }
        $lines += "| $($r.Severity) | $($r.Rule) | $($r.Src) | $($r.Dst) | $($r.App) | $($r.Svc) | $($r.Action) | $($r.Profile) |$extraVals $($r.Type) | $($r.Detail) |$compareVal"
    }

    $sortedInventory = $Inventory
    if ($anyAnyAnyRuleNames.Count -gt 0) {
        $pinnedInv = @($Inventory | Where-Object { $anyAnyAnyRuleNames -contains $_.RuleName })
        $restInv = @($Inventory | Where-Object { $anyAnyAnyRuleNames -notcontains $_.RuleName })
        $sortedInventory = $pinnedInv + $restInv
    }

    $lines += ""
    $lines += "## Internet Exposure Inventory (all enabled allow rules touching the internet)"
    $lines += ""
    $invExtraHeader = if ($showCreatedModified) { " Created | Modified |" } else { "" }
    $lines += "| Rule | Direction | Source | Destination | Application | Service | Action | Profile |$invExtraHeader"
    $invSep = "|---|---|---|---|---|---|---|---|"
    if ($showCreatedModified) { $invSep += "---|---|" }
    $lines += $invSep
    foreach ($r in $sortedInventory) {
        $invExtraVals = if ($showCreatedModified) { " $($r.Created) | $($r.Modified) |" } else { "" }
        $lines += "| $($r.RuleName) | $($r.Direction) | $($r.Src) | $($r.Dst) | $($r.Application) | $($r.Service) | $($r.Action) | $($r.Profile) |$invExtraVals"
    }

    return $lines
}

# --------------------------------------------------------------------------
# Gemini call (masked input only)
# --------------------------------------------------------------------------

$SystemPrompt = @"
You are a Palo Alto / PAN-OS firewall policy review assistant helping a security
engineer prioritize cleanup of a firewall ruleset. You are given a list of
deterministic findings already computed algorithmically. Treat these as
established facts, do not second-guess or recompute them. Some values (IP
addresses) have been replaced with placeholder tokens like IP-MASKED-3 for
privacy. Refer to them by their placeholder token, never guess a real address.
You may also be given a "Tags" section listing free-text tags for the flagged
rules. Use these only as extra context (e.g. a tag mentioning "temporary" or
a ticket number is worth surfacing), never as a basis for inventing new
technical findings.

Your job:
- Write a short executive-readable summary (3-5 sentences) of the overall
  internet exposure and hygiene posture, referencing the findings.
- Propose a prioritized remediation order (inbound exposures and risky-port/
  application findings should generally outrank hygiene items like duplicates).
  Each array item should be the recommendation text only. Do NOT prefix it
  with your own "1.", "2." etc., the array's order already conveys sequence
  and the caller adds numbering when displaying it.
- If NO findings are provided, say so plainly instead of describing generic
  firewall risks. Never fill an empty input with a plausible-sounding but
  invented narrative.

Respond with a single JSON object only, no markdown fences, matching this schema:
{ "executive_summary": "...", "remediation_order": ["...", "...", "..."] }
"@

function Invoke-HttpPostWithSpinner {
    # Posts JSON via System.Net.Http.HttpClient asynchronously and polls the
    # Task on the calling thread to animate a spinner. Unlike Start-Job,
    # this stays in the same process/scope, so it doesn't need any of the
    # dot-sourced functions or script variables re-loaded into a separate
    # runspace. Works the same way on Windows PowerShell 5.1 and PowerShell 7.
    param([string]$Uri, [string]$JsonBody, [string]$Message = "Contacting Gemini")

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $client = [System.Net.Http.HttpClient]::new()
    $content = [System.Net.Http.StringContent]::new($JsonBody, [System.Text.Encoding]::UTF8, "application/json")

    try {
        $task = $client.PostAsync($Uri, $content)

        $spinChars = @('|', '/', '-', '\')
        $i = 0
        while (-not $task.IsCompleted) {
            Write-Host -NoNewline "`r$Message $($spinChars[$i % $spinChars.Length])  "
            Start-Sleep -Milliseconds 120
            $i++
        }
        Write-Host "`r$Message... done.          "

        $response = $task.GetAwaiter().GetResult()
        $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        return [PSCustomObject]@{
            StatusCode = [int]$response.StatusCode
            IsSuccess  = $response.IsSuccessStatusCode
            Body       = $responseBody
        }
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-GeminiNarrative {
    param([string]$UserPrompt, [string]$ApiKey, [string]$Model, [int]$MaxAttempts = 3)
    $bodyObj = @{
        system_instruction = @{ parts = @(@{ text = $SystemPrompt }) }
        contents           = @(@{ role = "user"; parts = @(@{ text = $UserPrompt }) })
        generationConfig   = @{ temperature = 0.2 }
    }
    $body = $bodyObj | ConvertTo-Json -Depth 10
    $uri = "https://generativelanguage.googleapis.com/v1beta/models/${Model}:generateContent?key=$ApiKey"

    # Transient server-side errors (rate limit / momentarily unavailable) are
    # worth a short retry with exponential backoff rather than giving up
    # immediately. A 503 in particular is usually Gemini being briefly
    # overloaded, not a problem with the request itself.
    $transientStatusCodes = @(429, 500, 502, 503, 504)
    $result = $null

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = Invoke-HttpPostWithSpinner -Uri $uri -JsonBody $body -Message "Contacting Gemini (attempt $attempt/$MaxAttempts)"
        }
        catch {
            Write-Host "ERROR: Gemini call failed: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }

        if ($result.IsSuccess) { break }

        $isTransient = $transientStatusCodes -contains $result.StatusCode
        if ($isTransient -and $attempt -lt $MaxAttempts) {
            $waitSeconds = [math]::Pow(2, $attempt)
            Write-Host "Note: Gemini call failed (attempt $attempt/$MaxAttempts, HTTP $($result.StatusCode)). This usually means the service is briefly overloaded. Retrying in $waitSeconds s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitSeconds
            $result = $null
            continue
        }

        Write-Host "ERROR: Gemini call failed: HTTP $($result.StatusCode). $($result.Body)" -ForegroundColor Red
        return $null
    }

    if (-not $result) { return $null }

    try {
        $response = $result.Body | ConvertFrom-Json
    }
    catch {
        Write-Host "ERROR: Gemini returned a response that could not be parsed as JSON." -ForegroundColor Red
        return $null
    }

    $rawText = $response.candidates[0].content.parts[0].text
    try { return $rawText | ConvertFrom-Json }
    catch { Write-Host "ERROR: Model did not return clean JSON:`n$rawText" -ForegroundColor Red; return $null }
}

# --------------------------------------------------------------------------
# HTML export (optional). Converts this script's own Markdown output to a
# standalone HTML file with basic styling (severity-colored table rows), no
# external dependencies required. Open it in any browser; use Print > Save
# as PDF there if a PDF is needed.
#
# Targets this script's own Markdown structure specifically (headers,
# tables, blockquotes, bold/code spans). Not a general-purpose parser.
# --------------------------------------------------------------------------

function ConvertTo-ReportHtml {
    param([string]$MarkdownContent, [string]$Title = "MooseAlto: Palo Alto Firewall Rule Hygiene Report")

    # Built from its Unicode codepoint instead of a literal character in this
    # file: Windows PowerShell 5.1 reads a .ps1 without a UTF-8 BOM using the
    # system ANSI codepage, which mis-decodes multi-byte literals like this.
    $robotEmoji = [System.Char]::ConvertFromUtf32(0x1F916)

    $css = @"
<style>
  :root {
    --ink: #1C1917;
    --paper: #FDFCFA;
    --gold: #A6720F;
    --gold-deep: #8A5D0A;
    --gold-tint: #F3E6C8;
    --slate: #2B2A28;
    --border: #E4DFD5;
    --muted: #6B655C;
    --critical: #B33A3A; --critical-bg: #F7E3E1;
    --high: #C1793A; --high-bg: #F8E8D6;
    --medium: #B8901A; --medium-bg: #FAF0D4;
    --low: #8A8580; --low-bg: #ECE9E4;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; margin: 40px; color: var(--ink); background: var(--paper); line-height: 1.45; }
  h1 { border-bottom: 3px solid var(--gold); padding-bottom: 10px; }
  h2 { margin: 0; color: var(--slate); }
  h3 { margin-top: 20px; color: var(--slate); }
  .table-wrap { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin: 12px 0; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 0; }
  th, td { padding: 8px 10px; text-align: left; vertical-align: top; border-top: 1px solid var(--border); }
  tr:first-child > th { border-top: none; }
  th { background: var(--slate); color: var(--paper); font-weight: 600; letter-spacing: 0.01em; border-top: none; }
  tr.data-row:nth-child(even) td { background: #FBF9F5; }
  tr.data-row:hover td { background: var(--gold-tint); }
  .sev-pill { display: inline-block; font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 99px; }
  .sev-pill-critical { background: var(--critical-bg); color: #8A2A2A; }
  .sev-pill-high { background: var(--high-bg); color: #8A4E17; }
  .sev-pill-medium { background: var(--medium-bg); color: #8A6B14; }
  .sev-pill-low { background: var(--low-bg); color: #5A564F; }
  blockquote { background: var(--gold-tint); border-left: 4px solid var(--gold); margin: 12px 0; padding: 10px 14px; }
  code { background: #F1EEE7; padding: 1px 5px; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', monospace; font-size: 0.92em; }
  .moose-logo { font-family: Consolas, 'Courier New', monospace; font-size: 10px; line-height: 1.1; color: var(--gold); white-space: pre; float: right; margin: 0 0 10px 20px; }
  details { clear: both; }
  ol { padding-left: 22px; }
  ol li { margin: 6px 0; }
  .ai-section { background: #F5F2FA; border: 1px solid #DCD2EC; border-left: 4px solid #7A5FB8; border-radius: 4px; padding: 4px 20px 16px 20px; margin-top: 16px; }
  .ai-section h2, .ai-section h3 { border-bottom: none; }
  .ai-badge { display: inline-block; font-size: 11px; font-weight: bold; color: #6B4FA8; background: #EAE2F7; border-radius: 10px; padding: 2px 10px; margin-bottom: 8px; letter-spacing: 0.02em; }
  details { margin-top: 32px; }
  details > summary { cursor: pointer; list-style: none; border-bottom: 2px solid var(--gold-tint); padding-bottom: 6px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2 { display: inline-block; margin: 0; border-bottom: none; padding-bottom: 0; }
  details > summary::before { content: '\25b6'; display: inline-block; margin-right: 8px; font-size: 13px; color: var(--gold); transition: transform 0.15s ease; }
  details[open] > summary::before { transform: rotate(90deg); }
  tr.filter-row td { background: #F7F5F0; padding: 4px 6px; }
  tr.filter-row input { width: 100%; box-sizing: border-box; font-size: 11px; padding: 3px 5px; border: 1px solid #CFC8B8; border-radius: 3px; font-family: inherit; }
  .filter-status { font-size: 11px; color: var(--muted); margin: 4px 0 0 2px; }
  .filter-status button { font-size: 11px; padding: 2px 8px; border: 1px solid #CFC8B8; border-radius: 3px; background: #F1EEE7; cursor: pointer; }
  .filter-status button:hover { background: var(--gold-tint); }
  .action-allow { color: #2E6B2E; font-weight: bold; }
  .action-deny { color: var(--critical); font-weight: bold; }
  .compare-new { color: var(--gold-deep); font-weight: bold; }
  .compare-resolved { color: #2E6B2E; font-weight: bold; }
  .stat-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0 20px 0; }
  .stat-card { background: var(--paper); border: 1px solid var(--border); border-top: 2px solid var(--gold); border-radius: 4px; padding: 10px 16px; min-width: 130px; box-shadow: 0 1px 2px rgba(28,25,23,0.04); }
  .stat-card .stat-value { font-size: 24px; font-weight: bold; color: var(--slate); }
  .stat-card .stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .chart-row { display: flex; flex-wrap: wrap; gap: 36px; margin: 12px 0 24px 0; }
  .pie-chart-wrap { display: flex; align-items: center; gap: 16px; }
  .pie-chart-title { font-size: 13px; font-weight: 600; margin-bottom: 8px; color: var(--slate); }
  .pie-legend { font-size: 12px; }
  .pie-legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; white-space: nowrap; }
  .pie-legend-swatch { display: inline-block; width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
</style>
<script>
function filterMooseTable(input) {
  var table = input.closest('table');
  var filterRow = table.querySelector('tr.filter-row');
  var filters = Array.prototype.map.call(filterRow.querySelectorAll('input'), function (i) { return i.value.toLowerCase(); });
  var rows = table.querySelectorAll('tbody tr.data-row');
  var visibleCount = 0;
  rows.forEach(function (row) {
    var cells = row.children;
    var visible = true;
    for (var i = 0; i < filters.length; i++) {
      if (filters[i] && cells[i] && cells[i].textContent.toLowerCase().indexOf(filters[i]) === -1) {
        visible = false;
        break;
      }
    }
    row.style.display = visible ? '' : 'none';
    if (visible) { visibleCount++; }
  });
  var status = table.nextElementSibling;
  if (status && status.classList.contains('filter-status')) {
    var label = status.querySelector('.status-text');
    if (label) { label.textContent = 'Showing ' + visibleCount + ' of ' + rows.length + ' rows'; }
  }
}
function clearMooseFilters(button) {
  var statusDiv = button.closest('.filter-status');
  var table = statusDiv.previousElementSibling;
  table.querySelectorAll('tr.filter-row input').forEach(function (i) { i.value = ''; });
  filterMooseTable(table.querySelector('tr.filter-row input'));
}
</script>
"@

    $lines = $MarkdownContent -split "`r?`n"
    $htmlLines = New-Object System.Collections.Generic.List[string]
    $inTable = $false
    $inList = $false
    $inAiSection = $false
    $inDetailsSection = $false
    $currentSectionHeading = ""
    $tableHasFilters = $false

    foreach ($line in $lines) {
        if ($line -match '^%%RAWHTML_BASE64%%(.+)$') {
            # Escape hatch for content that must not go through the
            # markdown pipeline below (SVG charts, stat card grids): the
            # table/list/paragraph handling below assumes plain text and
            # would mangle multi-line tags or literal < > characters.
            # Base64 avoids that entirely rather than trying to keep raw
            # HTML "line safe" during the split above.
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Matches[1]))
            $htmlLines.Add($decoded)
            continue
        }
        if ($line -match '^\|.*\|\s*$') {
            $cells = @($line.Trim().Trim('|') -split '\|' | ForEach-Object { $_.Trim() })
            $isSeparatorRow = -not ($cells | Where-Object { $_ -notmatch '^-+$' })
            if ($isSeparatorRow) { continue }

            if (-not $inTable) {
                # The small Summary table doesn't need per-column filters -
                # there are only a handful of rows. The bigger data tables
                # (findings, inventory) get a filter input under each header
                # cell, plus a clear-filters button and a visible-row count.
                $addFilters = $currentSectionHeading -ne "Summary"
                $actionColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "action")
                $compareColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "comparison")
                $htmlLines.Add("<div class='table-wrap'><table>")
                $htmlLines.Add("<tr>" + (($cells | ForEach-Object { "<th>$_</th>" }) -join "") + "</tr>")
                if ($addFilters) {
                    $filterCells = ($cells | ForEach-Object { "<td><input type='text' oninput='filterMooseTable(this)' placeholder='Filter...'></td>" }) -join ""
                    $htmlLines.Add("<tr class='filter-row'>$filterCells</tr>")
                }
                $htmlLines.Add("<tbody>")
                $inTable = $true
                $tableHasFilters = $addFilters
            }
            else {
                $rowClass = "data-row"
                $severityPillClass = ""
                switch ($cells[0]) {
                    "Critical" { $severityPillClass = "sev-pill-critical" }
                    "High"     { $severityPillClass = "sev-pill-high" }
                    "Medium"   { $severityPillClass = "sev-pill-medium" }
                    "Low"      { $severityPillClass = "sev-pill-low" }
                }
                $cellsHtml = for ($c = 0; $c -lt $cells.Count; $c++) {
                    if ($c -eq 0 -and $severityPillClass) {
                        "<td><span class='sev-pill $severityPillClass'>$($cells[$c])</span></td>"
                    }
                    elseif ($c -eq $actionColumnIndex) {
                        $actionLower = $cells[$c].Trim().ToLower()
                        if ($actionLower -eq "allow") { "<td><span class='action-allow'>$($cells[$c])</span></td>" }
                        elseif ($actionLower -eq "deny" -or $actionLower -eq "drop") { "<td><span class='action-deny'>$($cells[$c])</span></td>" }
                        else { "<td>$($cells[$c])</td>" }
                    }
                    elseif ($c -eq $compareColumnIndex) {
                        $compareLower = $cells[$c].Trim().ToLower()
                        if ($compareLower -eq "new") { "<td><span class='compare-new'>$($cells[$c])</span></td>" }
                        elseif ($compareLower -eq "resolved") { "<td><span class='compare-resolved'>$($cells[$c])</span></td>" }
                        else { "<td>$($cells[$c])</td>" }
                    }
                    else { "<td>$($cells[$c])</td>" }
                }
                $htmlLines.Add("<tr class='$rowClass'>" + ($cellsHtml -join "") + "</tr>")
            }
            continue
        }
        elseif ($inTable) {
            $htmlLines.Add("</tbody></table></div>")
            if ($tableHasFilters) { $htmlLines.Add("<div class='filter-status'><button type='button' onclick='clearMooseFilters(this)'>Clear filters</button> <span class='status-text'></span></div>") }
            $inTable = $false
        }

        # Consecutive "N. text" lines become a real <ol> instead of flat
        # paragraphs with no list styling.
        if ($line -match '^\d+\.\s+(.*)') {
            if (-not $inList) { $htmlLines.Add("<ol>"); $inList = $true }
            $htmlLines.Add("<li>$($Matches[1])</li>")
            continue
        }
        elseif ($inList) {
            $htmlLines.Add("</ol>")
            $inList = $false
        }

        if ($line -match '^> (.*)') { $htmlLines.Add("<blockquote>$($Matches[1])</blockquote>"); continue }
        if ($line -match '^### (.*)') { $htmlLines.Add("<h3>$($Matches[1])</h3>"); continue }
        if ($line -match '^## (.*)') {
            $headingText = $Matches[1]
            $currentSectionHeading = $headingText

            # Each top-level section becomes a collapsible <details>, open by
            # default. The previous one (if any) needs closing first - the
            # AI section's own div also needs closing before that, since
            # it's nested inside the details for that section.
            if ($inAiSection) { $htmlLines.Add("</div>"); $inAiSection = $false }
            if ($inDetailsSection) { $htmlLines.Add("</details>") }

            # Everything from the AI-Assisted Summary heading onward gets a
            # visually distinct container, reinforcing at a glance which
            # part of the report is deterministic and which is AI-generated,
            # not just via the wording of the heading itself.
            $isAiHeading = $headingText -match 'AI-Assisted'
            # The emoji lives in the actual heading text, not a CSS
            # ::before content property: generated-content emoji rendering
            # is inconsistent across browsers/viewers in a way that plain
            # text emoji isn't, since text goes through the standard font
            # fallback path uniformly.
            $displayHeadingText = if ($isAiHeading) { "$robotEmoji $headingText" } else { $headingText }
            $htmlLines.Add("<details open><summary><h2>$displayHeadingText</h2></summary>")
            $inDetailsSection = $true

            if ($isAiHeading) {
                $htmlLines.Add("<div class='ai-section'>")
                $htmlLines.Add("<span class='ai-badge'>AI GENERATED. REVIEW BEFORE ACTING</span>")
                $inAiSection = $true
            }
            continue
        }
        if ($line -match '^# (.*)') { $htmlLines.Add("<h1>$($Matches[1])</h1>"); continue }
        if ($line.Trim() -eq "") { continue }

        $formatted = $line -replace '\*\*(.+?)\*\*', '<b>$1</b>' -replace '\*([^*]+)\*', '<em>$1</em>' -replace '`([^`]+)`', '<code>$1</code>'
        $htmlLines.Add("<p>$formatted</p>")
    }
    if ($inTable) {
        $htmlLines.Add("</tbody></table>")
        if ($tableHasFilters) { $htmlLines.Add("<div class='filter-status'><button type='button' onclick='clearMooseFilters(this)'>Clear filters</button> <span class='status-text'></span></div>") }
    }
    if ($inList) { $htmlLines.Add("</ol>") }
    if ($inAiSection) { $htmlLines.Add("</div>") }
    if ($inDetailsSection) { $htmlLines.Add("</details>") }

    $mooseArt = @(
        ' ___            ___'
        '/   \          /   \'
        '\_   \        /  __/'
        ' _\   \      /  /__'
        ' \___  \____/   __/'
        '     \_       _/'
        '       | @ @  \_'
        '       |'
        '     _/     /\'
        '    /o)  (o/\ \_'
        '    \_____/ /'
        '      \____/'
    ) -join "`n"
    $mooseHtml = "<pre class='moose-logo'>$mooseArt</pre>"

    return "<html><head><meta charset='utf-8'><title>$Title</title>$css</head><body>$mooseHtml" + ($htmlLines -join "`n") + "</body></html>"
}

function Export-FindingsCsv {
    # Flat CSV of the findings table, same columns as the HTML/Markdown
    # table, for further filtering/pivoting in Excel or similar. Always
    # produced alongside the main report, not gated behind a switch.
    param([array]$Findings, [array]$Rules, [string]$CsvPath)

    $ruleLookup = @{}
    foreach ($r in $Rules) {
        $ruleLookup[$r.Name] = [PSCustomObject]@{
            Src         = "$($r.SrcZone -join ';') / $($r.SrcAddrRaw)"
            Dst         = "$($r.DstZone -join ';') / $($r.DstAddrRaw)"
            Application = if ($r.Application) { $r.Application -join "," } else { "any" }
            Service     = $r.ServiceRaw
            Action      = $r.Action
            Profile     = if ($r.Profile) { $r.Profile } else { "none" }
            Created     = $r.Created
            Modified    = $r.Modified
        }
    }

    $sorted = $Findings | Sort-Object { $SeverityOrder[$_.Severity] }
    $rows = foreach ($f in $sorted) {
        $ctx = $ruleLookup[$f.RuleName]
        [PSCustomObject]@{
            Severity    = $f.Severity
            Rule        = $f.RuleName
            Source      = if ($ctx) { $ctx.Src } else { "" }
            Destination = if ($ctx) { $ctx.Dst } else { "" }
            Application = if ($ctx) { $ctx.Application } else { "" }
            Service     = if ($ctx) { $ctx.Service } else { "" }
            Action      = if ($ctx) { $ctx.Action } else { "" }
            Profile     = if ($ctx) { $ctx.Profile } else { "" }
            Created     = if ($ctx) { $ctx.Created } else { "" }
            Modified    = if ($ctx) { $ctx.Modified } else { "" }
            Type        = $f.Type
            Detail      = $f.Detail
        }
    }

    $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
    Write-Host "CSV findings written to $CsvPath" -ForegroundColor Green
}

function Export-InventoryCsv {
    # Separate CSV for the Internet Exposure Inventory. CSV has no concept
    # of "tabs" like a workbook, so a second file is the equivalent.
    param([array]$Inventory, [string]$CsvPath)

    $rows = foreach ($r in $Inventory) {
        [PSCustomObject]@{
            Direction   = $r.Direction
            Rule        = $r.RuleName
            Source      = $r.Src
            Destination = $r.Dst
            Application = $r.Application
            Service     = $r.Service
            Action      = $r.Action
            Profile     = $r.Profile
        }
    }

    $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
    Write-Host "CSV inventory written to $CsvPath" -ForegroundColor Green
}

function Save-HtmlReport {
    # Converts markdown lines straight to HTML and writes it. No
    # intermediate file round-trip needed, since ConvertTo-ReportHtml
    # already works on an in-memory string.
    param([array]$MarkdownLines, [string]$HtmlPath)
    $htmlContent = ConvertTo-ReportHtml -MarkdownContent ($MarkdownLines -join "`n")
    $htmlContent | Out-File -FilePath $HtmlPath -Encoding utf8
}
