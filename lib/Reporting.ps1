# --------------------------------------------------------------------------
# Report rendering (Markdown/HTML) and the optional Gemini AI summary
# --------------------------------------------------------------------------

# The same patterns mask what goes to Gemini and then check the final
# request, so the check looks for exactly what should be gone. They're
# greedy on purpose: masking a version number costs nothing, leaking an
# address is the one thing that can't happen.
#  - dotted IPv4, also inside names and ranges ("Allow-10.1.1.1")
#  - IPv4 with "_" or "-" between octets ("Host_10_1_1_1")
#  - IPv6, full or with "::"
$script:IpMaskPatterns = @(
    @{ Name = 'ipv4'; Regex = [regex]'(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?!\d)' },
    @{ Name = 'ipv4-sep'; Regex = [regex]'(?<!\d)(\d{1,3})([_-])(\d{1,3})\2(\d{1,3})\2(\d{1,3})(?!\d)' },
    @{ Name = 'ipv6'; Regex = [regex]'(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)(?:/\d{1,3})?(?![0-9a-f:])' }
)

function Test-IpMaskCandidate {
    # Filters regex hits that are not addresses: separator form octets above
    # 255 (dates, port lists), a bare "::" with no hex group.
    param([string]$PatternName, [System.Text.RegularExpressions.Match]$Match)
    switch ($PatternName) {
        'ipv4-sep' {
            foreach ($g in 1, 3, 4, 5) { if ([int]$Match.Groups[$g].Value -gt 255) { return $false } }
            return $true
        }
        'ipv6' { return ($Match.Value -match '(?i)[0-9a-f]') }
    }
    return $true
}

function Protect-IPAddresses {
    # Each address becomes IP-MASKED-N, the same N all run long ($Map is
    # shared). Whole matches via regex: a plain string replace turned
    # 10.1.1.10/24 into "IP-MASKED-10/24" once 10.1.1.1 was masked.
    param(
        [AllowEmptyString()][AllowNull()][string]$Text,
        [Parameter(Mandatory = $true)][System.Collections.Hashtable]$Map
    )
    if (-not $Text) { return $Text }
    foreach ($p in $script:IpMaskPatterns) {
        $name = $p.Name
        $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            if (-not (Test-IpMaskCandidate -PatternName $name -Match $m)) { return $m.Value }
            # 10_1_2_3 and 10.1.2.3 are the same address: same placeholder.
            $ip = if ($name -eq 'ipv4-sep') { ($m.Groups[1].Value, $m.Groups[3].Value, $m.Groups[4].Value, $m.Groups[5].Value) -join '.' } else { $m.Value }
            if (-not $Map.ContainsKey($ip)) { $Map[$ip] = "IP-MASKED-$($Map.Count + 1)" }
            return $Map[$ip]
        }.GetNewClosure()
        $Text = $p.Regex.Replace($Text, $evaluator)
    }
    return $Text
}

function Find-IpAddressLeaks {
    # Every IP address still present in a text, by the same patterns the
    # masker uses. Empty result = clean.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $found = @()
    if (-not $Text) { return $found }
    foreach ($p in $script:IpMaskPatterns) {
        foreach ($m in $p.Regex.Matches($Text)) {
            if (Test-IpMaskCandidate -PatternName $p.Name -Match $m) { $found += $m.Value }
        }
    }
    return @($found | Select-Object -Unique)
}

function Test-GeminiPayloadClean {
    # Last look at the exact request. If a new field ever skips the masking,
    # nothing gets sent.
    param([string[]]$Texts)
    $leaks = @()
    foreach ($t in $Texts) { $leaks += Find-IpAddressLeaks -Text $t }
    $leaks = @($leaks | Select-Object -Unique)
    if ($leaks.Count -gt 0) {
        Write-Host "ERROR: the request to Gemini still contains $($leaks.Count) IP address(es) after masking (e.g. $(($leaks | Select-Object -First 3) -join ', ')). Nothing was sent. This is a MooseAlto bug: please report it." -ForegroundColor Red
        return $false
    }
    return $true
}

# --------------------------------------------------------------------------
# Report rendering
# --------------------------------------------------------------------------

$SeverityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }


function Get-DisplayAddress {
    # "Name (10.0.0.0/8)" when resolving changed something, else just the
    # raw value.
    param([string]$Raw, [array]$Resolved)
    $resolvedText = if ($Resolved) { ($Resolved -join ";") } else { "" }
    if (-not $resolvedText) { return $Raw }
    if ($resolvedText.Trim().ToLower() -eq $Raw.Trim().ToLower()) { return $Raw }
    return "$Raw ($resolvedText)"
}

function Get-SvgPieChart {
    # Plain SVG donut: one dashed circle per slice, no library. Arrays, not
    # a hashtable, so the slices keep the caller's order.
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
    # Start at 12 o'clock.
    $donut = "<svg viewBox='0 0 $Size $Size' width='$Size' height='$Size'><g transform='rotate(-90 $cx $cy)'>$rings</g><text x='$cx' y='$($cy - 2)' text-anchor='middle' font-size='20' font-weight='600' fill='#2B2A28'>$total</text><text x='$cx' y='$($cy + 14)' text-anchor='middle' font-size='9' fill='#6B655C'>$CenterLabel</text></svg>"
    return "<div class='pie-chart-wrap'>$donut<div class='pie-legend'>$legend</div></div>"
}

function Import-PreviousFindings {
    # The -CompareTo CSV. Only Rule/Type/Severity are needed, so older
    # versions work. Any problem returns $null and the comparison is skipped.
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
    if (-not $rows) {
        # Header only: a run with no findings, so everything is new now.
        $header = "$(Get-Content -Path $Path -TotalCount 1 -ErrorAction SilentlyContinue)"
        if ($header -match '(^|,)"?Rule"?(,|$)' -and $header -match '(^|,)"?Type"?(,|$)') { return , @() }
    }
    if (-not $rows -or -not ($rows | Get-Member -Name "Rule" -MemberType NoteProperty) -or -not ($rows | Get-Member -Name "Type" -MemberType NoteProperty)) {
        Write-Host "Note: -CompareTo file doesn't look like a MooseAlto findings CSV (missing Rule/Type columns). Skipping comparison." -ForegroundColor Yellow
        return $null
    }
    return @($rows)
}

function Get-FindingsComparison {
    # Matched by rule name and type. A renamed rule shows up as resolved
    # plus new; matching on content would bring its own ambiguity.
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
    param([array]$Findings, [array]$Inventory, [string]$InputCsvPath, [array]$Rules, [string]$ElapsedText = "", [array]$InternetZoneSet = @(), [string]$CompareToPath = "", [string]$AddressObjectsCsvPath = "", [string]$AddressGroupsCsvPath = "", [array]$CriticalZoneSet = @(), [int]$StaleHitDays = 365, [int]$MaxAddressListSize = 25, [switch]$SkipLLM, [string]$ComparisonNarrative = "")

    # Rule columns are looked up by name here, so findings stay small.
    $ruleLookup = @{}
    foreach ($r in $Rules) {
        $ruleLookup[$r.Name] = [PSCustomObject]@{
            Src         = "$($r.SrcZone -join ';') / $(Get-DisplayAddress -Raw $r.SrcAddrRaw -Resolved $r.SrcAddr)"
            Dst         = "$($r.DstZone -join ';') / $(Get-DisplayAddress -Raw $r.DstAddrRaw -Resolved $r.DstAddr)"
            Application = if ($r.Application) { $r.Application -join "," } else { "any" }
            Service     = $r.ServiceRaw
            Action      = $r.Action
            Profile     = if ($r.Profile) { $r.Profile } else { "none" }
            Created     = $r.Created
            Modified    = $r.Modified
        }
    }

    # Optional columns only show when something fills them.
    $showCreatedModified = @($Rules | Where-Object { $_.HasCreatedColumn -or $_.HasModifiedColumn }).Count -gt 0
    $showSuggestedFix = @($Findings | Where-Object { $_.SuggestedFix }).Count -gt 0
    $showMitreTag = @($Findings | Where-Object { $_.MitreTag }).Count -gt 0

    # The any_any_any_allow row goes on top; the rest by severity.
    $anyAnyAnyRuleNames = @($Findings | Where-Object { $_.Type -eq "any_any_any_allow" } | Select-Object -ExpandProperty RuleName -Unique)

    $sorted = $Findings | Sort-Object { $SeverityOrder[$_.Severity] }
    $pinned = @($sorted | Where-Object { $_.Type -eq "any_any_any_allow" })
    $rest = @($sorted | Where-Object { $_.Type -ne "any_any_any_allow" })
    $sorted = $pinned + $rest

    $lines = @("# $script:ReportTitle", "")
    $lines += "**Input file:** $InputCsvPath  "
    $lines += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')  "
    if ($ElapsedText) {
        $lines += "**Processing time:** $ElapsedText  "
    }

    # Only settings that differ from the defaults.
    $runInfoLines = @()
    if ($AddressObjectsCsvPath) { $runInfoLines += "**Address objects:** $AddressObjectsCsvPath  " }
    if ($AddressGroupsCsvPath) { $runInfoLines += "**Address groups:** $AddressGroupsCsvPath  " }
    if ($CriticalZoneSet.Count -gt 0) { $runInfoLines += "**Critical zones:** $($CriticalZoneSet -join ', ')  " }
    if ($InternetZoneSet.Count -gt 0 -and ($InternetZoneSet -join ',') -ne "untrust,internet,outside,external") {
        $runInfoLines += "**Internet-facing zones:** $($InternetZoneSet -join ', ')  "
    }
    if ($StaleHitDays -ne 365) { $runInfoLines += "**Stale threshold:** $StaleHitDays days  " }
    if ($MaxAddressListSize -ne 25) { $runInfoLines += "**Max address list size:** $MaxAddressListSize  " }
    if ($script:NoSecurityProfileChecks) { $runInfoLines += "**Security profile check:** off, the firewall does no IPS/AV/URL inspection (-NoSecurityProfileChecks)  " }
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
    # Overview cards and charts. Direction here is a rough count, simpler
    # than the inventory's per-rule label.
    $enabledRules = @($Rules | Where-Object { -not $_.Disabled })
    $disabledCount = @($Rules | Where-Object { $_.Disabled }).Count
    $allowRules = @($enabledRules | Where-Object { $_.Action -eq "allow" })
    $denyDropCount = @($enabledRules | Where-Object { (Get-ActionClass $_.Action) -eq "deny" }).Count
    $noProfileCount = @($allowRules | Where-Object { $_.Profile.ToLower() -eq "" -or $_.Profile.ToLower() -eq "none" }).Count
    $permissiveCount = @($allowRules | Where-Object { $null -eq $_.Application -and ($null -eq $_.SrcAddr -or $null -eq $_.DstAddr) }).Count

    $inboundCount = 0; $outboundCount = 0; $bothCount = 0; $internalCount = 0
    foreach ($r in $allowRules) {
        $srcInet = Test-SideIsInternet -Zones $r.SrcZone -AddrTokens $r.SrcAddr -InternetZoneSet $InternetZoneSet
        $dstInet = Test-SideIsInternet -Zones $r.DstZone -AddrTokens $r.DstAddr -InternetZoneSet $InternetZoneSet
        if ($srcInet -and $dstInet) { $bothCount++ }
        elseif ($srcInet) { $inboundCount++ }
        elseif ($dstInet) { $outboundCount++ }
        else { $internalCount++ }
    }
    # The same, as internet yes/no.
    $internetTouchingCount = $inboundCount + $outboundCount + $bothCount

    $appFrequency = @{}
    foreach ($r in $allowRules) {
        if ($null -eq $r.Application) { continue }
        foreach ($app in $r.Application) {
            if (-not $appFrequency.ContainsKey($app)) { $appFrequency[$app] = 0 }
            $appFrequency[$app]++
        }
    }
    $topApps = $appFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Port-based rules don't appear in the app table, so they get their own.
    $serviceFrequency = @{}
    foreach ($r in $allowRules) {
        if ($null -ne $r.Application -or $null -eq $r.Service) { continue }
        foreach ($svc in $r.Service) {
            # Not a port.
            if ($svc -eq "application-default") { continue }
            if (-not $serviceFrequency.ContainsKey($svc)) { $serviceFrequency[$svc] = 0 }
            $serviceFrequency[$svc]++
        }
    }
    $topServices = $serviceFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Most frequent finding types: one problem repeated, or many?
    $typeFrequency = @{}
    foreach ($f in $Findings) {
        if (-not $typeFrequency.ContainsKey($f.Type)) { $typeFrequency[$f.Type] = 0 }
        $typeFrequency[$f.Type]++
    }
    $topTypes = $typeFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Rules with the most findings: a good place to start.
    $ruleFrequency = @{}
    foreach ($f in $Findings) {
        if ($f.RuleName -eq "(ruleset-wide)") { continue }
        if (-not $ruleFrequency.ContainsKey($f.RuleName)) { $ruleFrequency[$f.RuleName] = 0 }
        $ruleFrequency[$f.RuleName]++
    }
    $topRulesByFindings = $ruleFrequency.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8

    # Tags split on ";" or ",", like other fields.
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

    # App-ID, port-based, or neither (any/any).
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
    $trafficScopePie = Get-SvgPieChart -Labels @("Touches internet", "Internal only") -Values @($internetTouchingCount, $internalCount) -Colors @("#B33A3A", "#6B8F5E") -CenterLabel "allow rules"

    # Inline icons: a CDN icon font would mean a network call.
    $iconShield = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><path d='M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5l8-3z'/></svg>"
    $iconExchange = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><path d='M7 3l4 4-4 4M3 7h8M17 21l-4-4 4-4M21 17h-8'/></svg>"
    $iconLock = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><rect x='4' y='11' width='16' height='9' rx='1'/><path d='M8 11V7a4 4 0 018 0v4'/></svg>"
    $iconGlobe = "<svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='#A6720F' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' style='vertical-align:-3px;margin-right:6px;'><circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3c2.5 2.7 4 6 4 9s-1.5 6.3-4 9c-2.5-2.7-4-6-4-9s1.5-6.3 4-9z'/></svg>"

    # The four charts share one row.
    $chartsHtml = "<div class='chart-row'>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconShield}Findings by severity</div>$severityPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconExchange}Allow rules by direction</div>$directionPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconLock}Allow rules: App-ID vs port-based matching</div>$appIdPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>${iconGlobe}Allow rules: internal vs internet-touching</div>$trafficScopePie</div>"
    $chartsHtml += "</div>"

    # Only tables with data are added, then packed into rows, so an empty
    # one doesn't leave a gap.
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
        if ($null -ne $previousFindings) {
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
            if ($ComparisonNarrative) {
                $lines += "> **AI trend assessment:** $ComparisonNarrative"
                $lines += ""
            }
            $lines += "New, resolved, and still-present findings are marked in the Comparison column of the table below."
            $lines += ""
        }
    }

    # One table for everything. Resolved findings aren't in $Findings any
    # more, so their columns come from the previous CSV; all rows then sort
    # by severity together.
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
            Suggested = if ($f.SuggestedFix) { $f.SuggestedFix } else { "" }
            Mitre    = if ($f.MitreTag) { $f.MitreTag } else { "" }
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
                Suggested = ""
                Mitre    = ""
            })
        }
        # Stable sort: within a severity, current rows stay ahead of resolved.
        $renderRows = [System.Collections.Generic.List[PSCustomObject]]@($renderRows | Sort-Object { $SeverityOrder[$_.Severity] })
    }

    # Optional columns are spliced in where needed.
    $lines += "## Algorithmic-based Findings"
    $lines += ""
    $extraHeader = if ($showCreatedModified) { " Created | Modified |" } else { "" }
    $suggestedHeader = if ($showSuggestedFix) { " Suggested Fix |" } else { "" }
    $mitreHeader = if ($showMitreTag) { " MITRE ATT&CK |" } else { "" }
    $compareHeader = if ($comparison) { " Comparison |" } else { "" }
    $lines += "| Severity | Rule | Source | Destination | Application | Service | Action | Profile |$extraHeader Type | Detail |$suggestedHeader$mitreHeader$compareHeader"
    $sep = "|---|---|---|---|---|---|---|---|"
    if ($showCreatedModified) { $sep += "---|---|" }
    $sep += "---|---|"
    if ($showSuggestedFix) { $sep += "---|" }
    if ($showMitreTag) { $sep += "---|" }
    if ($comparison) { $sep += "---|" }
    $lines += $sep
    foreach ($r in $renderRows) {
        $extraVals = if ($showCreatedModified) { " $($r.Created) | $($r.Modified) |" } else { "" }
        $suggestedVal = if ($showSuggestedFix) { " $($r.Suggested) |" } else { "" }
        $mitreVal = if ($showMitreTag) { " $($r.Mitre) |" } else { "" }
        $compareVal = if ($comparison) { " $($r.Compare) |" } else { "" }
        $lines += "| $($r.Severity) | $($r.Rule) | $($r.Src) | $($r.Dst) | $($r.App) | $($r.Svc) | $($r.Action) | $($r.Profile) |$extraVals $($r.Type) | $($r.Detail) |$suggestedVal$mitreVal$compareVal"
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

# MooseAlto.ps1 changes it for other vendors.
$script:ReportTitle = "MooseAlto: Palo Alto Firewall Rule Hygiene Report"

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
technical findings. You may also be given a "Findings Comparison" section:
counts and specific items of what's new, resolved, or still present
compared to a previous run of this same ruleset. The findings list may be labeled "(batch N of M)" when
the full ruleset was too large for one request and got split - if you see
this with M greater than 1, you are seeing only a slice of the findings, not
the whole ruleset. Write your executive summary about what's actually IN
this batch specifically, not as if it were a complete assessment of
everything - phrases like "the ruleset exhibits..." or "overall posture..."
overstate what a partial batch can support. A short, scoped observation
("this batch's findings center on X and Y") is more honest and, just as
importantly, avoids each batch's summary reading as a near-duplicate of
every other batch's when they get combined afterward.

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
- For findings whose type is any_any_any_allow, outbound_defined_dest_any_app,
  or port_based_rule_missing_app_id specifically, and ONLY those types, guess a
  plausible App-ID the rule was probably meant to use, based on the rule name,
  its Tags (if given), and any port/service already visible in the finding
  text. Base this only on what's actually in the rule name/tags/port; if
  nothing gives a real hint, omit that finding from this array entirely
  rather than guessing something generic like "web-browsing" by default.
  This is explicitly a guess for a human to verify, not a determination, and
  your reasoning field must say what specifically (which word in the name, tag,
  or port) led to the guess.
- For findings that clearly correspond to a well-known MITRE ATT&CK technique
  (a specific risky application/port, ICMP or DNS-tunneling patterns, and
  similar concrete techniques, not vague hygiene findings like duplicates or
  disabled rules), map it to that technique's ID and name. Only tag a finding
  when you're confident of the mapping; skip it entirely rather than forcing
  a speculative or overly generic tag (e.g. don't tag something as "T1071
  Application Layer Protocol" just because it's network traffic - that's too
  generic to be useful). Cite the specific tactic the technique falls under
  (e.g. "Lateral Movement", "Exfiltration").
- If a "Findings Comparison" section is given, write a short (2-4 sentence)
  narrative of the trend since the previous run: what got fixed, what's
  new, and whether the overall trajectory looks like real progress or
  just churn (e.g. resolved findings reappearing under a new rule name
  would be a sign of the latter, if the data suggests it - but don't
  speculate beyond what the counts and listed items actually show).
  Reference specific rule names from the New/Resolved lists when they
  illustrate the point, not just the counts. If nothing changed at all,
  say that plainly rather than padding it into a longer narrative.

Respond with a single JSON object only, no markdown fences, matching this schema:
{ "executive_summary": "...", "remediation_order": ["...", "...", "..."],
  "application_suggestions": [ { "rule_name": "...", "type": "...", "suggested_application": "...", "reasoning": "..." } ],
  "mitre_mappings": [ { "rule_name": "...", "type": "...", "technique_id": "...", "technique_name": "...", "tactic": "..." } ],
  "comparison_narrative": "..." }
The application_suggestions array may be empty if no finding of the eligible
types was given, or if none had enough of a hint to guess from. The
mitre_mappings array may be empty if nothing given maps clearly to a known
technique. Omit comparison_narrative entirely (not an empty string) if no
"Findings Comparison" section was given.
"@

function Invoke-HttpPostWithSpinner {
    # Async POST, polled here to draw a spinner. Same process, unlike
    # Start-Job, so nothing needs reloading. The default 100 s timeout is
    # too short for big batches; when it hits you get "A task was canceled",
    # which is a timeout, not a bad key.
    param([string]$Uri, [string]$JsonBody, [string]$Message = "Contacting Gemini", [int]$TimeoutSeconds = 180)

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
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
    param([string]$UserPrompt, [string]$ApiKey, [string]$Model, [int]$MaxAttempts = 3, [int]$TimeoutSeconds = 180)
    $bodyObj = @{
        system_instruction = @{ parts = @(@{ text = $SystemPrompt }) }
        contents           = @(@{ role = "user"; parts = @(@{ text = $UserPrompt }) })
        generationConfig   = @{ temperature = 0.2 }
    }
    # Fail closed: never send a request that still holds an IP address.
    if (-not (Test-GeminiPayloadClean -Texts @($SystemPrompt, $UserPrompt))) { return $null }
    $body = $bodyObj | ConvertTo-Json -Depth 10
    $uri = "https://generativelanguage.googleapis.com/v1beta/models/${Model}:generateContent?key=$ApiKey"

    # Rate limits and 5xx are usually brief: retry with backoff.
    $transientStatusCodes = @(429, 500, 502, 503, 504)
    $result = $null

    # Test hook (Test-AiAnalysis.ps1): no network. The request goes to the
    # log file and the canned answer comes back as Gemini's; everything
    # else runs for real.
    if ($env:MOOSEALTO_TEST_GEMINI_RESPONSE) {
        if ($env:MOOSEALTO_TEST_GEMINI_REQUEST_LOG) { Add-Content -Path $env:MOOSEALTO_TEST_GEMINI_REQUEST_LOG -Value $body }
        $mockText = Get-Content -Path $env:MOOSEALTO_TEST_GEMINI_RESPONSE -Raw
        $mockBody = @{ candidates = @(@{ content = @{ parts = @(@{ text = $mockText }) } }) } | ConvertTo-Json -Depth 6
        $result = [PSCustomObject]@{ IsSuccess = $true; StatusCode = 200; Body = $mockBody }
        $MaxAttempts = 0
    }

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $result = Invoke-HttpPostWithSpinner -Uri $uri -JsonBody $body -Message "Contacting Gemini (attempt $attempt/$MaxAttempts)" -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            # A timeout arrives as an exception, not a status code: retry it
            # like the transient errors.
            $inner = $_.Exception
            $isTimeout = $false
            while ($inner) {
                if ($inner -is [System.Threading.Tasks.TaskCanceledException] -or $inner -is [System.TimeoutException]) {
                    $isTimeout = $true
                    break
                }
                $inner = $inner.InnerException
            }

            if ($isTimeout -and $attempt -lt $MaxAttempts) {
                $waitSeconds = [math]::Pow(2, $attempt)
                Write-Host "Note: Gemini call timed out after $TimeoutSeconds s (attempt $attempt/$MaxAttempts). This usually means the response took longer than expected to arrive, not a problem with the request. Retrying in $waitSeconds s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $waitSeconds
                $result = $null
                continue
            }

            if ($isTimeout) {
                Write-Host "ERROR: Gemini call timed out after $TimeoutSeconds s on every attempt. The batch may be too large, or the network/proxy path to generativelanguage.googleapis.com is slow right now. Consider a smaller batch or a longer timeout." -ForegroundColor Red
            }
            else {
                Write-Host "ERROR: Gemini call failed: $($_.Exception.Message)" -ForegroundColor Red
            }
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
# HTML export: turns our own Markdown into a standalone HTML page (no
# external files). Only handles what we generate; not a general parser.
# --------------------------------------------------------------------------

function ConvertTo-ReportHtml {
    param([string]$MarkdownContent, [string]$Title = $script:ReportTitle)

    # From the codepoint: PS 5.1 would mangle a literal emoji in a BOM-less file.
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
  .table-wrap { border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; overflow-y: hidden; -webkit-overflow-scrolling: touch; margin: 12px 0; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 0; }
  th, td { padding: 8px 10px; text-align: left; vertical-align: top; border-top: 1px solid var(--border); }
  .col-truncate { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help; }
  th { position: relative; }
  .col-resize-handle { position: absolute; top: 0; right: 0; bottom: 0; width: 7px; cursor: col-resize; touch-action: none; }
  .col-drag-label { cursor: grab; display: inline-block; touch-action: none; }
  th.col-dragging { opacity: 0.4; }
  th.col-drop-target { background: rgba(166, 114, 15, 0.55); }
  .col-resize-handle:hover, .col-resize-handle.resizing { background: rgba(253, 252, 250, 0.35); }
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
  .chart-row > div { flex: 1 1 280px; min-width: 280px; }
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

function makeMooseColumnsResizable(table) {
  // Columns start at whatever width the browser's normal table-layout
  // (content-based) already computed - that's the "auto-adapts to the
  // screen" part, since it already accounts for what's actually in each
  // column. Freezing those widths into explicit inline styles and only
  // then switching to table-layout:fixed is what makes dragging a column
  // afterward behave predictably instead of every other column jumping
  // around to compensate.
  var headers = table.querySelectorAll('th');
  headers.forEach(function (th) {
    th.style.width = th.offsetWidth + 'px';
  });
  table.style.tableLayout = 'fixed';

  headers.forEach(function (th) {
    var handle = document.createElement('div');
    handle.className = 'col-resize-handle';
    th.appendChild(handle);

    var startX = 0;
    var startWidth = 0;

    function onMove(clientX) {
      var newWidth = startWidth + (clientX - startX);
      if (newWidth > 40) { th.style.width = newWidth + 'px'; }
    }
    function mouseMove(e) { onMove(e.pageX); }
    function mouseUp() {
      handle.classList.remove('resizing');
      document.removeEventListener('mousemove', mouseMove);
      document.removeEventListener('mouseup', mouseUp);
    }
    handle.addEventListener('mousedown', function (e) {
      startX = e.pageX;
      startWidth = th.offsetWidth;
      handle.classList.add('resizing');
      document.addEventListener('mousemove', mouseMove);
      document.addEventListener('mouseup', mouseUp);
      e.preventDefault();
    });

    // Separate from the native swipe-to-scroll on .table-wrap (that one
    // needs no JS at all, overflow-x:auto handles it on any modern
    // touch browser) - this is specifically for dragging the resize
    // handle itself with a finger.
    function touchMove(e) { onMove(e.touches[0].pageX); e.preventDefault(); }
    function touchEnd() {
      handle.classList.remove('resizing');
      document.removeEventListener('touchmove', touchMove);
      document.removeEventListener('touchend', touchEnd);
    }
    handle.addEventListener('touchstart', function (e) {
      startX = e.touches[0].pageX;
      startWidth = th.offsetWidth;
      handle.classList.add('resizing');
      document.addEventListener('touchmove', touchMove, { passive: false });
      document.addEventListener('touchend', touchEnd);
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('table.resizable-table').forEach(makeMooseColumnsResizable);
});

function makeMooseColumnsReorderable(table) {
  // The header row specifically (first <tr> in the table) drives which
  // index is "column N" - every other row (the filter row, if present,
  // and every data row) just gets its cell moved to match, so filters
  // and data stay aligned with whatever the header now says.
  var headerRow = table.querySelector('tr');
  var allRows = table.querySelectorAll('tr');

  function getHeaderIndex(th) {
    return Array.prototype.indexOf.call(headerRow.children, th);
  }

  function reorderAllRows(sourceIndex, targetIndex) {
    if (sourceIndex === targetIndex) { return; }
    allRows.forEach(function (row) {
      var cells = Array.prototype.slice.call(row.children);
      var sourceCell = cells[sourceIndex];
      if (!sourceCell) { return; }
      if (targetIndex >= cells.length) {
        row.appendChild(sourceCell);
      } else {
        row.insertBefore(sourceCell, cells[targetIndex]);
      }
    });
  }

  Array.prototype.slice.call(headerRow.children).forEach(function (th) {
    var label = th.querySelector('.col-drag-label');
    if (!label) { return; }

    var sourceIndex = null;
    var currentTargetTh = null;

    function clearHighlight() {
      if (currentTargetTh) { currentTargetTh.classList.remove('col-drop-target'); }
      currentTargetTh = null;
    }

    // document.elementFromPoint rather than tracking deltas: with columns
    // free to have any width (including user-resized ones), "which header
    // is the pointer over right now" is simpler and more reliable to ask
    // directly than to compute from a running offset.
    function findHeaderAt(clientX, clientY) {
      var el = document.elementFromPoint(clientX, clientY);
      while (el && el.tagName !== 'TH') { el = el.parentElement; }
      return (el && el.closest('tr') === headerRow) ? el : null;
    }

    function onMove(clientX, clientY) {
      var target = findHeaderAt(clientX, clientY);
      if (target !== currentTargetTh) {
        clearHighlight();
        if (target && target !== th) {
          target.classList.add('col-drop-target');
          currentTargetTh = target;
        }
      }
    }

    function endDrag() {
      th.classList.remove('col-dragging');
      if (currentTargetTh) {
        reorderAllRows(sourceIndex, getHeaderIndex(currentTargetTh));
      }
      clearHighlight();
    }

    function mouseMove(e) { onMove(e.clientX, e.clientY); }
    function mouseUp() {
      endDrag();
      document.removeEventListener('mousemove', mouseMove);
      document.removeEventListener('mouseup', mouseUp);
    }
    label.addEventListener('mousedown', function (e) {
      sourceIndex = getHeaderIndex(th);
      th.classList.add('col-dragging');
      document.addEventListener('mousemove', mouseMove);
      document.addEventListener('mouseup', mouseUp);
      e.preventDefault();
    });

    function touchMove(e) {
      var t = e.touches[0];
      onMove(t.clientX, t.clientY);
      e.preventDefault();
    }
    function touchEnd() {
      endDrag();
      document.removeEventListener('touchmove', touchMove);
      document.removeEventListener('touchend', touchEnd);
    }
    label.addEventListener('touchstart', function (e) {
      sourceIndex = getHeaderIndex(th);
      th.classList.add('col-dragging');
      document.addEventListener('touchmove', touchMove, { passive: false });
      document.addEventListener('touchend', touchEnd);
    }, { passive: true });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('table.resizable-table').forEach(makeMooseColumnsReorderable);
});
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
            # Raw HTML (charts, cards) travels as base64 so the Markdown
            # handling below can't mangle it.
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Matches[1]))
            $htmlLines.Add($decoded)
            continue
        }
        if ($line -match '^\|.*\|\s*$') {
            $cells = @($line.Trim().Trim('|') -split '\|' | ForEach-Object { $_.Trim() })
            $isSeparatorRow = -not ($cells | Where-Object { $_ -notmatch '^-+$' })
            if ($isSeparatorRow) { continue }

            if (-not $inTable) {
                # Filters on the big tables, not on the Summary.
                $addFilters = $currentSectionHeading -ne "Summary"
                $actionColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "action")
                $compareColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "comparison")
                $sourceColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "source")
                $destColumnIndex = [array]::IndexOf(($cells | ForEach-Object { $_.ToLower() }), "destination")
                # Resizable columns too, only on the big tables.
                $tableClass = if ($addFilters) { " class='resizable-table'" } else { "" }
                $htmlLines.Add("<div class='table-wrap'><table$tableClass>")
                $htmlLines.Add("<tr>" + (($cells | ForEach-Object { "<th><span class='col-drag-label'>$_</span></th>" }) -join "") + "</tr>")
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
                    elseif ($c -eq $sourceColumnIndex -or $c -eq $destColumnIndex) {
                        # Long address lists are cut with an ellipsis; the
                        # full text is in the tooltip, or widen the column.
                        "<td class='col-truncate' title='$($cells[$c].Replace("'", "&#39;"))'>$($cells[$c])</td>"
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

            # Each section is a collapsible <details>; close the previous one
            # (and the AI div inside it) first.
            if ($inAiSection) { $htmlLines.Add("</div>"); $inAiSection = $false }
            if ($inDetailsSection) { $htmlLines.Add("</details>") }

            # The AI part gets its own look, so nobody mistakes it for the
            # computed findings. The emoji is in the text: CSS ::before emoji
            # render unevenly across browsers.
            $isAiHeading = $headingText -match 'AI-Assisted'
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
    # The findings table as CSV, same columns as the report.
    param([array]$Findings, [array]$Rules, [string]$CsvPath)

    $ruleLookup = @{}
    foreach ($r in $Rules) {
        $ruleLookup[$r.Name] = [PSCustomObject]@{
            Src         = "$($r.SrcZone -join ';') / $(Get-DisplayAddress -Raw $r.SrcAddrRaw -Resolved $r.SrcAddr)"
            Dst         = "$($r.DstZone -join ';') / $(Get-DisplayAddress -Raw $r.DstAddrRaw -Resolved $r.DstAddr)"
            Application = if ($r.Application) { $r.Application -join "," } else { "any" }
            Service     = $r.ServiceRaw
            Action      = $r.Action
            Profile     = if ($r.Profile) { $r.Profile } else { "none" }
            Created     = $r.Created
            Modified    = $r.Modified
        }
    }

    # Suggested Fix / MITRE columns only exist once the AI step has filled
    # them (never on an offline run, so those CSVs are unchanged).
    $hasAiColumns = @($Findings | Where-Object { $_.PSObject.Properties['SuggestedFix'] -or $_.PSObject.Properties['MitreTag'] }).Count -gt 0

    $sorted = $Findings | Sort-Object { $SeverityOrder[$_.Severity] }
    $rows = foreach ($f in $sorted) {
        $ctx = $ruleLookup[$f.RuleName]
        $row = [PSCustomObject]@{
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
        if ($hasAiColumns) {
            $row | Add-Member -NotePropertyName 'Suggested Fix' -NotePropertyValue $(if ($f.PSObject.Properties['SuggestedFix']) { $f.SuggestedFix } else { '' })
            $row | Add-Member -NotePropertyName 'MITRE ATT&CK' -NotePropertyValue $(if ($f.PSObject.Properties['MitreTag']) { $f.MitreTag } else { '' })
        }
        $row
    }

    # No findings: write the header anyway (Export-Csv would write nothing),
    # so -CompareTo and -AnalyzeFindingsCsv still recognise the file.
    if (@($rows).Count -eq 0) {
        '"Severity","Rule","Source","Destination","Application","Service","Action","Profile","Created","Modified","Type","Detail"' | Set-Content -Path $CsvPath -Encoding utf8
    }
    else {
        $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
    }
    Write-Host "CSV findings written to $CsvPath" -ForegroundColor Green
}

function Export-FindingsJson {
    # JSON Lines, one finding per line, so a SIEM like Splunk takes each
    # line as an event with no extra config. The run metadata is repeated
    # on every line and there's no summary line, so every line has the same
    # shape. Suggested fix and MITRE only when the AI step filled them.
    param([array]$Findings, [array]$Rules, [string]$JsonPath, [string]$InputCsvPath, [string]$ToolVersion)

    $ruleLookup = @{}
    foreach ($r in $Rules) {
        $ruleLookup[$r.Name] = [PSCustomObject]@{
            SourceZone          = $r.SrcZone
            SourceAddress       = $r.SrcAddrRaw
            DestinationZone     = $r.DstZone
            DestinationAddress  = $r.DstAddrRaw
            Application         = if ($r.Application) { $r.Application } else { @("any") }
            Service             = $r.ServiceRaw
            Action              = $r.Action
            Profile             = if ($r.Profile) { $r.Profile } else { "none" }
        }
    }

    $generatedAt = (Get-Date).ToString("o")
    $sorted = $Findings | Sort-Object { $SeverityOrder[$_.Severity] }
    $lines = foreach ($f in $sorted) {
        $ctx = $ruleLookup[$f.RuleName]
        $row = [ordered]@{
            generated_at = $generatedAt
            tool         = "MooseAlto"
            tool_version = $ToolVersion
            input_file   = $InputCsvPath
            severity     = $f.Severity
            rule_name    = $f.RuleName
            type         = $f.Type
            detail       = $f.Detail
            source_zone         = if ($ctx) { $ctx.SourceZone } else { @() }
            source_address      = if ($ctx) { $ctx.SourceAddress } else { "" }
            destination_zone    = if ($ctx) { $ctx.DestinationZone } else { @() }
            destination_address = if ($ctx) { $ctx.DestinationAddress } else { "" }
            application  = if ($ctx) { $ctx.Application } else { @() }
            service      = if ($ctx) { $ctx.Service } else { "" }
            action       = if ($ctx) { $ctx.Action } else { "" }
            profile      = if ($ctx) { $ctx.Profile } else { "" }
        }
        if ($f.SuggestedFix) { $row["suggested_fix"] = $f.SuggestedFix }
        if ($f.MitreTag) { $row["mitre_attack"] = $f.MitreTag }
        ([PSCustomObject]$row | ConvertTo-Json -Depth 5 -Compress)
    }

    $lines | Out-File -FilePath $JsonPath -Encoding utf8
    Write-Host "JSON Lines findings written to $JsonPath ($($lines.Count) line(s), one finding per line - see README for a Splunk ingestion example)" -ForegroundColor Green
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

    if (@($rows).Count -eq 0) {
        '"Direction","Rule","Source","Destination","Application","Service","Action","Profile"' | Set-Content -Path $CsvPath -Encoding utf8
    }
    else {
        $rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
    }
    Write-Host "CSV inventory written to $CsvPath" -ForegroundColor Green
}

function Save-HtmlReport {
    # Markdown lines to HTML file.
    param([array]$MarkdownLines, [string]$HtmlPath)
    $htmlContent = ConvertTo-ReportHtml -MarkdownContent ($MarkdownLines -join "`n")
    $htmlContent | Out-File -FilePath $HtmlPath -Encoding utf8
}