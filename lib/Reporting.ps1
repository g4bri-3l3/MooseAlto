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
    # Dependency-free pie chart: plain SVG computed from arc trigonometry,
    # no charting library. Parallel arrays instead of a hashtable so slice
    # order is exactly what the caller specifies (hashtable enumeration
    # order isn't guaranteed in PowerShell, which would make the legend
    # and slice order shuffle between runs on the same data).
    param([string[]]$Labels, [int[]]$Values, [string[]]$Colors, [int]$Size = 170)

    $total = ($Values | Measure-Object -Sum).Sum
    if ($total -le 0) { return "<p style='color:#888;font-size:12px;'>No data.</p>" }

    $cx = $Size / 2
    $cy = $Size / 2
    $r = ($Size / 2) - 4

    $slices = ""
    $legend = ""
    $cumulative = 0
    for ($i = 0; $i -lt $Labels.Count; $i++) {
        $value = $Values[$i]
        if ($value -le 0) { continue }
        $color = $Colors[$i]
        $startAngle = ($cumulative / $total) * 360
        $cumulative += $value
        $endAngle = ($cumulative / $total) * 360

        if ($value -eq $total) {
            # A single 100% category can't be drawn as a zero-length arc;
            # a plain circle is the correct (and simpler) shape for it.
            $slices += "<circle cx='$cx' cy='$cy' r='$r' fill='$color' />"
        }
        else {
            $startRad = $startAngle * [Math]::PI / 180
            $endRad = $endAngle * [Math]::PI / 180
            $x1 = [Math]::Round($cx + $r * [Math]::Sin($startRad), 2)
            $y1 = [Math]::Round($cy - $r * [Math]::Cos($startRad), 2)
            $x2 = [Math]::Round($cx + $r * [Math]::Sin($endRad), 2)
            $y2 = [Math]::Round($cy - $r * [Math]::Cos($endRad), 2)
            $largeArc = if (($endAngle - $startAngle) -gt 180) { 1 } else { 0 }
            $slices += "<path d='M $cx,$cy L $x1,$y1 A $r,$r 0 $largeArc,1 $x2,$y2 Z' fill='$color' />"
        }
        $pct = [Math]::Round(($value / $total) * 100, 1)
        $legend += "<div class='pie-legend-item'><span class='pie-legend-swatch' style='background:$color'></span>$($Labels[$i]) ($value, $pct%)</div>"
    }
    return "<div class='pie-chart-wrap'><svg viewBox='0 0 $Size $Size' width='$Size' height='$Size'>$slices</svg><div class='pie-legend'>$legend</div></div>"
}

function Get-ReportLines {
    param([array]$Findings, [array]$Inventory, [string]$InputCsvPath, [array]$Rules, [string]$ElapsedText = "", [array]$InternetZoneSet = @())

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
        }
    }

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
    $lines += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
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
    if ($ElapsedText) {
        $lines += "| Processing time | $ElapsedText |"
    }
    $lines += ""

    # -------- Rule Statistics --------
    # A quick visual overview before the detailed findings table: how the
    # ruleset breaks down by action, direction, and profile coverage, plus
    # where the findings severity actually lands. Uses the same
    # zone/address "touches internet" signals as the deterministic checks,
    # but a simpler direction classification than the Inventory's (that
    # one deliberately distinguishes "definite" from "ambiguous" evidence
    # to pick the single best label per rule; here it's an aggregate count
    # across the whole ruleset, where that extra precision matters less
    # than just being reasonably representative).
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
    $statCardsHtml += "</div>"

    $severityPie = Get-SvgPieChart -Labels @("Critical", "High", "Medium", "Low") -Values @($critCount, $highCount, $medCount, $lowCount) -Colors @("#d9534f", "#f0ad4e", "#f7d774", "#adb5bd")
    $directionPie = Get-SvgPieChart -Labels @("Inbound", "Outbound", "Both sides", "Internal only") -Values @($inboundCount, $outboundCount, $bothCount, $internalCount) -Colors @("#5b8def", "#7bc67e", "#c77dd2", "#adb5bd")

    $chartsHtml = "<div class='chart-row'>"
    $chartsHtml += "<div><div class='pie-chart-title'>Findings by severity</div>$severityPie</div>"
    $chartsHtml += "<div><div class='pie-chart-title'>Allow rules by direction</div>$directionPie</div>"
    $chartsHtml += "</div>"

    $topAppsHtml = ""
    if ($topApps) {
        $topAppsHtml = "<div><div class='pie-chart-title'>Most common applications (allow rules)</div><table><tr><th>Application</th><th>Rule count</th></tr>"
        foreach ($entry in $topApps) {
            $topAppsHtml += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>"
        }
        $topAppsHtml += "</table></div>"
    }
    $topServicesHtml = ""
    if ($topServices) {
        $topServicesHtml = "<div><div class='pie-chart-title'>Most common services (allow rules, no App-ID)</div><table><tr><th>Service</th><th>Rule count</th></tr>"
        foreach ($entry in $topServices) {
            $topServicesHtml += "<tr><td>$($entry.Name)</td><td>$($entry.Value)</td></tr>"
        }
        $topServicesHtml += "</table></div>"
    }
    $appServiceRowHtml = ""
    if ($topAppsHtml -or $topServicesHtml) {
        $appServiceRowHtml = "<div class='chart-row'>$topAppsHtml$topServicesHtml</div>"
    }

    $statsHtmlBlock = $statCardsHtml + $chartsHtml + $appServiceRowHtml
    $statsBytes = [System.Text.Encoding]::UTF8.GetBytes($statsHtmlBlock)
    $lines += "%%RAWHTML_BASE64%%$([System.Convert]::ToBase64String($statsBytes))"
    $lines += ""

    $lines += "## Algorithmic-based Findings"
    $lines += ""
    $lines += "| Severity | Rule | Source | Destination | Application | Service | Action | Profile | Type | Detail |"
    $lines += "|---|---|---|---|---|---|---|---|---|---|"
    foreach ($f in $sorted) {
        $ctx = $ruleLookup[$f.RuleName]
        $src = if ($ctx) { $ctx.Src } else { "" }
        $dst = if ($ctx) { $ctx.Dst } else { "" }
        $app = if ($ctx) { $ctx.Application } else { "" }
        $svc = if ($ctx) { $ctx.Service } else { "" }
        $action = if ($ctx) { $ctx.Action } else { "" }
        $profile = if ($ctx) { $ctx.Profile } else { "" }
        $lines += "| $($f.Severity) | $($f.RuleName) | $src | $dst | $app | $svc | $action | $profile | $($f.Type) | $($f.Detail) |"
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
    $lines += "| Rule | Direction | Source | Destination | Application | Service | Action | Profile |"
    $lines += "|---|---|---|---|---|---|---|---|"
    foreach ($r in $sortedInventory) {
        $lines += "| $($r.RuleName) | $($r.Direction) | $($r.Src) | $($r.Dst) | $($r.Application) | $($r.Service) | $($r.Action) | $($r.Profile) |"
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
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a1a1a; }
  h1 { border-bottom: 2px solid #333; padding-bottom: 8px; }
  h2 { margin: 0; }
  h3 { margin-top: 20px; }
  table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 12px; }
  th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #2d2d2d; color: white; }
  tr.severity-critical td:first-child { background: #f8d7da; font-weight: bold; }
  tr.severity-high td:first-child { background: #fde2c8; font-weight: bold; }
  tr.severity-medium td:first-child { background: #fff3cd; }
  tr.severity-low td:first-child { background: #e2e3e5; }
  blockquote { background: #fff8e1; border-left: 4px solid #f0ad4e; margin: 12px 0; padding: 10px 14px; }
  code { background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-family: Consolas, monospace; }
  .moose-logo { font-family: Consolas, 'Courier New', monospace; font-size: 10px; line-height: 1.1; color: #b8860b; white-space: pre; float: right; margin: 0 0 10px 20px; }
  details { clear: both; }
  ol { padding-left: 22px; }
  ol li { margin: 6px 0; }
  .ai-section { background: #f3f0ff; border: 1px solid #d4c8f7; border-left: 4px solid #7c5cd6; border-radius: 4px; padding: 4px 20px 16px 20px; margin-top: 16px; }
  .ai-section h2, .ai-section h3 { border-bottom: none; }
  .ai-badge { display: inline-block; font-size: 11px; font-weight: bold; color: #7c5cd6; background: #ece5ff; border-radius: 10px; padding: 2px 10px; margin-bottom: 8px; }
  details { margin-top: 32px; }
  details > summary { cursor: pointer; list-style: none; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  details > summary::-webkit-details-marker { display: none; }
  details > summary h2 { display: inline-block; margin: 0; border-bottom: none; padding-bottom: 0; }
  details > summary::before { content: '\25b6'; display: inline-block; margin-right: 8px; font-size: 13px; color: #666; transition: transform 0.15s ease; }
  details[open] > summary::before { transform: rotate(90deg); }
  tr.filter-row td { background: #f7f7f7; padding: 4px 6px; }
  tr.filter-row input { width: 100%; box-sizing: border-box; font-size: 11px; padding: 3px 5px; border: 1px solid #bbb; border-radius: 3px; font-family: inherit; }
  .filter-status { font-size: 11px; color: #666; margin: 4px 0 0 2px; }
  .filter-status button { font-size: 11px; padding: 2px 8px; border: 1px solid #bbb; border-radius: 3px; background: #f0f0f0; cursor: pointer; }
  .filter-status button:hover { background: #e5e5e5; }
  .action-allow { color: #1a7a1a; font-weight: bold; }
  .action-deny { color: #b02a2a; font-weight: bold; }
  .stat-grid { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0 20px 0; }
  .stat-card { background: #f7f7f7; border: 1px solid #ddd; border-radius: 6px; padding: 10px 16px; min-width: 130px; }
  .stat-card .stat-value { font-size: 22px; font-weight: bold; color: #1a1a1a; }
  .stat-card .stat-label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }
  .chart-row { display: flex; flex-wrap: wrap; gap: 36px; margin: 12px 0 24px 0; }
  .pie-chart-wrap { display: flex; align-items: center; gap: 16px; }
  .pie-chart-title { font-size: 13px; font-weight: bold; margin-bottom: 8px; color: #333; }
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
                $htmlLines.Add("<table>")
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
                switch ($cells[0]) {
                    "Critical" { $rowClass += " severity-critical" }
                    "High"     { $rowClass += " severity-high" }
                    "Medium"   { $rowClass += " severity-medium" }
                    "Low"      { $rowClass += " severity-low" }
                }
                $cellsHtml = for ($c = 0; $c -lt $cells.Count; $c++) {
                    if ($c -eq $actionColumnIndex) {
                        $actionLower = $cells[$c].Trim().ToLower()
                        if ($actionLower -eq "allow") { "<td><span class='action-allow'>$($cells[$c])</span></td>" }
                        elseif ($actionLower -eq "deny" -or $actionLower -eq "drop") { "<td><span class='action-deny'>$($cells[$c])</span></td>" }
                        else { "<td>$($cells[$c])</td>" }
                    }
                    else { "<td>$($cells[$c])</td>" }
                }
                $htmlLines.Add("<tr class='$rowClass'>" + ($cellsHtml -join "") + "</tr>")
            }
            continue
        }
        elseif ($inTable) {
            $htmlLines.Add("</tbody></table>")
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
