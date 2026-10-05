# --------------------------------------------------------------------------
# Saved report: run context sidecar and AI analysis of a saved findings CSV
# --------------------------------------------------------------------------
#
# Every run writes <report>.context.json next to the findings CSV: all the
# rules, the inventory, the vendor and the settings. It never leaves the
# machine. -AnalyzeFindingsCsv reads the CSV (as edited by the user) plus
# that file and runs the AI step. Without the context (2.x reports) it
# still works, with less detail and the Palo Alto prompt.

$script:WithheldRuleNames = @()

function Protect-WithheldRuleNames {
    # Masks withheld rule names in text for Gemini. Longest first, so a
    # name containing another is replaced whole.
    param([string]$Text)
    if (-not $script:WithheldRuleNames -or $script:WithheldRuleNames.Count -eq 0 -or -not $Text) { return $Text }
    $i = 0
    $ordered = @($script:WithheldRuleNames | Sort-Object -Unique)
    $tokens = @{}
    foreach ($n in $ordered) { $i++; $tokens[$n] = "RULE-WITHHELD-$i" }
    foreach ($n in ($ordered | Sort-Object Length -Descending)) {
        $Text = $Text.Replace($n, $tokens[$n])
    }
    return $Text
}

function Get-ContextPath {
    param([Parameter(Mandatory)][string]$FindingsCsvPath)
    $base = if ($FindingsCsvPath -match '\.csv$') { $FindingsCsvPath -replace '\.csv$', '' } else { $FindingsCsvPath }
    return "$base.context.json"
}

function Save-RunContext {
    param(
        [Parameter(Mandatory)][string]$FindingsCsvPath,
        [array]$Rules, [array]$Inventory, [hashtable]$Settings
    )
    $path = Get-ContextPath -FindingsCsvPath $FindingsCsvPath
    $ctx = [ordered]@{
        format    = 'moosealto-context'
        version   = 1
        settings  = $Settings
        # filtered, or an empty list is written as [null]
        rules     = @($Rules | Where-Object { $null -ne $_ })
        inventory = @($Inventory | Where-Object { $null -ne $_ })
    }
    try {
        $ctx | ConvertTo-Json -Depth 5 -Compress | Set-Content -Path $path -Encoding UTF8
        Write-Host "Run context written to $path (local only, used by -AnalyzeFindingsCsv)" -ForegroundColor DarkGray
    }
    catch {
        Write-Host "Note: could not write the run context file ($path): $($_.Exception.Message). The report is complete; only a later -AnalyzeFindingsCsv on it will have less context." -ForegroundColor Yellow
    }
}

function New-RuleFromFindingRow {
    # A bare rule rebuilt from a CSV row, for rules the context doesn't know.
    param($Row)
    $splitSide = {
        param([string]$Text)
        $i = $Text.IndexOf(' / ')
        if ($i -ge 0) { return @($Text.Substring(0, $i), $Text.Substring($i + 3)) }
        return @($Text, '')
    }
    $src = & $splitSide "$($Row.Source)"
    $dst = & $splitSide "$($Row.Destination)"
    $app = "$($Row.Application)"
    return [PSCustomObject]@{
        Index = -1; Name = $Row.Rule
        SrcZone = @($src[0] -split ';' | Where-Object { $_ }); SrcAddrRaw = $src[1]; SrcAddr = $null
        DstZone = @($dst[0] -split ';' | Where-Object { $_ }); DstAddrRaw = $dst[1]; DstAddr = $null
        Application = $(if ($app -and $app -ne 'any') { @($app -split ',') } else { $null })
        ServiceRaw = "$($Row.Service)"; Service = $null
        Action = "$($Row.Action)"; Profile = "$($Row.Profile)"; Tags = ''; Disabled = $false
        HitCount = ''; UsageStatus = ''; LastHit = ''; Options = ''; HasOptionsColumn = $false
        Created = "$($Row.Created)"; Modified = "$($Row.Modified)"
        HasCreatedColumn = [bool]$Row.Created; HasModifiedColumn = [bool]$Row.Modified
        SrcAddrTokenCount = 0; DstAddrTokenCount = 0
    }
}

function Import-SavedReport {
    # Returns @{ Findings; Rules; Inventory; Settings; HasContext } or $null
    # when the file is not a MooseAlto findings CSV.
    param([Parameter(Mandatory)][string]$FindingsCsvPath)
    try { $rows = @(Import-Csv -Path $FindingsCsvPath) }
    catch { Write-Host "ERROR: $FindingsCsvPath could not be read as CSV: $($_.Exception.Message)" -ForegroundColor Red; return $null }
    if ($rows.Count -eq 0) {
        # A run with no findings writes a header-only CSV.
        $header = "$(Get-Content -Path $FindingsCsvPath -TotalCount 1 -ErrorAction SilentlyContinue)"
        if ($header -match '"?Severity"?,"?Rule"?,' -and $header -match '"?Type"?,"?Detail"?') {
            Write-Host "No findings in $FindingsCsvPath (the original run found nothing): nothing to analyze." -ForegroundColor Yellow
            return $null
        }
    }
    $cols = if ($rows.Count -gt 0) { @($rows[0].PSObject.Properties.Name) } else { @() }
    $missing = @(@('Severity', 'Rule', 'Type', 'Detail') | Where-Object { $cols -notcontains $_ })
    if ($rows.Count -eq 0 -or $missing.Count -gt 0) {
        Write-Host "ERROR: $FindingsCsvPath is not a MooseAlto findings CSV$(if ($missing.Count) { " (missing column(s): $($missing -join ', '))" } else { ' (no rows)' })." -ForegroundColor Red
        return $null
    }

    $findings = @($rows | ForEach-Object {
        [PSCustomObject]@{ RuleName = $_.Rule; Severity = $_.Severity; Type = $_.Type; Detail = $_.Detail }
    })

    $contextPath = Get-ContextPath -FindingsCsvPath $FindingsCsvPath
    if (-not (Test-Path $contextPath) -and $FindingsCsvPath -match '_ai\.csv$') {
        $contextPath = Get-ContextPath -FindingsCsvPath ($FindingsCsvPath -replace '_ai\.csv$', '.csv')
    }
    $rules = @(); $inventory = @(); $settings = @{}; $hasContext = $false
    if (Test-Path $contextPath) {
        try {
            $ctx = Get-Content -Path $contextPath -Raw | ConvertFrom-Json
            if ($ctx.format -ne 'moosealto-context') { throw "not a MooseAlto context file" }
            $rules = @($ctx.rules | Where-Object { $null -ne $_ })
            $inventory = @($ctx.inventory | Where-Object { $_ })
            foreach ($p in $ctx.settings.PSObject.Properties) { $settings[$p.Name] = $p.Value }
            $hasContext = $true
            $gen = if ($settings.generated -is [datetime]) { $settings.generated.ToString('yyyy-MM-dd HH:mm') } else { "$($settings.generated)" }
            Write-Host "Loaded run context from $contextPath ($($rules.Count) rule(s), generated $gen by MooseAlto $($settings.toolVersion), $($settings.vendor))." -ForegroundColor Green
        }
        catch {
            Write-Host "Note: $contextPath could not be read ($($_.Exception.Message)); continuing from the CSV alone." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "Note: no run context file next to the CSV ($contextPath). Continuing from the CSV alone: the summary covers only rules that have findings, Tags cannot be offered, and the Palo Alto prompt is used." -ForegroundColor Yellow
    }

    # Rules named in the CSV but not in the context (or no context at all).
    $known = New-Object System.Collections.Generic.HashSet[string]
    foreach ($r in $rules) { [void]$known.Add($r.Name) }
    $added = 0
    foreach ($row in $rows) {
        if ($row.Rule -eq '(ruleset-wide)' -or $known.Contains($row.Rule)) { continue }
        $rules += New-RuleFromFindingRow -Row $row
        [void]$known.Add($row.Rule)
        $added++
    }
    if ($hasContext -and $added -gt 0) {
        Write-Host "Note: $added rule name(s) in the CSV are not in the run context (renamed or edited in the CSV); their table columns come from the CSV, and they count as extra rules in the summary." -ForegroundColor Yellow
    }
    $removedCount = 0
    if ($hasContext -and $settings.findingsCount) { $removedCount = [int]$settings.findingsCount - $findings.Count }
    if ($removedCount -gt 0) {
        Write-Host "Note: the CSV has $removedCount finding(s) fewer than the original run ($($settings.findingsCount)); only the $($findings.Count) left in the CSV are used." -ForegroundColor Yellow
    }

    # Rules the user took out of the CSV: also mask their names where other
    # findings quote them (shadowing, anomalies).
    $withheld = @()
    if ($hasContext -and $settings.findingRules) {
        $inCsv = New-Object System.Collections.Generic.HashSet[string]
        foreach ($f in $findings) { [void]$inCsv.Add($f.RuleName) }
        $withheld = @($settings.findingRules | Where-Object { $_ -and -not $inCsv.Contains($_) })
        if ($withheld.Count -gt 0) {
            Write-Host "Note: $($withheld.Count) rule(s) with findings in the original run are no longer in the CSV; their names will also be masked (RULE-WITHHELD-N) inside the text of the findings that are sent." -ForegroundColor Yellow
        }
    }

    return @{ Findings = $findings; Rules = $rules; Inventory = $inventory; Settings = $settings; HasContext = $hasContext; WithheldRules = $withheld }
}
