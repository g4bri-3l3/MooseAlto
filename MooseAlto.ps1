<#
.SYNOPSIS
    MooseAlto: Palo Alto / Panorama-specific firewall rule hygiene analyzer (PowerShell).

.DESCRIPTION
    Hybrid deterministic + optional LLM-assisted review, built around PAN-OS's
    actual rule model (Zone + Address + Application, not just source/dest/port).
    The deterministic report is generated and saved FIRST, with real IP
    addresses intact (local-only output). Only if you confirm at the prompt
    afterward does anything get sent to Gemini, and at that point every IP
    address/CIDR in the outbound text is masked to a placeholder token first,
    so no real network topology leaves your machine.

    Requires the lib\ subfolder alongside this script:
      lib\IpHelpers.ps1       CIDR/IP parsing and containment
      lib\Parsing.ps1         CSV / rule / address-object parsing
      lib\DetectionRules.ps1  risky ports/apps data plus all finding logic
      lib\Reporting.ps1       Markdown/HTML rendering plus Gemini integration
    DetectionRules.ps1 is the one to edit when adding or tuning a check.
    Everything else rarely needs to change.

    Expected CSV schema: a Panorama/PAN-OS security rulebase CSV export
    (Policies > Security > PDF/CSV). Column layout is read from the file's
    own header row, which is fixed up automatically to handle two real-world
    quirks seen in actual exports:
      * An unnamed leading row-number column (blank header). Import-Csv's
        own auto-detection renames ALL headers to H1/H2/... when it hits
        this, misaligning every named column. This script reads and repairs
        the header itself instead of trusting that auto-detection.
      * Multi-value fields (zones, applications, addresses) are separated
        with ";" within a single CSV cell, not ",", since "," is already the
        CSV delimiter.
    Not every export includes "Disabled" or "Rule Usage: Hit Count" columns
    (e.g. a plain rulebase config export vs. a rule-usage report). Both are
    treated as optional; their related checks are simply skipped when absent
    rather than causing an error.

    Address values can also be:
      * a plain CIDR/IP (10.1.2.0/24): real CIDR containment applies
      * an IP range (10.0.0.0-10.255.255.255): kept as an opaque token
        (exact-match only), true range arithmetic is not implemented
      * negated ("[Negate]  10.0.0.0-10.255.255.255"), PAN-OS's "does NOT
        match" exclusion, also kept opaque
      * an address-object/group name: opaque, can't be resolved from a CSV
        export alone

.PARAMETER InputCsv
    Path to the Panorama/PAN-OS rules CSV export. If omitted, the script
    shows a banner and walks through an interactive setup prompt instead
    of failing. Useful when double-clicking the script rather than
    running it from a command line.
.PARAMETER OutHtml
    Path to write the HTML report (default: report_<timestamp>.html, so
    repeated runs never overwrite each other).
.PARAMETER OutCsv
    Path to write the findings CSV (default: report_<timestamp>.csv, same
    timestamp as OutHtml). A second file with the same base name plus
    "_inventory" is always written alongside it, covering the Internet
    Exposure Inventory as its own CSV.
.PARAMETER InternetZones
    Comma-separated zone names treated as internet-facing.
.PARAMETER AddressObjectsCsv
    Optional path to an Address Objects CSV export, to resolve named
    objects to their real IP/CIDR instead of treating them as opaque.
.PARAMETER AddressGroupsCsv
    Optional path to an Address Groups CSV export, to resolve named
    (static) groups the same way, including nested groups.
.PARAMETER StaleHitDays
    A rule with a non-zero hit count but a Last Hit date older than this
    many days is flagged as stale (default 365). Only applies if your
    export includes a Last Hit column.
.PARAMETER MaxAddressListSize
    A rule listing more than this many individual addresses in its source
    or destination (default 25) is flagged as an oversized address list,
    regardless of whether any single entry is risky.
.PARAMETER CompareTo
    Path to a findings CSV from a previous MooseAlto run. When set, the
    report includes a Comparison section showing which findings are new,
    resolved, or still present since that run. Matched by (rule name,
    finding type), so renaming a rule between runs will show up as a
    resolved finding under the old name and a new one under the new name.
.PARAMETER SkipLLM
    Never prompt for or send data to Gemini. Deterministic report only.
.PARAMETER ApiKey
    Gemini API key. Defaults to $env:GEMINI_API_KEY.
.PARAMETER Model
    Gemini model name. Defaults to gemini-3.5-flash.

.EXAMPLE
    .\MooseAlto.ps1 -InputCsv export.csv -OutHtml report.html -OutCsv report.csv
#>

[CmdletBinding()]
Param(
    [string]$InputCsv = "",
    [string]$OutHtml = "",
    [string]$OutCsv = "",
    [string]$InternetZones = "untrust,internet,outside,external",
    [string]$CriticalZones = "",
    [string]$AddressObjectsCsv = "",
    [string]$AddressGroupsCsv = "",
    [int]$StaleHitDays = 365,
    [int]$MaxAddressListSize = 25,
    [string]$CompareTo = "",
    [switch]$SkipLLM,
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model = "gemini-3.5-flash"
)

# Both default filenames share one timestamp, computed once, so a given run
# always produces a matching pair (report_<ts>.html / report_<ts>.csv)
# rather than two defaults that could differ by a second if computed
# independently.
$defaultTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutHtml) { $OutHtml = "report_$defaultTimestamp.html" }
if (-not $OutCsv) { $OutCsv = "report_$defaultTimestamp.csv" }

# --------------------------------------------------------------------------
# Banner. Always shown, whether or not parameters were supplied.
# --------------------------------------------------------------------------

$script:MooseAltoVersion = "1.7"

function Show-Banner {
    $lines = @(
        '######################################################################'
        '#  ___            ___                                                #'
        "# /   \          /   \                  MooseAlto v$script:MooseAltoVersion               #"
        '# \_   \        /  __/         Palo Alto Firewall Rule Analyzer      #'
        '#  _\   \      /  /__                                                #'
        '#  \___  \____/   __/                                                #'
        '#      \_       _/                                                   #'
        '#        | @ @  \_                     No blind spots.               #'
        '#        |                            Stay moose-alert.              #'
        '#      _/     /\                         Stay secure.                #'
        '#     /o)  (o/\ \_                                                   #'
        '#     \_____/ /                                                      #'
        '#       \____/              https://github.com/g4bri-3l3/MooseAlto   #'
        '######################################################################'
    )
    $lineCount = $lines.Count
    for ($i = 0; $i -lt $lineCount; $i++) {
        $line = $lines[$i]
        # Italic only renders with ANSI/VT support ($PSStyle exists on
        # PowerShell 7.2+). Falls back to plain text otherwise. Windows
        # PowerShell 5.1's classic console host doesn't reliably support it.
        $isTaglineLine = $line -match 'blind spots|moose-alert|Stay secure'
        if ($isTaglineLine -and $PSStyle) {
            Write-Host "$($PSStyle.Italic)$line$($PSStyle.Reset)" -ForegroundColor DarkYellow
        }
        else {
            Write-Host $line -ForegroundColor DarkYellow
        }

        # Cascading reveal: each line lands shortly after the previous one,
        # so the banner builds itself instead of dumping all at once. The
        # closing border pauses longer, giving the whole thing a
        # "settling into place" finish rather than stopping abruptly.
        if ($i -eq $lineCount - 1) {
            Start-Sleep -Milliseconds 450
        }
        else {
            Start-Sleep -Milliseconds 70
        }
    }
    Write-Host ""
}

Show-Banner

# --------------------------------------------------------------------------
# Interactive setup. Only runs if the script was launched without
# -InputCsv (e.g. double-clicked or run with no arguments). Any parameter
# already supplied on the command line is respected and never re-prompted.
# Press Enter on any optional prompt to keep the default shown in [brackets].
# --------------------------------------------------------------------------

if (-not $InputCsv) {
    Write-Host "No parameters supplied. Make a choice:" -ForegroundColor Cyan
    Write-Host "  1. Start interactive setup"
    Write-Host "  2. Exit"
    $menuChoice = $null
    while ($menuChoice -ne "1" -and $menuChoice -ne "2") {
        $menuChoice = Read-Host "Enter choice"
    }
    if ($menuChoice -eq "2") {
        Write-Host "Exiting."
        return
    }
    Write-Host ""
    Write-Host "Interactive setup (press Enter to accept a default)." -ForegroundColor Cyan
    Write-Host ""

    while (-not $InputCsv) {
        $InputCsv = Read-Host "CSV file to analyze (required)"
    }

    $inputVal = Read-Host "-OutHtml, HTML report path [$OutHtml]"
    if ($inputVal) { $OutHtml = $inputVal }

    $inputVal = Read-Host "-OutCsv, findings CSV path [$OutCsv]"
    if ($inputVal) { $OutCsv = $inputVal }

    $inputVal = Read-Host "Internet-facing zone names, comma-separated [$InternetZones]"
    if ($inputVal) { $InternetZones = $inputVal }

    $inputVal = Read-Host "Critical zone names e.g. SWIFT/CDE/ATM, comma-separated [none]"
    if ($inputVal) { $CriticalZones = $inputVal }

    $inputVal = Read-Host "Address Objects CSV path, optional [none]"
    if ($inputVal) { $AddressObjectsCsv = $inputVal }

    $inputVal = Read-Host "Address Groups CSV path, optional [none]"
    if ($inputVal) { $AddressGroupsCsv = $inputVal }

    $inputVal = Read-Host "Days since last hit to flag a rule as stale [$StaleHitDays]"
    if ($inputVal -match '^\d+$') { $StaleHitDays = [int]$inputVal }

    $inputVal = Read-Host "Max individual addresses in a list before flagging it as oversized [$MaxAddressListSize]"
    if ($inputVal -match '^\d+$') { $MaxAddressListSize = [int]$inputVal }

    $inputVal = Read-Host "Compare against a previous findings CSV, optional [none]"
    if ($inputVal) { $CompareTo = $inputVal }

    $inputVal = Read-Host "Skip the AI analysis step entirely? (y/N)"
    if ($inputVal -match '^[Yy]') { $SkipLLM = $true }

    if (-not $SkipLLM -and -not $ApiKey) {
        $inputVal = Read-Host "Gemini API key (not found in GEMINI_API_KEY env var, leave blank to skip AI analysis for this run)"
        if ($inputVal) { $ApiKey = $inputVal }
    }

    Write-Host ""
}

$InternetZoneSet = @($InternetZones -split "," | ForEach-Object { $_.Trim().ToLower() })
$CriticalZoneSet = @($CriticalZones -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" })


# --------------------------------------------------------------------------
# Load library modules. Each file owns one concern. DetectionRules.ps1 is
# the one to edit when adding/tuning a check; the others rarely change.
# --------------------------------------------------------------------------

. (Join-Path $PSScriptRoot "lib\IpHelpers.ps1")
. (Join-Path $PSScriptRoot "lib\Parsing.ps1")
. (Join-Path $PSScriptRoot "lib\DetectionRules.ps1")
. (Join-Path $PSScriptRoot "lib\Reporting.ps1")

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

# Without this, a missing/mistyped path doesn't stop the script here - it
# falls through into Import-PaloAltoRules, which throws a cascade of
# non-terminating errors (Get-Content, ConvertFrom-Csv, then null-index
# errors deeper in DetectionRules.ps1) but keeps running regardless, and
# ends up producing a "successful looking" report claiming 0 rules
# analyzed instead of a clear failure. A wrong path should stop here with
# one unambiguous message, not limp through and produce a misleading
# report.
if (-not (Test-Path -Path $InputCsv -PathType Leaf)) {
    Write-Host "ERROR: Input file not found: $InputCsv" -ForegroundColor Red
    Write-Host "Check the path and try again." -ForegroundColor Red
    return
}
if ((Get-Item -Path $InputCsv).Length -eq 0) {
    Write-Host "ERROR: Input file is empty: $InputCsv" -ForegroundColor Red
    return
}

$processingStartTime = Get-Date

$rules = Import-PaloAltoRules -Path $InputCsv

# Captured before any address-object/group resolution below, which
# replaces $rule.SrcAddr/DstAddr with the fully expanded member list.
# oversized_address_list needs the count of what the rule author actually
# wrote (e.g. two group names), not how many individual addresses those
# groups happen to expand to - a rule referencing two clearly-named,
# well-organized groups isn't the same audit concern as one with 100
# individually-enumerated IPs pasted directly into the field, even if the
# resolved address count comes out the same.
foreach ($rule in $rules) {
    $rule | Add-Member -NotePropertyName SrcAddrTokenCount -NotePropertyValue $(if ($null -eq $rule.SrcAddr) { 0 } else { $rule.SrcAddr.Count })
    $rule | Add-Member -NotePropertyName DstAddrTokenCount -NotePropertyValue $(if ($null -eq $rule.DstAddr) { 0 } else { $rule.DstAddr.Count })
}

$addressObjects = Import-AddressObjects -Path $AddressObjectsCsv
$addressGroups = Import-AddressGroups -Path $AddressGroupsCsv
if ($addressObjects.Count -gt 0 -or $addressGroups.Count -gt 0) {
    foreach ($rule in $rules) {
        $rule.SrcAddr = Resolve-AddressList -AddrTokens $rule.SrcAddr -Objects $addressObjects -Groups $addressGroups
        $rule.DstAddr = Resolve-AddressList -AddrTokens $rule.DstAddr -Objects $addressObjects -Groups $addressGroups
    }
    Write-Host "Resolved address objects/groups: $($addressObjects.Count) object(s), $($addressGroups.Count) group(s) loaded." -ForegroundColor Green
}

$findings = Invoke-DeterministicChecks -Rules $rules -InternetZoneSet $InternetZoneSet -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize
$inventory = Build-InternetExposureInventory -Rules $rules -InternetZoneSet $InternetZoneSet

Export-FindingsCsv -Findings $findings -Rules $rules -CsvPath $OutCsv
if ($OutCsv -match '\.csv$') {
    $inventoryCsvPath = $OutCsv -replace '\.csv$', '_inventory.csv'
}
else {
    $inventoryCsvPath = "${OutCsv}_inventory.csv"
}
Export-InventoryCsv -Inventory $inventory -CsvPath $inventoryCsvPath

# 1) Render and save the deterministic report FIRST, real IPs, local only.
# Kept in memory as markdown lines throughout; only ever written to disk as
# HTML (no intermediate .md file) via Save-HtmlReport. Timer stops here,
# right before writing, so the reported duration covers parsing through
# report generation but not the separate, optional, network-dependent
# Gemini step later.
$processingElapsed = (Get-Date) - $processingStartTime
$elapsedText = if ($processingElapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f [int]$processingElapsed.TotalMinutes, $processingElapsed.Seconds } else { "{0:N1}s" -f $processingElapsed.TotalSeconds }

$reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $InputCsv -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM
Save-HtmlReport -MarkdownLines $reportLines -HtmlPath $OutHtml

Write-Host "Report written to $OutHtml" -ForegroundColor Green
Write-Host "Rules parsed: $($rules.Count)"
Write-Host "Processing time: $elapsedText"

$critCount = @($findings | Where-Object { $_.Severity -eq "Critical" }).Count
$highCount = @($findings | Where-Object { $_.Severity -eq "High" }).Count
$medCount = @($findings | Where-Object { $_.Severity -eq "Medium" }).Count
$lowCount = @($findings | Where-Object { $_.Severity -eq "Low" }).Count

Write-Host -NoNewline "Deterministic findings: $($findings.Count) ("
Write-Host -NoNewline "$critCount Critical" -ForegroundColor Red
Write-Host -NoNewline ", "
Write-Host -NoNewline "$highCount High" -ForegroundColor Yellow
Write-Host -NoNewline ", "
Write-Host -NoNewline "$medCount Medium" -ForegroundColor DarkYellow
Write-Host -NoNewline ", "
Write-Host -NoNewline "$lowCount Low" -ForegroundColor Gray
Write-Host ")"

Write-Host "Internet-facing rules in inventory: $($inventory.Count)"

if ($SkipLLM) {
    return
}

if ($findings.Count -eq 0) {
    Write-Host "No deterministic findings to summarize. Skipping the Gemini call (avoids the model inventing plausible-sounding but ungrounded content)."
    return
}

# 2) Ask before sending anything externally.
Write-Host "Note: IP/CIDR addresses in finding details are masked before sending. Rule names are NOT masked and are sent as-is (the summary needs them to be readable). If your naming convention includes anything sensitive (customer names, internal codenames, hostnames), rename those rules first or decline below." -ForegroundColor Yellow
$answer = Read-Host "Send the results to Gemini for additional analysis? (Y/N)"

if ($answer -notmatch '^[Yy]') {
    Write-Host "Ok, nothing sent to Gemini. Deterministic report saved to $OutHtml."
    return
}

if (-not $ApiKey) {
    Write-Host "ERROR: GEMINI_API_KEY not set. Cannot proceed with AI analysis." -ForegroundColor Red
    return
}

# 3) Choose what to send. Disabled rules are never sent. A disabled rule
# isn't an active risk, so there's nothing for the AI to usefully prioritize
# about it.
$InternetFindingTypes = @(
    "inbound_from_any_public_ip", "inbound_risky_application", "inbound_risky_port",
    "outbound_any_public_defined_app", "outbound_defined_dest_any_app",
    "no_security_profile_on_exposed_rule"
)

$scopeAnswer = Read-Host "Send all findings, or only internet-exposure-related ones? (A=All, I=Internet)"
$sendOnlyInternet = ($scopeAnswer -match '^[Ii]')

$findingsToSend = @($findings | Where-Object { $_.Type -ne "disabled_rule_present" })
if ($sendOnlyInternet) {
    $findingsToSend = @($findingsToSend | Where-Object { $InternetFindingTypes -contains $_.Type })
}

if ($findingsToSend.Count -eq 0) {
    Write-Host "No findings in the selected category. Skipping the Gemini call."
    return
}

# 4) Mask every IP/CIDR in the finding details before building the outbound prompt.
$ipMap = @{}
$maskedLines = @("Deterministic findings:")
foreach ($f in $findingsToSend) {
    $maskedDetail = Protect-IPAddresses -Text $f.Detail -Map $ipMap
    $maskedLines += "- [$($f.Severity)] $($f.RuleName) ($($f.Type)): $maskedDetail"
}

# 4b) Tags are separate free text written by whoever maintains the ruleset -
# could contain project codenames, ticket numbers, or other internal notes.
# Ask separately before including them, rather than sending them by default.
$includeTags = $false
$tagsAnswer = Read-Host "Also include rule Tags in the prompt sent to Gemini? They may contain sensitive information (Y/N)"
if ($tagsAnswer -match '^[Yy]') {
    $includeTags = $true
    $flaggedRuleNames = @($findingsToSend | Select-Object -ExpandProperty RuleName -Unique)
    $tagsLines = @("", "Tags for the rules above (as additional context only):")
    foreach ($rn in $flaggedRuleNames) {
        $matchingRule = $rules | Where-Object { $_.Name -eq $rn } | Select-Object -First 1
        if ($matchingRule -and $matchingRule.Tags) {
            $tagsLines += "- $rn`: $($matchingRule.Tags)"
        }
    }
    if ($tagsLines.Count -gt 1) {
        $maskedLines += $tagsLines
    }
}

$userPrompt = $maskedLines -join "`n"

Write-Host "Sending $($findingsToSend.Count) finding(s) ($(if ($sendOnlyInternet) { 'internet-only' } else { 'all' })), $($ipMap.Count) masked IP address(es) to Gemini$(if ($includeTags) { ' (Tags included)' } else { ' (Tags excluded)' })..."

$llmResult = Invoke-GeminiNarrative -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model

if ($llmResult) {
    # Deterministic suggestions (see Add-DeterministicSuggestedFixes in
    # DetectionRules.ps1) are applied here, only when the user actually
    # went through the Gemini step, not unconditionally right after
    # detection runs. The Suggested Fix column is meant to be an
    # all-or-nothing thing tied to that one conscious choice, not a
    # column that silently shows partial content on every offline run
    # regardless of whether AI is being used at all.
    Add-DeterministicSuggestedFixes -Findings $findings

    # Apply any AI-guessed Application suggestions back onto the matching
    # findings BEFORE rebuilding the report, so they show up in the
    # Suggested Fix column itself rather than only in a separate summary
    # block. Matched by (rule name, type) together. The type allowlist
    # here is a deliberate second check on top of the system prompt's own
    # instruction to only suggest for these three types: if the model ever
    # returned a suggestion for some other type (a slip, not expected but
    # not impossible), blindly applying it would silently overwrite that
    # finding's existing deterministic SuggestedFix instead of leaving it
    # alone.
    if ($llmResult.application_suggestions) {
        $eligibleSuggestionTypes = @("any_any_any_allow", "outbound_defined_dest_any_app", "port_based_rule_missing_app_id")
        foreach ($sugg in $llmResult.application_suggestions) {
            if ($eligibleSuggestionTypes -notcontains $sugg.type) { continue }
            $matchingFinding = $findings | Where-Object { $_.RuleName -eq $sugg.rule_name -and $_.Type -eq $sugg.type } | Select-Object -First 1
            if ($matchingFinding) {
                $suggestionText = "AI guess (verify): App-ID '$($sugg.suggested_application)'. $($sugg.reasoning)"
                $matchingFinding | Add-Member -NotePropertyName SuggestedFix -NotePropertyValue $suggestionText -Force
            }
        }
    }

    # The Findings table was already rendered to text once above; there's
    # no cheaper way to get the Suggested Fix column populated (both the
    # deterministic entries just applied and any AI ones) than re-running
    # the same render call now that findings carry updated values.
    $reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $InputCsv -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM

    $aiLines = @("", "## AI-Assisted Summary (Gemini, IP addresses masked before sending)", "")
    $aiLines += $llmResult.executive_summary
    $aiLines += ""
    $aiLines += "### Suggested Remediation Order"
    $stepNum = 1
    foreach ($item in $llmResult.remediation_order) {
        # The model sometimes includes its own leading "1. " inside the
        # string despite the array already being ordered. Strip that so it
        # doesn't double up with the number we add here.
        $cleanItem = $item -replace '^\s*\d+[\.\)]\s*', ''
        $aiLines += "$stepNum. $cleanItem"
        $stepNum++
    }
    $aiLines += ""
    $aiLines += "*Note: any IP addresses above appear as IP-MASKED-N placeholders. The model never saw your real addresses.*"

    $reportLines += $aiLines
    Save-HtmlReport -MarkdownLines $reportLines -HtmlPath $OutHtml
    Write-Host "AI section added to $OutHtml" -ForegroundColor Green
}
