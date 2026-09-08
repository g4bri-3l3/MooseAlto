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

$script:MooseAltoVersion = "1.8"

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

    # Review-and-edit loop, once the guided pass above has a full set of
    # answers: enough parameters exist now that reviewing them all in one
    # place before committing is genuinely useful, not just "answer once,
    # restart the whole script if something's wrong." Same spirit as
    # Metasploit's show options / set X / run, minus the module system -
    # there's only ever one "module" here.
    $paramOrder = @("InputCsv", "OutHtml", "OutCsv", "InternetZones", "CriticalZones", "AddressObjectsCsv", "AddressGroupsCsv", "StaleHitDays", "MaxAddressListSize", "CompareTo", "SkipLLM")
    if (-not $SkipLLM) { $paramOrder += "ApiKey" }
    $paramPrompts = @{
        InputCsv            = "CSV file to analyze"
        OutHtml              = "HTML report path"
        OutCsv               = "Findings CSV path"
        InternetZones        = "Internet-facing zone names, comma-separated"
        CriticalZones        = "Critical zone names, comma-separated"
        AddressObjectsCsv    = "Address Objects CSV path"
        AddressGroupsCsv     = "Address Groups CSV path"
        StaleHitDays         = "Days since last hit to flag a rule as stale"
        MaxAddressListSize   = "Max individual addresses before flagging oversized"
        CompareTo            = "Previous findings CSV to compare against"
        SkipLLM              = "Skip AI analysis entirely (y/N)"
        ApiKey               = "Gemini API key"
    }

    while ($true) {
        Write-Host ""
        Write-Host "Current settings:" -ForegroundColor Cyan
        for ($pi = 0; $pi -lt $paramOrder.Count; $pi++) {
            $pname = $paramOrder[$pi]
            $val = Get-Variable -Name $pname -ValueOnly
            $displayVal =
                if ($pname -eq "ApiKey" -and $val) { "*" * 8 }
                elseif ($pname -eq "SkipLLM") { if ($val) { "Yes" } else { "No" } }
                elseif (-not $val) { "(none)" }
                else { $val }
            Write-Host ("  {0,2}. {1,-20} {2}" -f ($pi + 1), $pname, $displayVal)
        }
        Write-Host ""
        $editChoice = Read-Host "Type a number or name to change a setting, or press Enter to run"
        if (-not $editChoice) { break }

        $targetName = $null
        if ($editChoice -match '^\d+$') {
            $idx = [int]$editChoice - 1
            if ($idx -ge 0 -and $idx -lt $paramOrder.Count) { $targetName = $paramOrder[$idx] }
        }
        else {
            $targetName = $paramOrder | Where-Object { $_ -ieq $editChoice.Trim() } | Select-Object -First 1
        }
        if (-not $targetName) {
            Write-Host "Not a recognized setting. Use a number from the list above." -ForegroundColor Yellow
            continue
        }

        $currentVal = Get-Variable -Name $targetName -ValueOnly
        $newVal = Read-Host "$($paramPrompts[$targetName]) [$currentVal]"
        if (-not $newVal) { continue }

        if ($targetName -in @("StaleHitDays", "MaxAddressListSize")) {
            if ($newVal -match '^\d+$') { Set-Variable -Name $targetName -Value ([int]$newVal) }
            else { Write-Host "Must be a whole number, ignored." -ForegroundColor Yellow }
        }
        elseif ($targetName -eq "SkipLLM") {
            Set-Variable -Name $targetName -Value ($newVal -match '^[Yy]')
            if (-not $SkipLLM -and $paramOrder -notcontains "ApiKey") { $paramOrder += "ApiKey" }
        }
        else {
            Set-Variable -Name $targetName -Value $newVal
        }
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

# Attack-path analysis: pure graph search over the ruleset, no AI
# involved in finding the paths themselves (only, optionally, in
# narrating them afterward - see the Gemini section below). Scales with
# ruleset size the same way the rest of detection does, no separate cap.
$attackPaths = Find-AttackPaths -Rules $rules -Findings $findings -InternetZoneSet $InternetZoneSet -CriticalZoneSet $CriticalZoneSet

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

$reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $InputCsv -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM -AttackPaths $attackPaths
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

# 4) Mask every IP/CIDR in the finding details before building the outbound
# prompt(s). $ipMap is shared across every batch below (never reset
# per-batch) so the same real IP always gets the same placeholder
# wherever it reappears, keeping any address-based correlation (e.g.
# attack path steps sharing an address with a finding) intact even when
# findings are split across multiple calls.
$ipMap = @{}

# 4b) Tags are separate free text written by whoever maintains the ruleset -
# could contain project codenames, ticket numbers, or other internal notes.
# Ask separately before including them, rather than sending them by default.
$includeTags = $false
$tagsAnswer = Read-Host "Also include rule Tags in the prompt sent to Gemini? They may contain sensitive information (Y/N)"
if ($tagsAnswer -match '^[Yy]') { $includeTags = $true }

# 4c) Attack paths are already computed locally either way (see the report
# regardless of this answer) - this only controls whether that zone-to-zone
# topology (zone names, which rules connect them) also gets sent to Gemini
# for a plausibility/severity write-up. It's a different kind of exposure
# than an individual finding: it's a synthesis of network shape, not one
# isolated fact, so it gets its own opt-in rather than riding along with
# the findings by default.
$includeAttackPaths = $false
if ($attackPaths.Count -gt 0) {
    $pathsAnswer = Read-Host "$($attackPaths.Count) attack path(s) were found locally (always shown in the report). Also send them to Gemini for an AI plausibility/severity write-up? (Y/N)"
    if ($pathsAnswer -match '^[Yy]') { $includeAttackPaths = $true }
}

# 5) A large ruleset can produce enough findings to exceed Gemini's
# free-tier per-minute input-token quota in a single request (seen in
# practice around ~4,000 rules). Rather than fail outright, split into
# multiple smaller calls and merge the results - each batch stays
# comfortably under the limit regardless of total ruleset size. The
# character-count threshold is a rough proxy for token count (roughly 4
# chars/token for English text), kept deliberately conservative so the
# estimate being imprecise doesn't accidentally produce an oversized
# batch. The tradeoff: remediation ordering is well-ordered within each
# batch, but batches are simply concatenated after, not globally
# re-prioritized against each other.
$targetCharsPerBatch = 300000
$batches = New-Object System.Collections.Generic.List[System.Collections.Generic.List[PSCustomObject]]
$currentBatch = New-Object System.Collections.Generic.List[PSCustomObject]
$currentBatchChars = 0
foreach ($f in $findingsToSend) {
    $lineLength = $f.Detail.Length + $f.RuleName.Length + $f.Type.Length + 20
    if ($currentBatch.Count -gt 0 -and ($currentBatchChars + $lineLength) -gt $targetCharsPerBatch) {
        $batches.Add($currentBatch)
        $currentBatch = New-Object System.Collections.Generic.List[PSCustomObject]
        $currentBatchChars = 0
    }
    $currentBatch.Add($f)
    $currentBatchChars += $lineLength
}
if ($currentBatch.Count -gt 0) { $batches.Add($currentBatch) }

if ($batches.Count -gt 1) {
    Write-Host "Note: $($findingsToSend.Count) findings is large enough to risk exceeding Gemini's per-request quota. Splitting into $($batches.Count) batches sent one after another; this takes longer but avoids a single oversized request failing outright." -ForegroundColor Yellow
}

$mergedResult = [PSCustomObject]@{
    executive_summary        = ""
    remediation_order        = @()
    application_suggestions  = @()
    mitre_mappings           = @()
    attack_path_assessments  = @()
}
$executiveSummaries = @()

for ($bi = 0; $bi -lt $batches.Count; $bi++) {
    $batch = $batches[$bi]
    $maskedLines = @("Deterministic findings" + $(if ($batches.Count -gt 1) { " (batch $($bi + 1) of $($batches.Count))" } else { "" }) + ":")
    foreach ($f in $batch) {
        $maskedDetail = Protect-IPAddresses -Text $f.Detail -Map $ipMap
        $maskedLines += "- [$($f.Severity)] $($f.RuleName) ($($f.Type)): $maskedDetail"
    }

    if ($includeTags) {
        $flaggedRuleNames = @($batch | Select-Object -ExpandProperty RuleName -Unique)
        $tagsLines = @("", "Tags for the rules above (as additional context only):")
        foreach ($rn in $flaggedRuleNames) {
            $matchingRule = $rules | Where-Object { $_.Name -eq $rn } | Select-Object -First 1
            if ($matchingRule -and $matchingRule.Tags) {
                $tagsLines += "- $rn`: $($matchingRule.Tags)"
            }
        }
        if ($tagsLines.Count -gt 1) { $maskedLines += $tagsLines }
    }

    # Sent once, with the first batch only - attack paths are independent
    # of any single findings batch, so repeating them in every batch would
    # just waste tokens re-sending the same data.
    if ($bi -eq 0 -and $includeAttackPaths) {
        $pathLines = @("", "Attack Paths (already computed via graph search, zone-to-zone reachability - not something to recompute or second-guess):")
        for ($pi = 0; $pi -lt $attackPaths.Count; $pi++) {
            $p = $attackPaths[$pi]
            $nodes = @($p.Steps[0].From) + @($p.Steps | ForEach-Object { $_.To })
            $displayNodes = $nodes | ForEach-Object { if ($_ -eq "(internet)") { "Internet" } else { $_ } }
            $chainText = ($displayNodes -join " -> ")
            # Each hop's zone match, application, and service, plus
            # whether a zone was explicitly named in that rule or reached
            # only through its zone="any" match (a real PAN-OS semantic:
            # "any" matches every zone the firewall knows about, not just
            # ones written in that rule's own row) - worth weighing when
            # judging how concrete versus speculative a given hop is.
            $stepDetails = ($p.Steps | ForEach-Object {
                $fromNote = if ($_.SrcViaAny) { " [via any]" } else { "" }
                $toNote = if ($_.DstViaAny) { " [via any]" } else { "" }
                "$($_.From)$fromNote->$($_.To)$toNote via ``$($_.RuleName)`` (app: $($_.Application), service: $($_.Service))"
            }) -join "; "
            $pathLines += "- path_index ${pi}: $chainText - $stepDetails"
        }
        $maskedLines += $pathLines
    }

    $userPrompt = $maskedLines -join "`n"
    $batchLabel = if ($batches.Count -gt 1) { " (batch $($bi + 1)/$($batches.Count))" } else { "" }
    Write-Host "Sending $($batch.Count) finding(s)$batchLabel ($(if ($sendOnlyInternet) { 'internet-only' } else { 'all' })), $($ipMap.Count) masked IP address(es) total to Gemini$(if ($includeTags) { ' (Tags included)' } else { ' (Tags excluded)' })..."

    $batchResult = Invoke-GeminiNarrative -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model

    if (-not $batchResult) {
        Write-Host "Batch $($bi + 1) failed; continuing with the remaining batches (if any)." -ForegroundColor Yellow
        continue
    }

    if ($batchResult.executive_summary) { $executiveSummaries += $batchResult.executive_summary }
    if ($batchResult.remediation_order) { $mergedResult.remediation_order = @($mergedResult.remediation_order) + @($batchResult.remediation_order) }
    if ($batchResult.application_suggestions) { $mergedResult.application_suggestions = @($mergedResult.application_suggestions) + @($batchResult.application_suggestions) }
    if ($batchResult.mitre_mappings) { $mergedResult.mitre_mappings = @($mergedResult.mitre_mappings) + @($batchResult.mitre_mappings) }
    if ($batchResult.attack_path_assessments) { $mergedResult.attack_path_assessments = @($mergedResult.attack_path_assessments) + @($batchResult.attack_path_assessments) }

    # A short pause between batches, not just retry-on-failure within one:
    # free-tier quotas are also rate-limited per minute, and firing several
    # large requests back-to-back risks tripping that even when each one
    # individually fits under the token ceiling.
    # A short pause isn't enough here: the free-tier quota that matters
    # ("...InputTokensPerModelPerMinute") is cumulative across a rolling
    # 60-second window, not a per-request ceiling. Sending several
    # comfortably-sized batches only a few seconds apart still sums
    # their tokens into the SAME window and can trip the same 429 this
    # batching was meant to avoid. Waiting past 60 seconds between
    # batches means each one lands in a fresh window instead.
    if ($bi -lt $batches.Count - 1) {
        Write-Host "Waiting 65s before the next batch (Gemini's free-tier quota is per-minute, not per-request)..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 65
    }
}

if ($executiveSummaries.Count -eq 0) {
    Write-Host "ERROR: Gemini call failed for every batch. Deterministic report already saved to $OutHtml; no AI section added." -ForegroundColor Red
    return
}

$mergedResult.executive_summary =
    if ($executiveSummaries.Count -eq 1) { $executiveSummaries[0] }
    else { ($executiveSummaries | ForEach-Object { $_ }) -join "`n`n" }

$llmResult = $mergedResult

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

    # MITRE ATT&CK tags, matched the same way as the Application
    # suggestions above: by (rule name, type), applied only to a finding
    # that actually exists with that exact key, never blindly trusted.
    if ($llmResult.mitre_mappings) {
        foreach ($mapping in $llmResult.mitre_mappings) {
            $matchingFinding = $findings | Where-Object { $_.RuleName -eq $mapping.rule_name -and $_.Type -eq $mapping.type } | Select-Object -First 1
            if ($matchingFinding) {
                $mitreText = "$($mapping.technique_id) $($mapping.technique_name) ($($mapping.tactic))"
                $matchingFinding | Add-Member -NotePropertyName MitreTag -NotePropertyValue $mitreText -Force
            }
        }
    }

    # Attack-path assessments, matched by the same path_index given in the
    # prompt - the $attackPaths array's order is exactly what was sent, so
    # the index maps back directly to the same array position.
    if ($llmResult.attack_path_assessments) {
        foreach ($assessment in $llmResult.attack_path_assessments) {
            $idx = [int]$assessment.path_index
            if ($idx -ge 0 -and $idx -lt $attackPaths.Count) {
                $attackPaths[$idx] | Add-Member -NotePropertyName Assessment -NotePropertyValue $assessment.assessment -Force
            }
        }
    }

    # The Findings table was already rendered to text once above; there's
    # no cheaper way to get the Suggested Fix column populated (both the
    # deterministic entries just applied and any AI ones) than re-running
    # the same render call now that findings carry updated values.
    $reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $InputCsv -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM -AttackPaths $attackPaths

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