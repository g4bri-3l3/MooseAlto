<#
.SYNOPSIS
    MooseAlto: firewall rule hygiene analyzer (PowerShell). Built around the
    Palo Alto / Panorama rule model; FortiGate and Juniper SRX
    configurations are imported into the same model and go through the
    same checks.

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
      lib\Importers\         non Palo Alto inputs (FortiGate, Juniper SRX), turned
                              into the same rule objects as the PAN-OS CSV
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
.PARAMETER InputConfig
    Path to a firewall configuration from another vendor, analyzed through
    the same checks. Supported:
      * FortiGate / FortiOS 6.x and 7.x: .conf backup or "show
        full-configuration" output, single or multi VDOM, profile-based or
        NGFW policy-based mode
      * Juniper SRX: "show configuration | display set" (recommended) or
        the hierarchical configuration text, root and logical systems
    The vendor is detected from the file content. A configuration passed to
    -InputCsv by mistake is detected and handled the same way.
.PARAMETER AnalyzeFindingsCsv
    Runs only the AI analysis on a findings CSV saved by an earlier run,
    without parsing or checking any ruleset again: useful when the ruleset
    is large, when the offline analysis ran on a machine without internet
    access, or to review and trim the CSV before anything is sent. The
    run context file written next to every findings CSV
    (<name>.context.json) supplies the ruleset summary, Tags, vendor and
    settings; without it the analysis still runs on the CSV alone. Rows
    removed or rule names changed in the CSV are respected. Writes
    only <name>_ai.html (or -OutHtml): no CSV of any kind is created, and
    the input CSV is never modified. -CompareTo adds the trend narrative. Also option 2 of the menu shown
    when the script starts without parameters.
.PARAMETER HitCountFile
    Optional per rule usage data, in the form each platform exports it.
    Alias: -UsageJson. Asked by the interactive setup too.
      * PAN-OS: a rule usage CSV (Policy Optimizer export) with a Name
        column plus any of Hit Count, Last Hit, Rule Usage. Its values
        REPLACE those of the rules CSV for the rules it lists, matched by
        name; rules it does not list keep the rules CSV values.
      * FortiGate: the JSON returned by the monitor API
        (/api/v2/monitor/firewall/policy, or /security-policy in NGFW
        policy-based mode), one response or a JSON array of several
      * Juniper SRX: the text output of "show security policies hit-count"
.PARAMETER AppMapCsv
    Optional, with -InputConfig: extra application name mappings.
      * FortiGate: FortiGuard ID to name ("id,name" CSV, or the "APP ID;APP"
        layout of the public FortigateAppControlID table). IDs in the
        configuration's own "config application name" table take precedence.
      * Juniper SRX: AppSecure name to MooseAlto name ("id,name" CSV with
        id = junos:NAME), for signatures the built-in mapping spells
        differently.
.PARAMETER ExportNormalized
    Optional folder. With -InputConfig, also writes the imported ruleset as
    PAN-OS style CSVs (rules, address objects, address groups), useful for
    debugging an import or feeding another tool.
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
.PARAMETER RiskyTaxonomyPath
    Path to a JSON file extending the built-in risky-port/application and
    amplification-prone-service tables with environment-specific entries,
    without editing the script. A custom entry sharing a key with a
    built-in one overrides just that entry's label; everything else
    built-in stays. Expected shape:
    { "riskyPorts": {"31337": "Custom-Backdoor"}, "cleartextPorts": [31337],
      "riskyApplications": {"internal-legacy-app": "Custom Legacy Protocol"},
      "amplificationPronePorts": {"20000": "Custom-UDP-Service"},
      "amplificationProneApplications": {"internal-udp-app": "Custom UDP Service"} }
    All five top-level keys are optional.
.PARAMETER OutJson
    Optional path for a structured JSON export of the findings, meant for
    a SIEM, ticketing pipeline, or other automated consumer rather than a
    person. Not produced unless this is set. Written once after the
    deterministic report, and again (overwriting) after the optional
    Gemini step if that ran, so it reflects the enriched findings
    (Suggested Fix, MITRE tags) when available.
.PARAMETER NoSecurityProfileChecks
    The firewall does not inspect traffic (no IPS / antivirus / URL
    filtering profiles, because another device does it): the
    no_security_profile_on_exposed_rule check is not run, and Gemini is
    told not to recommend security profiles.
.PARAMETER SkipLLM
    Never prompt for or send data to Gemini. Deterministic report only.
.PARAMETER ApiKey
    Gemini API key. Defaults to $env:GEMINI_API_KEY.
.PARAMETER Model
    Gemini model name. Defaults to gemini-3.7-flash.

.EXAMPLE
    .\MooseAlto.ps1 -InputCsv export.csv -OutHtml report.html -OutCsv report.csv
.EXAMPLE
    .\MooseAlto.ps1 -InputConfig fw01.conf -HitCountFile fw01_policy_stats.json -OutHtml report.html
.EXAMPLE
    .\MooseAlto.ps1 -AnalyzeFindingsCsv report_20260928_101500.csv
.EXAMPLE
    .\MooseAlto.ps1 -InputConfig srx01_display_set.txt -HitCountFile srx01_hitcount.txt -OutHtml report.html
#>

[CmdletBinding()]
Param(
    [string]$InputCsv = "",
    [string]$InputConfig = "",
    [string]$AnalyzeFindingsCsv = "",
    [Alias('UsageJson')][string]$HitCountFile = "",
    [string]$AppMapCsv = "",
    [string]$ExportNormalized = "",
    [string]$OutHtml = "",
    [string]$OutCsv = "",
    [string]$InternetZones = "untrust,internet,outside,external",
    [string]$CriticalZones = "",
    [string]$AddressObjectsCsv = "",
    [string]$AddressGroupsCsv = "",
    [int]$StaleHitDays = 365,
    [int]$MaxAddressListSize = 25,
    [switch]$NoSecurityProfileChecks,
    [string]$CompareTo = "",
    [string]$RiskyTaxonomyPath = "",
    [string]$OutJson = "",
    [switch]$SkipLLM,
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model = "gemini-3.7-flash"
)

# One timestamp for both default names, so the .html and .csv match.
$defaultTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutHtml) { $OutHtml = "report_$defaultTimestamp.html" }
if (-not $OutCsv) { $OutCsv = "report_$defaultTimestamp.csv" }

# --------------------------------------------------------------------------
# Banner. Always shown, whether or not parameters were supplied.
# --------------------------------------------------------------------------

$script:MooseAltoVersion = "3.0"

function Show-Banner {
    $lines = @(
        '######################################################################'
        '#  ___            ___                                                #'
        "# /   \          /   \                  MooseAlto v$script:MooseAltoVersion               #"
        '# \_   \        /  __/           Firewall Rule Analyzer              #'
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
        # Italic needs $PSStyle (PS 7.2+); plain text otherwise.
        $isTaglineLine = $line -match 'blind spots|moose-alert|Stay secure'
        if ($isTaglineLine -and $PSStyle) {
            Write-Host "$($PSStyle.Italic)$line$($PSStyle.Reset)" -ForegroundColor DarkYellow
        }
        else {
            Write-Host $line -ForegroundColor DarkYellow
        }

        # Draw the banner line by line, with a longer pause at the end.
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
# Interactive setup, when no input file was given. Parameters already on
# the command line aren't asked again; Enter keeps the [default].
# --------------------------------------------------------------------------

# Vendor detection (lib\Importers) is loaded before the setup, so the
# questions asked can depend on what kind of file is being analyzed.
. (Join-Path $PSScriptRoot "lib\Importers\Import.ps1")

function Get-SetupVendor([string]$Path) {
    # Which questions to ask. Unknown files get the PAN-OS ones; the main
    # flow reports the problem later.
    if (-not $Path -or -not (Test-Path -Path $Path -PathType Leaf)) { return 'paloalto-csv' }
    $v = Get-InputVendor -Path $Path
    if ($v -notin @('paloalto-csv', 'fortios', 'junos', 'tufin')) { return 'paloalto-csv' }
    return $v
}

function Read-HostPath {
    # Read-Host with Tab completion of paths (Shift+Tab back, Esc clears).
    # Plain Read-Host when input is redirected or keys can't be read.
    param([string]$Prompt)
    $canReadKeys = $false
    try { $canReadKeys = -not [Console]::IsInputRedirected -and $null -ne $Host.UI.RawUI } catch { $canReadKeys = $false }
    if (-not $canReadKeys) { return "$(Read-Host $Prompt)".Trim().Trim('"') }

    $label = "${Prompt}: "
    Write-Host $label -NoNewline
    $buf = ''
    $cands = $null; $idx = -1
    $redraw = {
        param([string]$Old, [string]$New)
        # Back to the start of the typed text, rewrite, blank what is left.
        $back = "`b" * $Old.Length
        $pad = ' ' * [math]::Max(0, $Old.Length - $New.Length)
        [Console]::Write($back + $New + $pad + ("`b" * $pad.Length))
    }
    while ($true) {
        try { $k = [Console]::ReadKey($true) }
        catch { Write-Host ''; return "$(Read-Host $Prompt)".Trim().Trim('"') }
        # Quotes typed or pasted around the path are dropped.
        if ($k.Key -eq 'Enter') { [Console]::WriteLine(); return $buf.Trim().Trim('"') }
        if ($k.Key -eq 'Tab') {
            if ($null -eq $cands) {
                $typed = $buf.Trim('"')
                $sepIdx = [math]::Max($typed.LastIndexOf('\'), $typed.LastIndexOf('/'))
                $prefix = if ($sepIdx -ge 0) { $typed.Substring(0, $sepIdx + 1) } else { '' }
                $leaf = if ($sepIdx -ge 0) { $typed.Substring($sepIdx + 1) } else { $typed }
                $dir = if ($prefix) { $prefix } else { '.' }
                if ($dir -match '^~') { $dir = $dir -replace '^~', $HOME }
                $sep = if ($prefix -match '/' -and $prefix -notmatch '\\') { '/' } else { [System.IO.Path]::DirectorySeparatorChar }
                $items = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name.StartsWith($leaf, [System.StringComparison]::OrdinalIgnoreCase) } |
                    Sort-Object @{ Expression = { -not $_.PSIsContainer } }, Name)
                $cands = @($items | ForEach-Object { $prefix + $_.Name + $(if ($_.PSIsContainer) { $sep } else { '' }) })
                $idx = -1
            }
            if ($cands.Count -eq 0) { [Console]::Beep(); continue }
            $shift = ($k.Modifiers -band [ConsoleModifiers]::Shift) -ne 0
            $idx = if ($shift) { ($idx - 1 + $cands.Count) % $cands.Count } else { ($idx + 1) % $cands.Count }
            $new = $cands[$idx]
            & $redraw $buf $new
            $buf = $new
            # One candidate that is a folder: the next Tab lists its content.
            if ($cands.Count -eq 1 -and $new.Trim('"') -match '[\\/]$') { $cands = $null }
            continue
        }
        if ($k.Key -eq 'Escape') { & $redraw $buf ''; $buf = ''; $cands = $null; continue }
        if ($k.Key -eq 'Backspace') {
            if ($buf.Length -gt 0) { $new = $buf.Substring(0, $buf.Length - 1); & $redraw $buf $new; $buf = $new }
            $cands = $null; continue
        }
        if ($k.KeyChar -and -not [char]::IsControl($k.KeyChar)) {
            $buf += $k.KeyChar; [Console]::Write($k.KeyChar); $cands = $null
        }
    }
}

function Get-HitCountPrompt([string]$Vendor) {
    switch ($Vendor) {
        'fortios' { return "Hit counter file: FortiGate monitor API JSON (firewall/policy, or firewall/security-policy in NGFW mode)" }
        'junos' { return "Hit counter file: output of 'show security policies hit-count'" }
        'tufin' { return "Hit counter file: not used with a Tufin export (its Last Hit column is read)" }
        default { return "Rule usage CSV (Policy Optimizer export); when given, its Hit Count / Last Hit / Rule Usage replace the ones in the rules CSV" }
    }
}

if (-not $InputCsv -and -not $InputConfig -and -not $AnalyzeFindingsCsv) {
    Write-Host "No parameters supplied. Make a choice:" -ForegroundColor Cyan
    Write-Host "  1. Start interactive setup"
    Write-Host "  2. AI analysis of a saved report (findings CSV from an earlier run)"
    Write-Host "  3. Exit"
    $menuChoice = $null
    while ($menuChoice -notin @("1", "2", "3")) {
        $menuChoice = Read-Host "Enter choice"
    }
    if ($menuChoice -eq "3") {
        Write-Host "Exiting."
        return
    }
}
if ($menuChoice -eq "2") {
    Write-Host ""
    Write-Host "AI analysis of a saved report (press Enter to accept a default)." -ForegroundColor Cyan
    Write-Host "Nothing is sent before you confirm, IP addresses are masked, and the saved CSV can be trimmed beforehand." -ForegroundColor DarkGray
    Write-Host ""
    # Quotes stripped as in option 1: a path dragged onto the console
    # arrives wrapped in them when it contains spaces.
    while (-not $AnalyzeFindingsCsv) {
        $AnalyzeFindingsCsv = "$(Read-HostPath "Findings CSV from an earlier MooseAlto run (required)")".Trim().Trim('"')
    }
    $aiDefault = ($AnalyzeFindingsCsv -replace '\.csv$', '') -replace '_ai$', ''
    $inputVal = Read-HostPath "-OutHtml, HTML report path [${aiDefault}_ai.html]"
    $OutHtml = if ($inputVal) { $inputVal.Trim().Trim('"') } else { "${aiDefault}_ai.html" }
    $PSBoundParameters['OutHtml'] = $OutHtml
    $inputVal = Read-HostPath "Compare against an older findings CSV for a trend narrative, optional [none]"
    if ($inputVal) { $CompareTo = $inputVal.Trim().Trim('"') }
    if (-not $ApiKey) {
        $inputVal = Read-Host "Gemini API key (not found in GEMINI_API_KEY env var)"
        if ($inputVal) { $ApiKey = $inputVal }
    }
    $inputVal = Read-Host "Gemini model to use [$Model]"
    if ($inputVal) { $Model = $inputVal }
    Write-Host ""
}
if ($menuChoice -eq "1") {
    Write-Host ""
    Write-Host "Interactive setup (press Enter to accept a default)." -ForegroundColor Cyan
    Write-Host ""

    # Ask until we get something readable. A hit counter file given here is
    # kept as such, and we ask for the configuration.
    $vendorLabel = @{ 'paloalto-csv' = 'Palo Alto CSV export'; 'fortios' = 'FortiGate configuration'; 'junos' = 'Juniper SRX configuration'; 'tufin' = 'Tufin SecureTrack Rule Viewer export' }
    while ($true) {
        while (-not $InputCsv) {
            $InputCsv = Read-HostPath "File to analyze: PAN-OS CSV export, FortiGate or Juniper SRX config, Tufin Rule Viewer export (required)"
        }
        $InputCsv = $InputCsv.Trim().Trim('"')
        if (-not (Test-Path -Path $InputCsv -PathType Leaf)) {
            Write-Host "File not found: $InputCsv" -ForegroundColor Yellow
            $InputCsv = ""; continue
        }
        $detected = Get-InputVendor -Path $InputCsv
        $note = Get-HitCountFileNote -Vendor $detected
        if ($note) {
            Write-Host "This is $note." -ForegroundColor Yellow
            Write-Host "It will be used as the hit counter file. Now give the file to analyze." -ForegroundColor Yellow
            $HitCountFile = $InputCsv
            $InputCsv = ""; continue
        }
        if (-not $detected) {
            if ($InputCsv -match '\.csv$') {
                Write-Host "Note: the header does not look like a PAN-OS rulebase export (no Source Zone / Destination Address columns). It will be read as one; check the column warnings below." -ForegroundColor Yellow
                $detected = 'paloalto-csv'
            }
            else {
                Write-Host "Format not recognized: not a PAN-OS CSV export, a FortiGate configuration or a Juniper SRX configuration." -ForegroundColor Yellow
                $InputCsv = ""; continue
            }
        }
        break
    }
    $setupVendor = $detected
    Write-Host "Detected: $($vendorLabel[$setupVendor])" -ForegroundColor Cyan

    $inputVal = Read-HostPath "-OutHtml, HTML report path [$OutHtml]"
    if ($inputVal) { $OutHtml = $inputVal }

    $inputVal = Read-HostPath "-OutCsv, findings CSV path [$OutCsv]"
    if ($inputVal) { $OutCsv = $inputVal }

    $inputVal = Read-Host "Internet-facing zone names, comma-separated [$InternetZones]"
    if ($inputVal) { $InternetZones = $inputVal }

    $inputVal = Read-Host "Critical zone names e.g. SWIFT/CDE/ATM, comma-separated [none]"
    if ($inputVal) { $CriticalZones = $inputVal }

    if ($setupVendor -eq 'paloalto-csv') {
        # FortiGate and SRX configurations carry their own objects and
        # groups; a Tufin export names them only and they are not resolved.
        $inputVal = Read-HostPath "Address Objects CSV path, optional [none]"
        if ($inputVal) { $AddressObjectsCsv = $inputVal }

        $inputVal = Read-HostPath "Address Groups CSV path, optional [none]"
        if ($inputVal) { $AddressGroupsCsv = $inputVal }
    }

    if ($setupVendor -ne 'tufin') {
        $hitDefault = if ($HitCountFile) { $HitCountFile } else { 'none' }
        $inputVal = Read-HostPath "$(Get-HitCountPrompt $setupVendor), optional [$hitDefault]"
        if ($inputVal) { $HitCountFile = $inputVal.Trim().Trim('"') }
    }

    if ($setupVendor -in @('fortios', 'junos')) {
        $inputVal = Read-HostPath "Application name map CSV (id,name), optional [none]"
        if ($inputVal) { $AppMapCsv = $inputVal }
    }

    $inputVal = Read-Host "Days since last hit to flag a rule as stale [$StaleHitDays]"
    if ($inputVal -match '^\d+$') { $StaleHitDays = [int]$inputVal }

    $inputVal = Read-Host "Max individual addresses in a list before flagging it as oversized [$MaxAddressListSize]"
    if ($inputVal -match '^\d+$') { $MaxAddressListSize = [int]$inputVal }

    $inputVal = Read-Host "Does this firewall inspect traffic with security profiles (IPS, antivirus, URL filtering)? Answer N if another device does it, and the missing profile check is skipped (Y/n)"
    if ($inputVal -match '^[Nn]') { $NoSecurityProfileChecks = $true }

    $inputVal = Read-HostPath "Compare against a previous findings CSV, optional [none]"
    if ($inputVal) { $CompareTo = $inputVal }

    $inputVal = Read-Host "Skip the AI analysis step entirely? (y/N)"
    if ($inputVal -match '^[Yy]') { $SkipLLM = $true }

    if (-not $SkipLLM -and -not $ApiKey) {
        $inputVal = Read-Host "Gemini API key (not found in GEMINI_API_KEY env var, leave blank to skip AI analysis for this run)"
        if ($inputVal) { $ApiKey = $inputVal }
        else { $SkipLLM = $true }
    }

    if (-not $SkipLLM) {
        $inputVal = Read-Host "Gemini model to use [$Model]"
        if ($inputVal) { $Model = $inputVal }
    }

    # Review list: change any answer without starting over (a bit like
    # Metasploit's show options / set). Rebuilt each pass, so changing the
    # input file changes the questions.
    $paramPrompts = @{
        InputCsv            = "File to analyze (PAN-OS CSV, FortiGate or SRX config)"
        OutHtml              = "HTML report path"
        OutCsv               = "Findings CSV path"
        InternetZones        = "Internet-facing zone names, comma-separated"
        CriticalZones        = "Critical zone names, comma-separated"
        AddressObjectsCsv    = "Address Objects CSV path"
        AddressGroupsCsv     = "Address Groups CSV path"
        HitCountFile         = "Hit counter file"
        AppMapCsv            = "Application name map CSV (id,name)"
        StaleHitDays         = "Days since last hit to flag a rule as stale"
        MaxAddressListSize   = "Max individual addresses before flagging oversized"
        NoSecurityProfileChecks = "Skip the security profile check, the firewall does no IPS/AV/URL inspection (y/N)"
        CompareTo            = "Previous findings CSV to compare against"
        SkipLLM              = "Skip AI analysis entirely (y/N)"
        ApiKey               = "Gemini API key"
        Model                = "Gemini model to use"
    }

    while ($true) {
        $setupVendor = Get-SetupVendor $InputCsv
        $paramOrder = @("InputCsv", "OutHtml", "OutCsv", "InternetZones", "CriticalZones")
        if ($setupVendor -eq 'paloalto-csv') { $paramOrder += @("AddressObjectsCsv", "AddressGroupsCsv", "HitCountFile") }
        else { $paramOrder += @("HitCountFile", "AppMapCsv") }
        $paramOrder += @("StaleHitDays", "MaxAddressListSize", "NoSecurityProfileChecks", "CompareTo", "SkipLLM")
        if (-not $SkipLLM) { $paramOrder += @("ApiKey", "Model") }
        $paramPrompts.HitCountFile = Get-HitCountPrompt $setupVendor

        Write-Host ""
        Write-Host "Current settings ($($vendorLabel[$setupVendor])):" -ForegroundColor Cyan
        for ($pi = 0; $pi -lt $paramOrder.Count; $pi++) {
            $pname = $paramOrder[$pi]
            $val = Get-Variable -Name $pname -ValueOnly
            $displayVal =
                if ($pname -eq "ApiKey" -and $val) { "*" * 8 }
                elseif ($pname -in @("SkipLLM", "NoSecurityProfileChecks")) { if ($val) { "Yes" } else { "No" } }
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
        $pathParams = @("InputCsv", "OutHtml", "OutCsv", "AddressObjectsCsv", "AddressGroupsCsv", "HitCountFile", "AppMapCsv", "CompareTo")
        $newVal = if ($targetName -in $pathParams) { Read-HostPath "$($paramPrompts[$targetName]) [$currentVal]" } else { Read-Host "$($paramPrompts[$targetName]) [$currentVal]" }
        if (-not $newVal) { continue }

        if ($targetName -in @("StaleHitDays", "MaxAddressListSize")) {
            if ($newVal -match '^\d+$') { Set-Variable -Name $targetName -Value ([int]$newVal) }
            else { Write-Host "Must be a whole number, ignored." -ForegroundColor Yellow }
        }
        elseif ($targetName -in @("SkipLLM", "NoSecurityProfileChecks")) {
            Set-Variable -Name $targetName -Value ($newVal -match '^[Yy]')
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
# Library. Checks live in DetectionRules.ps1.
# --------------------------------------------------------------------------

. (Join-Path $PSScriptRoot "lib\IpHelpers.ps1")
. (Join-Path $PSScriptRoot "lib\Parsing.ps1")
. (Join-Path $PSScriptRoot "lib\DetectionRules.ps1")
. (Join-Path $PSScriptRoot "lib\Reporting.ps1")
. (Join-Path $PSScriptRoot "lib\SavedReport.ps1")

if ($RiskyTaxonomyPath) { Merge-CustomRiskyTaxonomy -Path $RiskyTaxonomyPath }

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# AI step (optional), for both a live run and -AnalyzeFindingsCsv. Reads
# $findings, $rules, $inventory, $comparison and the settings from script
# scope.
# --------------------------------------------------------------------------
$script:AnalyzeOnly = $false
$script:AiReportWritten = $false
# Source vendor of the ruleset ('' / 'paloalto-csv' for Palo Alto), set by
# Set-VendorPresentation; drives vendor specific wording in the AI step.
$script:SourceVendor = ''

function Invoke-AiStep {
    if ($findings.Count -eq 0) {
        Write-Host "No deterministic findings to summarize. Skipping the Gemini call (avoids the model inventing plausible-sounding but ungrounded content)."
        return
    }

    # 2) Ask before sending anything externally.
    Write-Host "Note: every IP address (IPv4, IPv6, CIDR, ranges, also inside rule names, object names and tags) is replaced by an IP-MASKED-N placeholder before sending, and the request is checked again right before it leaves: if any address were still in it, nothing would be sent. Rule names are otherwise sent as they are (the summary needs them to be readable). If your naming convention includes anything else sensitive (customer names, internal codenames, hostnames), rename those rules first or decline below." -ForegroundColor Yellow
    $answer = Read-Host "Send the results to Gemini for additional analysis? (Y/N)"

    if ($answer -notmatch '^[Yy]') {
        Write-Host "Ok, nothing sent to Gemini.$(if (-not $script:AnalyzeOnly) { " Deterministic report saved to $OutHtml." })"
        return
    }

    if (-not $ApiKey) {
        Write-Host "ERROR: GEMINI_API_KEY not set. Cannot proceed with AI analysis." -ForegroundColor Red
        return
    }

    # 3) What to send. Never disabled rules: they aren't a live risk.
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

    # 4) Mask IPs. One map for all batches, so an address keeps its
    # placeholder everywhere.
    $ipMap = @{}
    # Withheld rule names first (a name may contain an IP), then IPs.
    $maskText = { param($Text) Protect-IPAddresses -Text (Protect-WithheldRuleNames -Text "$Text") -Map $ipMap }
    # Rule names are masked too ("Allow-10.1.1.1"); this map turns the
    # model's answers back into real names.
    $maskedRuleToReal = @{}
    $maskRule = {
        param($Name)
        $masked = & $maskText $Name
        if (-not $maskedRuleToReal.ContainsKey($masked)) { $maskedRuleToReal[$masked] = "$Name" }
        return $masked
    }

    # 4b) Tags are free text (codenames, tickets): ask first, and only if
    # there are any.
    $includeTags = $false
    if (@($rules | Where-Object { $_.Tags }).Count -gt 0) {
        $tagsAnswer = Read-Host "Also include rule Tags in the prompt sent to Gemini? They may contain sensitive information (Y/N)"
        if ($tagsAnswer -match '^[Yy]') { $includeTags = $true }
    }

    # 4c) The trend since the previous run: its own question, and only when
    # something actually changed.
    $includeTrend = $false
    if ($comparison -and (($comparison.New.Count -gt 0) -or ($comparison.Resolved.Count -gt 0))) {
        $trendAnswer = Read-Host "This run includes a comparison against a previous report ($($comparison.New.Count) new, $($comparison.Resolved.Count) resolved). Also ask Gemini for a short trend narrative about the changes? (Y/N)"
        if ($trendAnswer -match '^[Yy]') { $includeTrend = $true }
    }

    # 5) Big rulesets (~4,000 rules) blow the free tier's per-minute token
    # quota, so split into batches and merge. Characters are a rough,
    # cautious stand-in for tokens. Order is right inside a batch; batches
    # are just appended.
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
        comparison_narrative     = ""
        application_suggestions  = @()
        mitre_mappings           = @()
        trend_narrative          = ""
    }
    $executiveSummaries = @()
    $batchSeverityWeight = @()

    for ($bi = 0; $bi -lt $batches.Count; $bi++) {
        $batch = $batches[$bi]
        $maskedLines = @()
        if ($NoSecurityProfileChecks) {
            # Stated by the user: threat inspection happens on another device.
            $maskedLines += "Context: this firewall does not inspect traffic (IPS, antivirus and URL filtering are done by another device). Do not recommend adding security profiles to its rules."
            $maskedLines += ""
        }
        $maskedLines += "Deterministic findings" + $(if ($batches.Count -gt 1) { " (batch $($bi + 1) of $($batches.Count))" } else { "" }) + ":"
        foreach ($f in $batch) {
            $maskedDetail = $null
            $maskedDetail = & $maskText $f.Detail
            $maskedLines += "- [$($f.Severity)] $(& $maskRule $f.RuleName) ($($f.Type)): $maskedDetail"
        }

        if ($includeTags) {
            $flaggedRuleNames = @($batch | Select-Object -ExpandProperty RuleName -Unique)
            $tagsLines = @("", "Tags for the rules above (as additional context only):")
            foreach ($rn in $flaggedRuleNames) {
                $matchingRule = $rules | Where-Object { $_.Name -eq $rn } | Select-Object -First 1
                if ($matchingRule -and $matchingRule.Tags) {
                    $tagsLines += "- $(& $maskRule $rn)`: $(& $maskText $matchingRule.Tags)"
                }
            }
            if ($tagsLines.Count -gt 1) { $maskedLines += $tagsLines }
        }

        # The trend goes with the first batch only.
        if ($bi -eq 0 -and $includeTrend) {
            $trendLines = @("", "Comparison against a previous report (already computed, not something to recompute):")
            foreach ($f in $comparison.New) {
                $maskedDetail = $null
                $maskedDetail = & $maskText $f.Detail
                $trendLines += "- NEW [$($f.Severity)] $(& $maskRule $f.RuleName) ($($f.Type)): $maskedDetail"
            }
            # Resolved rows come from the old CSV; withheld names get masked.
            foreach ($f in $comparison.Resolved) {
                $maskedDetail = $null
                $maskedDetail = & $maskText $f.Detail
                $maskedRule = & $maskRule "$($f.Rule)"
                $trendLines += "- RESOLVED [$($f.Severity)] $maskedRule ($($f.Type)): $maskedDetail"
            }
            $trendLines += "- Still present (unchanged since last run): $($comparison.Persistent.Count) finding(s)"
            $maskedLines += $trendLines
        }

        $userPrompt = $maskedLines -join "`n"
        $batchLabel = if ($batches.Count -gt 1) { " (batch $($bi + 1)/$($batches.Count))" } else { "" }
        Write-Host "Sending $($batch.Count) finding(s)$batchLabel ($(if ($sendOnlyInternet) { 'internet-only' } else { 'all' })), $($ipMap.Count) masked IP address(es) total to Gemini$(if ($includeTags) { ' (Tags included)' } else { ' (Tags excluded)' })..."

        $batchResult = Invoke-GeminiNarrative -UserPrompt $userPrompt -ApiKey $ApiKey -Model $Model

        if (-not $batchResult) {
            Write-Host "Batch $($bi + 1) failed; continuing with the remaining batches (if any)." -ForegroundColor Yellow
            continue
        }

        if ($batchResult.executive_summary) {
            $executiveSummaries += $batchResult.executive_summary
            $critInBatch = @($batch | Where-Object { $_.Severity -eq "Critical" }).Count
            $highInBatch = @($batch | Where-Object { $_.Severity -eq "High" }).Count
            $batchSeverityWeight += ($critInBatch * 100 + $highInBatch)
        }
        if ($batchResult.remediation_order) { $mergedResult.remediation_order = @($mergedResult.remediation_order) + @($batchResult.remediation_order) }
        if ($batchResult.application_suggestions) { $mergedResult.application_suggestions = @($mergedResult.application_suggestions) + @($batchResult.application_suggestions) }
        if ($batchResult.mitre_mappings) { $mergedResult.mitre_mappings = @($mergedResult.mitre_mappings) + @($batchResult.mitre_mappings) }
        # Only ever sent with the first batch, so at most one batch's result
        # will actually carry it - a straight assignment, not an append.
        if ($batchResult.comparison_narrative -and -not $mergedResult.comparison_narrative) {
            $mergedResult.comparison_narrative = $batchResult.comparison_narrative
        }
        if ($batchResult.trend_narrative) { $mergedResult.trend_narrative = $batchResult.trend_narrative }

        # The quota adds up over a rolling minute, so wait over 60 s between
        # batches or they all land in the same window and get a 429.
        if ($bi -lt $batches.Count - 1) {
            Write-Host "Waiting 65s before the next batch (Gemini's free-tier quota is per-minute, not per-request)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 65
        }
    }

    if ($executiveSummaries.Count -eq 0) {
        Write-Host "ERROR: Gemini call failed for every batch. $(if ($script:AnalyzeOnly) { 'No AI report written.' } else { "Deterministic report already saved to $OutHtml; no AI section added." })" -ForegroundColor Red
        return
    }

    # Several batch summaries repeat each other, so keep the one from the
    # batch with the most Critical/High findings, and say so.
    if ($executiveSummaries.Count -eq 1) {
        $mergedResult.executive_summary = $executiveSummaries[0]
    }
    else {
        $topBatchIndex = 0
        $topWeight = $batchSeverityWeight[0]
        for ($wi = 1; $wi -lt $batchSeverityWeight.Count; $wi++) {
            if ($batchSeverityWeight[$wi] -gt $topWeight) { $topWeight = $batchSeverityWeight[$wi]; $topBatchIndex = $wi }
        }
        $mergedResult.executive_summary = $executiveSummaries[$topBatchIndex] + "`n`n*(This ruleset needed $($executiveSummaries.Count) separate batches to send to Gemini; the summary above reflects the batch with the most Critical/High findings. The remediation list below draws from every batch.)*"
    }

    # Recommendations repeat across batches too, worded differently. Drop
    # later ones that mention a rule-like ALL_CAPS name already covered.
    # Rough, but it stops the same rule showing up four times.
    if ($mergedResult.remediation_order.Count -gt 0) {
        $seenRuleTokens = New-Object System.Collections.Generic.HashSet[string]
        $dedupedOrder = New-Object System.Collections.Generic.List[string]
        foreach ($item in $mergedResult.remediation_order) {
            $tokens = [regex]::Matches($item, '\b[A-Z][A-Z0-9_]{3,}\b') | ForEach-Object { $_.Value }
            $alreadySeen = $false
            foreach ($t in $tokens) {
                if ($seenRuleTokens.Contains($t)) { $alreadySeen = $true; break }
            }
            if ($alreadySeen) { continue }
            foreach ($t in $tokens) { [void]$seenRuleTokens.Add($t) }
            $dedupedOrder.Add($item)
        }
        $mergedResult.remediation_order = @($dedupedOrder)
    }

    $llmResult = $mergedResult

    if ($llmResult) {
        # The Suggested Fix column only exists with the AI step, so the fixed
        # suggestions are added here too.
        Add-DeterministicSuggestedFixes -Findings $findings

        # AI app guesses go into Suggested Fix, matched by rule and type.
        # The type list is checked again here, so a stray answer can't
        # overwrite a deterministic suggestion.
        if ($llmResult.application_suggestions) {
            $eligibleSuggestionTypes = @("any_any_any_allow", "outbound_defined_dest_any_app", "port_based_rule_missing_app_id")
            foreach ($sugg in $llmResult.application_suggestions) {
                if ($eligibleSuggestionTypes -notcontains $sugg.type) { continue }
                $realName = if ($maskedRuleToReal.ContainsKey("$($sugg.rule_name)")) { $maskedRuleToReal["$($sugg.rule_name)"] } else { "$($sugg.rule_name)" }
                $matchingFinding = $findings | Where-Object { $_.RuleName -eq $realName -and $_.Type -eq $sugg.type } | Select-Object -First 1
                if ($matchingFinding) {
                    # "App-ID" is Palo Alto's term (same rule as Get-AppIdLabel).
                    $appLabel = if ($script:SourceVendor -in @('fortios', 'junos')) { 'application' } else { 'App-ID' }
                    $suggestionText = "AI guess (verify): $appLabel '$($sugg.suggested_application)'. $($sugg.reasoning)"
                    $matchingFinding | Add-Member -NotePropertyName SuggestedFix -NotePropertyValue $suggestionText -Force
                }
            }
        }

        # MITRE tags, same matching.
        if ($llmResult.mitre_mappings) {
            foreach ($mapping in $llmResult.mitre_mappings) {
                $realName = if ($maskedRuleToReal.ContainsKey("$($mapping.rule_name)")) { $maskedRuleToReal["$($mapping.rule_name)"] } else { "$($mapping.rule_name)" }
                $matchingFinding = $findings | Where-Object { $_.RuleName -eq $realName -and $_.Type -eq $mapping.type } | Select-Object -First 1
                if ($matchingFinding) {
                    $mitreText = "$($mapping.technique_id) $($mapping.technique_name) ($($mapping.tactic))"
                    $matchingFinding | Add-Member -NotePropertyName MitreTag -NotePropertyValue $mitreText -Force
                }
            }
        }

        # Render again, now with the new columns.
        $reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $inputPath -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM -ComparisonNarrative $llmResult.comparison_narrative

        $aiLines = @("", "## AI-Assisted Summary (Gemini, IP addresses masked before sending)", "")
        $aiLines += $llmResult.executive_summary
        $aiLines += ""
        $aiLines += "### Suggested Remediation Order"
        $stepNum = 1
        foreach ($item in $llmResult.remediation_order) {
            # Drop the model's own "1. ", we number them ourselves.
            $cleanItem = $item -replace '^\s*\d+[\.\)]\s*', ''
            $aiLines += "$stepNum. $cleanItem"
            $stepNum++
        }
        $aiLines += ""
        $aiLines += "*Note: any IP addresses above, including those inside rule names, appear as IP-MASKED-N placeholders. The model never saw your real addresses.*"

        $reportLines += $aiLines
        Save-HtmlReport -MarkdownLines $reportLines -HtmlPath $OutHtml
        $script:AiReportWritten = $true
        Write-Host "AI section added to $OutHtml" -ForegroundColor Green
        if ($OutJson) { Export-FindingsJson -Findings $findings -Rules $rules -JsonPath $OutJson -InputCsvPath $inputPath -ToolVersion $script:MooseAltoVersion }
    }
    # Rewrite the CSV with the AI columns (not for a saved-report analysis,
    # which writes only HTML).
    if ($llmResult -and -not $script:AnalyzeOnly) {
        Export-FindingsCsv -Findings $findings -Rules $rules -CsvPath $OutCsv
    }
}

function Set-VendorPresentation {
    # Title and AI prompt per vendor, so advice names the right features.
    # $null for Palo Alto.
    param([string]$Vendor)
    $script:SourceVendor = $Vendor
    $vendorText = @{
        fortios = @{
            Title  = "MooseAlto: FortiGate Firewall Rule Hygiene Report"
            Role   = "You are a FortiGate / FortiOS firewall policy review assistant"
            Hint   = "WAN role / SD-WAN"
            Prompt = "`n`nThe ruleset was imported from a FortiGate configuration into a Palo Alto`nstyle rule model: zones are FortiOS zones or interfaces, applications are`nFortiGuard application control signatures, and a Service of`n`"application-default`" means enforce-default-app-port. Phrase every`nrecommendation in FortiOS terms (security profiles or profile groups,`napplication control, NGFW policy-based mode, security policies), not in`nPAN-OS specific terms such as App-ID or Applipedia.`n"
        }
        tufin = @{
            Title  = "MooseAlto: Multi-vendor Firewall Rule Hygiene Report (Tufin SecureTrack)"
            Role   = "You are a multi-vendor firewall policy review assistant"
            Hint   = "Tufin export"
            Prompt = "`n`nThe ruleset comes from a Tufin SecureTrack export covering several devices,`npossibly of different vendors. Every rule name is `"<device>/<rule>`" and rules`nare only compared within the same device and policy. Phrase each recommendation`nin the terms of the vendor that device runs (PAN-OS, FortiOS, Junos, Check Point,`nCisco and so on), and group advice by device when that makes it clearer.`n"
        }
        junos = @{
            Title  = "MooseAlto: Juniper SRX Firewall Rule Hygiene Report"
            Role   = "You are a Juniper SRX / Junos firewall policy review assistant"
            Hint   = "zone behind the default route"
            Prompt = "`n`nThe ruleset was imported from a Juniper SRX configuration into a Palo Alto`nstyle rule model: zones are SRX security zones, applications are AppSecure`ndynamic applications, and a Service of `"application-default`" means`n`"match application junos-defaults`". Phrase every recommendation in Junos`nterms (security policies, address books, applications and application`nsets, AppSecure dynamic-application, IDP / UTM / security intelligence`napplication services), not in PAN-OS specific terms such as App-ID or`nApplipedia.`n"
        }
    }[$Vendor]
    if ($vendorText) {
        $script:ReportTitle = $vendorText.Title
        $script:SystemPrompt = $script:SystemPrompt.Replace("You are a Palo Alto / PAN-OS firewall policy review assistant", $vendorText.Role) + $vendorText.Prompt
    }
    return $vendorText
}

# --------------------------------------------------------------------------
# AI analysis of a saved report (-AnalyzeFindingsCsv, menu option 2): no
# parsing, no checks; findings from the CSV, the rest from its context file.
# --------------------------------------------------------------------------
if ($AnalyzeFindingsCsv) {
    if (-not (Test-Path -Path $AnalyzeFindingsCsv -PathType Leaf)) {
        Write-Host "ERROR: Findings CSV not found: $AnalyzeFindingsCsv" -ForegroundColor Red
        return
    }
    if ($SkipLLM) {
        Write-Host "ERROR: -AnalyzeFindingsCsv runs only the AI analysis; it cannot be combined with -SkipLLM." -ForegroundColor Red
        return
    }
    $saved = Import-SavedReport -FindingsCsvPath $AnalyzeFindingsCsv
    if (-not $saved) { return }
    $script:WithheldRuleNames = @($saved.WithheldRules)

    # Outputs go next to the input CSV unless given explicitly, and never
    # overwrite it.
    $aiBase = $AnalyzeFindingsCsv -replace '\.csv$', ''
    if ($aiBase -notmatch '_ai$') { $aiBase = "${aiBase}_ai" }
    if (-not $PSBoundParameters.ContainsKey('OutHtml')) { $OutHtml = "$aiBase.html" }
    # Only the AI report is produced: no CSV of any kind.
    $script:AnalyzeOnly = $true
    if ($PSBoundParameters.ContainsKey('OutCsv')) {
        Write-Host "Note: -OutCsv is ignored with -AnalyzeFindingsCsv; this mode only writes the HTML report." -ForegroundColor Yellow
    }
    $OutCsv = $null

    $findings = $saved.Findings
    $rules = $saved.Rules
    $inventory = $saved.Inventory
    $st = $saved.Settings
    $inputPath = if ($st.inputPath) { "$($st.inputPath) (from saved report $AnalyzeFindingsCsv)" } else { $AnalyzeFindingsCsv }
    $elapsedText = if ($st.elapsedText) { "$($st.elapsedText) (original run)" } else { "" }
    if ($st.internetZones) { $InternetZoneSet = @($st.internetZones) }
    if ($st.criticalZones) { $CriticalZoneSet = @($st.criticalZones) }
    if ($st.staleHitDays) { $StaleHitDays = [int]$st.staleHitDays }
    if ($st.maxAddressListSize) { $MaxAddressListSize = [int]$st.maxAddressListSize }
    if ($st.noSecurityProfileChecks) { $NoSecurityProfileChecks = $true }
    $AddressObjectsCsv = "$($st.addressObjectsCsv)"; $AddressGroupsCsv = "$($st.addressGroupsCsv)"
    [void](Set-VendorPresentation -Vendor "$($st.vendor)")

    $comparison = $null
    if ($CompareTo) {
        $previousFindings = Import-PreviousFindings -Path $CompareTo
        if ($null -ne $previousFindings) { $comparison = Get-FindingsComparison -CurrentFindings $findings -PreviousFindings $previousFindings }
    }

    Write-Host "Loaded $($findings.Count) finding(s) from $AnalyzeFindingsCsv. Output: $OutHtml" -ForegroundColor Green
    if ($findings.Count -eq 0) {
        Write-Host "No findings to analyze." -ForegroundColor Yellow
        return
    }
    # The _ai report is only written when Gemini answers; otherwise it would
    # be a copy of the existing one.
    Invoke-AiStep
    if (-not $script:AiReportWritten) { Write-Host "No AI report written ($OutHtml): nothing was added to the saved report." -ForegroundColor Yellow }
    return
}

# One input path from here on, whichever parameter supplied it.
$inputPath = if ($InputConfig) { $InputConfig } else { $InputCsv }
if (-not (Test-Path -Path $inputPath -PathType Leaf)) {
    Write-Host "ERROR: Input file not found: $inputPath" -ForegroundColor Red
    Write-Host "Check the path and try again." -ForegroundColor Red
    return
}
if ((Get-Item -Path $inputPath).Length -eq 0) {
    Write-Host "ERROR: Input file is empty: $inputPath" -ForegroundColor Red
    return
}

# The content decides the vendor, not the parameter used.
$inputVendor = Get-InputVendor -Path $inputPath
if ($InputConfig -and $inputVendor -eq 'paloalto-csv') {
    Write-Host "Note: $inputPath looks like a PAN-OS CSV export, analyzing it as one." -ForegroundColor Yellow
}
$hitNote = Get-HitCountFileNote -Vendor $inputVendor
if ($hitNote) {
    Write-Host "ERROR: $inputPath is $hitNote. Pass the configuration as the input and this file with -HitCountFile." -ForegroundColor Red
    return
}
if ($InputConfig -and -not $inputVendor) {
    Write-Host "ERROR: could not recognize the configuration format of $inputPath (supported: FortiGate / FortiOS, Juniper SRX)." -ForegroundColor Red
    return
}
if (-not $inputVendor) {
    # Any .csv is still read as PAN-OS (the parser warns about columns);
    # anything else is refused.
    if ($inputPath -notmatch '\.csv$') {
        Write-Host "ERROR: $inputPath is not a PAN-OS CSV export, a FortiGate configuration or a Juniper SRX configuration." -ForegroundColor Red
        return
    }
    $inputVendor = 'paloalto-csv'
}

$processingStartTime = Get-Date

if ($HitCountFile -and $inputVendor -eq 'tufin') {
    Write-Host "Note: -HitCountFile is not used with a Tufin export; its Last Hit column is read instead." -ForegroundColor Yellow
    $HitCountFile = ""
}
if ($HitCountFile -and -not (Test-Path -Path $HitCountFile -PathType Leaf)) {
    Write-Host "ERROR: Hit counter file not found: $HitCountFile" -ForegroundColor Red
    return
}

$importResult = $null
if ($inputVendor -eq 'paloalto-csv') {
    $rules = @(Import-PaloAltoRules -Path $inputPath | Where-Object { $null -ne $_ })
    if ($rules.Count -eq 0) {
        Write-Host "ERROR: no rules found in $inputPath (the file has a header but no rule rows). Nothing to analyze; no report written." -ForegroundColor Red
        return
    }
    # A separate rule usage export (Policy Optimizer) replaces the usage
    # columns of the rules CSV for the rules it lists.
    if ($HitCountFile) { Set-PanRuleUsage -Rules $rules -Path $HitCountFile }
}
else {
    try { $importResult = Import-FirewallConfig -Path $inputPath -Vendor $inputVendor -HitCountFile $HitCountFile -AppMapCsv $AppMapCsv }
    catch {
        Write-Host "ERROR: $inputPath could not be imported: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    $rules = @($importResult.Rules | Where-Object { $null -ne $_ })
    $normReportBase = if ($OutHtml -match '\.html?$') { $OutHtml -replace '\.html?$', '' } else { $OutHtml }
    [void](Write-ImportSummary -Model $importResult.Model -ReportPath "${normReportBase}_normalization.txt" -HitCountFile $HitCountFile)
    if ($ExportNormalized) {
        $prefix = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)
        $exported = Export-MooseAltoInput -Model $importResult.Model -OutDir $ExportNormalized -Prefix $prefix
        Write-Host "Normalized ruleset written to $($exported.Rules)" -ForegroundColor Green
    }
    $vendorText = Set-VendorPresentation -Vendor $inputVendor
    # Internet zones found in the config are added to -InternetZones.
    $hinted = @($importResult.Model.ZoneHints.Keys | Where-Object { $importResult.Model.ZoneHints[$_] -eq 'internet' } | ForEach-Object { $_.ToLower() } | Where-Object { $InternetZoneSet -notcontains $_ })
    if ($hinted.Count -gt 0) {
        $InternetZoneSet = @($InternetZoneSet) + $hinted
        Write-Host "Internet-facing zones added from the configuration ($($vendorText.Hint)): $($hinted -join ', ')" -ForegroundColor Yellow
    }
    if (($AddressObjectsCsv -or $AddressGroupsCsv) -and $inputVendor -eq 'tufin') {
        Write-Host "Note: -AddressObjectsCsv/-AddressGroupsCsv are ignored with a Tufin export: its objects and groups are compared by name (see Known limitations)." -ForegroundColor Yellow
        $AddressObjectsCsv = ""; $AddressGroupsCsv = ""
    }
    elseif ($AddressObjectsCsv -or $AddressGroupsCsv) {
        Write-Host "Note: -AddressObjectsCsv/-AddressGroupsCsv are ignored with a configuration input; objects and groups are read from the configuration itself." -ForegroundColor Yellow
        $AddressObjectsCsv = ""; $AddressGroupsCsv = ""
    }
    if ($rules.Count -eq 0) {
        Write-Host "ERROR: no security policy found in $inputPath. Nothing to analyze; no report written (see ${normReportBase}_normalization.txt)." -ForegroundColor Red
        return
    }
}

# Count what the rule lists before resolving groups: two well-named groups
# aren't the same problem as 100 pasted IPs.
foreach ($rule in $rules) {
    $rule | Add-Member -NotePropertyName SrcAddrTokenCount -NotePropertyValue $(if ($null -eq $rule.SrcAddr) { 0 } else { $rule.SrcAddr.Count })
    $rule | Add-Member -NotePropertyName DstAddrTokenCount -NotePropertyValue $(if ($null -eq $rule.DstAddr) { 0 } else { $rule.DstAddr.Count })
}

if ($importResult) {
    $addressObjects = $importResult.Objects
    $addressGroups = $importResult.Groups
}
else {
    $addressObjects = Import-AddressObjects -Path $AddressObjectsCsv
    $addressGroups = Import-AddressGroups -Path $AddressGroupsCsv
}
if ($addressObjects.Count -gt 0 -or $addressGroups.Count -gt 0) {
    foreach ($rule in $rules) {
        $rule.SrcAddr = Resolve-AddressList -AddrTokens $rule.SrcAddr -Objects $addressObjects -Groups $addressGroups
        $rule.DstAddr = Resolve-AddressList -AddrTokens $rule.DstAddr -Objects $addressObjects -Groups $addressGroups
    }
    Write-Host "Resolved address objects/groups: $($addressObjects.Count) object(s), $($addressGroups.Count) group(s) loaded." -ForegroundColor Green
}

$vendorContext = if ($importResult) { $importResult.VendorContext } else { $null }
$findings = Invoke-DeterministicChecks -Rules $rules -InternetZoneSet $InternetZoneSet -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -VendorContext $vendorContext -SkipSecurityProfileCheck:$NoSecurityProfileChecks
$inventory = Build-InternetExposureInventory -Rules $rules -InternetZoneSet $InternetZoneSet

# Also needed by the AI trend, so compute it here.
$comparison = $null
if ($CompareTo) {
    $previousFindings = Import-PreviousFindings -Path $CompareTo
    if ($null -ne $previousFindings) {
        $comparison = Get-FindingsComparison -CurrentFindings $findings -PreviousFindings $previousFindings
    }
}

Export-FindingsCsv -Findings $findings -Rules $rules -CsvPath $OutCsv
if ($OutJson) { Export-FindingsJson -Findings $findings -Rules $rules -JsonPath $OutJson -InputCsvPath $inputPath -ToolVersion $script:MooseAltoVersion }
if ($OutCsv -match '\.csv$') {
    $inventoryCsvPath = $OutCsv -replace '\.csv$', '_inventory.csv'
}
else {
    $inventoryCsvPath = "${OutCsv}_inventory.csv"
}
Export-InventoryCsv -Inventory $inventory -CsvPath $inventoryCsvPath

# 1) Save the deterministic report first: real IPs, local only. The timer
# stops here, so the AI step doesn't count.
$processingElapsed = (Get-Date) - $processingStartTime
$elapsedText = if ($processingElapsed.TotalMinutes -ge 1) { "{0}m {1}s" -f [int]$processingElapsed.TotalMinutes, $processingElapsed.Seconds } else { "{0:N1}s" -f $processingElapsed.TotalSeconds }

# Run context for a later -AnalyzeFindingsCsv, written once the processing
# time is known so the saved report can show it too.
Save-RunContext -FindingsCsvPath $OutCsv -Rules $rules -Inventory $inventory -Settings @{
    toolVersion = $script:MooseAltoVersion; generated = (Get-Date -Format 's'); vendor = $inputVendor
    inputPath = $inputPath; findingsCount = @($findings).Count
    findingRules = @($findings | ForEach-Object { $_.RuleName } | Where-Object { $_ -ne '(ruleset-wide)' } | Select-Object -Unique)
    internetZones = @($InternetZoneSet); criticalZones = @($CriticalZoneSet)
    staleHitDays = $StaleHitDays; maxAddressListSize = $MaxAddressListSize
    noSecurityProfileChecks = [bool]$NoSecurityProfileChecks
    addressObjectsCsv = $AddressObjectsCsv; addressGroupsCsv = $AddressGroupsCsv
    elapsedText = $elapsedText
}

$reportLines = Get-ReportLines -Findings $findings -Inventory $inventory -InputCsvPath $inputPath -Rules $rules -ElapsedText $elapsedText -InternetZoneSet $InternetZoneSet -CompareToPath $CompareTo -AddressObjectsCsvPath $AddressObjectsCsv -AddressGroupsCsvPath $AddressGroupsCsv -CriticalZoneSet $CriticalZoneSet -StaleHitDays $StaleHitDays -MaxAddressListSize $MaxAddressListSize -SkipLLM:$SkipLLM
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

Invoke-AiStep
