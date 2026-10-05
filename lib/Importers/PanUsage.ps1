# --------------------------------------------------------------------------
# PAN-OS rule usage overlay (-HitCountFile with a PAN-OS CSV input)
# --------------------------------------------------------------------------
#
# The usage export (Policy Optimizer) is matched to the rules by name and
# its values win over the rules CSV. Blank cells and unlisted rules keep
# what the rules CSV had. Columns are found the same way Import-PaloAltoRules
# finds them.

function Import-PanRuleUsage {
    param([Parameter(Mandatory)][string]$Path)
    $rows = @(Read-HeaderFixedCsv -Path $Path | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) {
        Write-Host "WARNING: rule usage file $Path has no data rows (empty, or a header only); it was not applied." -ForegroundColor Red
        return $null
    }
    $cols = @($rows[0].PSObject.Properties.Name)
    if ($cols -notcontains 'Name') {
        Write-Host "WARNING: rule usage file $Path has no 'Name' column; it was not applied." -ForegroundColor Red
        return $null
    }
    $hitCol = $cols | Where-Object { $_ -match 'Hit Count' } | Select-Object -First 1
    $lastCol = $cols | Where-Object { $_ -match 'Last Hit' } | Select-Object -First 1
    $statusCol = $null
    $statusValues = @('used', 'unused', 'partially used')
    foreach ($c in $cols) {
        if ($c -in @('', 'Name', 'Location', 'Tags', 'Type')) { continue }
        $seen = @($rows | Select-Object -First 50 | ForEach-Object { $_.$c } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() } | Select-Object -Unique)
        if ($seen.Count -gt 0 -and -not ($seen | Where-Object { $statusValues -notcontains $_ })) { $statusCol = $c; break }
    }
    if (-not $hitCol -and -not $lastCol -and -not $statusCol) {
        Write-Host "WARNING: rule usage file $Path has no Hit Count, Last Hit or Rule Usage column; it was not applied." -ForegroundColor Red
        return $null
    }
    $byName = @{}
    $dupes = New-Object System.Collections.Generic.HashSet[string]
    foreach ($r in $rows) {
        if (-not $r.Name) { continue }
        $n = ($r.Name -replace '^\[Disabled\]\s*', '').Trim()
        if ($byName.ContainsKey($n)) { [void]$dupes.Add($n); continue }
        # Blank = $null, so it never overwrites the rules CSV.
        $hv = if ($hitCol) { "$($r.$hitCol)".Trim() } else { '' }
        $lv = if ($lastCol) { "$($r.$lastCol)".Trim() } else { '' }
        $sv = if ($statusCol) { "$($r.$statusCol)".Trim().ToLower() } else { '' }
        $byName[$n] = [PSCustomObject]@{
            HitCount    = $(if ($hv) { $hv } else { $null })
            LastHit     = $(if ($lv) { $lv } else { $null })
            UsageStatus = $(if ($sv) { $sv } else { $null })
        }
    }
    foreach ($d in $dupes) { $byName.Remove($d) }
    return @{ ByName = $byName; Duplicates = @($dupes); Columns = @(@($hitCol, $lastCol, $statusCol) | Where-Object { $_ }) }
}

function Set-PanRuleUsage {
    # Applies the usage file to the rule objects in place and reports.
    param([Parameter(Mandatory)][array]$Rules, [Parameter(Mandatory)][string]$Path)
    $usage = Import-PanRuleUsage -Path $Path
    if ($null -eq $usage) { return }
    $matched = 0
    $unmatched = @()
    foreach ($rule in $Rules) {
        # Import-PaloAltoRules suffixes repeated names; those are ambiguous.
        if ($rule.Name -match ' \(duplicate name #\d+\)$') { $unmatched += $rule.Name; continue }
        if (-not $usage.ByName.ContainsKey($rule.Name)) { $unmatched += $rule.Name; continue }
        $u = $usage.ByName[$rule.Name]
        if ($null -ne $u.HitCount) { $rule.HitCount = $u.HitCount }
        if ($null -ne $u.LastHit) { $rule.LastHit = $u.LastHit }
        if ($null -ne $u.UsageStatus) { $rule.UsageStatus = $u.UsageStatus }
        $matched++
    }
    Write-Host "Rule usage from $Path ($($usage.Columns -join ', ')) replaced the rules CSV values on $matched of $($Rules.Count) rule(s). Any earlier note about missing usage columns referred to the rules CSV only." -ForegroundColor Green
    $ruleNames = New-Object System.Collections.Generic.HashSet[string]
    foreach ($rule in $Rules) { [void]$ruleNames.Add($rule.Name) }
    $orphans = @($usage.ByName.Keys | Where-Object { -not $ruleNames.Contains($_) })
    if ($orphans.Count -gt 0) {
        Write-Host "Note: $($orphans.Count) name(s) in the usage file match no rule in the rules CSV (e.g. $(($orphans | Select-Object -First 5) -join ', ')). Check that both exports come from the same device group or firewall." -ForegroundColor Yellow
    }
    if ($unmatched.Count -gt 0) {
        $sample = ($unmatched | Select-Object -First 5) -join ', '
        Write-Host "Note: $($unmatched.Count) rule(s) are not in the usage file and keep the values from the rules CSV, if any (e.g. $sample)." -ForegroundColor Yellow
    }
    if ($usage.Duplicates.Count -gt 0) {
        Write-Host "Note: the usage file lists $($usage.Duplicates.Count) rule name(s) more than once ($(($usage.Duplicates | Select-Object -First 5) -join ', ')); those were not applied." -ForegroundColor Yellow
    }
}
