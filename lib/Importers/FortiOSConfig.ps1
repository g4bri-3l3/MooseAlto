# --------------------------------------------------------------------------
# FortiOS configuration reader
# --------------------------------------------------------------------------
#
# Syntax only: turns a backup or "show full-configuration" into a tree of
# config / edit / set blocks. What the settings mean is FortiOS.ps1's job.
#
# Multi-VDOM backups open the same "config vdom / edit X" more than once,
# so a table or entry seen again is merged, not replaced.
# Each node is an ordered hashtable: Kind, Name, Settings, Tables, Entries.

function New-FgtNode {
    param([string]$Kind, [string]$Name)
    return [ordered]@{
        Kind     = $Kind
        Name     = $Name
        Settings = [ordered]@{}
        Tables   = [ordered]@{}
        Entries  = [ordered]@{}
    }
}

function Split-FgtLine {
    # Words of one line, with quotes and \ escapes. OpenQuote tells the
    # caller the value carries on to the next line (comments, certificates).
    param([string]$Line)
    $words = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQuote = $false
    $hasToken = $false
    $i = 0
    while ($i -lt $Line.Length) {
        $c = $Line[$i]
        if ($inQuote) {
            if ($c -eq '\' -and ($i + 1) -lt $Line.Length) {
                [void]$sb.Append($Line[$i + 1]); $i += 2; continue
            }
            if ($c -eq '"') { $inQuote = $false; $i++; continue }
            [void]$sb.Append($c); $i++; continue
        }
        if ($c -eq '"') { $inQuote = $true; $hasToken = $true; $i++; continue }
        if ([char]::IsWhiteSpace($c)) {
            if ($hasToken) { $words.Add($sb.ToString()); [void]$sb.Clear(); $hasToken = $false }
            $i++; continue
        }
        [void]$sb.Append($c); $hasToken = $true; $i++
    }
    if ($hasToken -and -not $inQuote) { $words.Add($sb.ToString()) }
    return @{ Words = $words.ToArray(); OpenQuote = $inQuote }
}

function Read-FortiOSConfig {
    # Returns the root node. Odd lines go to $Warnings and are skipped; a
    # partly understood config beats a failed run.
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.Generic.List[string]]$Warnings
    )
    $raw = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path)
    $raw = $raw.TrimStart([char]0xFEFF)
    $lines = $raw -split "`r?`n"

    $root = New-FgtNode -Kind 'root' -Name ''
    $stack = New-Object System.Collections.Generic.List[object]
    $stack.Add($root)

    $pending = $null
    $lineNo = 0
    foreach ($physical in $lines) {
        $lineNo++
        if ($null -ne $pending) {
            $logical = $pending + "`n" + $physical
        }
        else {
            $trim = $physical.Trim()
            if ($trim -eq '' -or $trim.StartsWith('#')) { continue }
            $logical = $trim
        }
        $split = Split-FgtLine -Line $logical
        if ($split.OpenQuote) { $pending = $logical; continue }
        $pending = $null

        $w = $split.Words
        if ($w.Count -eq 0) { continue }
        $top = $stack[$stack.Count - 1]
        $kw = $w[0].ToLower()

        switch ($kw) {
            'config' {
                $name = (($w | Select-Object -Skip 1) -join ' ')
                if (-not $top.Tables.Contains($name)) { $top.Tables[$name] = New-FgtNode -Kind 'table' -Name $name }
                $stack.Add($top.Tables[$name])
            }
            'edit' {
                $id = if ($w.Count -gt 1) { $w[1] } else { '' }
                if ($top.Kind -ne 'table') {
                    if ($null -ne $Warnings) { $Warnings.Add("line ${lineNo}: 'edit $id' outside a config table, ignored") }
                    continue
                }
                if (-not $top.Entries.Contains($id)) { $top.Entries[$id] = New-FgtNode -Kind 'entry' -Name $id }
                $stack.Add($top.Entries[$id])
            }
            'next' {
                # Pop to the nearest entry; this also forgives a missing "end".
                while ($stack.Count -gt 1) {
                    $n = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1)
                    if ($n.Kind -eq 'entry') { break }
                }
            }
            'end' {
                while ($stack.Count -gt 1) {
                    $n = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1)
                    if ($n.Kind -eq 'table') { break }
                }
            }
            { $_ -in @('set', 'select') } {
                if ($w.Count -ge 2) { $top.Settings[$w[1]] = @($w | Select-Object -Skip 2) }
            }
            'unset' {
                if ($w.Count -ge 2 -and $top.Settings.Contains($w[1])) { $top.Settings.Remove($w[1]) }
            }
            'append' {
                if ($w.Count -ge 2) {
                    # Keep it an array, or "+" glues strings ("SSH"+"RDP").
                    $existing = @(if ($top.Settings.Contains($w[1])) { $top.Settings[$w[1]] })
                    $top.Settings[$w[1]] = @($existing) + @($w | Select-Object -Skip 2)
                }
            }
            default {
                if ($null -ne $Warnings) { $Warnings.Add("line ${lineNo}: unrecognised keyword '$($w[0])', ignored") }
            }
        }
    }
    if ($null -ne $pending -and $null -ne $Warnings) { $Warnings.Add("end of file reached inside an unterminated quoted value") }
    return $root
}

function Get-FgtVdomRoots {
    # One @{ Vdom; Node } per VDOM. Without VDOMs the root is "root".
    param([Parameter(Mandatory)]$Root)
    $result = @()
    if ($Root.Tables.Contains('vdom')) {
        foreach ($vd in $Root.Tables['vdom'].Entries.Values) {
            if ($vd.Tables.Count -gt 0) { $result += @{ Vdom = $vd.Name; Node = $vd } }
        }
    }
    if ($result.Count -eq 0) { $result += @{ Vdom = 'root'; Node = $Root } }
    return $result
}

function Get-FgtTable {
    # Safe lookup: returns the table node or $null.
    param($Node, [string]$Name)
    if ($null -ne $Node -and $Node.Tables.Contains($Name)) { return $Node.Tables[$Name] }
    return $null
}

function Get-FgtValue {
    # First value of a setting, or $Default.
    param($Node, [string]$Key, $Default = $null)
    if ($Node.Settings.Contains($Key)) {
        $v = @($Node.Settings[$Key])
        if ($v.Count -gt 0) { return $v[0] }
        return ''
    }
    return $Default
}

function Get-FgtList {
    # All values of a setting as an array (empty array when unset).
    param($Node, [string]$Key)
    if ($Node.Settings.Contains($Key)) { return @($Node.Settings[$Key]) }
    return @()
}
