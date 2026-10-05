# --------------------------------------------------------------------------
# Junos configuration reader
# --------------------------------------------------------------------------
#
# Syntax only. Reads "display set" or the curly brace form and returns one
# statement per leaf: @{ Words; Inactive; InactiveDepth; Line }.
#
# InactiveDepth is how many leading words were deactivated (0 = active).
# It lets Junos.ps1 tell a deactivated policy (rule kept, disabled) from a
# deactivated leaf inside it (just left out, like Junos does).

function Split-JunosWords {
    # Words, quoted strings and { } ; [ ]. Drops # and /* */ comments.
    param([string]$Text)
    $tokens = New-Object System.Collections.Generic.List[object]
    $i = 0; $n = $Text.Length; $line = 1
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($c -eq "`n") { $line++; $i++; continue }
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '/' -and ($i + 1) -lt $n -and $Text[$i + 1] -eq '*') {
            $end = $Text.IndexOf('*/', $i + 2)
            if ($end -lt 0) { break }
            $line += ($Text.Substring($i, $end - $i) -split "`n").Count - 1
            $i = $end + 2; continue
        }
        if ($c -eq '#') {
            $end = $Text.IndexOf("`n", $i)
            if ($end -lt 0) { break }
            $i = $end; continue
        }
        if ('{};[]'.IndexOf($c) -ge 0) { $tokens.Add(@{ T = [string]$c; S = $true; L = $line }); $i++; continue }
        if ($c -eq '"') {
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $n -and $Text[$i] -ne '"') {
                if ($Text[$i] -eq '\' -and ($i + 1) -lt $n) { [void]$sb.Append($Text[$i + 1]); $i += 2; continue }
                if ($Text[$i] -eq "`n") { $line++ }
                [void]$sb.Append($Text[$i]); $i++
            }
            $i++
            $tokens.Add(@{ T = $sb.ToString(); S = $false; L = $line }); continue
        }
        $start = $i
        while ($i -lt $n -and -not [char]::IsWhiteSpace($Text[$i]) -and '{};[]"'.IndexOf($Text[$i]) -lt 0) { $i++ }
        $tokens.Add(@{ T = $Text.Substring($start, $i - $start); S = $false; L = $line })
    }
    return $tokens
}

function Read-JunosConfig {
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.Generic.List[string]]$Warnings
    )
    $raw = [System.IO.File]::ReadAllText((Resolve-Path $Path).Path).TrimStart([char]0xFEFF) -replace "`r`n", "`n"
    $statements = New-Object System.Collections.Generic.List[object]
    # Go by the first real line (an annotation in curly form can contain
    # "set "). Set lines with no "{" anywhere also count, which tolerates a
    # pasted CLI prompt on top.
    $first = ($raw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Select-Object -First 1)
    $isSetFormat = ("$first" -match '^(set|deactivate|activate|delete|insert|protect|unprotect) \S') -or
        ($raw -match '(?m)^\s*(set|deactivate) \S' -and $raw -notmatch '(?m)\{\s*$')

    if ($isSetFormat) {
        $deactivated = New-Object System.Collections.Generic.List[object]
        $lineNo = 0
        foreach ($line in ($raw -split "`n")) {
            $lineNo++
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $words = @(Split-JunosWords $t | ForEach-Object { $_.T })
            if ($words.Count -lt 2) { continue }
            switch ($words[0]) {
                'set' { $statements.Add(@{ Words = @($words | Select-Object -Skip 1); Inactive = $false; InactiveDepth = 0; Line = $lineNo }) }
                'deactivate' { $dw = @($words | Select-Object -Skip 1); $deactivated.Add(@{ Path = ($dw -join ' '); Depth = $dw.Count }) }
                default {
                    if ($null -ne $Warnings -and $words[0] -notin @('delete', 'activate', 'protect', 'unprotect')) {
                        $Warnings.Add("line ${lineNo}: unrecognised statement '$($words[0])', ignored")
                    }
                }
            }
        }
        # Everything under a deactivated path is inactive.
        if ($deactivated.Count -gt 0) {
            foreach ($st in $statements) {
                $joined = ($st.Words -join ' ') + ' '
                foreach ($d in $deactivated) {
                    if ($joined.StartsWith("$($d.Path) ", [System.StringComparison]::Ordinal)) {
                        $st.Inactive = $true
                        if ($st.InactiveDepth -eq 0 -or $d.Depth -lt $st.InactiveDepth) { $st.InactiveDepth = $d.Depth }
                    }
                }
            }
        }
        return $statements
    }

    # Hierarchical form
    $tokens = Split-JunosWords $raw
    $pathStack = New-Object System.Collections.Generic.List[object]   # @{ Words; Inactive }
    $current = New-Object System.Collections.Generic.List[string]
    $currentInactive = $false
    $array = $null
    foreach ($tk in $tokens) {
        if ($tk.S) {
            switch ($tk.T) {
                '{' {
                    $pathStack.Add(@{ Words = @($current); Inactive = $currentInactive })
                    $current = New-Object System.Collections.Generic.List[string]; $currentInactive = $false
                }
                '}' {
                    if ($pathStack.Count -gt 0) { $pathStack.RemoveAt($pathStack.Count - 1) }
                    $current = New-Object System.Collections.Generic.List[string]; $currentInactive = $false
                }
                '[' { $array = New-Object System.Collections.Generic.List[string] }
                ']' { }
                ';' {
                    $prefix = @(); $depth = 0
                    foreach ($p in $pathStack) { $prefix += $p.Words; if ($p.Inactive -and $depth -eq 0) { $depth = $prefix.Count } }
                    if ($depth -eq 0 -and $currentInactive) { $depth = $prefix.Count + $current.Count + $(if ($null -ne $array) { 1 } else { 0 }) }
                    $inact = $depth -gt 0
                    if ($null -ne $array) {
                        foreach ($v in $array) { $statements.Add(@{ Words = @($prefix + $current + $v); Inactive = $inact; InactiveDepth = $depth; Line = $tk.L }) }
                        $array = $null
                    }
                    elseif ($current.Count -gt 0) {
                        $statements.Add(@{ Words = @($prefix + $current); Inactive = $inact; InactiveDepth = $depth; Line = $tk.L })
                    }
                    $current = New-Object System.Collections.Generic.List[string]; $currentInactive = $false
                }
            }
            continue
        }
        $w = $tk.T
        if ($null -ne $array) { $array.Add($w); continue }
        if ($current.Count -eq 0 -and $w -in @('inactive:', 'protect:', 'replace:')) {
            if ($w -eq 'inactive:') { $currentInactive = $true }
            continue
        }
        $current.Add($w)
    }
    return $statements
}
