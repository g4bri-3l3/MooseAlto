# --------------------------------------------------------------------------
# Detection rules: the risky port / app lists, the zone helpers and every
# check (Invoke-DeterministicChecks). Edit this file to add or tune a check.
# --------------------------------------------------------------------------

$RiskyPorts = @{
    20 = "FTP-DATA"; 21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 24 = "Legacy/unassigned"
    25 = "SMTP"; 69 = "TFTP"; 80 = "HTTP"; 110 = "POP3"; 143 = "IMAP"; 161 = "SNMP v1/v2c"
    389 = "LDAP"; 445 = "SMB"; 512 = "Rexec"; 513 = "Rlogin"; 514 = "Rsh"
    853 = "DNS over TLS"; 1433 = "MSSQL"; 1521 = "Oracle DB"; 1723 = "PPTP"; 3306 = "MySQL"; 3389 = "RDP"
    5432 = "PostgreSQL"; 5900 = "VNC"; 6379 = "Redis"; 8443 = "HTTPS-Alt/Admin"
    9200 = "Elasticsearch"; 27017 = "MongoDB"
}

# Cleartext by design (SSH and RDP are risky but encrypted). Only used to
# add a note to the finding text.
$CleartextPorts = @(20, 21, 23, 25, 69, 80, 110, 143, 161, 389, 512, 513, 514)

# Big public DNS resolvers. Reaching one directly bypasses corporate DNS,
# whatever the protocol; DoH looks like plain HTTPS, which is why we go by
# destination here. From dnsprivacy.org plus a few well-known providers;
# the long tail of small resolvers is left out on purpose.
$KnownPublicDnsResolvers = @(
    "8.8.8.8", "8.8.4.4",                     # Google
    "1.1.1.1", "1.0.0.1",                     # Cloudflare
    "9.9.9.9", "149.112.112.112", "9.9.9.10", # Quad9 (secured, secured-alt, unsecured)
    "208.67.222.222", "208.67.220.220",       # OpenDNS / Cisco Umbrella
    "94.140.14.14", "94.140.15.15",           # AdGuard DNS (default/non-filtering)
    "185.228.168.9", "185.228.169.9",         # CleanBrowsing (Security filter)
    "76.76.2.0", "76.76.10.0",                # Control D (unfiltered)
    "84.200.69.80", "84.200.70.40",           # DNS.WATCH
    "8.26.56.26", "8.20.247.20",              # Comodo Secure DNS
    "149.112.121.10", "149.112.122.10",       # CIRA Canadian Shield
    "77.88.8.8", "77.88.8.1"                  # Yandex DNS
)

# Best-effort App-ID names; check them against your App-ID database. The
# r-commands, PPTP and the data stores are the least certain. anydesk and
# dns-over-https were seen in a real export; the other remote access names
# follow the same pattern but weren't confirmed one by one.
$RiskyApplications = @{
    "ftp" = "FTP"; "ssh" = "SSH"; "telnet" = "Telnet"; "smtp" = "SMTP"
    "tftp" = "TFTP"; "pop3" = "POP3"; "imap" = "IMAP"; "snmp" = "SNMP"
    "ldap" = "LDAP"; "ms-rdp" = "RDP"; "ms-sql-db" = "MSSQL"; "mysql" = "MySQL"
    "oracle" = "Oracle DB"; "vnc" = "VNC"; "ms-ds-smb" = "SMB"; "smb" = "SMB"
    "rsh" = "Rsh"; "rlogin" = "Rlogin"; "pptp" = "PPTP"; "postgres" = "PostgreSQL"
    "redis" = "Redis"; "mongodb" = "MongoDB"; "elasticsearch-base" = "Elasticsearch"
    "anydesk" = "AnyDesk"; "teamviewer" = "TeamViewer"; "logmein" = "LogMeIn"
    "logmein-gotomypc" = "GoToMyPC"; "splashtop" = "Splashtop"; "chrome-remote-desktop" = "Chrome Remote Desktop"
    "dns-over-https" = "DNS over HTTPS"
}

# UDP services used for reflection / amplification DDoS: the victim is a
# third party, not this network. UDP only, since the spoofing needs no
# handshake. SNMP and LDAP are left out because the risky port list above
# already flags them.
$AmplificationPronePorts = @{
    17 = "QOTD"; 19 = "Chargen"; 123 = "NTP"; 137 = "NetBIOS Name Service"
    1900 = "SSDP/UPnP"; 5353 = "mDNS"; 11211 = "Memcached"
}

# The same services by App-ID, for rules using application-default. Short
# on purpose: only names we're fairly sure exist.
$AmplificationProneApplications = @{
    "ntp" = "NTP"; "ssdp" = "SSDP/UPnP"; "netbios-ns" = "NetBIOS Name Service"
}

function Merge-CustomRiskyTaxonomy {
    # Adds entries from a JSON file to the lists above (a same key just
    # changes the label). All keys are optional:
    # { "riskyPorts": {"31337": "Custom-Backdoor"}, "cleartextPorts": [31337],
    #   "riskyApplications": {"internal-legacy-app": "Custom Legacy Protocol"},
    #   "amplificationPronePorts": {"20000": "Custom-UDP-Service"},
    #   "amplificationProneApplications": {"internal-udp-app": "Custom UDP Service"} }
    # The hashtables are changed in place, so don't reassign them here.
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Host "WARNING: Risky taxonomy file not found at '$Path'. Continuing with built-in defaults only." -ForegroundColor Yellow
        return
    }
    try {
        $customJson = Get-Content -Path $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Host "WARNING: Could not parse '$Path' as JSON ($($_.Exception.Message)). Continuing with built-in defaults only." -ForegroundColor Yellow
        return
    }

    $addedPorts = 0
    if ($customJson.riskyPorts) {
        foreach ($prop in $customJson.riskyPorts.PSObject.Properties) {
            $portNum = 0
            if ([int]::TryParse($prop.Name, [ref]$portNum)) {
                $RiskyPorts[$portNum] = [string]$prop.Value
                $addedPorts++
            }
            else {
                Write-Host "WARNING: Skipping non-numeric riskyPorts key '$($prop.Name)' in '$Path'." -ForegroundColor Yellow
            }
        }
    }

    $addedCleartext = 0
    if ($customJson.cleartextPorts) {
        foreach ($p in $customJson.cleartextPorts) {
            $portNum = 0
            if ([int]::TryParse([string]$p, [ref]$portNum) -and $CleartextPorts -notcontains $portNum) {
                $script:CleartextPorts = @($CleartextPorts) + @($portNum)
                $addedCleartext++
            }
        }
    }

    $addedApps = 0
    if ($customJson.riskyApplications) {
        foreach ($prop in $customJson.riskyApplications.PSObject.Properties) {
            $RiskyApplications[$prop.Name.ToLower()] = [string]$prop.Value
            $addedApps++
        }
    }

    $addedAmpPorts = 0
    if ($customJson.amplificationPronePorts) {
        foreach ($prop in $customJson.amplificationPronePorts.PSObject.Properties) {
            $portNum = 0
            if ([int]::TryParse($prop.Name, [ref]$portNum)) {
                $AmplificationPronePorts[$portNum] = [string]$prop.Value
                $addedAmpPorts++
            }
            else {
                Write-Host "WARNING: Skipping non-numeric amplificationPronePorts key '$($prop.Name)' in '$Path'." -ForegroundColor Yellow
            }
        }
    }

    $addedAmpApps = 0
    if ($customJson.amplificationProneApplications) {
        foreach ($prop in $customJson.amplificationProneApplications.PSObject.Properties) {
            $AmplificationProneApplications[$prop.Name.ToLower()] = [string]$prop.Value
            $addedAmpApps++
        }
    }

    Write-Host "Loaded custom risky taxonomy from '$Path': $addedPorts port(s), $addedCleartext cleartext port(s), $addedApps application(s), $addedAmpPorts amplification port(s), $addedAmpApps amplification application(s) added/overridden." -ForegroundColor DarkGray
}

# --------------------------------------------------------------------------
# Internet-exposure and critical-zone helpers
# --------------------------------------------------------------------------


function Test-ZoneNameInSet {
    # Importers write a zone that exists in several VDOMs / logical systems as
    # "<scope>/<zone>"; the plain zone name given on the command line still
    # matches it.
    param([string]$ZoneLower, [array]$ZoneSet)
    if ($ZoneSet -contains $ZoneLower) { return $true }
    $slash = $ZoneLower.LastIndexOf('/')
    return ($slash -ge 0 -and $ZoneSet -contains $ZoneLower.Substring($slash + 1))
}

function Get-ActionClass {
    # PAN-OS blocks with deny, drop and reset-*; other vendors are imported
    # as allow / deny already.
    param([string]$Action)
    if ("$Action".Trim().ToLower() -eq 'allow') { return 'allow' }
    return 'deny'
}

function Get-RuleLocalName {
    # The name as written on the device, without the "<device>/", "<vdom>/"
    # or duplicate-name additions. Empty when the rule has no name at all.
    param($Rule)
    if ($Rule.PSObject.Properties['LocalName']) { return "$($Rule.LocalName)" }
    return "$($Rule.Name)"
}

function Test-ZoneTouchesInternet {
    param([array]$Zones, [array]$InternetZoneSet)
    # Set by Invoke-DeterministicChecks; when it isn't, "any" counts as
    # internet, the old behavior.
    $anyImpliesInternet = if (Get-Variable -Name AnyZoneImpliesInternet -Scope Script -ErrorAction SilentlyContinue) { $script:AnyZoneImpliesInternet } else { $true }
    foreach ($z in $Zones) {
        $zl = $z.Trim().ToLower()
        if (Test-ZoneNameInSet $zl $InternetZoneSet) { return $true }
        if ($zl -eq "any" -and $anyImpliesInternet) { return $true }
    }
    return $false
}

function Test-ZoneIsNamedInternetZone {
    # Like Test-ZoneTouchesInternet but "any" doesn't count: only a zone
    # actually named as internet facing. Firmer evidence of direction.
    param([array]$Zones, [array]$InternetZoneSet)
    foreach ($z in $Zones) {
        $zl = $z.Trim().ToLower()
        if (Test-ZoneNameInSet $zl $InternetZoneSet) { return $true }
    }
    return $false
}

function Test-ServiceNameImpliesRiskyApp {
    # Old rulebases name service objects after the protocol: "smtp",
    # "smtp-25", "SMTP_Relay_25". Try the whole name, then each piece.
    # "ms-rdp-3389" slips through; rare enough to live with.
    param([string]$ServiceToken, [hashtable]$RiskyApplications)
    if ($RiskyApplications.ContainsKey($ServiceToken)) { return $ServiceToken }
    $subTokens = @($ServiceToken -split '[-_\s\.]+' | Where-Object { $_ -ne "" })
    foreach ($sub in $subTokens) {
        if ($RiskyApplications.ContainsKey($sub)) { return $sub }
    }
    return $null
}

function Test-ServiceEffectivelyAny {
    # application-default with Application any restricts nothing, so it
    # counts as Service any.
    param($ParsedService, $Application, [string]$ServiceRaw)
    if ($null -eq $ParsedService) { return $true }
    return ($null -eq $Application) -and $ServiceRaw -and ($ServiceRaw.Trim().ToLower() -eq "application-default")
}

function Get-KnownDnsResolverMatches {
    # Every known resolver in the field, not just the first. Exact IP match,
    # ignoring a /32.
    param($AddrTokens)
    if (-not $AddrTokens) { return @() }
    $matches = foreach ($tok in $AddrTokens) {
        $ip = (Get-CidrParts $tok).IP
        if ($KnownPublicDnsResolvers -contains $ip) { $ip }
    }
    return @($matches)
}

function Test-ZoneInSet {
    # For any zone list (critical zones). Unlike the internet test, "any"
    # doesn't match.
    param([array]$Zones, [array]$ZoneSet)
    if (-not $ZoneSet -or $ZoneSet.Count -eq 0) { return $false }
    foreach ($z in $Zones) {
        if (Test-ZoneNameInSet $z.Trim().ToLower() $ZoneSet) { return $true }
    }
    return $false
}

function Test-ZonesCoveredFast {
    # Does Earlier cover Later? Inputs are already lowercased, which matters
    # inside the pairwise loops.
    param([array]$EarlierLower, [array]$LaterLower)
    if ($EarlierLower -contains "any") { return $true }
    foreach ($z in $LaterLower) {
        if ($EarlierLower -notcontains $z) { return $false }
    }
    return $true
}

function Test-ZonesEqualFast {
    # Same zones both ways. Lowercased input.
    param([array]$ALower, [array]$BLower)
    return (Test-ZonesCoveredFast -EarlierLower $ALower -LaterLower $BLower) -and (Test-ZonesCoveredFast -EarlierLower $BLower -LaterLower $ALower) -and (-not ($ALower -contains "any" -and -not ($BLower -contains "any"))) -and (-not ($BLower -contains "any" -and -not ($ALower -contains "any")))
}

function Test-ZonesOverlapFast {
    # At least one zone in common (for the correlation check).
    param([array]$ALower, [array]$BLower)
    if ($ALower -contains "any" -or $BLower -contains "any") { return $true }
    foreach ($z in $ALower) {
        if ($BLower -contains $z) { return $true }
    }
    return $false
}

function Test-AddressTouchesInternet {
    # A public IP counts, and so does any "[Negate] X": excluding one range
    # still leaves most of the internet in. An "any" address doesn't count by
    # itself (the zone decides that). Used for findings, not for direction,
    # which needs firmer evidence (see the next function).
    param($AddrTokens)
    if ($null -eq $AddrTokens) { return $false }
    foreach ($tok in $AddrTokens) {
        if ($tok -match '^\[Negate\]\s*') { return $true }
        if (Test-IsPlainIP $tok) {
            if (-not (Test-PrivateOrSpecialIP $tok)) { return $true }
        }
    }
    return $false
}

function Test-AddressIsExclusivelyPublic {
    # For the direction label only: a literal public IP is proof, a negation
    # isn't (it still includes private space too).
    param($AddrTokens)
    if ($null -eq $AddrTokens) { return $false }
    foreach ($tok in $AddrTokens) {
        if (Test-IsPlainIP $tok) {
            if (-not (Test-PrivateOrSpecialIP $tok)) { return $true }
        }
    }
    return $false
}

function Test-AddressIsExclusivelyPrivate {
    # True only if every token is a plain private IP/CIDR. Lets a private
    # address override a zone of "any" (zone and address must both match).
    # Ranges, names or anything mixed: false, to be on the safe side.
    param($AddrTokens)
    if ($null -eq $AddrTokens -or $AddrTokens.Count -eq 0) { return $false }
    foreach ($tok in $AddrTokens) {
        if ($tok -match '^\[Negate\]') { return $false }
        if (-not (Test-IsPlainIP $tok)) { return $false }
        if (-not (Test-PrivateOrSpecialIP $tok)) { return $false }
    }
    return $true
}

function Test-SideIsInternet {
    # A named internet zone always counts. A zone of "any" counts unless
    # the address is strictly private.
    param([array]$Zones, $AddrTokens, [array]$InternetZoneSet)
    if (Test-ZoneIsNamedInternetZone -Zones $Zones -InternetZoneSet $InternetZoneSet) { return $true }
    if (Test-AddressTouchesInternet -AddrTokens $AddrTokens) { return $true }
    if ((Test-ZoneTouchesInternet -Zones $Zones -InternetZoneSet $InternetZoneSet) -and -not (Test-AddressIsExclusivelyPrivate -AddrTokens $AddrTokens)) { return $true }
    return $false
}

# --------------------------------------------------------------------------
# Deterministic checks
# --------------------------------------------------------------------------


function Get-AppIdLabel {
    # "App-ID" is Palo Alto's word; other vendors get "application".
    param($Rule)
    if ($Rule.Vendor -and $Rule.Vendor -ne 'paloalto') { return 'application' }
    return 'App-ID'
}

function Invoke-DeterministicChecks {
    # VendorContext is $null for a PAN-OS CSV. Importers pass the vendor and
    # the zones where same-zone traffic passes with no rule.
    param([array]$Rules, [array]$InternetZoneSet, [array]$CriticalZoneSet, [int]$StaleHitDays = 365, [int]$MaxAddressListSize = 25, [hashtable]$VendorContext = $null, [switch]$SkipSecurityProfileCheck)
    $findings = @()

    # On a purely internal firewall (no zone in the ruleset is an internet
    # zone) "any" can't include the internet, so don't treat it as such.
    $script:AnyZoneImpliesInternet = $false
    foreach ($rule in $Rules) {
        foreach ($z in (@($rule.SrcZone) + @($rule.DstZone))) {
            if (Test-ZoneNameInSet $z.Trim().ToLower() $InternetZoneSet) { $script:AnyZoneImpliesInternet = $true; break }
        }
        if ($script:AnyZoneImpliesInternet) { break }
    }

    # Some exports have an Options column that never mentions logging; then
    # every rule would look unlogged. Only run the logging checks if at
    # least one rule shows logging. Session start/end logging or a forwarding
    # profile each count: either way a record of the traffic exists.
    $loggingPattern = "session start|session end"
    $forwardingPattern = "log forwarding"
    $anyRuleShowsLogging = $false
    foreach ($r in $Rules) {
        if ($r.HasOptionsColumn -and $r.Options -and $r.Options.ToLower() -match "$loggingPattern|$forwardingPattern") {
            $anyRuleShowsLogging = $true
            break
        }
    }

    $totalRules = $Rules.Count
    $ruleIndex = 0
    foreach ($rule in $Rules) {
        $ruleIndex++
        if ($ruleIndex % 25 -eq 0 -or $ruleIndex -eq $totalRules) {
            $pct = if ($totalRules -gt 0) { [int](($ruleIndex / $totalRules) * 100) } else { 100 }
            Write-Progress -Activity "Analyzing ruleset" -Status "Running checks ($ruleIndex of $totalRules)" -PercentComplete $pct -Id 1
        }
        if ($rule.Disabled) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Low"; Type = "disabled_rule_present"
                Detail   = "Rule is disabled but still present in the ruleset. Housekeeping candidate for removal if permanently retired."
            }
            continue
        }
        # A "DENY_..." rule that actually allows (or the other way round) is
        # easy to misread. Runs before the allow-only part below because it
        # needs deny rules too. Whole words only; names with both kinds of
        # word are skipped as ambiguous.
        $localName = Get-RuleLocalName $rule
        $nameTokensForAction = @($localName -split '[-_\s\.]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() })
        $denyIntentWords = @("deny", "block", "drop", "reject")
        $allowIntentWords = @("allow", "permit", "accept")
        $hasDenyIntent = ($denyIntentWords | Where-Object { $nameTokensForAction -contains $_ }).Count -gt 0
        $hasAllowIntent = ($allowIntentWords | Where-Object { $nameTokensForAction -contains $_ }).Count -gt 0
        $actionLowerForName = Get-ActionClass $rule.Action
        if ($hasDenyIntent -and -not $hasAllowIntent -and $actionLowerForName -eq "allow") {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "rule_name_action_mismatch"
                Detail   = "Rule name suggests it denies/blocks traffic, but Action is actually '$($rule.Action)'. Anyone reading the ruleset by name alone would reasonably assume this traffic is blocked when it isn't. Verify whether the name is stale (rule was toggled without renaming) or the action was set incorrectly."
            }
        }
        elseif ($hasAllowIntent -and -not $hasDenyIntent -and $actionLowerForName -eq "deny") {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "rule_name_action_mismatch"
                Detail   = "Rule name suggests it allows/permits traffic, but Action is actually '$($rule.Action)'. Anyone reading the ruleset by name alone would reasonably assume this traffic is permitted when it isn't. Verify whether the name is stale (rule was toggled without renaming) or the action was set incorrectly."
            }
        }

        # Names that say nothing ("Rule 5", "New Rule", "12"). The whole name
        # must match, "regola" included for Italian GUIs. Underscores count
        # as spaces because SRX names can't have spaces.
        $trimmedRuleName = $localName.Trim()
        $isGenericName = ($trimmedRuleName -match '(?i)^(rule|regola|policy|security[\s_]*rule|new[\s_]*rule|allow|deny|untitled|unnamed|default|sample|example)[\s_]*#?[\s_]*\d*$') -or ($trimmedRuleName -match '^\d+$')
        if ($isGenericName) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Low"; Type = "generic_rule_name"
                Detail   = "Rule name ('$($rule.Name)') does not describe what traffic it actually controls, reading like a GUI default or placeholder rather than a deliberate name. Every future review has to reconstruct intent from the match criteria alone, which slows down audits and raises the odds this rule gets misjudged during a cleanup pass. Rename to reflect source, destination, or purpose."
            }
        }

        if ($rule.Action -ne "allow") { continue }

        $srcIsInet = Test-SideIsInternet -Zones $rule.SrcZone -AddrTokens $rule.SrcAddr -InternetZoneSet $InternetZoneSet
        $dstIsInet = Test-SideIsInternet -Zones $rule.DstZone -AddrTokens $rule.DstAddr -InternetZoneSet $InternetZoneSet

        # A named internet zone as source is as open as "any".
        $srcZoneFullyOpen = ($rule.SrcZone -contains "any") -or (Test-ZoneTouchesInternet -Zones $rule.SrcZone -InternetZoneSet $InternetZoneSet)
        $serviceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
        if ($srcZoneFullyOpen -and $null -eq $rule.SrcAddr -and
            ($rule.DstZone -contains "any") -and $null -eq $rule.DstAddr -and
            $null -eq $rule.Application -and $serviceEffectivelyAny) {
            $srcZoneDetail = if ($rule.SrcZone -contains "any") { "'any'" } else { "an internet-facing zone ('$($rule.SrcZone -join ';')')" }
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Critical"; Type = "any_any_any_allow"
                Detail   = "Source zone is $srcZoneDetail with source address, destination zone/address, application, and service all left unrestricted (any). This is functionally the broadest possible rule, reachable by anyone on the internet."
            }
        }

        if (Test-IsNegatedPublicPattern -RawTokens $rule.SrcAddr -Strict) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "negated_rfc1918_effectively_public"
                Detail   = "Source address ('$($rule.SrcAddrRaw)') negates the private RFC1918 ranges. Functionally equivalent to 'any public source address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }
        if (Test-IsNegatedPublicPattern -RawTokens $rule.DstAddr -Strict) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "negated_rfc1918_effectively_public"
                Detail   = "Destination address ('$($rule.DstAddrRaw)') negates the private RFC1918 ranges. Functionally equivalent to 'any public destination address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }
        if (Test-IsAllRfc1918Pattern -RawTokens $rule.SrcAddr -Strict) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "all_rfc1918_effectively_private"
                Detail   = "Source address ('$($rule.SrcAddrRaw)') lists all three private RFC1918 ranges together. Functionally equivalent to 'any private source address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }
        if (Test-IsAllRfc1918Pattern -RawTokens $rule.DstAddr -Strict) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "all_rfc1918_effectively_private"
                Detail   = "Destination address ('$($rule.DstAddrRaw)') lists all three private RFC1918 ranges together. Functionally equivalent to 'any private destination address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }

        if ($rule.HitCount -match '^\d+$' -and [int64]$rule.HitCount -eq 0) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "zero_hit_count"
                Detail   = "Recorded hit count of zero. Candidate for removal after confirming the observation window is representative."
            }
        }

        # Panorama's own verdict, across all the firewalls the rule applies to.
        if ($rule.UsageStatus -eq "unused") {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "rule_usage_unused"
                Detail   = "Panorama reports this rule's status as 'unused' across the firewalls it applies to. Candidate for removal after confirming the observation window is representative."
            }
        }
        elseif ($rule.UsageStatus -eq "partially used") {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Low"; Type = "rule_usage_partially_used"
                Detail   = "Panorama reports this rule's status as 'partially used'. It has traffic on some firewalls it applies to but not others. Worth checking whether that's expected (e.g. a device-group rule that only makes sense on some sites) or a targeting mismatch."
            }
        }

        # Hit once, but not for a long time. Zero hits is zero_hit_count's job.
        # Tufin has a date but no counter: the date proves it was hit.
        $hasHits = ($rule.HitCount -match '^\d+$' -and [int64]$rule.HitCount -gt 0) -or ($rule.PSObject.Properties['LastHitMeansHit'] -and $rule.LastHitMeansHit)
        if ($hasHits -and $rule.LastHit) {
            $parsedLastHit = [datetime]::MinValue
            if ([datetime]::TryParse($rule.LastHit, [ref]$parsedLastHit)) {
                $daysSinceLastHit = (New-TimeSpan -Start $parsedLastHit -End (Get-Date)).Days
                if ($daysSinceLastHit -gt $StaleHitDays) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "stale_last_hit"
                        Detail   = "Last matched traffic $daysSinceLastHit days ago ($($rule.LastHit)), past the $StaleHitDays-day staleness threshold, despite $(if ($rule.HitCount -match '^\d+$') { "a non-zero hit count ($($rule.HitCount))" } else { 'having been hit' }). Worth confirming this is still needed rather than a one-off grant nobody uses anymore."
                    }
                }
            }
        }

        # Critical zones (SWIFT, CDE, HSM...) must be isolated from the rest
        # of the network too, not just the internet. Only with -CriticalZones.
        if ($rule.Action -eq "allow" -and $CriticalZoneSet.Count -gt 0) {
            $dstIsCritical = Test-ZoneInSet -Zones $rule.DstZone -ZoneSet $CriticalZoneSet
            $srcIsCritical = Test-ZoneInSet -Zones $rule.SrcZone -ZoneSet $CriticalZoneSet
            if ($dstIsCritical -and -not $srcIsCritical) {
                $criticalServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
                $broadDims = @()
                # Zone any with a specific source address isn't open.
                if (($rule.SrcZone -contains "any") -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr)) { $broadDims += "source zone" }
                if (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr) { $broadDims += "source address" }
                if (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr) { $broadDims += "destination address (reaches the entire critical zone, not a specific host)" }
                if ($null -eq $rule.Application -and $criticalServiceEffectivelyAny) { $broadDims += "application" }
                if ($criticalServiceEffectivelyAny) { $broadDims += "service" }
                if ($broadDims.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "unrestricted_access_to_critical_zone"
                        Detail   = "Rule allows access into critical zone '$($rule.DstZone -join ';')' from a non-critical zone ('$($rule.SrcZone -join ';')') with $($broadDims -join '/') left unrestricted. Critical zones (e.g. SWIFT secure zone, CDE, ATM, core banking) must be isolated from the general network per SWIFT CSCF, PCI DSS, and FFIEC guidance, not just from the internet."
                    }
                }
            }

            # The other direction: wide open egress out of a critical zone.
            if ($srcIsCritical -and -not $dstIsCritical) {
                $egressServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
                $egressBroadDims = @()
                if (($rule.DstZone -contains "any") -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr)) { $egressBroadDims += "destination zone" }
                if (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr) { $egressBroadDims += "destination address" }
                if (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr) { $egressBroadDims += "source address (any host in the critical zone, not a specific one)" }
                if ($null -eq $rule.Application -and $egressServiceEffectivelyAny) { $egressBroadDims += "application" }
                if ($egressServiceEffectivelyAny) { $egressBroadDims += "service" }
                if ($egressBroadDims.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "unrestricted_egress_from_critical_zone"
                        Detail   = "Rule allows critical zone '$($rule.SrcZone -join ';')' unrestricted reach OUT to a non-critical zone ('$($rule.DstZone -join ';')') with $($egressBroadDims -join '/') left unrestricted. Isolation requirements (SWIFT CSCF, PCI DSS, FFIEC) apply in both directions: a host inside the critical zone with unrestricted egress can exfiltrate data or reach a C2 server just as easily as an attacker could reach in through an overly broad inbound rule."
                    }
                }
            }

            # Tagged PCI/SWIFT/... but touching no critical zone: the tag is
            # stale or -CriticalZones is missing a zone. Whole tag words only;
            # skipped when a zone is any (that already includes the zone).
            if ($rule.Tags) {
                $complianceScopeTags = @("pci", "pci-dss", "cde", "swift", "cscf", "hipaa", "phi", "sox", "ffiec", "core-banking", "atm", "hsm")
                $tagTokensForScope = @($rule.Tags -split '[-_\s\.,;]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() })
                $matchedScopeTag = $complianceScopeTags | Where-Object { $tagTokensForScope -contains $_ } | Select-Object -First 1
                if ($matchedScopeTag) {
                    $srcTouchesAnyZone = $rule.SrcZone -contains "any"
                    $dstTouchesAnyZone = $rule.DstZone -contains "any"
                    $touchesCriticalZone = (Test-ZoneInSet -Zones $rule.SrcZone -ZoneSet $CriticalZoneSet) -or (Test-ZoneInSet -Zones $rule.DstZone -ZoneSet $CriticalZoneSet)
                    if (-not $touchesCriticalZone -and -not $srcTouchesAnyZone -and -not $dstTouchesAnyZone) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "Medium"; Type = "compliance_tag_without_critical_zone"
                            Detail   = "Rule is tagged '$($rule.Tags)' (matched compliance/critical-scope keyword '$matchedScopeTag'), but neither its source zone ('$($rule.SrcZone -join ';')') nor its destination zone ('$($rule.DstZone -join ';')') is in the configured critical zone set ($($CriticalZoneSet -join ', ')). Either the tag no longer reflects what this rule actually touches, or -CriticalZones is missing a zone this organization considers in scope. Worth confirming for anyone using Tags to build a compliance inventory."
                        }
                    }
                }
            }
        }

        # "Temporary" rules that are still broad: a classic audit finding.
        # Looks at the name and the tags, whole words only (so
        # "Attempted-Migration" isn't "temp").
        if ($rule.Action -eq "allow") {
            $tempKeywords = @("temp", "poc", "test", "trial")
            $nameTokens = @($localName -split '[-_\s\.]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() })
            $tagTokens = @()
            if ($rule.Tags) { $tagTokens = @($rule.Tags -split '[-_\s\.,;]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() }) }
            $matchedInName = $tempKeywords | Where-Object { $nameTokens -contains $_ } | Select-Object -First 1
            $matchedInTags = $tempKeywords | Where-Object { $tagTokens -contains $_ } | Select-Object -First 1
            $matchedKeyword = if ($matchedInName) { $matchedInName } else { $matchedInTags }
            $matchSource = if ($matchedInName -and $matchedInTags) { "both the rule name and its tags ('$($rule.Tags)')" } elseif ($matchedInName) { "the rule name itself" } else { "its tags ('$($rule.Tags)')" }
            $tempTagServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
            $isBroadRule = (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr) -or (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr) -or ($null -eq $rule.Application -and $tempTagServiceEffectivelyAny)
            if ($matchedKeyword -and $isBroadRule) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "temporary_tag_but_broad_rule"
                    Detail   = "Rule signals temporary/POC/test intent via $matchSource, but still has an unrestricted source/destination address or application. Temporary broad-access rules that are never tightened or removed are a common real world audit finding. Verify this is still needed."
                }
            }
            elseif ($matchedKeyword) {
                # Narrow but still "temporary": a reminder, so Low.
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Low"; Type = "temporary_tag_still_present"
                    Detail   = "Rule signals temporary/POC/test intent via $matchSource. Scope is already restricted, not a broad-exposure concern, but this suggests it was meant to be reviewed and removed at some point. Worth confirming it's still needed."
                }
            }
        }

        # Application any with explicit ports: no App-ID visibility, whatever
        # the port is.
        $serviceIsPortBased = $rule.Service -and ($rule.ServiceRaw.Trim().ToLower() -ne "application-default")
        if ($rule.Action -eq "allow" -and $null -eq $rule.Application -and $serviceIsPortBased) {
            $portsHere = Get-ServicePorts -ServiceTokens $rule.Service
            $cleartextHit = @($portsHere | Where-Object { $CleartextPorts -contains $_ })
            $riskyHit = @($portsHere | Where-Object { $RiskyPorts.ContainsKey($_) })
            $extraNote = ""
            if ($cleartextHit.Count -gt 0) {
                $extraNote = " At least one port ($($cleartextHit -join ',')) is also unencrypted/cleartext by design."
            }
            elseif ($riskyHit.Count -gt 0) {
                $extraNote = " At least one port ($($riskyHit -join ',')) is also on the high-risk list."
            }
            # Wording per vendor. On FortiGate an app control profile
            # ("app:" in Profile) already closes the gap.
            $portDetail = "Rule matches by port ($($rule.ServiceRaw)) with Application left as 'any', instead of a named App-ID.$extraNote Consider migrating to an explicit application for App-ID-based inspection."
            $skipPortBased = $false
            if ($rule.Vendor -eq 'fortios') {
                if ($rule.Profile -match '(^|;)app:') { $skipPortBased = $true }
                $portDetail = "Rule matches by port ($($rule.ServiceRaw)) with no application match and no application control profile.$extraNote Consider an application control profile, or matching applications in NGFW policy-based mode, so traffic is identified by application rather than by port alone."
            }
            elseif ($rule.Vendor -and $rule.Vendor -notin @('paloalto', 'junos')) {
                $portDetail = "Rule matches by port ($($rule.ServiceRaw)) with no application match.$extraNote Consider matching the application (application control / application aware rules on this platform), so traffic is identified by application rather than by port alone."
            }
            if ($rule.Vendor -eq 'junos') {
                $portDetail = "Rule matches by port ($($rule.ServiceRaw)) with no dynamic application.$extraNote Consider matching the application with AppSecure (match dynamic-application, with application junos-defaults), so traffic is identified by application rather than by port alone."
            }
            if (-not $skipPortBased) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "port_based_rule_missing_app_id"
                    Detail   = $portDetail
                }
            }
        }

        # 200 listed addresses are as hard to audit as "any".
        if ($rule.Action -eq "allow") {
            $srcCount = $rule.SrcAddrTokenCount
            $dstCount = $rule.DstAddrTokenCount
            $oversizedSides = @()
            if ($srcCount -gt $MaxAddressListSize) { $oversizedSides += "source ($srcCount addresses)" }
            if ($dstCount -gt $MaxAddressListSize) { $oversizedSides += "destination ($dstCount addresses)" }
            if ($oversizedSides.Count -gt 0) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "oversized_address_list"
                    Detail   = "Rule lists an unusually large number of individual addresses in $($oversizedSides -join ' and ') (threshold: $MaxAddressListSize). Large enumerated address lists are hard to audit, easy to accumulate stale entries in, and just as difficult to reason about as an unrestricted rule even though nothing here literally says 'any'. Consider consolidating into a CIDR range or address group, or confirming every entry is still needed."
                }
            }
        }

        # No logging, no trail. Only when the export carries logging info
        # (see $anyRuleShowsLogging).
        if ($rule.Action -eq "allow" -and $rule.HasOptionsColumn -and $anyRuleShowsLogging) {
            $optionsLower = $rule.Options.ToLower()
            if ($optionsLower -notmatch "$loggingPattern|$forwardingPattern") {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "no_logging_enabled"
                    Detail   = "Rule shows no evidence of logging enabled (neither log-at-session-start nor log-at-session-end, nor a Log Forwarding profile). If this traffic is ever involved in an incident, there's no record of it having occurred. Verify logging is intentionally disabled here, not an oversight."
                }
            }
        }

        # A public resolver bypasses corporate DNS, whatever the protocol.
        if ($rule.Action -eq "allow") {
            $resolverMatches = Get-KnownDnsResolverMatches -AddrTokens $rule.DstAddr
            if ($resolverMatches.Count -gt 0) {
                $resolverList = $resolverMatches -join ", "
                $plural = if ($resolverMatches.Count -gt 1) { "s" } else { "" }
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "reaches_known_public_dns_resolver"
                    Detail   = "Destination includes $($resolverMatches.Count) well-known public DNS resolver$($plural) ($resolverList). Direct reachability to third-party resolvers can bypass internal DNS security controls (filtering, threat-intel blocklists), especially over DoH/DoT where the query itself is encrypted and invisible to inspection. Verify this is intentional and not a bypass of corporate DNS."
                }
            }

            # Plain, unencrypted DNS: port 53 or the dns / dns-base app.
            $dnsPorts = Get-ServicePorts -ServiceTokens $rule.Service
            $dnsByPort = $dnsPorts -contains 53
            $dnsByApp = (-not $dnsByPort) -and (@($rule.Application | Where-Object { $_ -in @('dns', 'dns-base') }).Count -gt 0)
            if ($dnsByPort -or $dnsByApp) {
                $dnsWhat = if ($dnsByPort) { "plain DNS (port 53)" } else { "plain DNS ($(Get-AppIdLabel $rule) '$(@($rule.Application | Where-Object { $_ -in @('dns', 'dns-base') })[0])')" }
                if ($null -eq $rule.DstAddr) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "plain_dns_to_unrestricted_destination"
                        Detail   = "Rule allows $dnsWhat to an unrestricted destination (any). Unencrypted queries can go to literally any server, with no way to filter or inspect where they end up. A common DNS-tunneling/data-exfiltration pattern, not just a DNS-bypass one. Consider scoping the destination to approved resolvers."
                    }
                }
                elseif ($resolverMatches.Count -gt 0) {
                    $resolverList = $resolverMatches -join ", "
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "plain_dns_to_known_resolver"
                        Detail   = "Rule allows $dnsWhat specifically to a well-known public resolver ($resolverList). Unlike DoH/DoT to the same destination, the query content itself is visible in cleartext to anyone observing the traffic, on top of bypassing internal DNS controls."
                    }
                }
            }
        }

        if ($srcIsInet) {
            # Context more than risk, hence Medium: the dangerous cases get
            # their own findings. The text says whether the zone or the
            # address is what's open.
            $zoneIsTheReason = Test-ZoneTouchesInternet -Zones $rule.SrcZone -InternetZoneSet $InternetZoneSet
            $zonePhrase = if ($zoneIsTheReason) { "source zone '$($rule.SrcZone -join ';')' is internet-facing" } else { "source address itself includes public IP space" }
            $addrPhrase = if ($null -eq $rule.SrcAddr) { "with an unrestricted source address (any), reachable from anywhere on the internet" } else { "though scoped to a specific source address ('$($rule.SrcAddrRaw)'), not an unrestricted source" }
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "inbound_from_internet"
                Detail   = "Inbound rule reachable from the internet ($zonePhrase) $addrPhrase, reaching destination zone='$($rule.DstZone -join ';')', address='$($rule.DstAddrRaw)'."
            }
        }

        if ($dstIsInet) {
            # Same thing for the destination side.
            $dstZoneIsTheReason = Test-ZoneTouchesInternet -Zones $rule.DstZone -InternetZoneSet $InternetZoneSet
            $dstZonePhrase = if ($dstZoneIsTheReason) { "destination zone '$($rule.DstZone -join ';')' is internet-facing" } else { "destination address itself includes public IP space" }
            $dstAddrPhrase = if ($null -eq $rule.DstAddr) { "with an unrestricted destination address (any), reaching anywhere on the internet" } else { "though scoped to a specific destination address ('$($rule.DstAddrRaw)'), not an unrestricted destination" }
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "outbound_to_internet"
                Detail   = "Outbound rule reaching the internet ($dstZonePhrase) $dstAddrPhrase, from source zone='$($rule.SrcZone -join ';')', address='$($rule.SrcAddrRaw)'."
            }
        }

        if (-not $srcIsInet -and $dstIsInet -and $null -eq $rule.DstAddr -and $null -ne $rule.Application) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "outbound_any_public_defined_app"
                Detail   = "Outbound to any public destination, but application is restricted to $($rule.Application -join ','). Narrower than fully open, still worth confirming business need for an unrestricted destination."
            }
        }

        # Application any with a fixed port is a port-based rule, not an open
        # one (port_based_rule_missing_app_id covers it).
        if (-not $srcIsInet -and $dstIsInet -and $null -ne $rule.DstAddr -and $null -eq $rule.Application -and (Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw)) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "outbound_defined_dest_any_app"
                Detail   = "Outbound to a defined destination ($($rule.DstAddrRaw)), but application/service is unrestricted (any). Consider scoping to the specific application(s) actually needed."
            }
        }

        # Risky protocols going out: an exfiltration / C2 channel if the
        # host is compromised. High, like the internal ones, since it needs a
        # foothold first.
        if (-not $srcIsInet -and $dstIsInet) {
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($RiskyApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "outbound_risky_application"
                            Detail   = "Outbound rule permits a high-risk application ($($RiskyApplications[$app]), $(Get-AppIdLabel $rule) '$app') from source address='$($rule.SrcAddrRaw)' out to the internet. A potential data-exfiltration or tunneling channel if the source host is ever compromised. Verify this is intentional and scoped down if not."
                        }
                    }
                }
            }
            # Service objects named after the protocol ("smtp").
            if ($rule.Service) {
                foreach ($svc in $rule.Service) {
                    $matchedRiskyName = Test-ServiceNameImpliesRiskyApp -ServiceToken $svc -RiskyApplications $RiskyApplications
                    if ($matchedRiskyName) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "outbound_risky_application"
                            Detail   = "Outbound rule permits a high-risk application ($($RiskyApplications[$matchedRiskyName]), named as Service '$svc' rather than $(Get-AppIdLabel $rule)) from source address='$($rule.SrcAddrRaw)' out to the internet. A potential data-exfiltration or tunneling channel if the source host is ever compromised. Verify this is intentional and scoped down if not."
                        }
                    }
                }
            }
            $outPorts = Get-ServicePorts -ServiceTokens $rule.Service
            foreach ($port in $outPorts) {
                if ($RiskyPorts.ContainsKey($port)) {
                    $cleartextNote = if ($CleartextPorts -contains $port) { ". UNENCRYPTED/cleartext protocol" } else { "" }
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "High"; Type = "outbound_risky_port"
                        Detail   = "Outbound rule permits a high-risk port ($($RiskyPorts[$port]), port $port)$cleartextNote from source address='$($rule.SrcAddrRaw)' out to the internet. A potential data-exfiltration or tunneling channel if the source host is ever compromised. Verify this is intentional and scoped down if not."
                    }
                }
            }

            # ICMP out to anywhere: a covert channel nobody inspects. "ping"
            # and "icmp" are separate App-IDs, so check both, plus IPv6 and
            # traceroute. A service named icmp counts too, just in case.
            $icmpFamilyApps = @("ping", "icmp", "ipv6-icmp", "traceroute")
            $hasIcmpApp = $rule.Application -and (@($rule.Application | Where-Object { $icmpFamilyApps -contains $_ }).Count -gt 0)
            $hasIcmpService = $rule.Service -and (@($rule.Service | Where-Object { $_ -match "icmp" }).Count -gt 0)
            if (($hasIcmpApp -or $hasIcmpService) -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr)) {
                $icmpMatchSource = if ($hasIcmpApp) { "Application ($(($rule.Application | Where-Object { $icmpFamilyApps -contains $_ }) -join ', '))" } else { "Service" }
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "outbound_icmp_to_unrestricted_destination"
                    Detail   = "Rule allows outbound ICMP-family traffic ($icmpMatchSource) from source address='$($rule.SrcAddrRaw)' to an unrestricted destination (any). ICMP is often overlooked by inspection compared to TCP/UDP traffic; data can be encoded in echo/payload fields to exfiltrate data or maintain a covert C2 channel. Consider scoping the destination to specific, known hosts if this is meant for reachability testing."
                }
            }
        }

        # Only the source matters here: an internet destination as well
        # doesn't make it any safer.
        if ($srcIsInet) {
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($RiskyApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "Critical"; Type = "inbound_risky_application"
                            Detail   = "Inbound from the internet using a high-risk application ($($RiskyApplications[$app]), $(Get-AppIdLabel $rule) '$app') toward destination address='$($rule.DstAddrRaw)'. Verify this is intentional and scoped down (specific source IPs, MFA/VPN in front of it) if not."
                        }
                    }
                }
            }
            if ($rule.Service) {
                foreach ($svc in $rule.Service) {
                    $matchedRiskyName = Test-ServiceNameImpliesRiskyApp -ServiceToken $svc -RiskyApplications $RiskyApplications
                    if ($matchedRiskyName) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "Critical"; Type = "inbound_risky_application"
                            Detail   = "Inbound from the internet using a high-risk application ($($RiskyApplications[$matchedRiskyName]), named as Service '$svc' rather than $(Get-AppIdLabel $rule)) toward destination address='$($rule.DstAddrRaw)'. Verify this is intentional and scoped down (specific source IPs, MFA/VPN in front of it) if not."
                        }
                    }
                }
            }
            $ports = Get-ServicePorts -ServiceTokens $rule.Service
            foreach ($port in $ports) {
                if ($RiskyPorts.ContainsKey($port)) {
                    $cleartextNote = if ($CleartextPorts -contains $port) { ". This is an UNENCRYPTED/cleartext protocol; credentials and data are visible to anyone who can observe the traffic" } else { "" }
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "inbound_risky_port"
                        Detail   = "Inbound from the internet on a high-risk port ($($RiskyPorts[$port]), port $port)$cleartextNote toward destination address='$($rule.DstAddrRaw)'. Verify this is intentional and scoped down if not."
                    }
                }
            }

            # Amplification: our server used against someone else. UDP only.
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($AmplificationProneApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "exposed_amplification_prone_service"
                            Detail   = "Inbound from the internet to an amplification-prone UDP service ($($AmplificationProneApplications[$app]), $(Get-AppIdLabel $rule) '$app') toward destination address='$($rule.DstAddrRaw)'. A server answering this from the open internet can be abused as a reflector/amplifier in a DDoS attack against a third party: the attacker spoofs the victim's source address, and your server sends its (often much larger) response there instead of back to the attacker. This is a risk to others as much as to this network. Restrict the source to specific, known hosts if this is meant for legitimate reachability."
                        }
                    }
                }
            }
            $udpPortsHere = Get-ServiceUdpPorts -ServiceTokens $rule.Service
            foreach ($port in $udpPortsHere) {
                if ($AmplificationPronePorts.ContainsKey($port)) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "High"; Type = "exposed_amplification_prone_service"
                        Detail   = "Inbound from the internet to an amplification-prone UDP service ($($AmplificationPronePorts[$port]), UDP port $port) toward destination address='$($rule.DstAddrRaw)'. A server answering this from the open internet can be abused as a reflector/amplifier in a DDoS attack against a third party: the attacker spoofs the victim's source address, and your server sends its (often much larger) response there instead of back to the attacker. This is a risk to others as much as to this network. Restrict the source to specific, known hosts if this is meant for legitimate reachability."
                    }
                }
            }
        }

        # Catch-all: internet on either side with some field left open. It
        # overlaps with the narrower checks above on purpose.
        if ($rule.Action -eq "allow" -and ($srcIsInet -or $dstIsInet)) {
            $serviceEffectivelyAny2 = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
            $anyDims = @()
            if (($rule.SrcZone -contains "any") -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr)) { $anyDims += "source zone" }
            if (Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr) { $anyDims += "source address" }
            if (($rule.DstZone -contains "any") -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr)) { $anyDims += "destination zone" }
            if (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr) { $anyDims += "destination address" }
            # Application any on a fixed port isn't "open application".
            if ($null -eq $rule.Application -and $serviceEffectivelyAny2) { $anyDims += "application" }
            if ($serviceEffectivelyAny2) { $anyDims += "service" }
            if ($anyDims.Count -gt 0) {
                # Everything open: Critical, even through a named internet
                # zone (any_any_any_allow only catches the literal "any").
                $severity = if ((Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr) -and (Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr) -and $null -eq $rule.Application -and $serviceEffectivelyAny2) { "Critical" } else { "High" }
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = $severity; Type = "internet_exposed_any_field"
                    Detail   = "Rule touches the internet (inbound and/or outbound: source '$($rule.SrcZone -join ';')' / '$($rule.SrcAddrRaw)', destination '$($rule.DstZone -join ';')' / '$($rule.DstAddrRaw)') with $($anyDims -join '/') left unrestricted (any). Every internet-adjacent 'any' widens what this rule can actually match."
                }
            }
        }

        # --- Fully internal traffic: broad exposure (lateral movement risk) ---
        if (-not $srcIsInet -and -not $dstIsInet) {
            $srcEffectivelyAny = Test-AddressFieldEffectivelyAny -RawTokens $rule.SrcAddr
            $dstEffectivelyAny = Test-AddressFieldEffectivelyAny -RawTokens $rule.DstAddr
            $internalServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
            $internalAppEffectivelyOpen = $null -eq $rule.Application -and $internalServiceEffectivelyAny
            if ($srcEffectivelyAny -or $dstEffectivelyAny -or $internalAppEffectivelyOpen -or $internalServiceEffectivelyAny) {
                $broadDims = @()
                if ($srcEffectivelyAny) { $broadDims += "source address" }
                if ($dstEffectivelyAny) { $broadDims += "destination address" }
                if ($internalAppEffectivelyOpen) { $broadDims += "application" }
                if ($internalServiceEffectivelyAny) { $broadDims += "service" }
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "broad_internal_exposure"
                    Detail   = "Internal-to-internal rule ($($rule.SrcZone -join ';') -> $($rule.DstZone -join ';')) with $($broadDims -join '/') left unrestricted (any). A common lateral-movement/ransomware-propagation pattern even though neither side touches the internet."
                }
            }

            # --- Fully internal traffic: risky/cleartext port or application ---
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($RiskyApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "internal_risky_application"
                            Detail   = "Internal rule ($($rule.SrcZone -join ';') -> $($rule.DstZone -join ';')) allows a high-risk application ($($RiskyApplications[$app]), $(Get-AppIdLabel $rule) '$app'). Lateral-movement risk even though this doesn't touch the internet directly."
                        }
                    }
                }
            }
            if ($rule.Service) {
                foreach ($svc in $rule.Service) {
                    $matchedRiskyName = Test-ServiceNameImpliesRiskyApp -ServiceToken $svc -RiskyApplications $RiskyApplications
                    if ($matchedRiskyName) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "internal_risky_application"
                            Detail   = "Internal rule ($($rule.SrcZone -join ';') -> $($rule.DstZone -join ';')) allows a high-risk application ($($RiskyApplications[$matchedRiskyName]), named as Service '$svc' rather than $(Get-AppIdLabel $rule)). Lateral-movement risk even though this doesn't touch the internet directly."
                        }
                    }
                }
            }
            $intPorts = Get-ServicePorts -ServiceTokens $rule.Service
            foreach ($port in $intPorts) {
                if ($RiskyPorts.ContainsKey($port)) {
                    $cleartextNote = if ($CleartextPorts -contains $port) { ". UNENCRYPTED/cleartext protocol" } else { "" }
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "High"; Type = "internal_risky_port"
                        Detail   = "Internal rule ($($rule.SrcZone -join ';') -> $($rule.DstZone -join ';')) allows a high-risk port ($($RiskyPorts[$port]), port $port)$cleartextNote. Lateral-movement risk even though this doesn't touch the internet directly."
                    }
                }
            }
        }

        # --- Exposed to the internet but no security profile applied ---
        # Not with -NoSecurityProfileChecks (another device inspects).
        if (-not $SkipSecurityProfileCheck -and ($srcIsInet -or $dstIsInet) -and ($rule.Profile.ToLower() -eq "" -or $rule.Profile.ToLower() -eq "none")) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "no_security_profile_on_exposed_rule"
                Detail   = "Rule touches the internet (inbound or outbound) but has no security profile group applied (Profile='$($rule.Profile)'). No threat prevention/antivirus/URL filtering inspection on this exposed traffic."
            }
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # Parse addresses, lowercase zones and classify actions once: the
    # pairwise loops below would otherwise redo it on every comparison.
    $parsedSrcAddr = @{}
    $parsedDstAddr = @{}
    $lowerSrcZone = @{}
    $lowerDstZone = @{}
    $actionClass = @{}
    foreach ($r in $Rules) {
        $parsedSrcAddr[$r.Index] = ConvertTo-ParsedAddressList -AddrTokens $r.SrcAddr
        $parsedDstAddr[$r.Index] = ConvertTo-ParsedAddressList -AddrTokens $r.DstAddr
        $lowerSrcZone[$r.Index] = @($r.SrcZone | ForEach-Object { $_.ToLower() })
        $lowerDstZone[$r.Index] = @($r.DstZone | ForEach-Object { $_.ToLower() })
        $actionClass[$r.Index] = Get-ActionClass $r.Action
    }

    # Duplicates and shadowing among enabled allow rules, in order.
    # Earlier rules are bucketed by zone pair (plus a list of "any" zone
    # rules), so each rule is only compared with ones whose zones can match.
    # Buckets are per Scope: different VDOMs / logical systems / devices
    # never see each other's traffic.
    $enabledAllow = @($Rules | Where-Object { -not $_.Disabled -and $_.Action -eq "allow" })
    $wildcardIdx = @{}
    $sigBuckets = @{}
    for ($i = 0; $i -lt $enabledAllow.Count; $i++) {
        if ($i % 100 -eq 0 -or $i -eq $enabledAllow.Count - 1) {
            $pct = if ($enabledAllow.Count -gt 0) { [int](($i / $enabledAllow.Count) * 100) } else { 100 }
            Write-Progress -Activity "Analyzing ruleset" -Status "Checking for shadowed/duplicate rules ($i of $($enabledAllow.Count))" -PercentComplete $pct -Id 1
        }
        $rule = $enabledAllow[$i]
        $ruleSrc = $parsedSrcAddr[$rule.Index]
        $ruleDst = $parsedDstAddr[$rule.Index]
        $ruleSrcZ = $lowerSrcZone[$rule.Index]
        $ruleDstZ = $lowerDstZone[$rule.Index]
        $ruleSig = (($ruleSrcZ | Sort-Object) -join ",") + "|" + (($ruleDstZ | Sort-Object) -join ",")

        $candidates = New-Object System.Collections.Generic.List[int]
        $scopeKey = "$($rule.Scope)"
        $ruleSig = "$scopeKey#" + $ruleSig
        if ($wildcardIdx.ContainsKey($scopeKey)) { $candidates.AddRange($wildcardIdx[$scopeKey]) }
        if ($sigBuckets.ContainsKey($ruleSig)) { $candidates.AddRange($sigBuckets[$ruleSig]) }
        $candidates.Sort()

        foreach ($j in $candidates) {
            $earlier = $enabledAllow[$j]
            $earlierSrc = $parsedSrcAddr[$earlier.Index]
            $earlierDst = $parsedDstAddr[$earlier.Index]
            $earlierSrcZ = $lowerSrcZone[$earlier.Index]
            $earlierDstZ = $lowerDstZone[$earlier.Index]

            $sameSrcZone = Test-ZonesEqualFast -ALower $earlierSrcZ -BLower $ruleSrcZ
            $sameDstZone = Test-ZonesEqualFast -ALower $earlierDstZ -BLower $ruleDstZ
            $sameSrcAddr = (Test-NetworksContainFast $earlierSrc $ruleSrc) -and (Test-NetworksContainFast $ruleSrc $earlierSrc)
            $sameDstAddr = (Test-NetworksContainFast $earlierDst $ruleDst) -and (Test-NetworksContainFast $ruleDst $earlierDst)
            $sameApp = (Test-ListContains $earlier.Application $rule.Application) -and (Test-ListContains $rule.Application $earlier.Application)
            $sameService = (Test-ListContains $earlier.Service $rule.Service) -and (Test-ListContains $rule.Service $earlier.Service)

            if ($sameSrcZone -and $sameDstZone -and $sameSrcAddr -and $sameDstAddr -and $sameApp -and $sameService) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "duplicate_rule"
                    Detail   = "Identical match criteria (zone/address/application/service) to earlier rule '$($earlier.Name)'. Functionally redundant."
                }
                break
            }

            # The service has to be covered too: tcp-853 doesn't shadow udp-53.
            $shadowed = (Test-ZonesCoveredFast -EarlierLower $earlierSrcZ -LaterLower $ruleSrcZ) -and
                        (Test-ZonesCoveredFast -EarlierLower $earlierDstZ -LaterLower $ruleDstZ) -and
                        (Test-NetworksContainFast $earlierSrc $ruleSrc) -and
                        (Test-NetworksContainFast $earlierDst $ruleDst) -and
                        (Test-ListContains $earlier.Application $rule.Application) -and
                        (Test-ListContains $earlier.Service $rule.Service)
            if ($shadowed) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "High"; Type = "shadowed_rule"
                    Detail   = "Fully covered by earlier rule '$($earlier.Name)'. This rule can never be hit, effectively dead policy."
                }
                break
            }
        }

        if (($ruleSrcZ -contains "any") -or ($ruleDstZ -contains "any")) {
            if (-not $wildcardIdx.ContainsKey($scopeKey)) { $wildcardIdx[$scopeKey] = New-Object System.Collections.Generic.List[int] }
            $wildcardIdx[$scopeKey].Add($i)
        }
        else {
            if (-not $sigBuckets.ContainsKey($ruleSig)) { $sigBuckets[$ruleSig] = New-Object System.Collections.Generic.List[int] }
            $sigBuckets[$ruleSig].Add($i)
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # Shadowing across actions, over all enabled rules: this is where
    # shadowing changes what the traffic does. Same bucketing as above.
    $enabledAll = @($Rules | Where-Object { $null -ne $_ -and -not $_.Disabled })
    $wildcardIdx2 = @{}
    $sigBuckets2 = @{}
    for ($i = 0; $i -lt $enabledAll.Count; $i++) {
        if ($i % 100 -eq 0 -or $i -eq $enabledAll.Count - 1) {
            $pct = if ($enabledAll.Count -gt 0) { [int](($i / $enabledAll.Count) * 100) } else { 100 }
            Write-Progress -Activity "Analyzing ruleset" -Status "Checking for cross-action shadowing ($i of $($enabledAll.Count))" -PercentComplete $pct -Id 1
        }
        $rule = $enabledAll[$i]
        $ruleSrc = $parsedSrcAddr[$rule.Index]
        $ruleDst = $parsedDstAddr[$rule.Index]
        $ruleSrcZ = $lowerSrcZone[$rule.Index]
        $ruleDstZ = $lowerDstZone[$rule.Index]
        $ruleSig = (($ruleSrcZ | Sort-Object) -join ",") + "|" + (($ruleDstZ | Sort-Object) -join ",")

        $candidates2 = New-Object System.Collections.Generic.List[int]
        $scopeKey = "$($rule.Scope)"
        $ruleSig = "$scopeKey#" + $ruleSig
        if ($wildcardIdx2.ContainsKey($scopeKey)) { $candidates2.AddRange($wildcardIdx2[$scopeKey]) }
        if ($sigBuckets2.ContainsKey($ruleSig)) { $candidates2.AddRange($sigBuckets2[$ruleSig]) }
        $candidates2.Sort()

        $foundCorrelationForRule = $false
        $ruleClass = $actionClass[$rule.Index]
        foreach ($j in $candidates2) {
            $earlier = $enabledAll[$j]
            $sameAction = $actionClass[$earlier.Index] -eq $ruleClass
            $earlierSrc = $parsedSrcAddr[$earlier.Index]
            $earlierDst = $parsedDstAddr[$earlier.Index]
            $earlierSrcZ = $lowerSrcZone[$earlier.Index]
            $earlierDstZ = $lowerDstZone[$earlier.Index]

            $crossShadowed = (Test-ZonesCoveredFast -EarlierLower $earlierSrcZ -LaterLower $ruleSrcZ) -and
                             (Test-ZonesCoveredFast -EarlierLower $earlierDstZ -LaterLower $ruleDstZ) -and
                             (Test-NetworksContainFast $earlierSrc $ruleSrc) -and
                             (Test-NetworksContainFast $earlierDst $ruleDst) -and
                             (Test-ListContains $earlier.Application $rule.Application) -and
                             (Test-ListContains $earlier.Service $rule.Service)

            # The first earlier rule that covers this one decides what happens
            # to its traffic. If it has the same action, no later candidate
            # matters: an allow further down can't open what a deny already
            # dropped.
            if ($crossShadowed -and $sameAction) { break }
            if ($sameAction) { continue }

            if ($crossShadowed) {
                if ($actionClass[$earlier.Index] -eq "allow" -and $ruleClass -eq "deny") {
                    # The deny never fires: that traffic is open.
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "allow_shadows_deny"
                        Detail   = "This DENY rule is fully covered by an earlier ALLOW rule ('$($earlier.Name)') with equal-or-broader scope. It can never trigger. The traffic it was meant to block is actually permitted by the earlier rule. Whoever relies on this deny believes the traffic is blocked; it isn't."
                    }
                }
                elseif ($actionClass[$earlier.Index] -eq "deny" -and $ruleClass -eq "allow") {
                    # The allow never fires: a functional bug, not exposure.
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "deny_shadows_allow"
                        Detail   = "This ALLOW rule is fully covered by an earlier DENY rule ('$($earlier.Name)') with equal-or-broader scope. It can never trigger. The traffic it was meant to permit is actually still blocked by the earlier rule. Not a security exposure, but a functional bug. Whoever relies on this allow believes access exists when it doesn't."
                    }
                }
                break
            }

            # Correlation (Al-Shaer/Hamed): different actions, partial overlap,
            # neither contains the other. Once per rule, Low.
            if (-not $foundCorrelationForRule) {
                $laterCoversEarlier = (Test-ZonesCoveredFast -EarlierLower $ruleSrcZ -LaterLower $earlierSrcZ) -and
                                      (Test-ZonesCoveredFast -EarlierLower $ruleDstZ -LaterLower $earlierDstZ) -and
                                      (Test-NetworksContainFast $ruleSrc $earlierSrc) -and
                                      (Test-NetworksContainFast $ruleDst $earlierDst) -and
                                      (Test-ListContains $rule.Application $earlier.Application) -and
                                      (Test-ListContains $rule.Service $earlier.Service)
                if (-not $laterCoversEarlier) {
                    $overlaps = (Test-ZonesOverlapFast $earlierSrcZ $ruleSrcZ) -and
                                (Test-ZonesOverlapFast $earlierDstZ $ruleDstZ) -and
                                (Test-NetworksOverlapFast $earlierSrc $ruleSrc) -and
                                (Test-NetworksOverlapFast $earlierDst $ruleDst) -and
                                (Test-ListsOverlap $earlier.Application $rule.Application) -and
                                (Test-ListsOverlap $earlier.Service $rule.Service)
                    if ($overlaps) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "Low"; Type = "correlation_anomaly"
                            Detail   = "This rule's match criteria partially overlap with an earlier rule ('$($earlier.Name)', action $($earlier.Action)) without either rule fully covering the other. For the traffic that matches both, the effective action depends only on which rule sits first in the rulebase, something neither rule states explicitly on its own. Review whether this overlap is intentional; if not, scope one of the two rules so they no longer share matching traffic."
                        }
                        $foundCorrelationForRule = $true
                    }
                }
            }
        }

        # Generalization: an earlier, narrower rule covered by this later,
        # broader one with the other action. Not dead, but fragile: delete or
        # reorder the exception and its traffic silently changes. The buckets
        # above only look backwards from narrow to broad, so scan back by
        # hand, and only when this rule looks broad (zone or address any).
        $ruleLooksBroadEnoughToGeneralize = ($ruleSrcZ -contains "any") -or ($ruleDstZ -contains "any") -or ($null -eq $ruleSrc) -or ($null -eq $ruleDst)
        if ($ruleLooksBroadEnoughToGeneralize) {
            for ($k = 0; $k -lt $i; $k++) {
                $candidateEarlier = $enabledAll[$k]
                if ($actionClass[$candidateEarlier.Index] -eq $ruleClass) { continue }
                if ("$($candidateEarlier.Scope)" -ne $scopeKey) { continue }   # other VDOM / logical system / device
                $candSrc = $parsedSrcAddr[$candidateEarlier.Index]
                $candDst = $parsedDstAddr[$candidateEarlier.Index]
                $candSrcZ = $lowerSrcZone[$candidateEarlier.Index]
                $candDstZ = $lowerDstZone[$candidateEarlier.Index]

                $laterCoversEarlier2 = (Test-ZonesCoveredFast -EarlierLower $ruleSrcZ -LaterLower $candSrcZ) -and
                                       (Test-ZonesCoveredFast -EarlierLower $ruleDstZ -LaterLower $candDstZ) -and
                                       (Test-NetworksContainFast $ruleSrc $candSrc) -and
                                       (Test-NetworksContainFast $ruleDst $candDst) -and
                                       (Test-ListContains $rule.Application $candidateEarlier.Application) -and
                                       (Test-ListContains $rule.Service $candidateEarlier.Service)
                if (-not $laterCoversEarlier2) { continue }

                # Identical rules are shadowing, not generalization.
                $earlierCoversLater2 = (Test-ZonesCoveredFast -EarlierLower $candSrcZ -LaterLower $ruleSrcZ) -and
                                       (Test-ZonesCoveredFast -EarlierLower $candDstZ -LaterLower $ruleDstZ) -and
                                       (Test-NetworksContainFast $candSrc $ruleSrc) -and
                                       (Test-NetworksContainFast $candDst $ruleDst) -and
                                       (Test-ListContains $candidateEarlier.Application $rule.Application) -and
                                       (Test-ListContains $candidateEarlier.Service $rule.Service)
                if ($earlierCoversLater2) { continue }

                $findings += [PSCustomObject]@{
                    RuleName = $candidateEarlier.Name; Severity = "Low"; Type = "generalization_anomaly"
                    Detail   = "This rule is fully covered by a later, broader rule ('$($rule.Name)') that uses a different action ($($rule.Action)). Right now this rule fires first as a deliberate-looking exception ahead of that broader rule. If it is ever removed (e.g. during cleanup, on the assumption the later rule already covers it) or reordered below it, the effective behavior for its traffic changes silently, with nothing from the firewall itself flagging the change. Verify this is a known, intentional exception."
                }
                break
            }
        }

        if (($ruleSrcZ -contains "any") -or ($ruleDstZ -contains "any")) {
            if (-not $wildcardIdx2.ContainsKey($scopeKey)) { $wildcardIdx2[$scopeKey] = New-Object System.Collections.Generic.List[int] }
            $wildcardIdx2[$scopeKey].Add($i)
        }
        else {
            if (-not $sigBuckets2.ContainsKey($ruleSig)) { $sigBuckets2[$ruleSig] = New-Object System.Collections.Generic.List[int] }
            $sigBuckets2[$ruleSig].Add($i)
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # PAN-OS allows intrazone traffic by default, so an internet zone needs
    # an explicit block to itself. Any deny-type rule anywhere does; the text
    # suggests drop, which (unlike deny) sends nothing back to a scanner.
    # Other vendors: only zones that really allow intrazone traffic.
    $intrazoneZones = @($InternetZoneSet)
    if ($VendorContext) {
        $allowZones = @($VendorContext.IntrazoneAllowZones)
        $intrazoneZones = @($InternetZoneSet | Where-Object { $allowZones -contains $_ }) + @($allowZones | Where-Object { $InternetZoneSet -notcontains $_ -and (Test-ZoneNameInSet $_ $InternetZoneSet) })
    }
    # Several VDOMs / logical systems / devices: each one needs its own
    # block rule, and only for the zones it actually uses.
    $scopeNames = @($Rules | ForEach-Object { "$($_.Scope)" } | Select-Object -Unique)
    $multiScope = $scopeNames.Count -gt 1
    $intrazoneMissing = @()
    foreach ($scopeName in $scopeNames) {
        $scopeRules = if ($multiScope) { @($Rules | Where-Object { "$($_.Scope)" -eq $scopeName }) } else { $Rules }
        $scopeZones = $intrazoneZones
        if ($multiScope) {
            $usedZones = @($scopeRules | ForEach-Object { @($_.SrcZone) + @($_.DstZone) } | ForEach-Object { $_.Trim().ToLower() } | Select-Object -Unique)
            $scopeZones = @($intrazoneZones | Where-Object { $usedZones -contains $_ })
        }
        if ($scopeZones.Count -eq 0) { continue }
        $hasExplicitOutsideIntrazoneBlock = $false
        foreach ($rule in $scopeRules) {
            if ($rule.Disabled -or (Get-ActionClass $rule.Action) -ne "deny") { continue }
            $srcCoversInternetZone = ($rule.SrcZone -contains "any") -or (@($rule.SrcZone | Where-Object { Test-ZoneNameInSet $_.Trim().ToLower() $InternetZoneSet }).Count -gt 0)
            $dstCoversInternetZone = ($rule.DstZone -contains "any") -or (@($rule.DstZone | Where-Object { Test-ZoneNameInSet $_.Trim().ToLower() $InternetZoneSet }).Count -gt 0)
            if ($srcCoversInternetZone -and $dstCoversInternetZone -and $null -eq $rule.Application -and (Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw)) {
                $hasExplicitOutsideIntrazoneBlock = $true
                break
            }
        }
        if (-not $hasExplicitOutsideIntrazoneBlock) { $intrazoneMissing += @{ Scope = $scopeName; Zones = $scopeZones } }
    }
    if ($intrazoneMissing.Count -gt 0) {
        $intrazoneZones = @($intrazoneMissing[0].Zones)
        $intrazoneDetail = "No explicit block rule found for the internet-facing zone talking to itself (e.g. $($InternetZoneSet[0]) -> $($InternetZoneSet[0]), any application, drop). PAN-OS allows intrazone traffic by default unless a rule overrides it, unlike interzone traffic which is denied by default. Use 'drop', not 'deny': deny falls back to the matched application's own default deny behavior, which can still send a TCP reset or ICMP unreachable back, revealing that something is listening there. Drop silently discards the packet instead, giving an internet scanner nothing to work with."
        if ($VendorContext -and $VendorContext.Vendor -eq 'fortios') {
            $intrazoneDetail = "Internet-facing zone '$($intrazoneZones[0])' is configured with 'intrazone allow', so traffic between its member interfaces passes without any policy, and no explicit deny policy for that zone to itself was found. Unless this is intended, set 'intrazone deny' on the zone or add an explicit deny policy."
        }
        elseif ($VendorContext -and $VendorContext.Vendor -eq 'junos') {
            # Only possible with default-policy permit-all.
            $intrazoneDetail = "Security policies default-policy is permit-all, so traffic from internet-facing zone '$($intrazoneZones[0])' to itself (and every other flow no policy matches) is allowed without a policy, and no explicit deny policy for that zone to itself was found. Set 'security policies default-policy deny-all', or add an explicit deny policy from-zone $($intrazoneZones[0]) to-zone $($intrazoneZones[0])."
        }
        if ($multiScope) {
            $intrazoneDetail += " Missing in: " + (($intrazoneMissing | ForEach-Object { "$($_.Scope) ($($_.Zones -join ', '))" }) -join '; ') + "."
        }
        $findings += [PSCustomObject]@{
            RuleName = "(ruleset-wide)"; Severity = "Low"; Type = "missing_explicit_intrazone_internet_deny"
            Detail   = $intrazoneDetail
        }
    }

    # Whether the implicit default deny is logged is a device setting we
    # can't see. A logged deny-all cleanup rule removes the doubt. Low,
    # defense in depth. Only when the export carries logging info at all.
    if ($anyRuleShowsLogging) {
        $cleanupMissing = @()
        foreach ($scopeName in $scopeNames) {
            $scopeRules = if ($multiScope) { @($Rules | Where-Object { "$($_.Scope)" -eq $scopeName }) } else { $Rules }
            $hasExplicitLoggedCleanupDeny = $false
            foreach ($rule in $scopeRules) {
                if ($rule.Disabled -or (Get-ActionClass $rule.Action) -ne "deny") { continue }
                $ruleServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
                if (($rule.SrcZone -contains "any") -and ($rule.DstZone -contains "any") -and
                    $null -eq $rule.SrcAddr -and $null -eq $rule.DstAddr -and $null -eq $rule.Application -and $ruleServiceEffectivelyAny -and
                    $rule.HasOptionsColumn -and $rule.Options -and ($rule.Options.ToLower() -match "$loggingPattern|$forwardingPattern")) {
                    $hasExplicitLoggedCleanupDeny = $true
                    break
                }
            }
            if (-not $hasExplicitLoggedCleanupDeny) { $cleanupMissing += $scopeName }
        }
        if ($cleanupMissing.Count -gt 0) {
            $cleanupWhere = if ($multiScope) { "in $($cleanupMissing.Count) of the $($scopeNames.Count) policies in this export" } else { "anywhere in the ruleset" }
            $cleanupDetail = "No explicit, broad deny/drop rule (any zone, any address, any application, any service) with logging enabled was found $cleanupWhere. Whether traffic that falls through to the implicit default deny actually gets logged depends on a device setting this export has no visibility into. A dedicated cleanup rule at the bottom of the rulebase, deny any/any/any with logging on, removes that uncertainty and guarantees a record of everything that didn't match an explicit rule above it."
            if ($multiScope) { $cleanupDetail += " Missing in: $($cleanupMissing -join ', ')." }
            $findings += [PSCustomObject]@{
                RuleName = "(ruleset-wide)"; Severity = "Low"; Type = "no_explicit_deny_log_rule"
                Detail   = $cleanupDetail
            }
        }
    }

    return $findings
}

function Add-DeterministicSuggestedFixes {
    # A handful of finding types have an obvious, context-free next step -
    # the same suggestion applies no matter which specific rule triggered
    # it. Deliberately NOT covering types whose right answer depends on
    # the specific rule's content (e.g. what to actually scope an any/any
    # rule down to) - those are handled separately by the AI step instead.
    #
    # Only called when the user has actually agreed to the Gemini step
    # (see MooseAlto.ps1), not unconditionally from
    # Invoke-DeterministicChecks: the Suggested Fix column is meant to be
    # an all-or-nothing thing tied to that one conscious choice, not a
    # column that silently appears with partial content on every run
    # regardless of whether AI is being used at all.
    param([array]$Findings)
    $deterministicSuggestions = @{
        "disabled_rule_present"        = "Candidate for removal. Confirm with the rule owner it's no longer needed, then delete."
        "rule_usage_unused"            = "Candidate for removal. Confirm with the rule owner, then delete."
        "stale_last_hit"               = "Candidate for removal. Confirm the access is still needed with the rule owner."
        "duplicate_rule"                = "Remove this rule. Fully covered by an earlier rule with identical match criteria."
        "shadowed_rule"                 = "Remove this rule. Never matches, fully covered by an earlier rule."
        "temporary_tag_but_broad_rule"  = "Confirm with the rule owner whether still needed. If yes, narrow the scope; if no, remove."
        "temporary_tag_still_present"   = "Confirm with the rule owner whether still needed. Remove the tag or the rule if stale."
        "generalization_anomaly"        = "Confirm this is a known, intentional exception. Document it (e.g. a rule comment or naming convention) so it survives cleanup and reordering."
        "correlation_anomaly"           = "Review the overlapping traffic between the two rules named here. Scope one of them more narrowly, or document which one is meant to take precedence and why."
        "exposed_amplification_prone_service" = "Restrict the source to specific, known hosts, or remove internet reachability entirely if not required for legitimate use."
        "generic_rule_name"             = "Rename this rule to describe the traffic it actually controls (source, destination, or purpose), instead of relying on rule order to convey intent."
        "compliance_tag_without_critical_zone" = "Confirm with the rule owner whether the tag or the -CriticalZones list is out of date. Update whichever one no longer reflects reality."
        "no_explicit_deny_log_rule"     = "Add an explicit deny any/any/any rule at the bottom of the rulebase with logging enabled."
    }
    foreach ($f in $Findings) {
        if ($deterministicSuggestions.ContainsKey($f.Type)) {
            $f | Add-Member -NotePropertyName SuggestedFix -NotePropertyValue $deterministicSuggestions[$f.Type] -Force
        }
    }
}

function Build-InternetExposureInventory {
    param([array]$Rules, [array]$InternetZoneSet)
    $inventory = @()
    foreach ($rule in $Rules) {
        if ($rule.Disabled -or $rule.Action -ne "allow") { continue }
        $srcIsInet = Test-SideIsInternet -Zones $rule.SrcZone -AddrTokens $rule.SrcAddr -InternetZoneSet $InternetZoneSet
        $dstIsInet = Test-SideIsInternet -Zones $rule.DstZone -AddrTokens $rule.DstAddr -InternetZoneSet $InternetZoneSet
        if (-not ($srcIsInet -or $dstIsInet)) { continue }

        # Prefer a concrete Inbound/Outbound classification whenever one
        # side has definite evidence (a named internet zone, a real public
        # IP, or a negated-RFC1918 pattern). "Both sides internet-facing"
        # is reserved for when a side's internet classification comes ONLY
        # from a zone literally set to "any" on both sides (genuinely
        # ambiguous - "any" doesn't distinguish a direction) or when both
        # sides are independently, definitely internet-facing.
        $srcIsDefinite = (Test-ZoneIsNamedInternetZone -Zones $rule.SrcZone -InternetZoneSet $InternetZoneSet) -or (Test-AddressIsExclusivelyPublic -AddrTokens $rule.SrcAddr)
        $dstIsDefinite = (Test-ZoneIsNamedInternetZone -Zones $rule.DstZone -InternetZoneSet $InternetZoneSet) -or (Test-AddressIsExclusivelyPublic -AddrTokens $rule.DstAddr)

        if ($srcIsDefinite -and -not $dstIsDefinite) {
            $direction = "Inbound"
        }
        elseif ($dstIsDefinite -and -not $srcIsDefinite) {
            $direction = "Outbound"
        }
        elseif ($srcIsInet -and $dstIsInet) {
            $direction = "Both sides internet-facing"
        }
        elseif ($srcIsInet) {
            $direction = "Inbound"
        }
        else {
            $direction = "Outbound"
        }

        $inventory += [PSCustomObject]@{
            Direction   = $direction
            RuleName    = $rule.Name
            Src         = "$($rule.SrcZone -join ';') / $(Get-DisplayAddress -Raw $rule.SrcAddrRaw -Resolved $rule.SrcAddr)"
            Dst         = "$($rule.DstZone -join ';') / $(Get-DisplayAddress -Raw $rule.DstAddrRaw -Resolved $rule.DstAddr)"
            Application = if ($rule.Application) { $rule.Application -join "," } else { "any" }
            Service     = $rule.ServiceRaw
            Action      = $rule.Action
            Profile     = if ($rule.Profile) { $rule.Profile } else { "none" }
            Created     = $rule.Created
            Modified    = $rule.Modified
        }
    }
    return $inventory
}
