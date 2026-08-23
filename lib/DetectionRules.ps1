# --------------------------------------------------------------------------
# Detection rules: risky ports/apps data, internet/critical-zone helpers,
# and the actual finding logic (Invoke-DeterministicChecks). This is the file
# to edit when adding or tuning a check. Everything else (parsing, reporting)
# lives elsewhere.
# --------------------------------------------------------------------------

$RiskyPorts = @{
    20 = "FTP-DATA"; 21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 24 = "Legacy/unassigned"
    25 = "SMTP"; 69 = "TFTP"; 110 = "POP3"; 143 = "IMAP"; 161 = "SNMP v1/v2c"
    389 = "LDAP"; 445 = "SMB"; 512 = "Rexec"; 513 = "Rlogin"; 514 = "Rsh"
    853 = "DNS over TLS"; 1433 = "MSSQL"; 1521 = "Oracle DB"; 1723 = "PPTP"; 3306 = "MySQL"; 3389 = "RDP"
    5432 = "PostgreSQL"; 5900 = "VNC"; 6379 = "Redis"; 8443 = "HTTPS-Alt/Admin"
    9200 = "Elasticsearch"; 27017 = "MongoDB"
}

# Ports that are unencrypted/cleartext by design (as opposed to "just risky
# because it's a management/admin surface", e.g. SSH/RDP are encrypted but
# still worth flagging as high-value targets). Used only to annotate findings.
$CleartextPorts = @(20, 21, 23, 25, 69, 110, 143, 161, 389, 512, 513, 514)

# Well-known public DNS resolvers. Traffic reaching one of these directly
# bypasses internal/corporate DNS, which matters regardless of whether the
# specific protocol is plain DNS, DoT (port 853), or DoH (usually
# indistinguishable from ordinary HTTPS at the port level, since it rides
# over 443. This is why DoH gets checked by destination here rather than
# by port the way the other risky protocols are).
#
# Sourced from https://dnsprivacy.org/public_resolvers/ plus a handful of
# other big, recognizable providers with stable published anycast IPs,
# cross-checked against their own sites. Deliberately does not include the
# long tail of smaller/personal DNSCrypt and DoH operators (e.g. the full
# https://github.com/DNSCrypt/dnscrypt-resolvers list runs to hundreds of
# entries): the value of this check is flagging traffic to a provider a
# reviewer would immediately recognize as a real bypass, not accumulating
# every obscure resolver that could theoretically match.
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

# Best-effort App-ID name -> label mapping. Verify against your own App-ID
# database. Names can be renamed/added across content-pack updates. The
# entries for legacy r-commands, PPTP, and the "often left with no auth"
# modern data-store apps (redis/mongodb/elasticsearch/postgres) are lower
# confidence guesses. Check these especially carefully against your tenant.
# "anydesk" and "dns-over-https" are confirmed against a real PAN-OS
# export; the other remote-access tool names (teamviewer, logmein,
# splashtop, chrome-remote-desktop) follow the same naming pattern but
# haven't been individually confirmed the same way.
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

# --------------------------------------------------------------------------
# Internet-exposure and critical-zone helpers
# --------------------------------------------------------------------------


function Test-ZoneTouchesInternet {
    param([array]$Zones, [array]$InternetZoneSet)
    foreach ($z in $Zones) {
        $zl = $z.Trim().ToLower()
        if ($zl -eq "any" -or $InternetZoneSet -contains $zl) { return $true }
    }
    return $false
}

function Test-ZoneIsNamedInternetZone {
    # Same as Test-ZoneTouchesInternet but excludes the "any" case: true
    # only for a specifically named internet-facing zone (Untrust, outside,
    # etc.), not for a zone that merely could include internet because it's
    # set to "any". Used to tell apart concrete evidence of direction from
    # the weaker, direction-neutral "any" signal.
    param([array]$Zones, [array]$InternetZoneSet)
    foreach ($z in $Zones) {
        $zl = $z.Trim().ToLower()
        if ($InternetZoneSet -contains $zl) { return $true }
    }
    return $false
}

function Test-ServiceEffectivelyAny {
    # "application-default" isn't literally "any" in the Service field, but
    # when Application is ALSO "any" it places no real restriction on the
    # traffic - it just means "whichever app matches, on that app's normal
    # port", and the app itself is unrestricted. Treating this combination
    # as equivalent to Service: any avoids under-counting how open a rule
    # really is just because Service happens to say the (very common)
    # default value rather than the literal word "any".
    param($ParsedService, $Application, [string]$ServiceRaw)
    if ($null -eq $ParsedService) { return $true }
    return ($null -eq $Application) -and $ServiceRaw -and ($ServiceRaw.Trim().ToLower() -eq "application-default")
}

function Get-KnownDnsResolverMatches {
    # Returns ALL known public DNS resolver IPs found in an address field
    # (as an array), not just the first one. A field like "8.8.8.8;1.1.1.1"
    # legitimately contains two different known resolvers; reporting only
    # the first one silently drops the other from the finding text.
    # Checked as a literal IP match after stripping any CIDR suffix, since
    # a resolver would typically appear as a /32 or bare IP.
    param($AddrTokens)
    if (-not $AddrTokens) { return @() }
    $matches = foreach ($tok in $AddrTokens) {
        $ip = (Get-CidrParts $tok).IP
        if ($KnownPublicDnsResolvers -contains $ip) { $ip }
    }
    return @($matches)
}

function Test-ZoneInSet {
    # Generic version of Test-ZoneTouchesInternet for an arbitrary named zone
    # set (e.g. critical/crown-jewel zones), without the "any" auto-match -
    # a rule scoped to "any" zone isn't automatically "in" a specific named
    # critical zone the way it's automatically internet-facing.
    param([array]$Zones, [array]$ZoneSet)
    if (-not $ZoneSet -or $ZoneSet.Count -eq 0) { return $false }
    foreach ($z in $Zones) {
        if ($ZoneSet -contains $z.Trim().ToLower()) { return $true }
    }
    return $false
}

function Test-ZonesCoveredFast {
    # Same semantics as Test-ZonesCovered, but both inputs are already
    # lowercased (see the pre-computation before the O(n^2) loops below),
    # avoiding a fresh ToLower() pipeline pass on every comparison a rule's
    # zones take part in.
    param([array]$EarlierLower, [array]$LaterLower)
    if ($EarlierLower -contains "any") { return $true }
    foreach ($z in $LaterLower) {
        if ($EarlierLower -notcontains $z) { return $false }
    }
    return $true
}

function Test-ZonesEqualFast {
    # Same semantics as Test-ZonesEqual, but both inputs are already
    # lowercased.
    param([array]$ALower, [array]$BLower)
    return (Test-ZonesCoveredFast -EarlierLower $ALower -LaterLower $BLower) -and (Test-ZonesCoveredFast -EarlierLower $BLower -LaterLower $ALower) -and (-not ($ALower -contains "any" -and -not ($BLower -contains "any"))) -and (-not ($BLower -contains "any" -and -not ($ALower -contains "any")))
}

function Test-AddressTouchesInternet {
    # "any" address does not by itself count as "touches the internet" -
    # that case is handled by zone="any" in Test-ZoneTouchesInternet. A rule
    # scoped to an explicit internal zone (e.g. Trust) with an unrestricted
    # address field is still internal. Only a concrete, non-private IP
    # literal counts as a real internet signal here.
    #
    # A "[Negate] X" token is also treated as touching the internet
    # regardless of what X specifically is, not just the narrow "negates
    # all three RFC1918 ranges together" pattern (see
    # Test-IsNegatedPublicPattern, still used for the dedicated
    # negated_rfc1918_effectively_public finding and its specific wording).
    # Excluding any single bounded range, however it's chosen, still
    # matches everything else - both private space AND the overwhelming
    # majority of public IP space. A rule negating one arbitrary /24 is
    # still reachable from virtually the entire internet; it just wasn't
    # written as the specific "any-public" idiom this script already knew
    # to recognize.
    #
    # This intentionally counts a negation as "touches the internet" for
    # risk-detection purposes (used by inbound_risky_*, no_security_profile,
    # internet_exposed_any_field, etc.), where being permissive is correct:
    # the address genuinely could be public, and that's worth flagging. It
    # is deliberately NOT used for direction classification - see
    # Test-AddressIsExclusivelyPublic below for why that needs a stricter bar.
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
    # Stricter than Test-AddressTouchesInternet above, used only for
    # Inbound/Outbound/Both-sides direction labeling, not risk detection.
    # A literal public IP/CIDR (e.g. 80.23.3.3) can ONLY be an internet
    # address - that's unambiguous, definite evidence of direction. A
    # "[Negate] X" token is different: excluding one range still leaves in
    # ALL of RFC1918 private space too, so the address could just as
    # easily be an internal host (e.g. 10.200.60.1) as a public one - it's
    # broad evidence of possible exposure (correctly caught above for
    # findings), but not proof of which direction traffic actually flows.
    # Counting it as "definite" here would wrongly let one strong signal on
    # this side silently outrank the other side's genuine, if weaker,
    # internet-touching evidence (e.g. a "Destination Zone: any" that could
    # equally mean this rule permits outbound just as much as inbound).
    param($AddrTokens)
    if ($null -eq $AddrTokens) { return $false }
    foreach ($tok in $AddrTokens) {
        if (Test-IsPlainIP $tok) {
            if (-not (Test-PrivateOrSpecialIP $tok)) { return $true }
        }
    }
    return $false
}

function Test-SideIsInternet {
    param([array]$Zones, $AddrTokens, [array]$InternetZoneSet)
    return (Test-ZoneTouchesInternet -Zones $Zones -InternetZoneSet $InternetZoneSet) -or (Test-AddressTouchesInternet -AddrTokens $AddrTokens)
}

# --------------------------------------------------------------------------
# Deterministic checks
# --------------------------------------------------------------------------

function Invoke-DeterministicChecks {
    param([array]$Rules, [array]$InternetZoneSet, [array]$CriticalZoneSet, [int]$StaleHitDays = 365, [int]$MaxAddressListSize = 25)
    $findings = @()

    # Computed once, not per-rule: does the Options column actually carry
    # logging information anywhere in this ruleset? Some export types
    # include the column but never populate it with logging detail at all,
    # which would make every single rule look "unlogged" if checked
    # naively. Confirming at least one real example exists first avoids
    # that false-positive flood.
    #
    # Logging and forwarding are two genuinely separate PAN-OS settings:
    # "Log at Session Start"/"Log at Session End" control whether a log
    # entry is created AT ALL (stored locally on the firewall regardless
    # of anything else), while a Log Forwarding profile only controls
    # whether those already-created local logs also get sent to Panorama
    # or an external destination. A rule with logging on but no forwarding
    # profile still has a real, locally-queryable audit trail, so either
    # signal alone is enough here: this check is about "does a record of
    # this traffic exist anywhere," not "is it centralized."
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
        # A rule named as if it denies/blocks something but is actually
        # configured to allow it (or vice versa) is a dangerous, easy
        # mistake to miss on a quick read: whoever reviews the ruleset
        # later sees "DENY_..." and reasonably assumes that traffic is
        # blocked, when it's actually permitted. Checked here, BEFORE the
        # action=allow gate below, since it's the one check in this
        # function that specifically needs to see deny/drop rules too -
        # everything after this gate assumes allow.
        #
        # Matched by exact token (same tokenization as the temp/POC check
        # further down), not raw substring, to avoid a false positive on
        # a name that merely contains one of these words as part of a
        # longer word. Rules where the name contains BOTH a deny-style and
        # an allow-style token are skipped rather than guessed at, since
        # the naming intent itself is ambiguous there, not clearly
        # contradicted.
        $nameTokensForAction = @($rule.Name -split '[-_\s\.]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() })
        $denyIntentWords = @("deny", "block", "drop", "reject")
        $allowIntentWords = @("allow", "permit", "accept")
        $hasDenyIntent = ($denyIntentWords | Where-Object { $nameTokensForAction -contains $_ }).Count -gt 0
        $hasAllowIntent = ($allowIntentWords | Where-Object { $nameTokensForAction -contains $_ }).Count -gt 0
        $actionLowerForName = $rule.Action.ToLower()
        if ($hasDenyIntent -and -not $hasAllowIntent -and $actionLowerForName -eq "allow") {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "rule_name_action_mismatch"
                Detail   = "Rule name suggests it denies/blocks traffic, but Action is actually '$($rule.Action)'. Anyone reading the ruleset by name alone would reasonably assume this traffic is blocked when it isn't. Verify whether the name is stale (rule was toggled without renaming) or the action was set incorrectly."
            }
        }
        elseif ($hasAllowIntent -and -not $hasDenyIntent -and ($actionLowerForName -eq "deny" -or $actionLowerForName -eq "drop")) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "rule_name_action_mismatch"
                Detail   = "Rule name suggests it allows/permits traffic, but Action is actually '$($rule.Action)'. Anyone reading the ruleset by name alone would reasonably assume this traffic is permitted when it isn't. Verify whether the name is stale (rule was toggled without renaming) or the action was set incorrectly."
            }
        }

        if ($rule.Action -ne "allow") { continue }

        $srcIsInet = Test-SideIsInternet -Zones $rule.SrcZone -AddrTokens $rule.SrcAddr -InternetZoneSet $InternetZoneSet
        $dstIsInet = Test-SideIsInternet -Zones $rule.DstZone -AddrTokens $rule.DstAddr -InternetZoneSet $InternetZoneSet

        # A source scoped to a NAMED internet-facing zone (e.g. "outside")
        # is functionally just as open as a literal "any" source zone -
        # both mean "anyone reachable from that zone", which for an
        # internet-facing zone means anyone on the internet. Checking only
        # for the literal string "any" would miss a rule that's otherwise
        # exactly this broad just because the zone has a specific name.
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

        if (Test-IsNegatedPublicPattern -RawTokens $rule.SrcAddr) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "negated_rfc1918_effectively_public"
                Detail   = "Source address ('$($rule.SrcAddrRaw)') negates the private RFC1918 ranges. Functionally equivalent to 'any public source address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }
        if (Test-IsNegatedPublicPattern -RawTokens $rule.DstAddr) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "negated_rfc1918_effectively_public"
                Detail   = "Destination address ('$($rule.DstAddrRaw)') negates the private RFC1918 ranges. Functionally equivalent to 'any public destination address', even though no token literally says 'any'. Easy to miss in manual review."
            }
        }

        if ($rule.HitCount -match '^\d+$' -and [int]$rule.HitCount -eq 0) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "zero_hit_count"
                Detail   = "Recorded hit count of zero. Candidate for removal after confirming the observation window is representative."
            }
        }

        # Panorama's own Rule Usage status (used/unused/partially used) is a
        # distinct signal from a numeric hit count. It's computed across
        # every managed firewall a rule applies to, not just one. See
        # https://docs.paloaltonetworks.com/ngfw/administration/monitoring/view-policy-rule-usage
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

        # A rule with SOME recorded hits isn't caught by zero_hit_count, but
        # if its last match was a long time ago it's still effectively
        # stale, e.g. a one-off access grant nobody has used in over a
        # year. Only fires for a positive hit count; hit count = 0 is
        # already covered above, and re-flagging it here would just be
        # noise about the same underlying fact.
        if ($rule.HitCount -match '^\d+$' -and [int]$rule.HitCount -gt 0 -and $rule.LastHit) {
            $parsedLastHit = [datetime]::MinValue
            if ([datetime]::TryParse($rule.LastHit, [ref]$parsedLastHit)) {
                $daysSinceLastHit = (New-TimeSpan -Start $parsedLastHit -End (Get-Date)).Days
                if ($daysSinceLastHit -gt $StaleHitDays) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "stale_last_hit"
                        Detail   = "Last matched traffic $daysSinceLastHit days ago ($($rule.LastHit)), past the $StaleHitDays-day staleness threshold, despite a non-zero hit count ($($rule.HitCount)). Worth confirming this is still needed rather than a one-off grant nobody uses anymore."
                    }
                }
            }
        }

        # Critical zone isolation (such as SWIFT CSCF / PCI DSS / FFIEC): sensitive
        # zones (SWIFT secure zone, CDE, ATM, core banking, HSM, POS, etc.) must be
        # isolated from the general network, not just from the internet.
        # Only fires if -CriticalZones was actually configured. This is
        # org-specific with no sensible universal default.
        if ($rule.Action -eq "allow" -and $CriticalZoneSet.Count -gt 0) {
            $dstIsCritical = Test-ZoneInSet -Zones $rule.DstZone -ZoneSet $CriticalZoneSet
            $srcIsCritical = Test-ZoneInSet -Zones $rule.SrcZone -ZoneSet $CriticalZoneSet
            if ($dstIsCritical -and -not $srcIsCritical) {
                $criticalServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
                $broadDims = @()
                if ($rule.SrcZone -contains "any") { $broadDims += "source zone" }
                if ($null -eq $rule.SrcAddr) { $broadDims += "source address" }
                if ($null -eq $rule.DstAddr) { $broadDims += "destination address (reaches the entire critical zone, not a specific host)" }
                if ($null -eq $rule.Application) { $broadDims += "application" }
                if ($criticalServiceEffectivelyAny) { $broadDims += "service" }
                if ($broadDims.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "unrestricted_access_to_critical_zone"
                        Detail   = "Rule allows access into critical zone '$($rule.DstZone -join ';')' from a non-critical zone ('$($rule.SrcZone -join ';')') with $($broadDims -join '/') left unrestricted. Critical zones (e.g. SWIFT secure zone, CDE, ATM, core banking) must be isolated from the general network per SWIFT CSCF, PCI DSS, and FFIEC guidance, not just from the internet."
                    }
                }
            }

            # Mirror case: the critical zone reaching OUT broadly, not just
            # the general network reaching IN. SWIFT CSCF and PCI DSS both
            # require isolation in both directions, not just "nothing gets
            # in without control" - a compromised or misused host inside a
            # critical zone with unrestricted egress can exfiltrate data or
            # reach a C2 server just as easily as an attacker could reach in
            # through an overly broad inbound rule.
            if ($srcIsCritical -and -not $dstIsCritical) {
                $egressServiceEffectivelyAny = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
                $egressBroadDims = @()
                if ($rule.DstZone -contains "any") { $egressBroadDims += "destination zone" }
                if ($null -eq $rule.DstAddr) { $egressBroadDims += "destination address" }
                if ($null -eq $rule.SrcAddr) { $egressBroadDims += "source address (any host in the critical zone, not a specific one)" }
                if ($null -eq $rule.Application) { $egressBroadDims += "application" }
                if ($egressServiceEffectivelyAny) { $egressBroadDims += "service" }
                if ($egressBroadDims.Count -gt 0) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "unrestricted_egress_from_critical_zone"
                        Detail   = "Rule allows critical zone '$($rule.SrcZone -join ';')' unrestricted reach OUT to a non-critical zone ('$($rule.DstZone -join ';')') with $($egressBroadDims -join '/') left unrestricted. Isolation requirements (SWIFT CSCF, PCI DSS, FFIEC) apply in both directions: a host inside the critical zone with unrestricted egress can exfiltrate data or reach a C2 server just as easily as an attacker could reach in through an overly broad inbound rule."
                    }
                }
            }
        }

        # A rule tagged as temporary/POC/test that's still broad is a
        # documented real world audit failure pattern (SWIFT CSCF cites
        # "broad allow-any firewall entries added as a temporary change
        # years ago and never removed").
        #
        # Checked in both the rule Name and Tags, not Tags alone: a rule
        # literally named "TEMP_ACCESS_11" or "POC-Integration-Test" with
        # no tags set at all is a common pattern (our own demo data does
        # exactly this), and tags-only matching would miss it.
        #
        # Matched by exact token, not raw substring: splitting on the
        # common separators (-, _, space, .) first and comparing whole
        # tokens avoids a false positive like "Attempted-Migration"
        # matching "temp" as a substring of "Attempted".
        if ($rule.Action -eq "allow") {
            $tempKeywords = @("temp", "poc", "test", "trial")
            $nameTokens = @($rule.Name -split '[-_\s\.]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() })
            $tagTokens = @()
            if ($rule.Tags) { $tagTokens = @($rule.Tags -split '[-_\s\.,;]+' | Where-Object { $_ -ne "" } | ForEach-Object { $_.ToLower() }) }
            $matchedInName = $tempKeywords | Where-Object { $nameTokens -contains $_ } | Select-Object -First 1
            $matchedInTags = $tempKeywords | Where-Object { $tagTokens -contains $_ } | Select-Object -First 1
            $matchedKeyword = if ($matchedInName) { $matchedInName } else { $matchedInTags }
            $matchSource = if ($matchedInName -and $matchedInTags) { "both the rule name and its tags ('$($rule.Tags)')" } elseif ($matchedInName) { "the rule name itself" } else { "its tags ('$($rule.Tags)')" }
            $isBroadRule = ($null -eq $rule.SrcAddr) -or ($null -eq $rule.DstAddr) -or ($null -eq $rule.Application)
            if ($matchedKeyword -and $isBroadRule) {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "temporary_tag_but_broad_rule"
                    Detail   = "Rule signals temporary/POC/test intent via $matchSource, but still has an unrestricted source/destination address or application. Temporary broad-access rules that are never tightened or removed are a common real world audit finding. Verify this is still needed."
                }
            }
            elseif ($matchedKeyword) {
                # Narrowly-scoped temp-tagged rules aren't a broad-exposure
                # risk the way the case above is, but the tag itself is
                # still a lifecycle signal someone deliberately left behind:
                # a scoped vendor/POC grant that was meant to be revisited
                # and reviewed is just as easy to forget as a broad one,
                # it just isn't dangerous in the same way. Kept as its own
                # Low finding rather than folded into the Medium one above,
                # since the two represent genuinely different urgency, not
                # the same fact at two severities.
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Low"; Type = "temporary_tag_still_present"
                    Detail   = "Rule signals temporary/POC/test intent via $matchSource. Scope is already restricted, not a broad-exposure concern, but this suggests it was meant to be reviewed and removed at some point. Worth confirming it's still needed."
                }
            }
        }

        # Port-based matching instead of App-ID: Application left as "any"
        # but Service names explicit port(s). This loses App-ID visibility
        # (app-hopping over non-standard ports, App-ID-specific threat
        # signatures) regardless of whether the port itself happens to be on
        # the risky list. This is a distinct best-practice concern from
        # inbound/internal_risky_port, which only fires for specific ports.
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
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "port_based_rule_missing_app_id"
                Detail   = "Rule matches by port ($($rule.ServiceRaw)) with Application left as 'any', instead of a named App-ID.$extraNote Consider migrating to an explicit application for App-ID-based inspection."
            }
        }

        # A rule can be just as hard to audit and maintain with 200
        # individually-listed addresses as with a literal "any" - large
        # enumerated lists are a common symptom of a whitelist that grew
        # unchecked over time, and are easy to skip past in manual review
        # since nothing about them LOOKS wide open the way "any" does.
        # Several real-world firewall audit checklists specifically call
        # this out as its own finding, distinct from the any/none-based
        # checks elsewhere in this file.
        if ($rule.Action -eq "allow") {
            $srcCount = if ($null -eq $rule.SrcAddr) { 0 } else { $rule.SrcAddr.Count }
            $dstCount = if ($null -eq $rule.DstAddr) { 0 } else { $rule.DstAddr.Count }
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

        # An allow rule with no logging at all leaves no trail if that
        # traffic is ever involved in an incident. Only checked when the
        # Options column both exists AND has been confirmed to actually
        # carry logging information somewhere in this ruleset (see
        # anyRuleShowsLogging below, computed once outside this loop):
        # some export types don't include logging detail in this column at
        # all, and flagging every single rule in that case would be a
        # false-positive flood rather than a real finding.
        if ($rule.Action -eq "allow" -and $rule.HasOptionsColumn -and $anyRuleShowsLogging) {
            $optionsLower = $rule.Options.ToLower()
            if ($optionsLower -notmatch "$loggingPattern|$forwardingPattern") {
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = "Medium"; Type = "no_logging_enabled"
                    Detail   = "Rule shows no evidence of logging enabled (neither log-at-session-start nor log-at-session-end, nor a Log Forwarding profile). If this traffic is ever involved in an incident, there's no record of it having occurred. Verify logging is intentionally disabled here, not an oversight."
                }
            }
        }

        # Direct reachability to a well-known public DNS resolver bypasses
        # internal/corporate DNS. Worth flagging regardless of the exact
        # protocol (plain DNS, DoT, or DoH, the last of which is otherwise
        # invisible at the port level since it rides over ordinary HTTPS).
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

            # Two more specific plain-DNS (port 53) patterns, distinct from
            # the general resolver check above: that one fires regardless
            # of protocol, these confirm the traffic is specifically
            # unencrypted DNS, which adds a cleartext-exposure angle on top
            # of the DNS-bypass one (queries visible to anyone observing
            # the traffic, not just reaching an uncontrolled resolver).
            $dnsPorts = Get-ServicePorts -ServiceTokens $rule.Service
            if ($dnsPorts -contains 53) {
                if ($null -eq $rule.DstAddr) {
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "plain_dns_to_unrestricted_destination"
                        Detail   = "Rule allows plain DNS (port 53) to an unrestricted destination (any). Unencrypted queries can go to literally any server, with no way to filter or inspect where they end up. A common DNS-tunneling/data-exfiltration pattern, not just a DNS-bypass one. Consider scoping the destination to approved resolvers."
                    }
                }
                elseif ($resolverMatches.Count -gt 0) {
                    $resolverList = $resolverMatches -join ", "
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "plain_dns_to_known_resolver"
                        Detail   = "Rule allows plain DNS (port 53) specifically to a well-known public resolver ($resolverList). Unlike DoH/DoT to the same destination, the query content itself is visible in cleartext to anyone observing the traffic, on top of bypassing internal DNS controls."
                    }
                }
            }
        }

        if ($srcIsInet) {
            # It fires whenever the source touches the internet by ANY means,
            # including a rule
            # scoped to one single concrete address (e.g. a whitelisted
            # partner IP) where the ZONE is what's unrestricted, not the
            # address. Renamed and reworded to say which one it actually is.
            #
            # Severity is Medium, not High: by itself this is context (which
            # rules make up the internet-facing surface), not a concrete
            # risk. Whatever makes a specific rule actually dangerous (a
            # risky app/port, no security profile, wide-open fields) already
            # fires its own more specific Critical/High finding above.
            $zoneIsTheReason = Test-ZoneTouchesInternet -Zones $rule.SrcZone -InternetZoneSet $InternetZoneSet
            $zonePhrase = if ($zoneIsTheReason) { "source zone '$($rule.SrcZone -join ';')' is internet-facing" } else { "source address itself includes public IP space" }
            $addrPhrase = if ($null -eq $rule.SrcAddr) { "with an unrestricted source address (any), reachable from anywhere on the internet" } else { "though scoped to a specific source address ('$($rule.SrcAddrRaw)'), not an unrestricted source" }
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "inbound_from_internet"
                Detail   = "Inbound rule reachable from the internet ($zonePhrase) $addrPhrase, reaching destination zone='$($rule.DstZone -join ';')', address='$($rule.DstAddrRaw)'."
            }
        }

        if ($dstIsInet) {
            # Symmetric counterpart to inbound_from_internet above, same
            # Medium reasoning: on its own this is context (which rules send
            # traffic out to the internet), not a concrete risk by itself.
            # Fires regardless of srcIsInet, same as the inbound check does.
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

        if (-not $srcIsInet -and $dstIsInet -and $null -ne $rule.DstAddr -and $null -eq $rule.Application) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "Medium"; Type = "outbound_defined_dest_any_app"
                Detail   = "Outbound to a defined destination ($($rule.DstAddrRaw)), but application/service is unrestricted (any). Consider scoping to the specific application(s) actually needed."
            }
        }

        # A risky/cleartext protocol permitted OUTBOUND to the internet fell
        # through the cracks between the two checks below: inbound_risky_*
        # requires the SOURCE to touch internet, internal_risky_* requires
        # NEITHER side to. A pure outbound rule (source internal, destination
        # internet) matches neither condition, even though an internal host
        # allowed to run RDP/SSH/Telnet out to arbitrary internet
        # destinations is a real concern in its own right: a data
        # exfiltration or C2 tunneling channel if that host is ever
        # compromised, not just an internet-exposure question. Same High
        # severity as internal_risky_*, matching the same "requires the
        # attacker to already have some internal position" reasoning,
        # rather than Critical's "reachable with no prior access at all".
        if (-not $srcIsInet -and $dstIsInet) {
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($RiskyApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "High"; Type = "outbound_risky_application"
                            Detail   = "Outbound rule permits a high-risk application ($($RiskyApplications[$app]), App-ID '$app') from source address='$($rule.SrcAddrRaw)' out to the internet. A potential data-exfiltration or tunneling channel if the source host is ever compromised. Verify this is intentional and scoped down if not."
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
        }

        # Note: fires on $srcIsInet alone, not requiring the destination to
        # be non-internet. A risky/cleartext protocol reachable from an
        # internet-facing source is dangerous regardless of whether the
        # destination side also happens to be internet-facing (e.g. both
        # Source Zone and Destination Zone set to "any") - that combination
        # is if anything more exposed, not less, so it should not silently
        # avoid this check the way an overly strict "inbound-only" condition
        # would cause.
        if ($srcIsInet) {
            if ($rule.Application) {
                foreach ($app in $rule.Application) {
                    if ($RiskyApplications.ContainsKey($app)) {
                        $findings += [PSCustomObject]@{
                            RuleName = $rule.Name; Severity = "Critical"; Type = "inbound_risky_application"
                            Detail   = "Inbound from the internet using a high-risk application ($($RiskyApplications[$app]), App-ID '$app') toward destination address='$($rule.DstAddrRaw)'. Verify this is intentional and scoped down (specific source IPs, MFA/VPN in front of it) if not."
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
        }

        # General catch-all: any rule that touches the internet on either
        # side (inbound and/or outbound, including a literal "any" zone,
        # which the directional checks above treat as internet-facing too)
        # with source address, destination address, or application left
        # unrestricted. The narrower checks above only fire for specific
        # single-dimension combinations (e.g. broad destination but a
        # defined app); this one catches the gaps between them, such as a
        # rule where BOTH destination and application are "any"
        # simultaneously, or a rule with "Destination Zone: any" reaching
        # both directions at once. Deliberately allowed to overlap with the
        # more specific findings above; each is independently true and
        # worth surfacing.
        if ($rule.Action -eq "allow" -and ($srcIsInet -or $dstIsInet)) {
            $serviceEffectivelyAny2 = Test-ServiceEffectivelyAny -ParsedService $rule.Service -Application $rule.Application -ServiceRaw $rule.ServiceRaw
            $anyDims = @()
            if ($rule.SrcZone -contains "any") { $anyDims += "source zone" }
            if ($null -eq $rule.SrcAddr) { $anyDims += "source address" }
            if ($rule.DstZone -contains "any") { $anyDims += "destination zone" }
            if ($null -eq $rule.DstAddr) { $anyDims += "destination address" }
            if ($null -eq $rule.Application) { $anyDims += "application" }
            if ($serviceEffectivelyAny2) { $anyDims += "service" }
            if ($anyDims.Count -gt 0) {
                # Escalated to Critical when address, application, AND
                # service are all wide open, regardless of whether the side
                # touching internet got there via a literal "any" zone or a
                # specifically named internet zone (e.g. "outside"). Without
                # this, a rule scoped to a named internet zone but otherwise
                # just as open as any_any_any_allow (any source address, any
                # destination, any app, any service) only ever reached High
                # - the same practical risk, understated because
                # any_any_any_allow only fires on the literal string "any".
                $severity = if ($null -eq $rule.SrcAddr -and $null -eq $rule.DstAddr -and $null -eq $rule.Application -and $serviceEffectivelyAny2) { "Critical" } else { "High" }
                $findings += [PSCustomObject]@{
                    RuleName = $rule.Name; Severity = $severity; Type = "internet_exposed_any_field"
                    Detail   = "Rule touches the internet (inbound and/or outbound: source '$($rule.SrcZone -join ';')' / '$($rule.SrcAddrRaw)', destination '$($rule.DstZone -join ';')' / '$($rule.DstAddrRaw)') with $($anyDims -join '/') left unrestricted (any). Every internet-adjacent 'any' widens what this rule can actually match."
                }
            }
        }

        # --- Fully internal traffic: broad exposure (lateral movement risk) ---
        if (-not $srcIsInet -and -not $dstIsInet) {
            if ($null -eq $rule.SrcAddr -or $null -eq $rule.DstAddr -or $null -eq $rule.Application -or $null -eq $rule.Service) {
                $broadDims = @()
                if ($null -eq $rule.SrcAddr) { $broadDims += "source address" }
                if ($null -eq $rule.DstAddr) { $broadDims += "destination address" }
                if ($null -eq $rule.Application) { $broadDims += "application" }
                if ($null -eq $rule.Service) { $broadDims += "service" }
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
                            Detail   = "Internal rule ($($rule.SrcZone -join ';') -> $($rule.DstZone -join ';')) allows a high-risk application ($($RiskyApplications[$app]), App-ID '$app'). Lateral-movement risk even though this doesn't touch the internet directly."
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
        if (($srcIsInet -or $dstIsInet) -and ($rule.Profile.ToLower() -eq "" -or $rule.Profile.ToLower() -eq "none")) {
            $findings += [PSCustomObject]@{
                RuleName = $rule.Name; Severity = "High"; Type = "no_security_profile_on_exposed_rule"
                Detail   = "Rule touches the internet (inbound or outbound) but has no security profile group applied (Profile='$($rule.Profile)'). No threat prevention/antivirus/URL filtering inspection on this exposed traffic."
            }
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # Pre-parse every rule's addresses AND lowercase its zones ONCE here,
    # since both O(n^2) loops below compare the same rule against many
    # others - without this, the same strings get re-parsed/re-lowercased
    # on every single comparison they take part in.
    $parsedSrcAddr = @{}
    $parsedDstAddr = @{}
    $lowerSrcZone = @{}
    $lowerDstZone = @{}
    foreach ($r in $Rules) {
        $parsedSrcAddr[$r.Index] = ConvertTo-ParsedAddressList -AddrTokens $r.SrcAddr
        $parsedDstAddr[$r.Index] = ConvertTo-ParsedAddressList -AddrTokens $r.DstAddr
        $lowerSrcZone[$r.Index] = @($r.SrcZone | ForEach-Object { $_.ToLower() })
        $lowerDstZone[$r.Index] = @($r.DstZone | ForEach-Object { $_.ToLower() })
    }

    # Duplicate / shadowed detection (order-sensitive, enabled allow rules only)
    #
    # Zone-pair bucketing: two rules can only match/shadow each other if
    # their zones are compatible (exactly equal, or one side is "any").
    # Grouping earlier rules by their exact zone-pair signature, and
    # keeping a separate short list of "any"-zoned rules that could
    # potentially match anything, means a rule only gets compared against
    # candidates that could plausibly match - not every earlier rule
    # unconditionally. On a ruleset spanning many distinct zones (the
    # normal case at real-world scale), most rule PAIRS have incompatible
    # zones, so skipping those comparisons entirely is what turns
    # the effective cost from O(n^2) into roughly O(n x average bucket
    # size), which is much smaller when zones are varied.
    $enabledAllow = @($Rules | Where-Object { -not $_.Disabled -and $_.Action -eq "allow" })
    $wildcardIdx = New-Object System.Collections.Generic.List[int]
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
        $candidates.AddRange($wildcardIdx)
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

            # Service/port coverage matters here too: a rule scoped to one
            # specific port (e.g. tcp-853) does not actually shadow a later
            # rule on a different port (e.g. udp-53), even if zone/address/
            # application otherwise look broad enough to cover it. PAN-OS
            # itself still differentiates them by service, so treating them
            # as shadowing without this check would be a false positive.
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
            $wildcardIdx.Add($i)
        }
        else {
            if (-not $sigBuckets.ContainsKey($ruleSig)) { $sigBuckets[$ruleSig] = New-Object System.Collections.Generic.List[int] }
            $sigBuckets[$ruleSig].Add($i)
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # Cross-action shadowing (order-sensitive, across ALL enabled rules,
    # allow and deny together, in original rule order). The same-action loop
    # above only ever compares allow-vs-allow, so it can never catch the case
    # where a rule is shadowed by an EARLIER rule with a DIFFERENT action,
    # which is the scenario where shadowing actually changes what traffic
    # does, rather than just being redundant. Same zone-pair bucketing as
    # above, plus a same-action skip within each candidate check.
    $enabledAll = @($Rules | Where-Object { -not $_.Disabled })
    $wildcardIdx2 = New-Object System.Collections.Generic.List[int]
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
        $candidates2.AddRange($wildcardIdx2)
        if ($sigBuckets2.ContainsKey($ruleSig)) { $candidates2.AddRange($sigBuckets2[$ruleSig]) }
        $candidates2.Sort()

        foreach ($j in $candidates2) {
            $earlier = $enabledAll[$j]
            if ($earlier.Action -eq $rule.Action) { continue }  # same-action case already handled above
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

            if ($crossShadowed) {
                if ($earlier.Action -eq "allow" -and $rule.Action -eq "deny") {
                    # Dangerous: the deny meant to block something never fires.
                    # That traffic is actually wide open via the earlier allow.
                    # A false sense of security, not just dead policy.
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Critical"; Type = "allow_shadows_deny"
                        Detail   = "This DENY rule is fully covered by an earlier ALLOW rule ('$($earlier.Name)') with equal-or-broader scope. It can never trigger. The traffic it was meant to block is actually permitted by the earlier rule. Whoever relies on this deny believes the traffic is blocked; it isn't."
                    }
                }
                elseif ($earlier.Action -eq "deny" -and $rule.Action -eq "allow") {
                    # Less dangerous: the allow exception never fires and
                    # traffic stays blocked. A functional bug (not a security
                    # exposure), but worth flagging before someone "fixes" it
                    # by adding an even broader rule higher up to chase the
                    # symptom.
                    $findings += [PSCustomObject]@{
                        RuleName = $rule.Name; Severity = "Medium"; Type = "deny_shadows_allow"
                        Detail   = "This ALLOW rule is fully covered by an earlier DENY rule ('$($earlier.Name)') with equal-or-broader scope. It can never trigger. The traffic it was meant to permit is actually still blocked by the earlier rule. Not a security exposure, but a functional bug. Whoever relies on this allow believes access exists when it doesn't."
                    }
                }
                break
            }
        }

        if (($ruleSrcZ -contains "any") -or ($ruleDstZ -contains "any")) {
            $wildcardIdx2.Add($i)
        }
        else {
            if (-not $sigBuckets2.ContainsKey($ruleSig)) { $sigBuckets2[$ruleSig] = New-Object System.Collections.Generic.List[int] }
            $sigBuckets2[$ruleSig].Add($i)
        }
    }
    Write-Progress -Activity "Analyzing ruleset" -Completed -Id 1

    # Ruleset-wide check (not per-rule): PAN-OS's implicit default differs
    # by scope. Interzone traffic (different zones) is denied by default,
    # but INTRAZONE traffic (same zone to itself) is ALLOWED by default
    # unless a rule overrides it. For an internet-facing zone specifically,
    # that default-allow applies to traffic hitting the firewall's own
    # external-facing interface. An explicit block for that zone talking to
    # itself is standard hygiene to override the implicit allow with a
    # deliberate decision instead. This looks for that rule ANYWHERE in the
    # enabled ruleset (not strictly requiring it to be the literal last
    # rule): what matters is that it exists and isn't itself shadowed by
    # something broader placed after it, which the shadow checks above
    # would already catch separately if that were the case.
    #
    # Accepts both "deny" and "drop" as satisfying it, but only recommends
    # "drop" in the wording below. PAN-OS's "deny" uses the matched
    # application's own default deny behavior, which for many apps still
    # sends something back (a TCP reset, an ICMP unreachable). "Drop"
    # silently discards the packet, no response at all, so an internet
    # scanner learns nothing about whether anything is even listening
    # there, this being exactly the perimeter case where that matters most.
    $hasExplicitOutsideIntrazoneBlock = $false
    foreach ($rule in $Rules) {
        if ($rule.Disabled -or ($rule.Action -ne "deny" -and $rule.Action -ne "drop")) { continue }
        $srcCoversInternetZone = ($rule.SrcZone -contains "any") -or (($rule.SrcZone | Where-Object { $InternetZoneSet -contains $_.Trim().ToLower() }).Count -gt 0)
        $dstCoversInternetZone = ($rule.DstZone -contains "any") -or (($rule.DstZone | Where-Object { $InternetZoneSet -contains $_.Trim().ToLower() }).Count -gt 0)
        if ($srcCoversInternetZone -and $dstCoversInternetZone -and $null -eq $rule.Application) {
            $hasExplicitOutsideIntrazoneBlock = $true
            break
        }
    }
    if (-not $hasExplicitOutsideIntrazoneBlock -and $InternetZoneSet.Count -gt 0) {
        $findings += [PSCustomObject]@{
            RuleName = "(ruleset-wide)"; Severity = "Low"; Type = "missing_explicit_intrazone_internet_deny"
            Detail   = "No explicit block rule found for the internet-facing zone talking to itself (e.g. $($InternetZoneSet[0]) -> $($InternetZoneSet[0]), any application, drop). PAN-OS allows intrazone traffic by default unless a rule overrides it, unlike interzone traffic which is denied by default. Use 'drop', not 'deny': deny falls back to the matched application's own default deny behavior, which can still send a TCP reset or ICMP unreachable back, revealing that something is listening there. Drop silently discards the packet instead, giving an internet scanner nothing to work with."
        }
    }

    return $findings
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
            Src         = "$($rule.SrcZone -join ';') / $($rule.SrcAddrRaw)"
            Dst         = "$($rule.DstZone -join ';') / $($rule.DstAddrRaw)"
            Application = if ($rule.Application) { $rule.Application -join "," } else { "any" }
            Service     = $rule.ServiceRaw
            Action      = $rule.Action
            Profile     = if ($rule.Profile) { $rule.Profile } else { "none" }
        }
    }
    return $inventory
}
