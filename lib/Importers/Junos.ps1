# --------------------------------------------------------------------------
# Juniper SRX (Junos) -> normalized model
# --------------------------------------------------------------------------
#
# SRX policies are named and zone based like PAN-OS, so most of it maps
# straight across (full table in the README). Things to keep in mind:
# global policies go after all zone pair policies, because that's the order
# SRX evaluates them in; "default-policy permit-all" becomes an explicit
# allow-any rule at the end; and the zone behind the default route is
# treated as internet facing.

. (Join-Path $PSScriptRoot 'JunosConfig.ps1')
. (Join-Path $PSScriptRoot 'Common.ps1')

# Predefined junos-* applications ("proto/port" or a ready token), from the
# published "show groups junos-defaults applications" output plus a few
# newer ones. If the config carries junos-defaults itself, that wins.
# RPC entries use the portmapper port (135 / 111).
$script:JunosPredefinedAppSpecs = @{
    'junos-ftp' = 'tcp/21'; 'junos-ftp-data' = 'tcp/20'; 'junos-tftp' = 'udp/69'; 'junos-twamp' = 'tcp/862'
    'junos-rtsp' = 'tcp/554'; 'junos-netbios-session' = 'tcp/139'; 'junos-smb-session' = 'tcp/445'
    'junos-ssh' = 'tcp/22'; 'junos-telnet' = 'tcp/23'; 'junos-smtp' = 'tcp/25'; 'junos-smtps' = 'tcp/587'
    'junos-tacacs' = 'tcp/49'; 'junos-tacacs-ds' = 'tcp/65'; 'junos-dhcp-client' = 'udp/68'; 'junos-dhcp-server' = 'udp/67'
    'junos-bootpc' = 'udp/68'; 'junos-bootps' = 'udp/67'; 'junos-finger' = 'tcp/79'; 'junos-http' = 'tcp/80'
    'junos-https' = 'tcp/443'; 'junos-pop3' = 'tcp/110'; 'junos-pop3s' = 'tcp/995'; 'junos-ident' = 'tcp/113'
    'junos-nntp' = 'tcp/119'; 'junos-ntp' = 'udp/123'; 'junos-imap' = 'tcp/143'; 'junos-imaps' = 'tcp/993'
    'junos-bgp' = 'tcp/179'; 'junos-ldap' = 'tcp/389'; 'junos-snpp' = 'tcp/444'; 'junos-biff' = 'udp/512'
    'junos-who' = 'udp/513'; 'junos-syslog' = 'udp/514'; 'junos-printer' = 'tcp/515'; 'junos-rip' = 'udp/520'
    'junos-radius' = 'udp/1812'; 'junos-radacct' = 'udp/1813'; 'junos-nfsd-tcp' = 'tcp/2049'; 'junos-nfsd-udp' = 'udp/2049'
    'junos-cvspserver' = 'tcp/2401'; 'junos-ldp-tcp' = 'tcp/646'; 'junos-ldp-udp' = 'udp/646'
    'junos-xnm-ssl' = 'tcp/3220'; 'junos-xnm-clear-text' = 'tcp/3221'; 'junos-ike' = 'udp/500'; 'junos-ike-nat' = 'udp/4500'
    'junos-aol' = 'tcp/5190-5193'; 'junos-chargen' = 'udp/19'; 'junos-dhcp-relay' = 'udp/67'; 'junos-discard' = 'udp/9'
    'junos-dns-udp' = 'udp/53'; 'junos-dns-tcp' = 'tcp/53'; 'junos-echo' = 'udp/7'; 'junos-gopher' = 'tcp/70'
    'junos-gtp' = 'udp/2123'; 'junos-gnutella' = 'udp/6346-6347'; 'junos-gre' = 'ip-proto-47'; 'junos-http-ext' = 'tcp/7001'
    'junos-icmp-all' = 'icmp'; 'junos-icmp-ping' = 'icmp-8'; 'junos-ping' = 'icmp'; 'junos-pingv6' = 'icmp6'
    'junos-internet-locator-service' = 'tcp/389'; 'junos-irc' = 'tcp/6660-6669'; 'junos-l2tp' = 'udp/1701'
    'junos-lpr' = 'tcp/515'; 'junos-mail' = 'tcp/25'
    'junos-h323' = @('tcp/1720', 'udp/1719', 'tcp/1503', 'tcp/389', 'tcp/522', 'tcp/1731')
    'junos-mgcp-ua' = 'udp/2427'; 'junos-mgcp-ca' = 'udp/2727'; 'junos-msn' = 'tcp/1863'
    'junos-ms-rpc-tcp' = 'tcp/135'; 'junos-ms-rpc-udp' = 'udp/135'; 'junos-ms-rpc-uuid-any-udp' = 'udp/135'
    'junos-ms-sql' = 'tcp/1433'; 'junos-nbname' = 'udp/137'; 'junos-nbds' = 'udp/138'; 'junos-nfs' = 'udp/111'
    'junos-ns-global' = 'tcp/15397'; 'junos-ns-global-pro' = 'tcp/15397'; 'junos-nsm' = 'udp/69'
    'junos-ospf' = 'ip-proto-89'; 'junos-pc-anywhere' = 'udp/5632'
    'junos-icmp6-dst-unreach-addr' = 'icmp6-1'; 'junos-icmp6-dst-unreach-admin' = 'icmp6-1'
    'junos-icmp6-dst-unreach-beyond' = 'icmp6-1'; 'junos-icmp6-dst-unreach-port' = 'icmp6-1'
    'junos-icmp6-dst-unreach-route' = 'icmp6-1'; 'junos-icmp6-echo-reply' = 'icmp6-129'; 'junos-icmp6-echo-request' = 'icmp6-128'
    'junos-icmp6-packet-too-big' = 'icmp6-2'; 'junos-icmp6-param-prob-header' = 'icmp6-4'; 'junos-icmp6-param-prob-nexthdr' = 'icmp6-4'
    'junos-icmp6-param-prob-option' = 'icmp6-4'; 'junos-icmp6-time-exceed-reassembly' = 'icmp6-3'
    'junos-icmp6-time-exceed-transit' = 'icmp6-3'; 'junos-icmp6-all' = 'icmp6'
    'junos-pptp' = 'tcp/1723'; 'junos-realaudio' = 'tcp/554'; 'junos-sccp' = 'tcp/2000'; 'junos-sctp-any' = 'ip-proto-132'
    'junos-sip' = @('udp/5060', 'tcp/5060'); 'junos-rsh' = 'tcp/514'; 'junos-smb' = @('tcp/139', 'tcp/445')
    'junos-sql-monitor' = 'udp/1434'; 'junos-sqlnet-v1' = 'tcp/1525'; 'junos-sqlnet-v2' = 'tcp/1521'
    'junos-talk' = @('udp/517', 'tcp/517'); 'junos-ntalk' = @('udp/518', 'tcp/518'); 'junos-r2cp' = 'udp/28672'
    'junos-tcp-any' = 'tcp/1-65535'; 'junos-udp-any' = 'udp/1-65535'; 'junos-uucp' = 'udp/540'
    'junos-vdo-live' = 'udp/7000-7010'; 'junos-wais' = 'tcp/210'; 'junos-whois' = 'tcp/43'; 'junos-winframe' = 'tcp/1494'
    'junos-x-windows' = 'tcp/6000-6063'; 'junos-ymsg' = @('tcp/5000-5010', 'tcp/5050', 'udp/5000-5010', 'udp/5050')
    'junos-wxcontrol' = 'tcp/3578'; 'junos-snmp-agentx' = 'tcp/705'; 'junos-stun' = @('udp/3478-3479', 'tcp/3478-3479')
    'junos-persistent-nat' = 'ip-proto-255'; 'junos-rdp' = 'tcp/3389'; 'junos-vxlan' = 'udp/4789'
    # 5800, not 5900, so keep the name too or VNC goes unnoticed.
    'junos-vnc' = @('tcp/5800', 'junos-vnc')
}
foreach ($n in @('epm', 'msexchange-directory-rfr', 'msexchange-info-store', 'msexchange-directory-nsp', 'wmic-admin',
        'wmic-webm-level1login', 'wmic-webm-objectsink', 'wmic-webm-services', 'wmic-webm-callresult', 'wmic-webm-login-clientid',
        'wmic-webm-login-helper', 'wmic-webm-refreshing-services', 'wmic-webm-remote-refresher', 'wmic-webm-shutdown',
        'wmic-webm-classobject', 'wmic-admin2', 'wmic-mgmt', 'iis-com-1', 'iis-com-adminbase', 'uuid-any-tcp')) {
    $script:JunosPredefinedAppSpecs["junos-ms-rpc-$n"] = 'tcp/135'
}
$script:JunosSunRpc = @('portmap', 'nfs', 'mountd', 'ypbind', 'status', 'ypserv', 'rquotad', 'nlockmgr', 'ruserd', 'sadmind', 'sprayd', 'walld', 'any')
foreach ($n in @('') + $script:JunosSunRpc) {
    $base = if ($n) { "junos-sun-rpc-$n" } else { 'junos-sun-rpc' }
    $script:JunosPredefinedAppSpecs["$base-tcp"] = 'tcp/111'; $script:JunosPredefinedAppSpecs["$base-udp"] = 'udp/111'
}

# Tokens for each predefined application, built once from the specs.
$script:JunosPredefinedApps = @{}
foreach ($k in $script:JunosPredefinedAppSpecs.Keys) {
    $toks = @()
    foreach ($spec in @($script:JunosPredefinedAppSpecs[$k])) {
        if ($spec -match '^(tcp|udp)/(\d+)(?:-(\d+))?$') {
            $lo = [int]$Matches[2]; $hi = if ($Matches[3]) { [int]$Matches[3] } else { $lo }
            $toks += ConvertTo-PortTokens -Proto $Matches[1] -Low $lo -High $hi
        }
        else { $toks += $spec }
    }
    $script:JunosPredefinedApps[$k] = @($toks | Select-Object -Unique)
}

$script:JunosPredefinedAppSets = @{
    'junos-routing-inbound' = @('junos-bgp', 'junos-rip', 'junos-ldp-tcp', 'junos-ldp-udp')
    'junos-cifs' = @('junos-netbios-session', 'junos-smb-session')
    'junos-mgcp' = @('junos-mgcp-ua', 'junos-mgcp-ca')
    'junos-ms-rpc' = @('junos-ms-rpc-tcp', 'junos-ms-rpc-udp')
    'junos-ms-rpc-msexchange' = @('junos-ms-rpc-tcp', 'junos-ms-rpc-udp', 'junos-ms-rpc-epm', 'junos-ms-rpc-msexchange-directory-rfr', 'junos-ms-rpc-msexchange-info-store', 'junos-ms-rpc-msexchange-directory-nsp')
    'junos-ms-rpc-wmic' = @('junos-ms-rpc-tcp', 'junos-ms-rpc-wmic-admin', 'junos-ms-rpc-wmic-admin2', 'junos-ms-rpc-wmic-webm-level1login', 'junos-ms-rpc-wmic-mgmt')
    'junos-ms-rpc-iis-com' = @('junos-ms-rpc-tcp', 'junos-ms-rpc-iis-com-1', 'junos-ms-rpc-iis-com-adminbase')
    'junos-ms-rpc-any' = @('junos-ms-rpc-tcp', 'junos-ms-rpc-udp', 'junos-ms-rpc-uuid-any-tcp', 'junos-ms-rpc-uuid-any-udp')
    'junos-sun-rpc' = @('junos-sun-rpc-tcp', 'junos-sun-rpc-udp')
    'junos-sun-rpc-nfs-access' = @('junos-sun-rpc-tcp', 'junos-sun-rpc-udp', 'junos-sun-rpc-portmap-tcp', 'junos-sun-rpc-portmap-udp', 'junos-sun-rpc-nfs-tcp', 'junos-sun-rpc-nfs-udp', 'junos-sun-rpc-mountd-tcp', 'junos-sun-rpc-mountd-udp')
}
foreach ($n in $script:JunosSunRpc) {
    $members = @('junos-sun-rpc-tcp', 'junos-sun-rpc-udp')
    if ($n -notin @('portmap', 'any')) { $members += @('junos-sun-rpc-portmap-tcp', 'junos-sun-rpc-portmap-udp') }
    $members += @("junos-sun-rpc-$n-tcp", "junos-sun-rpc-$n-udp")
    $script:JunosPredefinedAppSets["junos-sun-rpc-$n"] = $members
}

# Keywords "destination-port" accepts.
$script:JunosNamedPorts = @{
    'ftp-data' = 20; 'ftp' = 21; 'ssh' = 22; 'telnet' = 23; 'smtp' = 25; 'tacacs' = 49; 'tacacs-ds' = 65; 'domain' = 53
    'bootps' = 67; 'bootpc' = 68; 'dhcp' = 67; 'tftp' = 69; 'finger' = 79; 'http' = 80; 'kerberos-sec' = 88; 'pop3' = 110
    'sunrpc' = 111; 'ident' = 113; 'nntp' = 119; 'ntp' = 123; 'netbios-ns' = 137; 'netbios-dgm' = 138; 'netbios-ssn' = 139
    'imap' = 143; 'snmp' = 161; 'snmptrap' = 162; 'xdmcp' = 177; 'bgp' = 179; 'ldap' = 389; 'mobileip-agent' = 434
    'mobilip-mn' = 435; 'snpp' = 444; 'https' = 443; 'kpasswd' = 464; 'exec' = 512; 'biff' = 512; 'login' = 513; 'who' = 513
    'cmd' = 514; 'syslog' = 514; 'printer' = 515; 'talk' = 517; 'ntalk' = 518; 'rip' = 520; 'timed' = 525; 'klogin' = 543
    'kshell' = 544; 'ldp' = 646; 'msdp' = 639; 'krb-prop' = 754; 'krbupdate' = 760; 'socks' = 1080; 'pptp' = 1723
    'radius' = 1812; 'radacct' = 1813; 'nfsd' = 2049; 'cvspserver' = 2401; 'eklogin' = 2105; 'ekshell' = 2106
    'rkinit' = 2108; 'zephyr-srv' = 2102; 'zephyr-clt' = 2103; 'zephyr-hm' = 2104
}

# Named ICMP / ICMPv6 types accepted by "icmp-type" / "icmp6-type".
$script:JunosIcmpTypes = @{
    'echo-reply' = 0; 'unreachable' = 3; 'source-quench' = 4; 'redirect' = 5; 'echo-request' = 8
    'router-advertisement' = 9; 'router-solicit' = 10; 'time-exceeded' = 11; 'parameter-problem' = 12
    'timestamp' = 13; 'timestamp-reply' = 14; 'info-request' = 15; 'info-reply' = 16
    'mask-request' = 17; 'mask-reply' = 18
}
$script:JunosIcmp6Types = @{
    'destination-unreachable' = 1; 'packet-too-big' = 2; 'time-exceeded' = 3; 'parameter-problem' = 4
    'echo-request' = 128; 'echo-reply' = 129; 'membership-query' = 130; 'membership-report' = 131
    'membership-termination' = 132; 'router-solicit' = 133; 'router-advertisement' = 134
    'neighbor-solicit' = 135; 'neighbor-advertisement' = 136; 'redirect' = 137; 'node-information-request' = 139
    'node-information-reply' = 140
}

# IP protocol names accepted by "protocol".
$script:JunosProtocolNumbers = @{
    'icmp' = 1; 'igmp' = 2; 'ipip' = 4; 'tcp' = 6; 'egp' = 8; 'udp' = 17; 'rsvp' = 46; 'gre' = 47
    'esp' = 50; 'ah' = 51; 'icmp6' = 58; 'ospf' = 89; 'pim' = 103; 'vrrp' = 112; 'sctp' = 132
}

# Only where AppSecure and our list spell it differently; anything else is
# just lowercased (junos:SSH -> ssh). -AppMapCsv can add more.
$script:JunosAppCanonical = @{
    'rdp' = 'ms-rdp'; 'ms-rdp' = 'ms-rdp'; 'http' = 'web-browsing'; 'https' = 'ssl'; 'ssl' = 'ssl'
    'smb' = 'ms-ds-smb'; 'cifs' = 'ms-ds-smb'; 'mssql' = 'ms-sql-db'; 'ms-sql' = 'ms-sql-db'
    'postgresql' = 'postgres'; 'doh' = 'dns-over-https'; 'dns-over-https' = 'dns-over-https'
    # GOTOMYPC is verified; the others are our best guess at the spelling
    'gotomypc' = 'logmein-gotomypc'; 'elasticsearch' = 'elasticsearch-base'; 'upnp' = 'ssdp'
    'netbios-ns' = 'netbios-ns'; 'netbios-name' = 'netbios-ns'; 'nbns' = 'netbios-ns'
    'google-remote-desktop' = 'chrome-remote-desktop'; 'oracle-tns' = 'oracle'; 'sqlnet' = 'oracle'
}

function ConvertTo-JunosCanonicalApp {
    param([string]$DynamicApp, [hashtable]$UserMap)
    if ($UserMap -and $UserMap.ContainsKey($DynamicApp.ToLower())) { return $UserMap[$DynamicApp.ToLower()] }
    $k = ($DynamicApp -replace '^(?i)junos:', '').ToLower()
    if ($script:JunosAppCanonical.ContainsKey($k)) { return $script:JunosAppCanonical[$k] }
    return ($k -replace '[\._\s]+', '-')
}

function Test-JunosIpInPrefix {
    param([string]$Ip, [string]$Prefix)
    if ($Prefix -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { return $false }
    $net = $Matches[1]; $bits = [int]$Matches[2]
    if ($Ip -notmatch '^\d+\.\d+\.\d+\.\d+$') { return $false }
    $toInt = { param($a) $o = $a.Split('.') | ForEach-Object { [uint32]$_ }; ($o[0] -shl 24) -bor ($o[1] -shl 16) -bor ($o[2] -shl 8) -bor $o[3] }
    $mask = if ($bits -eq 0) { [uint32]0 } else { [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $bits)) }
    return ((& $toInt $Ip) -band $mask) -eq ((& $toInt $net) -band $mask)
}

function Read-JunosHitCount {
    # "show security policies hit-count" text. Keys are scope|from|to|name,
    # plus scope|*|*|name as a fallback (-1 when that name is ambiguous).
    param([string]$Path)
    $map = @{}
    if (-not $Path) { return $map }
    $scope = 'root'
    foreach ($line in (Get-Content -Path $Path)) {
        if ($line -match '^\s*Logical system:\s*(\S+)') {
            $scope = if ($Matches[1] -eq 'root-logical-system') { 'root' } else { $Matches[1] }
            continue
        }
        if ($line -match '^\s*\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)(\s+\S+)?\s*$') {
            $map["$scope|$($Matches[1])|$($Matches[2])|$($Matches[3])"] = [int64]$Matches[4]
            $any = "$scope|*|*|$($Matches[3])"
            if ($map.ContainsKey($any)) { $map[$any] = -1 } else { $map[$any] = [int64]$Matches[4] }
        }
    }
    return $map
}

function Expand-JunosGroups {
    # Expands groups applied at the top (or logical system) level. Like on
    # Junos, what's written explicitly wins over the group. Wildcards,
    # deeper apply-groups and unused groups are skipped and reported.
    # junos-defaults is handled by the caller.
    param($Statements, $Model)
    $explicit = New-Object System.Collections.Generic.List[object]
    $groupStmts = [ordered]@{}
    $applied = New-Object System.Collections.Generic.List[object]
    foreach ($st in @($Statements)) {
        if ($null -eq $st) { continue }
        $w = @($st.Words); $pre = @(); $rest = $w
        if ($w.Count -ge 3 -and $w[0] -in @('logical-systems', 'tenants')) { $pre = @($w[0], $w[1]); $rest = @($w | Select-Object -Skip 2) }
        if ($pre.Count -eq 0 -and $rest.Count -ge 3 -and $rest[0] -eq 'groups' -and $rest[1] -ne 'junos-defaults') {
            $g = $rest[1]
            if (-not $groupStmts.Contains($g)) { $groupStmts[$g] = New-Object System.Collections.Generic.List[object] }
            # skip a deactivated group; a deactivated leaf keeps its depth
            if ($st.Inactive -and $st.InactiveDepth -le 2) { continue }
            $groupStmts[$g].Add(@{ Words = @($rest | Select-Object -Skip 2); Inactive = $st.Inactive; InactiveDepth = $(if ($st.Inactive) { $st.InactiveDepth - 2 } else { 0 }); Line = $st.Line })
            continue
        }
        if ($rest.Count -eq 2 -and $rest[0] -eq 'apply-groups') {
            if (-not $st.Inactive) { $applied.Add(@{ Pre = $pre; Group = $rest[1] }) }
            continue
        }
        $ai = [array]::IndexOf([string[]]$rest, 'apply-groups')
        if ($ai -ge 0 -and $ai -eq $rest.Count - 2 -and $rest[0] -ne 'groups') {
            Add-NormDiagnostic $Model 'lossy' '' "apply-groups '$($rest[-1])' at '$((@($pre) + @($rest | Select-Object -First $ai)) -join ' ')' is not expanded (only top level and logical system level apply-groups are); what the group adds there is not analyzed"
            continue
        }
        $explicit.Add($st)
    }
    if ($groupStmts.Count -eq 0 -and $applied.Count -eq 0) { return $explicit }

    $leafKey = { param([string[]]$W) if ($W.Count -lt 2) { return ($W -join ' ') } return (($W | Select-Object -First ($W.Count - 1)) -join ' ') }
    $taken = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($st in $explicit) { [void]$taken.Add((& $leafKey @($st.Words))) }
    $added = New-Object System.Collections.Generic.List[object]
    $used = @{}
    $wildReported = @{}
    foreach ($ap in $applied) {
        $g = $ap.Group
        if (-not $groupStmts.Contains($g)) {
            $lvl = if ($g -match '\$') { 'info' } else { 'warn' }
            Add-NormDiagnostic $Model $lvl '' "apply-groups '$g' names a group that is not defined in the input (chassis cluster node groups such as `${node} are not expanded); nothing added"
            continue
        }
        $used[$g] = $true
        $newKeys = New-Object System.Collections.Generic.List[string]
        foreach ($gs in $groupStmts[$g]) {
            if (@($gs.Words | Where-Object { $_ -match '^<.*>$' }).Count -gt 0) {
                if (-not $wildReported.ContainsKey($g)) {
                    $wildReported[$g] = $true
                    Add-NormDiagnostic $Model 'lossy' '' "configuration group '$g' uses wildcards (<*>); those statements are not expanded, what they add is not analyzed"
                }
                continue
            }
            $words = @($ap.Pre) + @($gs.Words)
            $k = & $leafKey $words
            if ($taken.Contains($k)) { continue }
            $newKeys.Add($k)
            $added.Add(@{ Words = $words; Inactive = $gs.Inactive; InactiveDepth = $(if ($gs.Inactive) { $gs.InactiveDepth + @($ap.Pre).Count } else { 0 }); Line = $gs.Line })
        }
        foreach ($k in $newKeys) { [void]$taken.Add($k) }
    }
    foreach ($g in $groupStmts.Keys) {
        if ($used.ContainsKey($g) -or $groupStmts[$g].Count -eq 0) { continue }
        $hasSec = @($groupStmts[$g] | Where-Object { $_.Words[0] -in @('security', 'applications', 'logical-systems') }).Count -gt 0
        Add-NormDiagnostic $Model $(if ($hasSec) { 'lossy' } else { 'info' }) '' "configuration group '$g' is not applied by a top level or logical system apply-groups; its statements are ignored"
    }
    $explicit.AddRange($added)
    return $explicit
}

function ConvertFrom-Junos {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$HitCountFile,
        [string]$AppMapCsv
    )
    $model = New-NormModel -Vendor 'junos' -Source $Path
    $warn = New-Object System.Collections.Generic.List[string]
    $statements = Read-JunosConfig -Path $Path -Warnings $warn
    foreach ($w in $warn) { Add-NormDiagnostic $model 'warn' '' $w }
    $hits = Read-JunosHitCount -Path $HitCountFile

    $userAppMap = @{}
    if ($AppMapCsv) {
        foreach ($row in (Import-Csv -Path $AppMapCsv)) {
            if ($row.id -and $row.name) { $userAppMap[$row.id.Trim().ToLower()] = $row.name.Trim() }
        }
    }

    # ---- collect, per scope (root or logical system)
    $scopes = [ordered]@{}
    function Get-Scope([string]$Name) {
        if (-not $scopes.Contains($Name)) {
            $scopes[$Name] = @{
                IfAddr = @{}; ZoneOfIf = @{}; Zones = [ordered]@{}; DefaultNextHops = @()
                Apps = @{}; AppSets = @{}; Policies = [ordered]@{}; DefaultPermitAll = $false
                # address books: book -> @{ Addr = name -> @{Type; Val}; Sets = name -> members }
                # ("global", "zone:Z" for a zone's own book, or a named book)
                Books = [ordered]@{}; BookZones = @{}
            }
        }
        return $scopes[$Name]
    }

    $statements = Expand-JunosGroups -Statements $statements -Model $model

    foreach ($st in $statements) {
        $w = @($st.Words)
        $scopeName = 'root'
        if ($w.Count -ge 3 -and $w[0] -in @('logical-systems', 'tenants')) { $scopeName = $w[1]; $w = @($w | Select-Object -Skip 2) }
        # Depth of the deactivated path relative to $w (0 = active).
        $inDepth = if ($st.Inactive) { [int]$st.InactiveDepth - (@($st.Words).Count - $w.Count) } else { 0 }
        if ($w.Count -ge 3 -and $w[0] -eq 'groups') {
            # Other groups are already expanded; junos-defaults applications
            # override our predefined table.
            if ($w[1] -eq 'junos-defaults' -and $w[2] -eq 'applications') { $w = @($w | Select-Object -Skip 2); $inDepth -= 2 }
            else { continue }
        }
        if ($w.Count -lt 2) { continue }
        # Inactive stuff is skipped, except policy statements: a deactivated
        # policy still shows up as a disabled rule.
        $isPolicyStmt = $w[0] -eq 'security' -and $w[1] -eq 'policies' -and $w.Count -ge 3 -and $w[2] -ne 'default-policy'
        if ($st.Inactive -and ($inDepth -le 0 -or -not $isPolicyStmt)) { continue }
        $sc = Get-Scope $scopeName

        # interfaces IF unit N family inet address A/L
        if ($w[0] -eq 'interfaces' -and $w.Count -ge 8 -and $w[2] -eq 'unit' -and $w[4] -eq 'family' -and $w[5] -eq 'inet' -and $w[6] -eq 'address') {
            # A unit can carry several addresses (primary and secondary).
            $ifk = "$($w[1]).$($w[3])"
            if (-not $sc.IfAddr.ContainsKey($ifk)) { $sc.IfAddr[$ifk] = @() }
            $sc.IfAddr[$ifk] += $w[7]; continue
        }
        # security zones security-zone Z ...
        if ($w[0] -eq 'security' -and $w[1] -eq 'zones' -and $w.Count -ge 4 -and $w[2] -eq 'security-zone') {
            $z = $w[3]; $sc.Zones[$z] = $true
            if ($w.Count -ge 6 -and $w[4] -eq 'interfaces') { $sc.ZoneOfIf[$w[5]] = $z }
            if ($w.Count -ge 7 -and $w[4] -eq 'address-book') { $w = @('security', 'address-book', "zone:$z") + @($w | Select-Object -Skip 5) }
            else { continue }
        }
        # security address-book BOOK address NAME ... / address-set S ...
        if ($w[0] -eq 'security' -and $w[1] -eq 'address-book' -and $w.Count -ge 5) {
            $kind = $w[3]; $name = $w[4]; $bookName = $w[2]
            if (-not $sc.Books.Contains($bookName)) { $sc.Books[$bookName] = @{ Addr = [ordered]@{}; Sets = [ordered]@{} } }
            $book = $sc.Books[$bookName]
            # security address-book BOOK attach zone Z
            if ($kind -eq 'attach' -and $w[4] -eq 'zone' -and $w.Count -ge 6) {
                if (-not $sc.BookZones.ContainsKey($bookName)) { $sc.BookZones[$bookName] = @() }
                $sc.BookZones[$bookName] += $w[5]
                continue
            }
            if ($kind -eq 'address' -and $w.Count -ge 6) {
                $val = $null; $type = $null
                switch ($w[5]) {
                    'range-address' { if ($w.Count -ge 9) { $type = 'ip-range'; $val = "$($w[6])-$($w[8])" } }
                    'dns-name' { $type = 'fqdn'; $val = $w[6] }
                    'wildcard-address' { $type = 'ip-wildcard'; $val = $w[6] }
                    'description' { }
                    default {
                        if ($w[5] -match '^[\d\.]+(/\d+)?$' -or $w[5] -match ':') {
                            # IPv6 gets its own type and stays opaque.
                            $type = if ($w[5] -match ':') { 'ip6-netmask' } else { 'ip-netmask' }
                            $val = $(if ($w[5] -match '/') { $w[5] } elseif ($w[5] -match ':') { "$($w[5])/128" } else { "$($w[5])/32" })
                        }
                    }
                }
                if ($type) { $book.Addr[$name] = @{ Name = $name; Type = $type; Val = $val } }
            }
            elseif ($kind -eq 'address-set' -and $w.Count -ge 7 -and $w[5] -in @('address', 'address-set')) {
                if (-not $book.Sets.Contains($name)) { $book.Sets[$name] = @{ Name = $name; Members = New-Object System.Collections.Generic.List[string] } }
                $book.Sets[$name].Members.Add($w[6])
            }
            continue
        }
        # applications application NAME [term T] protocol|destination-port|icmp-type ...
        if ($w[0] -eq 'applications' -and $w.Count -ge 4) {
            if ($w[1] -eq 'application') {
                $app = $w[2]; $rest = @($w | Select-Object -Skip 3)
                $term = 'default'
                if ($rest.Count -ge 2 -and $rest[0] -eq 'term') { $term = $rest[1]; $rest = @($rest | Select-Object -Skip 2) }
                if (-not $sc.Apps.ContainsKey($app)) { $sc.Apps[$app] = [ordered]@{} }
                if (-not $sc.Apps[$app].Contains($term)) { $sc.Apps[$app][$term] = @{} }
                # A line can hold several pairs ("protocol tcp destination-port 8080").
                for ($k = 0; $k + 1 -lt $rest.Count; $k += 2) { $sc.Apps[$app][$term][$rest[$k]] = $rest[$k + 1] }
            }
            elseif ($w[1] -eq 'application-set' -and $w.Count -ge 5 -and $w[3] -in @('application', 'application-set')) {
                if (-not $sc.AppSets.ContainsKey($w[2])) { $sc.AppSets[$w[2]] = @() }
                $sc.AppSets[$w[2]] += $w[4]
            }
            continue
        }
        # security policies ...
        if ($w[0] -eq 'security' -and $w[1] -eq 'policies' -and $w.Count -ge 3) {
            if ($w[2] -eq 'default-policy' -and $w.Count -ge 4) { $sc.DefaultPermitAll = ($w[3] -eq 'permit-all'); continue }
            $from = $null; $to = $null; $pname = $null; $rest = @(); $isGlobal = $false
            if ($w[2] -eq 'from-zone' -and $w.Count -ge 8 -and $w[4] -eq 'to-zone' -and $w[6] -eq 'policy') {
                $from = $w[3]; $to = $w[5]; $pname = $w[7]; $rest = @($w | Select-Object -Skip 8)
            }
            elseif ($w[2] -eq 'global' -and $w.Count -ge 5 -and $w[3] -eq 'policy') {
                $isGlobal = $true; $pname = $w[4]; $rest = @($w | Select-Object -Skip 5)
            }
            else { continue }
            # Deactivated below the policy name: drop the leaf. At or above
            # it: the policy is disabled.
            $nameIdx = if ($isGlobal) { 4 } else { 7 }
            if ($st.Inactive -and $inDepth -gt $nameIdx + 1) { continue }
            $key = if ($isGlobal) { "global||$pname" } else { "$from|$to|$pname" }
            if (-not $sc.Policies.Contains($key)) {
                $sc.Policies[$key] = @{
                    Global = $isGlobal; From = @(); To = @(); Name = $pname; Inactive = $false
                    Src = @(); Dst = @(); SrcEx = $false; DstEx = $false; Apps = @(); DynApps = @()
                    Action = $null; Services = @(); Log = @(); Descr = ''; Identity = $false; Sched = ''; UrlCat = $false
                }
                if (-not $isGlobal) { $sc.Policies[$key].From = @($from); $sc.Policies[$key].To = @($to) }
            }
            $p = $sc.Policies[$key]
            if ($st.Inactive) { $p.Inactive = $true }
            if ($rest.Count -eq 0) { continue }
            switch ($rest[0]) {
                'match' {
                    # Usually one condition per line, but a typed line can chain several.
                    $k = 1
                    while ($k -lt $rest.Count) {
                        $key = $rest[$k]
                        if ($key -in @('source-address-excluded', 'destination-address-excluded')) {
                            if ($key -eq 'source-address-excluded') { $p.SrcEx = $true } else { $p.DstEx = $true }
                            $k++; continue
                        }
                        $v = if ($k + 1 -lt $rest.Count) { $rest[$k + 1] } else { $null }
                        switch ($key) {
                            'source-address' { $p.Src += $v }
                            'destination-address' { $p.Dst += $v }
                            'application' { $p.Apps += $v }
                            'dynamic-application' { $p.DynApps += $v }
                            'from-zone' { $p.From += $v }
                            'to-zone' { $p.To += $v }
                            { $_ -in @('source-identity', 'source-end-user-profile') } { $p.Identity = $true }
                            'url-category' { $p.UrlCat = $true }
                        }
                        $k += 2
                    }
                }
                'then' {
                    if ($rest.Count -lt 2) { break }
                    switch ($rest[1]) {
                        'permit' {
                            if (-not $p.Action) { $p.Action = 'allow' }
                            if ($rest.Count -ge 4 -and $rest[2] -eq 'application-services') {
                                $svc = $rest[3]; $val = if ($rest.Count -ge 5) { $rest[4] } else { '' }
                                switch ($svc) {
                                    'idp' { $p.Services += 'idp' }
                                    'idp-policy' { $p.Services += "idp:$val" }
                                    'utm-policy' { $p.Services += "utm:$val" }
                                    'security-intelligence-policy' { $p.Services += "secintel:$val" }
                                    'advanced-anti-malware-policy' { $p.Services += "aamw:$val" }
                                    'application-firewall' { $p.Services += "appfw:$(if ($rest.Count -ge 6) { $rest[5] } else { $val })" }
                                }
                            }
                        }
                        'deny' { $p.Action = 'deny' }
                        'reject' { $p.Action = 'deny' }
                        'log' { if ($rest.Count -ge 3) { $p.Log += $rest[2] } }
                    }
                }
                'description' { $p.Descr = ($rest | Select-Object -Skip 1) -join ' ' }
                'scheduler-name' { $p.Sched = $(if ($rest.Count -ge 2) { $rest[1] } else { '' }) }
            }
            continue
        }
        # routing-options static route 0.0.0.0/0 next-hop X   (also inside routing-instances)
        $rw = $w
        if ($rw[0] -eq 'routing-instances' -and $rw.Count -ge 3) { $rw = @($rw | Select-Object -Skip 2) }
        if ($rw.Count -ge 6 -and $rw[0] -eq 'routing-options' -and $rw[1] -eq 'static' -and $rw[2] -eq 'route' -and $rw[3] -eq '0.0.0.0/0' -and $rw[4] -in @('next-hop', 'qualified-next-hop')) {
            $sc.DefaultNextHops += $rw[5]
        }
    }

    # ---- address books -> model objects and groups
    # Same name, same value everywhere: plain name. Same name, different
    # values in different books: one copy per book as NAME@book, and each
    # policy picks the one its zones can see (zone book, attached books,
    # then global).
    $defs = @{}
    foreach ($scopeName in $scopes.Keys) {
        foreach ($bookName in $scopes[$scopeName].Books.Keys) {
            $b = $scopes[$scopeName].Books[$bookName]
            foreach ($a in $b.Addr.Values) {
                $k = $a.Name.ToLower(); if (-not $defs.ContainsKey($k)) { $defs[$k] = @() }
                $defs[$k] += @{ Name = $a.Name; Scope = $scopeName; Book = $bookName; Sig = "a|$($a.Type)|$($a.Val)".ToLower(); Members = @() }
            }
            foreach ($g in $b.Sets.Values) {
                $k = $g.Name.ToLower(); if (-not $defs.ContainsKey($k)) { $defs[$k] = @() }
                $defs[$k] += @{ Name = $g.Name; Scope = $scopeName; Book = $bookName; Sig = ('s|' + ($g.Members -join ',')).ToLower(); Members = @($g.Members) }
            }
        }
    }
    $conflict = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $defs.Keys) { if (@($defs[$k] | ForEach-Object { $_.Sig } | Select-Object -Unique).Count -gt 1) { [void]$conflict.Add($k) } }
    # a set with ambiguous members is ambiguous too
    do {
        $changed = $false
        foreach ($k in $defs.Keys) {
            if ($conflict.Contains($k) -or @($defs[$k]).Count -lt 2) { continue }
            if (@($defs[$k] | ForEach-Object { $_.Members } | Where-Object { $conflict.Contains($_) }).Count -gt 0) { [void]$conflict.Add($k); $changed = $true }
        }
    } while ($changed)
    $qualify = {
        param([string]$ScopeName, [string]$BookName, [string]$Name)
        if (-not $conflict.Contains($Name)) { return $Name }
        $bk = if ($BookName -like 'zone:*') { $BookName.Substring(5) } else { $BookName }
        if ($ScopeName -ne 'root') { $bk = "${ScopeName}:$bk" }
        return "$Name@$bk"
    }
    $findBook = {
        # the book a name resolves to, seen from the given zones
        param($Sc, [string[]]$Zones, [string]$Name)
        $order = @()
        foreach ($z in @($Zones | Where-Object { $_ -and $_ -ne 'any' })) {
            $order += "zone:$z"
            foreach ($bn in $Sc.BookZones.Keys) { if ($Sc.BookZones[$bn] -contains $z) { $order += $bn } }
        }
        $order += 'global'
        foreach ($bn in $order) {
            if ($Sc.Books.Contains($bn) -and ($Sc.Books[$bn].Addr.Contains($Name) -or $Sc.Books[$bn].Sets.Contains($Name))) { return $bn }
        }
        $found = $null
        foreach ($bn in $Sc.Books.Keys) { if ($Sc.Books[$bn].Addr.Contains($Name) -or $Sc.Books[$bn].Sets.Contains($Name)) { $found = $bn } }
        return $found
    }
    foreach ($scopeName in $scopes.Keys) {
        $sc = $scopes[$scopeName]
        foreach ($bookName in $sc.Books.Keys) {
            $b = $sc.Books[$bookName]
            foreach ($a in $b.Addr.Values) { Add-NormObject $model (& $qualify $scopeName $bookName $a.Name) $a.Type $a.Val }
            foreach ($g in $b.Sets.Values) {
                $members = foreach ($m in $g.Members) {
                    $mb = if ($b.Addr.Contains($m) -or $b.Sets.Contains($m)) { $bookName } else { & $findBook $sc @() $m }
                    if ($mb) { & $qualify $scopeName $mb $m } else { $m }
                }
                Add-NormGroup $model (& $qualify $scopeName $bookName $g.Name) @($members)
            }
        }
    }
    foreach ($k in ($conflict | Sort-Object)) {
        $orig = @($defs[$k])[0].Name
        $names = @($defs[$k] | ForEach-Object { & $qualify $_.Scope $_.Book $orig } | Select-Object -Unique)
        Add-NormDiagnostic $model 'info' '' "address book name '$orig' has different definitions in several address books ($($names -join ', ')); registered once per book, policies resolve it through the address books of their zones"
    }

    # ---- resolve applications
    # Prefix names with the scope only if more than one scope has policies.
    $multiScope = @($scopes.Values | Where-Object { $_.Policies.Count -gt 0 -or $_.DefaultPermitAll }).Count -gt 1
    # Zone names are per logical system. A name used by more than one of
    # them becomes "<scope>/<zone>", as FortiGate VDOM zones do, so the
    # internet and intrazone hints of one can't leak into the other.
    $zoneScopes = @{}
    foreach ($sn in $scopes.Keys) {
        $s = $scopes[$sn]
        if ($s.Policies.Count -eq 0 -and -not $s.DefaultPermitAll) { continue }
        foreach ($z in (@($s.Zones.Keys) + @($s.Policies.Values | ForEach-Object { @($_.From) + @($_.To) }))) {
            if (-not $z -or $z -eq 'any') { continue }
            if (-not $zoneScopes.ContainsKey($z)) { $zoneScopes[$z] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$zoneScopes[$z].Add($sn)
        }
    }
    $sharedZones = New-Object System.Collections.Generic.HashSet[string]
    foreach ($z in $zoneScopes.Keys) { if ($zoneScopes[$z].Count -gt 1) { [void]$sharedZones.Add($z) } }
    if ($sharedZones.Count -gt 0) {
        Add-NormDiagnostic $model 'info' '' "zone name(s) $(@($sharedZones | Sort-Object) -join ', ') exist in more than one logical system; written as <logical system>/<zone> in rules and zone hints"
    }
    $zoneName = {
        param([string]$ScopeName, [string]$Zone)
        if ($sharedZones.Contains($Zone)) { return "$ScopeName/$Zone" }
        return $Zone
    }
    foreach ($scopeName in $scopes.Keys) {
        $sc = $scopes[$scopeName]

        # zones behind the default route are internet facing
        foreach ($nh in $sc.DefaultNextHops) {
            $ifName = $null
            if ($sc.ZoneOfIf.ContainsKey($nh)) { $ifName = $nh }
            else {
                foreach ($ifu in $sc.IfAddr.Keys) {
                    if (@($sc.IfAddr[$ifu] | Where-Object { Test-JunosIpInPrefix -Ip $nh -Prefix $_ }).Count -gt 0) { $ifName = $ifu; break }
                }
            }
            if ($ifName -and $sc.ZoneOfIf.ContainsKey($ifName)) {
                $model.ZoneHints[(& $zoneName $scopeName $sc.ZoneOfIf[$ifName])] = 'internet'
            }
        }

        $cache = @{}
        $resolveApp = $null
        $resolveApp = {
            param([string]$Name, $Seen)
            if ($cache.ContainsKey($Name)) { return $cache[$Name] }
            if ($Seen.Contains($Name)) { return @() }
            [void]$Seen.Add($Name)
            $out = @()
            # "any" can be an application-set member too.
            if ($Name -eq 'any') { $out += 'any' }
            elseif ($sc.AppSets.ContainsKey($Name)) {
                foreach ($m in $sc.AppSets[$Name]) { $out += & $resolveApp $m $Seen }
            }
            elseif ($sc.Apps.ContainsKey($Name)) {
                foreach ($term in $sc.Apps[$Name].Values) {
                    $proto = if ($term.ContainsKey('protocol')) { "$($term['protocol'])".ToLower() } else { '' }
                    # "protocol 6" is as valid as "protocol tcp"
                    $proto = switch ($proto) { '6' { 'tcp' } '17' { 'udp' } '132' { 'sctp' } '1' { 'icmp' } '58' { 'icmp6' } default { $proto } }
                    $dp = if ($term.ContainsKey('destination-port')) { "$($term['destination-port'])" } else { '' }
                    switch -Regex ($proto) {
                        '^(tcp|udp|sctp)$' {
                            if ($dp -eq '') { $out += "$proto-1-65535"; break }
                            $lo = $null; $hi = $null
                            if ($dp -match '^(\d+)-(\d+)$') { $lo = [int]$Matches[1]; $hi = [int]$Matches[2] }
                            elseif ($dp -match '^\d+$') { $lo = [int]$dp; $hi = $lo }
                            elseif ($script:JunosNamedPorts.ContainsKey($dp.ToLower())) { $lo = $script:JunosNamedPorts[$dp.ToLower()]; $hi = $lo }
                            if ($null -ne $lo) { $out += ConvertTo-PortTokens -Proto $proto -Low $lo -High $hi }
                            else { $out += $dp.ToLower(); Add-NormDiagnostic $model 'warn' '' "application '$Name': destination-port '$dp' not understood, kept as opaque token" }
                        }
                        '^icmp6?$' {
                            $tk = if ($proto -eq 'icmp6') { 'icmp6-type' } else { 'icmp-type' }
                            if (-not $term.ContainsKey($tk) -and $term.ContainsKey('icmp-type')) { $tk = 'icmp-type' }
                            if ($term.ContainsKey($tk)) {
                                $it = "$($term[$tk])".ToLower()
                                $names = if ($proto -eq 'icmp6') { $script:JunosIcmp6Types } else { $script:JunosIcmpTypes }
                                if ($names.ContainsKey($it)) { $it = $names[$it] }
                                $out += "$proto-$it"
                            }
                            else { $out += $proto }
                        }
                        '^\d+$' { $out += "ip-proto-$proto" }
                        '^$' { }
                        default {
                            if ($script:JunosProtocolNumbers.ContainsKey($proto)) { $out += "ip-proto-$($script:JunosProtocolNumbers[$proto])" }
                            else { $out += "ip-proto-$proto"; Add-NormDiagnostic $model 'warn' '' "application '$Name': protocol '$proto' not recognised, kept as opaque token" }
                        }
                    }
                }
                if ($out.Count -eq 0) { $out += 'ip-proto-0' }
                $hint = Get-NormAppHintToken $Name
                if ($hint) { $out += $hint }
            }
            elseif ($script:JunosPredefinedAppSets.ContainsKey($Name)) {
                foreach ($m in $script:JunosPredefinedAppSets[$Name]) { $out += & $resolveApp $m $Seen }
            }
            elseif ($script:JunosPredefinedApps.ContainsKey($Name)) { $out += $script:JunosPredefinedApps[$Name] }
            else {
                Add-NormDiagnostic $model 'warn' '' "application '$Name' is not defined in the configuration and is not a known predefined junos-* application; kept as opaque token"
                $out += $Name.ToLower()
            }
            $out = @($out | Select-Object -Unique)
            $cache[$Name] = $out
            return $out
        }

        # ---- policies: zone pair ones first, global ones after
        $ordered = @($sc.Policies.Values | Where-Object { -not $_.Global }) + @($sc.Policies.Values | Where-Object { $_.Global })
        foreach ($p in $ordered) {
            # Junos won't commit a policy with no action or no match, so this
            # is a partial export. As a deny-everything rule it would shadow
            # everything after it, so skip it.
            $hasMatch = ($p.Src.Count + $p.Dst.Count + $p.Apps.Count + $p.DynApps.Count) -gt 0
            if (-not $p.Action -or -not $hasMatch) {
                $what = if (-not $p.Action) { 'no then action (permit/deny/reject)' } else { 'no match condition' }
                Add-NormDiagnostic $model 'warn' $p.Name "policy has $what, which Junos would not commit; skipped"
                continue
            }
            $r = New-NormRule
            $r.Id = if ($p.Global) { "global/$($p.Name)" } else { "$($p.From[0])>$($p.To[0])/$($p.Name)" }
            $r.Name = $p.Name
            $r.LocalName = $p.Name
            $r.Scope = $scopeName
            $r.Enabled = -not $p.Inactive
            $r.SrcZones = $(if ($p.From.Count -eq 0 -or $p.From -contains 'any') { @('any') } else { @($p.From | ForEach-Object { & $zoneName $scopeName $_ }) })
            $r.DstZones = $(if ($p.To.Count -eq 0 -or $p.To -contains 'any') { @('any') } else { @($p.To | ForEach-Object { & $zoneName $scopeName $_ }) })
            # Global policies only see the global address book.
            $srcView = if ($p.Global) { @() } else { @($p.From) }
            $dstView = if ($p.Global) { @() } else { @($p.To) }
            $mapAddr = {
                param([string[]]$Names, [string[]]$Zones)
                foreach ($n in $Names) {
                    if (-not $conflict.Contains($n)) { $n; continue }
                    $bn = & $findBook $sc $Zones $n
                    if ($bn) { & $qualify $scopeName $bn $n } else { $n }
                }
            }
            # any / any-ipv4 make the side any. any-ipv6 next to IPv4 addresses
            # must not widen them (same as all6 on FortiGate): it stays as an
            # opaque token. any-ipv6 alone is read as any, as FortiGate does.
            $sideAddrs = {
                param([string[]]$Names, [string[]]$Zones, [string]$Label)
                $Names = @($Names | Where-Object { $_ })
                if (@($Names | Where-Object { $_ -in @('any', 'any-ipv4') }).Count -gt 0) { return }
                if (@($Names | Where-Object { $_ -ne 'any-ipv6' }).Count -eq 0) { return }
                if ($Names -contains 'any-ipv6') {
                    Add-NormDiagnostic $model 'lossy' $p.Name "IPv6 $Label is unrestricted (any-ipv6); kept as an opaque any-ipv6 token next to the IPv4 addresses"
                }
                & $mapAddr $Names $Zones
            }
            $r.SrcAddrs = @(& $sideAddrs @($p.Src) $srcView 'source')
            $r.DstAddrs = @(& $sideAddrs @($p.Dst) $dstView 'destination')
            $r.SrcNegate = $p.SrcEx -and $r.SrcAddrs.Count -gt 0
            $r.DstNegate = $p.DstEx -and $r.DstAddrs.Count -gt 0
            # Excluding "any" leaves nothing to match: a dead policy, like a
            # negated "all" on FortiGate.
            foreach ($side in @(@{ Ex = $p.SrcEx; Count = $r.SrcAddrs.Count; Label = 'source' }, @{ Ex = $p.DstEx; Count = $r.DstAddrs.Count; Label = 'destination' })) {
                if ($side.Ex -and $side.Count -eq 0) {
                    $r.Enabled = $false
                    Add-NormDiagnostic $model 'warn' $p.Name "$($side.Label)-address-excluded with $($side.Label) any: the policy can never match (dead rule); exported as disabled"
                }
            }
            $r.Action = $(if ($p.Action) { $p.Action } else { 'deny' })

            # dynamic applications (AppSecure)
            $dyn = @($p.DynApps | Where-Object { $_ -and $_ -notin @('any', 'none') })
            $apps = @(); $groups = @()
            foreach ($d in $dyn) {
                # Groups are junos:a:b, or lowercase (junos:p2p). Signatures
                # are uppercase (junos:HTTP). Case is all we have to go on.
                $isGroup = (($d -split ':').Count -gt 2) -or ($d -cmatch '^junos:[a-z0-9-]*[a-z][a-z0-9-]*$')
                if ($isGroup) { $groups += $d; $apps += 'junosapp-group-' + (($d -replace '^(?i)junos:', '') -replace '[:\._]+', '-').ToLower() }
                else { $apps += ConvertTo-JunosCanonicalApp -DynamicApp $d -UserMap $userAppMap }
            }
            $r.Applications = @($apps | Select-Object -Unique)
            if ($groups.Count -gt 0) { Add-NormDiagnostic $model 'lossy' $p.Name "dynamic application group(s) $($groups -join ', ') kept as junosapp-group-<name>; MooseAlto cannot expand a group" }

            # port applications
            $tokens = @()
            $appNames = @($p.Apps | Where-Object { $_ })
            if ($appNames -contains 'junos-defaults') {
                if ($r.Applications.Count -gt 0) { $tokens = @('application-default') }
                $appNames = @($appNames | Where-Object { $_ -ne 'junos-defaults' })
            }
            if ($appNames.Count -gt 0 -and $appNames -notcontains 'any') {
                foreach ($a in $appNames) { $tokens += & $resolveApp $a (New-Object System.Collections.Generic.HashSet[string]) }
            }
            $tokens = @($tokens | Select-Object -Unique)
            $r.Services = $(if ($tokens -contains 'application-default') { @('application-default') } elseif (Test-NormServiceIsAny $tokens) { @() } else { $tokens })
            if (@($r.Services | Where-Object { $_ -match '^(tcp|udp|sctp)-\d+-\d+$' }).Count -gt 0) {
                Add-NormDiagnostic $model 'lossy' $p.Name "port range(s) $(($r.Services | Where-Object { $_ -match '^(tcp|udp|sctp)-\d+-\d+$' }) -join ', ') larger than $($script:ExpandRangeLimit) ports; MooseAlto port checks do not look inside ranges"
            }

            $r.Profile = $(if ($p.Services.Count -gt 0) { ($p.Services | Select-Object -Unique) -join ';' } else { 'none' })
            $logParts = @()
            if ($p.Log -contains 'session-init') { $logParts += 'Log at Session Start' }
            if ($p.Log -contains 'session-close') { $logParts += 'Log at Session End' }
            $r.Log = ($logParts -join '; ')
            $r.Comment = $p.Descr
            $r.Tags = $p.Descr

            if ($p.Identity) { Add-NormDiagnostic $model 'lossy' $p.Name "restricted to users (source-identity / end user profile); MooseAlto has no identity dimension, rule may look broader than it is" }
            if ($p.UrlCat) { Add-NormDiagnostic $model 'lossy' $p.Name "url-category restricts destinations by web category; not represented" }
            if ($p.Sched) { Add-NormDiagnostic $model 'info' $p.Name "scheduler '$($p.Sched)' (rule is time limited)" }

            if ($hits.Count -gt 0) {
                $fromKey = if ($p.Global) { '*' } else { $p.From[0] }
                $toKey = if ($p.Global) { '*' } else { $p.To[0] }
                $hk = "$scopeName|$fromKey|$toKey|$($p.Name)"
                # Global policies are printed as "Any Any"; try that before
                # the name-only fallback.
                if ($p.Global -and $hits.ContainsKey("$scopeName|Any|Any|$($p.Name)")) { $hk = "$scopeName|Any|Any|$($p.Name)" }
                if (-not $hits.ContainsKey($hk)) { $hk = "$scopeName|*|*|$($p.Name)" }
                if ($hits.ContainsKey($hk) -and $hits[$hk] -ge 0) { $r.HitCount = "$($hits[$hk])" }
            }
            $model.Rules.Add($r)
        }

        if ($sc.DefaultPermitAll) {
            $r = New-NormRule
            $r.Id = 'default-policy'; $r.Name = 'default-policy (permit-all)'; $r.Scope = $scopeName
            $r.Action = 'allow'; $r.Log = ''
            $model.Rules.Add($r)
            foreach ($z in $sc.Zones.Keys) { $model.IntrazoneAllowZones.Add((& $zoneName $scopeName $z).ToLower()) }
            Add-NormDiagnostic $model 'warn' 'default-policy (permit-all)' "security policies default-policy is permit-all: every flow not matched by a policy is allowed. Added as an explicit trailing allow any rule so the checks see it"
        }
        foreach ($z in $sc.Zones.Keys) {
            $zq = & $zoneName $scopeName $z
            if (-not $model.ZoneHints.Contains($zq)) { $model.ZoneHints[$zq] = 'internal' }
        }
    }

    # ---- make names unique (Junos allows the same name in two zone pairs)
    $counts = @{}
    foreach ($r in $model.Rules) { $k = "$($r.Scope)|$($r.Name)"; $counts[$k] = 1 + $(if ($counts.ContainsKey($k)) { $counts[$k] } else { 0 }) }
    foreach ($r in $model.Rules) {
        if ($counts["$($r.Scope)|$($r.Name)"] -gt 1 -and $r.Id -ne 'default-policy') { $r.Name = $r.Id }
        if ($multiScope) { $r.Name = "$($r.Scope)/$($r.Name)" }
    }

    if ($model.Rules.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no security policy found in the input' }
    if ($HitCountFile -and $hits.Count -eq 0) {
        Add-NormDiagnostic $model 'error' '' "hit counter file has no line in the 'show security policies hit-count' layout (Index, From zone, To zone, Name, Policy count); nothing applied"
    }
    elseif ($HitCountFile -and @($model.Rules | Where-Object { $_.HitCount -ne '' }).Count -eq 0) {
        Add-NormDiagnostic $model 'error' '' "hit counter file matched no policy: check that it comes from the same device and logical system"
    }
    if (-not $HitCountFile) { Add-NormDiagnostic $model 'info' '' 'no hit counter file supplied: Hit Count left blank (usage checks will not run)' }
    return $model
}
