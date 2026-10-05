# --------------------------------------------------------------------------
# FortiOS -> normalized model
# --------------------------------------------------------------------------
#
# Config backup (single or multi VDOM) plus, optionally, the monitor API
# JSON with hit counters. The full field mapping is in the README; whatever
# gets lost on a rule ends up in the normalization notes.
# The non-obvious bits: interfaces are used as zone names, and a VIP becomes
# its mapped (internal) address, since that's the host really exposed.

. (Join-Path $PSScriptRoot 'FortiOSConfig.ps1')
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'FortiOSApps.ps1')

# FortiOS default services, for configs that don't spell them out. When the
# config defines them under "service custom", that wins.
$script:FgtPredefinedServices = @{
    'ALL'          = @('ip-proto-0')
    'ALL_TCP'      = @('tcp-1-65535')
    'ALL_UDP'      = @('udp-1-65535')
    'ALL_ICMP'     = @('icmp')
    'ALL_ICMP6'    = @('icmp6')
    'PING'         = @('icmp-8')
    'TRACEROUTE'   = @('udp-33434-33535')
    'HTTP'         = @('tcp-80')
    'HTTPS'        = @('tcp-443')
    'SSH'          = @('tcp-22')
    'TELNET'       = @('tcp-23')
    'FTP'          = @('tcp-21')
    'FTP_GET'      = @('tcp-21')
    'FTP_PUT'      = @('tcp-21')
    'TFTP'         = @('udp-69')
    'SMTP'         = @('tcp-25')
    'SMTPS'        = @('tcp-465')
    'POP3'         = @('tcp-110')
    'POP3S'        = @('tcp-995')
    'IMAP'         = @('tcp-143')
    'IMAPS'        = @('tcp-993')
    'DNS'          = @('tcp-53', 'udp-53')
    'NTP'          = @('tcp-123', 'udp-123')
    'SNMP'         = @('tcp-161', 'tcp-162', 'udp-161', 'udp-162')
    'SYSLOG'       = @('udp-514')
    'LDAP'         = @('tcp-389')
    'LDAP_UDP'     = @('udp-389')
    'KERBEROS'     = @('tcp-88', 'tcp-464', 'udp-88', 'udp-464')
    'RDP'          = @('tcp-3389')
    'VNC'          = @('tcp-5900')
    'SAMBA'        = @('tcp-139')
    'SMB'          = @('tcp-445')
    'MS-SQL'       = @('tcp-1433', 'tcp-1434')
    'MYSQL'        = @('tcp-3306')
    'IKE'          = @('udp-500', 'udp-4500')
    'PPTP'         = @('tcp-1723')
    'L2TP'         = @('tcp-1701', 'udp-1701')
    'RADIUS'       = @('udp-1812', 'udp-1813')
    'DHCP'         = @('udp-67', 'udp-68')
    'BGP'          = @('tcp-179')
    'NFS'          = @('tcp-111', 'tcp-2049', 'udp-111', 'udp-2049')
    'SIP'          = @('tcp-5060', 'udp-5060')
    'X-WINDOWS'    = @('tcp-6000-6063')
    'GRE'          = @('ip-proto-47')
    'ESP'          = @('ip-proto-50')
    'AH'           = @('ip-proto-51')
    # 7.x defaults (Fortinet tech tip on default services)
    'REXEC'        = @('tcp-512')
    'RLOGIN'       = @('tcp-513')
    'RSH'          = @('tcp-514')
    'DCE-RPC'      = @('tcp-135', 'udp-135')
    'ONC-RPC'      = @('tcp-111', 'udp-111')
    'AFS3'         = @('tcp-7000-7009', 'udp-7000-7009')
    'DHCP6'        = @('udp-546', 'udp-547')
    'OSPF'         = @('ip-proto-89')
    'RIP'          = @('udp-520')
    'PC-Anywhere'  = @('tcp-5631', 'udp-5632')
    'WINS'         = @('tcp-1512', 'udp-1512')
    'SOCKS'        = @('tcp-1080', 'udp-1080')
    'SQUID'        = @('tcp-3128')
    'H323'         = @('tcp-1720', 'tcp-1503', 'udp-1719')
    'IRC'          = @('tcp-6660-6669')
    'RTSP'         = @('tcp-554', 'tcp-7070', 'tcp-8554', 'udp-554')
    'SCCP'         = @('tcp-2000')
    'SIP-MSNMESSENGER' = @('tcp-1863')
    'NNTP'         = @('tcp-119')
    'FINGER'       = @('tcp-79')
    'GOPHER'       = @('tcp-70')
    'WAIS'         = @('tcp-210')
    'WINFRAME'     = @('tcp-1494', 'tcp-2598')
    'UUCP'         = @('tcp-540')
    'TALK'         = @('udp-517', 'udp-518')
    'AOL'          = @('tcp-5190', 'tcp-5191', 'tcp-5192', 'tcp-5193', 'tcp-5194')
    'CVSPSERVER'   = @('tcp-2401', 'udp-2401')
    'MGCP'         = @('udp-2427', 'udp-2727')
    'RADIUS-OLD'   = @('udp-1645', 'udp-1646')
    'INTERNET-LOCATOR-SERVICE' = @('tcp-389')
    'PING6'        = @('icmp6-128')
    'TIMESTAMP'    = @('icmp-13')
    'INFO_REQUEST' = @('icmp-15')
    'INFO_ADDRESS' = @('icmp-17')
}

$script:FgtPredefinedServiceGroups = @{
    'Web Access'     = @('DNS', 'HTTP', 'HTTPS')
    'Email Access'   = @('DNS', 'IMAP', 'IMAPS', 'POP3', 'POP3S', 'SMTP', 'SMTPS')
    'Windows AD'     = @('DCE-RPC', 'DNS', 'KERBEROS', 'LDAP', 'LDAP_UDP', 'SAMBA', 'SMB')
}

function ConvertFrom-FgtMask {
    # "10.0.0.0 255.255.255.0" or "10.0.0.0/24" -> "10.0.0.0/24"
    param([string[]]$Parts)
    if ($null -eq $Parts -or $Parts.Count -eq 0) { return '0.0.0.0/0' }   # FortiOS default subnet
    if ($Parts.Count -eq 1 -and $Parts[0] -match '/') { return $Parts[0] }
    if ($Parts.Count -lt 2) { return "$($Parts[0])/32" }
    $bits = 0
    foreach ($octet in ($Parts[1] -split '\.')) {
        $b = [Convert]::ToString([int]$octet, 2)
        $bits += ($b.ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }
    return "$($Parts[0])/$bits"
}

function Get-FgtPortRanges {
    # "80 443:1024-65535 8080-8090" -> @{Low;High} list. Destination ports
    # only; the ":source" part is dropped.
    param([string[]]$Values)
    $out = @()
    foreach ($v in $Values) {
        $dst = ($v -split ':')[0]
        if ($dst -match '^(\d+)-(\d+)$') { $out += @{ Low = [int]$Matches[1]; High = [int]$Matches[2] } }
        elseif ($dst -match '^\d+$') { $out += @{ Low = [int]$dst; High = [int]$dst } }
    }
    return $out
}

function Resolve-FgtService {
    param($Ctx, [string]$Name, [System.Collections.Generic.HashSet[string]]$Visited)
    if ($Ctx.ServiceCache.ContainsKey($Name)) { return $Ctx.ServiceCache[$Name] }
    if ($null -eq $Visited) { $Visited = New-Object System.Collections.Generic.HashSet[string] }
    if (-not $Visited.Add($Name)) { return @() }

    $tokens = @()
    $found = $false
    if ($null -ne $Ctx.SvcGroups -and $Ctx.SvcGroups.Entries.Contains($Name)) {
        $found = $true
        foreach ($m in (Get-FgtList $Ctx.SvcGroups.Entries[$Name] 'member')) {
            $tokens += Resolve-FgtService -Ctx $Ctx -Name $m -Visited $Visited
        }
    }
    elseif ($null -ne $Ctx.SvcCustom -and $Ctx.SvcCustom.Entries.Contains($Name)) {
        $found = $true
        $e = $Ctx.SvcCustom.Entries[$Name]
        $proto = (Get-FgtValue $e 'protocol' 'TCP/UDP/SCTP').ToUpper()
        switch -Regex ($proto) {
            '^ICMP6?$' {
                $t = Get-FgtValue $e 'icmptype'
                $base = $proto.ToLower()
                $tokens += $(if ($null -ne $t -and $t -ne '') { "$base-$t" } else { $base })
            }
            '^IP$' {
                $tokens += "ip-proto-$(Get-FgtValue $e 'protocol-number' '0')"
            }
            '^ALL$' { $tokens += 'ip-proto-0' }
            default {
                foreach ($pair in @(@('tcp', 'tcp-portrange'), @('udp', 'udp-portrange'), @('sctp', 'sctp-portrange'), @('udp', 'udplite-portrange'))) {
                    foreach ($r in (Get-FgtPortRanges (Get-FgtList $e $pair[1]))) {
                        $tokens += ConvertTo-PortTokens -Proto $pair[0] -Low $r.Low -High $r.High
                    }
                }
                if ($tokens.Count -eq 0) {
                    Add-NormDiagnostic $Ctx.Model 'warn' '' "service '$Name' has no port range (fqdn/iprange/proxy service?), treated as any"
                    $tokens += 'ip-proto-0'
                }
            }
        }
        # Keep the name of remote access tools ("AnyDesk-Support") as an
        # extra token. Only for those: on every service it would make equal
        # services with different names look different to the shadow checks.
        $hint = Get-NormAppHintToken $Name
        if ($hint) { $tokens += $hint }
    }
    elseif ($script:FgtPredefinedServiceGroups.ContainsKey($Name)) {
        $found = $true
        foreach ($m in $script:FgtPredefinedServiceGroups[$Name]) { $tokens += Resolve-FgtService -Ctx $Ctx -Name $m -Visited $Visited }
    }
    elseif ($script:FgtPredefinedServices.ContainsKey($Name.ToUpper())) {
        $found = $true
        $tokens += $script:FgtPredefinedServices[$Name.ToUpper()]
    }
    if (-not $found) {
        Add-NormDiagnostic $Ctx.Model 'warn' '' "service '$Name' is not defined in the config and is not a known predefined service; kept as opaque token"
        $tokens += $Name.ToLower()
    }
    $tokens = @($tokens | Select-Object -Unique)
    $Ctx.ServiceCache[$Name] = $tokens
    return $tokens
}

function Import-FgtAddresses {
    # With several VDOMs, names get a "<vdom>/" prefix: the same name can be
    # a different host in another VDOM.
    param($Ctx, $Vdom)
    $m = $Ctx.Model
    $p = $Ctx.Prefix
    foreach ($tblName in @('firewall address', 'firewall address6')) {
        $tbl = Get-FgtTable $Vdom $tblName
        if ($null -eq $tbl) { continue }
        $v6 = $tblName -eq 'firewall address6'
        foreach ($e in $tbl.Entries.Values) {
            $name = "$p$($e.Name)"
            # "all" and "none" exist in both tables; keep the IPv4 one.
            if ($v6 -and $m.Objects.ContainsKey($name.ToLower())) { continue }
            $type = (Get-FgtValue $e 'type' 'ipmask').ToLower()
            switch ($type) {
                { $_ -in @('ipmask', 'interface-subnet', 'ipprefix') } {
                    if ($v6) {
                        # Own type, so the IPv4 math leaves it alone.
                        Add-NormObject $m $name 'ip6-netmask' (Get-FgtValue $e 'ip6' '::/0')
                        break
                    }
                    $hasSubnet = @(Get-FgtList $e 'subnet').Count -gt 0
                    $sub = ConvertFrom-FgtMask (Get-FgtList $e 'subnet')
                    if ($type -eq 'interface-subnet' -and -not $hasSubnet) {
                        # No subnet line: take it from the interface, never any.
                        $ifName = Get-FgtValue $e 'interface' ''
                        $sub = ''
                        foreach ($holder in @($Ctx.Root, (Get-FgtTable $Ctx.Root 'global'))) {
                            $ifTbl = Get-FgtTable $holder 'system interface'
                            if ($null -ne $ifTbl -and $ifName -and $ifTbl.Entries.Contains($ifName)) {
                                $sub = ConvertFrom-FgtMask (Get-FgtList $ifTbl.Entries[$ifName] 'ip')
                                if ($sub -eq '/32') { $sub = '' }
                            }
                        }
                        if (-not $sub) {
                            Add-NormObject $m $name 'interface-subnet' $ifName
                            Add-NormDiagnostic $m 'lossy' '' "address '$name' is the subnet of interface '$ifName', whose address is not in the configuration; left unresolved"
                            break
                        }
                    }
                    if ($sub -eq '/32' -or $sub -eq '') { $sub = '0.0.0.0/0' }
                    Add-NormObject $m $name 'ip-netmask' $sub
                }
                'iprange' { Add-NormObject $m $name $(if ($v6) { 'ip6-range' } else { 'ip-range' }) "$(Get-FgtValue $e 'start-ip')-$(Get-FgtValue $e 'end-ip')" }
                { $_ -in @('fqdn', 'wildcard-fqdn') } { Add-NormObject $m $name 'fqdn' (Get-FgtValue $e 'fqdn' (Get-FgtValue $e 'wildcard-fqdn' '')) }
                'geography' { Add-NormObject $m $name 'geo' (Get-FgtValue $e 'country' '') }
                'wildcard' { Add-NormObject $m $name 'ip-wildcard' ((Get-FgtList $e 'wildcard') -join ' ') }
                default {
                    Add-NormObject $m $name $type ''
                    Add-NormDiagnostic $m 'lossy' '' "address '$name' has type '$type' (dynamic/SDN/MAC), left unresolved"
                }
            }
        }
    }
    foreach ($tblName in @('firewall addrgrp', 'firewall addrgrp6')) {
        $tbl = Get-FgtTable $Vdom $tblName
        if ($null -eq $tbl) { continue }
        foreach ($e in $tbl.Entries.Values) {
            Add-NormGroup $m "$p$($e.Name)" @(Get-FgtList $e 'member' | ForEach-Object { "$p$_" })
            if ((Get-FgtValue $e 'exclude' 'disable') -eq 'enable') {
                Add-NormDiagnostic $m 'lossy' '' "address group '$p$($e.Name)' uses exclude-member ($((Get-FgtList $e 'exclude-member') -join ', ')); exclusion is ignored, so the group is treated as WIDER than it really is"
            }
        }
    }
    # VIPs: what's exposed is the mapped address.
    $tbl = Get-FgtTable $Vdom 'firewall vip'
    if ($null -ne $tbl) {
        foreach ($e in $tbl.Entries.Values) {
            $name = "$p$($e.Name)"
            $mapped = @(Get-FgtList $e 'mappedip')
            $ext = Get-FgtValue $e 'extip' ''
            if ($mapped.Count -eq 0) {
                # Load balancing VIPs list their hosts under realservers.
                $rs = Get-FgtTable $e 'realservers'
                if ($null -ne $rs) { $mapped = @($rs.Entries.Values | ForEach-Object { Get-FgtValue $_ 'ip' '' } | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -Unique) }
            }
            if ($mapped.Count -eq 0) {
                # Still nothing (fqdn VIP, access proxy). Don't leave an
                # empty group behind: that would read as any.
                $ma = Get-FgtValue $e 'mapped-addr' ''
                if ($ma) {
                    Add-NormGroup $m $name @("$p$ma")
                    Add-NormDiagnostic $m 'info' '' "VIP '$name': external $ext -> mapped address object '$ma' (policies are evaluated against the mapped address)"
                }
                else {
                    Add-NormObject $m $name 'vip-unresolved' ''
                    Add-NormDiagnostic $m 'lossy' '' "VIP '$name' (type $(Get-FgtValue $e 'type' 'static-nat')) has no mapped address in the configuration; kept as an opaque object"
                }
                continue
            }
            if ($mapped.Count -eq 1) {
                $val = $mapped[0]
                if ($val -match '^(\S+)-(\S+)$' -and $Matches[1] -eq $Matches[2]) { $val = $Matches[1] }
                if ($val -notmatch '[-/]') { $val = "$val/32" }
                $type = if ($val -match '-') { 'ip-range' } else { 'ip-netmask' }
                Add-NormObject $m $name $type $val
            }
            else {
                $names = @()
                $i = 0
                foreach ($mv in $mapped) {
                    $i++; $n = "$name#$i"; $names += $n
                    $v = if ($mv -notmatch '[-/]') { "$mv/32" } else { $mv }
                    Add-NormObject $m $n $(if ($v -match '-') { 'ip-range' } else { 'ip-netmask' }) $v
                }
                Add-NormGroup $m $name $names
            }
            $pf = if ((Get-FgtValue $e 'portforward' 'disable') -eq 'enable') { " port $(Get-FgtValue $e 'extport') -> $(Get-FgtValue $e 'mappedport')" } else { '' }
            Add-NormDiagnostic $m 'info' '' "VIP '$name': external $ext -> mapped $($mapped -join ',')$pf (policies are evaluated against the mapped address)"
        }
    }
    $tbl = Get-FgtTable $Vdom 'firewall vipgrp'
    if ($null -ne $tbl) { foreach ($e in $tbl.Entries.Values) { Add-NormGroup $m "$p$($e.Name)" @(Get-FgtList $e 'member' | ForEach-Object { "$p$_" }) } }
}

function Get-FgtZoneNames {
    # Zone names defined in one VDOM: system zones and SD-WAN zones.
    param($Vdom)
    $names = @()
    $zTbl = Get-FgtTable $Vdom 'system zone'
    if ($null -ne $zTbl) { $names += @($zTbl.Entries.Keys) }
    foreach ($sdName in @('system sdwan', 'system virtual-wan-link')) {
        $sd = Get-FgtTable $Vdom $sdName
        if ($null -eq $sd) { continue }
        $names += 'virtual-wan-link'
        $sdz = Get-FgtTable $sd 'zone'
        if ($null -ne $sdz) { $names += @($sdz.Entries.Keys) }
    }
    return @($names | Select-Object -Unique)
}

function Get-FgtZoneName {
    # A zone name used in more than one VDOM becomes "<vdom>/<zone>" so the
    # hints don't overwrite each other. Others stay as they are, so
    # -InternetZones and -CriticalZones match what the FortiGate shows.
    param($Ctx, [string]$Name)
    if ($null -ne $Ctx.QualifiedZones -and $Ctx.QualifiedZones.Contains($Name)) { return "$($Ctx.Vdom)/$Name" }
    return $Name
}

function Import-FgtZoneHints {
    # Internet facing: role wan interfaces, zones holding one, SD-WAN zones.
    param($Ctx, $Root, $Vdom)
    $wanIfs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($holder in @($Root, (Get-FgtTable $Root 'global'), $Vdom)) {
        $ifTbl = Get-FgtTable $holder 'system interface'
        if ($null -eq $ifTbl) { continue }
        foreach ($e in $ifTbl.Entries.Values) {
            # Only count interfaces of this VDOM.
            $ifVdom = Get-FgtValue $e 'vdom' ''
            if ($ifVdom -and $Ctx.Prefix -and $ifVdom -ne $Ctx.Vdom) { continue }
            if ((Get-FgtValue $e 'role' '') -eq 'wan') { [void]$wanIfs.Add($e.Name) }
        }
    }
    $zTbl = Get-FgtTable $Vdom 'system zone'
    $zoneMembers = New-Object System.Collections.Generic.HashSet[string]
    if ($null -ne $zTbl) { foreach ($z in $zTbl.Entries.Values) { foreach ($i in (Get-FgtList $z 'interface')) { [void]$zoneMembers.Add($i) } } }
    # Zone members never show up in a policy, so only hint standalone ones.
    foreach ($ifName in $wanIfs) { if (-not $zoneMembers.Contains($ifName)) { $Ctx.Model.ZoneHints[$ifName] = 'internet' } }
    if ($null -ne $zTbl) {
        foreach ($z in $zTbl.Entries.Values) {
            $zn = Get-FgtZoneName $Ctx $z.Name
            if ((Get-FgtValue $z 'intrazone' 'deny') -eq 'allow') { $Ctx.Model.IntrazoneAllowZones.Add($zn.ToLower()) }
            $members = Get-FgtList $z 'interface'
            $isWan = @($members | Where-Object { $wanIfs.Contains($_) }).Count -gt 0
            $Ctx.Model.ZoneHints[$zn] = $(if ($isWan) { 'internet' } else { 'internal' })
        }
    }
    foreach ($sdName in @('system sdwan', 'system virtual-wan-link')) {
        $sd = Get-FgtTable $Vdom $sdName
        if ($null -eq $sd) { continue }
        $Ctx.Model.ZoneHints[(Get-FgtZoneName $Ctx 'virtual-wan-link')] = 'internet'
        $sdz = Get-FgtTable $sd 'zone'
        if ($null -ne $sdz) { foreach ($z in $sdz.Entries.Keys) { $Ctx.Model.ZoneHints[(Get-FgtZoneName $Ctx $z)] = 'internet' } }
    }
}

function Read-FgtUsage {
    # Monitor API JSON: one response, an array of them (one per VDOM), or
    # just the results array.
    param([string]$Path)
    $map = @{}
    if (-not $Path) { return $map }
    try { $json = Get-Content -Path $Path -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { $map['__error'] = "hit counter file is not valid JSON (expected the FortiGate monitor API response): $($_.Exception.Message)"; return $map }
    $responses = @()
    if ($json -is [array]) {
        if ($json.Count -gt 0 -and $null -ne $json[0].results) { $responses = $json }
        else { $responses = @([PSCustomObject]@{ vdom = 'root'; results = $json }) }
    }
    # PS 7 unrolls a one-element array, so a single policy arrives bare.
    elseif ($null -eq $json.results -and $null -ne $json.policyid) { $responses = @([PSCustomObject]@{ vdom = 'root'; results = @($json) }) }
    else { $responses = @($json) }
    foreach ($resp in $responses) {
        $vd = if ($resp.vdom) { $resp.vdom } else { 'root' }
        # "name" is the endpoint (policy, security-policy, policy6).
        $tbl = if ($resp.name) { $resp.name } else { 'policy' }
        foreach ($p in @($resp.results)) {
            if ($null -eq $p -or $null -eq $p.policyid) { continue }
            $map["$vd|$tbl|$($p.policyid)"] = $p
        }
    }
    return $map
}

function ConvertFrom-FgtEpoch {
    param($Epoch)
    if ($null -eq $Epoch -or [int64]$Epoch -le 0) { return '-' }
    return ([DateTimeOffset]::FromUnixTimeSeconds([int64]$Epoch)).UtcDateTime.ToString('yyyy-MM-dd')
}

function Get-FgtProfileParts {
    # "av:<name>", "app:<name>"... The checks read "app:" as app control.
    param($Entry)
    $parts = @()
    $map = [ordered]@{
        'av-profile' = 'av'; 'ips-sensor' = 'ips'; 'webfilter-profile' = 'web'; 'application-list' = 'app'
        'dnsfilter-profile' = 'dns'; 'file-filter-profile' = 'file'; 'emailfilter-profile' = 'email'
        'dlp-sensor' = 'dlp'; 'dlp-profile' = 'dlp'; 'waf-profile' = 'waf'; 'voip-profile' = 'voip'
        'icap-profile' = 'icap'; 'videofilter-profile' = 'video'; 'casb-profile' = 'casb'
    }
    foreach ($k in $map.Keys) {
        $v = Get-FgtValue $Entry $k ''
        if ($v) { $parts += "$($map[$k]):$v" }
    }
    return $parts
}

function Get-FgtProfileSummary {
    # "none", the group name plus its profiles (so app control inside a
    # group still shows), or the single profiles.
    param($Entry, $ProfileGroups)
    if ((Get-FgtValue $Entry 'utm-status' '') -eq 'disable') { return 'none' }
    if ((Get-FgtValue $Entry 'profile-type' 'single') -eq 'group') {
        $g = Get-FgtValue $Entry 'profile-group' ''
        if ($g) {
            if ($null -ne $ProfileGroups -and $ProfileGroups.Entries.Contains($g)) {
                $gp = @(Get-FgtProfileParts $ProfileGroups.Entries[$g])
                if ($gp.Count -gt 0) { return (@($g) + $gp) -join ';' }
            }
            return $g
        }
    }
    $parts = @(Get-FgtProfileParts $Entry)
    if ($parts.Count -eq 0) { return 'none' }
    return ($parts -join ';')
}

function Get-FgtAddrSide {
    # One side of a policy. IPv4 and IPv6 lists are separate, each with its
    # own negate flag (in policy6, srcaddr is the IPv6 one).
    # "all" = any, negated "all" = nothing; only "none" = nothing, negated = any.
    # Dead = the side can never match. Empty Addrs = any.
    param($Entry, [string]$Side, [bool]$Policy6)
    $sideName = if ($Side -eq 'src') { 'source' } else { 'destination' }
    if ($Policy6) {
        $fams = @(@{ Label = 'IPv6'; Names = @(Get-FgtList $Entry "${Side}addr") + @(Get-FgtList $Entry "${Side}addr6"); Neg = (Get-FgtValue $Entry "${Side}addr-negate" 'disable') -eq 'enable' })
        $v4 = $null; $v6 = $fams[0]
    }
    else {
        $v4 = @{ Label = 'IPv4'; Names = @(Get-FgtList $Entry "${Side}addr") + @(Get-FgtList $Entry "${Side}addr4"); Neg = (Get-FgtValue $Entry "${Side}addr-negate" 'disable') -eq 'enable' }
        $v6 = @{ Label = 'IPv6'; Names = @(Get-FgtList $Entry "${Side}addr6"); Neg = (Get-FgtValue $Entry "${Side}addr6-negate" 'disable') -eq 'enable' }
        $fams = @($v4, $v6)
    }
    $notes = @()
    foreach ($f in $fams) {
        $n = @($f.Names | Where-Object { $_ })
        $f.List = @()
        if ($n.Count -eq 0) { $f.State = 'absent'; continue }
        if (@($n | Where-Object { $_ -in @('all', 'all6') }).Count -gt 0) {
            $f.State = if ($f.Neg) { 'negall' } else { 'any' }
            continue
        }
        $real = @($n | Where-Object { $_ -ne 'none' })
        if ($real.Count -eq 0) { $f.State = if ($f.Neg) { 'any' } else { 'none' }; continue }
        $f.State = 'list'; $f.List = $real
    }
    $out = @{ Addrs = @(); Negate = $false; Dead = $false; DeadReason = ''; Notes = @() }
    $live = @($fams | Where-Object { $_.State -in @('any', 'list') })
    if ($live.Count -eq 0) {
        $present = @($fams | Where-Object { $_.State -ne 'absent' })
        if ($present.Count -eq 0) { return $out }   # no address set at all: any
        $out.Dead = $true
        if (@($present | Where-Object { $_.State -eq 'negall' }).Count -gt 0) {
            $out.DeadReason = "negated $sideName contains 'all': the rule can never match (dead rule); exported as disabled"
        }
        else {
            $out.DeadReason = "$sideName is only 'none' (matches no address): the rule can never match; exported as disabled"
            $out.Addrs = @('none')
        }
        return $out
    }
    foreach ($f in $fams) {
        if ($f.State -eq 'negall' -and $live.Count -gt 0) { $notes += "negated $($f.Label) $sideName contains 'all': $($f.Label) traffic never matches this rule" }
    }
    if ($null -ne $v4 -and $v4.State -in @('any', 'list')) {
        if ($v4.State -eq 'any') { $out.Notes = $notes; return $out }
        $out.Addrs = $v4.List; $out.Negate = $v4.Neg
        if ($v6.State -in @('any', 'list')) {
            if ($v6.Neg -ne $v4.Neg) {
                $notes += "IPv6 $sideName ($($v6.Names -join ', ')) has a different negation than the IPv4 $sideName; only the IPv4 part is exported"
            }
            elseif ($v6.State -eq 'any') {
                # all6 must not turn the IPv4 list into any.
                $out.Addrs = @($v4.List) + @('all6')
                $notes += "IPv6 $sideName is unrestricted (all6); kept as an opaque all6 token next to the IPv4 addresses"
            }
            else { $out.Addrs = @($v4.List) + @($v6.List) }
        }
    }
    else {
        if ($v6.State -eq 'list') { $out.Addrs = $v6.List; $out.Negate = $v6.Neg }
    }
    $out.Notes = $notes
    return $out
}

function Get-FgtIsdbTokens {
    # Internet Service references of one side ($Infix '', '-src', '6',
    # '6-src'). If none can be read we still return a token, never any.
    param($Entry, [string]$Infix)
    $tokens = @()
    foreach ($k in @('name', 'id', 'custom', 'fortiguard')) { $tokens += @(Get-FgtList $Entry "internet-service$Infix-$k" | ForEach-Object { "isdb:$_" }) }
    foreach ($k in @('group', 'custom-group')) { $tokens += @(Get-FgtList $Entry "internet-service$Infix-$k" | ForEach-Object { "isdb-group:$_" }) }
    if ($tokens.Count -eq 0) { $tokens = @('isdb:unresolved') }
    return @($tokens | Select-Object -Unique)
}

function ConvertFrom-FortiOS {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$UsageJson,
        [string[]]$Vdoms,
        [string]$AppMapCsv
    )
    $model = New-NormModel -Vendor 'fortios' -Source $Path
    $warn = New-Object System.Collections.Generic.List[string]
    $root = Read-FortiOSConfig -Path $Path -Warnings $warn
    foreach ($w in $warn) { Add-NormDiagnostic $model 'warn' '' $w }
    $usage = Read-FgtUsage -Path $UsageJson
    if ($usage.ContainsKey('__error')) { Add-NormDiagnostic $model 'error' '' $usage['__error']; $usage = @{} }
    $appMap = New-FgtAppResolver -Root $root -AppMapCsv $AppMapCsv

    $vdomRoots = @(Get-FgtVdomRoots -Root $root)
    if ($Vdoms) { $vdomRoots = @($vdomRoots | Where-Object { $Vdoms -contains $_.Vdom }) }
    $multi = $vdomRoots.Count -gt 1

    # Zone names defined in more than one VDOM (see Get-FgtZoneName).
    $qualifiedZones = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($multi) {
        $zoneSeen = @{}
        foreach ($vr in $vdomRoots) {
            foreach ($zn in (Get-FgtZoneNames $vr.Node)) {
                if ($zoneSeen.ContainsKey($zn)) { [void]$qualifiedZones.Add($zn) } else { $zoneSeen[$zn] = $true }
            }
        }
        if ($qualifiedZones.Count -gt 0) {
            Add-NormDiagnostic $model 'info' '' "zone name(s) $(@($qualifiedZones) -join ', ') exist in more than one VDOM; written as <vdom>/<zone> in rules and zone hints"
        }
    }

    foreach ($vr in $vdomRoots) {
        $vdom = $vr.Node
        $prefix = if ($multi) { "$($vr.Vdom)/" } else { '' }
        $ctx = @{
            Model          = $model
            Vdom           = $vr.Vdom
            Prefix         = $prefix
            QualifiedZones = $qualifiedZones
            SvcCustom      = Get-FgtTable $vdom 'firewall service custom'
            SvcGroups      = Get-FgtTable $vdom 'firewall service group'
            ServiceCache   = @{}
            AppGroups      = Get-FgtTable $vdom 'application group'
            AppMap         = $appMap
            Root           = $root
        }
        $profileGroups = Get-FgtTable $vdom 'firewall profile-group'
        $settings = Get-FgtTable $vdom 'system settings'
        $ngfwMode = if ($null -ne $settings) { Get-FgtValue $settings 'ngfw-mode' 'profile-based' } else { 'profile-based' }
        Import-FgtAddresses -Ctx $ctx -Vdom $vdom
        Import-FgtZoneHints -Ctx $ctx -Root $root -Vdom $vdom

        # In NGFW policy-based mode the rules live in security-policy;
        # "firewall policy" is only the SSL/auth pre-match there.
        $tables = @('firewall policy', 'firewall policy6', 'firewall security-policy')
        if ($ngfwMode -eq 'policy-based') {
            $pre = Get-FgtTable $vdom 'firewall policy'
            if ($null -ne $pre) {
                Add-NormDiagnostic $model 'info' '' "VDOM $($vr.Vdom): NGFW policy-based mode, $($pre.Entries.Count) SSL inspection & authentication policies not exported (the security policies are the rulebase)"
            }
            $tables = @('firewall security-policy')
        }
        foreach ($tblName in $tables) {
            $tbl = Get-FgtTable $vdom $tblName
            if ($null -eq $tbl) { continue }
            $usageTable = $tblName -replace '^firewall ', ''
            $isPolicy6 = $tblName -eq 'firewall policy6'
            foreach ($e in $tbl.Entries.Values) {
                $r = New-NormRule
                $r.Id = $e.Name
                $baseName = Get-FgtValue $e 'name' ''
                $r.LocalName = $baseName
                if (-not $baseName) { $baseName = "policy-$($e.Name)" }
                if ($isPolicy6) { $baseName = "$baseName (policy6)" }
                $r.Name = if ($multi) { "$($vr.Vdom)/$baseName" } else { $baseName }
                $r.Scope = $vr.Vdom
                $r.Enabled = (Get-FgtValue $e 'status' 'enable') -ne 'disable'

                $si = @(Get-FgtList $e 'srcintf' | ForEach-Object { Get-FgtZoneName $ctx $_ })
                $di = @(Get-FgtList $e 'dstintf' | ForEach-Object { Get-FgtZoneName $ctx $_ })
                $r.SrcZones = $(if ($si.Count -eq 0) { @('any') } else { $si })
                $r.DstZones = $(if ($di.Count -eq 0) { @('any') } else { $di })

                $srcSide = Get-FgtAddrSide -Entry $e -Side 'src' -Policy6 $isPolicy6
                $dstSide = Get-FgtAddrSide -Entry $e -Side 'dst' -Policy6 $isPolicy6
                $r.SrcAddrs = @($srcSide.Addrs | ForEach-Object { "$prefix$_" })
                $r.DstAddrs = @($dstSide.Addrs | ForEach-Object { "$prefix$_" })
                $r.SrcNegate = $srcSide.Negate
                $r.DstNegate = $dstSide.Negate
                $srcDead = $srcSide.Dead; $dstDead = $dstSide.Dead

                # Internet Service replaces the address list of its side.
                if ((Get-FgtValue $e 'internet-service' 'disable') -eq 'enable') {
                    $r.DstAddrs = @(Get-FgtIsdbTokens $e '')
                    $r.DstNegate = (Get-FgtValue $e 'internet-service-negate' 'disable') -eq 'enable'
                    $dstDead = $false
                    Add-NormDiagnostic $model 'lossy' $r.Name "destination is Internet Service DB ($($r.DstAddrs -join ', ')); kept as opaque isdb: tokens"
                }
                if ((Get-FgtValue $e 'internet-service-src' 'disable') -eq 'enable') {
                    $r.SrcAddrs = @(Get-FgtIsdbTokens $e '-src')
                    $r.SrcNegate = (Get-FgtValue $e 'internet-service-src-negate' 'disable') -eq 'enable'
                    $srcDead = $false
                    Add-NormDiagnostic $model 'lossy' $r.Name "source is Internet Service DB ($($r.SrcAddrs -join ', ')); kept as opaque isdb: tokens"
                }
                # IPv6 Internet Service is added to the side, unless it's any.
                foreach ($isd in @(@{ Key = 'internet-service6'; Infix = '6'; Dst = $true }, @{ Key = 'internet-service6-src'; Infix = '6-src'; Dst = $false })) {
                    if ((Get-FgtValue $e $isd.Key 'disable') -ne 'enable') { continue }
                    $t6 = @(Get-FgtIsdbTokens $e $isd.Infix)
                    if ($isd.Dst) {
                        if ($dstDead -or $r.DstAddrs.Count -gt 0) { $r.DstAddrs = @($(if ($dstDead) { @() } else { $r.DstAddrs })) + $t6; $dstDead = $false }
                    }
                    elseif ($srcDead -or $r.SrcAddrs.Count -gt 0) { $r.SrcAddrs = @($(if ($srcDead) { @() } else { $r.SrcAddrs })) + $t6; $srcDead = $false }
                    Add-NormDiagnostic $model 'lossy' $r.Name "IPv6 Internet Service DB ($($t6 -join ', ')) kept as opaque isdb: tokens"
                }
                foreach ($side in @($srcSide, $dstSide)) { foreach ($note in $side.Notes) { Add-NormDiagnostic $model 'lossy' $r.Name $note } }
                if ($srcDead -or $dstDead) {
                    $r.Enabled = $false
                    foreach ($side in @(@($srcDead, $srcSide), @($dstDead, $dstSide))) {
                        if ($side[0]) { Add-NormDiagnostic $model 'warn' $r.Name $side[1].DeadReason }
                    }
                }

                $act = (Get-FgtValue $e 'action' 'deny').ToLower()
                $r.Action = $(if ($act -in @('accept', 'ipsec')) { 'allow' } else { 'deny' })
                if ($act -eq 'ipsec') { Add-NormDiagnostic $model 'info' $r.Name "action ipsec (policy based VPN) mapped to allow" }

                $svcNames = @(Get-FgtList $e 'service')
                $tokens = @()
                foreach ($s in $svcNames) { $tokens += Resolve-FgtService -Ctx $ctx -Name $s }
                if ((Get-FgtValue $e 'service-negate' 'disable') -eq 'enable') {
                    Add-NormDiagnostic $model 'lossy' $r.Name "service-negate enabled (all except $($svcNames -join ', ')); exported as any"
                    $tokens = @('ip-proto-0')
                }
                $tokens = @($tokens | Select-Object -Unique)
                $r.Services = $(if (Test-NormServiceIsAny $tokens) { @() } else { $tokens })
                if (@($r.Services | Where-Object { $_ -match '^(tcp|udp|sctp)-\d+-\d+$' }).Count -gt 0) {
                    Add-NormDiagnostic $model 'lossy' $r.Name "port range(s) $(($r.Services | Where-Object { $_ -match '^(tcp|udp|sctp)-\d+-\d+$' }) -join ', ') larger than $($script:ExpandRangeLimit) ports; MooseAlto port checks do not look inside ranges"
                }

                # Applications set on the policy itself (NGFW mode).
                $appInfo = Resolve-FgtApplications -Ctx $ctx -Entry $e
                $appTokens = @($appInfo.Apps) + @($appInfo.Categories | ForEach-Object { ConvertTo-FgtCategoryToken $_ })
                if ($appTokens.Count -gt 0) {
                    $r.Applications = $appTokens
                    if ($appInfo.Unknown.Count -gt 0) {
                        Add-NormDiagnostic $model 'lossy' $r.Name "application ID(s) $($appInfo.Unknown -join ', ') not in the ID map; kept as fortiapp-<id> (add them with -AppMapCsv)"
                    }
                    if ($appInfo.Categories.Count -gt 0) {
                        Add-NormDiagnostic $model 'lossy' $r.Name "application categories/groups $($appInfo.Categories -join ', ') kept as fortiapp-category-<name>; MooseAlto cannot expand a category"
                    }
                    # Default app ports and no service = application-default.
                    if ($r.Services.Count -eq 0 -and $tblName -eq 'firewall security-policy' -and (Get-FgtValue $e 'enforce-default-app-port' 'enable') -eq 'enable') {
                        $r.Services = @('application-default')
                    }
                }
                $urlCat = @(Get-FgtList $e 'url-category')
                if ($urlCat.Count -gt 0) { Add-NormDiagnostic $model 'lossy' $r.Name "url-category $($urlCat -join ', ') restricts destinations by web category; not represented" }

                $r.Profile = Get-FgtProfileSummary -Entry $e -ProfileGroups $profileGroups
                $r.Comment = (Get-FgtValue $e 'comments' '') -replace "[`r`n]+", ' '
                # Written like the PAN-OS Options column. The default "utm"
                # only logs sessions that hit a security event.
                $lt = Get-FgtValue $e 'logtraffic' 'utm'
                $logParts = @()
                if ((Get-FgtValue $e 'logtraffic-start' 'disable') -eq 'enable') { $logParts += 'Log at Session Start' }
                switch ($lt) {
                    'all'     { $logParts += 'Log at Session End' }
                    'utm'     { $logParts += 'Log security events only (FortiOS logtraffic utm)' }
                    'disable' { $logParts += 'Logging disabled (FortiOS logtraffic disable)' }
                }
                $r.Log = ($logParts -join '; ')
                $r.Tags = @(@(Get-FgtList $e 'tags') + @($r.Comment) | Where-Object { $_ }) -join ';'

                $sched = Get-FgtValue $e 'schedule' 'always'
                if ($sched -ne 'always') { Add-NormDiagnostic $model 'info' $r.Name "schedule '$sched' (rule is time limited)" }
                $ids = @(Get-FgtList $e 'groups') + @(Get-FgtList $e 'users')
                if ($ids.Count -gt 0) { Add-NormDiagnostic $model 'lossy' $r.Name "restricted to users/groups ($($ids -join ', ')); MooseAlto has no identity dimension, rule may look broader than it is" }

                $u = $usage["$($vr.Vdom)|$usageTable|$($e.Name)"]
                if ($null -ne $u) {
                    $hc = if ($null -ne $u.hit_count) { [int64]$u.hit_count } else { 0 }
                    $r.HitCount = "$hc"
                    $r.LastHit = $(if ($null -eq $u.last_used -and $hc -gt 0) { '' } else { ConvertFrom-FgtEpoch $u.last_used })
                }
                $model.Rules.Add($r)
            }
        }
    }
    if ($model.Rules.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no firewall policy found in the input' }
    if ($UsageJson -and $usage.Count -gt 0 -and @($model.Rules | Where-Object { $_.HitCount -ne '' }).Count -eq 0) {
        $endpoints = @($usage.Keys | ForEach-Object { ($_ -split '\|')[1] } | Select-Object -Unique) -join ', '
        $vdomsIn = @($usage.Keys | ForEach-Object { ($_ -split '\|')[0] } | Select-Object -Unique) -join ', '
        Add-NormDiagnostic $model 'error' '' "hit counter file matched no policy: it holds counters for endpoint '$endpoints' in VDOM '$vdomsIn'. In NGFW policy-based mode save /api/v2/monitor/firewall/security-policy, otherwise /api/v2/monitor/firewall/policy, for every VDOM analyzed."
    }
    if (-not $UsageJson) { Add-NormDiagnostic $model 'info' '' 'no hit counter file supplied: Hit Count and Last Hit left blank (usage checks will not run)' }
    return $model
}
