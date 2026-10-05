# --------------------------------------------------------------------------
# FortiGuard application IDs -> MooseAlto application names
# --------------------------------------------------------------------------
#
# FortiOS stores applications as numeric IDs. We look each one up in the
# config's own "application name" table, then -AppMapCsv, then the table
# below, and rename it the way the PAN-OS checks spell it (RDP -> ms-rdp).
# Unknown IDs become "fortiapp-<id>".
#
# The first block was checked by hand on fortiguard.com (September 2026);
# the rest comes from github.com/Jaimer/FortigateAppControlID, which agrees
# with every ID we checked. That table is GPL, so it isn't bundled, but
# -AppMapCsv takes it as is.

$script:FgtBuiltinAppIds = @{
    15511 = 'RDP'
    15510 = 'VNC'
    16060 = 'SSH'
    16091 = 'Telnet'
    15896 = 'FTP'
    16074 = 'SMTP'
    16906 = 'SNMP'
    16265 = 'Kerberos'
    15921 = 'TeamViewer'
    39164 = 'AnyDesk'
    43462 = 'Splashtop'
    15891 = 'LogMeIn'
    47816 = 'DNS.Over.HTTPS'
    15893 = 'HTTP.BROWSER'
    40568 = 'HTTPS.BROWSER'
    15895 = 'SSL'
    16513 = 'Postgres'
    44624 = 'SMB.v3'
    31884 = 'Windows.File.Sharing_Open.Directory'
    # second block (public table)
    16195 = 'DNS'
    15886 = 'MySQL'
    16197 = 'MSSQL'
    25434 = 'IKE'
    16173 = 'LDAP'
    16104 = 'POP3'
    16103 = 'IMAP'
    16253 = 'TFTP'
    16270 = 'NTP'
    34640 = 'SIP'
    37200 = 'MQTT'
    16714 = 'PPTP'
    33002 = 'MongoDB'
    24466 = 'Ping'
    16206 = 'ICMP'
    # third block (same public table): the rest of the risky app lists
    15888 = 'Oracle.TNS'
    16899 = 'Rsh'
    16275 = 'Rlogin'
    16915 = 'Rexec'
    16395 = 'GoToMyPC'
    31988 = 'LogMeIn_Rescue'
    29610 = 'Chrome.Remote.Desktop'
    16083 = 'UPnP'
    17017 = 'NetBIOS.Name.Service'
    44611 = 'SMB.v1'
    44623 = 'SMB.v2'
    27457 = 'Windows.File.Sharing'
    16613 = 'CHARGEN'
    37253 = 'Memcached'
}

# FortiGuard name (lowercase) -> MooseAlto / PAN-OS application name.
$script:FgtAppCanonical = @{
    'rdp'                                 = 'ms-rdp'
    'vnc'                                 = 'vnc'
    'ssh'                                 = 'ssh'
    'telnet'                              = 'telnet'
    'ftp'                                 = 'ftp'
    'smtp'                                = 'smtp'
    'snmp'                                = 'snmp'
    'kerberos'                            = 'kerberos'
    'teamviewer'                          = 'teamviewer'
    'anydesk'                             = 'anydesk'
    'splashtop'                           = 'splashtop'
    'logmein'                             = 'logmein'
    'dns.over.https'                      = 'dns-over-https'
    'http.browser'                        = 'web-browsing'
    'https.browser'                       = 'ssl'
    'ssl'                                 = 'ssl'
    'postgres'                            = 'postgres'
    'smb.v3'                              = 'ms-ds-smb'
    'windows.file.sharing_open.directory' = 'ms-ds-smb'
    'dns'                                 = 'dns'
    'mysql'                               = 'mysql'
    'mssql'                               = 'ms-sql-db'
    'ike'                                 = 'ike'
    'ldap'                                = 'ldap'
    'pop3'                                = 'pop3'
    'imap'                                = 'imap'
    'tftp'                                = 'tftp'
    'ntp'                                 = 'ntp'
    'sip'                                 = 'sip'
    'mqtt'                                = 'mqtt'
    'pptp'                                = 'pptp'
    'mongodb'                             = 'mongodb'
    'ping'                                = 'ping'
    'icmp'                                = 'icmp'
    'oracle.tns'                          = 'oracle'
    'rsh'                                 = 'rsh'
    'rlogin'                              = 'rlogin'
    'rexec'                               = 'rexec'
    'gotomypc'                            = 'logmein-gotomypc'
    'logmein_rescue'                      = 'logmein-rescue'
    'chrome.remote.desktop'               = 'chrome-remote-desktop'
    'upnp'                                = 'ssdp'
    'netbios.name.service'                = 'netbios-ns'
    'smb.v1'                              = 'ms-ds-smb'
    'smb.v2'                              = 'ms-ds-smb'
    'windows.file.sharing'                = 'ms-ds-smb'
    'chargen'                             = 'chargen'
    'memcached'                           = 'memcached'
}

# FortiGuard application category IDs (same public table, Categories.csv).
$script:FgtAppCategories = @{
    2 = 'P2P'; 3 = 'VoIP'; 5 = 'Video/Audio'; 6 = 'Proxy'; 7 = 'Remote.Access'; 8 = 'Game'
    12 = 'General.Interest'; 15 = 'Network.Service'; 17 = 'Update'; 19 = 'Botnet'; 21 = 'Email'
    22 = 'Storage.Backup'; 23 = 'Social.Media'; 25 = 'Web.Client'; 26 = 'Industrial'
    28 = 'Collaboration'; 29 = 'Business'; 30 = 'Cloud.IT'; 31 = 'Mobile'
}

function ConvertTo-FgtCategoryToken {
    param([string]$Id)
    if ($Id -match '^\d+$' -and $script:FgtAppCategories.ContainsKey([int]$Id)) {
        return 'fortiapp-category-' + ($script:FgtAppCategories[[int]$Id].ToLower() -replace '[\./]+', '-')
    }
    return "fortiapp-category-$Id"
}

function ConvertTo-FgtCanonicalApp {
    param([string]$FortiGuardName)
    $k = $FortiGuardName.ToLower()
    if ($script:FgtAppCanonical.ContainsKey($k)) { return $script:FgtAppCanonical[$k] }
    return ($k -replace '[\._\s]+', '-')
}

function New-FgtAppResolver {
    # Builds the id -> FortiGuard name map for one input.
    param($Root, [string]$AppMapCsv)
    $map = @{}
    foreach ($k in $script:FgtBuiltinAppIds.Keys) { $map["$k"] = @{ Name = $script:FgtBuiltinAppIds[$k]; Source = 'builtin' } }
    if ($AppMapCsv) {
        # Accepts "id,name" or the "APP ID;APP;..." layout of the public table.
        $first = (Get-Content -Path $AppMapCsv -TotalCount 1).TrimStart([char]0xFEFF)
        $delim = if ($first -match ';' -and $first -notmatch ',') { ';' } else { ',' }
        foreach ($row in (Import-Csv -Path $AppMapCsv -Delimiter $delim)) {
            $id = if ($row.id) { $row.id } else { $row.'APP ID' }
            $nm = if ($row.name) { $row.name } else { $row.APP }
            if ($id -and $nm) { $map["$id".Trim()] = @{ Name = $nm.Trim(); Source = 'csv' } }
        }
    }
    foreach ($holder in @($Root, (Get-FgtTable $Root 'global'))) {
        $tbl = Get-FgtTable $holder 'application name'
        if ($null -eq $tbl) { continue }
        foreach ($e in $tbl.Entries.Values) {
            $id = Get-FgtValue $e 'id' ''
            if ($id) { $map["$id"] = @{ Name = $e.Name; Source = 'config' } }
        }
    }
    return $map
}

function Resolve-FgtApplications {
    # Apps, unknown IDs and categories of one policy, groups expanded.
    param($Ctx, $Entry)
    $ids = New-Object System.Collections.Generic.List[string]
    $cats = New-Object System.Collections.Generic.List[string]
    foreach ($i in (Get-FgtList $Entry 'application')) { $ids.Add($i) }
    foreach ($c in (Get-FgtList $Entry 'app-category')) { $cats.Add($c) }
    foreach ($g in (Get-FgtList $Entry 'app-group')) {
        if ($null -ne $Ctx.AppGroups -and $Ctx.AppGroups.Entries.Contains($g)) {
            $ge = $Ctx.AppGroups.Entries[$g]
            # 7.x filter groups (risk, popularity...) can't be expanded from
            # the config. One token, so the rule doesn't look like any.
            if ((Get-FgtValue $ge 'type' 'application') -eq 'filter') { $cats.Add("group:$g"); continue }
            foreach ($i in (Get-FgtList $ge 'application')) { $ids.Add($i) }
            foreach ($c in (Get-FgtList $ge 'category')) { $cats.Add($c) }
        }
        else { $cats.Add("group:$g") }
    }
    $apps = @(); $unknown = @()
    foreach ($id in ($ids | Select-Object -Unique)) {
        if ($Ctx.AppMap.ContainsKey($id)) { $apps += ConvertTo-FgtCanonicalApp $Ctx.AppMap[$id].Name }
        else { $apps += "fortiapp-$id"; $unknown += $id }
    }
    return @{ Apps = @($apps | Select-Object -Unique); Unknown = $unknown; Categories = @($cats | Select-Object -Unique) }
}
