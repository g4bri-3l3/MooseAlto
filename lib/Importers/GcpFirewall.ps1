# --------------------------------------------------------------------------
# Google Cloud VPC firewall rules
# --------------------------------------------------------------------------
#
# Input: "gcloud compute firewall-rules list --format=json" (one or more
# networks), or the REST answer ({ "items": [...] }).
#
# Rules are per VPC network and direction, evaluated by priority; at equal
# priority deny wins, so deny rules are sorted first. Every network also has
# two implied rules nobody can delete or see in the export: deny all
# ingress and allow all egress, priority 65535. They are added at the end
# with the tag "gcp-implied".
#
# Targets (target tags, target service accounts) are the local addresses,
# as tag:<name> / sa:<account>; source tags and accounts likewise on the
# remote side. A rule without sourceRanges matches 0.0.0.0/0 only when it
# has no source tags or accounts either.

function Test-GcpFirewallJson {
    param([string]$Head)
    return ($Head -match '"compute#firewall"' -or ($Head -match '"(sourceRanges|destinationRanges)"\s*:' -and $Head -match '"direction"\s*:'))
}

function Get-GcpNetworkName {
    param([string]$Url)
    if (-not $Url) { return 'default' }
    return ($Url -split '/')[-1]
}

function ConvertFrom-GcpFirewall {
    param([Parameter(Mandatory)][string]$Path)
    $model = New-NormModel -Vendor 'gcp' -Source $Path
    $json = Read-CloudJson -Path $Path
    $items = if ($json -is [array]) { @($json) } elseif (Get-CloudProp $json 'items') { @(Get-CloudProp $json 'items') } else { @($json) }
    $items = @($items | Where-Object { $_ -and (Get-CloudProp $_ 'name') })

    $networks = @($items | ForEach-Object { Get-GcpNetworkName "$(Get-CloudProp $_ 'network')" } | Select-Object -Unique)
    $unsupportedSeen = @{}

    foreach ($net in $networks) {
        foreach ($dir in @('inbound', 'outbound')) {
            $gcpDir = if ($dir -eq 'inbound') { 'INGRESS' } else { 'EGRESS' }
            $list = @($items | Where-Object {
                    (Get-GcpNetworkName "$(Get-CloudProp $_ 'network')") -eq $net -and
                    $(if (Get-CloudProp $_ 'direction') { "$(Get-CloudProp $_ 'direction')" -ieq $gcpDir } else { $gcpDir -eq 'INGRESS' })
                })
            # Priority, then deny before allow (deny wins a tie), then name.
            $list = @($list | Sort-Object @{ Expression = { $p = Get-CloudProp $_ 'priority'; if ($null -eq $p) { 1000 } else { [int]$p } } },
                @{ Expression = { if (Get-CloudProp $_ 'denied') { 0 } else { 1 } } },
                @{ Expression = { "$(Get-CloudProp $_ 'name')" } })

            foreach ($fw in $list) {
                $ruleName = "$(Get-CloudProp $fw 'name')"
                $fullName = "$net/$ruleName"

                # FQDNs, geolocation, threat intelligence lists and address
                # groups have no addresses to compare. Kept as names
                # (fqdn:example.com), so a rule matching only those doesn't
                # turn into 0.0.0.0/0, and they never count as internet.
                $otherSrc = @(); $otherDst = @()
                foreach ($f in @('sourceFqdns', 'sourceRegionCodes', 'sourceThreatIntelligences', 'sourceAddressGroups', 'destinationFqdns', 'destinationRegionCodes', 'destinationThreatIntelligences', 'destinationAddressGroups')) {
                    $vals = @(Get-CloudProp $fw $f | Where-Object { $_ })
                    if ($vals.Count -eq 0) { continue }
                    $label = ($f -replace '^(source|destination)', '').ToLower() -replace 's$', ''
                    $toks = @($vals | ForEach-Object { "${label}:$_" })
                    if ($f -like 'source*') { $otherSrc += $toks } else { $otherDst += $toks }
                    Add-NormDiagnostic $model 'lossy' $fullName "$f ($($vals -join ', ')) kept by name: no address comparison, never read as internet"
                    $unsupportedSeen[$f] = $true
                }

                $srcRanges = @(Get-CloudProp $fw 'sourceRanges' | Where-Object { $_ })
                $srcTags = @(Get-CloudProp $fw 'sourceTags' | Where-Object { $_ } | ForEach-Object { "tag:$_" })
                $srcSas = @(Get-CloudProp $fw 'sourceServiceAccounts' | Where-Object { $_ } | ForEach-Object { "sa:$_" })
                $dstRanges = @(Get-CloudProp $fw 'destinationRanges' | Where-Object { $_ })
                $targets = @(Get-CloudProp $fw 'targetTags' | Where-Object { $_ } | ForEach-Object { "tag:$_" }) +
                           @(Get-CloudProp $fw 'targetServiceAccounts' | Where-Object { $_ } | ForEach-Object { "sa:$_" })

                if ($dir -eq 'inbound') {
                    $remoteTokens = @($srcRanges) + @($srcTags) + @($srcSas) + @($otherSrc)
                    if ($remoteTokens.Count -eq 0) { $remoteTokens = @('0.0.0.0/0') }
                    $localTokens = @($targets)
                    if ($dstRanges.Count -gt 0) {
                        Add-NormDiagnostic $model 'info' $fullName "ingress destinationRanges ($($dstRanges -join ', ')) narrow the targets further; only the targets are represented"
                    }
                }
                else {
                    $remoteTokens = @($dstRanges) + @($otherDst)
                    if ($remoteTokens.Count -eq 0) { $remoteTokens = @('0.0.0.0/0') }
                    $localTokens = @($targets)
                    if ($srcRanges.Count -gt 0) { $localTokens = @($srcRanges) + @($targets) }
                }
                $remote = Get-CloudRemoteSide -Model $model -RuleName $fullName -Tokens $remoteTokens
                $local = Get-CloudLocalAddrs -Tokens $localTokens

                $denied = @(Get-CloudProp $fw 'denied' | Where-Object { $_ })
                $allowed = @(Get-CloudProp $fw 'allowed' | Where-Object { $_ })
                $action = if ($denied.Count -gt 0) { 'deny' } else { 'allow' }
                $services = @()
                $isAny = $false
                foreach ($e in @($allowed) + @($denied)) {
                    $toks = @(ConvertTo-CloudServiceTokens -Proto "$(Get-CloudProp $e 'IPProtocol')" -Ports @(Get-CloudProp $e 'ports'))
                    if ($toks.Count -eq 0) { $isAny = $true }
                    $services += $toks
                }
                $services = if ($isAny) { @() } else { @($services | Select-Object -Unique) }
                if (Test-NormServiceIsAny $services) { $services = @() }

                $rule = New-CloudRule -Name $fullName -LocalName $ruleName -Scope "$net/$dir" -Vendor 'gcp' -Direction $dir `
                    -LocalZone $net -LocalAddrs $local -Remote $remote -Services $services -Action $action
                $rule.Enabled = -not ("$(Get-CloudProp $fw 'disabled')" -ieq 'true')
                $logCfg = Get-CloudProp $fw 'logConfig'
                $rule.Log = if ($logCfg -and "$(Get-CloudProp $logCfg 'enable')" -ieq 'true') { 'Log at Session End' } else { '' }
                $rule.Comment = "$(Get-CloudProp $fw 'description')"
                # PowerShell 7 turns ISO strings into [datetime] on its own.
                $createdRaw = Get-CloudProp $fw 'creationTimestamp'
                if ($createdRaw -is [datetime]) { $rule.Created = $createdRaw.ToUniversalTime().ToString('yyyy-MM-dd') }
                elseif ("$createdRaw" -match '^(\d{4}-\d{2}-\d{2})') { $rule.Created = $Matches[1] }
                $model.Rules.Add($rule)
            }

            # The implied rule closing this direction.
            $implied = if ($dir -eq 'inbound') { 'implied-deny-ingress' } else { 'implied-allow-egress' }
            $rule = New-CloudRule -Name "$net/$implied" -LocalName $implied -Scope "$net/$dir" -Vendor 'gcp' -Direction $dir `
                -LocalZone $net -LocalAddrs @() -Remote @{ Zone = 'any'; Addrs = @(); Internet = $true } -Services @() `
                -Action $(if ($dir -eq 'inbound') { 'deny' } else { 'allow' }) -Tags 'gcp-implied'
            # Implied rules can't log.
            $rule.Log = ''
            $model.Rules.Add($rule)
        }
    }

    Add-NormDiagnostic $model 'info' '' "$($items.Count) firewall rule(s) on $($networks.Count) network(s): $($networks -join ', '); implied deny-ingress / allow-egress rules added at priority 65535"
    if ($items.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no firewall rule found in the export' }
    return $model
}
