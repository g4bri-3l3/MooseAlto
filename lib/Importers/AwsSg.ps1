# --------------------------------------------------------------------------
# AWS EC2 security groups
# --------------------------------------------------------------------------
#
# Input: "aws ec2 describe-security-groups" output ({ "SecurityGroups": [...] }),
# or the bare array.
#
# A security group only allows, and its rules have no order: traffic passes
# if any rule matches. So there is nothing to shadow across actions, and a
# rule covered by another one of the same group is redundant whatever its
# position. Each IpPermission becomes one rule, with every CIDR, IPv6 range,
# prefix list and referenced group it lists. Rules have no names; the rule
# name is "<group>/<in|out> <service>".
#
# The default egress rule (all traffic to 0.0.0.0/0) is tagged
# "aws-default-egress": it is real and open, but it's there because nobody
# removed it, not because somebody wrote it.

function Test-AwsSgJson {
    param([string]$Head)
    return ($Head -match '"SecurityGroups"\s*:' -or ($Head -match '"GroupId"\s*:' -and $Head -match '"IpPermissions(Egress)?"\s*:'))
}

function Get-AwsPermissionPorts {
    # FromPort/ToPort as port specs; for ICMP they are type and code.
    param($Perm)
    $from = Get-CloudProp $Perm 'FromPort'
    $to = Get-CloudProp $Perm 'ToPort'
    if ($null -eq $from -or [int]$from -lt 0) { return @() }
    if ($null -eq $to -or [int]$to -lt 0) { $to = $from }
    if ([int]$from -eq [int]$to) { return @("$from") }
    return @("$from-$to")
}

function ConvertFrom-AwsSg {
    param([Parameter(Mandatory)][string]$Path)
    $model = New-NormModel -Vendor 'aws' -Source $Path
    $json = Read-CloudJson -Path $Path
    $groups = if ($json -is [array]) { @($json) } elseif (Get-CloudProp $json 'SecurityGroups') { @(Get-CloudProp $json 'SecurityGroups') } else { @($json) }
    $groups = @($groups | Where-Object { $_ -and (Get-CloudProp $_ 'GroupId') })

    $byId = @{}
    foreach ($g in $groups) { $byId["$(Get-CloudProp $g 'GroupId')"] = "$(Get-CloudProp $g 'GroupName')" }
    $labelItems = foreach ($g in $groups) {
        @{ Key = "$(Get-CloudProp $g 'GroupId')"; Name = "$(Get-CloudProp $g 'GroupName')"; Parent = "$(Get-CloudProp $g 'VpcId')" }
    }
    $labels = Get-CloudZoneLabels -Items @($labelItems)

    $prefixLists = 0
    foreach ($g in $groups) {
        $gid = "$(Get-CloudProp $g 'GroupId')"
        $zone = $labels[$gid]
        foreach ($dir in @('inbound', 'outbound')) {
            $field = if ($dir -eq 'inbound') { 'IpPermissions' } else { 'IpPermissionsEgress' }
            $short = if ($dir -eq 'inbound') { 'in' } else { 'out' }
            foreach ($perm in @(Get-CloudProp $g $field | Where-Object { $_ })) {
                $remoteTokens = @()
                $descs = @()
                foreach ($x in @(Get-CloudProp $perm 'IpRanges' | Where-Object { $_ })) {
                    $remoteTokens += "$(Get-CloudProp $x 'CidrIp')"
                    if (Get-CloudProp $x 'Description') { $descs += "$(Get-CloudProp $x 'Description')" }
                }
                foreach ($x in @(Get-CloudProp $perm 'Ipv6Ranges' | Where-Object { $_ })) {
                    $remoteTokens += "$(Get-CloudProp $x 'CidrIpv6')"
                    if (Get-CloudProp $x 'Description') { $descs += "$(Get-CloudProp $x 'Description')" }
                }
                foreach ($x in @(Get-CloudProp $perm 'PrefixListIds' | Where-Object { $_ })) {
                    $remoteTokens += "pl:$(Get-CloudProp $x 'PrefixListId')"
                    $prefixLists++
                }
                foreach ($x in @(Get-CloudProp $perm 'UserIdGroupPairs' | Where-Object { $_ })) {
                    $ref = "$(Get-CloudProp $x 'GroupId')"
                    # Same account: the group name reads better. Another
                    # account or a peered VPC: keep the id.
                    $refName = if ($byId.ContainsKey($ref)) { $byId[$ref] } else { $ref }
                    $remoteTokens += "sg:$refName"
                    if (Get-CloudProp $x 'Description') { $descs += "$(Get-CloudProp $x 'Description')" }
                }
                $remoteTokens = @($remoteTokens | Where-Object { $_ -and $_ -notmatch ':$' })
                if ($remoteTokens.Count -eq 0) { continue }

                $services = @(ConvertTo-CloudServiceTokens -Proto "$(Get-CloudProp $perm 'IpProtocol')" -Ports @(Get-AwsPermissionPorts $perm))
                $proto = ConvertTo-CloudProtocol "$(Get-CloudProp $perm 'IpProtocol')"
                $icmpPorts = @(Get-AwsPermissionPorts $perm)
                if ($proto -eq 'icmp' -and $icmpPorts.Count -gt 0 -and $icmpPorts[0] -match '^\d+$') { $services = @("icmp-$($icmpPorts[0])") }

                $isDefaultEgress = ($dir -eq 'outbound') -and $services.Count -eq 0 -and $remoteTokens.Count -eq 1 -and $remoteTokens[0] -eq '0.0.0.0/0'
                $tags = if ($isDefaultEgress) { 'aws-default-egress' } else { '' }
                # The findings table has no Tags column: the name says it.
                $name = "$zone/$short $(Get-CloudServiceLabel $services)$(if ($isDefaultEgress) { ' (default egress)' })"
                $remote = Get-CloudRemoteSide -Model $model -RuleName $name -Tokens $remoteTokens
                # No rule names on AWS: LocalName stays empty, so the naming
                # checks (generic name, name vs action) don't run on our
                # made-up names.
                $rule = New-CloudRule -Name $name -LocalName '' -Scope "$zone/$dir" -Vendor 'aws' -Direction $dir `
                    -LocalZone $zone -LocalAddrs @() -Remote $remote -Services $services -Action 'allow' -Tags $tags
                $rule.Comment = (@($descs | Select-Object -Unique) -join '; ')
                $model.Rules.Add($rule)
            }
        }
    }

    if ($prefixLists -gt 0) {
        Add-NormDiagnostic $model 'lossy' '' "$prefixLists prefix list reference(s) (pl:...) kept by name: the export doesn't say which CIDRs they hold, so they never count as internet"
    }
    $refs = @($model.Rules | Where-Object { @($_.SrcAddrs + $_.DstAddrs | Where-Object { "$_" -like 'sg:*' }).Count -gt 0 }).Count
    if ($refs -gt 0) {
        Add-NormDiagnostic $model 'info' '' "$refs rule(s) reference other security groups (sg:...): compared by name, read as internal"
    }
    Add-NormDiagnostic $model 'info' '' "$($groups.Count) security group(s) read; allow-only rules without order, each group is two scopes (inbound, outbound)"
    if ($model.Rules.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no security group rule found in the export' }
    return $model
}
