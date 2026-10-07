# --------------------------------------------------------------------------
# Azure Network Security Groups
# --------------------------------------------------------------------------
#
# Input: "az network nsg list -o json" (one or more NSGs), a single
# "az network nsg show", or the same objects from the ARM REST API / Resource
# Graph, where the rule lists sit under "properties".
#
# Rules are evaluated by priority, inbound and outbound separately, so each
# NSG gives two scopes. The six default rules (65000-65500) are added at the
# end of each list with the tag "azure-default": they are the policy too, and
# AllowInternetOutBound in particular opens all egress unless a rule above it
# says otherwise.
#
# Service tags: Internet is the public address space, modeled as "not
# RFC1918" (negated private ranges) and shown as "Internet": it covers any
# public range but not 10.0.0.0/8, so AllowInternetOutBound doesn't make
# DenyAllOutBound look dead. AzureCloud (and its regional forms) is
# public address space shared with every Azure customer: internet, token
# kept. VirtualNetwork, other tags (Storage, Sql, AzureLoadBalancer...) and
# application security groups (asg:<name>) stay opaque internal tokens; on
# the protected side VirtualNetwork means everything behind the NSG (any).

$script:AzureInternetTags = @('azurecloud')

function Test-AzureNsgJson {
    param([string]$Head)
    return ($Head -match '(?i)Microsoft\.Network/networkSecurityGroups' -or $Head -match '"(defaultSecurityRules|securityRules)"\s*:')
}

function Get-AzurePrefixes {
    # Singular and plural fields, plus application security groups.
    param($Rule, [ValidateSet('source', 'destination')][string]$Side)
    $out = @()
    $one = Get-CloudProp $Rule "${Side}AddressPrefix"
    if ($one) { $out += "$one" }
    foreach ($p in @(Get-CloudProp $Rule "${Side}AddressPrefixes")) { if ($p) { $out += "$p" } }
    foreach ($asg in @(Get-CloudProp $Rule "${Side}ApplicationSecurityGroups")) {
        if (-not $asg) { continue }
        $id = "$(Get-CloudProp $asg 'id')"
        $name = if ($id) { ($id -split '/')[-1] } else { "$(Get-CloudProp $asg 'name')" }
        if ($name) { $out += "asg:$name" }
    }
    return $out
}

function Get-AzurePorts {
    param($Rule, [ValidateSet('source', 'destination')][string]$Side)
    $out = @()
    $one = Get-CloudProp $Rule "${Side}PortRange"
    if ($one) { $out += "$one" }
    foreach ($p in @(Get-CloudProp $Rule "${Side}PortRanges")) { if ($p) { $out += "$p" } }
    return $out
}

function ConvertFrom-AzureNsg {
    param([Parameter(Mandatory)][string]$Path)
    $model = New-NormModel -Vendor 'azure' -Source $Path
    $json = Read-CloudJson -Path $Path
    # A list, one NSG, or a Resource Graph answer ({ data: [...] }).
    $nsgs = @()
    if ($json -is [array]) { $nsgs = @($json) }
    elseif (Get-CloudProp $json 'data') { $nsgs = @(Get-CloudProp $json 'data') }
    elseif (Get-CloudProp $json 'value') { $nsgs = @(Get-CloudProp $json 'value') }
    else { $nsgs = @($json) }
    $nsgs = @($nsgs | Where-Object { $_ -and (Get-CloudProp $_ 'name') })

    $labelItems = foreach ($n in $nsgs) {
        @{ Key = "$(Get-CloudProp $n 'id')|$(Get-CloudProp $n 'name')"; Name = "$(Get-CloudProp $n 'name')"; Parent = "$(Get-CloudProp $n 'resourceGroup')" }
    }
    $labels = Get-CloudZoneLabels -Items @($labelItems)

    $unattached = @()
    foreach ($nsg in $nsgs) {
        $props = Get-CloudProp $nsg 'properties'
        if (-not $props) { $props = $nsg }
        $nsgName = "$(Get-CloudProp $nsg 'name')"
        $zone = $labels["$(Get-CloudProp $nsg 'id')|$nsgName"]

        $subnets = @(Get-CloudProp $props 'subnets' | Where-Object { $_ })
        $nics = @(Get-CloudProp $props 'networkInterfaces' | Where-Object { $_ })
        $hasAssocInfo = ($null -ne $props.PSObject.Properties['subnets']) -or ($null -ne $props.PSObject.Properties['networkInterfaces'])
        if ($hasAssocInfo -and $subnets.Count -eq 0 -and $nics.Count -eq 0) { $unattached += $zone }

        $custom = @(Get-CloudProp $props 'securityRules' | Where-Object { $_ })
        $defaults = @(Get-CloudProp $props 'defaultSecurityRules' | Where-Object { $_ })
        if ($defaults.Count -eq 0) {
            Add-NormDiagnostic $model 'warn' $zone "no defaultSecurityRules in the export: the default rules (AllowVnetInBound, AllowInternetOutBound...) are not analyzed for this NSG"
        }

        foreach ($dir in @('inbound', 'outbound')) {
            # ARM REST nests each rule's fields under "properties" as well;
            # the name stays outside.
            $list = @()
            foreach ($pair in @(@($custom, $false), @($defaults, $true))) {
                foreach ($raw in @($pair[0])) {
                    if (-not $raw) { continue }
                    $rp = Get-CloudProp $raw 'properties'
                    if (-not $rp) { $rp = $raw }
                    if ("$(Get-CloudProp $rp 'direction')" -ieq $dir) {
                        $list += [PSCustomObject]@{ Rule = $rp; Name = "$(Get-CloudProp $raw 'name')"; Default = $pair[1] }
                    }
                }
            }
            $list = @($list | Sort-Object { [int](Get-CloudProp $_.Rule 'priority') })

            foreach ($item in $list) {
                $r = $item.Rule
                $ruleName = $item.Name
                $fullName = "$zone/$ruleName"
                $src = @(Get-AzurePrefixes $r 'source')
                $dst = @(Get-AzurePrefixes $r 'destination')
                $remoteTokens = if ($dir -eq 'inbound') { $src } else { $dst }
                $localTokens = if ($dir -eq 'inbound') { $dst } else { $src }
                $remote = Get-CloudRemoteSide -Model $model -RuleName $fullName -Tokens $remoteTokens -InternetTags $script:AzureInternetTags -PublicTags @('internet')
                $local = Get-CloudLocalAddrs -Tokens $localTokens

                $services = @(ConvertTo-CloudServiceTokens -Proto "$(Get-CloudProp $r 'protocol')" -Ports @(Get-AzurePorts $r 'destination'))
                $srcPorts = @(Get-AzurePorts $r 'source' | Where-Object { $_ -ne '*' })
                if ($srcPorts.Count -gt 0) {
                    Add-NormDiagnostic $model 'lossy' $fullName "source port restricted to $($srcPorts -join ','): not represented, rule may look broader than it is"
                }

                $access = "$(Get-CloudProp $r 'access')"
                $action = if ($access -ieq 'Deny') { 'deny' } else { 'allow' }

                $tags = if ($item.Default) { 'azure-default' } else { '' }
                $rule = New-CloudRule -Name $fullName -LocalName $ruleName -Scope "$zone/$dir" -Vendor 'azure' -Direction $dir `
                    -LocalZone $zone -LocalAddrs $local -Remote $remote -Services $services -Action $action -Tags $tags
                $rule.Comment = "$(Get-CloudProp $r 'description')"
                $model.Rules.Add($rule)
            }
        }
    }

    if ($unattached.Count -gt 0) {
        Add-NormDiagnostic $model 'info' '' "NSG(s) not associated with any subnet or network interface, so their rules filter no traffic today: $($unattached -join ', ')"
    }
    Add-NormDiagnostic $model 'info' '' "$($nsgs.Count) NSG(s) read; each one is two scopes (inbound, outbound), rules ordered by priority"
    if ($model.Rules.Count -eq 0) { Add-NormDiagnostic $model 'error' '' 'no NSG security rule found in the export' }
    return $model
}
