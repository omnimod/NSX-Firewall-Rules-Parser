	<#
		.SYNOPSIS
		This is a simple PowerShell command to parse NSX firewall rules

		.PARAMETER FilePath
		Specifies the path to the pcoip_server log file.
		
		.EXAMPLE
		.\parse-nsxrules.ps1 -FilePath C:\Temp\NSX_rules.xml -Format HTML -ResultPath C:\Temp\parsed_rules.html
		
		.DESCRIPTION
		
		The Parse-NSXRules cmdlet converts the regular XML exported NSX firewall rules to the HTML or CSV format for better readability
		
		.LINK
		https://github.com/omnimod/NSX-Firewall-Rules-Parser
	#>

Param(
	[Parameter(Mandatory=$True,
	Position=0,
	HelpMessage="Enter the path where the result file will be saved")]	
	[String] $ResultPath,
		
	[Parameter(Position=1,
	HelpMessage="Enter the path to the exported NSX firewall rules")]
	[String] $FilePath,

	[Parameter(Position=2,
	HelpMessage="Select properties to display, separated by commas")]	
	[String] $Property = "",
	
	[Parameter(Position=3,
	HelpMessage="Specify the format of the result file. Could be HTML, CSV or XML")]		
	[ValidateSet("CSV", "HTML", "XML")]
	[String]$Format = "HTML",
	
	[Parameter(
	HelpMessage="Specify the IP address or DNS name of NSX Manager")]		
	[String]$NSXManager,
	
	[Parameter(
	HelpMessage="Specify the username to connect to the NSX Manager")]		
	[String]$Username,		
	
	[Parameter(
	HelpMessage="Specify the password to connect to the NSX Manager")]		
	[String]$Password	
)

#Convert an array of objects to string
function Format-Entries ($entries) {
	if($entries) {
		$str = ""
		$negate = ""

		if($entries.excluded -eq $true) {
			$negate = "[NE] "
		}
		
		$i = 0
		$num = $entries.ChildNodes.Count
		
		foreach ($entry in $entries.ChildNodes) {
			$i++
			
			if($i -eq $num) {
				$eol=""
			}

			switch ($entry.type) {
				"Application"                 { $str += "[APP] "    + $negate + $entry.name + $eol }
				"ApplicationGroup"            { $str += "[APPG] "   + $negate + $entry.name + $eol }			
				"ClusterComputeResource"      { $str += "[CLU] "    + $negate + $entry.name + $eol }
				"Datacenter"                  { $str += "[DC] "     + $negate + $entry.name + $eol }			
				"DISTRIBUTED_FIREWALL"        { $str += "[DFW] "    + $negate + $entry.name + $eol }
				"DistributedVirtualPortgroup" { $str += "[DVPG] "   + $negate + $entry.name + $eol }			
				"Edge"                        { $str += "[EDGE] "   + $negate + $entry.name + $eol }
				"Hostsystem"                  { $str += "[HOST] "   + $negate + $entry.name + $eol }					
				"Ipv4Address"                 { $str += "[IPv4] "   + $negate + $entry.value + $eol }
				"Ipv6Address"                 { $str += "[IPv6] "   + $negate + $entry.value + $eol }
				"IPSet"                       { $str += "[IPSET] "  + $negate + $entry.name + $eol }
				"Network"                     { $str += "[STPG] "   + $negate + $entry.name + $eol }
				"ResourcePool"                { $str += "[RP] "     + $negate + $entry.name + $eol }
				"SecurityGroup"               { $str += "[SG] "     + $negate + $entry.name + $eol }
				"VirtualApp"                  { $str += "[VAPP] "   + $negate + $entry.name + $eol }				
				"VirtualMachine"              { $str += "[VM] "     + $negate + $entry.name + $eol }
				"VirtualWire"                 { $str += "[LSWC] "   + $negate + $entry.name + $eol }				
				"Vnic"                        { $str += "[VNIC] "   + $negate + $entry.name + $eol }
				default                       { $str += $entry.Name + $eol }
			}
		}
		return $str
	} else {
		return "any"
	}
}

#Create a HTML document
function Export-Html ($data) {
	$title = "NSX Firewall Rules"
	$head = "<style type='text/css'> table { border-collapse: collapse; } table, th, td { border: 1px solid black; } </style>"
	$postcontent = "<p>[APP] - Application
			[APPG] - Application Group
			[CLU] - Cluster
			[DC] - Datacenter
			[DFW] - DISTRIBUTED_FIREWALL
			[DVPG] - Distributed vSwitch Portgroup
			[EDGE] - Edge
			[HOST] - Hostsystem
			[IPv4] - Ipv4Address
			[IPv6] - Ipv6Address
			[IPSET] - IPSet
			[STPG] - Standard vSwitch Portgroup
			[RP] - Resource Pool
			[SG] - Security Group
			[VAPP] - Virtual App
			[VM] - VirtualMachine
			[LSWC] - Logical Switch
			[VNIC] - Virtual Machine vNIC
			[NE] - Negate
			</p>"

	return (($data | ConvertTo-Html -Head $head -Title "NSX Firewall Rules" -PostContent $postcontent) -replace $eol,"<br />")
}

#Convert XML to PSObject
function Parse-L3FWRules($sections) {

	$result = @()
	foreach ($section in $sections) {
		$rules = $section.rule
		foreach ($rule in $rules) {
			$result += $rule | select @{Label="section"; Expression={
						$section.name
					}},
					disabled,
					id,
					name,
					@{Label="source"; Expression={
						Format-Entries ($_.sources)
					}},
					@{Label="destination"; Expression={
						Format-Entries ($_.destinations) 
					}},
					@{Label="services"; Expression={
						Format-Entries ($_.services) 
					}},
					@{Label="applied to"; Expression={
						Format-Entries ($_.appliedToList) 
					}},
					action,
					direction,
					logged
		}
	}

	return $result
}

function Get-NSXFirewallConfig {
	
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem) {
return true;
}
}
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	function Get-BasicAuthCreds {
		param([string]$Username,[string]$Password)
		$AuthString = "{0}:{1}" -f $Username,$Password
		$AuthBytes  = [System.Text.Encoding]::Ascii.GetBytes($AuthString)
		return [Convert]::ToBase64String($AuthBytes)
	}
	
	$Credentials = Get-BasicAuthCreds -Username $Username -Password $Password
	$Uri = "https://" + $NSXManager + "/api/4.0/firewall/globalroot-0/config"
	$response = Invoke-WebRequest -Method Get -Uri $Uri -Headers @{"Authorization"="Basic $Credentials"}
	
	if($response.StatusCode -eq 200) {
		return ($response.Content)
	}
}

if($Format -eq "CSV") {
	$eol = ", "
}
else {
	$eol = "`n"
}

if($FilePath -ne "") {
	$doc = [xml] (Get-Content $FilePath)
	$sections = $doc.firewallDraft.config.layer3Sections.section
}
elseif($NSXManager -ne $null) {
	$doc = [xml] (Get-NSXFirewallConfig);
	$sections = $doc.firewallConfiguration.layer3Sections.section
}
else {
	return
}

$l3rules = Parse-L3FWRules($sections)

if($Property -ne "") {
	$Properties = $Property.Split(",")
	$l3rules = $l3rules | Select $Properties
}

switch ($Format) {
	"CSV"		{ $l3rules | Export-CSV -Path $ResultPath }
	"HTML"		{ Export-Html($l3rules) > $ResultPath }
	"XML"		{ $doc.OuterXml > $ResultPath }
}

return