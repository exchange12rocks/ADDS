<# MIT License

		Copyright (c) 2016 Kirill Nikolaev

		Permission is hereby granted, free of charge, to any person obtaining a copy
		of this software and associated documentation files (the "Software"), to deal
		in the Software without restriction, including without limitation the rights
		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
		copies of the Software, and to permit persons to whom the Software is
		furnished to do so, subject to the following conditions:

		The above copyright notice and this permission notice shall be included in all
		copies or substantial portions of the Software.

		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
		SOFTWARE.
#>

#Requires -Version 3.0
#Requires -Modules DnsServer, DnsClient

<# EvendIds:
		10 - Unspecified error
		20 - Cannot get data from the input DNS records file
		21 - Cannot get data from the input NS file
		25 - Cannot write back into the input file
		27 - Cannot write into text log 
		30 - Wrong type of a DNS record
		35 - Multiple records with different types returned 
		40 - DNS record doesn't exist @ NS
		43 - NS is unreachable
		47 - Resolve-DnsName cmdlet failed to resolve DNS record
		50 - Could not find suitable set of NS for a record in the input NS file
		51 - Single-labeled records are not supported yet
		55 - DNS-zone creation is not yet supported
		70 - Function Sync-DnsRecord failed
		72 - Function New-DnsRecord failed
		74 - Function Update-DnsRecord failed
		80 - Cannot import DNSServer PowerShell module
		82 - Cannot import DNSClient PowerShell module
		90 - Remove-DnsServerResourceRecord cmdlet @ internal NS failed
		95 - Get-DnsServerResourceRecord cmdlet @ internal NS failed
		96 - Add-DnsServerResourceRecordCName cmdlet @ internal NS failed
		97 - Add-DnsServerResourceRecordA cmdlet @ internal NS failed
		100 - Start
		105 - Finish
#>

[CmdletBinding()]
Param(
	[string]$SMTPFrom = 'DNSUpdater@example.com',
	[string[]]$SMTPTo = @('DNS-Administrators@example.com', 'AD-Administrators@example.com'),
	[string[]]$SMTPCc = @(),
	[string]$SMTPServer = 'smtp.example.com',
	[string]$EventLogLogName = 'DNS Zones Synchronizer',
	[string]$ErrorMailBodyPrefix = '',
	[string]$ErrorMailSubjectPrefix = ''
)

$ErrorActionPreference = 'Stop'

function Register-EventLog {
	[CmdletBinding()]
	Param (
		[string]$LogName = $script:EventLogLogName,
		[string]$SourceName = $script:EventLogSourceName,
		[int]$MaximumSize = 10240KB,
		[Diagnostics.OverflowAction]$OverFlowAction = 'OverwriteAsNeeded'

	)
	try { # TODO: New-EventLog doesn't support ShouldProcess
		New-EventLog -LogName $LogName -Source $SourceName
		}
	catch {
		Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot create new event log {0}' -f $LogName) -TextLog -Exit
	}
	try { #TODO: Limit-EventLog will fail if the event log does not exists even in ShouldProcess mode
		Limit-EventLog -LogName $LogName -MaximumSize $MaximumSize -OverFlowAction $OverFlowAction
	}
	catch {
		Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot set properties for event log {0}' -f $LogName) -TextLog -Exit
	}
}

function Add-ToEventLog {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Message to write into the log')]
		[string]$Message,
		[int]$EventId = 0,
		[Diagnostics.EventLogEntryType]$EntryType = 'Information',
		[string]$LogName = $script:EventLogLogName,
		[string]$SourceName = $script:EventLogSourceName
	)
    
	[bool]$LogRegistered = $False

	try {
		$LogRegistered = [Diagnostics.EventLog]::SourceExists($SourceName)
	}
	catch {
		if ($Error[0].FullyQualifiedErrorId -eq 'SecurityException') {
			$LogRegistered = $False
		}
		else {
			Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot determine if {0} is registered' -f $LogName) -TextLog -Exit
		}
	}

	if (!$LogRegistered) {
		try {
			Register-EventLog -LogName $LogName -SourceName $SourceName
		}
		catch {
			Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot register event log {0}' -f $LogName) -TextLog -Exit
		}
	}
	try { # TODO: Write-EventLog doesn't support ShouldProcess
		Write-EventLog -LogName $LogName -Source $SourceName -Message $Message -EventId $EventId -EntryType $EntryType
	}
	catch {
		Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot write into event log {0} with source {1}' -f $LogName, $SourceName) -TextLog -Exit
	}
}

function Add-ToTextLog {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Message to write into the log-file')]
		[string]$Message,
		[string]$LogPath = $script:TextLogPath
	)
	try {
		Add-Content -Path $LogPath -Value $Message
	}
	catch {
		Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot write into text log {0}' -f $LogPath) -EventId 27 -EventLog -Exit
	}
}

function Invoke-ErrorProcessing {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Error object to process')]
		[Management.Automation.ErrorRecord]$ErrorRecord,
		[Parameter(Mandatory,
		HelpMessage='Message to write into logs')]
		[string]$Message,
		[switch]$Exit,
		[bool]$Mail=$false,
		[string]$SMTPFrom=$script:SMTPFrom,
		[array]$SMTPTo=$script:SMTPTo,
		[array]$SMTPCc=$script:SMTPCc,
		[string]$SMTPServer=$script:SMTPServer,
		[switch]$TextLog,
		[string]$TextLogPath=$script:TextLogPath,
		[switch]$EventLog,
		[string]$EventLogLogName=$script:EventLogLogName,
		[string]$EventLogSourceName=$script:EventLogSourceName,
		[int]$EventId=0
	)

	$ErrorMessage = ("{0}. The error was:`r`n{1}`r`n{2}" -f $Message, $ErrorRecord.Exception.Message, $ErrorRecord.InvocationInfo.PositionMessage)

	if ($EventLog) {
		Add-ToEventLog -LogName $EventLogLogName -SourceName $EventLogSourceName -Message $ErrorMessage -EventId $EventId -EntryType Error
	}

	if ($TextLog) {
		Add-ToTextLog -Message $ErrorMessage
	}

	if ($Exit -and $TextLog) {
		Add-ToTextLog -Message 'Exiting...'
	}
	if ($Mail) {
		if ($ErrorMailSubjectPrefix) {
			$Subject = ('{0} ' -f $ErrorMailSubjectPrefix)
		}
		$Subject += ('Error in {0} script @ {1}' -f $script:ScriptName, $env:COMPUTERNAME)

		if ($ErrorMailBodyPrefix) {
			$Body = ("{0}`r`n`r`n{1}" -f $ErrorMailBodyPrefix, $ErrorMessage)
		}
		else {
			$Body = $ErrorMessage
		}

		if ($TextLog) { # TODO: Send-MailMessage doesn't support ShouldProcess
			Send-MailMessage -From $SMTPFrom -Subject $Subject -To $SMTPTo -Cc $SMTPCc -Body ("{0}`r`n`r`nSee log-file attached for more information." -f $Body) -SmtpServer $SMTPServer -Attachments $TextLogPath -ErrorAction Stop
		}
		else {
			Send-MailMessage -From $SMTPFrom -Subject $Subject -To $SMTPTo -Cc $SMTPCc -Body $Body -SmtpServer $SMTPServer -ErrorAction Stop
		}
	}

	if ($Exit) {
		Exit
	}
}

Function Sync-DnsRecord {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Type of the DNS record')]
		[ValidateSet('A','CNAME')]
		[Microsoft.DnsClient.Commands.RecordType]$RecordType,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS record')]
		[ValidateLength(1,63)]
		[string]$RecordName,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS zone for the record')]
		[ValidateLength(1,127)]
		[string]$ZoneName,

		[Parameter(Mandatory,
		HelpMessage='Data for the DNS record')]
		[string[]]$RecordData,
        
		[Parameter(Mandatory,
		HelpMessage='Name Server IP address')]
		[ipaddress]$NSIP,

		[Parameter(HelpMessage='Action to do: to update the DNS record by default, or to create it, if this parameter is specified')]
		[switch]$Create
	)

	if ($RecordName -eq '.') { # Special case to process records for the zone itself.
		if ($RecordType -eq 'CNAME') { # CNAMEs at the zone level are not yet supported.
			return $null
		}
		else {
			if ($Create) { # We do not yet support creation of DNS-zones.
				$Message = ('DNS-zone creation ({0}) is not yet supported.' -f $ZoneName)
				Add-ToTextLog -Message $Message
				Add-ToEventLog -Message $Message -EventId 55 -EntryType Warning
				return $null
			}
		}
	}

	if ($Create) {
		try {
			New-DnsRecord -RecordType $RecordType -RecordName $RecordName -RecordData $RecordData -ZoneName $ZoneName -NSIP $NSIP
		}
		catch {
			Invoke-ErrorProcessing -Message ('Function New-DnsRecord failed: RecordName - {0}, ZoneName - {1}, RecordType - {2}, Action - {3}, RecordData - {4}' -f $RecordName, $ZoneName, $RecordType, $Action, $RecordData) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 72
		}
	}
	else {
		try {
			Update-DnsRecord -RecordType $RecordType -RecordName $RecordName -RecordData $RecordData -ZoneName $ZoneName -NSIP $NSIP
		}
		catch {
			Invoke-ErrorProcessing -Message ('Function Update-DnsRecord failed: RecordName - {0}, ZoneName - {1}, RecordType - {2}, Action - {3}, RecordData - {4}' -f $RecordName, $ZoneName, $RecordType, $Action, $RecordData) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 74
		}
	}
}

function Update-DnsRecord {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Type of the DNS record')]
		[ValidateSet('A','CNAME')]
		[Microsoft.DnsClient.Commands.RecordType]$RecordType,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS record')]
		[ValidateLength(1,63)]
		[string]$RecordName,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS zone for the record')]
		[ValidateLength(1,127)]
		[string]$ZoneName,

		[Parameter(Mandatory,
		HelpMessage='Data for the DNS record')]
		[string[]]$RecordData,
        
		[Parameter(Mandatory,
		HelpMessage='Name Server IP address')]
		[ipaddress]$NSIP
	)

	if ($RecordName -eq '.') {
		Add-ToTextLog -Message ('(Get-DnsServerResourceRecord -ZoneName {0} -Name {1} -ComputerName {2} -Node | Where-Object {$_.HostName -eq ''@'' -and $_.RecordType -in (''A'', ''CNAME'')}).RecordType' -f $ZoneName, $RecordName, $NSIP)
		try {
			$RecordTypeInt = (Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $RecordName -ComputerName $NSIP -Node | Where-Object {$_.HostName -eq '@' -and $_.RecordType -in ('A', 'CNAME')}).RecordType
		}
		catch {
			Invoke-ErrorProcessing -Message ("Get-DnsServerResourceRecord cmdlet for '{0}' record in '{1}' zone  @ internal NS {2} failed" -f $RecordName, $ZoneName, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 95
			return $null
		}
	}
	else {
		Add-ToTextLog -Message ('(Get-DnsServerResourceRecord -ZoneName {0} -Name {1} -ComputerName {2} -Node).RecordType' -f $ZoneName, $RecordName, $NSIP)
		try {
			$RecordTypeInt = (Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $RecordName -ComputerName $NSIP -Node).RecordType
		}
		catch {
			if ($Error[0].CategoryInfo.Category -eq 'ObjectNotFound') { # If Resolve-DNSName cmdlet has returned record data, but they are not available via WMI, this means there is a wildcard-record exists.
				New-DnsRecord -RecordType $RecordType -RecordName $RecordName -ZoneName $ZoneName -RecordData $RecordData -NSIP $NSIP # Therefore, we need to switch to create the record rather than updating one.
				return $null
			}
			else {
				Invoke-ErrorProcessing -Message ("Get-DnsServerResourceRecord cmdlet for '{0}' record in '{1}' zone @ internal NS {2} failed" -f $RecordName, $ZoneName, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 95
				return $null
			}
		}
	}

	if ($RecordTypeInt -is 'System.Array') {
		$RecordTypeInt = $RecordTypeInt | Select-Object -Unique
		if ($RecordTypeInt -is 'System.Array') {
			$Message = ("Multiple records with different types returned for the name '{0}' in '{1}' zone at NS {2}" -f $RecordName, $ZoneName, $NSIP)
			Add-ToTextLog -Message $Message
			Add-ToEventLog -Message $Message -EventId 35 -EntryType Error
			return $null
		}
	}

	if ($RecordTypeInt -in ('A','CNAME')) {
		Add-ToTextLog -Message ('Remove-DnsServerResourceRecord -Name {0} -ZoneName {1} -RRType {2} -ComputerName {3} -Force' -f $RecordName, $ZoneName, $RecordTypeInt, $NSIP)
		try {
			Remove-DnsServerResourceRecord -Name $RecordName -ZoneName $ZoneName -RRType $RecordTypeInt -ComputerName $NSIP -Force
		}
		catch {
			Invoke-ErrorProcessing -Message ("Remove-DnsServerResourceRecord cmdlet for '{0}' record of type '{1}' in '{2}' zone @ internal NS {3} failed" -f $RecordName, $RecordTypeInt, $ZoneName, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 90
		}

		New-DnsRecord -RecordType $RecordType -RecordName $RecordName -ZoneName $ZoneName -RecordData $RecordData -NSIP $NSIP
	}
	else {
		$Message = ('Wrong type of internal record: Name - {0}, Zone - {1}, Type - {2}' -f $RecordName, $ZoneName, $RecordType)
		Add-ToTextLog -Message $Message
		Add-ToEventLog -Message $Message -EventId 30 -EntryType Error
		return $null
	}
}

function New-DnsRecord {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Type of the DNS record')]
		[ValidateSet('A','CNAME')]
		[Microsoft.DnsClient.Commands.RecordType]$RecordType,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS record')]
		[ValidateLength(1,63)]
		[string]$RecordName,
        
		[Parameter(Mandatory,
		HelpMessage='Data for the DNS record')]
		[string[]]$RecordData,

		[Parameter(Mandatory,
		HelpMessage='Name of the DNS zone for the record')]
		[ValidateLength(1,127)]
		[string]$ZoneName,
        
		[Parameter(Mandatory,
		HelpMessage='Name Server IP address')]
		[ipaddress]$NSIP
	)

	switch ($RecordType) {
		'CNAME' {
			foreach ($RecordEntry in $RecordData) {
				Add-ToTextLog -Message ('Add-DnsServerResourceRecordCName -HostNameAlias {0} -Name {1} -ZoneName {2} -ComputerName {3}' -f $RecordEntry, $RecordName, $ZoneName, $NSIP)
				try {
					Add-DnsServerResourceRecordCName -HostNameAlias $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIP
				}
				catch {
					Invoke-ErrorProcessing -Message ("Add-DnsServerResourceRecordCName cmdlet for '{0}' record of type CNAME in '{1}' zone @ internal NS {2} failed" -f $RecordName, $ZoneName, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 96
				}
			}
		Break}
		'A' {
			foreach ($RecordEntry in $RecordData) {
				Add-ToTextLog -Message ('Add-DnsServerResourceRecordA -IPv4Address {0} -Name {1} -ZoneName {2} -ComputerName {3}' -f $RecordEntry, $RecordName, $ZoneName, $NSIP)
				try {
					Add-DnsServerResourceRecordA -IPv4Address $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIP
				}
				catch {
					Invoke-ErrorProcessing -Message ("Add-DnsServerResourceRecordA cmdlet for '{0}' record of type 'A' in '{1}' zone @ internal NS {2} failed" -f $RecordName, $ZoneName, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 97
				}
			}
		Break}
		Default {
			$Message = ('Wrong type of a record: Name - {0}, Zone - {1}, Type - {2}' -f $RecordName, $ZoneName, $RecordType)
			Add-ToTextLog -Message $Message
			Add-ToEventLog -Message $Message -EventId 30 -EntryType Error
			return $null
		}
	}
}

function Receive-DnsData {
	Param (
		[Parameter(Mandatory,
		HelpMessage='Host name for which the function will retrieve data')]
		[string]$RecordName,
		[Parameter(Mandatory,
		HelpMessage='Zone name where to look for the host')]
		[string]$ZoneName,
		[Parameter(Mandatory,
		HelpMessage='DNS server IP address which use for lookup')]
		[ipaddress]$NSIP,
		[switch]$External,
		[Microsoft.DnsClient.Commands.RecordType[]]$RecordType = ('A', 'CNAME')
	)

	function Invoke-LocalSpecificErrorProcessing {
        Param (
            [switch]$EventLog,
            [string]$FullRecordName,
            [Microsoft.DnsClient.Commands.RecordType[]]$RecordType,
            [string]$NSTypeText,
            [ipaddress]$NSIP
        )

		$RecordTypeAsAString = ''
		foreach ($Type in $RecordType) {
			$RecordTypeAsAString += ('{0},' -f $Type)
		}
		$Message = ("DNS name '{0}' of type(s) '{1}' doesn't exist @ {2} NS {3}" -f $FullRecordName, $RecordTypeAsAString, $NSTypeText, $NSIP)
		if ($EventLog) {
			Add-ToEventLog -Message $Message -EventId 40 -EntryType Error
		}
		Add-ToTextLog -Message $Message
		Continue
	}

	if ($External) {
		$NSTypeText = 'external'
		$EventLogRequired = $True
	}
	else {
		$NSTypeText = 'internal'
		$EventLogRequired = $False
	}

	if ($RecordName -eq '.') { # The function accepts a dot in $RecordName parameter as an indicator that the record is at the zone level.
		$FullRecordName = $ZoneName
	}
	else {
		$FullRecordName = ('{0}.{1}' -f $RecordName, $ZoneName)
	}

	Try {
		$Answer = Resolve-DnsName -Name $FullRecordName -Server $NSIP -Type ALL | Where-Object {$_.Name -eq $FullRecordName -and $RecordType -contains $_.QueryType}
	}
	Catch {
		if ($Error[0].CategoryInfo.Category -eq 'ResourceUnavailable') {
			Invoke-ErrorProcessing -Message ("DNS record '{0}' doesn't exist @ {1} NS {2}" -f $FullRecordName, $NSTypeText, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog:$EventLogRequired -EventId 40
			return $null
		}
		elseif ($Error[0].CategoryInfo.Category -eq 'OperationTimeout') {
			Invoke-ErrorProcessing -Message ('{0} NS {1} is unreachable' -f $NSTypeText, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 43
			Continue
		}
		else {
			Invoke-ErrorProcessing -Message ("Resolve-DnsName cmdlet failed to resolve '{0}' against {1} NS {2}" -f $FullRecordName, $NSTypeText, $NSIP) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 47
			Continue
		}
	}
	if ($Answer) {
		if ($Answer.Type) {
			if (($Answer.Type | Select-Object -Unique).GetType().FullName -ne 'Microsoft.DnsClient.Commands.RecordType') { # While multiple records with different types are not the case for 'CNAME' and 'A' types of records, some rogue DNS-server still might allow creation of both of them. Furthermore, you may, try to synchronize records of another types.
				$Message = ("Multiple records with different types returned for the name '{0}' from {1} NS {2}" -f $FullRecordName, $NSTypeText, $NSIP)
				Add-ToTextLog -Message $Message
				Add-ToEventLog -Message $Message -EventId 35 -EntryType Error
				Continue
			}
		}
		else {
			Invoke-LocalSpecificErrorProcessing -EventLog:$EventLogRequired -FullRecordName $FullRecordName -RecordType $RecordType -NSTypeText $NSTypeText -NSIP $NSIP
		}
		return $Answer
	}
	else {
		Invoke-LocalSpecificErrorProcessing -EventLog:$EventLogRequired -FullRecordName $FullRecordName -RecordType $RecordType -NSTypeText $NSTypeText -NSIP $NSIP
	}
}

function Optimize-DnsRecord {
    [OutputType([String[]])]
    Param (
        [Parameter(Mandatory,
        HelpMessage='DNS record object to strip.')]
        [Microsoft.DnsClient.Commands.DnsRecord[]]$DnsRecord,
        [bool]$Skip = $true,
        [switch]$External
    )

    if ($External) {
        $NSTypeText = 'external'
    }
    else {
        $NSTypeText = 'internal'
    }

    $RecordType = $DnsRecord[0].Type
    switch ($RecordType) {
        'CNAME' {
            $RecordData = $DnsRecord.NameHost | Select-Object -Unique
            Break
        }
        'A' {
            $RecordData = $DnsRecord.IPAddress | Select-Object -Unique
            Break
        }
        Default {
            $Message = ("Type '{0}' of a record for '{1}' @ {2} NS is incompatible." -f $RecordType, $DnsRecord.Name, $NSTypeText)
            Add-ToTextLog -Message $Message
            Add-ToEventLog -Message $Message -EventId 30 -EntryType Error
            if ($Skip) {
                Continue
            }
        }
    }

    return $RecordData
}

function Optimize-Records {
    [CmdletBinding()]
    Param (
        [string]$FilePath = $Script:InRECFilePath
    )

    Try {
        $RecordNames = Get-Content -Path $FilePath
    }
    Catch {
        Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot get data from {0} file' -f $FilePath) -EventId 20 -EventLog -TextLog -Exit
    }

    $RecordNames = $RecordNames | Sort-Object -Unique # To ease troubleshooting process, we sort the list before processing, then leave only unique records.

    Try {
        Set-Content -Path $FilePath -Value $RecordNames
    }
    Catch {
        Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot write back into {0} file' -f $FilePath) -EventId 25 -EventLog -TextLog -Exit
    }

    return $RecordNames
}

function Get-RecordSet {
    Param (
        [Parameter(Mandatory,
        HelpMessage='FQDN for which appropriate NS set will be searched.')]
        [ValidateLength(1,63)]
        [string]$RecordName,
        [string]$NSFilePath = $script:InNSFilePath
    )

    Try {
        $NSData = Import-Csv -Path $NSFilePath -Delimiter ';'
    }
    Catch {
        Invoke-ErrorProcessing -ErrorRecord $Error[0] -Message ('Cannot get data from {0} file' -f $InNSFilePath) -EventId 21 -EventLog -TextLog -Exit
    }

    if ($RecordName -match '\.') { # Is this is a NOT single-labeled record?
        $NSSet = $NSData | Where-Object {$_.Zone -eq $RecordName}

        if ($NSSet) {
            $RecordName = '.'
        }
        else {
            $RecordNameSplitted = $RecordName.Split('.')

            for ($Counter = 1; $Counter -lt $RecordNameSplitted.Count; $Counter++) {
                $RecordNameTrimmed = ''
                for ($Counter2 = $Counter; $Counter2 -lt $RecordNameSplitted.Count; $Counter2++) {
                    $RecordNameTrimmed += $RecordNameSplitted[$Counter2]

                    if ($Counter2 -lt $RecordNameSplitted.Count-1) {
                        $RecordNameTrimmed += '.'
                    }
                }
                $NSSet = $NSData | Where-Object {$_.Zone -eq $RecordNameTrimmed}
                if ($NSSet) {
                    $RecordNameTemp = ''
                    for ($Counter2 = 0; $Counter2 -lt $Counter; $Counter2++) {
                        $RecordNameTemp += $RecordNameSplitted[$Counter2]
                        if ($Counter2 -lt $Counter-1) {
                            $RecordNameTemp += '.'
                        }
                    }
                    $RecordName = $RecordNameTemp
                    break
                }
            }
        }

        return [pscustomobject]@{
            NSSet = $NSSet
            RecordName = $RecordName
        }
    }
    else { # If it IS a single-labeled record, stop its processing.
        $Message = ('Single-labeled records, like {0}, are not supported yet.' -f $RecordName)
        Add-ToTextLog -Message $Message
        Add-ToEventLog -Message $Message -EventId 51 -EntryType Warning
        return $null
    }
}

$CurrentMoment = Get-Date
if ($CurrentMoment.Month -lt 10) {
    $CurrentMonth = ('0{0}' -f $CurrentMoment.Month) # Add leading zero if number of month is single-digit
}
else {
    $CurrentMonth = $CurrentMoment.Month
}
if ($CurrentMoment.Day -lt 10) {
    $CurrentDay = ('0{0}' -f $CurrentMoment.Day) # Add leading zero if number of day is single-digit
}
else {
    $CurrentDay = $CurrentMoment.Day
}
$CurrentYear = $CurrentMoment.Year

$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Path
$ScriptName = ($MyInvocation.MyCommand.Name).Substring(0,($MyInvocation.MyCommand.Name).Length-4)

$InRECFilePath = Join-Path -Path $ScriptPath -ChildPath ('{0}-REC.txt' -f $ScriptName)
$InNSFilePath = Join-Path -Path $ScriptPath -ChildPath ('{0}-NS.txt' -f $ScriptName)
$TextLogPath = Join-Path -Path $ScriptPath -ChildPath ('{0}-{1}-{2}-{3}.txt' -f $ScriptName, $CurrentYear, $CurrentMonth, $CurrentDay)
$EventLogSourceName = $ScriptName

try {
    Import-Module -Name DnsServer
}
catch {
    Invoke-ErrorProcessing -Message 'Cannot import DNSServer PowerShell module' -ErrorRecord $Error[0] -EventId 80 -EventLog -TextLog -Exit
}

try {
    Import-Module -Name DnsClient
}
catch {
    Invoke-ErrorProcessing -Message 'Cannot import DNSClient PowerShell module' -ErrorRecord $Error[0] -EventId 82 -EventLog -TextLog -Exit
}

$null = Resolve-DnsName -Name ([Environment]::MachineName) -ErrorAction Ignore # Dirty hack to load all required classes

$Message = ('START {0}' -f $CurrentMoment)
Add-ToTextLog -Message $Message
Add-ToEventLog -Message $Message -EventId 100 -EntryType Information

$RecordNames = Optimize-Records -FilePath $InRECFilePath

foreach ($RecordName in $RecordNames){
    if ($RecordName -and $RecordName -notmatch '^\s+$') { # If the line is empty or just spaces, we ignore it.
        [bool]$Action = $false
        Add-ToTextLog -Message ('RecordName: {0}' -f $RecordName)

        $RecordSet = Get-RecordSet -RecordName $RecordName

        if ($RecordSet) {
            $NSIPInt = $RecordSet.NSSet.IntIP
            $NSIPExt = $RecordSet.NSSet.ExtIP
            $ZoneName = $RecordSet.NSSet.Zone
            $RecordName = $RecordSet.RecordName

            $AnswerExt = Receive-DnsData -RecordName $RecordName -ZoneName $ZoneName -NSIP $NSIPExt -External
            if ($AnswerExt) {
                $RecordTypeExt = $AnswerExt.Type | Select-Object -Unique # We assume that Receive-DnsData returns records of the same type only, therefore, we can safely determine their type by picking any one.
                Add-ToTextLog -Message ('RecordName: {0}, ZoneName: {1}, RecordTypeExt: {2}' -f $RecordName, $ZoneName, $RecordTypeExt)

                $AnswerInt = Receive-DnsData -RecordName $RecordName -ZoneName $ZoneName -NSIP $NSIPInt

                $RecordDataExt = Optimize-DnsRecord -DnsRecord $AnswerExt -External

                Add-ToTextLog -Message ('RecordName: {0}, ZoneName: {1}, RecordTypeExt: {2}, RecordDataExt: {3}' -f $RecordName, $ZoneName, $RecordTypeExt, $RecordDataExt)

                if ($AnswerInt) {
                    $RecordTypeInt = $AnswerInt.Type | Select-Object -Unique # We assume that Receive-DnsData returns records of the same type only, therefore, we can safely determine their type by picking any one.
                    $RecordDataInt = Optimize-DnsRecord -DnsRecord $AnswerInt
                    Add-ToTextLog -Message ('RecordName: {0}, ZoneName: {1}, RecordTypeExt: {2}, RecordDataExt: {3}, RecordTypeInt: {4}, RecordDataInt: {5}' -f $RecordName, $ZoneName, $RecordTypeExt, $RecordDataExt, $RecordTypeInt, $RecordDataInt)
                }
                else {
                    $Action = $true
                }
            }
            else {
                Continue
            }

            if ($Action -and ($RecordName -eq '.')) {
                $Message = ('DNS-zone creation ({0}) is not yet supported.' -f $ZoneName)
                Add-ToTextLog -Message $Message
                Add-ToEventLog -Message $Message -EventId 55 -EntryType Warning
                Continue
            }
            else {
                if (!$Action) {
                    $Compared = Compare-Object -ReferenceObject $RecordDataExt -DifferenceObject $RecordDataInt
                }
                if ($Action -or $Compared) {
                    Try {
                        Sync-DnsRecord -RecordType $RecordTypeExt -RecordName $RecordName -ZoneName $ZoneName -RecordData $RecordDataExt -NSIP $NSIPInt -Create:$Action
                    }
                    Catch {
                        Invoke-ErrorProcessing -Message ('Function Sync-DnsRecord failed: RecordName - {0}, ZoneName - {1}, RecordType - {2},  RecordData - {3}, Action - {4}' -f $RecordName, $ZoneName, $RecordTypeExt, $RecordDataExt, $Action) -ErrorRecord $Error[0] -TextLog -EventLog -EventId 70
                        Continue
                    }
                }
                else {
                    Add-ToTextLog -Message ("Internal and external records '{0}' in '{1}' zone are the same" -f $RecordName, $ZoneName)
                }
            }
        }
        else {
            $Message = ('Could not find suitable set of NS for {0} record in the input file {1}.' -f $RecordName, $InNSFilePath)
            Add-ToTextLog -Message $Message
            Add-ToEventLog -Message $Message -EventId 50 -EntryType Warning
            Continue
        }
    }
}

$CurrentMoment = Get-Date
$Message = ('END {0}' -f $CurrentMoment)
Add-ToTextLog -Message $Message
Add-ToEventLog -Message $Message -EventId 105 -EntryType Information