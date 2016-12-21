<#MIT License

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
SOFTWARE. #>

#Requires -Version 3.0
#Requires -Modules DnsServer

#EvendIds:
#10 - Unspecified error
#20 - Cannot get data from the input DNS records file
#21 - Cannot get data from the input NS file
#25 - Cannot write back into the input file
#27 - Cannot write into text log 
#30 - Wrong type of a DNS record
#35 - Multiple records with different types returned 
#40 - DNS record doesn't exist @ NS
#43 - NS is unreachable
#47 - Resolve-DnsName cmdlet failed to resolve DNS record
#50 - Could not find suitable set of NS for a record in the input NS file
#51 - Single-labeled records are not supported yet
#70 - Function Update-DnsRecord failed
#80 - Cannot import DNSServer PowerShell module
#90 - Remove-DnsServerResourceRecord cmdlet @ internal NS failed
#95 - Get-DnsServerResourceRecord cmdlet @ internal NS failed
#96 - Add-DnsServerResourceRecordCName cmdlet @ internal NS failed
#97 - Add-DnsServerResourceRecordA cmdlet @ internal NS failed
#100 - Start
#105 - Finish

$ErrorActionPreference = 'Stop'

function Register-EventLog {
    Param(
        [Parameter(Mandatory=$False)]
        [string]$LogName = $script:EventLogLogName,
        [Parameter(Mandatory=$False)]
        [string]$SourceName = $script:EventLogSourceName,
        [Parameter(Mandatory=$False)]
        [int64]$MaximumSize = 10240KB,
        [Parameter(Mandatory=$False)]
        [System.Diagnostics.OverflowAction]$OverFlowAction = 'OverwriteAsNeeded'

    )
    try {
        New-EventLog -LogName $LogName -Source $SourceName
        }
    catch {
        Process-Error -ErrorRecord $Error[0] -Message "Cannot create new event log $LogName" -TextLog -Exit
    }
    try {
        Limit-EventLog -LogName $LogName -MaximumSize $MaximumSize -OverFlowAction $OverFlowAction
    }
    catch {
        Process-Error -ErrorRecord $Error[0] -Message "Cannot set properties for event log $LogName" -TextLog -Exit
    }
}

function Add-ToEventLog {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Message,
        [Parameter(Mandatory=$False)]
        [int32]$EventId = 0,
        [Parameter(Mandatory=$False)]
        [System.Diagnostics.EventLogEntryType]$EntryType = 'Information',
        [Parameter(Mandatory=$False)]
        [string]$LogName = $script:EventLogLogName,
        [Parameter(Mandatory=$False)]
        [string]$SourceName = $script:EventLogSourceName
    )

    [bool]$LogRegistered = $False

    try {
        $LogRegistered = [System.Diagnostics.EventLog]::SourceExists($SourceName)
    }
    catch {
        if ($Error[0].FullyQualifiedErrorId -eq 'SecurityException') {
            $LogRegistered = $False
        }
        else {
            Process-Error -ErrorRecord $Error[0] -Message "Cannot determine if $LogName is registered" -TextLog -Exit
        }
    }

    if (!$LogRegistered) {
        try {
            Register-EventLog -LogName $LogName -SourceName $SourceName
        }
        catch {
            Process-Error -ErrorRecord $Error[0] -Message "Cannot register event log $LogName" -TextLog -Exit
        }
    }
    try {
        Write-EventLog -LogName $LogName -Source $SourceName -Message $Message -EventId $EventId -EntryType $EntryType
    }
    catch {
        Process-Error -ErrorRecord $Error[0] -Message "Cannot write into event log $LogName with source $SourceName" -TextLog -Exit
    }
}

function Add-ToTextLog {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Message,
        [Parameter(Mandatory=$False)]
        [string]$LogPath = $script:TextLogPath
    )
    try {
        Add-Content $LogPath $Message
    }
    catch {
        Process-Error -ErrorRecord $Error[0] -Message "Cannot write into text log $LogPath" -EventId 27 -EventLog -Exit
    }
}

function Process-Error {
	Param(
		[Parameter(Mandatory=$True)]
		[System.Management.Automation.ErrorRecord]$ErrorRecord,
		[Parameter(Mandatory=$True)]
		[string]$Message,
		[Parameter(Mandatory=$False)]
		[switch]$Exit,
		[Parameter(Mandatory=$False)]
		[bool]$Mail=$false,
		[Parameter(Mandatory=$False)]
		[string]$SMTPFrom=$script:SMTPFrom,
		[Parameter(Mandatory=$False)]
		[System.Array]$SMTPTo=$script:SMTPTo,
		[Parameter(Mandatory=$False)]
		[System.Array]$SMTPCc=$script:SMTPCc,
		[Parameter(Mandatory=$False)]
		[string]$SMTPServer=$script:SMTPServer,
		[Parameter(Mandatory=$False)]
		[switch]$TextLog,
		[Parameter(Mandatory=$False)]
		[string]$TextLogPath=$script:TextLogPath,
		[Parameter(Mandatory=$False)]
		[switch]$EventLog,
        [Parameter(Mandatory=$False)]
        [string]$EventLogLogName=$script:EventLogLogName,
        [Parameter(Mandatory=$False)]
        [string]$EventLogSourceName=$script:EventLogSourceName,
        [Parameter(Mandatory=$False)]
        [int32]$EventId=0
	)

    $ErrorMessage = "$Message. The error was:`n$($ErrorRecord.Exception.Message)`n$($ErrorRecord.InvocationInfo.PositionMessage)"

    if ($EventLog) {
        Add-ToEventLog -LogName $EventLogLogName -SourceName $EventLogSourceName -Message $ErrorMessage -EventId $EventId -EntryType Error
    }

    if ($TextLog) {
	    Add-ToTextLog $ErrorMessage
    }

    if ($Exit -and $TextLog) {
		Add-ToTextLog 'Exiting...'
	}
	if ($Mail) {
        $Subject = "Error in $script:ScriptName script @ $(hostname)"
        $Body = "To INFRA BS`n`n$ErrorMessage"
        if ($TextLog) {
		    Send-MailMessage -From $SMTPFrom -Subject $Subject -To $SMTPTo -Cc $SMTPCc -Body "$Body`n`nSee log-file attached for more information." -SmtpServer $SMTPServer -Attachments $TextLogPath -ErrorAction Stop
        }
        else {
            Send-MailMessage -From $SMTPFrom -Subject $Subject -To $SMTPTo -Cc $SMTPCc -Body $Body -SmtpServer $SMTPServer -ErrorAction Stop
        }
	}

	if ($Exit) {
		Exit
	}
}

Function Update-DnsRecord {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false,
        HelpMessage='Type of the DNS record')]
        [ValidateSet('A','CNAME')]
        [Microsoft.DnsClient.Commands.RecordType]$RecordType,

        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false,
        HelpMessage='Name of the DNS record')]
        [ValidateLength(1,63)]
        [string]$RecordName,

        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false,
        HelpMessage='Name of the DNS zone for the record')]
        [ValidateLength(1,127)]
        [string]$ZoneName,

        [Parameter(Mandatory=$true,
        ValueFromPipeline=$false,
        HelpMessage='Data for the DNS record')]
        [string[]]$RecordData,

        [Parameter(Mandatory=$false,
        ValueFromPipeline=$false,
        HelpMessage='Action to do: to update the DNS record by default, or to create it, if this parameter is specified')]
        [switch]$Create
    )

    Try {
		If (!$Create) {
        	Add-ToTextLog "(Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $RecordName -ComputerName $NSIPInt).RecordType"
            try {
        	    $RecordTypesInt = (Get-DnsServerResourceRecord -ZoneName $ZoneName -Name $RecordName -ComputerName $NSIPInt).RecordType
            }
            catch {
                if ($Error[0].CategoryInfo.Category -eq 'ObjectNotFound') { # If Resolve-DNSName cmdlet has returned record data, but it is not available via WMI, it means that there is a wildcard-record exists.
                    Update-DnsRecord -RecordType $RecordType -RecordName $RecordName -ZoneName $ZoneName -RecordData $RecordData -Create # Therefore, we need to switch to create mode for this record.
                    return
                }
                else {
                    Process-Error -Message "Get-DnsServerResourceRecord cmdlet for '$RecordName' record in '$ZoneName' zone  @ internal NS $NSIPInt failed" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 95
                    return
                }
            }
        	switch ($RecordTypesInt[0]) {
            	'C' {
                	$RecordTypeInt = 'CName'
            	Break}
            	'A' {
                	$RecordTypeInt = 'A'
            	Break}
            	Default {
                	Process-Error -Message "Wrong type of internal record" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 30
                	return
            	}
        	}
			Add-ToTextLog "Remove-DnsServerResourceRecord -Name $RecordName -ZoneName $ZoneName -RRType $RecordTypeInt -ComputerName $NSIPInt -Force"
            try {
        	    Remove-DnsServerResourceRecord -Name $RecordName -ZoneName $ZoneName -RRType $RecordTypeInt -ComputerName $NSIPInt -Force
            }
            catch {
                Process-Error -Message "Remove-DnsServerResourceRecord cmdlet for '$RecordName' record of type '$RecordTypeInt' in '$ZoneName' zone @ internal NS $NSIPInt failed" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 90
            }
		}
        switch ($RecordType) {
            'CNAME' {
                foreach ($RecordEntry in $RecordData) {
                    Add-ToTextLog "Add-DnsServerResourceRecordCName -HostNameAlias $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIPInt"
                    try {
                        Add-DnsServerResourceRecordCName -HostNameAlias $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIPInt
                    }
                    catch {
                        Process-Error -Message "Add-DnsServerResourceRecordCName cmdlet for '$RecordName' record of type CNAME in '$ZoneName' zone @ internal NS $NSIPInt failed" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 96
                    }
                }
            Break}
            'A' {
                foreach ($RecordEntry in $RecordData) {
                    Add-ToTextLog "Add-DnsServerResourceRecordA -IPv4Address $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIPInt"
                    try {
                        Add-DnsServerResourceRecordA -IPv4Address $RecordEntry -Name $RecordName -ZoneName $ZoneName -ComputerName $NSIPInt
                    }
                    catch {
                        Process-Error -Message "Add-DnsServerResourceRecordA cmdlet for '$RecordName' record of type 'A' in '$ZoneName' zone @ internal NS $NSIPInt failed" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 97
                    }
                }
            Break}
            Default {
                Process-Error -Message "Wrong type of external record: Name - $RecordName, Zone - $ZoneName, Type - $RecordType" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 35
            }
        }
    }
    Catch {
        Process-Error -Message "Unspecified Error: Name - $RecordName, Zone - $ZoneName, Type - $RecordType, Action - $Action, RecordData - $RecordData" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 10
    }
}

function Process-DnsName {
	Param(
		[Parameter(Mandatory=$True)]
		[string]$RecordName,
		[Parameter(Mandatory=$True)]
		[string]$ZoneName,
		[Parameter(Mandatory=$True)]
		[string]$NSIP,
		[Parameter(Mandatory=$False)]
		[switch]$External,
		[Parameter(Mandatory=$False)]
		[Microsoft.DnsClient.Commands.RecordType[]]$RecordType = ('A', 'CNAME')
	)

    if ($External) {
        $NSTypeText = 'external'
        $EventLogRequired = $True
    }
    else {
        $NSTypeText = 'internal'
        $EventLogRequired = $False
    }

    Try {
        $Answer = Resolve-DnsName "$RecordName.$ZoneName" -Server $NSIP -Type ALL | Where-Object {$_.Name -eq "$RecordName.$ZoneName" -and $RecordType -contains $_.QueryType}
    }
    Catch {
        if ($Error[0].CategoryInfo.Category -eq 'ResourceUnavailable') {
            Process-Error -Message "DNS record '$RecordName.$ZoneName' doesn't exist @ $NSTypeText NS $NSIP" -ErrorRecord $Error[0] -TextLog -EventLog:$EventLogRequired -EventId 40
            return $null
        }
        elseif ($Error[0].CategoryInfo.Category -eq 'OperationTimeout') {
            Process-Error -Message "$NSTypeText NS $NSIP is unreachable" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 43
            Continue
        }
        else {
            Process-Error -Message "Resolve-DnsName cmdlet failed to resolve '$RecordName.$ZoneName' against $NSTypeText NS $NSIP" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 47
            Continue
        }
    }
    if ($Answer.Type) {
        if (($Answer.Type | Select-Object -Unique).Count -gt 1) {
            $Message = "Multiple records with different types returned for the name '$RecordName.$ZoneName' from $NSTypeText NS $NSIP"
            Add-ToTextLog $Message
            Add-ToEventLog $Message -EventId 35 -EntryType Error
            Continue
        }
    }
    else {
        $Message = "DNS name '$RecordName.$ZoneName' of type(s) '$RecordType' doesn't exist @ $NSTypeText NS $NSIP"
        if ($External) {
            Add-ToEventLog $Message -EventId 40 -EntryType Error
        }
        Add-ToTextLog $Message
        Continue
    }

    return $Answer
}

function Clean-DnsRecord {
    [OutputType([System.String[]])]
    Param(
        [Parameter(Mandatory=$true)]
        [Microsoft.DnsClient.Commands.DnsRecord[]]$DnsRecord,
        [Parameter(Mandatory=$False)]
        [bool]$Skip = $true,
		[Parameter(Mandatory=$False)]
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
            $Message = "Type '$RecordType' of a record for '$($DnsRecord.Name)' @ $NSTypeText NS is incompatible."
            Add-ToTextLog $Message
            Add-ToEventLog $Message -EventId 30 -EntryType Error
            if ($Skip) {
                Continue
            }
        }
    }

    return $RecordData
}

try {
    Import-Module DnsServer
}
catch {
    Process-Error -Message 'Cannot import DNSServer PowerShell module' -ErrorRecord $Error[0] -EventId 80 -EventLog -TextLog -Exit
}

Resolve-DnsName -Name ([System.Environment]::MachineName) -ErrorAction Ignore | Out-Null # dirty hack to load all required classes

$SMTPServer = 'smtp.example.com'
$SMTPFrom = 'DNSUpdater@example.com'
$SMTPTo = 'Administrators@example.com'
#TODO: Parametrize

$CurrentMoment = Get-Date
if ($CurrentMoment.Month -lt 10) {
	$CurrentMonth = "0$($CurrentMoment.Month)" #Add leading zero if number of month is single-digit
}
else {
	$CurrentMonth = $CurrentMoment.Month
}
if ($CurrentMoment.Day -lt 10) {
	$CurrentDay = "0$($CurrentMoment.Day)" #Add leading zero if number of day is single-digit
}
else {
	$CurrentDay = $CurrentMoment.Day
}
$CurrentYear = $CurrentMoment.Year

$ScriptPath = Split-Path $MyInvocation.MyCommand.Path
$ScriptName = ($MyInvocation.MyCommand.Name).Substring(0,($MyInvocation.MyCommand.Name).Length-4)

$InRECFilePath = Join-Path $ScriptPath "$ScriptName-REC.txt"
$InNSFilePath = Join-Path $ScriptPath "$ScriptName-NS.txt"
$TextLogPath = Join-Path $ScriptPath "$ScriptName-$CurrentYear-$CurrentMonth-$CurrentDay.txt"
$EventLogLogName = 'DNS Zones Synchronizer'
$EventLogSourceName = $ScriptName

$Message = "START $CurrentMoment"
Add-ToTextLog $Message
Add-ToEventLog $Message -EventId 100 -EntryType Information

Try {
    $RecordNames = Get-Content $InRECFilePath
}
Catch {
    Process-Error -ErrorRecord $Error[0] -Message "Cannot get data from $InRECFilePath" -EventId 20 -EventLog -TextLog -Exit
}

$RecordNames = $RecordNames | Sort-Object

Try {
    Set-Content $InRECFilePath $RecordNames
}
Catch {
    Process-Error -ErrorRecord $Error[0] -Message "Cannot write back into $InRECFilePath" -EventId 25 -EventLog -TextLog -Exit
}

Try {
    $NSData = Import-Csv $InNSFilePath -Delimiter ';'
}
Catch {
    Process-Error -ErrorRecord $Error[0] -Message "Cannot get data from $InNSFilePath" -EventId 21 -EventLog -TextLog -Exit
}

foreach ($RecordName in $RecordNames){
	[bool]$Action = $false
    Add-ToTextLog "RecordName: $RecordName"

    if ($RecordName -match '\.') { # Is this is a single-labeled record?
        $NSSet = $NSData | where {$_.Zone -eq $RecordName}

        if (!$NSSet) {
            $RecordNameSplitted = $RecordName.Split('.')

            for ($Counter = 1; $Counter -lt $RecordNameSplitted.Count; $Counter++) {
                $RecordNameTrimmed = ''
                for ($Counter2 = $Counter; $Counter2 -lt $RecordNameSplitted.Count; $Counter2++) {
                    $RecordNameTrimmed += $RecordNameSplitted[$Counter2]

                    if ($Counter2 -lt $RecordNameSplitted.Count-1) {
                        $RecordNameTrimmed += '.'
                    }
                }
                $NSSet = $NSData | where {$_.Zone -eq $RecordNameTrimmed}
                if ($NSSet) {
                    $RecordName = ''
                    for ($Counter2 = 0; $Counter2 -lt $Counter; $Counter2++) {
                        $RecordName += $RecordNameSplitted[$Counter2]
                        if ($Counter2 -lt $Counter-1) {
                            $RecordName += '.'
                        }
                    }
                    break
                }
            }
        }
    }
    else {
        $Message = "Single-labeled records, like $RecordName, are not supported yet."
        Add-ToTextLog $Message
        Add-ToEventLog $Message -EventId 51 -EntryType Warning
        Continue
    }

    if ($NSSet) {
        $NSIPInt = $NSSet.IntIP
        $NSIPExt = $NSSet.ExtIP
        $ZoneName = $NSSet.Zone

        $AnswerExt = Process-DnsName -RecordName $RecordName -ZoneName $ZoneName -NSIP $NSIPExt -External
        if ($AnswerExt) {
            $RecordTypeExt = $AnswerExt[0].Type
            Add-ToTextLog "RecordName: $RecordName, ZoneName: $ZoneName, RecordTypeExt: $RecordTypeExt"

            $AnswerInt = Process-DnsName -RecordName $RecordName -ZoneName $ZoneName -NSIP $NSIPInt

            $RecordDataExt = Clean-DnsRecord -DnsRecord $AnswerExt -External

            Add-ToTextLog "RecordName: $RecordName, ZoneName: $ZoneName, RecordTypeExt: $RecordTypeExt, RecordDataExt: $RecordDataExt"

            if ($AnswerInt) {
                $RecordTypeInt = $AnswerInt[0].Type
                $RecordDataInt = Clean-DnsRecord -DnsRecord $AnswerInt
                Add-ToTextLog "RecordName: $RecordName, ZoneName: $ZoneName, RecordTypeExt: $RecordTypeExt, RecordDataExt: $RecordDataExt, RecordTypeInt: $RecordTypeInt, RecordDataInt: $RecordDataInt"
            }
            else {
                $Action = $true
            }
        }
        else {
            Continue
        }

        if (!$Action) {
            $Compared = Compare-Object $RecordDataExt $RecordDataInt
        }
        if ($Action -or $Compared) {
            Try {
                Update-DnsRecord -RecordType $RecordTypeExt -RecordName $RecordName -ZoneName $ZoneName -RecordData $RecordDataExt -Create:$Action
            }
            Catch {
                Process-Error -Message "Function Update-DnsRecord failed: RecordName - $RecordName, ZoneName - $ZoneName, RecordType - $RecordTypeExt,  RecordData - $RecordDataExt, Action - $Action" -ErrorRecord $Error[0] -TextLog -EventLog -EventId 70
                Continue
            }
        }
        else {
            Add-ToTextLog "External and internal records '$RecordName' in the zone '$ZoneName' are the same"
        }
    }
    else {
        $Message = "Could not find suitable set of NS for $RecordName record in the input $InNSFilePath file."
        Add-ToTextLog $Message
        Add-ToEventLog $Message -EventId 50 -EntryType Warning
        Continue
    }
}

$Message = "END $(Get-Date)"
Add-ToTextLog $Message
Add-ToEventLog $Message -EventId 105 -EntryType Information