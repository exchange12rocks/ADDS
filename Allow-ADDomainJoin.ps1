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
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Allows a user to join their computer into Active Directory domain.

.DESCRIPTION
Allows a user to join their computer into Active Directory domain w/o assistance of Service Desk engineer if the computer account is already pre-created. After executing that script a user can reinstall OS multiple times and still be able to join the machine into domain, while computer name will stay the same.
Right now the script works only for the domain where an account running the script resides.

.PARAMETER ComputerName
sAMAccountName of a computer.

.PARAMETER UserName
sAMAccountName of a user.

.PARAMETER ComputerDomain
FQDN of an AD domain where target computer is located.

.PARAMETER UserDomain
FQDN of an AD domain where target user is located.

.EXAMPLE
.\Allow-ADDomainJoin.ps1 -UserName ExampleUser -ComputerName ExampleComputer

.NOTES
NAME: Allow-ADDomainJoin
AUTHOR: Kirill Nikolaev
LASTEDIT: 03/11/2016 10:02:10
KEYWORDS: Active Directory, ADDS, self-service, service desk, workstations, end-users

.LINK
https://exchange12rocks.org/2016/03/14/how-to-allow-users-to-join-their-computers-into-ad-domain/
#>

Param(
	[Parameter(Mandatory,
	HelpMessage='sAMAccount name of a computer account at which you like to delegate domain-joining permissions')]
	[string]$ComputerName,
	[Parameter(Mandatory,
	HelpMessage='sAMAccount name of a user account to which you like to delegate domain-joining permissions')]
	[string]$UserName,
	[string]$ComputerDomain = 'example.com',
	[string]$UserDomain = 'example.com'
)

$ErrorActionPreference = 'Stop'

Import-Module -Name ActiveDirectory

[string]$ComputerWDC = (Get-ADDomainController -DomainName $ComputerDomain -Discover -Writable -NextClosestSite).HostName
[string]$UserWDC = (Get-ADDomainController -DomainName $UserDomain -Discover -Writable -NextClosestSite).HostName
[string]$ComputerDomainNB = (Get-ADDomain -Identity $ComputerDomain).NetBIOSName

Try {
	$ADObject = Get-ADComputer -Identity $ComputerName -Server $ComputerWDC
}
Catch {
	Write-Error -Message ("Cannot get computer {0} from AD DS @ {1}:`r`n{2}`r`n{3}" -f $ComputerName, $ComputerWDC, $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}

Try {
    $null = New-PSDrive -Name $ComputerDomainNB -Root '' -PSProvider ActiveDirectory -Server $ComputerWDC
}
Catch {
    Write-Error -Message ("Cannot create new PSDrive for {0} AD domain @ {1}:`r`n{2}`r`n{3}" -f $ComputerDomain, $ComputerWDC, $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
    Exit
}

Try { #TODO: Get-Acl desn't support ShouldProcess
	$DACL = Get-Acl -Path ('{0}:\{1}' -f $ComputerDomainNB, $ADObject.DistinguishedName)
}
Catch {
	Write-Error -Message ("Cannot get DACL for object {0} @ {1}:`r`n{2}`r`n{3}" -f $ADObject.DistinguishedName, $ComputerWDC, $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}
Try {
	$UserSID = (Get-ADUser -Identity $UserName -Properties SID -Server $UserWDC).SID
}
Catch {
	Write-Error -Message ("Cannot get user {0} from AD DS @ {1}:`r`n{2}`r`n{3}" -f $UserName, $UserWDC, $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}

Try {
	$ACEs = @()
}
Catch {
	Write-Error -Message ("Cannot initialize empty ACEs object:`r`n{0}`r`n{1}" -f $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}

Try {
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'197076', 'Allow', [GUID]'00000000-0000-0000-0000-000000000000', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'WriteProperty', 'Allow', [GUID]'3e0abfd0-126a-11d0-a060-00aa006c33ed', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'WriteProperty', 'Allow', [GUID]'bf967953-0de6-11d0-a285-00aa003049e2', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'WriteProperty', 'Allow', [GUID]'bf967950-0de6-11d0-a285-00aa003049e2', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'WriteProperty', 'Allow', [GUID]'5f202010-79a5-11d0-9020-00c04fc2d4cf', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'WriteProperty', 'Allow', [GUID]'4c164200-20c0-11d0-a768-00aa006e0529', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'Self', 'Allow', [GUID]'f3a64788-5306-11d1-a9c5-0000f80367c1', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList ($UserSID,'Self', 'Allow', [GUID]'72e39547-7b18-11d1-adef-00c04fd8d5cd', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
}
Catch {
	Write-Error -Message ("Error while creating ACE objects:`r`n{0}`r`n{1}" -f $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}

Try {
	foreach ($ACE in $ACEs) {
		$DACL.AddAccessRule($ACE)
	}
}
Catch {
	Write-Error -Message ("Error while populating DACL with ACE objects:`r`n{0}`r`n{1}" -f $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}
Try {
	Set-Acl -AclObject $DACL -Path ('{0}:\{1}' -f $ComputerDomainNB, $ADObject.DistinguishedName)
}
Catch {
	Write-Error -Message ("Error while writing DACL back to {0} @ {1}:`r`n{2}`n{3}" -f $ADObject.DistinguishedName, $ComputerWDC, $Error[0].Exception.Message, $Error[0].InvocationInfo.PositionMessage)
	Exit
}

Write-Output -InputObject ('{0} is now allowed to join {1} to the domain {2}.' -f $UserName, $ComputerName, $ComputerDomain)