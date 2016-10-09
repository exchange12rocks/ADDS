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
	[Parameter(Mandatory=$True)]
	[string]$ComputerName,
	[Parameter(Mandatory=$True)]
	[string]$UserName,
	[Parameter(Mandatory=$False)]
	[string]$ComputerDomain = 'example.com',
	[Parameter(Mandatory=$False)]
	[string]$UserDomain = 'example.com'
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

[string]$ComputerWDC = (Get-ADDomainController -DomainName $ComputerDomain -Discover -Writable -NextClosestSite).HostName
[string]$UserWDC = (Get-ADDomainController -DomainName $UserDomain -Discover -Writable -NextClosestSite).HostName
[string]$ComputerDomainNB = (Get-ADDomain $ComputerDomain).NetBIOSName

Try {
	$ADObject = Get-ADComputer $ComputerName -Server $ComputerWDC
}
Catch {
	Write-Error "Cannot get computer $ComputerName from AD DS @ $($ComputerWDC):`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}

Try {
    New-PSDrive -Name $ComputerDomainNB -Root '' -PsProvider ActiveDirectory -Server $ComputerWDC | Out-Null
}
Catch {
    Write-Error "Cannot create new PSDrive for $ComputerDomain AD domain @ $($ComputerWDC):`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
    Exit
}

Try {
	$DACL = Get-Acl -Path "$($ComputerDomainNB):\$($ADObject.DistinguishedName)"
}
Catch {
	Write-Error "Cannot get DACL for object $($ADObject.DistinguishedName) @ $($ComputerWDC):`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}
Try {
	$UserSID = (Get-ADUser $UserName -Properties SID -Server $UserWDC).SID
}
Catch {
	Write-Error "Cannot get user $UserName from AD DS @ $($UserWDC):`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}

Try {
	$ACEs = @()
}
Catch {
	Write-Error "Cannot initialize empty ACEs object:`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}

Try {
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'197076', 'Allow', [GUID]'00000000-0000-0000-0000-000000000000', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'WriteProperty', 'Allow', [GUID]'3e0abfd0-126a-11d0-a060-00aa006c33ed', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'WriteProperty', 'Allow', [GUID]'bf967953-0de6-11d0-a285-00aa003049e2', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'WriteProperty', 'Allow', [GUID]'bf967950-0de6-11d0-a285-00aa003049e2', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'WriteProperty', 'Allow', [GUID]'5f202010-79a5-11d0-9020-00c04fc2d4cf', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'WriteProperty', 'Allow', [GUID]'4c164200-20c0-11d0-a768-00aa006e0529', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'Self', 'Allow', [GUID]'f3a64788-5306-11d1-a9c5-0000f80367c1', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
	$ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule ($UserSID,'Self', 'Allow', [GUID]'72e39547-7b18-11d1-adef-00c04fd8d5cd', 'None', [GUID]'00000000-0000-0000-0000-000000000000')
}
Catch {
	Write-Error "Error while creating ACE objects:`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}

Try {
	foreach ($ACE in $ACEs) {
		$DACL.AddAccessRule($ACE)
	}
}
Catch {
	Write-Error "Error while populating DACL with ACE objects:`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}
Try {
	Set-Acl -AclObject $DACL -Path "$($ComputerDomainNB):\$($ADObject.DistinguishedName)"
}
Catch {
	Write-Error "Error while writing DACL back to $($ADObject.DistinguishedName) @ $($ComputerWDC):`n$($Error[0].Exception.Message)`n$($Error[0].InvocationInfo.PositionMessage)"
	Exit
}

Write-Output "$UserName is now allowed to join $ComputerName to the domain $ComputerDomain."