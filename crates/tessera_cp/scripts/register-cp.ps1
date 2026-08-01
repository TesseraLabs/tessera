<#
.SYNOPSIS
    Registers the Tessera credential provider on this machine.

.DESCRIPTION
    Writes the two registry keys LogonUI needs: the COM in-process server under
    HKCR\CLSID\{CLSID}, and the enrolled-provider entry under
    HKLM\...\Authentication\Credential Providers\{CLSID}.

    A broken credential provider is a machine nobody can log on to. Run this
    only on a virtual machine with a fresh snapshot, and make sure a second
    local administrator account exists before you do. The way back is
    unregister-cp.ps1, from another session or from safe mode.

.PARAMETER DllPath
    Path to tessera_cp.dll. Must be somewhere SYSTEM can read at the logon
    screen — a per-user profile directory will not do.

.EXAMPLE
    .\register-cp.ps1 -DllPath 'C:\Program Files\Tessera\tessera_cp.dll'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DllPath
)

$ErrorActionPreference = 'Stop'

# Must match PROVIDER_CLSID in crates/tessera_cp/src/lib.rs.
$Clsid = '{D88A8B6F-ECE6-4A9D-B6A6-1C30562C0448}'
$Name = 'Tessera Credential Provider'

if (-not (Test-Path -LiteralPath $DllPath)) {
    throw "DLL not found: $DllPath"
}
$FullPath = (Resolve-Path -LiteralPath $DllPath).Path

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Registration writes to HKLM and HKCR: run this from an elevated session.'
}

$comKey = "Registry::HKEY_CLASSES_ROOT\CLSID\$Clsid"
$inprocKey = "$comKey\InprocServer32"
$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"

New-Item -Path $comKey -Force | Out-Null
Set-ItemProperty -Path $comKey -Name '(default)' -Value $Name

New-Item -Path $inprocKey -Force | Out-Null
Set-ItemProperty -Path $inprocKey -Name '(default)' -Value $FullPath
# The provider keeps no apartment-affine state of its own; "Apartment" is what
# every in-box credential provider declares and what LogonUI expects.
Set-ItemProperty -Path $inprocKey -Name 'ThreadingModel' -Value 'Apartment'

New-Item -Path $providerKey -Force | Out-Null
Set-ItemProperty -Path $providerKey -Name '(default)' -Value $Name

Write-Host "Registered $Name"
Write-Host "  CLSID: $Clsid"
Write-Host "  DLL:   $FullPath"
Write-Host 'Lock the session (Win+L) to see the tile. Keep this window open.'
