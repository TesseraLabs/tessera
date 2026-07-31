<#
.SYNOPSIS
    Removes the Tessera credential provider's registration.

.DESCRIPTION
    Deletes both keys register-cp.ps1 created. Standard Windows logon is
    unaffected either way — this only takes the Tessera tile off the screen.

    Deleting a key that is not there is not an error: the script is meant to be
    usable as a rescue step without first checking what state the machine is in.

.EXAMPLE
    .\unregister-cp.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Must match PROVIDER_CLSID in crates/tessera_cp/src/lib.rs.
$Clsid = '{D88A8B6F-ECE6-4A9D-B6A6-1C30562C0448}'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Deregistration writes to HKLM and HKCR: run this from an elevated session.'
}

$providerKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"
$comKey = "Registry::HKEY_CLASSES_ROOT\CLSID\$Clsid"

foreach ($key in @($providerKey, $comKey)) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse -Force
        Write-Host "Removed $key"
    }
    else {
        Write-Host "Not present: $key"
    }
}

Write-Host 'The Tessera tile is gone. Standard logon was never touched.'
