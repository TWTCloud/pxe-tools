# SPDX-License-Identifier: LGPL-3.0-only
# Record first-boot evidence on the test disk and shut down before inspecting it.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$GuestId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,20}$')][string]$DiskSerial
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT') {
    throw 'This command requires the installed Windows fixture.'
}
$prefix = 'PXE_TOOLS_WINDOWS '
if (Test-Path -LiteralPath 'S:\') {
    throw 'The fixture EFI drive letter is already in use.'
}
& mountvol.exe 'S:' '/s'
if ($LASTEXITCODE -ne 0) { throw 'The system EFI partition could not be mounted.' }
try {
    $previous = Get-Content -LiteralPath 'S:\PXE-LAB\WINPE.LOG' -Raw
    if (-not $previous.StartsWith($prefix)) { throw 'Missing WinPE receipt.' }
    $winpe = $previous.Substring($prefix.Length) | ConvertFrom-Json
    if ($winpe.phase -ne 'winpe' -or [guid]$winpe.guest_id -ne $GuestId -or
        $winpe.disk_serial -cne $DiskSerial) {
        throw 'The EFI partition does not have the verified WinPE fixture identity.'
    }
    $stage = 'S:\PXE-LAB\STAGE.LOG'
    Set-Content -LiteralPath $stage -Value 'windows-specialize' -Encoding Ascii
    $receipt = Join-Path $env:TEMP 'pxe-windows-receipt.log'
    & (Join-Path $PSScriptRoot 'pxe-collect.ps1') -GuestId $GuestId -DiskSerial $DiskSerial -ReceiptPath $receipt
    $started = Get-Content -LiteralPath $receipt -Raw
    if (-not $started.StartsWith($prefix)) {
        throw 'Missing first-boot receipt.'
    }
    $windows = $started.Substring($prefix.Length) | ConvertFrom-Json
    if ($windows.phase -ne 'windows' -or -not $windows.system_disk_matches -or
        -not $windows.secure_boot -or $windows.tpm_spec -ne '2.0') {
        throw 'The installed fixture did not boot with the expected disk, Secure Boot and TPM 2.0.'
    }
    Copy-Item -LiteralPath $receipt -Destination 'S:\PXE-LAB\WINDOWS.LOG'
    Set-Content -LiteralPath $stage -Value 'windows-finished' -Encoding Ascii
} finally {
    & mountvol.exe 'S:' '/d'
    if ($LASTEXITCODE -ne 0) { throw 'The EFI partition could not be unmounted.' }
}
& shutdown.exe '/s' '/t' '10'
if ($LASTEXITCODE -ne 0) { throw 'The installed fixture could not schedule shutdown.' }
