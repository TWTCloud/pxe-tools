# SPDX-License-Identifier: LGPL-3.0-only
# Report the lab VM state without changing a disk or the firmware.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$GuestId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,40}$')][string]$DiskSerial,
    [ValidatePattern('^COM[1-9][0-9]?$')][string]$SerialPort = 'COM1',
    [string]$ReceiptPath = ''
)

$ErrorActionPreference = 'Stop'
$actualId = [guid](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
if ($actualId -ne $GuestId) { throw 'Unexpected SMBIOS identity for the deployment fixture.' }

$isWinPE = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT'
$disks = @(Get-Disk | Where-Object { ([string]$_.SerialNumber).Trim() -ceq $DiskSerial })
if ($disks.Count -ne 1) { throw 'The disposable disk serial did not identify exactly one disk.' }
$selected = $disks[0]
$secureBoot = Confirm-SecureBootUEFI
$tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm
$tpmSpec = if ($tpm) { ([string]$tpm.SpecVersion -split ',')[0].Trim() } else { '' }

$receipt = [ordered]@{
    guest_id = $actualId.ToString()
    disk_serial = ([string]$selected.SerialNumber).Trim()
    secure_boot = [bool]$secureBoot
    tpm_spec = $tpmSpec
    partition_style = [string]$selected.PartitionStyle
}

if ($isWinPE) {
    $receipt.phase = 'winpe'
    & wpeutil.exe UpdateBootInfo | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WinPE could not report its boot type.' }
    $receipt.pe_boot_type = (Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEBootType)
} else {
    $receipt.phase = 'windows'
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $systemPartition = Get-Partition -DriveLetter ($os.SystemDrive.TrimEnd(':'))
    $receipt.system_disk_matches = $systemPartition.DiskNumber -eq $selected.Number
    $receipt.product_type = [int]$os.ProductType
    $receipt.build = [int]$os.BuildNumber
    $receipt.edition = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID
}

$message = 'PXE_TOOLS_WINDOWS ' + (ConvertTo-Json -InputObject $receipt -Compress)
if ($ReceiptPath) {
    Set-Content -LiteralPath $ReceiptPath -Value $message -Encoding Ascii
    return
}
$port = [System.IO.Ports.SerialPort]::new($SerialPort, 115200, 'None', 8, 'One')
try {
    $port.WriteTimeout = 5000
    $port.Open()
    $port.WriteLine($message)
} finally {
    $port.Dispose()
}
