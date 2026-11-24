# SPDX-License-Identifier: LGPL-3.0-only
# Apply an explicitly selected Windows image to the blank disk of the isolated PXE fixture.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$GuestId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,20}$')][string]$DiskSerial,
    [Parameter(Mandatory)][ValidateRange(1, 128)][int]$ImageIndex
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) {
    throw 'This command may only run in the disposable Windows PE guest.'
}
if ([guid](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID -ne $GuestId) {
    throw 'Unexpected disposable guest UUID.'
}
if (-not (Confirm-SecureBootUEFI)) {
    throw 'UEFI Secure Boot must be active in this fixture.'
}
$tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm
if (-not $tpm -or (([string]$tpm.SpecVersion -split ',')[0].Trim() -ne '2.0')) {
    throw 'The disposable Windows fixture requires TPM 2.0.'
}
$disks = @(Get-Disk | Where-Object { -not $_.IsReadOnly })
if ($disks.Count -ne 1 -or ([string]$disks[0].SerialNumber).Trim() -cne $DiskSerial -or
    $disks[0].PartitionStyle -ne 'RAW' -or $disks[0].Size -lt 64GB) {
    throw 'Expected exactly one writable, blank disposable disk with the configured serial.'
}
$disk = $disks[0]
if ((Test-Path -LiteralPath 'S:\') -or (Test-Path -LiteralPath 'W:\') -or
    (Get-Volume | Where-Object { $_.DriveLetter -in @('S','W') })) {
    throw 'The fixture partition letters are already in use.'
}
$images = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=5' | ForEach-Object {
    foreach ($name in @('install.wim','install.esd')) {
        $candidate = Join-Path ($_.DeviceID + '\') "sources\$name"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate }
    }
})
if ($images.Count -ne 1) {
    throw 'Attach exactly one approved Windows installation ISO as a read-only optical drive.'
}
$probe = Join-Path $PSScriptRoot 'pxe-collect.ps1'
$receipt = Join-Path $env:TEMP 'pxe-winpe-receipt.log'
& $probe -GuestId $GuestId -DiskSerial $DiskSerial -ReceiptPath $receipt

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)

    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE." }
}

$commands = Join-Path $env:TEMP 'pxe-fixture-partitions.txt'
@"
select disk $($disk.Number)
convert gpt
create partition efi size=260 offset=1024
format quick fs=fat32 label=System
assign letter=S
create partition msr size=16
create partition primary
format quick fs=ntfs label=Windows
assign letter=W
exit
"@ | Set-Content -LiteralPath $commands -Encoding Ascii
try {
    Invoke-Checked -Program 'diskpart.exe' -Arguments @('/s',$commands)
} finally {
    Remove-Item -LiteralPath $commands -ErrorAction SilentlyContinue
}
Update-HostStorageCache
# DiskPart mounts the EFI volume even when StorageWMI omits its drive letter.
$partitions = @(Get-Partition -DiskNumber $disk.Number)
$esp = @($partitions | Where-Object {
    $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -and
    $_.Offset -eq 1MB -and $_.Size -eq 260MB
})
$system = @($partitions | Where-Object { $_.DriveLetter -eq 'W' })
if ($esp.Count -ne 1 -or $system.Count -ne 1 -or
    -not (Test-Path -LiteralPath 'S:\' -PathType Container) -or
    -not (Test-Path -LiteralPath 'W:\' -PathType Container)) {
    throw 'The assigned partitions do not match the disposable disk.'
}
Write-Host 'The disposable GPT layout and the WinPE drive mappings are ready.'
Invoke-Checked -Program 'dism.exe' -Arguments @('/Apply-Image',"/ImageFile:$($images[0])","/Index:$ImageIndex",'/ApplyDir:W:\')
Copy-Item -LiteralPath $probe -Destination 'W:\Windows\System32\pxe-collect.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'pxe-first-boot.ps1') -Destination 'W:\Windows\System32'
$panther = 'W:\Windows\Panther'
$null = New-Item -ItemType Directory -Path $panther -Force
@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" wcm:action="add">
          <Order>1</Order>
          <Description>Collect the first Windows boot evidence</Description>
          <Path>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File %SystemRoot%\System32\pxe-first-boot.ps1 -GuestId $GuestId -DiskSerial $DiskSerial</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"@ | Set-Content -LiteralPath (Join-Path $panther 'Unattend.xml') -Encoding Ascii
Invoke-Checked -Program 'bcdboot.exe' -Arguments @('W:\Windows','/s','S:','/f','UEFI')
$null = New-Item -ItemType Directory -Path 'S:\PXE-LAB'
Copy-Item -LiteralPath $receipt -Destination 'S:\PXE-LAB\WINPE.LOG'
Invoke-Checked -Program 'wpeutil.exe' -Arguments @('Shutdown')
