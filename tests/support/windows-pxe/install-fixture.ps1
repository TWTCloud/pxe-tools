# SPDX-License-Identifier: LGPL-3.0-only
# Apply an explicitly selected Windows image to the blank disk of the isolated PXE fixture.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$GuestId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,40}$')][string]$DiskSerial,
    [switch]$UseUniqueId,
    [Parameter(Mandatory)][ValidateRange(1, 128)][int]$ImageIndex,
    [string]$InstallImageUri = '',
    [string]$InstallImageSha256 = ''
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
$diskProperty = if ($UseUniqueId) { 'UniqueId' } else { 'SerialNumber' }
if ($disks.Count -ne 1 -or ([string]$disks[0].$diskProperty).Trim() -cne $DiskSerial -or
    $disks[0].PartitionStyle -ne 'RAW' -or $disks[0].Size -lt 64GB) {
    throw 'Expected exactly one writable, blank disposable disk with the configured identifier.'
}
$disk = $disks[0]
if ((Test-Path -LiteralPath 'S:\') -or (Test-Path -LiteralPath 'W:\') -or
    (Get-Volume | Where-Object { $_.DriveLetter -in @('S','W') })) {
    throw 'The fixture partition letters are already in use.'
}
$image = ''
if ($InstallImageUri) {
    if ($InstallImageUri -cnotmatch '^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/pxe/windows/[a-z0-9-]{1,40}/install\.(?:wim|esd)$' -or
        $InstallImageSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw 'The PXE Tools image URL or digest is invalid.'
    }
} else {
    $images = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=5' | ForEach-Object {
        foreach ($name in @('install.wim','install.esd')) {
            $candidate = Join-Path ($_.DeviceID + '\') "sources\$name"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate }
        }
    })
    if ($images.Count -ne 1) {
        throw 'Attach exactly one approved Windows installation ISO as a read-only optical drive.'
    }
    $image = $images[0]
}
$probe = Join-Path $PSScriptRoot 'pxe-collect.ps1'
$receipt = Join-Path $env:TEMP 'pxe-winpe-receipt.log'
& $probe -GuestId $GuestId -DiskSerial $DiskSerial -UseUniqueId:$UseUniqueId -ReceiptPath $receipt

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)

    # DISM writes console progress while applying an image. Keep that output out of the WinPE PowerShell pipeline.
    $process = Start-Process -FilePath $Program -ArgumentList $Arguments -NoNewWindow -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "$Program failed with exit code $($process.ExitCode)." }
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
$null = New-Item -ItemType Directory -Path 'S:\PXE-LAB'
Copy-Item -LiteralPath $receipt -Destination 'S:\PXE-LAB\WINPE.LOG'
$stage = 'S:\PXE-LAB\STAGE.LOG'
Set-Content -LiteralPath $stage -Value 'apply-windows' -Encoding Ascii
$download = 'W:\PXE-LAB-download'
$stagedDownload = $false
$scratch = 'W:\PXE-LAB-scratch'
$null = New-Item -ItemType Directory -Path $scratch
try {
    if ($InstallImageUri) {
        $null = New-Item -ItemType Directory -Path $download
        $stagedDownload = $true
        $image = Join-Path $download ([IO.Path]::GetFileName(([uri]$InstallImageUri).AbsolutePath))
        $client = New-Object Net.WebClient
        try {
            $client.Proxy = $null
            $client.DownloadFile([uri]$InstallImageUri, $image)
        } finally { $client.Dispose() }
        if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ne $InstallImageSha256) {
            throw 'The cached Windows image does not match the digest in WinPE.'
        }
    }
    Invoke-Checked -Program 'dism.exe' -Arguments @('/Apply-Image',"/ImageFile:$image","/Index:$ImageIndex",'/ApplyDir:W:\',"/ScratchDir:$scratch",'/LogPath:S:\PXE-LAB\DISM.LOG')
} finally {
    if ($stagedDownload) {
        if (Test-Path -LiteralPath $image -PathType Leaf) { Remove-Item -LiteralPath $image -Force }
        Remove-Item -LiteralPath $download
    }
}
Remove-Item -LiteralPath $scratch
Set-Content -LiteralPath $stage -Value 'prepare-first-boot' -Encoding Ascii
Copy-Item -LiteralPath $probe -Destination 'W:\Windows\System32\pxe-collect.ps1'
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'pxe-first-boot.ps1') -Destination 'W:\Windows\System32'
$panther = 'W:\Windows\Panther'
$null = New-Item -ItemType Directory -Path $panther -Force
$identityFlag = if ($UseUniqueId) { ' -UseUniqueId' } else { '' }
@"
@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%SystemRoot%\System32\pxe-first-boot.ps1" -GuestId $GuestId -DiskSerial $DiskSerial$identityFlag
exit /b %errorlevel%
"@ | Set-Content -LiteralPath 'W:\Windows\System32\pxe-first-boot.cmd' -Encoding Ascii
@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" wcm:action="add">
          <Order>1</Order>
          <Description>Collect the first Windows boot evidence</Description>
          <Path>%SystemRoot%\System32\cmd.exe /d /c %SystemRoot%\System32\pxe-first-boot.cmd</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"@ | Set-Content -LiteralPath (Join-Path $panther 'Unattend.xml') -Encoding Ascii
Invoke-Checked -Program 'bcdboot.exe' -Arguments @('W:\Windows','/s','S:','/f','UEFI')
$defaultLoader = 'S:\EFI\Boot\bootx64.efi'
if (-not (Test-Path -LiteralPath $defaultLoader -PathType Leaf)) {
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $defaultLoader) -Force
    Copy-Item -LiteralPath 'S:\EFI\Microsoft\Boot\bootmgfw.efi' -Destination $defaultLoader
}
Set-Content -LiteralPath $stage -Value 'winpe-finished' -Encoding Ascii
Invoke-Checked -Program 'wpeutil.exe' -Arguments @('Shutdown')
