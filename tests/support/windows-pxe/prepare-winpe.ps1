# SPDX-License-Identifier: LGPL-3.0-only
# Prepare the evidence-collecting WinPE used by the isolated deployment test.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$WindowsIso,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$WindowsIsoSha256,
    [Parameter(Mandatory)][string]$Wimboot,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$WimbootSha256,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][guid]$GuestId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9-]{1,40}$')][string]$DiskSerial,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9]{1,40}$')][string]$Edition,
    [ValidateRange(0, 128)][int]$InstallImageIndex = 0,
    [switch]$UseUniqueId,
    [string]$InstallImageUri = '',
    [string]$AdkDirectory = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (($UseUniqueId -and $DiskSerial -cnotmatch '^[A-F0-9]{32}$') -or
    (-not $UseUniqueId -and $DiskSerial.Length -gt 20)) {
    throw 'Provide the VHDX storage identifier or an AHCI serial, according to the test platform.'
}
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess) {
    throw 'Run from a 64-bit PowerShell session on the isolated Windows media builder.'
}
if (Test-Path -LiteralPath $OutputDirectory) {
    throw 'The WinPE output directory must be new.'
}
if ($OutputDirectory -match '["%&|<>^!\r\n]') {
    throw 'The output path contains characters interpreted by the ADK batch file.'
}

function Get-ApprovedMedia {
    param([string]$Path, [string]$Sha256)

    $media = Get-Item -LiteralPath $Path
    if ($media.PSIsContainer -or ($media.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $media.FullName -Algorithm SHA256).Hash -ne $Sha256) {
        throw 'An input file differs from the approved fixture media.'
    }
    $media
}

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)

    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw ("{0} failed with exit code {1}." -f [IO.Path]::GetFileName($Program), $LASTEXITCODE)
    }
}

$approvedIso = Get-ApprovedMedia -Path $WindowsIso -Sha256 $WindowsIsoSha256
$approvedWimboot = Get-ApprovedMedia -Path $Wimboot -Sha256 $WimbootSha256
$selectedImage = $null
$installName = ''
$installHash = ''
if ($InstallImageUri -and ($InstallImageIndex -eq 0 -or
    $InstallImageUri -cnotmatch '^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/pxe/windows/[a-z0-9-]{1,40}/install\.(?:wim|esd)$')) {
    throw 'Provide the PXE Tools installation image URL and a valid WIM index.'
}
if ($InstallImageIndex -gt 0) {
    if ((Get-DiskImage -ImagePath $approvedIso.FullName).Attached) {
        throw 'Dismount the approved ISO before preparing its WinPE edition.'
    }
    $isoDrive = Mount-DiskImage -ImagePath $approvedIso.FullName -Access ReadOnly -PassThru
    try {
        $root = "$(($isoDrive | Get-Volume).DriveLetter):\sources"
        $images = @('install.wim', 'install.esd' | ForEach-Object {
            $candidate = Join-Path $root $_
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate }
        })
        if ($images.Count -ne 1) {
            throw 'The approved ISO must contain one Windows installation image.'
        }
        $selectedImage = Get-WindowsImage -ImagePath $images[0] -Index $InstallImageIndex
        if ($selectedImage.EditionId -ne $Edition) {
            throw 'The selected WIM index does not match the requested Windows edition.'
        }
        if ($InstallImageUri) {
            $installName = [IO.Path]::GetFileName($images[0])
            if ($installName -ne [IO.Path]::GetFileName(([uri]$InstallImageUri).AbsolutePath)) {
                throw 'The installation image URL does not match the file format in the approved ISO.'
            }
            $installHash = (Get-FileHash -LiteralPath $images[0] -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } finally {
        Dismount-DiskImage -ImagePath $approvedIso.FullName | Out-Null
    }
}
$adk = (Get-Item -LiteralPath $AdkDirectory).FullName
if ($adk -match '["%&|<>^!\r\n]') {
    throw 'The ADK path contains characters interpreted by its batch files.'
}
$deployment = Join-Path $adk 'Deployment Tools'
$winpe = Join-Path $adk 'Windows Preinstallation Environment'
$copype = Join-Path $winpe 'copype.cmd'
$setEnvironment = Join-Path $deployment 'DandISetEnv.bat'
$dism = Join-Path $deployment 'amd64\DISM\dism.exe'
$packages = Join-Path $winpe 'amd64\WinPE_OCs'
foreach ($file in @($copype, $setEnvironment, $dism)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw 'Install the Microsoft ADK Deployment Tools and the matching WinPE add-on on this runner.'
    }
}
$packageFiles = foreach ($name in @('WinPE-WMI', 'WinPE-NetFX', 'WinPE-Scripting', 'WinPE-PowerShell',
                                    'WinPE-StorageWMI', 'WinPE-SecureStartup', 'WinPE-SecureBootCmdlets')) {
    $component = Join-Path $packages "$name.cab"
    if (-not (Test-Path -LiteralPath $component -PathType Leaf)) {
        throw "The ADK package $name is unavailable."
    }
    $component
    $language = Join-Path $packages "en-us\${name}_en-us.cab"
    if (Test-Path -LiteralPath $language -PathType Leaf) {
        $language
    }
}

$output = (New-Item -ItemType Directory -Path $OutputDirectory).FullName
$work = Join-Path $output 'work'
$boot = (New-Item -ItemType Directory -Path (Join-Path $output 'boot')).FullName
$setup = Join-Path $output 'prepare.cmd'
@"
@echo off
call "$setEnvironment" || exit /b 1
call "$copype" amd64 "$work"
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $setup -Encoding Ascii
Invoke-Checked -Program $env:ComSpec -Arguments @('/d','/c',$setup)

$image = Join-Path $work 'media\sources\boot.wim'
$mount = Join-Path $work 'mount'
Invoke-Checked -Program $dism -Arguments @('/Mount-Image',"/ImageFile:$image",'/Index:1',"/MountDir:$mount")
$mounted = $true
try {
    foreach ($package in $packageFiles) {
        Invoke-Checked -Program $dism -Arguments @("/Image:$mount",'/Add-Package',"/PackagePath:$package")
    }
    $system = Join-Path $mount 'Windows\System32'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'collect.ps1') -Destination (Join-Path $system 'pxe-collect.ps1')
    $script = "pxe-collect.ps1"
    $parameters = "-GuestId $GuestId -DiskSerial $DiskSerial"
    if ($InstallImageIndex -gt 0) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-fixture.ps1') -Destination $system
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'first-boot-fixture.ps1') -Destination (Join-Path $system 'pxe-first-boot.ps1')
        $script = "install-fixture.ps1"
        $parameters += " -ImageIndex $InstallImageIndex"
    }
    if ($UseUniqueId) { $parameters += ' -UseUniqueId' }
    if ($installHash) { $parameters += " -InstallImageUri `"$InstallImageUri`" -InstallImageSha256 $installHash" }
    @"
@echo off
wpeinit
if errorlevel 1 exit /b 1
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%SystemRoot%\System32\$script" $parameters
exit /b %errorlevel%
"@ | Set-Content -LiteralPath (Join-Path $system 'startnet.cmd') -Encoding Ascii
    Invoke-Checked -Program $dism -Arguments @('/Unmount-Image',"/MountDir:$mount",'/Commit')
    $mounted = $false
} finally {
    if ($mounted) {
        Invoke-Checked -Program $dism -Arguments @('/Unmount-Image',"/MountDir:$mount",'/Discard')
    }
}

Move-Item -LiteralPath $image -Destination (Join-Path $boot 'boot.wim')
Copy-Item -LiteralPath (Join-Path $work 'media\EFI\Microsoft\Boot\BCD') -Destination (Join-Path $boot 'BCD')
Copy-Item -LiteralPath (Join-Path $work 'media\Boot\boot.sdi') -Destination (Join-Path $boot 'boot.sdi')
Copy-Item -LiteralPath $approvedWimboot.FullName -Destination (Join-Path $boot 'wimboot')

function Get-BootHash([string]$Name) {
    (Get-FileHash -LiteralPath (Join-Path $boot $Name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$case = [ordered]@{
    guest_id = $GuestId.ToString()
    disk_serial = $DiskSerial
    edition = $Edition
    iso_sha256 = $WindowsIsoSha256.ToLowerInvariant()
    wimboot_sha256 = Get-BootHash 'wimboot'
    winpe_sha256 = Get-BootHash 'boot.wim'
    bcd_sha256 = Get-BootHash 'BCD'
    boot_sdi_sha256 = Get-BootHash 'boot.sdi'
}
if ($UseUniqueId) { $case.Add('disk_identity', 'unique_id') }
if ($selectedImage) {
    $case.Add('image_index', [int]$selectedImage.ImageIndex)
    $case.Add('edition_label', [string]$selectedImage.ImageName)
}
if ($installHash) {
    $case.Add('install_image', $installName)
    $case.Add('install_sha256', $installHash)
}
[IO.File]::WriteAllText((Join-Path $output 'case.json'), ($case | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
