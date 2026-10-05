# KeelShim - Windows 7 user-mode UI translation for the Windows 10 kernel
# Copyright (C) 2026 Kevin Dalli <projectkeel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

[CmdletBinding()]
param(
    [string]$Win10Iso = 'C:\Keel-media\LTSC2021_x64.iso',
    [string]$Win7Iso  = 'C:\Keel-media\Win7SP1_x64.iso',
    [string]$Out      = 'C:\Keel-media\Keel-LTSC2021.iso',
    [string]$Work     = 'C:\Keel-media\_keeliso',

    [ValidateSet('Interactive', 'UEFI', 'BIOS')]
    [string]$Disk = 'Interactive',
    [switch]$SkipBuild,
    [switch]$SkipRegMerge,
    [switch]$KeepWork,
    [switch]$ReuseWork,
    [switch]$AllowDonorMismatch
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
function Say($t)  { Write-Host "  $t" -ForegroundColor DarkGray }
function Step($t) { Write-Host ""; Write-Host "! $t !" -ForegroundColor Cyan }

$buildLog = Join-Path (Split-Path -Parent $Out) 'make-keel-iso.log'
New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
Start-Transcript -Path $buildLog -Force | Out-Null
trap { Write-Host "!FAILED! $($_.Exception.Message)" -ForegroundColor Red; Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; break }

$toolsRoot = if ($env:KEEL_TOOLS) { $env:KEEL_TOOLS } else { 'C:\Keel-tools' }
if (-not (Test-Path (Join-Path $toolsRoot 'msvc\VC\Tools\MSVC'))) {
    Step '0. provisioning the toolchain'
    Say "no toolchain at $toolsRoot so downloading it now, this takes a while on a first run"
    & (Join-Path $here 'setup-toolchain.ps1') -ToolsRoot $toolsRoot
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "setup-toolchain.ps1 failed ($LASTEXITCODE)" }
}

. (Join-Path $here 'env.ps1') | Out-Null
$sevenZip = (Get-Command 7z.exe -ErrorAction Stop).Source

if (-not (Test-Path $Win10Iso)) { throw "Windows 10 LTSC ISO not found $Win10Iso" }

Step '1. prerequisites'
# toolchains provisioned before python-registry was on the pip list lack it, and make-cut3 and the reg merge import it
$toolsPy = Join-Path $toolsRoot 'python\python.exe'
if (Test-Path $toolsPy) {
    & $toolsPy -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('pefile') and u.find_spec('Registry') else 1)"
    if ($LASTEXITCODE -ne 0) {
        Say 'python is missing pefile or python-registry so installing them'
        & $toolsPy -m pip install --quiet pefile python-registry
        if ($LASTEXITCODE -ne 0) { throw "pip could not install pefile and python-registry into $toolsPy" }
    }
}
if (-not (Test-Path (Join-Path $root 'donor\raw\Windows\System32\dwm.exe'))) {
    if (-not (Test-Path $Win7Iso)) { throw "donor\raw is empty and the Windows 7 ISO was not found at $Win7Iso" }
    Say 'donor\raw missing so extracting it from the Windows 7 ISO'
    & (Join-Path $here 'extract-donor.ps1') -Iso $Win7Iso
}
$cut3Ok = $false
if (Test-Path (Join-Path $root 'donor\cut3')) {
    & (Join-Path $here 'make-cut3-manifest.ps1') -AllowDonorMismatch:$AllowDonorMismatch
    $cut3Ok = ($LASTEXITCODE -eq 0)
    # cut3 is generated from donor\raw, so a stale or half-built one is rebuilt rather than refused
    if (-not $cut3Ok) { Say 'donor\cut3 does not match tools\cut3-manifest.json so rebuilding it from donor\raw' }
}
else { Say 'donor\cut3 missing so building the Windows 7 userland from donor\raw' }
if (-not $cut3Ok) {
    & (Join-Path $here 'make-cut3.ps1') -Win10Iso $Win10Iso -AllowDonorMismatch:$AllowDonorMismatch
    if ($LASTEXITCODE -ne 0) { throw "make-cut3.ps1 failed ($LASTEXITCODE), donor\cut3 does not match tools\cut3-manifest.json so refusing to build media from it" }
}
if ($AllowDonorMismatch) {
    Write-Warning '-AllowDonorMismatch so donor\cut3 is not held to tools\cut3-manifest.json, keelshim patches fixed offsets in the donor and another build can break the shell or compositor'
}

if (-not $SkipBuild) {
    Say 'building Keel'
    foreach ($b in 'build.ps1', 'build32.ps1') {
        $res = & (Join-Path $here $b) 2>&1
        if ($LASTEXITCODE -ne 0) { $res | Select-Object -Last 40 | ForEach-Object { Say $_ }; throw "$b failed ($LASTEXITCODE)" }
        $res | Select-Object -Last 1 | ForEach-Object { Say $_ }
    }
    & (Join-Path $here 'make-dwmapi32-seam.ps1') | Select-Object -Last 1 | ForEach-Object { Say $_ }
    & (Join-Path $here 'sign-driver.ps1') | Select-Object -Last 1 | ForEach-Object { Say $_ }
}
foreach ($f in 'out\debug\keelshim\keelshim.dll', 'out\debug\keeltsf\keeltsf.dll', 'out\debug\keelldr\keelldr.exe',
               'out\debug\keelexp\keelexp.exe', 'out\debug\keeldrv\keeldrv.sys', 'out\debug\keeldrv\keeltest.cer') {
    if (-not (Test-Path (Join-Path $root $f))) { throw "missing build output $f  (run without -SkipBuild)" }
}
Say 'prerequisites ok'

Step '2. unpack the Windows 10 ISO'
$mediaDir = Join-Path $Work 'media'
if ($ReuseWork -and (Test-Path (Join-Path $mediaDir 'sources\install.wim'))) {
    Say 'reusing the existing staging tree (-ReuseWork)'
} else {
    if (Test-Path $Work) { Remove-Item $Work -Recurse -Force }
    New-Item -ItemType Directory -Force $mediaDir | Out-Null
    Say "extracting $Win10Iso -> $mediaDir  (this takes a few minutes)"
    & $sevenZip x $Win10Iso "-o$mediaDir" -y -bso0 -bsp0 | Out-Null
}
if (-not (Test-Path (Join-Path $mediaDir 'sources\install.wim'))) {
    if (Test-Path (Join-Path $mediaDir 'sources\install.esd')) { throw 'this ISO carries install.esd not install.wim and the registry precompute needs a .wim, use a .wim-based LTSC ISO.' }
    throw 'sources\install.wim not found in the extracted media'
}
Say "media tree has $((Get-ChildItem $mediaDir -Recurse -File | Measure-Object).Count) files"

$etfs   = Join-Path $mediaDir 'boot\etfsboot.com'
$efisys = Join-Path $mediaDir 'efi\microsoft\boot\efisys.bin'
Say ("BIOS boot image {0}" -f $(if (Test-Path $etfs) { 'boot\etfsboot.com' } else { 'ABSENT' }))
Say ("UEFI boot image {0}" -f $(if (Test-Path $efisys) { 'efi\microsoft\boot\efisys.bin' } else { 'ABSENT' }))

Step '4. stage the Keel payload'

$oem = Join-Path $mediaDir 'sources\$OEM$\$1\Keel'
foreach ($d in 'bin', 'bin32', 'bin32\seam', 'rtm', 'win7theme\en-US', 'vm', 'regmerge', 'fallback') {
    New-Item -ItemType Directory -Force (Join-Path $oem $d) | Out-Null
}
$o = Join-Path $root 'out\debug'; $o32 = Join-Path $root 'out\x86'
Copy-Item "$o\keeldrv\keeldrv.sys", "$o\keeldrv\keeltest.cer", "$o\keelshim\keelshim.dll", "$o\keeltsf\keeltsf.dll",
          "$o\keelldr\keelldr.exe", "$o\keelexp\keelexp.exe", "$o\keelbroker\keelbroker.exe",
          "$o\keeluxsms\keeluxsms.exe", "$o\keeldxprobe\keeldxprobe.exe" (Join-Path $oem 'bin') -Force

Copy-Item "$o\keeldcomp\dcomp.dll" (Join-Path $oem 'bin\keeldcomp.dll') -Force
if (Test-Path "$o32\keelshim32.dll") { Copy-Item "$o32\keelshim32.dll", "$o32\keelldr32.exe" (Join-Path $oem 'bin32') -Force }
else { Write-Warning 'out\x86 missing so 32-bit apps will hang in TSF on the installed machine' }
if (Test-Path "$o32\dwmapi-seam\dwmapi.dll") { Copy-Item "$o32\dwmapi-seam\*.dll" (Join-Path $oem 'bin32\seam') -Force }
else { Write-Warning 'out\x86\dwmapi-seam missing so no 32-bit in-app glass (Word title bar)' }
Copy-Item (Join-Path $root 'donor\cut3\*') (Join-Path $oem 'rtm') -Recurse -Force
Copy-Item (Join-Path $oem 'rtm\dwm.exe') (Join-Path $oem 'rtm\keeldwm.exe') -Force
$lui = Join-Path $root 'donor\raw\Windows\System32\LogonUI.exe'
if (Test-Path $lui) { Copy-Item $lui (Join-Path $oem 'rtm\keellogonui.exe') -Force }
Copy-Item (Join-Path $root 'donor\cut3\aero.msstyles') (Join-Path $oem 'win7theme\aero.msstyles') -Force
Copy-Item (Join-Path $root 'donor\cut3\en-US\aero.msstyles.mui') (Join-Path $oem 'win7theme\en-US\aero.msstyles.mui') -Force
Copy-Item (Join-Path $root 'vm\*.ps1') (Join-Path $oem 'vm') -Force
Copy-Item (Join-Path $root 'tools\apply-reg-merge.ps1') (Join-Path $oem 'vm') -Force

$cplTsv = Join-Path $root 'vm\cpl-reg-win7.tsv'
if (Test-Path $cplTsv) { Copy-Item $cplTsv (Join-Path $oem 'vm') -Force }
else { Write-Warning 'vm\cpl-reg-win7.tsv missing so Control Panel items will not be repaired, run tools\export-cpl-reg.ps1' }
# the installed machine then shows it came from media built past the donor check
$mismatchNote = Join-Path $oem 'donor-mismatch.txt'
if ($AllowDonorMismatch) { Set-Content $mismatchNote "built $(Get-Date -Format s) with -AllowDonorMismatch, donor\cut3 was not held to tools\cut3-manifest.json" -Encoding ascii }
else { Remove-Item $mismatchNote -Force -ErrorAction SilentlyContinue }
Say ("payload {0} MB, {1} files" -f [int]((Get-ChildItem $oem -Recurse -File | Measure-Object Length -Sum).Sum / 1MB),
                                   (Get-ChildItem $oem -Recurse -File | Measure-Object).Count)

Step '5. precompute the Windows 7 registry merge'
if ($SkipRegMerge) { Say 'skipped (-SkipRegMerge) so Control Panel will likely not open on the installed machine' }
else {

    $py = @((Join-Path $toolsRoot 'python\python.exe'), "$env:SystemDrive\Keel-tools\python\python.exe") |
          Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $py) {
        $cand = (Get-Command python -EA SilentlyContinue).Source
        if ($cand -and $cand -notlike '*\WindowsApps\*') { $py = $cand }
    }
    $regMergePy = Join-Path $root 'tools\census\reg_merge.py'
    $donorCfg = Join-Path $root 'donor\raw\Windows\System32\config'
    if (-not $py -or -not (Test-Path $regMergePy)) {
        throw "cannot compute the Win7 registry merge python=$py regMerge=$regMergePy. Without it the " +
              'media installs a machine whose Control Panel does not open. Pass -SkipRegMerge to build anyway.'
    }
    else {
        $stock = Join-Path $Work 'stockhive'
        New-Item -ItemType Directory -Force $stock | Out-Null
        Say 'extracting the stock SOFTWARE/DEFAULT hives from install.wim'
        & $sevenZip e (Join-Path $mediaDir 'sources\install.wim') "-o$stock" `
            '1\Windows\System32\config\SOFTWARE' '1\Windows\System32\config\DEFAULT' -y -bso0 -bsp0 | Out-Null
        $targets = @(
            @{ Name = 'software'; Stock = "$stock\SOFTWARE"; Donor = "$donorCfg\SOFTWARE"; RegRoot = 'HKEY_LOCAL_MACHINE\SOFTWARE' },
            @{ Name = 'default';  Stock = "$stock\DEFAULT";  Donor = "$donorCfg\DEFAULT";  RegRoot = 'HKEY_USERS\.DEFAULT' },
            @{ Name = 'hkcu';     Stock = "$stock\DEFAULT";  Donor = "$donorCfg\DEFAULT";  RegRoot = 'HKEY_CURRENT_USER' }
        )
        foreach ($t in $targets) {
            if (-not (Test-Path $t.Stock)) { Write-Warning "  $($t.Name) stock hive not found in install.wim so skipped"; continue }
            if (-not (Test-Path $t.Donor)) { Write-Warning "  $($t.Name) donor hive missing ($($t.Donor)) so skipped"; continue }
            $outDir = Join-Path $Work "merge-$($t.Name)"
            Say "  diffing the Win7 $($t.Name) hive against the stock Win10 one"
            & $py $regMergePy $t.Donor $t.Stock $t.RegRoot $outDir | ForEach-Object { Say "    $_" }
            $tsv = Join-Path $outDir 'merge.tsv'
            if (Test-Path $tsv) { Copy-Item $tsv (Join-Path $oem "regmerge\$($t.Name).tsv") -Force }
            else { Write-Warning "  $($t.Name) reg_merge produced no merge.tsv" }
        }
    }
}

Step "6. answer file (disk layout $Disk)"
$auSrc = Join-Path $root 'vm\autounattend-keel-iso.xml'
$auDst = Join-Path $mediaDir 'autounattend.xml'

. {

    $ns = 'urn:schemas-microsoft-com:unattend'
    $wcm = 'http://schemas.microsoft.com/WMIConfig/2002/State'
    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($auSrc)
    $nsm = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $nsm.AddNamespace('u', $ns)
    $setup = $doc.SelectSingleNode("//u:settings[@pass='windowsPE']/u:component[@name='Microsoft-Windows-Setup']", $nsm)
    if (-not $setup) { throw 'Microsoft-Windows-Setup component not found in the answer file' }

    function NewEl([string]$name, [string]$text) {
        $e = $doc.CreateElement($name, $ns)
        if ($PSBoundParameters.ContainsKey('text') -and $null -ne $text) { $e.InnerText = $text }
        return $e
    }
    function AddAction([System.Xml.XmlElement]$e) { $a = $doc.CreateAttribute('wcm', 'action', $wcm); $a.Value = 'add'; [void]$e.Attributes.Append($a); $e }
    function NewPart([int]$order, [string]$type, [string]$size) {
        $p = AddAction (NewEl 'CreatePartition')
        [void]$p.AppendChild((NewEl 'Order' $order))
        [void]$p.AppendChild((NewEl 'Type' $type))
        if ($size) { [void]$p.AppendChild((NewEl 'Size' $size)) } else { [void]$p.AppendChild((NewEl 'Extend' 'true')) }
        $p
    }
    function NewModify([int]$order, [int]$id, [hashtable]$props) {
        $m = AddAction (NewEl 'ModifyPartition')
        [void]$m.AppendChild((NewEl 'Order' $order))
        [void]$m.AppendChild((NewEl 'PartitionID' $id))
        foreach ($k in $props.Keys) { [void]$m.AppendChild((NewEl $k $props[$k])) }
        $m
    }

    $dc = $null; $targetPartition = 0
    if ($Disk -ne 'Interactive') {
    $dc = NewEl 'DiskConfiguration'
    [void]$dc.AppendChild((NewEl 'WillShowUI' 'OnError'))
    $dsk = AddAction (NewEl 'Disk')
    [void]$dsk.AppendChild((NewEl 'DiskID' '0'))
    [void]$dsk.AppendChild((NewEl 'WillWipeDisk' 'true'))
    $cp = NewEl 'CreatePartitions'; $mp = NewEl 'ModifyPartitions'
    if ($Disk -eq 'UEFI') {

        [void]$cp.AppendChild((NewPart 1 'EFI' '260'))
        [void]$cp.AppendChild((NewPart 2 'MSR' '16'))
        [void]$cp.AppendChild((NewPart 3 'Primary' $null))
        [void]$mp.AppendChild((NewModify 1 1 ([ordered]@{ Label = 'System'; Format = 'FAT32' })))
        [void]$mp.AppendChild((NewModify 2 2 ([ordered]@{})))
        [void]$mp.AppendChild((NewModify 3 3 ([ordered]@{ Label = 'Windows'; Format = 'NTFS'; Letter = 'C' })))
        $targetPartition = 3
    } else {
        [void]$cp.AppendChild((NewPart 1 'Primary' $null))
        [void]$mp.AppendChild((NewModify 1 1 ([ordered]@{ Active = 'true'; Format = 'NTFS'; Label = 'Windows'; Letter = 'C' })))
        $targetPartition = 1
    }
    [void]$dsk.AppendChild($cp); [void]$dsk.AppendChild($mp); [void]$dc.AppendChild($dsk)
    }

    $ii = NewEl 'ImageInstall'
    $os = NewEl 'OSImage'
    $from = NewEl 'InstallFrom'
    $md = AddAction (NewEl 'MetaData')
    [void]$md.AppendChild((NewEl 'Key' '/IMAGE/INDEX')); [void]$md.AppendChild((NewEl 'Value' '1'))
    [void]$from.AppendChild($md)
    [void]$os.AppendChild($from)
    if ($Disk -ne 'Interactive') {
        $to = NewEl 'InstallTo'
        [void]$to.AppendChild((NewEl 'DiskID' '0')); [void]$to.AppendChild((NewEl 'PartitionID' $targetPartition))
        [void]$os.AppendChild($to)
    }
    [void]$os.AppendChild((NewEl 'WillShowUI' 'OnError'))
    if ($Disk -ne 'Interactive') { [void]$os.AppendChild((NewEl 'InstallToAvailablePartition' 'false')) }
    [void]$ii.AppendChild($os)

    $userData = $setup.SelectSingleNode('u:UserData', $nsm)
    if ($dc) { [void]$setup.InsertBefore($dc, $userData) }
    [void]$setup.InsertAfter($ii, $userData)
    $doc.Save($auDst)
    if ($Disk -eq 'Interactive') { Say 'interactive so Setup asks for the edition, then where to install' }
    else { Say "$Disk layout injected (WIPES DISK 0), installing to partition $targetPartition" }
}

try { $chk = New-Object System.Xml.XmlDocument; $chk.Load($auDst) }
catch { throw "the answer file written to the media is not valid XML: $($_.Exception.Message)" }
Say 'autounattend.xml placed at the media root and validated'

Step '7. build the ISO'
$oscdimg = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
    "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe",
    (Join-Path $toolsRoot 'oscdimg\oscdimg.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $oscdimg) { $oscdimg = (Get-ChildItem $toolsRoot -Filter oscdimg.exe -Recurse -EA SilentlyContinue | Select-Object -First 1).FullName }

if (Test-Path $Out) { Remove-Item $Out -Force }
if ($oscdimg) {
    Say "using $oscdimg"

    $bootdata = if (Test-Path $efisys) { "2#p0,e,b`"$etfs`"#pEF,e,b`"$efisys`"" } else { "1#p0,e,b`"$etfs`"" }

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    # oscdimg writes progress to stderr, so treating stderr as failure aborts a good build
    try { & $oscdimg -m -o -u2 -udfver102 "-bootdata:$bootdata" $mediaDir $Out }
    finally { $ErrorActionPreference = $prevEap }
    if ($LASTEXITCODE -ne 0) { throw "oscdimg failed ($LASTEXITCODE)" }
    Say ('dual-boot media written (BIOS + UEFI El Torito entries)')
} else {
    Write-Warning 'oscdimg.exe not found (it ships in the Windows ADK "Deployment Tools").'
    Write-Warning 'falling back to IMAPI2 which can only produce a BIOS-bootable (El Torito) image'
    Write-Warning 'the result will boot a Gen-1 or BIOS machine but NOT a UEFI one, install the ADK for dual boot.'
    if (-not (Test-Path $etfs)) { throw 'boot\etfsboot.com missing so cannot make a bootable image without oscdimg' }
    if (-not ('ISOFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices.ComTypes;
public class ISOFile {
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks) {
    int bytes = 0; byte[] buf = new byte[BlockSize]; var ptr = (IntPtr)(&bytes);
    FileStream o = File.OpenWrite(Path); IStream i = Stream as IStream;
    if (o != null) { while (TotalBlocks-- > 0) { i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes); } o.Flush(); o.Close(); }
  }
}
'@ -CompilerParameters (New-Object CodeDom.Compiler.CompilerParameters -Property @{CompilerOptions='/unsafe'; GenerateInMemory=$true})
    }
    $stream = New-Object -ComObject ADODB.Stream -Property @{ Type = 1 }
    $stream.Open(); $stream.LoadFromFile($etfs)
    $boot = New-Object -ComObject IMAPI2FS.BootOptions
    $boot.AssignBootImage($stream)
    $boot.Emulation = 0
    $boot.PlatformId = 0
    $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage

    $fsi.ChooseImageDefaultsForMediaType(18)
    try { $fsi.FreeMediaBlocks = 0 } catch {}

    $fsi.FileSystemsToCreate = 4
    $fsi.UDFRevision = 0x102
    $fsi.VolumeName = 'KEEL'
    $fsi.BootImageOptions = $boot
    $fsi.Root.AddTree($mediaDir, $false)
    $res = $fsi.CreateResultImage()
    [ISOFile]::Create($Out, $res.ImageStream, $res.BlockSize, $res.TotalBlocks)
}

if (-not $KeepWork) { Remove-Item $Work -Recurse -Force -EA SilentlyContinue }
Write-Host ""
Write-Host ("ISO {0}  ({1:N2} GB)" -f $Out, ((Get-Item $Out).Length / 1GB)) -ForegroundColor Green
Write-Host "boot a machine or VM from it and it installs Windows 10 LTSC unattended, then applies Keel and"
Write-Host "reboots into the Windows 7 desktop, test it in a throwaway VM"
Write-Host "    boot a throwaway VM from it without another answer-file ISO since the two would race" -ForegroundColor White
Write-Host "build log $buildLog, doc\troubleshooting.md has what a good install looks like and where its logs are"
Stop-Transcript | Out-Null
