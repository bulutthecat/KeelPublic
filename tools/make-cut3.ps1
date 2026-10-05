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
param([string]$Win10Iso = 'C:\Keel-media\LTSC2021_x64.iso', [switch]$SkipVerify, [switch]$AllowDonorMismatch)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
. (Join-Path $here 'env.ps1') | Out-Null

$raw      = Join-Path $root 'donor\raw'
$cut3     = Join-Path $root 'donor\cut3'
$manifest = Join-Path $here 'cut3-manifest.json'
$census   = Join-Path $here 'census'

function Say($t)  { Write-Host "  $t" -ForegroundColor DarkGray }
function Step($t) { Write-Host ""; Write-Host "! $t !" -ForegroundColor Cyan }

if (-not (Test-Path (Join-Path $raw 'Windows\System32\dwm.exe'))) {
    throw "donor\raw is empty so run tools\extract-donor.ps1 against your Windows 7 SP1 ISO first"
}
$want = (Get-Content $manifest -Raw | ConvertFrom-Json).files

# the seams forward to the Windows 10 build the media installs, not to whatever this machine runs
if (-not (Test-Path (Join-Path $root 'host-ref\raw\Windows\System32\user32.dll'))) {
    Step '0. Windows 10 reference binaries'
    & (Join-Path $here 'extract-hostref.ps1') -Iso $Win10Iso
}

Step '1. copy the Windows 7 files this build starts from'
if (Test-Path $cut3) { Remove-Item $cut3 -Recurse -Force }
New-Item -ItemType Directory -Force $cut3 | Out-Null
$copied = 0
foreach ($w in $want) {
    if (-not $w.from) { continue }
    $src = Join-Path $raw ($w.from -replace '/', '\')
    if (-not (Test-Path -LiteralPath $src)) { throw "donor file missing $($w.from)  (needed for $($w.path))" }
    $dst = Join-Path $cut3 $w.path
    $dir = Split-Path $dst -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    Copy-Item -LiteralPath $src $dst -Force
    # the WIM copies are hidden and read-only, and every later stage writes to them in place
    (Get-Item -LiteralPath $dst -Force).Attributes = 'Normal'
    $copied++
}
Say "$copied files copied from donor\raw"

Step '2. api-set forwarder shims'
$stubs = @($want | Where-Object { (Split-Path $_.path -Leaf) -like 'api-ms*' } | ForEach-Object { $_.path })
foreach ($s in $stubs) {
    & (Join-Path $here 'make-apiset-shim.ps1') -Stub $s -OutDir $cut3 | Select-String 'built|unresolved' | ForEach-Object { Say $_.Line }
}
Say "$($stubs.Count) shims built"

Step '3. the private Common-Controls assembly'
$asm = Join-Path $cut3 'Keel.Common-Controls'
New-Item -ItemType Directory -Force $asm | Out-Null
$ccMan = Get-ChildItem (Join-Path $raw 'Windows\winsxs\Manifests') -Force -Filter 'amd64_microsoft.windows.common-controls_*_6.0.7601.23403_*.manifest' |
         Select-Object -First 1
if (-not $ccMan) { throw 'no Win7 Common-Controls 6.0.7601.23403 manifest under donor\raw\Windows\winsxs\Manifests' }
# the DLL comes from the same WinSxS payload, System32\comctl32.dll is v5.82 and the Win7 explorer exits 1 on it
$ccDll = Join-Path $ccMan.Directory.Parent.FullName "$($ccMan.BaseName)\comctl32.dll"
if (-not (Test-Path -LiteralPath $ccDll)) { throw "no Win7 Common-Controls 6.0.7601.23403 comctl32.dll at $ccDll so rerun tools\extract-donor.ps1" }
Copy-Item -LiteralPath $ccDll (Join-Path $asm 'comctl32.dll') -Force
(Get-Item -LiteralPath (Join-Path $asm 'comctl32.dll') -Force).Attributes = 'Normal'
$x = Get-Content $ccMan.FullName -Raw
$x = [regex]::Replace($x, '<assemblyIdentity\b[^>]*?name="Microsoft\.Windows\.Common-Controls"[^>]*?/>',
                      '<assemblyIdentity name="Keel.Common-Controls" version="6.0.7601.23403" processorArchitecture="amd64" type="win32"/>')
$x = [regex]::Replace($x, '(?s)<dependency\b.*?</dependency>', '')
# the hash and signature info cover the stock comctl32 and the import patch below invalidates them, so they cannot stay
$x = [regex]::Replace($x, '(?s)<(\w+:)?hash\b.*?</(\w+:)?hash>', '')
$x = [regex]::Replace($x, '(?s)<signatureInfo\b.*?</signatureInfo>', '')
$x = [regex]::Replace($x, '(?s)<memberships\b.*?</memberships>', '')
$x = [regex]::Replace($x, '\s(hash|hashalg)="[^"]*"', '')
$x = [regex]::Replace($x, '\scmiv2:[\w]+="[^"]*"', '')
$x = [regex]::Replace($x, '\sxmlns:cmiv2="[^"]*"', '')
$x = [regex]::Replace($x, '(?m)^\s*\r?\n', '')
[IO.File]::WriteAllText((Join-Path $asm 'Keel.Common-Controls.manifest'), $x, (New-Object System.Text.UTF8Encoding($false)))
# Win10 looks for comctl32's MUI by name in its own WinSxS store and never finds the Win7 one, so the strings go into the binary
$ccMui = Get-ChildItem (Join-Path $raw 'Windows\winsxs') -Force -Directory -Filter 'amd64_microsoft.windows.c..-controls.resources_*_6.0.7600.16385_en-us_*' |
         Select-Object -First 1
if (-not $ccMui) { throw 'no Win7 Common-Controls 6.0 en-us resources under donor\raw\Windows\winsxs so rerun tools\extract-donor.ps1' }
python (Join-Path $census 'embed_mui.py') (Join-Path $asm 'comctl32.dll') (Join-Path $ccMui.FullName 'comctl32.dll.mui') | ForEach-Object { Say $_ }
if ($LASTEXITCODE -ne 0) { throw 'embed_mui failed' }

Step '4. import seams'
& (Join-Path $here 'make-user32-seam.ps1')   | Select-Object -Last 1
& (Join-Path $here 'make-ntdll-seam.ps1')    | Select-Object -Last 1
# comctl32 is a donor here too, or the forwarder misses the 111 kernel32 names only it imports
& (Join-Path $here 'make-kernel32-seam.ps1') -Donors 'shell32.dll', 'Keel.Common-Controls\comctl32.dll' | Select-Object -Last 1

Step '5. retarget the Common-Controls dependency'
# every donor binary, a Win7 one left on the Win10 comctl32 gets Win10 controls that call uxtheme exports Win7 lacks
$targets = @($want | Where-Object { $_.from -and $_.path -imatch '\.(dll|exe|cpl)$' } |
             ForEach-Object { Join-Path $cut3 $_.path })
Say "$($targets.Count) binaries to retarget"
if ($targets.Count) {
    python (Join-Path $census 'rewrite_manifest_dep.py') @targets | Select-String 'rewrote' | ForEach-Object { Say $_.Line }
    if ($LASTEXITCODE -ne 0) { throw 'rewrite_manifest_dep failed' }
}

Step '6. shell host manifests'
# control.exe and rundll32.exe need the same activation context as explorer, or Win7 shell32 fails DllMain inside them
foreach ($exe in 'explorer.exe', 'control.exe', 'rundll32.exe') {
    & (Join-Path $here 'apply-manifest.ps1') -Exe $exe | Select-Object -Last 1
    & (Join-Path $here 'apply-manifest-com.ps1') -Exe $exe | Select-Object -Last 1
}

if (-not $SkipVerify) {
    Step '7. verify against the manifest'
    & (Join-Path $here 'make-cut3-manifest.ps1') -AllowDonorMismatch:$AllowDonorMismatch
    exit $LASTEXITCODE
}
