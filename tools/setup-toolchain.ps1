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

param(
    [string]$ToolsRoot = 'C:\Keel-tools',
    [string[]]$Skip = @(),
    [string]$VcVersionPin = ''
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$ProgressPreference = 'SilentlyContinue'

$Dl   = Join-Path $ToolsRoot '_dl'
$Msvc = Join-Path $ToolsRoot 'msvc'
New-Item -ItemType Directory -Force $ToolsRoot, $Dl, $Msvc | Out-Null
Start-Transcript -Path (Join-Path $Dl 'setup-toolchain.log') -Append | Out-Null
$Curl = "$env:SystemRoot\System32\curl.exe"
$sw = [Diagnostics.Stopwatch]::StartNew()
function Log($m) { Write-Host ("[{0:hh\:mm\:ss}] {1}" -f $sw.Elapsed, $m) }
function Skipped($k) { return ($Skip -contains $k) }

$Src = @{
    cmake        = 'https://github.com/Kitware/CMake/releases/download/v4.4.3/cmake-4.4.3-windows-x86_64.zip'
    ninja        = 'https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip'
    git          = 'https://github.com/git-for-windows/git/releases/download/v2.55.0.windows.5/MinGit-2.55.0.5-64-bit.zip'
    detours      = 'https://github.com/microsoft/Detours/archive/refs/tags/v4.0.1.zip'
    python       = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
    sevenzr      = 'https://www.7-zip.org/a/7zr.exe'
    sevenzmsi    = 'https://www.7-zip.org/a/7z2301-x64.msi'
    wdksetup     = 'https://go.microsoft.com/fwlink/?linkid=2286137'
    vschannel    = 'https://aka.ms/vs/17/release/channel'
}
$SdkPackageId = 'Win11SDK_10.0.26100'

function Get-File([string]$Url, [string]$Dest, [string]$Sha256 = '') {
    if (Test-Path $Dest) {
        if (-not $Sha256) { return }
        if ((Get-FileHash $Dest -Algorithm SHA256).Hash -ieq $Sha256) { return }
        Remove-Item $Dest -Force
    }
    New-Item -ItemType Directory -Force (Split-Path $Dest) | Out-Null
    $tmp = "$Dest.part"
    & $Curl -L -sS --retry 8 --retry-delay 3 --retry-all-errors -o $tmp $Url
    if ($LASTEXITCODE -ne 0) { throw "download failed ($LASTEXITCODE) $Url" }
    if ($Sha256) {
        $h = (Get-FileHash $tmp -Algorithm SHA256).Hash
        if ($h -ine $Sha256) { Remove-Item $tmp -Force; throw "sha256 mismatch for $Url (got $h, want $Sha256)" }
    }
    Move-Item $tmp $Dest -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Expand-ZipTo([string]$Zip, [string]$Dest, [string]$StripPrefix = '', [switch]$StripTopDir) {
    New-Item -ItemType Directory -Force $Dest | Out-Null
    $z = [IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $top = ''
        if ($StripTopDir) {
            $first = $z.Entries | Where-Object { $_.FullName -match '/' } | Select-Object -First 1
            if ($first) { $top = ($first.FullName -split '/')[0] + '/' }
        }
        foreach ($e in $z.Entries) {
            $name = $e.FullName
            if ($StripPrefix) { if (-not $name.StartsWith($StripPrefix, 'OrdinalIgnoreCase')) { continue }; $name = $name.Substring($StripPrefix.Length) }
            if ($top -and $name.StartsWith($top)) { $name = $name.Substring($top.Length) }
            if (-not $name) { continue }
            $name = [Uri]::UnescapeDataString($name)
            $target = Join-Path $Dest ($name -replace '/', '\')
            if ($name.EndsWith('/')) { New-Item -ItemType Directory -Force $target | Out-Null; continue }
            New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true)
        }
    } finally { $z.Dispose() }
}

function Invoke-MsiAdminInstall([string]$Msi, [string]$TargetDir) {
    $log = Join-Path $Dl ("msi-" + [IO.Path]::GetFileNameWithoutExtension($Msi) + ".log")
    $p = Start-Process msiexec.exe -ArgumentList @('/a', "`"$Msi`"", '/qn', "TARGETDIR=`"$TargetDir`"", '/L*v', "`"$log`"") -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec /a failed ($($p.ExitCode)) for $Msi, see $log" }
}

function Mark([string]$name) { Set-Content -Path (Join-Path $Dl "$name.done") -Value (Get-Date -Format s) -Encoding ascii }
function Done([string]$name) { return (Test-Path (Join-Path $Dl "$name.done")) }

$man = $null
function Get-VsManifest {
    if ($script:man) { return $script:man }
    $manPath = Join-Path $Dl 'VisualStudio.vsman'
    if (-not (Test-Path $manPath)) {
        Log 'fetching VS channel manifest'
        $chan = Invoke-RestMethod $Src.vschannel
        $item = $chan.channelItems | Where-Object { $_.id -eq 'Microsoft.VisualStudio.Manifests.VisualStudio' }
        Get-File $item.payloads[0].url $manPath
    }
    Log 'parsing VS manifest'
    $script:man = (Get-Content $manPath -Raw | ConvertFrom-Json)
    return $script:man
}
function Get-VsPackage([string]$Id, [string]$Language = 'en-US') {
    $m = Get-VsManifest
    $c = @($m.packages | Where-Object { $_.id -ieq $Id })
    if ($c.Count -eq 0) { throw "package not in manifest $Id" }
    $pick = @($c | Where-Object { -not $_.language -or $_.language -ieq $Language })
    if ($pick.Count -eq 0) { $pick = $c }

    $x = @($pick | Where-Object { -not $_.chip -or $_.chip -ieq 'x64' -or $_.chip -ieq 'neutral' })
    if ($x.Count -gt 0) { $pick = $x }
    return $pick[0]
}
function Install-VsPackage([string]$Id, [string]$TargetDir) {
    $p = Get-VsPackage $Id
    $dir = Join-Path $Dl ("vs\" + $p.id)
    foreach ($pl in $p.payloads) {
        $f = Join-Path $dir ($pl.fileName -replace '/', '\')
        Get-File $pl.url $f $pl.sha256
    }
    switch ($p.type) {
        'Vsix' {
            foreach ($pl in $p.payloads) {
                $f = Join-Path $dir ($pl.fileName -replace '/', '\')
                Expand-ZipTo -Zip $f -Dest $TargetDir -StripPrefix 'Contents/'
            }
        }
        'Msi' {
            foreach ($pl in $p.payloads | Where-Object { $_.fileName -like '*.msi' }) {
                $f = Join-Path $dir ($pl.fileName -replace '/', '\')
                Invoke-MsiAdminInstall $f $TargetDir
            }
        }
        default { throw "unhandled package type $($p.type) for $Id" }
    }
    Log "installed $Id ($($p.type), $($p.version))"
}

if (-not (Skipped 'msvc') -and -not (Done 'msvc')) {
    $m = Get-VsManifest
    $v = $VcVersionPin
    if (-not $v) {
        $v = $m.packages | Where-Object { $_.id -match '^Microsoft\.VC\.(\d+\.\d+\.\d+\.\d+)\.Tools\.HostX64\.TargetX64\.base$' } |
             ForEach-Object { [regex]::Match($_.id, 'VC\.(\d+\.\d+\.\d+\.\d+)\.').Groups[1].Value } |
             Sort-Object { [version]$_ } -Unique | Select-Object -Last 1
    }
    Log "MSVC toolset family $v"
    $pkgs = @(
        "Microsoft.VisualCpp.DIA.SDK",
        "Microsoft.VC.$v.CRT.Headers.base",
        "Microsoft.VC.$v.CRT.x64.Desktop.base",
        "Microsoft.VC.$v.CRT.x64.Desktop.spectre.base",
        "Microsoft.VC.$v.CRT.x64.Store.base",
        "Microsoft.VC.$v.CRT.Redist.X64.base",
        "Microsoft.VC.$v.Tools.HostX64.TargetX64.base",
        "Microsoft.VC.$v.Tools.HostX64.TargetX64.Res.base",
        "Microsoft.VC.$v.ATL.Headers.base",
        "Microsoft.VC.$v.ATL.X64.base",
        "Microsoft.VC.$v.ATL.X64.Spectre.base",
        "Microsoft.VC.$v.ASAN.Headers.base",
        "Microsoft.VC.$v.ASAN.X64.base",
        "Microsoft.VisualCpp.RuntimeDebug.14",

        "Microsoft.VC.$v.Tools.HostX64.TargetX86.base",
        "Microsoft.VC.$v.Tools.HostX64.TargetX86.Res.base",
        "Microsoft.VC.$v.CRT.x86.Desktop.base",
        "Microsoft.VC.$v.CRT.x86.Desktop.spectre.base",

        "Microsoft.VC.$v.CRT.x86.Store.base",
        "Microsoft.VC.$v.CRT.Redist.X86.base"
    )
    foreach ($id in $pkgs) {
        try { Install-VsPackage $id $Msvc } catch { Log "WARN $id $($_.Exception.Message)" ; if ($id -notmatch 'ASAN|RuntimeDebug|DIA|TargetX86|x86|X86') { throw } }
    }

    $vcBin = Get-ChildItem (Join-Path $Msvc 'VC\Tools\MSVC') -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1
    $binDir = Join-Path $vcBin.FullName 'bin\Hostx64\x64'
    $dia = Get-ChildItem $Msvc -Recurse -Filter msdia140.dll -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match 'amd64|x64' } | Select-Object -First 1
    if ($dia) { Copy-Item $dia.FullName $binDir -Force }

    Get-ChildItem $Msvc -Recurse -Include 'msvcp140d.dll','vcruntime140d.dll','vcruntime140_1d.dll','ucrtbased.dll','concrt140d.dll' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch 'x86|arm' } | ForEach-Object { Copy-Item $_.FullName $binDir -Force -ErrorAction SilentlyContinue }

    Remove-Item (Join-Path $binDir 'vctip.exe') -Force -ErrorAction SilentlyContinue
    Mark 'msvc'
}

if (-not (Skipped 'sdk') -and -not (Done 'sdk')) {
    $p = Get-VsPackage $SdkPackageId
    $dir = Join-Path $Dl 'sdk'
    Log "downloading $($p.payloads.Count) SDK payloads ($([math]::Round(($p.payloads | Measure-Object size -Sum).Sum/1MB)) MB)"
    foreach ($pl in $p.payloads) {
        Get-File $pl.url (Join-Path $dir ($pl.fileName -replace '/', '\')) $pl.sha256
    }
    $msis = @(
        'Windows SDK-x86_en-us.msi',
        'Windows SDK for Windows Store Apps Tools-x86_en-us.msi',
        'Windows SDK for Windows Store Apps Headers-x86_en-us.msi',
        'Windows SDK for Windows Store Apps Headers OnecoreUap-x86_en-us.msi',
        'Windows SDK for Windows Store Apps Libs-x86_en-us.msi',
        'Windows SDK OnecoreUap Headers x86-x86_en-us.msi',
        'Windows SDK OnecoreUap Headers x64-x86_en-us.msi',
        'Windows SDK Desktop Headers x86-x86_en-us.msi',
        'Windows SDK Desktop Headers x64-x86_en-us.msi',
        'Windows SDK Desktop Libs x86-x86_en-us.msi',
        'Windows SDK Desktop Libs x64-x86_en-us.msi',
        'Windows SDK Desktop Tools x64-x86_en-us.msi',
        'Windows SDK Signing Tools-x86_en-us.msi',
        'Windows SDK Modern Versioned Developer Tools-x86_en-us.msi',
        'Universal CRT Headers Libraries and Sources-x86_en-us.msi',
        'Universal CRT Tools x64-x64_en-us.msi',
        'Universal CRT Redistributable-x86_en-us.msi',
        'Application Verifier x64 External Package (DesktopEditions)-x64_en-us.msi'
    )
    foreach ($n in $msis) {
        $f = Join-Path $dir "Installers\$n"
        if (-not (Test-Path $f)) { Log "WARN SDK msi missing $n"; continue }
        Invoke-MsiAdminInstall $f $Msvc
        Log "extracted $n"
    }
    Mark 'sdk'
}

if (-not (Skipped 'debuggers') -and -not (Done 'debuggers')) {
    $p = Get-VsPackage $SdkPackageId
    $setup = $p.payloads | Where-Object { $_.fileName -ieq 'winsdksetup.exe' } | Select-Object -First 1
    $setupExe = Join-Path $Dl 'sdk\winsdksetup.exe'
    Get-File $setup.url $setupExe $setup.sha256
    $layout = Join-Path $Dl 'sdkdbg'
    $msi = Get-ChildItem $layout -Recurse -Filter 'X64 Debuggers And Tools-x64_en-us.msi' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $msi) {
        Log 'winsdksetup /layout (debuggers only)'
        $pr = Start-Process $setupExe -ArgumentList @('/features','OptionId.WindowsDesktopDebuggers','/layout',"`"$layout`"",'/quiet','/norestart') -Wait -PassThru
        if ($pr.ExitCode -ne 0) { throw "winsdksetup layout failed ($($pr.ExitCode))" }
        $msi = Get-ChildItem $layout -Recurse -Filter 'X64 Debuggers And Tools-x64_en-us.msi' | Select-Object -First 1
        if (-not $msi) { throw 'debugger msi not found in layout' }
    }
    Invoke-MsiAdminInstall $msi.FullName $Msvc
    Log 'extracted debuggers'
    Mark 'debuggers'
}

if (-not (Skipped 'wdk') -and -not (Done 'wdk')) {
    $wdkExe = Join-Path $Dl 'wdksetup.exe'
    Get-File $Src.wdksetup $wdkExe
    $layout = Join-Path $Dl 'wdk'
    $msis = @(Get-ChildItem $layout -Recurse -Filter '*.msi' -ErrorAction SilentlyContinue)
    if ($msis.Count -eq 0) {
        Log 'wdksetup /layout'
        $pr = Start-Process $wdkExe -ArgumentList @('/layout',"`"$layout`"",'/quiet','/norestart') -Wait -PassThru
        if ($pr.ExitCode -ne 0) { throw "wdksetup layout failed ($($pr.ExitCode))" }
        $msis = @(Get-ChildItem $layout -Recurse -Filter '*.msi')
    }
    foreach ($m in $msis) {
        if ($m.Name -match 'arm|ARM|x86_en-us\.msi$' -and $m.Name -notmatch 'Windows Driver Kit') { }
        if ($m.Name -match 'arm') { continue }
        try { Invoke-MsiAdminInstall $m.FullName $Msvc; Log "extracted $($m.Name)" }
        catch { Log "WARN $($_.Exception.Message)" }
    }
    Mark 'wdk'
}

if (-not (Skipped 'tools')) {
    if (-not (Done 'cmake')) { $z = Join-Path $Dl 'cmake.zip'; Get-File $Src.cmake $z; Expand-ZipTo $z (Join-Path $ToolsRoot 'cmake') -StripTopDir; Mark 'cmake'; Log 'cmake' }
    if (-not (Done 'ninja')) { $z = Join-Path $Dl 'ninja.zip'; Get-File $Src.ninja $z; Expand-ZipTo $z (Join-Path $ToolsRoot 'ninja'); Mark 'ninja'; Log 'ninja' }
    if (-not (Done 'git'))   { $z = Join-Path $Dl 'mingit.zip'; Get-File $Src.git $z; Expand-ZipTo $z (Join-Path $ToolsRoot 'git'); Mark 'git'; Log 'git' }
    if (-not (Done '7zip')) {
        $d = Join-Path $ToolsRoot '7zip'; New-Item -ItemType Directory -Force $d | Out-Null
        Get-File $Src.sevenzr (Join-Path $d '7zr.exe')
        $msi = Join-Path $Dl '7z-x64.msi'; Get-File $Src.sevenzmsi $msi
        $tmp = Join-Path $Dl '7zmsi'; Invoke-MsiAdminInstall $msi $tmp
        $exe = Get-ChildItem $tmp -Recurse -Filter 7z.exe | Select-Object -First 1
        Copy-Item (Join-Path $exe.DirectoryName '*') $d -Recurse -Force
        Mark '7zip'; Log '7-zip'
    }
}

if (-not (Skipped 'python') -and -not (Done 'python')) {
    $exe = Join-Path $Dl 'python-3.12.10-amd64.exe'; Get-File $Src.python $exe
    $pyDir = Join-Path $ToolsRoot 'python'
    if (-not (Test-Path (Join-Path $pyDir 'python.exe'))) {
        Log 'installing python (per-user, no PATH changes)'
        $pyLog = Join-Path $Dl 'python-install.log'
        $pr = Start-Process $exe -ArgumentList @('/quiet','/log',"`"$pyLog`"",'InstallAllUsers=0',"TargetDir=$pyDir",'PrependPath=0','Include_test=0','Include_launcher=0','AssociateFiles=0','Shortcuts=0','Include_doc=0','CompileAll=0') -Wait -PassThru
        if ($pr.ExitCode -ne 0) { throw "python installer failed ($($pr.ExitCode)), see $pyLog" }
        if (-not (Test-Path (Join-Path $pyDir 'python.exe'))) { throw "python installer exited 0 but left no python.exe in $pyDir, see $pyLog" }
    }
    & (Join-Path $pyDir 'python.exe') -m pip install --upgrade --quiet pip
    if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed' }
    Mark 'python'; Log 'python'
}

if (-not (Skipped 'python')) {
    # every run, since a toolchain provisioned before a module was added never reruns the stage above
    $py = Join-Path $ToolsRoot 'python\python.exe'
    if (-not (Test-Path $py)) { throw "no python at $py, delete $Dl\python.done to reinstall it" }
    $modules = [ordered]@{ pefile = 'pefile'; Registry = 'python-registry'; lief = 'lief'; capstone = 'capstone'; rich = 'rich' }
    $names = ($modules.Keys | ForEach-Object { "'$_'" }) -join ', '
    $missing = @(& $py -c "import importlib.util as u; print('\n'.join(m for m in [$names] if not u.find_spec(m)))" | Where-Object { $_ })
    if ($missing.Count) {
        Log "installing python modules $($missing -join ', ')"
        & $py -m pip install --quiet @($missing | ForEach-Object { $modules[$_] })
        if ($LASTEXITCODE -ne 0) { throw 'pip install failed' }
    }
}

if (-not (Skipped 'detours') -and -not (Done 'detours')) {
    $z = Join-Path $Dl 'detours.zip'; Get-File $Src.detours $z
    $srcDir = Join-Path $ToolsRoot 'detours'
    Expand-ZipTo $z $srcDir -StripTopDir
    Log 'building detours (nmake)'
    $envScript = Join-Path $PSScriptRoot 'env.ps1'
    $build = @"
`$ErrorActionPreference='Stop'
. '$envScript' -ToolsRoot '$ToolsRoot'
`$env:DETOURS_TARGET_PROCESSOR='X64'
Set-Location '$srcDir\src'
nmake
exit `$LASTEXITCODE
"@
    $bp = Join-Path $Dl 'build-detours.ps1'; Set-Content $bp $build -Encoding ascii
    $pr = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$bp`"") -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $Dl 'build-detours.log')
    if ($pr.ExitCode -ne 0 -or -not (Test-Path (Join-Path $srcDir 'lib.X64\detours.lib'))) { throw "detours build failed, see $Dl\build-detours.log" }
    Mark 'detours'; Log 'detours built'
}

[Environment]::SetEnvironmentVariable('KEEL_TOOLS', $ToolsRoot, 'User')
[Environment]::SetEnvironmentVariable('KEEL_ROOT', (Resolve-Path (Join-Path $PSScriptRoot '..')).Path, 'User')
[Environment]::SetEnvironmentVariable('_NT_SYMBOL_PATH', 'SRV*C:\Keel-symbols*https://msdl.microsoft.com/download/symbols', 'User')
New-Item -ItemType Directory -Force 'C:\Keel-symbols', 'C:\Keel-media' | Out-Null

Log 'toolchain ready'
Stop-Transcript | Out-Null
