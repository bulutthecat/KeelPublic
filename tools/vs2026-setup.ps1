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

<#
.SYNOPSIS
    One-stop provisioning of the VS2026 Community build environment for OpenDWM
    (Project Keel) on Windows 11 25H2 (b26300+) x64.

.DESCRIPTION
    Run this ONCE after cloning. It makes "open build\Keel.sln, press F5" true:

      1. sanity-checks the OS (x64, b22621+; warns below 26300 = 25H2)
      2. installs missing prerequisites through winget (silent, I agree to licenses):
           - Visual Studio Community 2026 with the C++ workload + CMake tools
             (exact package id auto-discovered from 'winget search'; override with
              -VsId if the store id differs in your region/channel)
           - Windows 11 SDK 10.0.26100 (only if VS did not already bring a newer one)
           - Windows Driver Kit 11 (needed only for the keeldrv project)
           - Git for Windows, Python 3, Ninja, CMake (each skipped when present)
         Every install can be skipped with -Skip git,python,ninja,cmake,vs,sdk,wdk
      3. provisions the repo-local toolchain via tools\setup-toolchain.ps1
         (MSVC redist layout + builds Microsoft Detours v4.0.1 -> lib.X64\detours.lib,
          which keelshim/keeltsf/keelldr link against). Skip with -SkipToolchain.
      4. regenerates build\Keel.sln + build\vs\*.vcxproj with tools\gen-vs2026-sln.py
         (GUID-stable via build\project-guids.json)
      5. smoke-tests the solution: msbuild /t:Restore,NoRebuild /v:m on keelcommon
         (fastest target, no detours dependency) unless -NoSmoke

.PARAMETER ToolsRoot
    Where setup-toolchain.ps1 puts MSVC/Detours/etc. Default C:\Keel-tools.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1 -Skip wdk -NoSmoke
#>
[CmdletBinding()]
param(
    [string]$ToolsRoot = 'C:\Keel-tools',
    [string]$VsId = '',                 # winget package id of VS2026 Community
    [ValidateSet('Community','Professional','Enterprise')][string]$VsEdition = 'Community',
    [string[]]$Skip = @(),
    [switch]$SkipToolchain,
    [switch]$NoSmoke
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repoRoot = Split-Path $PSScriptRoot
$sw = [Diagnostics.Stopwatch]::StartNew()
function Log($m) { Write-Host ("[{0:hh\:mm\:ss}] {1}" -f $sw.Elapsed, $m) }
function Skipped($k) { return ($Skip -contains $k) }

# ---------------------------------------------------------------- 1. sanity --
$os = [System.Environment]::OSVersion.Version
if (-not ([Environment]::Is64BitOperatingSystem)) { throw 'OpenDWM VS projects are x64 host only.' }
Log "Windows build $([int]$os.Build) detected"
if ($os.Build -lt 22621) { throw "Windows 11 required (25H2 = b26300+); found build $([int]$os.Build)." }
if ($os.Build -lt 26300) { Log 'WARN: pre-25H2 build - VS2026 may refuse to install; continuing.' }

# ------------------------------------------------------- 2. winget helpers --
function Get-Winget {
    $g = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $g) {
        $candidate = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path $candidate) { return $candidate }
    }
    if ($g) { return $g.Source }
    return $null
}
function Invoke-WingetInstall([string]$Id, [string]$ExtraArgs = @()) {
    $winget = Get-Winget
    if (-not $winget) { Log "WARN winget unavailable - install '$Id' manually"; return $false }
    Log "winget install $Id"
    $args = @('install','--id',$Id,'--exact','--silent','--accept-package-agreements','--accept-source-agreements')
    if ($ExtraArgs) { $args += $ExtraArgs }
    & $winget @args
    $rc = $LASTEXITCODE
    # 0 = installed, -1978335189 (0x8A15002B) = no applicable upgrade = already installed
    if ($rc -ne 0 -and $rc -ne -1978335189) { Log "WARN winget $Id exit $rc (continuing)" ; return $false }
    return $true
}
function Find-WingetId([string]$Query, [string]$MatchRegex) {
    $winget = Get-Winget
    if (-not $winget) { return $null }
    $out = & $winget search $Query --accept-source-agreements 2>$null | Out-String
    ($out -split "`r?`n") | ForEach-Object {
        if ($_ -match '^\s*(\S+)\s' ) { $Matches[1] }
    } | Where-Object { $_ -match $MatchRegex } | Select-Object -First 1
}

# --------------------------------------------------- 3. individual checks ---
function Test-VsWithCpp {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { return $false }
    $inst = & $vswhere -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    return [bool]$inst
}
function Get-LatestInstalledSdk {
    $kits = @("$env:ProgramFiles\Windows Kits\10", (Join-Path $ToolsRoot 'msvc\Windows Kits\10'))
    $best = $null
    foreach ($k in $kits) {
        $inc = Join-Path $k 'Include'
        if (-not (Test-Path $inc)) { continue }
        foreach ($d in (Get-ChildItem $inc -Directory | Where-Object { $_.Name -match '^\d+(\.\d+)+$' -and (Test-Path (Join-Path $_.FullName 'um\x64')) })) {
            $v = [version]$d.Name
            if (-not $best -or $v -gt $best) { $best = $v }
        }
    }
    if ($best) { return $best.ToString() } else { return $null }
}
function Test-WdkKmLibs {
    $kits = "$env:ProgramFiles\Windows Kits\10"
    return (Test-Path (Join-Path $kits 'Lib\*\km\x64\ntoskrnl.lib' -ErrorAction SilentlyContinue)) -or
           (@(Get-ChildItem (Join-Path $kits 'Lib') -Recurse -Filter ntoskrnl.lib -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -match '\\km\\x64\\' }).Count -gt 0)
}

# ------------------------------------------------------ 4. installations ----
if (-not (Skipped 'git') -and -not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
    Invoke-WingetInstall 'Git.Git' | Out-Null
}
if (-not (Skipped 'python') -and -not (Get-Command py.exe -ErrorAction SilentlyContinue) `
                                   -and -not (Get-Command python.exe -ErrorAction SilentlyContinue)) {
    Invoke-WingetInstall 'Python.Python.3.12' | Out-Null
}
if (-not (Skipped 'ninja') -and -not (Get-Command ninja.exe -ErrorAction SilentlyContinue)) {
    Invoke-WingetInstall 'Ninja-build.Ninja' | Out-Null
}
if (-not (Skipped 'cmake') -and -not (Get-Command cmake.exe -ErrorAction SilentlyContinue)) {
    Invoke-WingetInstall 'Kitware.CMake' | Out-Null
}

if (-not (Skipped 'vs')) {
    if (Test-VsWithCpp) {
        Log 'VS with C++ workload already installed - skipping VS install'
    } else {
        $id = $VsId
        if (-not $id) {
            # VS2026 (Dev18) publishes as Microsoft.VisualStudio.Community / .Professional /
            # .Enterprise once in the public winget source; fall back to searching so this
            # script keeps working across channel renames.
            $known = "Microsoft.VisualStudio.$VsEdition"
            $probe = Get-Winget
            if ($probe) {
                $found = (& $probe show $known --accept-source-agreements 2>$null | Out-String)
                if ($found -notmatch 'No package found') { $id = $known }
            }
            if (-not $id) {
                $id = Find-WingetId "Visual Studio $VsEdition" "^Microsoft\.VisualStudio\.(Community|Professional|Enterprise)$"
            }
        }
        if (-not $id) { throw "Could not resolve a winget id for VS2026 $VsEdition. Install it manually (workload: 'Desktop development with C++'), or pass -VsId <id>." }
        Log "installing $id with the C++ desktop workload (~several GB, unattended)"
        Invoke-WingetInstall $id @(
            '--override', ('--quiet --wait --norestart --nocache ' +
              '--add Microsoft.VisualStudio.Workload.NativeDesktop ' +
              '--add Microsoft.VisualStudio.Component.VC.CMake.Project ' +
              '--includeRecommended')
        ) | Out-Null
        if (-not (Test-VsWithCpp)) { throw "VS install reported success but vswhere finds no C++ toolset - check %TEMP%\*vs_installer*logs" }
    }
}

if (-not (Skipped 'sdk')) {
    $have = Get-LatestInstalledSdk
    if ($have -and ([version]$have) -ge [version]'10.0.26100') {
        Log "Windows SDK $have already installed - skipping"
    } else {
        Invoke-WingetInstall 'Microsoft.WindowsSDK.10.0.26100' | Out-Null
        $have = Get-LatestInstalledSdk
        if (-not $have) { Log 'WARN: no Windows SDK with um\x64 libs found after install' }
    }
}

if (-not (Skipped 'wdk')) {
    if (Test-WdkKmLibs) {
        Log 'WDK km libs present - skipping'
    } else {
        # WDK ships as an MSI bundle (no stable winget id across releases); use the
        # fwlink that always points at the current Win11 WDK, same URL as setup-toolchain.ps1.
        Log 'installing Windows Driver Kit (needed only for keeldrv.sys)'
        $exe = Join-Path ([IO.Path]::GetTempPath()) 'wdksetup-vs2026.exe'
        try {
            Invoke-WebRequest 'https://go.microsoft.com/fwlink/?linkid=2286137' -OutFile $exe -UseBasicParsing
            $p = Start-Process $exe -ArgumentList @('/quiet','/norestart','/features','OptionId.DesktopWDK') -Wait -PassThru
            if ($p.ExitCode -ne 0) { Log "WARN wdksetup exit $($p.ExitCode) - keeldrv will fail until WDK is installed" }
        } catch {
            Log "WARN WDK download/install failed: $($_.Exception.Message) - keeldrv excluded from comfort path"
        } finally {
            Remove-Item $exe -Force -ErrorAction SilentlyContinue
        }
    }
}

# refresh PATH/INCLUDE-relevant env for this process after installs
$machinePath = [Environment]::GetEnvironmentVariable('PATH','Machine')
$userPath    = [Environment]::GetEnvironmentVariable('PATH','User')
$env:PATH    = "$machinePath;$userPath;$env:PATH"

# ------------------------------------------- 5. repo-local toolchain --------
if (-not $SkipToolchain) {
    Log 'running tools\setup-toolchain.ps1 (MSVC layout + Detours import lib)'
    & (Join-Path $PSScriptRoot 'setup-toolchain.ps1') -ToolsRoot $ToolsRoot
    if ($LASTEXITCODE) { throw "setup-toolchain.ps1 failed ($LASTEXITCODE)" }
}
$detLib = Join-Path $ToolsRoot 'detours\lib.X64\detours.lib'
if (-not (Test-Path $detLib)) { Log "WARN: $detLib missing - keelshim/keeltsf/keelldr will not link until setup-toolchain.ps1 succeeds" }

# ------------------------------------- 6. regenerate sln + smoke test -------
$py = $null
foreach ($c in 'py','python','python3') { $g = Get-Command $c -ErrorAction SilentlyContinue; if ($g) { $py = $g.Source; break } }
if (-not $py) { $cand = Join-Path $ToolsRoot 'python\python.exe'; if (Test-Path $cand) { $py = $cand } }
if ($py) {
    Log 'regenerating build\Keel.sln + build\vs\*.vcxproj (stable GUIDs)'
    & $py (Join-Path $PSScriptRoot 'gen-vs2026-sln.py')
    if ($LASTEXITCODE) { throw "gen-vs2026-sln.py failed ($LASTEXITCODE)" }
} else {
    Log 'WARN python not found - keeping the checked-in build\Keel.sln as-is'
}

if (-not $NoSmoke -and (Test-VsWithCpp)) {
    Log 'smoke-testing the solution (msbuild keelcommon)'
    $msbuild = $null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $msbuild = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    }
    if (-not $msbuild) { $g = Get-Command msbuild.exe -ErrorAction SilentlyContinue; if ($g) { $msbuild = $g.Source } }
    if ($msbuild) {
        & $msbuild (Join-Path $repoRoot 'build\vs\keelcommon.vcxproj') /p:Configuration=Debug /p:Platform=x64 /v:m /nologo
        if ($LASTEXITCODE -eq 0) { Log 'smoke build OK - solution is ready: open build\Keel.sln in VS2026 and press F7' }
        else { Log "WARN smoke build exit $LASTEXITCODE - open build\Keel.sln and read the Error List; common cause: KEEL_TOOLS/Detours missing (see log above)" }
    } else {
        Log 'WARN msbuild not located - skipping smoke test'
    }
}

Log 'done. Next steps:'
Write-Host @"
  1. open  $repoRoot\build\Keel.sln   in Visual Studio 2026 Community
     (set startup project: keelldr for debugging, or build the whole solution)
  2. build  msbuild build\Keel.sln /p:Configuration=Debug /p:Platform=x64
            msbuild build\Keel.sln /p:Configuration=Debug /p:Platform=Win32
  3. driver: keeldrv needs the WDK (installed above unless -Skip wdk);
             ARM64EC config exists for kits that dropped x64 km libs.
  4. rerun this script any time after moving machines; it is idempotent.
"@
