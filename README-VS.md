# Building OpenDWM (Project Keel) with Visual Studio 2026 Community
Windows 11 25H2 (build 26300+) · x64 host · no CMake required

## One command to get everything

```powershell
git clone https://github.com/ArtemITuser/OpenDWM.git
cd OpenDWM
powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1
```

The script is idempotent and does, in order:

| Step | What happens | Skip flag |
|------|--------------|-----------|
| 1 | checks OS arch/build (x64, b22621+, warns <26300) | — |
| 2 | `winget` installs whatever is missing: VS2026 Community (+ *Desktop development with C++* + CMake tools), Win11 SDK 10.0.26100, WDK (for keeldrv only), Git, Python 3.12, Ninja, CMake | `-Skip vs,sdk,wdk,git,python,ninja,cmake` |
| 3 | runs `tools\setup-toolchain.ps1` → repo-local MSVC layout in `C:\Keel-tools` and builds **Microsoft Detours v4.0.1** (`detours\lib.X64\detours.lib`, needed by keelshim/keeltsf/keelldr) | `-SkipToolchain` |
| 4 | regenerates `build\Keel.sln` + `build\vs\*.vcxproj` via `tools\gen-vs2026-sln.py` | — |
| 5 | smoke-builds `keelcommon.vcxproj` with the located MSBuild | `-NoSmoke` |

Useful switches: `-ToolsRoot D:\Keel-tools`, `-VsId Microsoft.VisualStudio.Community`
(if winget's id differs on your channel), `-VsEdition Professional`.

Then simply open **`build\Keel.sln`** in VS2026 Community — nothing else to configure.

## Solution layout

* solution folders: **x64** (12 projects), **x86** (5 projects), **driver** (keeldrv)
* configurations: `Debug` / `RelWithDebInfo` × `x64` / `Win32` / `ARM64EC` (driver only)
* toolset: `v145` (VS2026). Pin another one per invocation:
  `msbuild build\Keel.sln /p:VctoolsVersion=v144` — `build\Directory.Build.props` honours it.
* SDK: `WindowsTargetPlatformVersion = 10.0` → newest installed SDK (the 26100+ kit from step 2).
* outputs land in `out\vs\<Config>\<target>\` so they never collide with the Ninja flow
  (`tools\build.ps1` / `out\debug`).
* IDE state is safe across regenerations: project GUIDs are pinned in
  `build\project-guids.json` (delete that file only if you *want* fresh GUIDs everywhere).

## Command-line builds

```powershell
msbuild build\Keel.sln /p:Configuration=Debug         /p:Platform=x64    # x64 side
msbuild build\Keel.sln /p:Configuration=RelWithDebInfo /p:Platform=Win32 # wow64 side
msbuild build\Keel.sln /t:keeldrv /p:Configuration=Debug /p:Platform=x64 # driver (needs WDK)
```

`Directory.Build.props` auto-resolves `KEEL_TOOLS` (→ `%DETOURS_ROOT%` or `%KEEL_TOOLS%`
or `C:\Keel-tools`), the Windows Kits root, the newest SDK version and the KMDF libs;
if your WDK ships no x64 kernel libs, the ARM64EC configuration of keeldrv still builds
(the check target reports this clearly instead of a raw link error).

## After editing sources / CMakeLists.txt

`build\Keel.sln` and `build\vs\*.vcxproj` are generated artifacts — regenerate them:

```powershell
py -3 tools\gen-vs2026-sln.py
```

Source lists, defines and link inputs mirror `src/CMakeLists.txt` and
`src32/CMakeLists.txt`; new targets must be added to `main()` in the generator
(one `emit(...)` call each).

## Troubleshooting

* **`LNK1104 detours.lib`** → run `tools\setup-toolchain.ps1` (step 3 above); verify
  `C:\Keel-tools\detours\lib.X64\detours.lib`. Or set `DETOURS_ROOT` before launching VS.
* **keeldrv: "this WDK ships no x64 km libraries"** → install the WDK or build the
  ARM64EC configuration of the driver project.
* **VS says projects need migration** → you opened an old checkout; pull and rerun
  `py -3 tools\gen-vs2026-sln.py` (GUIDs stay stable, `.vs\` cache can be deleted).
* **winget cannot find VS2026** (Insider channel lag) → install manually from
  aka.ms/vspr, workload *Desktop development with C++*, then rerun with `-Skip vs`.
