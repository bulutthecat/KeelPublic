# Building the Keel installer ISO (live/install media)

This is the "package into an installable image" step that sits **after** the VS2026
build (`README-VS.md`). One command stages a Windows 10 LTSC 2021 x64 ISO with the
Windows 7 donor userland and the Keel payload, and produces a bootable unattended
install ISO. Everything runs on Windows 11 25H2 with VS2026 Community; no manual
installs are required except supplying the two Microsoft ISOs you own licenses for.

## What you need before the first run

| # | Item | Why | Where it comes from |
|---|------|-----|---------------------|
| 1 | Windows 10 IoT Enterprise LTSC 2021 x64 ISO (**must carry `sources\install.wim`, not `.esd`**) | base OS + installer + boot sectors + stock registry hives | your licensed copy, e.g. Visual Studio Subscriptions / EVAL center |
| 2 | Windows 7 SP1 x64 ISO | donor userland (dwm.exe, shell, aero theme) | your licensed copy (e.g. UUP dump-era retail ISO) |
| 3 | VS2026 + SDK 26100 + WDK + Detours | compilation | `tools\vs2026-setup.ps1` installs all of this automatically |
| 4 | 7-Zip, Python, CMake, Ninja, MinGit | extraction, reg-merge census, build | downloaded by `tools\setup-toolchain.ps1` into `C:\Keel-tools` |
| 5 | ~80 GB free disk on `C:` (staging tree + output ISO) | unpacking two ISOs | - |
| 6 | Internet access on first run | toolchain downloads | - |

Place the ISOs where the scripts look by default:

```
C:\Keel-media\LTSC2021_x64.iso   # Windows 10 IoT Enterprise LTSC 2021 x64
C:\Keel-media\Win7SP1_x64.iso    # Windows 7 SP1 x64
```

(Other paths work too — pass `-Win10Iso` / `-Win7Iso`.)

## One command

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File tools\make-keel-iso.ps1
```

Optional switches:

```
-Win10Iso <path>   -Win7Iso <path>   -Out <iso path>     -Work <staging dir>
-Disk Interactive|UEFI|BIOS   (partition layout in autounattend.xml)
-SkipBuild         reuse existing out\debug and out\x86 artifacts
-SkipRegMerge      skip the Win7 registry hive diff (Control Panel will likely break)
-ReuseWork         keep/reuse the staging tree (faster reruns)
-KeepWork          don't delete the staging tree afterwards
```

What it does, in order (see the script's own steps):

1. Provisions the toolchain into `C:\Keel-tools` if absent (`setup-toolchain.ps1`).
2. Extracts the Win7 donor into `donor\raw` (`extract-donor.ps1`) and builds the
   retargeted userland `donor\cut3` against the pinned host reference
   (`host-ref\raw`, captured from your LTSC ISO by `extract-hostref.ps1`; verified
   file-by-file against `tools\cut3-manifest.json` SHA-256s).
3. Builds everything: `build.ps1` (x64) + `build32.ps1` (x86), the dwmapi seam
   (`make-dwmapi32-seam.ps1`) and signs the driver (`sign-driver.ps1`).
4. Unpacks the LTSC ISO, stages the payload under `sources\$OEM$\$1\Keel`
   (bin/bin32/rtm/win7theme/vm/regmerge/fallback).
5. Precomputes the Windows 7 registry merge by diffing donor hives against the
   stock `install.wim` SOFTWARE/DEFAULT hives (needs Python + `tools\census\reg_merge.py`).
6. Writes `autounattend.xml` (disk mode selectable; sets `bcdedit /set testsigning on`).
7. Produces the bootable ISO with **oscdimg** (UEFI+BIOS, etfsboot/efisys from the LTSC media).

Output: `C:\Keel-media\Keel-LTSC2021.iso`. Boot it in a throwaway VM (Hyper-V/VMware/QEMU,
no other answer file mounted — the two would race); it installs LTSC unattended, applies
Keel via `vm\apply-keel-guest.ps1`, reboots into the Windows 7 desktop.

## Gotchas found while wiring this up

* **oscdimg is NOT installed by `setup-toolchain.ps1`.** It ships only with the
  Windows ADK ("Deployment Tools"). Either install the ADK
  (<https://learn.microsoft.com/windows/hardware/get-started/adk-install>, pick
  *Deployment Tools*), or drop any `oscdimg.exe` into `C:\Keel-tools\oscdimg\`
  (the script searches `$env:KEEL_TOOLS` recursively as a fallback). Without it
  the script warns and falls back to .NET `System.IO.Compression` ISO writing,
  which produces a **non-bootable** image unless `boot\etfsboot.com` is present
  in the staged media (it is, when using a genuine LTSC ISO — but prefer oscdimg).
* **`install.esd` LTSC images are rejected** at the registry-precompute step. Use a
  `.wim`-based ISO (retail/EVAL LTSC 2021 images ship `install.wim`).
* **Test signing.** `sign-driver.ps1` creates a self-signed CodeSigning cert in
  `Cert:\CurrentUser\My` and exports `out\debug\keeldrv\keeltest.cer`. The media's
  answer file enables `testsigning`, so nothing to do for VM testing; for bare metal
  keep Secure Boot off or import `keeltest.cer` into the machine's Root +
  TrustedPublisher store. Delete/recreate the cert only if you want fresh thumbprints.
* **Donor must be SP1 x64 7601 exactly** — offsets/ordinals are pinned to that build
  (README "Targeted Platforms"); cut3 verification fails loudly otherwise.
* 32-bit outputs (`out\x86`) are optional but strongly recommended: without them the
  script warns that 32-bit apps hang in TSF and there is no in-app glass for Word etc.
* Rerun speed: after the first successful pass use `-SkipBuild -ReuseWork` to only
  restage media, or `-SkipBuild` alone to rebuild the ISO from current binaries.

## Quick checklist for the very first run

```powershell
# 1. one-shot environment (VS workload, SDK, WDK, Detours, smoke build)
powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1
# 2. put your two ISOs into C:\Keel-media (names as above)
# 3. (optional but recommended) install ADK Deployment Tools for oscdimg
# 4. build the media (~30-60 min first run: donor extraction + cut3 + full build)
powershell -ExecutionPolicy Bypass -File tools\make-keel-iso.ps1
# 5. boot C:\Keel-media\Keel-LTSC2021.iso in a throwaway VM
```
