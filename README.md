# Keel

![header1](https://github.com/bulutthecat/KeelPublic/blob/main/doc/imgs/img1.png)

Run Windows 7's real compositor, theme engine and shell on the Windows 10 kernel.

What made Windows 7 so special to so many different people is undoubtedly the graphical
interface. The entirety of the Windows 7 experience lives in user-mode, specifically the
Desktop Window Manager (`dwm.exe`, `dwmcore.dll`, `udwm.dll`, `dwmredir.dll`,
`milcore.dll`, `dwmapi.dll`), the themeing engine (`uxtheme.dll`, `themeui.dll`, `aero.msstyles`)
and the shell (`explorer.exe`, `shell32.dll`, `explorerframe.dll`, `stobject.dll`).

If you notice, none of that is actually a part of the system kernel, and all the compatibility
issues live *in the kernel*. When installing unsupported drivers, attempting to fix
graphical hangs on boot caused by *int10h*, getting bluetooth or modern Wifi drivers working.
You are attempting to patch the kernel of Windows 7, or implement workarounds
to get existing software functional well past manufacturer or software support window.

So why not meet in the middle and patch the Windows 10 kernel to support the
Windows 7 graphical environment instead? Everyone knows it would be impossible
to support all drivers from all manufacturers, so what if we simply didn't?

Keel is a translation layer first and foremost, with no regard for reimplementing a compositor,
window manager or a desktop environment. Windows 7 handles all of that for us.

**It is important to remember that this project is in a very VERY early stage!!
you should not expect everything to be working perfectly and there are plenty
of weird, obtuse, and downright annoying bugs that are going to be patched
over time. There are and will be graphical bugs, crashes, glitches and weird
behavior which make it unsuitable without great manual modification for daily
use. Futures you might expect to 'just work' might not work at all
compared to Windows 10 or Windows 7 and are going to be ironed out
over time.**

If you want to support me and get access to pre-compiled / build ISO images
with updates up to two weeks ahead of public releases, feel free to join my
Patreon! It compensates me for my work, and lets me keep this project
open. Visit the [Keel Project Patreon welcome post](https://www.patreon.com/ProjectKeel/posts/official-keel-170459791?utm_medium=clipboard_copy&utm_source=copyLink&utm_campaign=postshare_creator&utm_content=join_link) for more information.

![banner](https://github.com/bulutthecat/KeelPublic/blob/main/doc/imgs/img2.jpg?raw=true)
^ Example of an Surface Pro 7 (With no Win7 drivers) running the latest version of Fusion 360 (with no win7 version).

## Targeted Platforms

| Role  | Platform                                 | Build      |
|-------|------------------------------------------|------------|
| Host  | Windows 10 IoT Enterprise LTSC 2021, x64 | 10.0.19044 |
| Donor | Windows 7 Service Pack 1, x64            | 6.1.7601   |

Every reverse-engineering result is tied to these two builds. Offsets, ordinals and
structure layouts are build specific and I will not be changing this until
Windows 10 LTSC becomes out of date.

## Layout

```
src\      keelshim (translation DLL), keelldr (loader), keeldrv (driver),
          keeldcomp (dcomp trans.), keelbroker, keeluxsms, probes and tests
src32\    32-bit keelshim32, keelldr32, probes
tools\    toolchain, donor extraction, translation generation, ISO builder
vm\       payload and the installer media
donor\    (ignored) extracted Windows 7 binaries
```

## Building the installer media and installing

You are required to supply the ISO image for both Windows 10 IoT Enterprise LTSC 2021 x64
and Windows 7 SP1 x64.

By default, Keel expects these images to be located and named like this:
`C:\Keel-media\LTSC2021_x64.iso # Windows 10 LTSC`
`C:\Keel-media\Win7SP1_x64.iso # Windows 7 SP1`

**OPTIONAL:** For UEFI support, make sure to install the [Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install]), you only need the "Development Tools" future.

The build does not care which Windows it runs on. The import seams are generated against the
`user32`, `ntdll`, `kernel32` and `dwmapi` taken out of the LTSC image you provided.


After cloning / downloading the repository, from an administrator PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File tools\make-keel-iso.ps1
```

The Windows 10 ISO supplies the base system and the installer along with boot sectors;
`tools\extract-hostref.ps1` also grabs the handful of Windows 10 binaries the seams forward to out
of it, into `host-ref\raw`. The Windows 7 ISO provides the userland. `tools\extract-donor.ps1` unpacks it into `donor\raw`,
then `tools\make-cut3.ps1` builds `donor\cut3` from it. Should be ~181 files copied straight out of the
donor, plus the api-set shims, the import seams and the retargeted manifests. Both run on their
own when their output is missing, and the result is checked against `tools\cut3-manifest.json`,
which carries a SHA-256 for every donor file so it *should* warn you.

The execution payload is located in `sources\$OEM$\$1\Keel`, and the answer file
installs Windows unattended, disables defender, and runs `vm\first-boot.ps1`, which applies the
stack and reboots into the windows 7 desktop.

This doesnt result in a modified `install.wim`. Keel is designed to be a machine state
(registry, IFEO, `AppInit_DLLs`, a shell swap and a signed driver) rather than files
in an image, so the media installs stock Windows 10 and then patches it.

This is for all the modded Windows dev's out there, who want to provide their own pre-modified
version of the Windows 10 LTSC branch. `make-keel-iso.ps1` runs the earlier stages for you.

Useful switches: `-SkipBuild` to reuse `out\`, `-SkipRegMerge` to skip the registry
delta, and `-Disk UEFI|BIOS` to pick a fully automatic disk layout instead of the
interactive default. It needs `oscdimg.exe` from the Windows ADK Deployment Tools.

If you want to experiment with a different Windows 7 image, `-AllowDonorMismatch` lets the
build through when the donor files don't match the checksums in `tools\cut3-manifest.json`.
Keelshim patches code at fixed offsets inside the donor binaries, so expect a broken shell or
compositor on anything but the exact build. Media built this way leaves `C:\Keel\donor-mismatch.txt`
on the installed machine so it's obvious in a bug report.

Every run writes its full output to `make-keel-iso.log` next to the ISO. What a good build and
install look like, where the installed machine keeps its logs (`C:\Keel\first-boot.log`,
`C:\Keel\native-keel.log`) and the known failure states are in
[doc/troubleshooting.md](doc/troubleshooting.md).

### The toolchain

Nothing has to be installed by hand. On its first run `make-keel-iso.ps1` provisions
everything into `C:\Keel-tools` before it builds anything, and later runs skip whatever
is already there. You can also do it on its own:

```powershell
powershell -ExecutionPolicy Bypass -File tools\setup-toolchain.ps1
```

It fetches MSVC, the Windows SDK and WDK, CMake, Ninja, Python, MinGit and 7-Zip, builds
Detours from source, and creates `C:\Keel-media` for your two ISOs. Override the location
with `-ToolsRoot`, resume a partial run by re-running it, and skip a stage with
`-Skip msvc,wdk,tools,python,detours`. Progress is logged to
`C:\Keel-tools\_dl\setup-toolchain.log`.

The Windows ADK is the one thing it does not fetch because of the maintainer rules.

### Building with Visual Studio 2026 (alternative to CMake)

`build\Keel.sln` (18 VC++ projects, Debug/RelWithDebInfo x64/Win32/ARM64EC) is checked
in and kept in sync with CMake. One command installs VS2026 Community + SDK + WDK +
Detours and smoke-builds a project:

```powershell
powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1
msbuild build\Keel.sln /p:Configuration=RelWithDebInfo /p:Platform=x64
```

See `README-VS.md` for details; regenerate the solution after edits with
`python tools\gen-vs2026-sln.py`.

### Building the code alone

```powershell
. .\tools\env.ps1                  # env for the portable toolchain
cmake -S src -B out\debug -G Ninja
cmake --build out\debug
.\tools\build32.ps1                # the 32-bit tree which needs its own toolchain
```

The 32-bit tree must be built by `tools\build32.ps1`, which activates an x86
toolchain. Building it from a shell that is sourcing `tools\env.ps1` fails
to link.

## Defender

Defender must be off before anything is applied. Its ML engine classifies the
Windows 7 shell swap as `Trojan:Win32/Bearfoos.A!ml` and remediates it, deleting COM
registrations and scheduled tasks in a way that survives reboots and looks like a bug.
The answer file disables it during `specialize`, which is the only moment
the machine can do that to itself because tamper protection refuses later attempts.

Blame microsoft.

## Known bugs and limitations

These are bugs understood well enough to describe and all of them are on my patch list.

These are all high-priority items, and WILL be patched as soon as possible.
Expect these to be fixed within the coming four to five weeks.

- **The logon screen is black.** Windows 10's `LogonUI` draws through DirectComposition and emits
  no GDI present tokens which is required for rendering by the Windows 7 compositor. 
  For now, the system autologin's, so do not lock, sign out or set a password.
- **UWP applications do not render.** (Settings, Xbox, Store), for the same reason. Win32
  applications are unaffected. A DirectComposition implementation inside keeldwm is planned
  for those applications, but nothing else.
- **Black horizontal streaks on Intel GPU's (on rare occasions)**
- **Explorer freezes at random.** The shell or an open folder window can stop responding with no
  clear trigger.
- **RemoteApp and Desktop Connections does not launch.** This requires a binary not present in Windows 7 SP1
  The Windows 10 era items (Storage Spaces, File History, Work Folders) are not
  functional as of right now including some of the right click items on the desktop.
- **In-app Aero glass is black in 64-bit programs.** Internet Explorer draws its title and toolbar
  band black with no caption buttons, and the Windows troubleshooter (msdt) draws its header black.
  The seam that fixed Office 2010 covers every 32-bit process, but these windows belong to 64-bit
  processes that load Windows 10's own dwmapi, which never reaches the Windows 7 compositor. IE's
  tabs are 32-bit and do connect, its frame is 64-bit and does not. The fix is the same seam for 64-bit.
- **Control Panel says "This computer is not running genuine Windows".** This has nothing to do with
  activation and it shows on activated machines too. The Windows 7 Control Panel runs a tamper check
  that looks for a licensing service and file (`sppuinotify`) that Windows 10 removed. (After further testing,
  activation appears to get rid of the notification. I am looking into this further).
- **Devices and Printers never finishes loading.** The window opens and stays blank.
- **Run > Browse (and other file dialogs the shell opens itself) does nothing.** Windows 10's
  comdlg32 cannot load inside the Windows 7 shell, it asks the Windows 7 shell32 for three exports
  it does not have.
- **`control.exe` can only open the Control Panel home.** `control appwiz.cpl` and
  `control powercfg.cpl` show "No such interface supported" because the Windows 7 control.exe hands
  them to Windows 10's rundll32, and `control /name Microsoft.X` opens nothing because a COM class it
  activates out of process is not registered. Opening the same pages from Control Panel works for now.
- **Windows servicing is untested and will most likely not work.** Every offset is designed for
  19044, SFC and cumulative update will revert in-place changes.
- **Test signing has to stay on.** `keeldrv` is not WHQL signed as of right now, this is planned
  for future updates if there is enough demand for me to get a licence.

Quick patch updates will be included for items in this list, as new bug fixes come out.
So from the time you install there will be a path to patch the operating system without
having to reinstall every time a fix comes to a major bug like ones of the above (in
theory, some patches might not be able to be done in-place).

These will be included in the releases tab in the form of a powershell scripts.

# Licencing / Legal

This project is licenced under GPLv3. For more information, read `LICENCE.md`.

If you really want to use this project and GPLv3 licencing isnt a good fit for your
application, please feel free to contact me directly for an alternative licencing
option for your usecase. You can find me directly at `projectkeel@gmail.com`

You may also use the email above for reporting critical security issues and additionally
for legal or copyright reasons.
