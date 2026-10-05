# Troubleshooting a Keel build

This page covers what a healthy build and install look like, where every log is located, and more
common failiures that you might find. If something here does not match
what you see, open an issue and attach the logs listed under "What to send".

## Where the logs are

Two machines are involved and they keep different logs in different locations.
The *build machine* is the one you ran `make-keel-iso.ps1` on.
Whilte the *installed machine* is the one you booted the ISO on, its logs
are located on the drive Keel was installed to.

| Machine   | File                                    | Written by                                                          |
|-----------|-----------------------------------------|---------------------------------------------------------------------|
| build     | `C:\Keel-media\make-keel-iso.log`       | `make-keel-iso.ps1` run, next to the ISO (follows `-Out`)           |
| build     | `C:\Keel-tools\_dl\setup-toolchain.log` | toolchain provisioning                                              |
| build     | `C:\Keel-tools\_dl\build-debug.log`     | the CMake build (`tools\build.ps1`)                                 |
| installed | `C:\Keel\first-boot.log`                | `vm\first-boot.ps1`, which applies Keel while Windows Setup runs    |
| installed | `C:\Keel\native-keel.log`               | keelldr and keelshim: the compositor and the shell, every boot      |
| installed | `C:\Keel\native-keel64.log`             | keeltsf, injected into every 64-bit process                         |
| installed | `C:\Keel\native-keel32.log`             | keelshim32 and keelldr32, the 32-bit side                           |
| installed | `C:\Keel\native-keeldcomp.log`          | the DirectComposition seam                                          |
| installed | `C:\Keel\keelstub.log`                  | the user32 seam the Win7 compositor imports                         |
| installed | `C:\Keel\dumps\`                        | crash dumps of any process (Windows Error Reporting LocalDumps)     |
| installed | `C:\Keel\donor-mismatch.txt`            | only there when the media was built with `-AllowDonorMismatch`      |
| installed | `C:\Windows\Panther\UnattendGC\setupact.log` | Windows Setup itself, including the `first-boot.ps1` command   |

`native-keel.log` is appended to on every boot and can grow to a substatial size. Each boot starts with a pair of
`[keelldr ...] host 10.0.19044.... pinned=1` / `launched pid ...` lines, the first one is the
compositor (`keeldwm.exe`) and the next one is the current shell instance (`explorer.exe`).

### What to send

`make-keel-iso.log`, `first-boot.log` and `native-keel.log` (zip it), plus a listing of
`C:\Keel\dumps`. If you only have the console output of `make-keel-iso.ps1`, that also works to help.

If the system boots but you cannot get graphics initilization, you can use WinRE (Windows Recovery) to copy the logs to a USB drive
and upload.

## What a good build looks like

`make-keel-iso.log` should pass through these lines in this order. The numbered `make-cut3` steps
only appear in a run that builds from `donor\cut3`:

```
! 1. prerequisites !
  ...
! 3. the private Common-Controls assembly !
  ...\Keel.Common-Controls\comctl32.dll embedded 32 resources from ...
  ...
! 7. verify against the manifest !
cut3 283 files on disk, manifest expects 283 (126 built here, recorded ...)
cut3 matches the manifest.
  ...
  build exit 0
  ...
x86 dwmapi seam built in ...\out\x86\dwmapi-seam
  ...
  prerequisites ok
  ...
! 5. precompute the Windows 7 registry merge !
  ...
      new keys=69351 new values=215056 ...
      wrote 4 file(s) to C:\Keel-media\_keeliso\merge-software
  ...
ISO C:\Keel-media\Keel-LTSC2021.iso  (4.72 GB)
```

A *WARNING* line anywhere in steps 4 or 5 means the installed machine will be missing often critical software.

## What a good install looks like

1. Boot the ISO (USB, DVD or VM), with Secure Boot **off**. Setup asks for the edition and the disk
   unless you built with `-Disk UEFI|BIOS`.
2. Setup copies Windows and with it `sources\$OEM$\$1\Keel` from the media to `C:\Keel` on the
   target disk.
3. At "Getting ready", Setup runs `C:\Keel\vm\first-boot.ps1` as SYSTEM.
   It takes about a minute and writes `C:\Keel\first-boot.log` under normal conditions.
4. Setup reboots, skips OOBE and signs in automatically as `keel` (password `1111`).
5. The screen can stay black for a few seconds while the Windows 7 compositor starts. Then you get the
   Windows 7 desktop: the Start orb, the taskbar with the tray clock, and Recycle Bin on the desktop.
   The very first sign-in is slower because the Windows 7 shell runs its one-time per-user setup, after that
   startup should be quick.

It is ready when the Start orb and taskbar are there. To confirm from a prompt everything is installed correctly:

```powershell
Test-Path C:\Keel\.keel-applied                          # True
Get-Process keeldwm, explorer | Select-Object Name, Path # C:\Keel\rtm\keeldwm.exe and C:\Keel\rtm\explorer.exe
sc.exe query keeldrv                                     # STATE : 4 RUNNING
```

### Healthy first-boot.log:

```
  registry merge applying C:\Keel\regmerge\software.tsv
    lines=284407 keysCreated=69351 ...
  'keel' administrator=True
    Shell=C:\Keel\bin\keelldr.exe --donor C:\Keel\rtm C:\Keel\rtm\explorer.exe
    testsigning=testsigning             Yes
    keeldrv=        START_TYPE         : 2   AUTO_START
    cert in Root=1
    IFEO set=True
Keel applied but not rebooting since Setup reboots into OOBE by itself, ...
```

These lines show up on working installs too and do not cause a significant problem:

- `PS>TerminatingError(Import-Certificate): "Access is denied..."`. The script falls back to
  `certutil` silently.
- `!WARNING! Defender is still active and will remediate the shell swap`. Defender is still running
  while Setup runs, the answer file disables it from the next boot on. Check after install with
  `sc.exe query WinDefend`, which should say `STOPPED`.
- `keysDenied=1 ... ProtectedRoots` and `valuesFailed=1` or `2` in the registry merge.

## Failure states

### Only the wallpaper is visible with no taskbar, Start orb or desktop icons

The mouse works and Ctrl+Shift+Esc opens Task Manager, but there is no shell, and
`Get-Process explorer` returns nothing.

`native-keel.log` shows the shell starting (a block of `[keelshim ... pid=N]` lines that includes
`com/exit diagnostics installed (... explorer=1)` and
`byte-patched explorer!ShouldStartDesktopAndTray`), and then that pid stops logging. Builds from
2026-10-02 on also log the exit itself:

```
[keelshim I pid=N ...] proc; RtlExitUserProcess code=0x1
[keelshim I pid=N ...]   #0 KERNEL32.DLL+0x...
[keelshim I pid=N ...]   #1 explorer.exe+0x...
```

A Windows 7 donor that is not the exact build Keel is made
from (see "The Windows 7 ISO is the wrong build" below). keelshim patches code at fixed offsets
inside the donor's `explorer.exe`, `shell32.dll`, `explorerframe.dll` and `dui70.dll`, and on any
other build those offsets point at the wrong code.

### A Windows 10 desktop instead of Windows 7

Keel was never applied. Look at the installed machine:

- **No `C:\Keel` folder.** Setup did not copy the payload. Install by booting the machine from the
  media, not by running `setup.exe` from inside a running Windows. If you write the ISO to USB with
  Rufus, decline its "Customize Windows installation" options. The Keel media already carries its own
  answer file, and a second one can replace it.
- **`C:\Keel` exists but `first-boot.log` is missing or ends early.** The specialize pass did not run
  it. `C:\Windows\Panther\UnattendGC\setupact.log` shows each command Setup ran and its result.
- **`first-boot.log` shows the `SECURE BOOT IS ENABLED` banner.** Turn Secure Boot off in the firmware
  settings. With it on, test signing and `AppInit_DLLs` are ignored.

### A black screen

The Windows 7 compositor did not start. Check, from Shift+F10 on the installer if nothing else works:

- the `[keelldr ...] host ... pinned=` line in `native-keel.log`. `pinned=0` means the installed
  Windows is not build 19044, so the Windows 10 ISO was not LTSC 2021.
- `sc.exe query keeldrv`, which must be `RUNNING`. If it is not, check that Secure Boot is off and
  `bcdedit` shows `testsigning Yes`.
- `C:\Keel\dumps` for `keeldwm.exe` dumps.

### The desktop works but Control Panel does not open

The Windows 7 registry merge is missing. `make-keel-iso.log` step 5 says `skipped` or
`reg_merge produced no merge.tsv`, and `first-boot.log` says `registry merge ... not on the media so
skipped`. The usual reason was a toolchain without the `python-registry` module, which
`setup-toolchain.ps1` and `make-keel-iso.ps1` now install. Rebuild the ISO.

### Things stop working some time after install

Folder windows or Control Panel stop opening, often after a reboot, and it looks like a bug. This
is Defender remediating the shell swap (see the Defender section in the README).
`sc.exe query WinDefend` should say `STOPPED`.

## Build-time failures

### The Windows 7 ISO is the wrong build

Symptoms: `donor file missing ...`, `no Win7 Common-Controls 6.0.7601.23403 manifest ...`, or
`cut3 DOES NOT MATCH the manifest.` with `CHANGED` files.

Keel is built against one specific Windows 7 SP1 x64 image, fully updated to the end of support.
`extract-donor.ps1` prints its version as `6.1.7601.24546`. The binaries Keel patches must be these
exact versions:

| File                        | Version          |
|-----------------------------|------------------|
| `explorer.exe`              | 6.1.7601.23537   |
| `shell32.dll`               | 6.1.7601.24468   |
| `ExplorerFrame.dll`         | 6.1.7601.24468   |
| `dwm.exe`, `dwmcore.dll`, `dwmredir.dll`, `uxtheme.dll`, `dui70.dll` | 6.1.7601.23403 |
| `uDWM.dll`                  | 6.1.7600.16385   |
| Common-Controls v6 (WinSxS) | 6.0.7601.23403   |

A plain SP1 image (6.1.7601.17514) is missing the Common-Controls 6.0.7601.23403 assembly, so the build
stops. Adding updates by hand until it gets past that point is not enough (nor is it recomended)
unless you end up with exactly the versions above. keelshim patches code at fixed offsets in these files,
and other versions pass build but WILL result in a broken shell or compositor.

To experiment anyway, pass `-AllowDonorMismatch` to `make-keel-iso.ps1` (or `make-cut3.ps1`). The
`CHANGED` and `BUILT FROM THE WRONG FILE` results are then still listed but no longer stop the build.
`MISSING` files still stop it, as does the missing Common-Controls 6.0.7601.23403 assembly. A machine
installed from such media has `C:\Keel\donor-mismatch.txt`, so check for that file first when a
report comes in.

### cut3 DOES NOT MATCH ... BUILT FROM THE WRONG FILE

A `donor\cut3` left over from an older `make-cut3.ps1` or a failed run. `make-keel-iso.ps1` rebuilds
it on its own. To do it by hand you can find and run the utility directly `tools\make-cut3.ps1`.

### No module named 'Registry'

The toolchain's Python lacks `python-registry`. Re-running `setup-toolchain.ps1` or `make-keel-iso.ps1`
installs whatever module is missing. By hand: `C:\Keel-tools\python\python.exe -m pip install python-registry`.

If `setup-toolchain.ps1` stops with `python installer exited 0 but left no python.exe`, the
installer's own log is `C:\Keel-tools\_dl\python-install.log`.

### this ISO has install.esd not install.wim

Use a `.wim` based Windows 10 LTSC 2021 ISO (build 19044). This is a requirement for the registry merge (see above).
