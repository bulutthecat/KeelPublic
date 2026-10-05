/*
 * KeelShim - Windows 7 user-mode UI translation for the Windows 10 kernel
 * Copyright (C) 2026 Kevin Dalli <projectkeel@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <objbase.h>
#include <psapi.h>
#include <sddl.h>
#include <intrin.h>
#include <detours.h>
#include <cwctype>
#include <cwchar>

#include "keel/log.h"
#include "keel/version.h"

namespace keelshim {

void StartUxSmsServer();
void RegisterAsSessionCompositorOnce();

namespace {

using GetVersionExWFn = BOOL(WINAPI*)(LPOSVERSIONINFOW);
#pragma warning(push)
#pragma warning(disable : 4996)
GetVersionExWFn g_realGetVersionExW = GetVersionExW;
#pragma warning(pop)

BOOL WINAPI HookedGetVersionExW(LPOSVERSIONINFOW info) {
    const BOOL ok = g_realGetVersionExW(info);
    if (ok && info) {
        info->dwMajorVersion = 6;
        info->dwMinorVersion = 1;
        info->dwBuildNumber = 7601;
        info->dwPlatformId = VER_PLATFORM_WIN32_NT;
        if (info->dwOSVersionInfoSize >= sizeof(OSVERSIONINFOEXW)) {
            auto ex = reinterpret_cast<LPOSVERSIONINFOEXW>(info);
            ex->wServicePackMajor = 1;
            ex->wServicePackMinor = 0;
        }

        static const wchar_t kSp1[] = L"Service Pack 1";
        for (size_t i = 0; i < sizeof(kSp1) / sizeof(wchar_t) && i < 128; ++i) info->szCSDVersion[i] = kSp1[i];
        KEEL_TRACE(L"GetVersionExW -> 6.1.7601 SP1 (spoofed)");
    }
    return ok;
}

using InitSessionPortFn = long(WINAPI*)();
InitSessionPortFn g_realInitSessionPort = nullptr;

long WINAPI HookedInitSessionPort() {
    KEEL_INFO(L"dwm; InitializeSessionPort ENTER");
    long hr = g_realInitSessionPort();
    KEEL_INFO(L"dwm; InitializeSessionPort -> 0x%08lX", (unsigned long)hr);

    RegisterAsSessionCompositorOnce();
    return hr;
}

typedef struct _KUNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } KUNICODE_STRING;
using NtConnectPortFn = long(NTAPI*)(PHANDLE, KUNICODE_STRING*, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
using NtAlpcConnectPortFn = long(NTAPI*)(PHANDLE, KUNICODE_STRING*, PVOID, PVOID, ULONG, PVOID, PVOID, PSIZE_T, PVOID, PVOID, PVOID);
NtConnectPortFn g_realNtConnectPort = nullptr;
NtAlpcConnectPortFn g_realNtAlpcConnectPort = nullptr;

static const wchar_t* kUxSmsRedirect = L"\\RPC Control\\UxSmsApiPort";

long NTAPI HookedNtConnectPort(PHANDLE h, KUNICODE_STRING* name, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f) {
    wchar_t buf[300] = L"(null)";
    int n = 0;
    if (name && name->Buffer) {
        n = name->Length / 2; if (n > 290) n = 290;
        for (int k = 0; k < n; ++k) buf[k] = name->Buffer[k];
        buf[n] = 0;
    }

    if (n == 13 && _wcsicmp(buf, L"\\UxSmsApiPort") == 0) {
        KUNICODE_STRING redir;
        redir.Buffer = const_cast<wchar_t*>(kUxSmsRedirect);
        redir.Length = (USHORT)(wcslen(kUxSmsRedirect) * 2);
        redir.MaximumLength = redir.Length + 2;
        long st = g_realNtConnectPort(h, &redir, a, b, c, d, e, f);
        KEEL_INFO(L"lpc; NtConnectPort('\\UxSmsApiPort') REDIRECTED to '%s' -> 0x%08lX", kUxSmsRedirect, (unsigned long)st);
        return st;
    }
    long st = g_realNtConnectPort(h, name, a, b, c, d, e, f);
    KEEL_INFO(L"lpc; NtConnectPort('%s' len=%u) -> 0x%08lX", buf, name ? name->Length : 0, (unsigned long)st);
    return st;
}
long NTAPI HookedNtAlpcConnectPort(PHANDLE h, KUNICODE_STRING* name, PVOID oa, PVOID pa, ULONG fl, PVOID sid, PVOID msg, PSIZE_T len, PVOID oat, PVOID iat, PVOID to) {
    long st = g_realNtAlpcConnectPort(h, name, oa, pa, fl, sid, msg, len, oat, iat, to);
    const wchar_t* nm = (name && name->Buffer) ? name->Buffer : L"(null)";
    KEEL_INFO(L"dwm; NtAlpcConnectPort('%s') -> 0x%08lX", nm, (unsigned long)st);
    return st;
}

struct KOBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; KUNICODE_STRING* ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; };
using NtCreateWaitablePortFn = long(NTAPI*)(PHANDLE, KOBJECT_ATTRIBUTES*, ULONG, ULONG, ULONG);
NtCreateWaitablePortFn g_realNtCreateWaitablePort = nullptr;

static PSECURITY_DESCRIPTOR BuildSessionPortSd() {
    wchar_t ownerAce[160] = L"";
    HANDLE tok = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        BYTE buf[256]; DWORD cb = 0;
        LPWSTR s = nullptr;
        if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &cb) &&
            ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf)->User.Sid, &s)) {
            swprintf_s(ownerAce, L"(A;;GA;;;%s)", s);
            LocalFree(s);
        }
        CloseHandle(tok);
    }
    wchar_t sddl[256];
    swprintf_s(sddl, L"D:(A;;GA;;;SY)(A;;GA;;;IU)%s", ownerAce);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) {
        KEEL_ERROR(L"dwm; session API port SDDL '%s' rejected, err=%lu", sddl, GetLastError());
        return nullptr;
    }
    KEEL_INFO(L"dwm; session API port DACL = %s", sddl);
    return sd;
}

long NTAPI HookedNtCreateWaitablePort(PHANDLE h, KOBJECT_ATTRIBUTES* oa, ULONG maxConnInfo, ULONG maxMsg, ULONG maxPool) {
    static PSECURITY_DESCRIPTOR s_sd = nullptr;
    wchar_t nm[128] = L"(null)";
    if (oa && oa->ObjectName && oa->ObjectName->Buffer) {
        int n = oa->ObjectName->Length / 2; if (n > 127) n = 127;
        for (int k = 0; k < n; ++k) nm[k] = oa->ObjectName->Buffer[k];
        nm[n] = 0;
    }
    const bool apiPort = wcsstr(nm, L"-ApiPort-") != nullptr;
    const bool patched = apiPort && oa->SecurityDescriptor == nullptr;
    if (patched) {
        if (!s_sd) s_sd = BuildSessionPortSd();
        oa->SecurityDescriptor = s_sd;
    }
    long st = g_realNtCreateWaitablePort(h, oa, maxConnInfo, maxMsg, maxPool);
    KEEL_INFO(L"dwm; NtCreateWaitablePort('%s' sd=%s) -> 0x%08lX", nm, patched ? L"keel(SY+IU+owner)" : L"as-is", (unsigned long)st);
    return st;
}

constexpr DWORD kUxThemeLoaderCtor   = 0x1cacc;
constexpr DWORD kUxThemeLoaderLoad   = 0x1cdf0;
// RVAs into the Win7 uxtheme, re-derive these if the donor uxtheme build changes
constexpr DWORD kUxFileCtor          = 0xbebc;
constexpr DWORD kUxFileOpenHandle    = 0xbf54;
constexpr DWORD kUxOpenThemeFromFile = 0x39338;
constexpr DWORD kUxGetThemeDefaults  = 0x38970;
static const wchar_t* kWin7Msstyles  = L"C:\\Keel\\win7theme\\aero.msstyles";

using UxCtorFn        = void*(*)(void*);
using UxLoadThemeFn   = long(*)(void*, void*, void*, const wchar_t*, const wchar_t*, const wchar_t*, void**, int);
using UxOpenHandleFn  = long(*)(void*, void*, unsigned long, int);
using UxDefaultsFn    = long(*)(const wchar_t*, wchar_t*, int, wchar_t*, int);
using UxOpenFromFileFn= void*(*)(void*, HWND, LPCWSTR, int);
using OpenThemeDataFn   = void*(WINAPI*)(HWND, LPCWSTR);
using OpenThemeDataExFn = void*(WINAPI*)(HWND, LPCWSTR, DWORD);
using GetCurThemeNameFn = long(WINAPI*)(LPWSTR, int, LPWSTR, int, LPWSTR, int);
using GetThemeColorFn   = long(WINAPI*)(void*, int, int, int, unsigned long*);
using GetThemeMarginsFn = long(WINAPI*)(void*, void*, int, int, int, void*, void*);
using GetThemeIntFn     = long(WINAPI*)(void*, int, int, int, int*);

void* g_win7ThemeFile = nullptr;
UxOpenFromFileFn g_openThemeFromFile = nullptr;
OpenThemeDataFn   g_realOpenThemeData = nullptr;
OpenThemeDataExFn g_realOpenThemeDataEx = nullptr;
GetCurThemeNameFn g_realGetCurThemeName = nullptr;
GetThemeColorFn   g_realGetThemeColor = nullptr;
GetThemeMarginsFn g_realGetThemeMargins = nullptr;
GetThemeIntFn     g_realGetThemeInt = nullptr;

// Win7 uxtheme keeps the sub-app in prop 0xa911, the sub-id list in 0xa910 and the GetWindowTheme handle in 0xa912
constexpr WORD kAtomSubIdList = 0xa910, kAtomSubAppName = 0xa911, kAtomWindowTheme = 0xa912;
constexpr DWORD kOtdNonClient = 0x2;
void GetThemeProps(HWND hwnd, wchar_t* app, int cap, wchar_t* ids, int icap) {
    app[0] = 0; ids[0] = 0; if (!hwnd) return;
    ATOM a = (ATOM)(ULONG_PTR)GetPropW(hwnd, (LPCWSTR)(ULONG_PTR)kAtomSubAppName); if (a) GetAtomNameW(a, app, cap);
    ATOM b = (ATOM)(ULONG_PTR)GetPropW(hwnd, (LPCWSTR)(ULONG_PTR)kAtomSubIdList);  if (b) GetAtomNameW(b, ids, icap);
}
volatile LONG g_themeMissLog = 60;
void LogThemeMiss(HWND hwnd, LPCWSTR cls, void* fallback, bool retried) {
    if (InterlockedDecrement(&g_themeMissLog) <= 0) return;
    wchar_t wc[64] = {}; if (hwnd) GetClassNameW(hwnd, wc, 63);
    wchar_t app[128], ids[128]; GetThemeProps(hwnd, app, 128, ids, 128);
    KEEL_INFO(L"theme; MISS in Win7 theme file classlist='%s' wndclass='%s' subapp='%s' subids='%s' retriedPlain=%d -> fallback %p",
              cls ? cls : L"", wc, app, ids, (int)retried, fallback);
}

// the 4th argument is fClient, not OTD flags, and 0 skips prop 0xa912 so GetWindowTheme returns NULL
void* OpenWin7Theme(HWND hwnd, LPCWSTR cls, DWORD otdFlags, bool* retried) {
    *retried = false;
    if (hwnd) RemovePropW(hwnd, (LPCWSTR)(ULONG_PTR)kAtomWindowTheme);
    const int fClient = (otdFlags & kOtdNonClient) ? 0 : 1;
    void* h = g_openThemeFromFile(g_win7ThemeFile, hwnd, cls, fClient);
    if (!h && hwnd) {
        wchar_t app[128], ids[128]; GetThemeProps(hwnd, app, 128, ids, 128);
        if (app[0] || ids[0]) { *retried = true; h = g_openThemeFromFile(g_win7ThemeFile, nullptr, cls, fClient); }
    }
    return h;
}

volatile LONG g_ncThemeLog = 300;
bool IsFrameClass(LPCWSTR cls) {
    return cls && (wcsstr(cls, L"Window") || wcsstr(cls, L"Composited") || wcsstr(cls, L"Frame") || wcsstr(cls, L"Caption"));
}
void* WINAPI HookedOpenThemeData(HWND hwnd, LPCWSTR cls) {
    bool retried = false;
    if (g_win7ThemeFile && g_openThemeFromFile && cls) {
        void* h = OpenWin7Theme(hwnd, cls, 0, &retried);
        if (cls && wcsstr(cls, L"DWM")) KEEL_INFO(L"dwm; OpenThemeData('%s') -> %p (in-proc Win7 theme)", cls, h);
        if (IsFrameClass(cls) && InterlockedDecrement(&g_ncThemeLog) > 0)
            KEEL_INFO(L"nctheme; OpenThemeData('%s' hwnd=%p) -> %p from Win7 file=%p", cls, hwnd, h, g_win7ThemeFile);
        if (h) return h;
    }
    void* f = g_realOpenThemeData ? g_realOpenThemeData(hwnd, cls) : nullptr;
    if (IsFrameClass(cls) && InterlockedDecrement(&g_ncThemeLog) > 0)
        KEEL_INFO(L"nctheme; FELL THROUGH '%s' hwnd=%p -> real=%p (Win7 file=%p)", cls, hwnd, f, g_win7ThemeFile);
    if (g_win7ThemeFile) LogThemeMiss(hwnd, cls, f, retried);
    return f;
}
void* WINAPI HookedOpenThemeDataEx(HWND hwnd, LPCWSTR cls, DWORD flags) {
    bool retried = false;
    if (g_win7ThemeFile && g_openThemeFromFile && cls) {
        void* h = OpenWin7Theme(hwnd, cls, flags, &retried);
        if (h) return h;
    }
    void* f = g_realOpenThemeDataEx ? g_realOpenThemeDataEx(hwnd, cls, flags) : nullptr;
    if (g_win7ThemeFile) LogThemeMiss(hwnd, cls, f, retried);
    return f;
}
long WINAPI HookedGetCurThemeName(LPWSTR file, int cf, LPWSTR col, int cc, LPWSTR sz, int cs) {
    if (g_win7ThemeFile) {
        if (file && cf > 0) wcsncpy_s(file, cf, kWin7Msstyles, _TRUNCATE);
        if (col && cc > 0)  wcsncpy_s(col, cc, L"NormalColor", _TRUNCATE);
        if (sz && cs > 0)   wcsncpy_s(sz, cs, L"NormalSize", _TRUNCATE);
        return 0;
    }
    return g_realGetCurThemeName ? g_realGetCurThemeName(file, cf, col, cc, sz, cs) : (long)0x80070490;
}
long WINAPI HookedGetThemeColor(void* h, int part, int state, int prop, unsigned long* col) {
    long r = g_realGetThemeColor(h, part, state, prop, col);
    if (r < 0) KEEL_INFO(L"dwm; GetThemeColor(part=%d state=%d prop=%d) -> 0x%08lX", part, state, prop, (unsigned long)r);
    return r;
}
long WINAPI HookedGetThemeMargins(void* h, void* dc, int part, int state, int prop, void* r2, void* m) {
    long r = g_realGetThemeMargins(h, dc, part, state, prop, r2, m);
    if (r < 0) KEEL_INFO(L"dwm; GetThemeMargins(part=%d state=%d prop=%d) -> 0x%08lX", part, state, prop, (unsigned long)r);
    return r;
}
long WINAPI HookedGetThemeInt(void* h, int part, int state, int prop, int* val) {
    long r = g_realGetThemeInt(h, part, state, prop, val);
    if (r < 0) KEEL_INFO(L"dwm; GetThemeInt(part=%d state=%d prop=%d) -> 0x%08lX", part, state, prop, (unsigned long)r);
    return r;
}

using SetWindowThemeFn = long(WINAPI*)(HWND, LPCWSTR, LPCWSTR);
SetWindowThemeFn g_realSetWindowTheme = nullptr;
volatile LONG g_swtLog = 50;
long WINAPI HookedSetWindowTheme(HWND h, LPCWSTR app, LPCWSTR ids) {
    long r = g_realSetWindowTheme(h, app, ids);
    if (InterlockedDecrement(&g_swtLog) > 0) {
        wchar_t wc[64] = {}; if (h) GetClassNameW(h, wc, 63);
        KEEL_INFO(L"theme; SetWindowTheme hwnd=%p class='%s' subapp='%s' subids='%s' -> 0x%08lX",
                  h, wc, app ? app : L"(null)", ids ? ids : L"(null)", (unsigned long)r);
    }
    return r;
}

using GetWndCompInfoFn = long(WINAPI*)(HWND, void*);
GetWndCompInfoFn g_realGetWndCompInfo = nullptr;
volatile LONG g_gwciLog = 30;

using DwmValidateWindowFn = BOOL(WINAPI*)(HWND, DWORD);
DwmValidateWindowFn g_dwmValidateWindow = nullptr;
volatile LONG g_validateLog = 40;

void ValidateWindowForKernel(HWND hwnd, const wchar_t* why) {
    if (!g_dwmValidateWindow || !hwnd) return;
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    SetLastError(0);
    const BOOL ok = g_dwmValidateWindow(hwnd, pid);
    if (InterlockedDecrement(&g_validateLog) > 0)
        KEEL_INFO(L"validate(%s); DwmValidateWindow(hwnd=%p pid=%lu) -> %d err=%lu", why, hwnd, pid, (int)ok, GetLastError());
}

long WINAPI HookedGetWndCompInfo(HWND hwnd, void* info) {
    ValidateWindowForKernel(hwnd, L"create");
    long r = g_realGetWndCompInfo(hwnd, info);
    if (InterlockedDecrement(&g_gwciLog) > 0) {
        unsigned long long a = 0, b = 0; unsigned long cb = 0;
        __try {
            if (info) { cb = *reinterpret_cast<unsigned long*>(info);
                        a = *reinterpret_cast<unsigned long long*>(info);
                        b = *reinterpret_cast<unsigned long long*>(reinterpret_cast<BYTE*>(info) + 8); }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        wchar_t cls[48] = {}; if (hwnd) GetClassNameW(hwnd, cls, 47);
        KEEL_INFO(L"redir; GetWindowCompositionInfo(hwnd=%p '%s') -> 0x%08lX cb=%lu [0]=%016llX [8]=%016llX",
                  hwnd, cls, (unsigned long)r, cb, a, b);
    }
    return r;
}

constexpr DWORD RVA_Redir_KernelAsync  = 0x12f8;
constexpr DWORD RVA_Redir_CreateSurface = 0x5a0c;

constexpr DWORD RVA_Redir_NotifyBlurBehind = 0x6268;

using NotifyBlurFn = long(__fastcall*)(void* self, HWND hwnd, const void* bb, const void* rgn);
NotifyBlurFn g_realNotifyBlur = nullptr;
volatile LONG g_blurLog = 60;

void* volatile g_blurMgr = nullptr;
long __fastcall HookedNotifyBlur(void* self, HWND hwnd, const void* bb, const void* rgn) {
    if (!g_blurMgr) g_blurMgr = self;
    const long r = g_realNotifyBlur(self, hwnd, bb, rgn);
    if (InterlockedDecrement(&g_blurLog) > 0) {
        DWORD flags = 0, enable = 0;
        __try {
            if (bb) { flags = *static_cast<const DWORD*>(bb); enable = static_cast<const DWORD*>(bb)[1]; }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        wchar_t cls[56]{}; if (hwnd && IsWindow(hwnd)) GetClassNameW(hwnd, cls, 55);
        KEEL_INFO(L"blur; NotifyBlurBehindWindowRequest(hwnd=%p '%s' flags=0x%lX enable=%lu rgn=%d) -> 0x%08lX"
                  L"  [turns per-pixel alpha ON for a window]",
                  hwnd, cls, flags, enable, rgn ? 1 : 0, (unsigned long)r);
    }
    return r;
}

constexpr ULONGLONG kLsMask = 0xFFFFFFFFull;
inline ULONGLONG NormLs(ULONGLONG h) { return h & kLsMask; }
LONG g_nLsNormalized = 0;
volatile LONG g_lsNormLog = 12;
void SurfNoteToken(ULONGLONG lsNormalised);

extern const wchar_t* const kUlwAlphaProp;

const wchar_t* FocusClass() {
    static wchar_t cls[64] = L"";
    static bool init = false;
    if (!init) { init = true; if (GetEnvironmentVariableW(L"KEEL_FOCUSCLASS", cls, 64) == 0) wcscpy_s(cls, L"Button"); }
    return cls;
}
volatile ULONGLONG g_orbSprite = 0, g_orbHlsurf = 0;
HWND g_orbHwnd = nullptr;
volatile LONG g_orbMilLog = 600, g_orbPhtLog = 300;
BYTE g_orbLastMil[0x50]{};
bool g_orbLastValid = false;
LONG g_orbDupes = 0;

ULONGLONG g_orbLsHist[8]{};
int g_orbLsCount = 0;
bool OrbKnowsLs(ULONGLONG h) {
    if (!h) return false;
    for (int i = 0; i < g_orbLsCount; ++i) if (g_orbLsHist[i] == h) return true;
    return false;
}

using CreateSurfaceFn = long(__fastcall*)(void*, void*, int, bool);
CreateSurfaceFn g_realCreateSurface = nullptr;
volatile LONG g_csLog = 40;

constexpr DWORD RVA_Redir_NotifyDirty = 0xc6e0;
using NotifyDirtyFn = long(__fastcall*)(void* channel, ULONG resourceId, ULONG flags, ULONGLONG ctx);
constexpr ULONG kDirtySpriteFlags = 6;
volatile LONG g_fullDirtyLog = 16;
volatile LONG g_nCreateSurface = 0;

constexpr DWORD RVA_Redir_SetGDISpriteImage  = 0x4c18;
constexpr DWORD RVA_Redir_NodeSetSpriteImage = 0x796c;
using SetGdiImgFn  = long(__fastcall*)(void*, void*, bool, bool);
using NodeSetImgFn = long(__fastcall*)(void*, ULONG, ULONG);
SetGdiImgFn  g_realSetGdiImg  = nullptr;
NodeSetImgFn g_realNodeSetImg = nullptr;
volatile LONG g_bindLog = 300;

constexpr DWORD RVA_Redir_GetClipRegion   = 0x5000;
constexpr DWORD RVA_Redir_SetSpriteClip   = 0x4a54;
constexpr DWORD RVA_Redir_CreateEmptyClip = 0x6134;
using GetClipRgnFn     = long(__fastcall*)(void*, void*, ULONG*);
using SetSpriteClipFn  = long(__fastcall*)(void*, ULONG, ULONG, int);
using CreateEmptyClipFn= long(__fastcall*)(void*, void*, ULONG*);
GetClipRgnFn      g_realGetClipRgn    = nullptr;
SetSpriteClipFn   g_realSetSpriteClip = nullptr;
CreateEmptyClipFn g_realCreateEmptyClip = nullptr;
volatile LONG g_clipLog = 400;
__declspec(thread) int t_emptyClip = 0;

long __fastcall HookedCreateEmptyClip(void* self, void* channel, ULONG* out) {
    const long r = g_realCreateEmptyClip(self, channel, out);
    t_emptyClip = 1;
    return r;
}
long __fastcall HookedGetClipRgn(void* self, void* channel, ULONG* out) {
    BYTE* p = reinterpret_cast<BYTE*>(self);
    HWND hw = nullptr; LONG wr[4]{};
    __try {
        hw = *reinterpret_cast<HWND*>(p + 0xb8);
        memcpy(wr, p + 0x48, sizeof(wr));
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    t_emptyClip = 0;
    const long r = g_realGetClipRgn(self, channel, out);

    wchar_t cls[40]{}; if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 39);
    if (hw && InterlockedDecrement(&g_clipLog) > 0) {

        int rgnType = -1; RECT box{};
        HRGN rgn = CreateRectRgn(0, 0, 0, 0);
        if (rgn) {
            rgnType = GetWindowRgn(hw, rgn);
            if (rgnType > 1) GetRgnBox(rgn, &box);
            DeleteObject(rgn);
        }
        KEEL_INFO(L"clip; GetClipRegion hwnd=%p '%s' -> hr=0x%08lX clipRes=%lu emptyClip=%d"
                  L" | GetWindowRgn=%d box=(%ld,%ld,%ld,%ld) surf=%ldx%ld",
                  hw, cls, (unsigned long)r, out ? *out : 0, t_emptyClip,
                  rgnType, box.left, box.top, box.right, box.bottom,
                  wr[2] - wr[0], wr[3] - wr[1]);
    }
    return r;
}

using SetWindowRgnExFn = int(WINAPI*)(HWND, HRGN, DWORD);
SetWindowRgnExFn g_realSetWindowRgnEx = nullptr;
volatile LONG g_rgnFixLog = 60;
volatile LONG g_nRgnFixed = 0;

// uDWM sets the region in SCREEN coords but Win7 expects window relative, else the clip misses its own sprite
int WINAPI HookedSetWindowRgnEx(HWND hwnd, HRGN hrgn, DWORD flags) {
    if (hwnd && hrgn) {
        RECT wr{}, box{};
        if (GetWindowRect(hwnd, &wr) && GetRgnBox(hrgn, &box) != NULLREGION &&
            (wr.left != 0 || wr.top != 0)) {

            const LONG dx = box.left - wr.left, dy = box.top - wr.top;
            if (dx > -64 && dx < 64 && dy > -64 && dy < 64) {
                OffsetRgn(hrgn, -wr.left, -wr.top);
                InterlockedIncrement(&g_nRgnFixed);
                if (InterlockedDecrement(&g_rgnFixLog) > 0) {
                    wchar_t cls[40]{}; if (IsWindow(hwnd)) GetClassNameW(hwnd, cls, 39);
                    KEEL_INFO(L"rgn; '%s' hwnd=%p screen-relative region (%ld,%ld,%ld,%ld) on window"
                              L" (%ld,%ld,%ld,%ld) -> window-relative (%ld,%ld,%ld,%ld)",
                              cls, hwnd, box.left, box.top, box.right, box.bottom,
                              wr.left, wr.top, wr.right, wr.bottom,
                              box.left - wr.left, box.top - wr.top,
                              box.right - wr.left, box.bottom - wr.top);
                }
            }
        }
    }
    return g_realSetWindowRgnEx(hwnd, hrgn, flags);
}

long __fastcall HookedSetSpriteClip(void* channel, ULONG node, ULONG clipRes, int flag) {
    const long r = g_realSetSpriteClip(channel, node, clipRes, flag);
    if (InterlockedDecrement(&g_clipLog) > 0)
        KEEL_INFO(L"clip; WindowNode_SetSpriteClip(node=%lu, clipRes=%lu, flag=%d) -> 0x%08lX",
                  node, clipRes, flag, (unsigned long)r);
    return r;
}

long __fastcall HookedSetGdiImg(void* self, void* channel, bool p2, bool p3) {
    BYTE* p = reinterpret_cast<BYTE*>(self);
    ULONG f18 = 0, nodeId = 0, bmpId = 0; HWND hw = nullptr;
    __try {
        f18    = *reinterpret_cast<ULONG*>(p + 0x18);
        bmpId  = *reinterpret_cast<ULONG*>(p + 0x8c);
        nodeId = *reinterpret_cast<ULONG*>(p + 0xfc);
        hw     = *reinterpret_cast<HWND*>(p + 0xb8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    const long r = g_realSetGdiImg(self, channel, p2, p3);

    wchar_t cls[40]{}; if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 39);
    if (hw && !wcscmp(cls, FocusClass()) && InterlockedDecrement(&g_bindLog) > 0) {
        KEEL_INFO(L"bind; SetGDISpriteImage p2=%d p3=%d f18=%08lX bit16=%d node=%lu bmp=%lu"
                  L" -> %s hr=0x%08lX '%s'",
                  p2 ? 1 : 0, p3 ? 1 : 0, f18, (f18 >> 16) & 1, nodeId, bmpId,
                  (((f18 >> 16) & 1) == 0 || p3) ? L"SETIMAGE" : (p2 ? L"notifyOnly" : L"NOTHING"),
                  (unsigned long)r, cls);
    }
    return r;
}

volatile LONG g_nodeBindLog = 400;
long __fastcall HookedNodeSetImg(void* channel, ULONG nodeId, ULONG bmpId) {
    const long r = g_realNodeSetImg(channel, nodeId, bmpId);
    if (InterlockedDecrement(&g_nodeBindLog) > 0)
        KEEL_INFO(L"bind; WindowNode_SetSpriteImage(node=%lu, bmp=%lu) -> 0x%08lX",
                  nodeId, bmpId, (unsigned long)r);
    return r;
}

long __fastcall HookedCreateSurface(void* self, void* channel, int fmt, bool arg3) {
    BYTE* p = reinterpret_cast<BYTE*>(self);
    int cxBefore = 0, cyBefore = 0; HWND hwnd = nullptr;
    __try {
        cxBefore = *reinterpret_cast<int*>(p + 0xd4);
        cyBefore = *reinterpret_cast<int*>(p + 0xd8);
        hwnd     = *reinterpret_cast<HWND*>(p + 0xb8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    const long r = g_realCreateSurface(self, channel, fmt, arg3);
    InterlockedIncrement(&g_nCreateSurface);

    {
        wchar_t oc[48]{}; if (hwnd && IsWindow(hwnd)) GetClassNameW(hwnd, oc, 47);
        if (!wcscmp(oc, FocusClass())) {
            ULONGLONG spr = 0, ls = 0;
            __try {
                spr = *reinterpret_cast<ULONGLONG*>(p + 0xc0);
                ls  = *reinterpret_cast<ULONGLONG*>(p + 0xc8);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (spr != g_orbSprite || ls != g_orbHlsurf) {
                g_orbSprite = spr; g_orbHlsurf = ls; g_orbHwnd = hwnd; g_orbLastValid = false;

                const ULONGLONG n = NormLs(ls);
                if (n && !OrbKnowsLs(n) && g_orbLsCount < 8) g_orbLsHist[g_orbLsCount++] = n;
                KEEL_INFO(L"orbTrace; latched hwnd=%p sprite=%llX hlsurf=%llX (norm %llX)",
                          hwnd, spr, ls, n);
            }
        }
    }
    if (InterlockedDecrement(&g_csLog) > 0) {
        int cx = 0, cy = 0; ULONGLONG spr = 0, ls = 0;
        __try {
            cx  = *reinterpret_cast<int*>(p + 0xd4);
            cy  = *reinterpret_cast<int*>(p + 0xd8);
            spr = *reinterpret_cast<ULONGLONG*>(p + 0xc0);
            ls  = *reinterpret_cast<ULONGLONG*>(p + 0xc8);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        wchar_t cls[48]{}; if (hwnd && IsWindow(hwnd)) GetClassNameW(hwnd, cls, 47);
        KEEL_INFO(L"redir; CreateSurface(hwnd=%p '%s' fmt=%d) %dx%d -> %dx%d sprite=%llX hlsurf=%llX -> 0x%08lX",
                  hwnd, cls, fmt, cxBefore, cyBefore, cx, cy, spr, ls, (unsigned long)r);
    }
    return r;
}

constexpr DWORD RVA_Redir_MilCheckHR = 0x7c50;
constexpr DWORD RVA_Core_MilCheckHR  = 0x46f40;
using MilChkFn = void(__fastcall*)(unsigned flags, long* state, unsigned kind, long hr, unsigned line);
MilChkFn g_realMilChkRedir = nullptr;
MilChkFn g_realMilChkCore  = nullptr;
volatile LONG g_milChkLog = 300;

void __fastcall HookedMilChkRedir(unsigned flags, long* state, unsigned kind, long hr, unsigned line) {
    if (hr < 0 && InterlockedDecrement(&g_milChkLog) > 0)
        KEEL_WARN(L"mil; dwmredir hr=0x%08lX line=%u (flags=%u kind=%u)",
                  (unsigned long)hr, line, flags, kind);
    g_realMilChkRedir(flags, state, kind, hr, line);
}
void __fastcall HookedMilChkCore(unsigned flags, long* state, unsigned kind, long hr, unsigned line) {
    if (hr < 0 && InterlockedDecrement(&g_milChkLog) > 0)
        KEEL_WARN(L"mil; dwmcore  hr=0x%08lX line=%u (flags=%u kind=%u)",
                  (unsigned long)hr, line, flags, kind);
    g_realMilChkCore(flags, state, kind, hr, line);
}

using BitBltFn = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, DWORD);
using CreateDIBSectionFn = HBITMAP(WINAPI*)(HDC, const BITMAPINFO*, UINT, VOID**, HANDLE, DWORD);
BitBltFn g_realBitBlt = nullptr;
CreateDIBSectionFn g_realCreateDIBSection = nullptr;
volatile LONG g_gdiLog = 40, g_gdiDibLog = 20;

const wchar_t* CallerModule(void* ret);

using HlSetFn = BOOL(WINAPI*)(ULONGLONG, ULONG, void*, ULONG);
using HlGetFn = BOOL(WINAPI*)(ULONGLONG, ULONG, void*, ULONG*);
HlSetFn g_realHlSet = nullptr;
HlGetFn g_realHlGet = nullptr;
volatile LONG g_hlSetLog = 60, g_hlGetLog = 60;

BOOL WINAPI HookedHlSet(ULONGLONG h, ULONG cls, void* data, ULONG cb) {
    SetLastError(0);
    const BOOL r = g_realHlSet(h, cls, data, cb);
    const DWORD err = GetLastError();
    if (InterlockedDecrement(&g_hlSetLog) > 0)
        KEEL_INFO(L"hl; [%s] SetInformation(h=%llX type=0x%llX class=%lu cb=%lu) -> %d err=%lu",
                  CallerModule(_ReturnAddress()), h, (h >> 16) & 0x1F, cls, cb, (int)r, err);
    return r;
}
BOOL WINAPI HookedHlGet(ULONGLONG h, ULONG cls, void* out, ULONG* pcb) {
    SetLastError(0);
    const BOOL r = g_realHlGet(h, cls, out, pcb);
    const DWORD err = GetLastError();
    if (InterlockedDecrement(&g_hlGetLog) > 0) {
        wchar_t hex[3 * 32 + 1]{}; int n = 0;
        __try {
            if (out && r) for (int i = 0; i < 32; ++i) n += swprintf_s(hex + n, 3 * 32 + 1 - n, L"%02X ", reinterpret_cast<BYTE*>(out)[i]);
        } __except (EXCEPTION_EXECUTE_HANDLER) { wcscpy_s(hex, L"<unreadable>"); }
        KEEL_INFO(L"hl; [%s] GetInformation(h=%llX type=0x%llX class=%lu cb=%lu) -> %d err=%lu | %s",
                  CallerModule(_ReturnAddress()), h, (h >> 16) & 0x1F, cls,
                  (pcb ? *pcb : 0), (int)r, err, hex);
    }
    return r;
}

const wchar_t* CallerModule(void* ret) {
    static wchar_t name[64];
    HMODULE m = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(ret), &m) || !m) return L"?";
    wchar_t full[MAX_PATH]{}; GetModuleFileNameW(m, full, MAX_PATH);
    const wchar_t* leaf = wcsrchr(full, L'\\');
    wcscpy_s(name, leaf ? leaf + 1 : full);
    return name;
}

BOOL WINAPI HookedBitBlt(HDC dst, int x, int y, int cx, int cy, HDC src, int sx, int sy, DWORD rop) {
    const BOOL r = g_realBitBlt(dst, x, y, cx, cy, src, sx, sy, rop);
    if (InterlockedDecrement(&g_gdiLog) > 0)
        KEEL_INFO(L"gdi; BitBlt from %s dst=%p src=%p %d,%d %dx%d rop=0x%08lX -> %d (err=%lu)",
                  CallerModule(_ReturnAddress()), dst, src, x, y, cx, cy, rop, (int)r, GetLastError());
    return r;
}
HBITMAP WINAPI HookedCreateDIBSection(HDC dc, const BITMAPINFO* bmi, UINT usage, VOID** bits,
                                      HANDLE sect, DWORD off) {
    const HBITMAP r = g_realCreateDIBSection(dc, bmi, usage, bits, sect, off);
    if (InterlockedDecrement(&g_gdiDibLog) > 0)
        KEEL_INFO(L"gdi; CreateDIBSection from %s %ldx%ld bpp=%u -> %p",
                  CallerModule(_ReturnAddress()),
                  bmi ? bmi->bmiHeader.biWidth : 0, bmi ? bmi->bmiHeader.biHeight : 0,
                  bmi ? bmi->bmiHeader.biBitCount : 0, r);
    return r;
}

using DirtyRgnFn = long(WINAPI*)(ULONGLONG, void*, void*, void*, void*, void*, void*, void*, void*);
DirtyRgnFn g_realDirtyRgn = nullptr;
volatile LONG g_dirtyRgnLog = 8;

long WINAPI HookedDirtyRgn(ULONGLONG h, void* a2, void* a3, void* a4, void* a5,
                           void* , void* , void* , void* ) {
    if (InterlockedDecrement(&g_dirtyRgnLog) > 0)
        KEEL_INFO(L"gdi; DwmHLSurfGetDirtyRgn(h=%llX) forwarding Win7's 5 args and NULLing Win10's extra 4", h);
    return g_realDirtyRgn(h, a2, a3, a4, a5, nullptr, nullptr, nullptr, nullptr);
}

volatile LONG g_probeLsLog = 40;
void ProbeLogicalSurface(ULONGLONG h, const wchar_t* what) {
    if (!h || !g_realHlGet) return;
    if (InterlockedDecrement(&g_probeLsLog) <= 0) return;
    BYTE buf[0x80]{}; ULONG cb = 0x40;
    SetLastError(0);
    const BOOL r6 = g_realHlGet(h, 6, buf, &cb);
    const DWORD e6 = GetLastError();
    ULONG cb3 = 0x40; BYTE buf3[0x80]{};
    SetLastError(0);
    const BOOL r3 = g_realHlGet(h, 3, buf3, &cb3);
    const DWORD e3 = GetLastError();
    KEEL_INFO(L"probeLS; %s=%llX -> style=%d(err %lu) data=%d(err %lu) [%02X %02X %02X %02X %02X %02X %02X %02X]",
              what, h, (int)r6, e6, (int)r3, e3,
              buf3[0], buf3[1], buf3[2], buf3[3], buf3[4], buf3[5], buf3[6], buf3[7]);
}

void InstallGdiTrace() {
    if (g_realBitBlt) return;
    HMODULE g = GetModuleHandleW(L"gdi32.dll"); if (!g) g = LoadLibraryW(L"gdi32.dll");
    if (!g) return;
    g_realBitBlt = (BitBltFn)GetProcAddress(g, "BitBlt");
    g_realCreateDIBSection = (CreateDIBSectionFn)GetProcAddress(g, "CreateDIBSection");
    HMODULE w = GetModuleHandleW(L"win32u.dll"); if (!w) w = LoadLibraryW(L"win32u.dll");
    g_realHlSet = w ? (HlSetFn)GetProcAddress(w, "NtGdiHLSurfSetInformation") : nullptr;
    g_realHlGet = w ? (HlGetFn)GetProcAddress(w, "NtGdiHLSurfGetInformation") : nullptr;
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (g_realBitBlt) DetourAttach(reinterpret_cast<PVOID*>(&g_realBitBlt), (PVOID)HookedBitBlt);
    if (g_realCreateDIBSection)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateDIBSection), (PVOID)HookedCreateDIBSection);
    if (g_realHlSet) DetourAttach(reinterpret_cast<PVOID*>(&g_realHlSet), (PVOID)HookedHlSet);
    if (g_realHlGet) DetourAttach(reinterpret_cast<PVOID*>(&g_realHlGet), (PVOID)HookedHlGet);
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"gdi; trace installed (BitBlt=%p DIB=%p HLSurfSet=%p HLSurfGet=%p commit=%ld)",
              g_realBitBlt, g_realCreateDIBSection, g_realHlSet, g_realHlGet, e);
    HMODULE gf = GetModuleHandleW(L"gdi32full.dll"); if (!gf) gf = LoadLibraryW(L"gdi32full.dll");
    g_realDirtyRgn = gf ? (DirtyRgnFn)GetProcAddress(gf, MAKEINTRESOURCEA(1007)) : nullptr;
    if (g_realDirtyRgn) {
        DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<PVOID*>(&g_realDirtyRgn), (PVOID)HookedDirtyRgn);
        const LONG de = DetourTransactionCommit();
        KEEL_INFO(L"gdi; DwmHLSurfGetDirtyRgn arity wrapper installed @%p (commit=%ld)", g_realDirtyRgn, de);
    } else {
        KEEL_WARN(L"gdi; gdi32full #1007 not resolved so DwmHLSurfGetDirtyRgn arity NOT fixed");
    }
}

constexpr DWORD RVA_Core_ProcessUpdate = 0x32ba4;
constexpr DWORD RVA_Core_ProcessPHT    = 0x9bdbc;
constexpr DWORD RVA_Core_DispatchPHT   = 0x4c00;

using DispatchPhtFn = long(__fastcall*)(void*, void*, void*, void*);
DispatchPhtFn g_realDispatchPht = nullptr;
volatile LONG g_dispPhtLog = 40;
LONG g_phtTypeCount[8] = {};
volatile LONG g_phtDumpLeft = 25;
volatile LONG g_phtAltDumpLeft = 12;
volatile LONG g_bltPhtLog = 20;

bool BltPhtDisabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NO_BLTPHT", v, 8) != 0 && v[0] == L'1') ? 1 : 0; }
    return cached == 1;
}
// present-history token layouts differ, Win7 keeps the lookup key at +0x10 and Win10 moved it to +0x18
constexpr ULONG kPhtMaxRects = 192;

constexpr DWORD RVA_Core_GetPresentHistory = 0x2d90;
using GetPhFn = long(__fastcall*)(void*, unsigned, void*, unsigned*);
GetPhFn g_realGetPh = nullptr;
volatile LONG g_getPhLog = 20;
LONG g_getPhCalls = 0, g_getPhTokens = 0;

long __fastcall HookedGetPresentHistory(void* self, unsigned cnt, void* buf, unsigned* outCnt) {
    const long r = g_realGetPh(self, cnt, buf, outCnt);
    unsigned produced = 0;
    __try { if (outCnt) produced = *outCnt; } __except (EXCEPTION_EXECUTE_HANDLER) {}
    InterlockedIncrement(&g_getPhCalls);
    if (produced) InterlockedAdd(&g_getPhTokens, (LONG)produced);
    if (produced && InterlockedDecrement(&g_getPhLog) > 0)
        KEEL_INFO(L"getPH; in=%u -> tokens=%u hr=0x%08lX", cnt, produced, (unsigned long)r);
    return r;
}

__declspec(thread) int t_focusPht = 0;
__declspec(thread) int t_focusCoreHits = 0;
volatile LONG g_focusCoreLog = 400;

long __fastcall HookedDispatchPht(void* self, void* token, void* comp, void* out) {
    ULONG type = 0xFFFFFFFF; ULONGLONG k8 = 0, k10 = 0;
    __try {
        BYTE* t = reinterpret_cast<BYTE*>(token);
        type = *reinterpret_cast<ULONG*>(t);
        k8   = *reinterpret_cast<ULONGLONG*>(t + 8);
        k10  = *reinterpret_cast<ULONGLONG*>(t + 0x10);
        (void)t;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (type < 8) InterlockedIncrement(&g_phtTypeCount[type]);

    if (type == 1) SurfNoteToken(NormLs(k10 ? k10 : k8));

    if ((OrbKnowsLs(NormLs(k10)) || OrbKnowsLs(NormLs(k8))) &&
        InterlockedDecrement(&g_orbPhtLog) > 0) {

        ULONG sz = 0, cnt = 0; LONG r[3][4]{};
        __try {
            const BYTE* t = reinterpret_cast<const BYTE*>(token);
            sz  = *reinterpret_cast<const ULONG*>(t + 4);
            cnt = *reinterpret_cast<const ULONG*>(t + 0x38);
            for (ULONG i = 0; i < 3 && i < cnt && 0x3c + (i + 1) * 16 <= sz; ++i)
                memcpy(r[i], t + 0x3c + i * 16, 16);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        KEEL_INFO(L"focusPht; type=%lu sz=%lu k10=%llX rects=%lu | (%ld,%ld,%ld,%ld) (%ld,%ld,%ld,%ld)"
                  L" (%ld,%ld,%ld,%ld)", type, sz, k10, cnt,
                  r[0][0], r[0][1], r[0][2], r[0][3], r[1][0], r[1][1], r[1][2], r[1][3],
                  r[2][0], r[2][1], r[2][2], r[2][3]);
    }

    {
        ULONG sz = 0, cWin7 = 0, cShift = 0;
        __try {
            const BYTE* t = reinterpret_cast<const BYTE*>(token);
            sz     = *reinterpret_cast<const ULONG*>(t + 4);
            cWin7  = *reinterpret_cast<const ULONG*>(t + 0x18);
            cShift = *reinterpret_cast<const ULONG*>(t + 0x20);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (g_phtDumpLeft > 0) {
            InterlockedDecrement(&g_phtDumpLeft);

            wchar_t d[600]{}; int n = 0;
            __try {
                const BYTE* t = reinterpret_cast<const BYTE*>(token);
                for (ULONG off = 0x30; off <= 0x64 && off + 4 <= sz; off += 4)
                    n += swprintf_s(d + n, 600 - n, L"%02lX:%ld ", off,
                                    (long)*reinterpret_cast<const LONG*>(t + off));
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            KEEL_INFO(L"pht; sz=%lu hlsurf=%llX f18=%lu | %s", sz, k10, cWin7, d);
        }
    }

    if (type != 1 && g_phtAltDumpLeft > 0) {
        InterlockedDecrement(&g_phtAltDumpLeft);
        ULONG sz = 0;
        wchar_t d[700]{}; int n = 0;
        __try {
            const BYTE* t = reinterpret_cast<const BYTE*>(token);
            sz = *reinterpret_cast<const ULONG*>(t + 4);
            const ULONG lim = sz < 0x60 ? sz : 0x60;
            for (ULONG off = 0; off + 4 <= lim && n < 640; off += 4)
                n += swprintf_s(d + n, 700 - n, L"%02lX:%08lX ", off,
                                (unsigned long)*reinterpret_cast<const ULONG*>(t + off));
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        KEEL_INFO(L"phtAlt; type=%lu sz=%lu | %s", type, sz, d);
    }

    if (type == 1) {
        BYTE* t = reinterpret_cast<BYTE*>(token);
        long r2 = 0;
        bool repacked = false;
        const bool isFocus = OrbKnowsLs(NormLs(k10)) || OrbKnowsLs(NormLs(k8));
        __try {
            const ULONG sz  = *reinterpret_cast<const ULONG*>(t + 4);
            ULONG cnt       = *reinterpret_cast<const ULONG*>(t + 0x38);
            const ULONG fit = (sz > 0x3c) ? (sz - 0x3c) / 16 : 0;
            if (cnt > fit) cnt = fit;
            if (cnt > kPhtMaxRects) cnt = kPhtMaxRects;
            BYTE buf[0x1c + kPhtMaxRects * 16]{};
            *reinterpret_cast<ULONG*>(buf + 0x00)     = 1;
            *reinterpret_cast<ULONG*>(buf + 0x04)     = 0x1c + cnt * 16;

            *reinterpret_cast<ULONGLONG*>(buf + 0x08) = NormLs(*reinterpret_cast<const ULONGLONG*>(t + 0x10));
            *reinterpret_cast<ULONGLONG*>(buf + 0x10) = *reinterpret_cast<const ULONGLONG*>(t + 0x18);
            *reinterpret_cast<ULONG*>(buf + 0x18)     = cnt;
            if (cnt) memcpy(buf + 0x1c, t + 0x3c, cnt * 16);
            repacked = true;
            if (isFocus) { t_focusPht = 1; t_focusCoreHits = 0; }
            r2 = g_realDispatchPht(self, buf, comp, out);
            if (isFocus) {
                t_focusPht = 0;
                KEEL_INFO(L"focusPhtResult; k10=%llX rects=%lu -> hr=0x%08lX reachedBitmap=%s (%d)",
                          k10, cnt, (unsigned long)r2,
                          t_focusCoreHits ? L"YES" : L"NO", t_focusCoreHits);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { repacked = false; t_focusPht = 0; }
        if (repacked) return r2;
    }

    if (type == 3 && !BltPhtDisabled()) {
        BYTE* t = reinterpret_cast<BYTE*>(token);
        long r2 = 0;
        bool repacked = false;
        __try {
            const ULONG sz = *reinterpret_cast<const ULONG*>(t + 4);
            ULONG cnt      = (sz >= 0x2c) ? *reinterpret_cast<const ULONG*>(t + 0x28) : 0;
            const ULONG fit = (sz > 0x2c) ? (sz - 0x2c) / 16 : 0;
            if (cnt > fit) cnt = fit;
            if (cnt > kPhtMaxRects) cnt = kPhtMaxRects;
            const ULONGLONG key = *reinterpret_cast<const ULONGLONG*>(t + 0x18);
            BYTE buf[0x24 + kPhtMaxRects * 16]{};
            *reinterpret_cast<ULONG*>(buf + 0x00)     = 3;
            *reinterpret_cast<ULONG*>(buf + 0x04)     = 0x24 + cnt * 16;
            *reinterpret_cast<ULONGLONG*>(buf + 0x08) = *reinterpret_cast<const ULONGLONG*>(t + 0x08);
            *reinterpret_cast<ULONGLONG*>(buf + 0x10) = key;
            *reinterpret_cast<ULONGLONG*>(buf + 0x18) = *reinterpret_cast<const ULONGLONG*>(t + 0x10);
            *reinterpret_cast<ULONG*>(buf + 0x20)     = cnt;
            if (cnt) memcpy(buf + 0x24, t + 0x2c, cnt * 16);
            repacked = true;
            if (InterlockedDecrement(&g_bltPhtLog) > 0)
                KEEL_INFO(L"bltPht; key=%llX rects=%lu -> Win7 BLT token (sz %lu -> %lu)",
                          key, cnt, sz, 0x24 + cnt * 16);
            r2 = g_realDispatchPht(self, buf, comp, out);
        } __except (EXCEPTION_EXECUTE_HANDLER) { repacked = false; }
        if (repacked) return r2;
    }
    const long r = g_realDispatchPht(self, token, comp, out);
    return r;
}
using CoreUpd3Fn = long(__fastcall*)(void*, void*, void*);
using CorePht2Fn = long(__fastcall*)(void*, void*);
CoreUpd3Fn g_realCoreProcessUpdate = nullptr;
CorePht2Fn g_realCoreProcessPht    = nullptr;
volatile LONG g_coreUpdLog = 15, g_corePhtLog = 15;

long __fastcall HookedCoreProcessUpdate(void* self, void* table, void* cmd) {
    const long r = g_realCoreProcessUpdate(self, table, cmd);
    if (InterlockedDecrement(&g_coreUpdLog) > 0)
        KEEL_INFO(L"core; GdiSpriteBitmap::ProcessUpdate(this=%p) -> 0x%08lX", self, (unsigned long)r);
    return r;
}
long __fastcall HookedCoreProcessPht(void* self, void* token) {
    const long r = g_realCoreProcessPht(self, token);
    if (t_focusPht) {
        ++t_focusCoreHits;
        if (InterlockedDecrement(&g_focusCoreLog) > 0)
            KEEL_INFO(L"focusCore; ProcessPresentHistoryToken(this=%p) -> 0x%08lX", self, (unsigned long)r);
    } else if (InterlockedDecrement(&g_corePhtLog) > 0) {
        KEEL_INFO(L"core; GdiSpriteBitmap::ProcessPresentHistoryToken(this=%p) -> 0x%08lX", self, (unsigned long)r);
    }
    return r;
}

void InstallMilFailureTrace() {
    HMODULE redir = GetModuleHandleW(L"dwmredir.dll");
    HMODULE core  = GetModuleHandleW(L"dwmcore.dll");
    const bool wantRedir = redir && !g_realMilChkRedir;
    const bool wantCore  = core  && !g_realMilChkCore;
    if (!wantRedir && !wantCore) return;
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (wantRedir) {
        g_realMilChkRedir = reinterpret_cast<MilChkFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_MilCheckHR);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realMilChkRedir), (PVOID)HookedMilChkRedir);
    }
    if (wantCore) {
        g_realMilChkCore = reinterpret_cast<MilChkFn>(reinterpret_cast<BYTE*>(core) + RVA_Core_MilCheckHR);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realMilChkCore), (PVOID)HookedMilChkCore);
        g_realCoreProcessUpdate = reinterpret_cast<CoreUpd3Fn>(reinterpret_cast<BYTE*>(core) + RVA_Core_ProcessUpdate);
        g_realCoreProcessPht    = reinterpret_cast<CorePht2Fn>(reinterpret_cast<BYTE*>(core) + RVA_Core_ProcessPHT);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCoreProcessUpdate), (PVOID)HookedCoreProcessUpdate);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCoreProcessPht),    (PVOID)HookedCoreProcessPht);
        g_realDispatchPht = reinterpret_cast<DispatchPhtFn>(reinterpret_cast<BYTE*>(core) + RVA_Core_DispatchPHT);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realDispatchPht), (PVOID)HookedDispatchPht);
        g_realGetPh = reinterpret_cast<GetPhFn>(reinterpret_cast<BYTE*>(core) + RVA_Core_GetPresentHistory);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realGetPh), (PVOID)HookedGetPresentHistory);
    }
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"mil; failure trace installed (dwmredir=%d dwmcore=%d commit=%ld)",
              (int)wantRedir, (int)wantCore, e);
}

enum MilRepack { XlatClamp = 0, XlatSpriteMoveTail };
struct MilXlat { ULONG win10; ULONG win7; USHORT win7Len; MilRepack repack; const wchar_t* name; };
constexpr MilXlat kMilXlat[] = {
    { 0x40000011, 0x40000010, 0x34, XlatClamp, L"NotifyChildCreate"      },
    { 0x40000012, 0x40000011, 0x1c, XlatClamp, L"NotifyChildLink"        },
    { 0x40000013, 0x40000012, 0x14, XlatClamp, L"NotifyChildUnlink"      },
    { 0x40000014, 0x40000013, 0x0c, XlatClamp, L"NotifyChildDestroy"     },
    { 0x40000015, 0x40000014, 0x40, XlatClamp, L"NotifyChildMoveSize"    },
    { 0x40000016, 0x40000015, 0x14, XlatClamp, L"NotifyChildStyleChange" },

    { 0x40000002, 0x40000002, 0x54, XlatClamp, L"CreateSprite"           },
    { 0x40000006, 0x40000006, 0x5c, XlatSpriteMoveTail, L"UpdateSprite"  },

    { 0x40000032, 0x40000034, 0x14, XlatClamp, L"NotifyGhostChange"      },
};
using KAsyncFn = long(*)(BYTE* portMsg);
KAsyncFn g_rKernelAsync = nullptr;
volatile LONG g_xlatLog = 60;

volatile LONG g_tailLog = 45;
volatile LONG g_geomLog = 400;
volatile LONG g_trayDumpLog = 6;
volatile LONG g_alphaFixLog = 30;

volatile LONG g_alphaHuntLog = 24;

bool AlphaExpEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_ALPHAEXP", v, 8) > 0 && v[0] == L'1') ? 1 : 0; }
    return cached == 1;
}

void ProbeLogicalSurface(ULONGLONG h, const wchar_t* what);

struct SurfMap {
    ULONGLONG hsprite; ULONGLONG hlsurf; HWND hwnd;
    ULONGLONG lastLs; ULONG lastCx, lastCy;
    int layered;
    int ulw;
    bool tokenSeen;
};
constexpr int kMaxSurf = 512;
SurfMap g_surf[kMaxSurf]{};
int g_surfUsed = 0;
int g_surfHigh = 0;
volatile LONG g_surfFullLog = 1;

volatile LONG g_nSprCreate = 0, g_nSprDestroy = 0, g_nSprUpdate = 0, g_nBitRaised = 0;

SurfMap* SurfBySprite(ULONGLONG hsprite) {
    if (!hsprite) return nullptr;
    for (int i = 0; i < g_surfUsed; ++i) if (g_surf[i].hsprite == hsprite) return &g_surf[i];
    return nullptr;
}
SurfMap* SurfAdd(ULONGLONG hsprite, ULONGLONG hlsurf, HWND hwnd) {
    if (g_surfUsed >= kMaxSurf) {
        if (InterlockedDecrement(&g_surfFullLog) >= 0)
            KEEL_INFO(L"surf; TABLE FULL at %d entries so failing OPEN (sprite=%llX)",
                      kMaxSurf, hsprite);
        return nullptr;
    }
    g_surf[g_surfUsed] = { hsprite, hlsurf, hwnd, 0, 0, 0, -1, -1, false };
    if (g_surfUsed + 1 > g_surfHigh) g_surfHigh = g_surfUsed + 1;
    return &g_surf[g_surfUsed++];
}

void SurfNoteToken(ULONGLONG lsNormalised) {
    if (!lsNormalised) return;
    for (int i = 0; i < g_surfUsed; ++i)
        if (g_surf[i].lastLs == lsNormalised || g_surf[i].hlsurf == lsNormalised) {
            g_surf[i].tokenSeen = true;
            return;
        }
}

void SurfRemoveBySprite(ULONGLONG hsprite) {
    if (!hsprite) return;
    for (int i = 0; i < g_surfUsed; ++i) {
        if (g_surf[i].hsprite != hsprite) continue;
        g_surf[i] = g_surf[--g_surfUsed];
        g_surf[g_surfUsed] = {};
        return;
    }
}

volatile LONG g_sprLifeLog = 2000;
void LogSpriteLife(const wchar_t* what, ULONGLONG hsprite, HWND hwnd, int live) {
    if (InterlockedDecrement(&g_sprLifeLog) <= 0) return;
    wchar_t cls[64] = L"(none)", title[96] = L"";
    bool topLevel = false;
    if (hwnd && IsWindow(hwnd)) {
        GetClassNameW(hwnd, cls, 64);
        GetWindowTextW(hwnd, title, 96);
        topLevel = (GetAncestor(hwnd, GA_ROOT) == hwnd);
    }
    if (!topLevel && !title[0]) { InterlockedIncrement(&g_sprLifeLog); return; }
    KEEL_INFO(L"spr; %s hsprite=%llX hwnd=%p class='%s' title='%s' live=%d", what, hsprite, hwnd, cls, title, live);
}

void NoteSurfaceMapping(const BYTE* pay, ULONG code) {
    switch (code) {
    case 0x40000002: {
        const ULONGLONG sp = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
        HWND hw = *reinterpret_cast<HWND const*>(pay + 0x0C);
        InterlockedIncrement(&g_nSprCreate);
        if (SurfMap* e = SurfBySprite(sp)) e->hwnd = hw; else SurfAdd(sp, 0, hw);
        LogSpriteLife(L"CREATE ", sp, hw, g_surfUsed);
        break;
    }
    case 0x40000006: {
        const ULONGLONG sp = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
        const ULONGLONG ls = *reinterpret_cast<const ULONGLONG*>(pay + 0xa8);
        InterlockedIncrement(&g_nSprUpdate);
        if (SurfMap* e = SurfBySprite(sp)) e->hlsurf = ls; else SurfAdd(sp, ls, nullptr);
        break;
    }
    case 0x40000003: {
        const ULONGLONG sp = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
        InterlockedIncrement(&g_nSprDestroy);
        SurfMap* e = SurfBySprite(sp);
        LogSpriteLife(L"DESTROY", sp, e ? e->hwnd : nullptr, g_surfUsed - (e ? 1 : 0));
        SurfRemoveBySprite(sp);
        break;
    }

    default: break;
    }
}

volatile LONG g_winEvtLog = 400;
void LogWindowEvent(const BYTE* pay, ULONG code) {
    if (g_winEvtLog <= 0) return;
    HWND hwnd = nullptr; HWND extra = nullptr; const wchar_t* what = nullptr;
    switch (code) {
    case 0x40000011: what = L"ChildCreate";      hwnd = *reinterpret_cast<HWND const*>(pay + 0x04); break;
    case 0x40000014: what = L"ChildDestroy";     hwnd = *reinterpret_cast<HWND const*>(pay + 0x04); break;
    case 0x40000016: what = L"ChildStyleChange"; hwnd = *reinterpret_cast<HWND const*>(pay + 0x04); break;
    case 0x40000032: what = L"GhostChange";      hwnd = *reinterpret_cast<HWND const*>(pay + 0x04);
                     extra = *reinterpret_cast<HWND const*>(pay + 0x0C); break;
    default: return;
    }
    if (InterlockedDecrement(&g_winEvtLog) <= 0) return;
    wchar_t cls[64] = L"", title[80] = L"";
    if (hwnd && IsWindow(hwnd)) { GetClassNameW(hwnd, cls, 64); GetWindowTextW(hwnd, title, 80); }
    KEEL_INFO(L"winevt; %s hwnd=%p class='%s' title='%s' other=%p", what, hwnd, cls, title, extra);
}

volatile LONG g_rareCodeLog = 250;
void LogRareCode(ULONG code, ULONG dataLen, const wchar_t* channel) {
    switch (code) {
    case 0x40000002: case 0x40000003: case 0x40000005: case 0x40000006: case 0x40000007: return;
    default: break;
    }
    if (InterlockedDecrement(&g_rareCodeLog) > 0) KEEL_INFO(L"milcmd[%s]; code=0x%08lX len=0x%lX", channel, code, dataLen);
}

void TraceOrbMil(const BYTE* pm, ULONG code, ULONG len) {
    const BYTE* pay = pm + 0x28;
    BYTE snap[0x50]{};
    const ULONG headLen = len < 0x3c ? len : 0x3c;
    memcpy(snap, pay, headLen);
    if (len >= 0xbc) memcpy(snap + 0x40, pay + 0xa8, 0x10);
    if (code == 0x40000006 && g_orbLastValid && memcmp(snap, g_orbLastMil, sizeof(snap)) == 0) {

        const LONG n = InterlockedIncrement(&g_orbDupes);
        if ((n % 8) == 0 && InterlockedDecrement(&g_orbMilLog) > 0)
            KEEL_INFO(L"orbMil; UPDATESPRITE unchanged x8 (total %ld) tick=%lu", n, GetTickCount());
        return;
    }
    memcpy(g_orbLastMil, snap, sizeof(snap));
    g_orbLastValid = true;
    if (InterlockedDecrement(&g_orbMilLog) <= 0) return;
    ULONG flags = 0, hasInfo = 0, attrs = 0, cx = 0, cy = 0; ULONGLONG ls = 0;
    LONG r1[4]{}, r2[4]{};
    __try {
        if (len >= 0x14) { flags = *reinterpret_cast<const ULONG*>(pay + 0x0c);
                           hasInfo = *reinterpret_cast<const ULONG*>(pay + 0x10); }
        if (len >= 0x34) { memcpy(r1, pay + 0x14, sizeof(r1)); memcpy(r2, pay + 0x24, sizeof(r2)); }
        if (len >= 0x40) attrs = *reinterpret_cast<const ULONG*>(pay + 0x3c);
        if (len >= 0xbc) { ls = *reinterpret_cast<const ULONGLONG*>(pay + 0xa8);
                           cx = *reinterpret_cast<const ULONG*>(pay + 0xb4);
                           cy = *reinterpret_cast<const ULONG*>(pay + 0xb8); }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KEEL_INFO(L"orbMil; code=0x%08lX len=%lu flags=0x%lX hasInfo=%lu rect=(%ld,%ld,%ld,%ld)"
              L" rect2=(%ld,%ld,%ld,%ld) attrs=0x%08lX hlsurf=%llX %lux%lu [dupes=%ld] tick=%lu",
              code, len, flags, hasInfo, r1[0], r1[1], r1[2], r1[3], r2[0], r2[1], r2[2], r2[3],
              attrs, ls, cx, cy, g_orbDupes, GetTickCount());
}

constexpr ULONG kDirtySpriteCmd   = 0x40000004;
constexpr USHORT kDirtySpriteLen  = 0x18;
LONG g_nLayerDirty = 0;
volatile LONG g_layerDirtyLog = 8;
bool LayerDirtyEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NOLAYERDIRTY", v, 8) > 0 && v[0] == L'1') ? 0 : 1; }
    return cached == 1;
}

bool SpriteIsLayered(SurfMap* e) {
    if (!e || !e->hwnd) return false;
    if (e->layered < 0) {
        if (!IsWindow(e->hwnd)) return false;
        e->layered = (GetWindowLongW(e->hwnd, GWL_EXSTYLE) & WS_EX_LAYERED) ? 1 : 0;
    }
    return e->layered == 1;
}

volatile LONG g_ulwAlphaLog = 8;
int SpriteUlwKind(SurfMap* e) {
    if (!SpriteIsLayered(e)) return 0;
    if (e->ulw != 2) {
        if (!IsWindow(e->hwnd)) return 0;
        e->ulw = static_cast<int>(reinterpret_cast<ULONG_PTR>(GetPropW(e->hwnd, kUlwAlphaProp)));
    }
    return e->ulw;
}

void SendDirtySprite(const BYTE* templateMsg, ULONGLONG hsprite) {
    BYTE msg[0x28 + kDirtySpriteLen]{};
    memcpy(msg, templateMsg, 0x28);
    *reinterpret_cast<USHORT*>(msg + 0x00) = kDirtySpriteLen;
    *reinterpret_cast<USHORT*>(msg + 0x02) = kDirtySpriteLen + 0x28;
    BYTE* p = msg + 0x28;
    *reinterpret_cast<ULONG*>(p + 0x00)     = kDirtySpriteCmd;
    *reinterpret_cast<ULONG*>(p + 0x04)     = kDirtySpriteFlags;
    *reinterpret_cast<ULONGLONG*>(p + 0x08) = hsprite;
    *reinterpret_cast<ULONGLONG*>(p + 0x10) = 0;
    g_rKernelAsync(msg);
    InterlockedIncrement(&g_nLayerDirty);
}

volatile LONG g_seqLog = 6000;
volatile LONG g_seqNo = 0;
bool MsgNamesFocus(const BYTE* pay, ULONG len) {
    if (!g_orbSprite && !g_orbHlsurf) return false;
    const ULONG scan = len < 0x40 ? len : 0x40;
    __try {
        for (ULONG off = 0; off + 8 <= scan; off += 4) {
            const ULONGLONG v = *reinterpret_cast<const ULONGLONG*>(pay + off);
            if (v && v == g_orbSprite) return true;
            const ULONGLONG n = NormLs(v);
            if (n && (n == NormLs(g_orbHlsurf) || OrbKnowsLs(n))) return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

volatile LONG g_orbScanLog = 60;
bool CodeIsHandled(ULONG code) {
    switch (code) {
    case 0x40000002: case 0x40000003: case 0x40000004: case 0x40000005: case 0x40000006:
    case 0x40000007: case 0x4000000C: case 0x40000010: case 0x40000011: case 0x40000012:
    case 0x40000013: case 0x40000014: case 0x40000015: case 0x40000016: case 0x40000029:
    case 0x40000032: case 0x40000034: case 0x40000037: case 0x40000038: case 0x4000003F:
    case 0x40000043: case 0x40000044: case 0x40000045: case 0x8000000A: case 0x8000000B:
        return true;
    default: return false;
    }
}
void ScanUnhandledForOrb(const BYTE* pm, ULONG code, ULONG len) {
    if (!g_orbSprite || CodeIsHandled(code) || len < 8 || len > 0x2000) return;
    const BYTE* pay = pm + 0x28;
    bool names = false;
    ULONG at = 0;
    __try {
        for (ULONG off = 0; off + 8 <= len; off += 4) {
            const ULONGLONG v = *reinterpret_cast<const ULONGLONG*>(pay + off);
            if (v == g_orbSprite || OrbKnowsLs(NormLs(v))) { names = true; at = off; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (!names || InterlockedDecrement(&g_orbScanLog) <= 0) return;
    wchar_t hex[420]{}; int n = 0;
    __try {
        const ULONG show = len < 96 ? len : 96;
        for (ULONG i = 0; i < show && n < 400; ++i) n += swprintf_s(hex + n, 420 - n, L"%02X ", pay[i]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    KEEL_INFO(L"orbScan; UNHANDLED code=0x%08lX len=%lu names the orb at +0x%lX | %s", code, len, at, hex);
}

long HookedKernelAsync(BYTE* pm) {
    ULONGLONG dirtySprite = 0;
    ULONG  seqCode = 0;
    USHORT seqLen = 0;
    bool   seqFocus = false;
    ULONG  seqFlags = 0;
    __try {
        ULONG* code = reinterpret_cast<ULONG*>(pm + 0x28);
        seqCode  = *code;
        seqLen   = *reinterpret_cast<USHORT*>(pm + 0x00);
        seqFocus = MsgNamesFocus(pm + 0x28, seqLen);

        if (seqLen >= 0x10) seqFlags = *reinterpret_cast<ULONG*>(pm + 0x28 + 0x0c);
        if (g_orbSprite && *reinterpret_cast<ULONGLONG*>(pm + 0x2c) == g_orbSprite)
            TraceOrbMil(pm, *code, *reinterpret_cast<ULONG*>(pm + 0x08));
        ScanUnhandledForOrb(pm, *code, *reinterpret_cast<ULONG*>(pm + 0x08));
        NoteSurfaceMapping(pm + 0x28, *code);
        LogWindowEvent(pm + 0x28, *code);
        LogRareCode(*code, *reinterpret_cast<ULONG*>(pm + 0x08), L"async");

        if (*code == 0x40000006 && InterlockedDecrement(&g_tailLog) > 0) {
            const BYTE* pay = pm + 0x28;
            const ULONG flags = *reinterpret_cast<const ULONG*>(pay + 0x0c);
            const ULONGLONG spr = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
            const ULONGLONG ls  = *reinterpret_cast<const ULONGLONG*>(pay + 0xa8);
            const ULONG cx = *reinterpret_cast<const ULONG*>(pay + 0xb4);
            const ULONG cy = *reinterpret_cast<const ULONG*>(pay + 0xb8);
            const SurfMap* e = SurfBySprite(spr);
            HWND hw = e ? e->hwnd : nullptr;
            wchar_t cls[40]{}; if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 39);
            KEEL_INFO(L"updGate; flags=0x%02lX bit10=%d hlsurf=%llX %lux%lu hwnd=%p '%s'",
                      flags, (flags & 0x10) ? 1 : 0, ls, cx, cy, hw, cls);
        }

        if (*code == 0x40000006 && g_alphaHuntLog > 0) {
            const BYTE* pay = pm + 0x28;
            const ULONGLONG spr = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
            const SurfMap* e = SurfBySprite(spr);
            HWND hw = e ? e->hwnd : nullptr;
            wchar_t cls[56]{}; if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 55);
            const bool popup = !wcscmp(cls, L"MozillaDropShadowWindowClass");
            const bool control = !wcscmp(cls, L"MozillaWindowClass");

            if (popup && g_blurMgr && g_realNotifyBlur && AlphaExpEnabled() && hw) {
                static HWND s_done[8]{}; bool already = false;
                for (HWND& d : s_done) { if (d == hw) { already = true; break; } }
                if (!already) {
                    for (HWND& d : s_done) { if (!d) { d = hw; break; } }
                    struct { DWORD dwFlags; BOOL fEnable; HRGN hRgnBlur; BOOL fTransitionOnMaximized; } bb{};

                    bb.dwFlags = 1 | 2;
                    bb.fEnable = TRUE;
                    const long br = g_realNotifyBlur(g_blurMgr, hw, &bb, nullptr);
                    KEEL_INFO(L"alphaExp; issued blur-behind for hwnd=%p '%s' -> 0x%08lX", hw, cls, (unsigned long)br);
                }
            }
            if ((popup || control) && InterlockedDecrement(&g_alphaHuntLog) > 0) {
                wchar_t hex[3 * 0x60 + 1]{}; int n = 0;
                for (int i = 0; i < 0x60; ++i) n += swprintf_s(hex + n, 3 * 0x60 + 1 - n, L"%02X ", pay[i]);
                wchar_t tail[3 * 0x30 + 1]{}; int m = 0;
                for (int i = 0; i < 0x30; ++i) m += swprintf_s(tail + m, 3 * 0x30 + 1 - m, L"%02X ", pay[0x98 + i]);
                KEEL_INFO(L"alphaHunt; %s '%s' ex=%08lX attr0=%08lX attr4=%08lX attr8=%08lX | %s",
                          popup ? L"POPUP  " : L"OPAQUE ", cls,
                          *reinterpret_cast<const ULONG*>(pay + 0x38),
                          *reinterpret_cast<const ULONG*>(pay + 0x3c),
                          *reinterpret_cast<const ULONG*>(pay + 0x40),
                          *reinterpret_cast<const ULONG*>(pay + 0x44), hex);
                KEEL_INFO(L"alphaHunt; %s '%s' TAIL hlsurf=%llX cx=%lu cy=%lu | at 0x98 %s",
                          popup ? L"POPUP  " : L"OPAQUE ", cls,
                          *reinterpret_cast<const ULONGLONG*>(pay + 0xa8),
                          *reinterpret_cast<const ULONG*>(pay + 0xb4),
                          *reinterpret_cast<const ULONG*>(pay + 0xb8), tail);
            }
        }

        if ((*code == 0x40000006 || *code == 0x40000007 || *code == 0x40000005) &&
            InterlockedDecrement(&g_geomLog) > 0) {
            const BYTE* pay = pm + 0x28;
            const ULONGLONG spr = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
            const SurfMap* e = SurfBySprite(spr);
            HWND hw = e ? e->hwnd : nullptr;
            wchar_t cls[40]{}; if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 39);
            if (*code == 0x40000007) {
                KEEL_INFO(L"vis; ShowSprite spr=%llX show=%ld '%s'",
                          spr, *reinterpret_cast<const LONG*>(pay + 0x0c), cls);
            } else if (*code == 0x40000005) {
                KEEL_INFO(L"vis; ZorderSprite spr=%llX after=%llX '%s'",
                          spr, *reinterpret_cast<const ULONGLONG*>(pay + 0x0c), cls);
            } else {
                const LONG* wr = reinterpret_cast<const LONG*>(pay + 0x14);
                const LONG* cr = reinterpret_cast<const LONG*>(pay + 0x24);

                if (!wcscmp(cls, L"Shell_TrayWnd") && InterlockedDecrement(&g_trayDumpLog) > 0) {
                    wchar_t hex[3 * 0xC4 + 1]{}; int n = 0;
                    for (int i = 0; i < 0xC4; ++i)
                        n += swprintf_s(hex + n, 3 * 0xC4 + 1 - n, L"%02X ", pay[i]);
                    KEEL_INFO(L"trayRaw; %s", hex);
                }
                KEEL_INFO(L"geom; '%s' flags=%08lX bit3=%d hasInfo=%ld win=(%ld,%ld,%ld,%ld) "
                          L"cli=(%ld,%ld,%ld,%ld) style=%08lX ex=%08lX attr=%08lX/%08lX/%08lX",
                          cls, *reinterpret_cast<const ULONG*>(pay + 0x0c),
                          (*reinterpret_cast<const ULONG*>(pay + 0x0c) & 8) ? 1 : 0,
                          *reinterpret_cast<const LONG*>(pay + 0x10),
                          wr[0], wr[1], wr[2], wr[3], cr[0], cr[1], cr[2], cr[3],
                          *reinterpret_cast<const ULONG*>(pay + 0x34),
                          *reinterpret_cast<const ULONG*>(pay + 0x38),
                          *reinterpret_cast<const ULONG*>(pay + 0x3c),
                          *reinterpret_cast<const ULONG*>(pay + 0x40),
                          *reinterpret_cast<const ULONG*>(pay + 0x44));
            }
        }
        for (const auto& x : kMilXlat) {
            if (*code != x.win10) continue;
            USHORT* dataLen = reinterpret_cast<USHORT*>(pm + 0x00);

            if (*dataLen < x.win7Len) break;
            if (InterlockedDecrement(&g_xlatLog) > 0)
                KEEL_INFO(L"redir; xlat 0x%08lX(%u) -> 0x%08lX(%u) %s hwnd=%p",
                          x.win10, (unsigned)*dataLen, x.win7, (unsigned)x.win7Len, x.name,
                          *reinterpret_cast<void**>(pm + 0x2c));

            if (x.repack == XlatSpriteMoveTail && *dataLen >= 0xbc) {
                BYTE* pay = pm + 0x28;
                const ULONGLONG rawLs  = *reinterpret_cast<const ULONGLONG*>(pay + 0xa8);
                const ULONGLONG hlsurf = NormLs(rawLs);
                if (rawLs != hlsurf) {
                    InterlockedIncrement(&g_nLsNormalized);
                    if (InterlockedDecrement(&g_lsNormLog) > 0)
                        KEEL_INFO(L"ls; sign-extended surface %llX -> %llX (present tokens key on the"
                                  L" 32-bit handle and the two spellings never match)", rawLs, hlsurf);
                }
                const ULONG style      = *reinterpret_cast<const ULONG*>(pay + 0xb0);
                const ULONG cx         = *reinterpret_cast<const ULONG*>(pay + 0xb4);
                const ULONG cy         = *reinterpret_cast<const ULONG*>(pay + 0xb8);
                *reinterpret_cast<ULONGLONG*>(pay + 0x48) = hlsurf;
                *reinterpret_cast<ULONG*>(pay + 0x50)     = style;
                *reinterpret_cast<ULONG*>(pay + 0x54)     = cx;
                *reinterpret_cast<ULONG*>(pay + 0x58)     = cy;

                ULONG* attrFlags = reinterpret_cast<ULONG*>(pay + 0x3c);
                const BYTE attrAlpha = pay[0x42];

                if (SpriteUlwKind(SurfBySprite(*reinterpret_cast<const ULONGLONG*>(pay + 0x04))) == 2 &&
                    pay[0x43] != 1) {
                    const BYTE was = pay[0x43];
                    pay[0x43] = 1;
                    if (InterlockedDecrement(&g_ulwAlphaLog) > 0)
                        KEEL_INFO(L"alpha; sprite=%llX is an UpdateLayeredWindow surface -> honouring"
                                  L" its per-pixel alpha (attr+7 %u -> 1, attrFlags %08lX)",
                                  *reinterpret_cast<const ULONGLONG*>(pay + 0x04), was, *attrFlags);
                }
                if ((*attrFlags & 2) && attrAlpha == 0) {
                    *attrFlags &= ~2u;
                    if (InterlockedDecrement(&g_alphaFixLog) > 0)
                        KEEL_INFO(L"alpha; sprite=%llX attr=%08lX had constant-alpha bit with alpha=0"
                                  L" -> cleared (would composite fully transparent)",
                                  *reinterpret_cast<const ULONGLONG*>(pay + 0x04), *attrFlags | 2u);
                }

                ULONG* spriteFlags = reinterpret_cast<ULONG*>(pay + 0x0c);
                if (hlsurf && cx && cy && !(*spriteFlags & 0x10)) {
                    const ULONGLONG spr = *reinterpret_cast<const ULONGLONG*>(pay + 0x04);
                    SurfMap* e = SurfBySprite(spr);
                    if (!e) e = SurfAdd(spr, hlsurf, nullptr);

                    if (LayerDirtyEnabled() && e && !e->tokenSeen && SpriteUlwKind(e) != 0) {
                        dirtySprite = spr;
                        if (InterlockedDecrement(&g_layerDirtyLog) > 0)
                            KEEL_INFO(L"layerDirty; sprite=%llX hwnd=%p surface=%llX %lux%lu has no"
                                      L" present tokens so synthesising DIRTYSPRITE(flags=%lu)",
                                      spr, e->hwnd, hlsurf, cx, cy, kDirtySpriteFlags);
                    }

                    if (!e || e->lastLs != hlsurf || e->lastCx != cx || e->lastCy != cy) {
                        *spriteFlags |= 0x10;
                        InterlockedIncrement(&g_nBitRaised);
                        if (e) { e->lastLs = hlsurf; e->lastCx = cx; e->lastCy = cy; }

                    }
                }
            }
            *code    = x.win7;
            *dataLen = x.win7Len;
            *reinterpret_cast<USHORT*>(pm + 0x02) = x.win7Len + 0x28;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    const long r = g_rKernelAsync(pm);

    if (seqFocus && InterlockedDecrement(&g_seqLog) > 0) {
        ULONG cAfter = 0; USHORT lAfter = 0;
        __try {
            cAfter = *reinterpret_cast<ULONG*>(pm + 0x28);
            lAfter = *reinterpret_cast<USHORT*>(pm + 0x00);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        wchar_t xlat[48] = L"";
        if (cAfter != seqCode || lAfter != seqLen)
            swprintf_s(xlat, L" -> 0x%08lX(%u)", cAfter, (unsigned)lAfter);
        KEEL_INFO(L"seq; #%ld 0x%08lX(%u)%s flags=0x%08lX bit3=%d hr=0x%08lX%s tick=%lu",
                  InterlockedIncrement(&g_seqNo), seqCode, (unsigned)seqLen, xlat,
                  seqFlags, (seqFlags & 8) ? 1 : 0,
                  r, dirtySprite ? L" +synthDirty" : L"", GetTickCount());
    }

    if (dirtySprite) {
        __try { SendDirtySprite(pm, dirtySprite); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return r;
}

using RDispatchFn = long(__fastcall*)(void*, void*, void*, void*);
RDispatchFn g_rMgrDispatch = nullptr;

struct MilShape { ULONG code; USHORT len; LONG hits; };
constexpr int kMaxShapes = 96;
MilShape g_shapes[kMaxShapes]{};
int g_shapeUsed = 0;

volatile LONG g_syncXlatLog = 20;

constexpr ULONG kMilSyncFlushForceRender = 0x80000009;
volatile LONG g_flushAckLog = 12;
volatile LONG g_hitReplyLog = 40;

long __fastcall HookedRedirDispatch(void* a, void* b, void* c, void* d) {
    USHORT dataLen = 0, type = 0; ULONG code = 0; const BYTE* pay = nullptr;
    BYTE* ackMsg = nullptr;
    wchar_t hex[3 * 200 + 1]{};
    __try {

        auto vt = *reinterpret_cast<void***>(a);
        using GetPortMsgFn = BYTE*(__fastcall*)(void*);
        BYTE* pm = reinterpret_cast<GetPortMsgFn>(vt[2])(a);
        dataLen = *reinterpret_cast<USHORT*>(pm + 0x00);
        type    = *reinterpret_cast<USHORT*>(pm + 0x04);

        BYTE* body = pm + ((type & 0x8000) ? 0x28 : 0x30);
        pay  = body;
        code = *reinterpret_cast<const ULONG*>(body);
        if (code == 0x40000018 && dataLen == 0x34) {
            *reinterpret_cast<ULONG*>(body) = 0x40000017;
            code = 0x40000017;
            if (InterlockedDecrement(&g_syncXlatLog) > 0)
                KEEL_INFO(L"redir; sync xlat 0x40000018(0x34) -> 0x40000017 HitTestQuery");
        } else if (code == kMilSyncFlushForceRender && (type & 0x8000)) {
            *reinterpret_cast<LONG*>(pm + 0x2c) = 0;
            ackMsg = pm;
        }
        int n = 0;
        for (int i = 0; i < 200 && i < dataLen; ++i) n += swprintf_s(hex + n, 3 * 200 + 1 - n, L"%02X ", body[i]);
    } __except (EXCEPTION_EXECUTE_HANDLER) { pay = nullptr; ackMsg = nullptr; }
    if (ackMsg) {
        if (InterlockedDecrement(&g_flushAckLog) > 0)
            KEEL_INFO(L"redir; sync 0x80000009 FlushForceRenderAndWaitForBatch -> S_OK (no Win7 equivalent)");
        return 0;
    }
    const long r = g_rMgrDispatch(a, b, c, d);

    if (code == 0x40000017 && InterlockedDecrement(&g_hitReplyLog) > 0) {
        __try {
            const ULONG ht = *reinterpret_cast<const ULONG*>(pay + 0x2c);
            const ULONG handled = *reinterpret_cast<const ULONG*>(pay + 0x30);
            KEEL_INFO(L"redir; HitTestQuery reply ht=0x%08lX handled=%lu (hr=0x%08lX)", ht, handled, (unsigned long)r);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (!pay) return r;

    LONG seen = -1;
    for (int i = 0; i < g_shapeUsed; ++i)
        if (g_shapes[i].code == code && g_shapes[i].len == dataLen) { seen = ++g_shapes[i].hits; break; }
    if (seen < 0 && g_shapeUsed < kMaxShapes) {
        g_shapes[g_shapeUsed] = { code, dataLen, 1 }; ++g_shapeUsed; seen = 1;
    }

    const bool sprite = (code == 0x40000002 || code == 0x40000006);
    if ((seen >= 1 && seen <= 2) || (sprite && seen <= 6)) {
        KEEL_INFO(L"redir; MILCMD 0x%08lX len=%u %s -> 0x%08lX | %s",
                  code, (unsigned)dataLen, (type & 0x8000) ? L"KERNEL" : L"user",
                  (unsigned long)r, hex);
    }
    return r;
}
void InstallDwmRedirTrace(HMODULE redir);

using GetDxSharedSurfaceFn = BOOL(WINAPI*)(HWND, HANDLE*, LUID*, ULONG*, ULONG*, ULONGLONG*);
GetDxSharedSurfaceFn g_getDxSharedSurface = nullptr;

BOOL CALLBACK ProbeWindowCb(HWND hwnd, LPARAM) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    RECT rc{}; GetWindowRect(hwnd, &rc);
    if (rc.right - rc.left <= 0 || rc.bottom - rc.top <= 0) return TRUE;
    wchar_t cls[64]{}; GetClassNameW(hwnd, cls, 63);
    HANDLE surf = nullptr; LUID luid{}; ULONG fmt = 0, flags = 0; ULONGLONG updateId = 0;
    SetLastError(0);
    const BOOL ok = g_getDxSharedSurface(hwnd, &surf, &luid, &fmt, &flags, &updateId);
    KEEL_INFO(L"probe; win hwnd=%p '%s' %ldx%ld -> ok=%d surf=%p luid=%lu:%ld fmt=%lu flags=0x%lX "
              L"updId=%llu err=%lu",
              hwnd, cls, rc.right - rc.left, rc.bottom - rc.top, (int)ok, surf,
              luid.LowPart, luid.HighPart, fmt, flags, updateId, GetLastError());
    return TRUE;
}

void DumpMilShapes(const wchar_t* when) {
    for (int i = 0; i < g_shapeUsed; ++i)
        KEEL_INFO(L"census(%s); MILCMD 0x%08lX len=%u  x%ld", when,
                  g_shapes[i].code, (unsigned)g_shapes[i].len, g_shapes[i].hits);
    KEEL_INFO(L"census(%s); GetPresentHistory calls=%ld tokens=%ld | token types 1(GDI)=%ld 2(FLIP)=%ld 3(BLT)=%ld",
              when, g_getPhCalls, g_getPhTokens, g_phtTypeCount[1], g_phtTypeCount[2], g_phtTypeCount[3]);
    for (int i = 0; i < g_surfUsed; ++i) {
        wchar_t cls[48]{};
        if (g_surf[i].hwnd && IsWindow(g_surf[i].hwnd)) GetClassNameW(g_surf[i].hwnd, cls, 47);
        KEEL_INFO(L"census(%s); sprite=%llX hlsurf=%llX hwnd=%p '%s'", when,
                  g_surf[i].hsprite, g_surf[i].hlsurf, g_surf[i].hwnd, cls);
    }
}

extern volatile LONG g_topLevelWindowCount;

using IsTDCFn = BOOL(WINAPI*)(void);
BOOL ComposedBitOnDesktop(const wchar_t* name, HDESK* opened) {
    *opened = OpenDesktopW(name, 0, FALSE, READ_CONTROL | DESKTOP_READOBJECTS);
    if (!*opened) return -1;
    if (!SetThreadDesktop(*opened)) return -2;
    static IsTDCFn f = (IsTDCFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "IsThreadDesktopComposited");
    return f ? f() : -3;
}
DWORD WINAPI ComposedAuditThread(LPVOID) {
    Sleep(30000);
    IsTDCFn f = (IsTDCFn)GetProcAddress(GetModuleHandleW(L"user32.dll"), "IsThreadDesktopComposited");
    KEEL_INFO(L"composed; dwm thread's own desktop -> %d", f ? f() : -3);
    static const wchar_t* const kDesks[3] = { L"Default", L"Winlogon", L"Disconnect" };
    for (const wchar_t* d : kDesks) {
        HDESK h = nullptr;
        const BOOL b = ComposedBitOnDesktop(d, &h);
        KEEL_INFO(L"composed; desktop '%s' -> %d (err=%lu)", d, b, b < 0 ? GetLastError() : 0);
        if (h) CloseDesktop(h);
    }

    wchar_t v[8]{};
    if (GetEnvironmentVariableW(L"KEEL_RECOMPOSE", v, 8) > 0 && v[0] == L'1') {
        HMODULE w = GetModuleHandleW(L"win32u.dll");
        using KsFn = LONG(WINAPI*)(void);
        KsFn ks = w ? (KsFn)GetProcAddress(w, "NtUserDwmKernelStartup") : nullptr;
        if (ks) {
            SetLastError(0);
            const LONG r = ks();
            KEEL_INFO(L"composed; NtUserDwmKernelStartup() again -> 0x%08lX err=%lu", (unsigned long)r, GetLastError());
            Sleep(2000);
            for (const wchar_t* d : kDesks) {
                HDESK h = nullptr; const BOOL b = ComposedBitOnDesktop(d, &h);
                KEEL_INFO(L"composed; after recompose, desktop '%s' -> %d", d, b);
                if (h) CloseDesktop(h);
            }
        } else KEEL_WARN(L"composed; win32u!NtUserDwmKernelStartup not found");
    }
    return 0;
}

DWORD WINAPI SurfaceProbeThread(LPVOID) {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    g_getDxSharedSurface = u32 ? (GetDxSharedSurfaceFn)GetProcAddress(u32, "DwmGetDxSharedSurface") : nullptr;
    if (!g_getDxSharedSurface) { KEEL_WARN(L"probe; user32!DwmGetDxSharedSurface unavailable"); return 0; }
    static const wchar_t* const kWhen[2] = { L"t30", L"t75" };
    static const DWORD kDelay[2] = { 30000, 45000 };
    for (int pass = 0; pass < 2; ++pass) {
        const wchar_t* when = kWhen[pass];
        Sleep(kDelay[pass]);
        KEEL_INFO(L"probe(%s); DwmGetDxSharedSurface=%p for visible top-level windows", when,
                  g_getDxSharedSurface);
        EnumWindows(ProbeWindowCb, 0);
        DumpMilShapes(when);

        if (g_realGetWndCompInfo && pass == 0) {
            HWND prog = FindWindowW(L"Progman", nullptr);
            static const unsigned long kSizes[] = { 0, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x60, 0x80, 0x100 };
            for (unsigned long sz : kSizes) {
                BYTE buf[0x200]{}; *reinterpret_cast<unsigned long*>(buf) = sz;
                SetLastError(0);
                const long r = g_realGetWndCompInfo(prog, buf);
                const DWORD err = GetLastError();
                int nz = 0; for (int i = 4; i < 0x200; ++i) if (buf[i]) ++nz;
                wchar_t hex[3 * 48 + 1]{}; int n = 0;
                for (int i = 0; i < 48; ++i) n += swprintf_s(hex + n, 3 * 48 + 1 - n, L"%02X ", buf[i]);
                KEEL_INFO(L"gwci; cbSize=0x%lX -> ret=%ld err=%lu nonzero=%d | %s", sz, r, err, nz, hex);
            }
        }
        KEEL_INFO(L"probe(%s); done", when);
    }

    LONG lastC = -1, lastD = -1, lastCS = -1;
    for (;;) {
        Sleep(15000);
        const LONG c = g_nSprCreate, d = g_nSprDestroy, cs = g_nCreateSurface;
        if (c == lastC && d == lastD && cs == lastCS) continue;
        lastC = c; lastD = d; lastCS = cs;
        KEEL_INFO(L"hb; sprites live=%d high=%d/%d (create=%ld destroy=%ld update=%ld) "
                  L"bit10=%ld CreateSurface=%ld TopLevelWindow=%ld",
                  g_surfUsed, g_surfHigh, kMaxSurf, c, d, g_nSprUpdate,
                  g_nBitRaised, cs, g_topLevelWindowCount);
    }
}

void BuildWin7ThemeFile(HMODULE ux) {
    auto at = [ux](DWORD rva){ return reinterpret_cast<BYTE*>(ux) + rva; };
    auto ctor   = reinterpret_cast<UxCtorFn>(at(kUxThemeLoaderCtor));
    auto load   = reinterpret_cast<UxLoadThemeFn>(at(kUxThemeLoaderLoad));
    auto defs   = reinterpret_cast<UxDefaultsFn>(at(kUxGetThemeDefaults));
    auto fctor  = reinterpret_cast<UxCtorFn>(at(kUxFileCtor));
    auto fopen  = reinterpret_cast<UxOpenHandleFn>(at(kUxFileOpenHandle));
    g_openThemeFromFile = reinterpret_cast<UxOpenFromFileFn>(at(kUxOpenThemeFromFile));

    wchar_t color[128] = L"NormalColor", size[128] = L"NormalSize";
    defs(kWin7Msstyles, color, 128, size, 128);
    void* loader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x500);
    if (!loader) { KEEL_ERROR(L"dwm; theme loader alloc failed"); return; }
    ctor(loader);
    void* section = nullptr;
    long hr = load(loader, nullptr, nullptr, kWin7Msstyles, color, size, &section, 0);
    HeapFree(GetProcessHeap(), 0, loader);
    if (hr < 0 || !section) { KEEL_ERROR(L"dwm; CThemeLoader::LoadTheme -> 0x%08lX section=%p", (unsigned long)hr, section); return; }
    void* file = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x40);
    if (!file) return;
    fctor(file);
    long ofh = fopen(file, section, 4 , 0);
    if (ofh < 0) { KEEL_ERROR(L"dwm; CUxThemeFile::OpenFromHandle -> 0x%08lX", (unsigned long)ofh); HeapFree(GetProcessHeap(),0,file); return; }
    g_win7ThemeFile = file;
    KEEL_INFO(L"dwm; built in-process Win7 theme file %p (color='%s' size='%s')", file, color, size);
}

bool g_themeBridgeReady = false;

void InstallThemeBridge(HMODULE ux) {
    if (g_themeBridgeReady || !ux) return;
    wchar_t p[MAX_PATH]{}; GetModuleFileNameW(ux, p, MAX_PATH);
    DWORD a=0,b=0,c=0,d=0;
    bool verOk = keel::GetFileVersion(p, a, b, c, d) && a==6 && b==1 && c==7601 && d==23403;
    KEEL_INFO(L"dwm; uxtheme %lu.%lu.%lu.%lu @ %s (theme bridge %s)", a, b, c, d, p, verOk ? L"OK" : L"skip");
    if (!verOk) return;
    g_themeBridgeReady = true;
    BuildWin7ThemeFile(ux);

    g_realOpenThemeData   = (OpenThemeDataFn)GetProcAddress(ux, "OpenThemeData");
    g_realOpenThemeDataEx = (OpenThemeDataExFn)GetProcAddress(ux, "OpenThemeDataEx");
    g_realGetCurThemeName = (GetCurThemeNameFn)GetProcAddress(ux, "GetCurrentThemeName");
    g_realGetThemeInt     = (GetThemeIntFn)GetProcAddress(ux, "GetThemeInt");
    g_realGetThemeColor   = (GetThemeColorFn)GetProcAddress(ux, "GetThemeColor");
    g_realGetThemeMargins = (GetThemeMarginsFn)GetProcAddress(ux, "GetThemeMargins");
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (g_realOpenThemeData)   DetourAttach(reinterpret_cast<PVOID*>(&g_realOpenThemeData), (PVOID)HookedOpenThemeData);
    if (g_realOpenThemeDataEx) DetourAttach(reinterpret_cast<PVOID*>(&g_realOpenThemeDataEx), (PVOID)HookedOpenThemeDataEx);
    if (g_realGetCurThemeName) DetourAttach(reinterpret_cast<PVOID*>(&g_realGetCurThemeName), (PVOID)HookedGetCurThemeName);
    if (g_realGetThemeInt)     DetourAttach(reinterpret_cast<PVOID*>(&g_realGetThemeInt), (PVOID)HookedGetThemeInt);
    if (g_realGetThemeColor)   DetourAttach(reinterpret_cast<PVOID*>(&g_realGetThemeColor), (PVOID)HookedGetThemeColor);
    if (g_realGetThemeMargins) DetourAttach(reinterpret_cast<PVOID*>(&g_realGetThemeMargins), (PVOID)HookedGetThemeMargins);
    g_realSetWindowTheme = (SetWindowThemeFn)GetProcAddress(ux, "SetWindowTheme");
    if (g_realSetWindowTheme) DetourAttach(reinterpret_cast<PVOID*>(&g_realSetWindowTheme), (PVOID)HookedSetWindowTheme);
    LONG e = DetourTransactionCommit();
    KEEL_INFO(L"dwm; theme bridge installed (commit=%ld, themeFile=%p)", e, g_win7ThemeFile);
}

void PatchBytes(PBYTE fn, const unsigned char* patch, size_t n, const wchar_t* label) {
    DWORD old = 0;
    if (VirtualProtect(fn, n, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy(fn, patch, n);
        DWORD tmp; VirtualProtect(fn, n, old, &tmp);
        FlushInstructionCache(GetCurrentProcess(), fn, n);
        KEEL_INFO(L"dwm; byte-patched %s", label);
    } else {
        KEEL_ERROR(L"dwm; VirtualProtect failed patching %s", label);
    }
}
void PatchReturnTrue(PBYTE fn, const wchar_t* label) {
    const unsigned char p[] = { 0xB0, 0x01, 0xC3 };
    PatchBytes(fn, p, sizeof(p), label);
}
void PatchReturnZero(PBYTE fn, const wchar_t* label) {
    const unsigned char p[] = { 0x31, 0xC0, 0xC3 };
    PatchBytes(fn, p, sizeof(p), label);
}
void PatchReturnOne(PBYTE fn, const wchar_t* label) {
    const unsigned char p[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    PatchBytes(fn, p, sizeof(p), label);
}

using DwmStartupFn = long(__cdecl*)(void*, void*);
DwmStartupFn g_realDwmClientStartup = nullptr;

using LdrLoadDllFn = long(NTAPI*)(PWSTR, PULONG, KUNICODE_STRING*, PVOID*);
LdrLoadDllFn g_realLdrLoadDll = nullptr;

long __cdecl HookedDwmClientStartup(void* a, void* b) {
    KEEL_INFO(L"dwm; DwmClientStartup(uDWM ord101) ENTER");
    long hr = g_realDwmClientStartup(a, b);
    KEEL_INFO(L"dwm; DwmClientStartup(uDWM ord101) -> 0x%08lX", (unsigned long)hr);
    return hr;
}

using DoStackCaptureFn = void(__cdecl*)(unsigned, long, unsigned);
DoStackCaptureFn g_realDoStackCapture = nullptr;
void __cdecl HookedDoStackCapture(unsigned skip, long hr, unsigned tag) {
    if (hr < 0) KEEL_INFO(L"dwm; uDWM failure hr=0x%08lX tag=0x%X", (unsigned long)hr, tag);
    g_realDoStackCapture(skip, hr, tag);
}

using UdwmThisCtorFn = void*(__fastcall*)(void*);
UdwmThisCtorFn g_realTopLevelWindowCtor = nullptr;
UdwmThisCtorFn g_realWindowDataCtor = nullptr;
volatile LONG g_topLevelWindowCount = 0;
volatile LONG g_windowDataCount = 0;
void* __fastcall HookedTopLevelWindowCtor(void* self) {
    LONG c = InterlockedIncrement(&g_topLevelWindowCount);
    KEEL_INFO(L"dwm; AUDIT CTopLevelWindow ctor #%ld (this=%p) window entered composition tree", c, self);
    return g_realTopLevelWindowCtor(self);
}
void* __fastcall HookedWindowDataCtor(void* self) {
    LONG c = InterlockedIncrement(&g_windowDataCount);
    KEEL_INFO(L"dwm; AUDIT CWindowData ctor #%ld (this=%p)", c, self);
    return g_realWindowDataCtor(self);
}

using ProcSyncFn  = long(__fastcall*)(void* self, int cmd, void* data, unsigned sz, bool bImm, unsigned long pid, const void* rpv, long* phr, unsigned* pcb);
using ProcAsyncFn = long(__fastcall*)(void* self, int cmd, const void* data, unsigned sz, bool bImm);
using WlVoidFn    = long(__fastcall*)(void* self);
using WlCreateFn  = long(__fastcall*)(void* self, void* idwmWindow);
ProcSyncFn  g_realProcessSyncDwm  = nullptr;
ProcAsyncFn g_realProcessAsyncDwm = nullptr;
WlVoidFn    g_realStartupBegin     = nullptr;
WlCreateFn  g_realCreateWindow     = nullptr;
volatile LONG g_syncDwmCount = 0, g_asyncDwmCount = 0, g_createWindowCount = 0;
long __fastcall HookedProcessSyncDwm(void* self, int cmd, void* data, unsigned sz, bool bImm, unsigned long pid, const void* rpv, long* phr, unsigned* pcb) {
    LONG c = InterlockedIncrement(&g_syncDwmCount);
    KEEL_INFO(L"dwm; AUDIT ProcessSyncDwmMessage #%ld cmd=%d sz=%u pid=%lu", c, cmd, sz, pid);
    return g_realProcessSyncDwm(self, cmd, data, sz, bImm, pid, rpv, phr, pcb);
}
volatile LONG g_asyncDwmLog = 700;
long __fastcall HookedProcessAsyncDwm(void* self, int cmd, const void* data, unsigned sz, bool bImm) {
    LONG c = InterlockedIncrement(&g_asyncDwmCount);

    if (InterlockedDecrement(&g_asyncDwmLog) > 0) {
        HWND hw = nullptr; wchar_t cls[48]{};
        __try {
            if (data && sz >= sizeof(void*)) {
                hw = *reinterpret_cast<HWND const*>(data);
                if (hw && IsWindow(hw)) GetClassNameW(hw, cls, 47);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { hw = nullptr; }
        KEEL_INFO(L"dwm; AUDIT ProcessAsyncDwmMessage #%ld cmd=0x%08X sz=%u hwnd=%p '%s'",
                  c, (unsigned)cmd, sz, hw, cls);
    }
    return g_realProcessAsyncDwm(self, cmd, data, sz, bImm);
}
long __fastcall HookedStartupBegin(void* self) {
    KEEL_INFO(L"dwm; AUDIT CWindowList::StartupBegin ENTER (enumerate existing windows from win32k)");
    long r = g_realStartupBegin(self);
    KEEL_INFO(L"dwm; AUDIT CWindowList::StartupBegin -> 0x%08lX (windows so far=%ld)", (unsigned long)r, g_topLevelWindowCount);
    return r;
}

WlVoidFn g_realStartupEnd = nullptr;
long __fastcall HookedStartupEnd(void* self) {
    const long r = g_realStartupEnd(self);
    KEEL_INFO(L"dwm; AUDIT CWindowList::StartupEnd -> 0x%08lX (render target enable)", (unsigned long)r);
    return r;
}
long __fastcall HookedCreateWindow(void* self, void* idw) {
    LONG c = InterlockedIncrement(&g_createWindowCount);
    KEEL_INFO(L"dwm; AUDIT CWindowList::CreateWindow #%ld (IDwmWindow=%p)", c, idw);
    return g_realCreateWindow(self, idw);
}

bool IsExplorerProcess();
void InstallDefViewProbe(HMODULE shell32);
void InstallDuiProbe(HMODULE dui70);
void InstallItemsViewProbe(HMODULE expframe);
DWORD WINAPI ThemeWatchdog(LPVOID);
void InstallShellStyleRedirect();
void InstallShellEnumProbe(HMODULE shell32);
void InstallTextInputHostStubs(HMODULE tif);

long NTAPI HookedLdrLoadDll(PWSTR path, PULONG flags, KUNICODE_STRING* name, PVOID* handle) {
    KUNICODE_STRING redirName;

    struct Redir { const wchar_t* leaf; const wchar_t* target; };

    static const Redir kWin7ShellLeaves[] = {
        { L"uxtheme.dll", L"uxtheme.dll" }, { L"explorerframe.dll", L"explorerframe.dll" },
        { L"shell32.dll", L"shell32.dll" }, { L"shlwapi.dll", L"shlwapi.dll" }, { L"propsys.dll", L"propsys.dll" } };
    if (name && name->Buffer && name->Length) {
        int n = name->Length / 2; wchar_t lo[MAX_PATH] = {};
        if (n > 0 && n < MAX_PATH) {
            for (int i = 0; i < n; ++i) lo[i] = (wchar_t)towlower(name->Buffer[i]);
            if (!wcsstr(lo, L"\\keel\\")) {
                static wchar_t r[MAX_PATH * 8]; static volatile LONG rslot = 0;
                const wchar_t* bs = wcsrchr(lo, L'\\'); const wchar_t* leafIn = bs ? bs + 1 : lo;
                for (const Redir& rd : kWin7ShellLeaves) {
                    if (!wcscmp(leafIn, rd.leaf)) {
                        wchar_t* rb = r + (MAX_PATH * (InterlockedIncrement(&rslot) & 7));
                        wsprintfW(rb, L"C:\\Keel\\rtm\\%s", rd.target);
                        if (GetFileAttributesW(rb) != INVALID_FILE_ATTRIBUTES) {
                            redirName.Buffer = rb; redirName.Length = (USHORT)(wcslen(rb) * 2); redirName.MaximumLength = redirName.Length + 2;
                            name = &redirName; path = nullptr;
                            KEEL_INFO(L"shell; LdrLoadDll redirect %s -> %s", lo, rb);
                        }
                        break;
                    }
                }
            }
        }
    }
    long st = g_realLdrLoadDll(path, flags, name, handle);
    if (st >= 0 && handle && *handle && name && name->Buffer) {
        int n = name->Length / 2; wchar_t buf[300] = {};
        if (n > 290) n = 290;
        for (int i = 0; i < n; ++i) buf[i] = (wchar_t)towlower(name->Buffer[i]);
        if (wcsstr(buf, L"uxtheme")) InstallThemeBridge((HMODULE)*handle);
        if (wcsstr(buf, L"shell32") && IsExplorerProcess()) { InstallDefViewProbe((HMODULE)*handle); InstallShellEnumProbe((HMODULE)*handle); }
        if (wcsstr(buf, L"explorerframe") && IsExplorerProcess()) InstallItemsViewProbe((HMODULE)*handle);
        if (wcsstr(buf, L"dui70") && IsExplorerProcess()) InstallDuiProbe((HMODULE)*handle);
        if (wcsstr(buf, L"textinput") && IsExplorerProcess()) InstallTextInputHostStubs((HMODULE)*handle);
        if (wcsstr(buf, L"dwmredir")) InstallDwmRedirTrace((HMODULE)*handle);
        if (wcsstr(buf, L"dwmredir") || wcsstr(buf, L"dwmcore")) InstallMilFailureTrace();
        if (!g_realDwmClientStartup && wcsstr(buf, L"udwm")) {

            PatchReturnTrue((PBYTE)*handle + 0x7be0, L"uDWM!CDesktopManager::IsFeatureEnabled");
            FARPROC p = GetProcAddress((HMODULE)*handle, MAKEINTRESOURCEA(101));
            if (p) {
                g_realDwmClientStartup = (DwmStartupFn)p;
                g_realTopLevelWindowCtor = reinterpret_cast<UdwmThisCtorFn>((PBYTE)*handle + 0x10a58);
                g_realWindowDataCtor     = reinterpret_cast<UdwmThisCtorFn>((PBYTE)*handle + 0x6c10);
                g_realProcessSyncDwm     = reinterpret_cast<ProcSyncFn>((PBYTE)*handle + 0x1c050);
                g_realProcessAsyncDwm    = reinterpret_cast<ProcAsyncFn>((PBYTE)*handle + 0x6400);
                g_realStartupBegin       = reinterpret_cast<WlVoidFn>((PBYTE)*handle + 0x19c4c);
                g_realCreateWindow       = reinterpret_cast<WlCreateFn>((PBYTE)*handle + 0x3a240);
                g_realStartupEnd         = reinterpret_cast<WlVoidFn>((PBYTE)*handle + 0x16668);
                DetourTransactionBegin();
                DetourAttach(reinterpret_cast<PVOID*>(&g_realStartupEnd), reinterpret_cast<PVOID>(HookedStartupEnd));
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(reinterpret_cast<PVOID*>(&g_realDwmClientStartup), reinterpret_cast<PVOID>(HookedDwmClientStartup));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realTopLevelWindowCtor), reinterpret_cast<PVOID>(HookedTopLevelWindowCtor));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realWindowDataCtor), reinterpret_cast<PVOID>(HookedWindowDataCtor));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realProcessSyncDwm), reinterpret_cast<PVOID>(HookedProcessSyncDwm));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realProcessAsyncDwm), reinterpret_cast<PVOID>(HookedProcessAsyncDwm));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realStartupBegin), reinterpret_cast<PVOID>(HookedStartupBegin));
                DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateWindow), reinterpret_cast<PVOID>(HookedCreateWindow));
                LONG e = DetourTransactionCommit();
                KEEL_INFO(L"dwm; uDWM loaded and hooked ord101 DwmClientStartup @ %p + AUDIT CTopLevelWindow & CWindowData ctors (commit=%ld)", p, e);
            } else {
                KEEL_INFO(L"dwm; uDWM loaded but ord101 not resolved");
            }
        }
    }
    return st;
}

using KmtFn = long(NTAPI*)(void*);

#define KMT_HOOK(shortname) \
    KmtFn g_realKmt_##shortname = nullptr; \
    volatile LONG g_kmtN_##shortname = 0; \
    volatile LONG g_kmtLast_##shortname = 0x7fffffff; \
    long NTAPI HookedKmt_##shortname(void* a){ long s = g_realKmt_##shortname(a); \
        const LONG n = InterlockedIncrement(&g_kmtN_##shortname); \
        if (n <= 8 || InterlockedExchange(&g_kmtLast_##shortname, s) != s) \
            KEEL_INFO(L"dwm; D3DKMT" L#shortname " -> 0x%08lX (call %ld)", (unsigned long)s, n); \
        return s; }

KMT_HOOK(CreateDevice)
KMT_HOOK(OpenAdapterFromHdc)
KMT_HOOK(OpenAdapterFromGdiDisplayName)
KMT_HOOK(OpenAdapterFromLuid)
KMT_HOOK(CreateContext)
KMT_HOOK(CreateContextVirtual)
KMT_HOOK(CreateAllocation)
KMT_HOOK(CreateAllocation2)
KMT_HOOK(QueryAdapterInfo)
KMT_HOOK(Escape)
KMT_HOOK(GetDeviceState)
KMT_HOOK(CreateSynchronizationObject)
KMT_HOOK(CreateSynchronizationObject2)
KMT_HOOK(MakeResident)
KMT_HOOK(MapGpuVirtualAddress)
KMT_HOOK(ReserveGpuVirtualAddress)
KMT_HOOK(CreateOverlay)
KMT_HOOK(OpenResource)
KMT_HOOK(SetDisplayMode)
KMT_HOOK(Present)
KMT_HOOK(SetVidPnSourceOwner)
KMT_HOOK(CheckExclusiveOwnership)
KMT_HOOK(GetPresentHistory)

KmtFn g_realKmt_SetVidPnSourceOwner1 = nullptr;
long NTAPI HookedKmt_SetVidPnSourceOwner1(void* a) {
    long s = g_realKmt_SetVidPnSourceOwner1(a);
    unsigned dev = a ? *(unsigned*)a : 0;
    unsigned cnt = a ? *(unsigned*)((char*)a + 0x18) : 0;
    int* pType = a ? *(int**)((char*)a + 0x08) : nullptr;
    unsigned* pSrc = a ? *(unsigned**)((char*)a + 0x10) : nullptr;
    int ownerType = pType ? pType[0] : -1;
    unsigned srcId = pSrc ? pSrc[0] : 0xFFFFFFFF;
    KEEL_INFO(L"dwm; D3DKMTSetVidPnSourceOwner1(hDev=0x%X cnt=%u ownerType=%d srcId=%u) -> 0x%08lX",
              dev, cnt, ownerType, srcId, (unsigned long)s);
    return s;
}

#define KMT_ENT(shortname) { "D3DKMT" #shortname, &g_realKmt_##shortname, (PVOID)HookedKmt_##shortname }

void AttachKmtHooks() {
    HMODULE g = GetModuleHandleW(L"gdi32.dll");
    if (!g) g = LoadLibraryW(L"gdi32.dll");
    struct { const char* name; KmtFn* real; PVOID hook; } k[] = {
        KMT_ENT(CreateDevice), KMT_ENT(OpenAdapterFromHdc), KMT_ENT(OpenAdapterFromGdiDisplayName),
        KMT_ENT(OpenAdapterFromLuid), KMT_ENT(CreateContext), KMT_ENT(CreateContextVirtual),
        KMT_ENT(CreateAllocation), KMT_ENT(CreateAllocation2), KMT_ENT(QueryAdapterInfo),
        KMT_ENT(Escape), KMT_ENT(GetDeviceState), KMT_ENT(CreateSynchronizationObject),
        KMT_ENT(CreateSynchronizationObject2), KMT_ENT(MakeResident), KMT_ENT(MapGpuVirtualAddress),
        KMT_ENT(ReserveGpuVirtualAddress), KMT_ENT(CreateOverlay), KMT_ENT(OpenResource),
        KMT_ENT(SetDisplayMode), KMT_ENT(Present), KMT_ENT(SetVidPnSourceOwner),
        KMT_ENT(SetVidPnSourceOwner1), KMT_ENT(CheckExclusiveOwnership), KMT_ENT(GetPresentHistory),
    };
    for (auto& e : k) {
        *e.real = (KmtFn)GetProcAddress(g, e.name);
        if (*e.real) DetourAttach(reinterpret_cast<PVOID*>(e.real), e.hook);

    }
}

using DwmInitTransportFn = long(WINAPI*)(void*, void*);
using MilCreateChannelFn = long(WINAPI*)(void*, void*, void*);
using MilHandleSfmFn      = long(WINAPI*)(void*, void*);
using DwmStartRedirFn     = int(WINAPI*)(int);
using DwmLockAllocFn      = long(WINAPI*)(int);
DwmInitTransportFn g_realDwmInitTransport = nullptr;
MilCreateChannelFn g_realMilCreateChannel = nullptr;
MilHandleSfmFn     g_realMilHandleSfm = nullptr;
DwmStartRedirFn    g_realDwmStartRedir = nullptr;
DwmLockAllocFn     g_realDwmLockAlloc = nullptr;

int WINAPI HookedDwmStartRedir(int a){
    SetLastError(0);
    int r = g_realDwmStartRedir(a);
    KEEL_INFO(L"dwm; DwmStartRedirection(%d) -> %d (GetLastError=%lu)", a, r, GetLastError());
    return r;
}
long WINAPI HookedDwmLockAlloc(int a){
    long s = g_realDwmLockAlloc(a);
    KEEL_INFO(L"dwm; DwmRedirectionManagerLockMemoryAllocations(%d) -> 0x%08lX", a, (unsigned long)s);
    return s;
}

long WINAPI HookedDwmInitTransport(void* a, void* b){
    long s = g_realDwmInitTransport(a, b);
    KEEL_INFO(L"dwm; DwmInitializeTransport -> 0x%08lX", (unsigned long)s);
    return s;
}
long WINAPI HookedMilCreateChannel(void* a, void* b, void* c){
    long s = g_realMilCreateChannel(a, b, c);
    KEEL_INFO(L"dwm; MilConnection_CreateChannel -> 0x%08lX", (unsigned long)s);
    return s;
}
long WINAPI HookedMilHandleSfm(void* a, void* b){
    long s = g_realMilHandleSfm(a, b);
    KEEL_INFO(L"dwm; MilConnection_HandleSfmEventOnPartition -> 0x%08lX", (unsigned long)s);
    return s;
}

using Mil6Fn = long(WINAPI*)(void*, void*, void*, void*, void*, void*);
#define MIL_HOOK(name) \
    Mil6Fn g_realMil_##name = nullptr; \
    long WINAPI HookedMil_##name(void* a, void* b, void* c, void* d, void* e, void* f){ \
        long s = g_realMil_##name(a,b,c,d,e,f); \
        KEEL_INFO(L"dwm; " L#name " -> 0x%08lX", (unsigned long)s); return s; }
MIL_HOOK(MilResource_CreateOrAddRefOnChannel)
MIL_HOOK(MilResource_SendCommand)
MIL_HOOK(MilResource_SendCommandBitmapSource)
MIL_HOOK(MilChannel_CommitChannel)
MIL_HOOK(MilChannel_SendSyncCommand)
MIL_HOOK(MilComposition_WaitForNextMessage)
MIL_HOOK(MilComposition_PeekNextMessage)
MIL_HOOK(MilComposition_SyncFlush)
MIL_HOOK(MilChannel_GetMarshalType)
MIL_HOOK(MilCompositionEngine_InitializePartitionManager)
MIL_HOOK(MilVisualTarget_AttachToHwnd)
MIL_HOOK(DwmRedirectionManagerInitialize)
#define MIL_ATT(name) do { void* p = (void*)GetProcAddress(core, #name); \
    if (p) { g_realMil_##name = (Mil6Fn)p; DetourAttach(reinterpret_cast<PVOID*>(&g_realMil_##name), (PVOID)HookedMil_##name); } } while(0)

void AttachMilTraceHooks(HMODULE core) {
    if (!core) return;
    MIL_ATT(MilResource_CreateOrAddRefOnChannel);
    MIL_ATT(MilResource_SendCommand);
    MIL_ATT(MilResource_SendCommandBitmapSource);
    MIL_ATT(MilChannel_CommitChannel);
    MIL_ATT(MilChannel_SendSyncCommand);
    MIL_ATT(MilComposition_WaitForNextMessage);
    MIL_ATT(MilComposition_PeekNextMessage);
    MIL_ATT(MilComposition_SyncFlush);
    MIL_ATT(MilChannel_GetMarshalType);
    MIL_ATT(MilCompositionEngine_InitializePartitionManager);
    MIL_ATT(MilVisualTarget_AttachToHwnd);
    HMODULE redir = GetModuleHandleW(L"dwmredir.dll");
    if (redir) { void* p = (void*)GetProcAddress(redir, "DwmRedirectionManagerInitialize");
        if (p) { g_realMil_DwmRedirectionManagerInitialize = (Mil6Fn)p;
                 DetourAttach(reinterpret_cast<PVOID*>(&g_realMil_DwmRedirectionManagerInitialize), (PVOID)HookedMil_DwmRedirectionManagerInitialize); } }
}

void AttachTransportHooks() {
    HMODULE redir = GetModuleHandleW(L"dwmredir.dll");
    HMODULE core  = GetModuleHandleW(L"dwmcore.dll");
    if (redir) {
        g_realDwmInitTransport = (DwmInitTransportFn)GetProcAddress(redir, "DwmInitializeTransport");
        if (g_realDwmInitTransport) DetourAttach(reinterpret_cast<PVOID*>(&g_realDwmInitTransport), (PVOID)HookedDwmInitTransport);
        else KEEL_INFO(L"dwm; DwmInitializeTransport not exported by dwmredir");
    } else KEEL_INFO(L"dwm; dwmredir.dll not loaded yet");
    if (core) {
        g_realMilCreateChannel = (MilCreateChannelFn)GetProcAddress(core, "MilConnection_CreateChannel");
        if (g_realMilCreateChannel) DetourAttach(reinterpret_cast<PVOID*>(&g_realMilCreateChannel), (PVOID)HookedMilCreateChannel);
        else KEEL_INFO(L"dwm; MilConnection_CreateChannel not exported by dwmcore");
        g_realMilHandleSfm = (MilHandleSfmFn)GetProcAddress(core, "MilConnection_HandleSfmEventOnPartition");
        if (g_realMilHandleSfm) DetourAttach(reinterpret_cast<PVOID*>(&g_realMilHandleSfm), (PVOID)HookedMilHandleSfm);
        else KEEL_INFO(L"dwm; MilConnection_HandleSfmEventOnPartition not exported by dwmcore");
    } else KEEL_INFO(L"dwm; dwmcore.dll not loaded yet");

    if (redir) {
        g_realDwmLockAlloc = (DwmLockAllocFn)GetProcAddress(redir, "DwmRedirectionManagerLockMemoryAllocations");
        if (g_realDwmLockAlloc) DetourAttach(reinterpret_cast<PVOID*>(&g_realDwmLockAlloc), (PVOID)HookedDwmLockAlloc);
        else KEEL_INFO(L"dwm; DwmRedirectionManagerLockMemoryAllocations not exported by dwmredir");
    }

    const wchar_t* mods[] = { L"user32.dll", L"win32u.dll", L"gdi32.dll", L"dwmredir.dll" };
    for (auto m : mods) {
        HMODULE h = GetModuleHandleW(m); if (!h) continue;
        FARPROC p = GetProcAddress(h, "DwmStartRedirection");
        if (p) { g_realDwmStartRedir = (DwmStartRedirFn)p;
                 DetourAttach(reinterpret_cast<PVOID*>(&g_realDwmStartRedir), (PVOID)HookedDwmStartRedir);
                 KEEL_INFO(L"dwm; hooked DwmStartRedirection in %s", m); break; }
    }
    if (!g_realDwmStartRedir) KEEL_INFO(L"dwm; DwmStartRedirection not found in user32/win32u/gdi32/dwmredir");
}

using GetDeviceCapsFn = int(WINAPI*)(HDC, int);
GetDeviceCapsFn g_realGetDeviceCaps = nullptr;
int WINAPI HookedGetDeviceCaps(HDC hdc, int index) {
    // dwmcore samples LOGPIXELS once and scales the whole composition by it, and 96 leaves the shell its real DPI
    if (index == LOGPIXELSX || index == LOGPIXELSY) return 96;
    return g_realGetDeviceCaps(hdc, index);
}

bool IsDwmProcess() {
    wchar_t p[MAX_PATH]{};
    GetModuleFileNameW(nullptr, p, MAX_PATH);
    for (wchar_t* s = p; *s; ++s) *s = (wchar_t)towlower(*s);
    return wcsstr(p, L"keeldwm.exe") || wcsstr(p, L"\\dwm.exe");
}

using CoCreateInstanceFn   = long(WINAPI*)(const GUID*, void*, DWORD, const GUID*, void**);
using CoCreateInstanceExFn = long(WINAPI*)(const GUID*, void*, DWORD, void*, DWORD, void*);
using CoGetClassObjectFn   = long(WINAPI*)(const GUID*, DWORD, void*, const GUID*, void**);
using RtlExitUserProcessFn = void(NTAPI*)(ULONG);
using MessageBoxWFn        = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
CoCreateInstanceFn   g_realCoCreateInstance = nullptr;
CoCreateInstanceExFn g_realCoCreateInstanceEx = nullptr;
CoGetClassObjectFn   g_realCoGetClassObject = nullptr;
RtlExitUserProcessFn g_realRtlExitUserProcess = nullptr;
MessageBoxWFn        g_realMessageBoxW = nullptr;

void GuidStr(const GUID* g, wchar_t out[40]) {
    if (!g) { wcscpy_s(out, 40, L"NULL"); return; }
    wsprintfW(out, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

bool g_comLogAll = false;
volatile LONG g_comFailLog = 150;
void FormatAddr(PVOID a, wchar_t* out, size_t cch);
void LogClsid(const wchar_t* tag, const GUID* c, const GUID* iid, long hr, PVOID ra) {
    if (hr >= 0 && !g_comLogAll) return;
    if (hr < 0 && InterlockedDecrement(&g_comFailLog) <= 0) return;
    wchar_t cs[40], is[40], who[80]; GuidStr(c, cs); GuidStr(iid, is); FormatAddr(ra, who, 80);
    if (hr < 0) KEEL_WARN(L"%s clsid=%s iid=%s hr=0x%08lX from %s", tag, cs, is, (unsigned long)hr, who);
    else        KEEL_INFO(L"%s clsid=%s iid=%s hr=0x%08lX from %s", tag, cs, is, (unsigned long)hr, who);
}

void* GetRtmClassObject(const GUID* clsid, const GUID* iid, void* outer) {
    HMODULE mods[256]; DWORD cb = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)) return nullptr;
    const DWORD n = cb / sizeof(HMODULE);
    for (DWORD k = 0; k < n; ++k) {
        wchar_t path[MAX_PATH]{};
        if (!GetModuleFileNameW(mods[k], path, MAX_PATH)) continue;
        if (_wcsnicmp(path, L"C:\\Keel\\rtm\\", 12) != 0) continue;
        using DllGetClassObjectFn = long(__stdcall*)(const GUID*, const GUID*, void**);
        auto dgco = reinterpret_cast<DllGetClassObjectFn>(GetProcAddress(mods[k], "DllGetClassObject"));
        if (!dgco) continue;
        IClassFactory* cf = nullptr;
        if (dgco(clsid, &IID_IClassFactory, reinterpret_cast<void**>(&cf)) != 0 || !cf) continue;
        void* obj = nullptr;
        const long chr = cf->CreateInstance(reinterpret_cast<IUnknown*>(outer), *iid, &obj);
        cf->Release();
        if (chr == 0 && obj) {
            const wchar_t* leaf = wcsrchr(path, L'\\'); leaf = leaf ? leaf + 1 : path;
            KEEL_INFO(L"com; served class from Win7 %s (registry pointed at a surrogate or Win10 server)", leaf);
            return obj;
        }
    }
    return nullptr;
}

// COpenControlPanel has AppID DllSurrogate set, so COM would activate it in dllhost against Win10 shell32
bool MustServeFromRtm(const GUID* c) {
    static const GUID kOpenControlPanel =
        { 0x06622D85, 0x6856, 0x4460, { 0x8D, 0xE1, 0xA8, 0x19, 0x21, 0xB4, 0x1C, 0x4B } };
    return c && memcmp(c, &kOpenControlPanel, sizeof(GUID)) == 0;
}
volatile LONG g_preServeLog = 8;
long WINAPI HookedCoCreateInstance(const GUID* c, void* o, DWORD x, const GUID* i, void** p) {
    if (c && i && p && MustServeFromRtm(c) && IsExplorerProcess()) {
        if (void* obj = GetRtmClassObject(c, i, o)) {
            if (InterlockedDecrement(&g_preServeLog) > 0)
                KEEL_INFO(L"com; pre-served COpenControlPanel from the Win7 shell32 (surrogate bypassed)");
            *p = obj;
            return 0;
        }
    }
    long hr = g_realCoCreateInstance(c, o, x, i, p);
    if ((hr == (long)0x80040154 || hr == (long)0x80040111) && c && i && p) {
        if (void* obj = GetRtmClassObject(c, i, o)) { *p = obj; return 0; }
    }
    LogClsid(L"com; CoCreateInstance", c, i, hr, _ReturnAddress()); return hr; }
long WINAPI HookedCoCreateInstanceEx(const GUID* c, void* o, DWORD x, void* si, DWORD n, void* r) {
    long hr = g_realCoCreateInstanceEx(c, o, x, si, n, r); LogClsid(L"com; CoCreateInstanceEx", c, nullptr, hr, _ReturnAddress()); return hr; }
long WINAPI HookedCoGetClassObject(const GUID* c, DWORD x, void* inf, const GUID* i, void** p) {
    long hr = g_realCoGetClassObject(c, x, inf, i, p); LogClsid(L"com; CoGetClassObject", c, i, hr, _ReturnAddress()); return hr; }
int WINAPI HookedMessageBoxW(HWND h, LPCWSTR t, LPCWSTR c, UINT ty) {
    KEEL_INFO(L"ui; MessageBoxW cap='%s' text='%s'", c ? c : L"", t ? t : L""); return g_realMessageBoxW(h, t, c, ty); }
void NTAPI HookedRtlExitUserProcess(ULONG code) {
    void* bt[16]; USHORT n = RtlCaptureStackBackTrace(1, 16, bt, nullptr);
    KEEL_INFO(L"proc; RtlExitUserProcess code=0x%lX", code);
    for (USHORT k = 0; k < n; ++k) {
        HMODULE m = nullptr; wchar_t nm[48] = L"?";
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)bt[k], &m) && m) {
            wchar_t pth[MAX_PATH]; GetModuleFileNameW(m, pth, MAX_PATH);
            const wchar_t* b = wcsrchr(pth, L'\\'); lstrcpynW(nm, b ? b + 1 : pth, 47);
            KEEL_INFO(L"  #%u %s+0x%llX", k, nm, (unsigned long long)((PBYTE)bt[k] - (PBYTE)m));
        } else KEEL_INFO(L"  #%u %p", k, bt[k]);
    }
    g_realRtlExitUserProcess(code);
}

using CreateWindowExWFn = HWND(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
CreateWindowExWFn g_realCreateWindowExW = nullptr;
HWND WINAPI HookedCreateWindowExW(DWORD ex, LPCWSTR cls, LPCWSTR wn, DWORD st, int x, int y, int cw, int ch, HWND par, HMENU mn, HINSTANCE hi, LPVOID pp) {
    HWND h = g_realCreateWindowExW(ex, cls, wn, st, x, y, cw, ch, par, mn, hi, pp);

    if (!h && cls && ((ULONG_PTR)cls >> 16))
        KEEL_INFO(L"shell; CreateWindowExW class='%s' -> NULL err=%lu", cls, GetLastError());
    return h;
}

using SPIWFn = BOOL(WINAPI*)(UINT, UINT, PVOID, UINT);
SPIWFn g_realSPIW = nullptr;
SPIWFn g_realSPIA = nullptr;

struct GpStartupInput { UINT32 version; void* cb; BOOL noThread; BOOL noCodecEnum; };
using GdiplusStartupFn  = int(WINAPI*)(ULONG_PTR*, const GpStartupInput*, void*);
using GdipCreateBmpFn   = int(WINAPI*)(const WCHAR*, void**);
using GdipGetWidthFn    = int(WINAPI*)(void*, UINT*);
using GdipGetHeightFn   = int(WINAPI*)(void*, UINT*);
using GdipCreateBmpIntFn= int(WINAPI*)(INT, INT, INT, INT, BYTE*, void**);
using GdipGetImgGfxFn   = int(WINAPI*)(void*, void**);
using GdipSetInterpFn   = int(WINAPI*)(void*, INT);
using GdipDrawImageRFn  = int(WINAPI*)(void*, void*, float, float, float, float);
using GdipSaveFn        = int(WINAPI*)(void*, const WCHAR*, const CLSID*, const void*);
using GdipDisposeImgFn  = int(WINAPI*)(void*);
using GdipDeleteGfxFn   = int(WINAPI*)(void*);

bool TranscodeWallpaperToBmp(const wchar_t* src, wchar_t* out, size_t cchOut) {
    HMODULE gp = LoadLibraryW(L"gdiplus.dll");
    if (!gp) { KEEL_WARN(L"wallpaper; gdiplus.dll unavailable"); return false; }
    auto pStartup = (GdiplusStartupFn)GetProcAddress(gp, "GdiplusStartup");
    auto pFromFile= (GdipCreateBmpFn)GetProcAddress(gp, "GdipCreateBitmapFromFile");
    auto pW       = (GdipGetWidthFn)GetProcAddress(gp, "GdipGetImageWidth");
    auto pH       = (GdipGetHeightFn)GetProcAddress(gp, "GdipGetImageHeight");
    auto pNew     = (GdipCreateBmpIntFn)GetProcAddress(gp, "GdipCreateBitmapFromScan0");
    auto pGfx     = (GdipGetImgGfxFn)GetProcAddress(gp, "GdipGetImageGraphicsContext");
    auto pInterp  = (GdipSetInterpFn)GetProcAddress(gp, "GdipSetInterpolationMode");
    auto pDraw    = (GdipDrawImageRFn)GetProcAddress(gp, "GdipDrawImageRect");
    auto pSave    = (GdipSaveFn)GetProcAddress(gp, "GdipSaveImageToFile");
    auto pDisp    = (GdipDisposeImgFn)GetProcAddress(gp, "GdipDisposeImage");
    auto pDelGfx  = (GdipDeleteGfxFn)GetProcAddress(gp, "GdipDeleteGraphics");
    if (!pStartup || !pFromFile || !pW || !pH || !pNew || !pGfx || !pDraw || !pSave || !pDisp) {
        KEEL_WARN(L"wallpaper; gdiplus entry points missing");
        return false;
    }
    ULONG_PTR tok = 0; GpStartupInput si{ 1, nullptr, FALSE, FALSE };
    if (pStartup(&tok, &si, nullptr) != 0) { KEEL_WARN(L"wallpaper; GdiplusStartup failed"); return false; }

    bool ok = false;
    void* img = nullptr;
    if (pFromFile(src, &img) == 0 && img) {
        UINT iw = 0, ih = 0; pW(img, &iw); pH(img, &ih);

        const int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
        void* dst = nullptr;

        if (pNew(cx, cy, 0, 0x26200A, nullptr, &dst) == 0 && dst) {
            void* gfx = nullptr;
            if (pGfx(dst, &gfx) == 0 && gfx) {
                if (pInterp) pInterp(gfx, 7);
                pDraw(gfx, img, 0.0f, 0.0f, (float)cx, (float)cy);
                pDelGfx(gfx);
            }

            static const CLSID kBmpEnc =
                { 0x557cf400, 0x1a04, 0x11d3, { 0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e } };
            swprintf_s(out, cchOut, L"C:\\Keel\\shell\\wallpaper-cache.bmp");
            CreateDirectoryW(L"C:\\Keel\\shell", nullptr);
            ok = (pSave(dst, out, &kBmpEnc, nullptr) == 0);
            KEEL_INFO(L"wallpaper; transcoded '%s' (%ux%u) -> '%s' %dx%d ok=%d",
                      src, iw, ih, out, cx, cy, ok);
            pDisp(dst);
        }
        pDisp(img);
    } else {
        KEEL_WARN(L"wallpaper; gdiplus could not decode '%s'", src);
    }

    return ok;
}

constexpr DWORD kShell32PaintWallpaperCmp = 0x1fcf1;
void PatchShellPaintWallpaper(HMODULE sh) {
    BYTE* p = reinterpret_cast<BYTE*>(sh) + kShell32PaintWallpaperCmp;
    static const BYTE expect[5] = { 0x83, 0xF8, 0x03, 0x0F, 0x84 };
    if (memcmp(p, expect, 5) != 0) {
        KEEL_WARN(L"shell; PaintWallpaper bytes at +0x%lX are %02X %02X %02X %02X %02X not the 7601.23403 "
                  L"pattern so not patching", kShell32PaintWallpaperCmp, p[0], p[1], p[2], p[3], p[4]);
        return;
    }
    DWORD old = 0;
    if (!VirtualProtect(p, 8, PAGE_EXECUTE_READWRITE, &old)) {
        KEEL_WARN(L"shell; VirtualProtect for PaintWallpaper patch failed %lu", GetLastError());
        return;
    }
    p[2] = 0xFF;
    VirtualProtect(p, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 8);
    KEEL_INFO(L"shell; patched CDesktopBrowser::PaintWallpaper (shell32+0x%lX) OBJ_DC compare -> never and "
              L"real DCs use the shell's own PaintMonitor path", kShell32PaintWallpaperCmp);
}
DWORD WINAPI ShellPatchThread(LPVOID) {

    wchar_t v[8]{};
    if (!(GetEnvironmentVariableW(L"KEEL_SHELLPATCH", v, 8) > 0 && v[0] == L'1')) {
        KEEL_INFO(L"shell; PaintWallpaper byte patch not applied (opt-in via KEEL_SHELLPATCH=1)");
        return 0;
    }
    for (int i = 0; i < 30; ++i) {
        if (HMODULE sh = GetModuleHandleW(L"C:\\Keel\\rtm\\shell32.dll")) { PatchShellPaintWallpaper(sh); return 0; }
        Sleep(1000);
    }
    KEEL_WARN(L"shell; C:\\Keel\\rtm\\shell32.dll never appeared so PaintWallpaper not patched");
    return 0;
}

bool PathIsBmp(const wchar_t* p);

volatile LONG g_paintDeskLog = 250;
volatile LONG g_paintDeskCalls = 0;
using PaintDesktopFn = BOOL(WINAPI*)(HDC);
PaintDesktopFn g_realPaintDesktop = nullptr;
HBITMAP g_wallBmp = nullptr;
LONG    g_wallCx = 0, g_wallCy = 0;
volatile LONG g_wallGen = 0;

void InvalidateDesktopWallpaper() {

    auto zap = [](HWND h, const wchar_t* what) {
        if (!h) return;
        const BOOL a = InvalidateRect(h, nullptr, TRUE);
        const BOOL b = RedrawWindow(h, nullptr, nullptr,
                                    RDW_INVALIDATE | RDW_ERASE | RDW_FRAME |
                                    RDW_ALLCHILDREN | RDW_ERASENOW | RDW_UPDATENOW);
        wchar_t cls[48]{}; GetClassNameW(h, cls, 47);
        KEEL_INFO(L"wallpaper; invalidate %s hwnd=%p '%s' inv=%d rdw=%d", what, h, cls, a, b);
    };
    zap(GetDesktopWindow(), L"desktop(#32769)");
    static const wchar_t* const kTop[2] = { L"Progman", L"WorkerW" };
    for (const wchar_t* c : kTop) {
        for (HWND top = FindWindowExW(nullptr, nullptr, c, nullptr); top;
             top = FindWindowExW(nullptr, top, c, nullptr)) {
            zap(top, L"top");
            HWND dv = FindWindowExW(top, nullptr, L"SHELLDLL_DefView", nullptr);
            if (!dv) continue;
            zap(dv, L"defview");
            zap(FindWindowExW(dv, nullptr, L"SysListView32", nullptr), L"listview");
        }
    }
}

void DropWallpaperCache() {
    if (HBITMAP old = reinterpret_cast<HBITMAP>(InterlockedExchangePointer(
            reinterpret_cast<PVOID*>(&g_wallBmp), nullptr)))
        DeleteObject(old);
}

volatile LONG g_wallSrcLog = 6;
wchar_t g_wallKeyPath[MAX_PATH]{};
FILETIME g_wallKeyTime{};
DWORD g_wallCheckedTick = 0;
bool EnsureWallpaperBitmap() {

    const DWORD now = GetTickCount();
    if (g_wallBmp && now - g_wallCheckedTick < 1000) return true;
    g_wallCheckedTick = now;
    wchar_t path[MAX_PATH]{}; DWORD cb = sizeof(path);
    const wchar_t* source = L"HKCU";
    HKEY k{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"Wallpaper", nullptr, nullptr, reinterpret_cast<LPBYTE>(path), &cb) != ERROR_SUCCESS)
            path[0] = 0;
        RegCloseKey(k);
    }
    if (!path[0]) {
        source = L"SPI_GETDESKWALLPAPER";
        SPIWFn spi = g_realSPIW ? g_realSPIW
                                : reinterpret_cast<SPIWFn>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "SystemParametersInfoW"));
        if (!spi || !spi(SPI_GETDESKWALLPAPER, MAX_PATH, path, 0)) path[0] = 0;

        if (!_wcsicmp(path, L"(None)")) path[0] = 0;
    }
    if (!path[0] && GetFileAttributesW(L"C:\\Keel\\shell\\wallpaper-cache.bmp") != INVALID_FILE_ATTRIBUTES) {
        source = L"shell transcode cache";
        wcscpy_s(path, L"C:\\Keel\\shell\\wallpaper-cache.bmp");
    }
    if (!path[0]) {
        if (InterlockedDecrement(&g_wallSrcLog) > 0) KEEL_INFO(L"wallpaper; no wallpaper path from any source yet");
        return false;
    }

    WIN32_FILE_ATTRIBUTE_DATA fa{};
    const bool haveTime = GetFileAttributesExW(path, GetFileExInfoStandard, &fa) != 0;
    if (g_wallBmp) {
        if (!_wcsicmp(path, g_wallKeyPath) && haveTime &&
            CompareFileTime(&fa.ftLastWriteTime, &g_wallKeyTime) == 0)
            return true;
        DropWallpaperCache();
    }
    if (InterlockedDecrement(&g_wallSrcLog) > 0)
        KEEL_INFO(L"wallpaper; path via %s = '%s'", source, path);

    wchar_t bmp[MAX_PATH]{};
    if (PathIsBmp(path)) wcscpy_s(bmp, path);
    else if (!TranscodeWallpaperToBmp(path, bmp, MAX_PATH)) return false;
    wcscpy_s(g_wallKeyPath, path);
    g_wallKeyTime = haveTime ? fa.ftLastWriteTime : FILETIME{};
    const int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
    HANDLE h = LoadImageW(nullptr, bmp, IMAGE_BITMAP, cx, cy, LR_LOADFROMFILE | LR_CREATEDIBSECTION);
    if (!h) { KEEL_WARN(L"wallpaper; LoadImage('%s') failed err=%lu", bmp, GetLastError()); return false; }
    g_wallBmp = reinterpret_cast<HBITMAP>(h);
    g_wallCx = cx; g_wallCy = cy;
    KEEL_INFO(L"wallpaper; cached '%s' as %dx%d for PaintDesktop", bmp, cx, cy);
    return true;
}

bool WallProbeEnabled() {
    static int cached = -1;
    if (cached < 0) {
        wchar_t v[8]{};
        cached = (GetEnvironmentVariableW(L"KEEL_WALLPROBE", v, 8) > 0 && v[0] == L'1') ? 1 : 0;
    }
    return cached == 1;
}

using PaintMonitorFn = BOOL(WINAPI*)(HMONITOR, HDC, const RECT*);
PaintMonitorFn g_realPaintMonitor = nullptr;
volatile LONG g_paintMonLog = 40;
BOOL WINAPI HookedPaintMonitor(HMONITOR hmon, HDC hdc, const RECT* rc) {
    const BOOL r = g_realPaintMonitor(hmon, hdc, rc);
    bool blitted = false;
    if (rc && EnsureWallpaperBitmap()) {
        if (HDC mem = CreateCompatibleDC(hdc)) {
            HGDIOBJ old = SelectObject(mem, g_wallBmp);
            const int w = rc->right - rc->left, h = rc->bottom - rc->top;
            if (w > 0 && h > 0)
                blitted = BitBlt(hdc, rc->left, rc->top, w, h, mem, rc->left, rc->top, SRCCOPY) != 0;
            SelectObject(mem, old);
            DeleteDC(mem);
        }
    }
    if (InterlockedDecrement(&g_paintMonLog) > 0)
        KEEL_INFO(L"wallpaper; PaintMonitor(hdc=%p rc=(%ld,%ld,%ld,%ld)) real=%d blitted=%d",
                  hdc, rc ? rc->left : 0, rc ? rc->top : 0, rc ? rc->right : 0, rc ? rc->bottom : 0, r, blitted);
    return r;
}

using NtUserPaintDesktopFn = BOOL(NTAPI*)(HDC);
NtUserPaintDesktopFn g_ntUserPaintDesktop = nullptr;

// Win10 PaintDesktop messages the shell, which repaints, which loops, so this uses the win32u stub with the Win7 semantics
BOOL WINAPI HookedPaintDesktop(HDC hdc) {
    if (!g_ntUserPaintDesktop) {
        HMODULE w = GetModuleHandleW(L"win32u.dll"); if (!w) w = LoadLibraryW(L"win32u.dll");
        if (w) g_ntUserPaintDesktop = (NtUserPaintDesktopFn)GetProcAddress(w, "NtUserPaintDesktop");
        KEEL_INFO(L"wallpaper; PaintDesktop -> %s", g_ntUserPaintDesktop ? L"win32u!NtUserPaintDesktop (Win7 semantics)" : L"user32!PaintDesktop (win32u export missing!)");
    }
    const BOOL r = g_ntUserPaintDesktop ? g_ntUserPaintDesktop(hdc)
                                        : g_realPaintDesktop(hdc);
    bool blitted = false;
    if (WallProbeEnabled()) {
        RECT rc{ 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN) };
        if (HBRUSH b = CreateSolidBrush(RGB(200, 0, 160))) {
            blitted = FillRect(hdc, &rc, b) != 0;
            DeleteObject(b);
        }
    } else if (EnsureWallpaperBitmap()) {
        if (HDC mem = CreateCompatibleDC(hdc)) {
            HGDIOBJ old = SelectObject(mem, g_wallBmp);

            blitted = BitBlt(hdc, 0, 0, g_wallCx, g_wallCy, mem, 0, 0, SRCCOPY) != 0;
            SelectObject(mem, old);
            DeleteDC(mem);
        }
    }
    if (InterlockedDecrement(&g_paintDeskLog) > 0) {

        HWND w = WindowFromDC(hdc);
        wchar_t cls[48]{}; if (w) GetClassNameW(w, cls, 47);
        RECT wr{}; if (w) GetWindowRect(w, &wr);
        RECT clip{}; const int cr = GetClipBox(hdc, &clip);

        RECT sys{}; int sr = 0;
        if (HRGN rgn = CreateRectRgn(0, 0, 1, 1)) {
            if (GetRandomRgn(hdc, rgn, SYSRGN) == 1) sr = GetRgnBox(rgn, &sys);
            DeleteObject(rgn);
        }
        KEEL_INFO(L"wallpaper; PaintDesktop(hdc=%p) real=%d blitted=%d hwnd=%p '%s' vis=%d "
                  L"win=(%ld,%ld,%ld,%ld) clip=%d(%ld,%ld,%ld,%ld) sysrgn=%d(%ld,%ld,%ld,%ld)",
                  hdc, r, blitted, w, cls, w ? IsWindowVisible(w) : -1,
                  wr.left, wr.top, wr.right, wr.bottom,
                  cr, clip.left, clip.top, clip.right, clip.bottom,
                  sr, sys.left, sys.top, sys.right, sys.bottom);
    }
    InterlockedIncrement(&g_paintDeskCalls);
    return r;
}

using DispatchMessageWFn = LRESULT(WINAPI*)(const MSG*);
using BeginPaintFn = HDC(WINAPI*)(HWND, LPPAINTSTRUCT);
DispatchMessageWFn g_realDispatchMessageW = nullptr;
BeginPaintFn g_realBeginPaint = nullptr;

struct PaintSlot { HWND hwnd; volatile LONG dispatched; volatile LONG begun; volatile LONG invalidated; PVOID ra[4];
                   PVOID bt[30]; volatile LONG btTaken; };

using DefViewWndProcFn = LRESULT(WINAPI*)(HWND, UINT, WPARAM, LPARAM);
DefViewWndProcFn g_realDefViewWndProc = nullptr;
volatile LONG g_wm34Count = 0, g_wm34W4 = 0, g_wm34W5 = 0, g_wm34Other = 0, g_spiSetWall = 0;
PVOID g_wm34Bt[30]; volatile LONG g_wm34BtTaken = 0;
PVOID g_spiWallRa[4];
volatile LONG g_wm34Log = 40;
void NoteSpiSetWallpaper(PVOID ra) {
    InterlockedIncrement(&g_spiSetWall);
    for (PVOID& s : g_spiWallRa) { if (s == ra) break; if (!s && InterlockedCompareExchangePointer(&s, ra, nullptr) == nullptr) break; }
}
volatile LONG g_dsvMsgLog = 40;
LRESULT WINAPI HookedDefViewWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == 0x34) {
        const LONG n = InterlockedIncrement(&g_wm34Count);
        if (w == 4) InterlockedIncrement(&g_wm34W4); else if (w == 5) InterlockedIncrement(&g_wm34W5); else InterlockedIncrement(&g_wm34Other);
        if (n >= 200 && InterlockedCompareExchange(&g_wm34BtTaken, 1, 0) == 0) RtlCaptureStackBackTrace(0, 30, g_wm34Bt, nullptr);
    }

    if (m == 0x4ad || m == 0x4af || m == 0x4b0 || m == 0x4a4) {
        if (InterlockedDecrement(&g_dsvMsgLog) > 0) KEEL_INFO(L"dsvmsg; DefView hwnd=%p got 0x%X (wParam=%p lParam=0x%llX) on tid %lu", h, m, (void*)w, (unsigned long long)l, GetCurrentThreadId());
        const LRESULT r = g_realDefViewWndProc(h, m, w, l);
        if (InterlockedDecrement(&g_dsvMsgLog) > 0) KEEL_INFO(L"dsvmsg; 0x%X handled -> %lld", m, (long long)r);
        return r;
    }
    return g_realDefViewWndProc(h, m, w, l);
}

using EnumObjectsFn = long(__fastcall*)(void*, HWND, ULONG, void**);
using SHRestrictedFn = DWORD(__stdcall*)(DWORD);
EnumObjectsFn g_realCplEnumObjects = nullptr, g_realRegEnumObjects = nullptr;
SHRestrictedFn g_realSHRestricted = nullptr;
volatile LONG g_enumLog = 60, g_restrictLog = 60;

int CountEnum(void* pe) {
    if (!pe) return -1;
    struct EnumVtbl { void* QI; void* AddRef; void* Release;
        long(__stdcall* Next)(void*, ULONG, void**, ULONG*);
        void* Skip; long(__stdcall* Reset)(void*); void* Clone; };
    auto vt = *reinterpret_cast<EnumVtbl**>(pe);
    int n = 0;
    __try {
        void* pidl = nullptr; ULONG got = 0;
        while (n < 500 && vt->Next(pe, 1, &pidl, &got) == 0 && got == 1) { CoTaskMemFree(pidl); pidl = nullptr; ++n; }
        vt->Reset(pe);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -2; }
    return n;
}

long __fastcall HookedCplEnumObjects(void* self, HWND h, ULONG flags, void** ppe) {
    const long hr = g_realCplEnumObjects(self, h, flags, ppe);
    if (InterlockedDecrement(&g_enumLog) > 0)
        KEEL_INFO(L"nsenum; CControlPanelFolder::EnumObjects(flags=0x%lX) -> hr=0x%08lX enum=%p",
                  flags, (unsigned long)hr, ppe ? *ppe : nullptr);
    return hr;
}
long __fastcall HookedRegEnumObjects(void* self, HWND h, ULONG flags, void** ppe) {
    const long hr = g_realRegEnumObjects(self, h, flags, ppe);
    if (InterlockedDecrement(&g_enumLog) > 0)
        KEEL_INFO(L"nsenum; CRegFolder::EnumObjects(flags=0x%lX) -> hr=0x%08lX enum=%p",
                  flags, (unsigned long)hr, ppe ? *ppe : nullptr);
    return hr;
}
DWORD __stdcall HookedSHRestricted(DWORD id) {
    const DWORD r = g_realSHRestricted(id);
    if (r && InterlockedDecrement(&g_restrictLog) > 0)
        KEEL_WARN(L"nsenum; SHRestricted(%lu) -> %lu (non-zero blocks the namespace folder)", id, r);
    return r;
}

using CreateViewObjectFn = long(__fastcall*)(void*, HWND, const GUID*, void**);
CreateViewObjectFn g_realCplCreateView = nullptr;
EnumObjectsFn g_realDeskEnumObjects = nullptr;

static const GUID kIID_IFrameLayoutDefinition =
    { 0x176c11b1, 0x4302, 0x4164, { 0x84, 0x30, 0xd5, 0xa9, 0xf0, 0xee, 0xac, 0xdb } };
bool CplDeclineFrame() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_CPLDECLINE", v, 8) > 0 && v[0] == L'1') ? 1 : 0; }
    return cached == 1;
}
volatile LONG g_cplPatchLog = 8;

using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
LoadLibraryExWFn g_realLoadLibraryExW = nullptr;
volatile LONG g_shellStyleLog = 4;

bool IsExplorerProcess();
volatile LONG g_rtmRedirectLog = 40;

// narrow on purpose, redirecting every System32 path that also exists in rtm maps core DLLs twice and drops the session to classic
bool IsAppletBinary(const wchar_t* leaf) {
    const size_t n = wcslen(leaf);
    if (n > 4 && _wcsicmp(leaf + n - 4, L".cpl") == 0) return true;
    if (_wcsicmp(leaf, L"ShellStyle.dll") == 0) return true;

    if (n > 4 && _wcsicmp(leaf + n - 4, L".dll") == 0) {
        for (const wchar_t* p = leaf; *p; ++p)
            if ((p[0] == L'c' || p[0] == L'C') && (p[1] == L'p' || p[1] == L'P') && (p[2] == L'l' || p[2] == L'L')) return true;
    }

    {
        static const wchar_t* const kAppletDlls[] = {
            L"recovery.dll", L"Vault.dll", L"fontext.dll", L"DeviceCenter.dll", L"FunDisc.dll",
            L"OobeFldr.dll", L"NetworkMap.dll", L"wucltux.dll", L"van.dll", L"Display.dll",
            // Win10 dropped the VAN media manager interface Win7 van.dll asks for, and its netcenter rejects the Win7 page host
            L"netcenter.dll", L"WlanMM.dll", L"RasMM.dll", L"wwanmm.dll",
            // Win10 netshell lacks the Network Connections command handlers, and a NULL one crashes the Win7 command bar
            L"netshell.dll",
            // Win7 netcenter drives the wizard framework through an interface Win10 changed, which corrupts the heap
            L"xwizards.dll", L"xwtpw32.dll", L"xwtpdui.dll",
            // the Win7 wizard pages, including the Wi-Fi key prompt the network flyout opens
            L"connect.dll", L"rasgcw.dll", L"wcnwiz.dll", L"wlanpref.dll", L"wlanconn.dll", L"wwanconn.dll",
            L"wlandlg.dll", L"wpdwcn.dll", L"pnidui.dll",
        };
        for (const wchar_t* a : kAppletDlls)
            if (_wcsicmp(leaf, a) == 0) return true;
    }
    return false;
}
bool Win7CopyFor(const wchar_t* path, wchar_t* out, size_t cch) {
    if (!path || (reinterpret_cast<ULONG_PTR>(path) >> 16) == 0) return false;
    if (wcsstr(path, L"\\Keel\\")) return false;
    const wchar_t* leaf = wcsrchr(path, L'\\');
    if (!leaf) return false;
    ++leaf;
    if (!IsAppletBinary(leaf)) return false;
    if (!wcsstr(path, L"\\System32\\") && !wcsstr(path, L"\\system32\\") && !wcsstr(path, L"\\SysWOW64\\")) {
        if (_wcsicmp(leaf, L"ShellStyle.dll") != 0) return false;
    }
    swprintf_s(out, cch, L"C:\\Keel\\rtm\\%s", leaf);
    return GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES;
}
HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR path, HANDLE file, DWORD flags) {
    wchar_t ours[MAX_PATH];
    if (IsExplorerProcess() && Win7CopyFor(path, ours, MAX_PATH)) {
        HMODULE m = g_realLoadLibraryExW(ours, file, flags);
        if (InterlockedDecrement(&g_rtmRedirectLog) > 0)
            KEEL_INFO(L"rtm; LoadLibraryExW('%s') -> Win7 '%s' (flags=0x%lX) -> %p", path, ours, flags, m);
        if (m) return m;
    }
    return g_realLoadLibraryExW(path, file, flags);
}

void LogThemeState() {
    HMODULE ux = GetModuleHandleW(L"uxtheme.dll");
    if (!ux) ux = LoadLibraryW(L"uxtheme.dll");
    if (!ux) { KEEL_WARN(L"theme; uxtheme.dll not loadable"); return; }
    using BoolFn = BOOL(WINAPI*)(); using OpenFn = HANDLE(WINAPI*)(HWND, LPCWSTR); using CloseFn = HRESULT(WINAPI*)(HANDLE);
    using CurFn = HRESULT(WINAPI*)(LPWSTR, int, LPWSTR, int, LPWSTR, int);
    auto isAppThemed = reinterpret_cast<BoolFn>(GetProcAddress(ux, "IsAppThemed"));
    auto isActive = reinterpret_cast<BoolFn>(GetProcAddress(ux, "IsThemeActive"));
    auto open = reinterpret_cast<OpenFn>(GetProcAddress(ux, "OpenThemeData"));
    auto close = reinterpret_cast<CloseFn>(GetProcAddress(ux, "CloseThemeData"));
    auto cur = reinterpret_cast<CurFn>(GetProcAddress(ux, "GetCurrentThemeName"));
    wchar_t theme[MAX_PATH]{}, color[64]{}, size[64]{}; HRESULT chr = cur ? cur(theme, MAX_PATH, color, 64, size, 64) : E_FAIL;
    wchar_t uxPath[MAX_PATH]{}; GetModuleFileNameW(ux, uxPath, MAX_PATH);
    const wchar_t* classes[] = { L"CommandModule", L"ControlPanel", L"ExplorerBar", L"Button", L"Window", L"CommonItemsDialog" };
    wchar_t line[512]; int n = swprintf_s(line, L"theme; uxtheme=%s appThemed=%d active=%d cur=0x%08lX '%s' color='%s' classes", uxPath, isAppThemed ? isAppThemed() : -1, isActive ? isActive() : -1, (unsigned long)chr, theme, color);
    for (const wchar_t* c : classes) { HANDLE h = open ? open(nullptr, c) : nullptr; n += swprintf_s(line + n, 512 - n, L" %s=%s", c, h ? L"ok" : L"NULL"); if (h && close) close(h); }
    KEEL_INFO(L"%s", line);
}

using IsThemedFn = BOOL(WINAPI*)();
IsThemedFn g_realIsThemeActive = nullptr, g_realIsAppThemed = nullptr, g_realIsCompositionActive = nullptr;
using DwmEnabledFn = long(WINAPI*)(BOOL*);
DwmEnabledFn g_dwmEnabledForUx = nullptr;
volatile LONG g_themeActiveLog = 4, g_compActiveLog = 40;
// Win7 uxtheme never completes the theme service handshake, so these answer FALSE and DirectUI then rejects every dtb() class
BOOL WINAPI HookedIsThemeActive() {
    const BOOL real = g_realIsThemeActive();
    if (!real && g_win7ThemeFile) { if (InterlockedDecrement(&g_themeActiveLog) > 0) KEEL_INFO(L"theme; IsThemeActive() real=0 -> TRUE (in-process Win7 theme file)"); return TRUE; }
    return real;
}
BOOL WINAPI HookedIsAppThemed() {
    const BOOL real = g_realIsAppThemed();
    if (!real && g_win7ThemeFile) { if (InterlockedDecrement(&g_themeActiveLog) > 0) KEEL_INFO(L"theme; IsAppThemed() real=0 -> TRUE (in-process Win7 theme file)"); return TRUE; }
    return real;
}
BOOL WINAPI HookedIsCompositionActive() {
    const BOOL real = g_realIsCompositionActive();
    BOOL on = FALSE;
    const bool dwmOn = g_dwmEnabledForUx && g_dwmEnabledForUx(&on) >= 0 && on;
    const BOOL answer = (real || (g_win7ThemeFile && dwmOn)) ? TRUE : FALSE;
    if (InterlockedDecrement(&g_compActiveLog) > 0)
        KEEL_INFO(L"theme; IsCompositionActive() real=%d dwm=%d themeFile=%p -> %d", real, dwmOn ? 1 : 0, g_win7ThemeFile, answer);
    return answer;
}
void InstallThemeActiveAnswers() {
    if (g_realIsThemeActive) return;
    HMODULE ux = GetModuleHandleW(L"uxtheme.dll"); if (!ux) ux = LoadLibraryW(L"uxtheme.dll");
    if (!ux) return;
    g_realIsThemeActive = reinterpret_cast<IsThemedFn>(GetProcAddress(ux, "IsThemeActive"));
    g_realIsAppThemed = reinterpret_cast<IsThemedFn>(GetProcAddress(ux, "IsAppThemed"));
    g_realIsCompositionActive = reinterpret_cast<IsThemedFn>(GetProcAddress(ux, "IsCompositionActive"));
    if (!g_realIsThemeActive || !g_realIsAppThemed) { KEEL_WARN(L"theme; IsThemeActive/IsAppThemed not found in uxtheme"); return; }
    if (HMODULE dwm = LoadLibraryW(L"dwmapi.dll"))
        g_dwmEnabledForUx = reinterpret_cast<DwmEnabledFn>(GetProcAddress(dwm, "DwmIsCompositionEnabled"));
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realIsThemeActive), reinterpret_cast<PVOID>(HookedIsThemeActive));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realIsAppThemed), reinterpret_cast<PVOID>(HookedIsAppThemed));
    if (g_realIsCompositionActive)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realIsCompositionActive), reinterpret_cast<PVOID>(HookedIsCompositionActive));
    const LONG e = DetourTransactionCommit();
    if (e != 0) KEEL_WARN(L"theme; IsThemeActive/IsAppThemed/IsCompositionActive hook commit=%ld", e);
    KEEL_INFO(L"theme; answers installed (IsCompositionActive %s, dwm query %s)",
              g_realIsCompositionActive ? L"hooked" : L"NOT EXPORTED", g_dwmEnabledForUx ? L"ok" : L"missing");
}

using DwmIsCompEnabledFn = long(WINAPI*)(BOOL*);
DwmIsCompEnabledFn g_realDwmIsCompEnabled = nullptr;
volatile LONG g_compLog = 60, g_compLastAnswer = -1;
long WINAPI HookedDwmIsCompositionEnabled(BOOL* enabled) {
    const long hr = g_realDwmIsCompEnabled(enabled);
    const LONG now = (hr >= 0 && enabled) ? (*enabled ? 1 : 0) : -2;
    const LONG prev = InterlockedExchange(&g_compLastAnswer, now);
    if ((prev != now || now == 0) && InterlockedDecrement(&g_compLog) > 0)
        KEEL_INFO(L"comp; DwmIsCompositionEnabled -> hr=0x%08lX enabled=%ld (was %ld) caller tid=%lu",
                  (unsigned long)hr, now, prev, GetCurrentThreadId());
    return hr;
}
void InstallCompositionAnswers() {
    if (g_realDwmIsCompEnabled) return;
    HMODULE d = GetModuleHandleW(L"dwmapi.dll"); if (!d) d = LoadLibraryW(L"dwmapi.dll");
    if (!d) return;
    g_realDwmIsCompEnabled = reinterpret_cast<DwmIsCompEnabledFn>(GetProcAddress(d, "DwmIsCompositionEnabled"));
    if (!g_realDwmIsCompEnabled) return;
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDwmIsCompEnabled), reinterpret_cast<PVOID>(HookedDwmIsCompositionEnabled));
    const LONG e = DetourTransactionCommit();
    if (e != 0) KEEL_WARN(L"comp; DwmIsCompositionEnabled hook commit=%ld", e);
}

DWORD WINAPI ThemeWatchdog(LPVOID) {
    int last = -1;
    for (;;) {
        Sleep(2500);

        int state = 0;
        if (g_win7ThemeFile) state |= 3;
        if (g_realIsThemeActive && g_realIsThemeActive()) state |= 4;
        if (g_realIsAppThemed && g_realIsAppThemed()) state |= 8;
        BOOL comp = FALSE;
        if (g_realDwmIsCompEnabled && g_realDwmIsCompEnabled(&comp) >= 0 && comp) state |= 16;
        if (state != last) {
            KEEL_INFO(L"watch; theme state %d -> %d (Window=%d Button=%d realThemeActive=%d realAppThemed=%d composition=%d themeFile=%p)",
                      last, state, (state & 1) != 0, (state & 2) != 0, (state & 4) != 0, (state & 8) != 0, (state & 16) != 0, g_win7ThemeFile);
            last = state;
        }
    }
}

using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                       BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessAsUserWFn = BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                             LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                             LPSTARTUPINFOW, LPPROCESS_INFORMATION);

CreateProcessWFn       g_realCreateProcessW = nullptr;
CreateProcessAsUserWFn g_realCreateProcessAsUserW = nullptr;
CreateProcessWFn       g_realCreateProcessWK32 = nullptr;
CreateProcessAsUserWFn g_realCreateProcessAsUserWK32 = nullptr;
volatile LONG g_donorPathLog = 80;

bool DonorPathFixEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NODONORPATHFIX", v, 8) > 0 && v[0] == L'1') ? 0 : 1; }
    return cached == 1;
}
void KeelDonorDir(wchar_t* out, DWORD cch) {
    out[0] = L'\0';
    if (GetEnvironmentVariableW(L"KEEL_DONOR", out, cch) == 0 || !out[0]) wcscpy_s(out, cch, L"C:\\Keel\\rtm");
}
bool SegIsDonor(const wchar_t* seg, size_t len, const wchar_t* donor, size_t dlen) {
    while (len && (seg[len - 1] == L'\\' || seg[len - 1] == L' ')) --len;
    while (dlen && (donor[dlen - 1] == L'\\' || donor[dlen - 1] == L' ')) --dlen;
    return len == dlen && len != 0 && _wcsnicmp(seg, donor, len) == 0;
}

bool TargetIsKeelOwn(LPCWSTR app, LPCWSTR cmd) {
    const wchar_t* s = app;
    if (!s || !*s) {
        s = cmd;
        while (s && *s == L'"') ++s;
    }
    return s && _wcsnicmp(s, L"C:\\Keel\\", 8) == 0;
}

wchar_t* EnvWithoutDonorPathFrom(const wchar_t* src) {
    wchar_t donor[MAX_PATH]; KeelDonorDir(donor, MAX_PATH);
    const size_t dlen = wcslen(donor);
    if (!dlen) return nullptr;
    LPWCH owned = src ? nullptr : GetEnvironmentStringsW();
    const wchar_t* env = src ? src : owned;
    if (!env) return nullptr;
    size_t total = 0;
    for (const wchar_t* p = env; *p;) { const size_t l = wcslen(p) + 1; total += l; p += l; }
    auto* out = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, (total + 2) * sizeof(wchar_t)));
    if (!out) { if (owned) FreeEnvironmentStringsW(owned); return nullptr; }
    size_t w = 0; bool stripped = false;
    for (const wchar_t* p = env; *p;) {
        const size_t l = wcslen(p) + 1;
        if (_wcsnicmp(p, L"PATH=", 5) == 0) {
            wchar_t* dst = out + w;
            wmemcpy(dst, L"PATH=", 5);
            size_t dw = 5; bool first = true;
            for (const wchar_t* v = p + 5; *v;) {
                const wchar_t* semi = wcschr(v, L';');
                const size_t segLen = semi ? static_cast<size_t>(semi - v) : wcslen(v);
                if (segLen) {
                    if (SegIsDonor(v, segLen, donor, dlen)) stripped = true;
                    else {
                        if (!first) dst[dw++] = L';';
                        wmemcpy(dst + dw, v, segLen); dw += segLen; first = false;
                    }
                }
                v = semi ? semi + 1 : v + segLen;
            }
            dst[dw++] = L'\0';
            w += dw;
        } else { wmemcpy(out + w, p, l); w += l; }
        p += l;
    }
    out[w] = L'\0';
    if (owned) FreeEnvironmentStringsW(owned);
    if (!stripped) { HeapFree(GetProcessHeap(), 0, out); return nullptr; }
    return out;
}

wchar_t* CleanEnvFor(LPCWSTR app, LPWSTR cmd, LPVOID suppliedEnv, DWORD flags) {
    if (!DonorPathFixEnabled() || TargetIsKeelOwn(app, cmd)) return nullptr;
    if (!suppliedEnv) return EnvWithoutDonorPathFrom(nullptr);
    if (flags & CREATE_UNICODE_ENVIRONMENT)
        return EnvWithoutDonorPathFrom(static_cast<const wchar_t*>(suppliedEnv));

    const char* a = static_cast<const char*>(suppliedEnv);
    size_t bytes = 0;
    for (const char* p = a; *p;) { const size_t l = strlen(p) + 1; bytes += l; p += l; }
    if (!bytes) return nullptr;
    const int wide = MultiByteToWideChar(CP_ACP, 0, a, static_cast<int>(bytes), nullptr, 0);
    if (wide <= 0) return nullptr;
    auto* tmp = static_cast<wchar_t*>(HeapAlloc(GetProcessHeap(), 0, (static_cast<size_t>(wide) + 2) * sizeof(wchar_t)));
    if (!tmp) return nullptr;
    MultiByteToWideChar(CP_ACP, 0, a, static_cast<int>(bytes), tmp, wide);
    tmp[wide] = L'\0';
    wchar_t* cleaned = EnvWithoutDonorPathFrom(tmp);
    HeapFree(GetProcessHeap(), 0, tmp);
    return cleaned;
}
void LogDonorPathStrip(LPCWSTR app, LPWSTR cmd, BOOL ok) {
    if (InterlockedDecrement(&g_donorPathLog) <= 0) return;
    KEEL_INFO(L"donorpath; '%s' launched without C:\\Keel\\rtm on PATH (ok=%d)",
              app ? app : (cmd ? cmd : L"?"), ok);
}

const wchar_t* ReplacementCurrentDir() {
    static wchar_t dir[MAX_PATH];
    static bool init = false;
    if (!init) {
        init = true;
        if (GetEnvironmentVariableW(L"USERPROFILE", dir, MAX_PATH) == 0 || !dir[0])
            GetSystemDirectoryW(dir, MAX_PATH);
    }
    return dir[0] ? dir : nullptr;
}

const wchar_t* CleanCurDirFor(LPCWSTR app, LPWSTR cmd, LPCWSTR suppliedDir) {
    if (!DonorPathFixEnabled() || TargetIsKeelOwn(app, cmd)) return nullptr;
    wchar_t cwd[MAX_PATH];
    const wchar_t* effective = suppliedDir;
    if (!effective) {
        const DWORD n = GetCurrentDirectoryW(MAX_PATH, cwd);
        if (!n || n >= MAX_PATH) return nullptr;
        effective = cwd;
    }
    wchar_t donor[MAX_PATH]; KeelDonorDir(donor, MAX_PATH);
    if (!SegIsDonor(effective, wcslen(effective), donor, wcslen(donor))) return nullptr;
    return ReplacementCurrentDir();
}

struct DllDirSwap {
    wchar_t saved[MAX_PATH];
    bool active;
    explicit DllDirSwap(bool engage) : active(false) {
        saved[0] = L'\0';
        if (!engage) return;
        const DWORD n = GetDllDirectoryW(MAX_PATH, saved);
        if (n >= MAX_PATH) { saved[0] = L'\0'; return; }
        active = true;
        SetDllDirectoryW(nullptr);
    }
    ~DllDirSwap() { if (active) SetDllDirectoryW(saved[0] ? saved : nullptr); }
    DllDirSwap(const DllDirSwap&) = delete;
    DllDirSwap& operator=(const DllDirSwap&) = delete;
};
bool ShouldCleanChild(LPCWSTR app, LPWSTR cmd) {
    return DonorPathFixEnabled() && !TargetIsKeelOwn(app, cmd);
}

volatile LONG g_cpTraceLog = 200;
void LogCreateAttempt(const wchar_t* via, LPCWSTR app, LPWSTR cmd, LPVOID env) {
    if (InterlockedDecrement(&g_cpTraceLog) <= 0) return;
    KEEL_INFO(L"cptrace; [%s] app='%s' cmd='%.120s' suppliedEnv=%d", via,
              app ? app : L"(null)", cmd ? cmd : L"(null)", env ? 1 : 0);
}

// Win10 RunVAN opens a XAML flyout Keel cannot show, the Win7 van.dll in a Win7 rundll32 asks the tray flyout instead
bool VanLaunchRewrite(LPCWSTR app, LPCWSTR cmd, wchar_t* outApp, size_t cchApp, wchar_t* outCmd, size_t cchCmd) {
    if (!cmd || TargetIsKeelOwn(app, cmd)) return false;
    static const wchar_t kEntry[] = L"van.dll,RunVAN";
    const size_t entryLen = wcslen(kEntry);
    const wchar_t* hit = nullptr;
    for (const wchar_t* p = cmd; *p && !hit; ++p)
        if (_wcsnicmp(p, kEntry, entryLen) == 0) hit = p;
    if (!hit) return false;
    const wchar_t* exe = (app && *app) ? app : cmd;
    bool rundll = false;
    for (const wchar_t* p = exe; *p && !rundll; ++p) rundll = _wcsnicmp(p, L"rundll32", 8) == 0;
    if (!rundll || GetFileAttributesW(L"C:\\Keel\\rtm\\rundll32.exe") == INVALID_FILE_ATTRIBUTES) return false;
    wcscpy_s(outApp, cchApp, L"C:\\Keel\\bin\\keelldr.exe");
    return swprintf_s(outCmd, cchCmd, L"\"C:\\Keel\\bin\\keelldr.exe\" --donor C:\\Keel\\rtm --shim C:\\Keel\\bin\\keelshim.dll "
                      L"C:\\Keel\\rtm\\rundll32.exe C:\\Keel\\rtm\\%s", hit) > 0;
}
#define KEEL_VAN_REWRITE()                                                                    \
    wchar_t vanApp[MAX_PATH], vanCmd[1024];                                                   \
    if (VanLaunchRewrite(app, cmd, vanApp, MAX_PATH, vanCmd, 1024)) {                         \
        KEEL_INFO(L"van; '%.100s' rerouted to the Win7 van.dll under keelldr", cmd);        \
        app = vanApp; cmd = vanCmd;                                                           \
        flags = (flags & ~(CREATE_NEW_CONSOLE | DETACHED_PROCESS)) | CREATE_NO_WINDOW;        \
    }
BOOL WINAPI HookedCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                 BOOL inherit, DWORD flags, LPVOID env, LPCWSTR curDir,
                                 LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    LogCreateAttempt(L"kernelbase!CreateProcessW", app, cmd, env);
    KEEL_VAN_REWRITE();
    DllDirSwap dllDirSwap(ShouldCleanChild(app, cmd));
    wchar_t* clean = CleanEnvFor(app, cmd, env, flags);
    if (clean) flags |= CREATE_UNICODE_ENVIRONMENT;
    const wchar_t* cdir = CleanCurDirFor(app, cmd, curDir);
    const BOOL ok = g_realCreateProcessW(app, cmd, pa, ta, inherit, flags, clean ? clean : env, cdir ? cdir : curDir, si, pi);
    if (clean) { LogDonorPathStrip(app, cmd, ok); HeapFree(GetProcessHeap(), 0, clean); }
    return ok;
}
BOOL WINAPI HookedCreateProcessAsUserW(HANDLE tok, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                       LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
                                       LPCWSTR curDir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    LogCreateAttempt(L"kernelbase!CreateProcessAsUserW", app, cmd, env);
    KEEL_VAN_REWRITE();
    DllDirSwap dllDirSwap(ShouldCleanChild(app, cmd));
    wchar_t* clean = CleanEnvFor(app, cmd, env, flags);
    if (clean) flags |= CREATE_UNICODE_ENVIRONMENT;
    const wchar_t* cdir = CleanCurDirFor(app, cmd, curDir);
    const BOOL ok = g_realCreateProcessAsUserW(tok, app, cmd, pa, ta, inherit, flags, clean ? clean : env, cdir ? cdir : curDir, si, pi);
    if (clean) { LogDonorPathStrip(app, cmd, ok); HeapFree(GetProcessHeap(), 0, clean); }
    return ok;
}
BOOL WINAPI HookedCreateProcessWK32(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                    BOOL inherit, DWORD flags, LPVOID env, LPCWSTR curDir,
                                    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    LogCreateAttempt(L"kernel32!CreateProcessW", app, cmd, env);
    KEEL_VAN_REWRITE();
    DllDirSwap dllDirSwap(ShouldCleanChild(app, cmd));
    wchar_t* clean = CleanEnvFor(app, cmd, env, flags);
    if (clean) flags |= CREATE_UNICODE_ENVIRONMENT;
    const wchar_t* cdir = CleanCurDirFor(app, cmd, curDir);
    const BOOL ok = g_realCreateProcessWK32(app, cmd, pa, ta, inherit, flags, clean ? clean : env, cdir ? cdir : curDir, si, pi);
    if (clean) { LogDonorPathStrip(app, cmd, ok); HeapFree(GetProcessHeap(), 0, clean); }
    return ok;
}
BOOL WINAPI HookedCreateProcessAsUserWK32(HANDLE tok, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                          LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
                                          LPCWSTR curDir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    LogCreateAttempt(L"kernel32!CreateProcessAsUserW", app, cmd, env);
    KEEL_VAN_REWRITE();
    DllDirSwap dllDirSwap(ShouldCleanChild(app, cmd));
    wchar_t* clean = CleanEnvFor(app, cmd, env, flags);
    if (clean) flags |= CREATE_UNICODE_ENVIRONMENT;
    const wchar_t* cdir = CleanCurDirFor(app, cmd, curDir);
    const BOOL ok = g_realCreateProcessAsUserWK32(tok, app, cmd, pa, ta, inherit, flags, clean ? clean : env, cdir ? cdir : curDir, si, pi);
    if (clean) { LogDonorPathStrip(app, cmd, ok); HeapFree(GetProcessHeap(), 0, clean); }
    return ok;
}
void InstallDonorPathFix() {
    if (g_realCreateProcessW || g_realCreateProcessWK32 || !IsExplorerProcess()) return;
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (kb) {
        g_realCreateProcessW = reinterpret_cast<CreateProcessWFn>(GetProcAddress(kb, "CreateProcessW"));
        g_realCreateProcessAsUserW = reinterpret_cast<CreateProcessAsUserWFn>(GetProcAddress(kb, "CreateProcessAsUserW"));
    }
    if (k32) {
        g_realCreateProcessWK32 = reinterpret_cast<CreateProcessWFn>(GetProcAddress(k32, "CreateProcessW"));
        g_realCreateProcessAsUserWK32 = reinterpret_cast<CreateProcessAsUserWFn>(GetProcAddress(k32, "CreateProcessAsUserW"));

        if (g_realCreateProcessWK32 == g_realCreateProcessW) g_realCreateProcessWK32 = nullptr;
        if (g_realCreateProcessAsUserWK32 == g_realCreateProcessAsUserW) g_realCreateProcessAsUserWK32 = nullptr;
    }
    if (!g_realCreateProcessW && !g_realCreateProcessWK32) { KEEL_WARN(L"donorpath; CreateProcessW not found"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (g_realCreateProcessW)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateProcessW), reinterpret_cast<PVOID>(HookedCreateProcessW));
    if (g_realCreateProcessAsUserW)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateProcessAsUserW), reinterpret_cast<PVOID>(HookedCreateProcessAsUserW));
    if (g_realCreateProcessWK32)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateProcessWK32), reinterpret_cast<PVOID>(HookedCreateProcessWK32));
    if (g_realCreateProcessAsUserWK32)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateProcessAsUserWK32), reinterpret_cast<PVOID>(HookedCreateProcessAsUserWK32));
    const LONG e = DetourTransactionCommit();
    wchar_t donor[MAX_PATH]; KeelDonorDir(donor, MAX_PATH);
    KEEL_INFO(L"donorpath; installed (commit=%ld, donor='%s', %s)", e, donor,
              DonorPathFixEnabled() ? L"on" : L"disabled by KEEL_NODONORPATHFIX");
}

const wchar_t* const kUlwAlphaProp = L"KeelUlwPerPixelAlpha";
using UlwIndirectFn = BOOL(WINAPI*)(HWND, const UPDATELAYEREDWINDOWINFO*);
using UlwFn = BOOL(WINAPI*)(HWND, HDC, POINT*, SIZE*, HDC, POINT*, COLORREF, BLENDFUNCTION*, DWORD);
UlwIndirectFn g_realUlwIndirect = nullptr;
UlwFn g_realUlw = nullptr;
volatile LONG g_ulwLog = 500;
volatile LONG g_ulwMarkLog = 40;

void MarkLayeredWindow(HWND hwnd, DWORD flags, const BLENDFUNCTION* blend, long cx, long cy,
                       const wchar_t* via) {
    const bool perPixel = (flags & ULW_ALPHA) && !(flags & ULW_COLORKEY) &&
                          blend && blend->AlphaFormat == AC_SRC_ALPHA;
    const ULONG_PTR want = perPixel ? 2u : 1u;
    if (reinterpret_cast<ULONG_PTR>(GetPropW(hwnd, kUlwAlphaProp)) == want) return;
    SetPropW(hwnd, kUlwAlphaProp, reinterpret_cast<HANDLE>(want));
    if (InterlockedDecrement(&g_ulwMarkLog) > 0) {
        wchar_t c[64] = L"?"; GetClassNameW(hwnd, c, 64);
        KEEL_INFO(L"ulw; hwnd=%p '%s' %ldx%ld via %s flags=0x%lX blend(alpha=%d fmt=%d) -> %s",
                  hwnd, c, cx, cy, via, flags,
                  blend ? blend->SourceConstantAlpha : -1, blend ? blend->AlphaFormat : -1,
                  perPixel ? L"per-pixel alpha" : L"opaque");
    }
}

BOOL WINAPI HookedUlwIndirect(HWND hwnd, const UPDATELAYEREDWINDOWINFO* info) {
    const BOOL ok = g_realUlwIndirect(hwnd, info);
    const DWORD err = ok ? 0 : GetLastError();
    long cx = -1, cy = -1, dx = -1, dy = -1; DWORD flags = 0; int blendOp = -1, alpha = -1, fmt = -1;
    const BLENDFUNCTION* blend = nullptr;
    __try {
        if (info) {
            flags = info->dwFlags;
            if (info->psize)  { cx = info->psize->cx; cy = info->psize->cy; }
            if (info->pptDst) { dx = info->pptDst->x; dy = info->pptDst->y; }
            blend = info->pblend;
            if (blend) { blendOp = blend->BlendOp; alpha = blend->SourceConstantAlpha; fmt = blend->AlphaFormat; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (ok) { __try { MarkLayeredWindow(hwnd, flags, blend, cx, cy, L"ULWIndirect"); }
              __except (EXCEPTION_EXECUTE_HANDLER) {} }

    if (InterlockedDecrement(&g_ulwLog) > 0) {
        wchar_t cls[64] = L"?";
        GetClassNameW(hwnd, cls, 64);
        if (!wcscmp(cls, L"Button"))
            KEEL_INFO(L"orb; UpdateLayeredWindowIndirect hwnd=%p cls=%s size=%ldx%ld dst=%ld,%ld flags=0x%lX"
                      L" blend(op=%d alpha=%d fmt=%d) -> %d err=%lu tick=%lu  <<< CONTENT CHANGED HERE",
                      hwnd, cls, cx, cy, dx, dy, flags, blendOp, alpha, fmt, ok, err, GetTickCount());
    }
    return ok;
}

BOOL WINAPI HookedUlw(HWND hwnd, HDC hdcDst, POINT* pptDst, SIZE* psize, HDC hdcSrc, POINT* pptSrc,
                      COLORREF crKey, BLENDFUNCTION* pblend, DWORD dwFlags) {
    const BOOL ok = g_realUlw(hwnd, hdcDst, pptDst, psize, hdcSrc, pptSrc, crKey, pblend, dwFlags);
    if (ok) {
        __try {
            MarkLayeredWindow(hwnd, dwFlags, pblend, psize ? psize->cx : -1, psize ? psize->cy : -1,
                              L"ULW");
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    return ok;
}
void InstallOrbTrace() {
    if (g_realUlwIndirect || g_realUlw || !IsExplorerProcess()) return;
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (!u32) return;
    g_realUlwIndirect = reinterpret_cast<UlwIndirectFn>(GetProcAddress(u32, "UpdateLayeredWindowIndirect"));
    g_realUlw         = reinterpret_cast<UlwFn>(GetProcAddress(u32, "UpdateLayeredWindow"));
    if (!g_realUlwIndirect && !g_realUlw) { KEEL_WARN(L"ulw; neither UpdateLayeredWindow entry found"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (g_realUlwIndirect)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realUlwIndirect), reinterpret_cast<PVOID>(HookedUlwIndirect));
    if (g_realUlw)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realUlw), reinterpret_cast<PVOID>(HookedUlw));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"ulw; layered-present marking installed (Indirect=%p, ULW=%p, commit=%ld)",
              g_realUlwIndirect, g_realUlw, e);
}

void InstallShellStyleRedirect() {
    if (g_realLoadLibraryExW) return;
    InstallThemeActiveAnswers();
    InstallCompositionAnswers();
    LogThemeState();
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    g_realLoadLibraryExW = kb ? reinterpret_cast<LoadLibraryExWFn>(GetProcAddress(kb, "LoadLibraryExW")) : nullptr;
    if (!g_realLoadLibraryExW) { KEEL_WARN(L"shellstyle; kernelbase!LoadLibraryExW not found so redirect not installed"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realLoadLibraryExW), reinterpret_cast<PVOID>(HookedLoadLibraryExW));
    const LONG e = DetourTransactionCommit();
    if (e != 0) KEEL_WARN(L"shellstyle; LoadLibraryExW hook commit=%ld", e);
}
long __fastcall HookedCplCreateView(void* self, HWND h, const GUID* riid, void** ppv) {
    if (riid && CplDeclineFrame() && memcmp(riid, &kIID_IFrameLayoutDefinition, sizeof(GUID)) == 0) {
        if (ppv) *ppv = nullptr;
        if (InterlockedDecrement(&g_cplPatchLog) > 0)
            KEEL_INFO(L"nsenum; declined IFrameLayoutDefinition for Control Panel -> DefView builds its item host");
        return (long)0x80004002;
    }
    const long hr = g_realCplCreateView(self, h, riid, ppv);
    if (InterlockedDecrement(&g_enumLog) > 0) {
        wchar_t g[48] = L"?"; if (riid) StringFromGUID2(*riid, g, 48);
        KEEL_INFO(L"nsenum; CControlPanelFolder::CreateViewObject(%s) -> hr=0x%08lX ppv=%p", g, (unsigned long)hr, ppv ? *ppv : nullptr);
    }
    return hr;
}
long __fastcall HookedDeskEnumObjects(void* self, HWND h, ULONG flags, void** ppe) {
    const long hr = g_realDeskEnumObjects(self, h, flags, ppe);
    if (InterlockedDecrement(&g_enumLog) > 0)
        KEEL_INFO(L"nsenum; CDesktopFolder::EnumObjects(flags=0x%lX) -> hr=0x%08lX", flags, (unsigned long)hr);
    return hr;
}

using GetEnumFlagsFn = ULONG(__fastcall*)(void*);
using DefViewOnCreateFn = __int64(__fastcall*)(void*, HWND);
using FillDoneFn = __int64(__fastcall*)(void*, void*, void*, void*, void*, void*);
GetEnumFlagsFn g_realGetEnumFlags = nullptr;
DefViewOnCreateFn g_realDefViewOnCreate = nullptr;
FillDoneFn g_realFillDone = nullptr;
ULONG __fastcall HookedGetEnumFlags(void* self) {
    const ULONG f = g_realGetEnumFlags(self);
    if (InterlockedDecrement(&g_enumLog) > 0) KEEL_INFO(L"nsenum; CDefView::_GetEnumFlags -> 0x%lX", f);
    return f;
}
__int64 __fastcall HookedDefViewOnCreate(void* self, HWND h) {
    const __int64 r = g_realDefViewOnCreate(self, h);
    if (InterlockedDecrement(&g_enumLog) > 0) KEEL_INFO(L"nsenum; CDefView::_OnCreate -> 0x%llX", (unsigned long long)r);
    return r;
}

volatile LONG g_fillDoneLog = 24;
void DumpDefViewChildren(const wchar_t* tag, HWND view) {
    if (!view || InterlockedDecrement(&g_fillDoneLog) <= 0) return;
    wchar_t line[512]; int n = 0;
    n += swprintf_s(line, L"%s view=%p visible=%d children:", tag, view, IsWindowVisible(view));
    for (HWND c = GetWindow(view, GW_CHILD); c && n < 440; c = GetWindow(c, GW_HWNDNEXT)) {
        wchar_t cls[48]{}; GetClassNameW(c, cls, 48); RECT rc{}; GetWindowRect(c, &rc);
        n += swprintf_s(line + n, 512 - n, L" [%s %p vis=%d %ldx%ld]", cls, c, IsWindowVisible(c), rc.right - rc.left, rc.bottom - rc.top);
    }
    KEEL_INFO(L"%s", line);
}
__int64 __fastcall HookedFillDone(void* self, void* a, void* b2, void* c, void* d, void* e) {
    const __int64 r = g_realFillDone(self, a, b2, c, d, e);
    if (InterlockedDecrement(&g_fillDoneLog) > 0) KEEL_INFO(L"nsenum; CDefView::_FillDone -> 0x%llX (tid %lu)", (unsigned long long)r, GetCurrentThreadId());
    DumpDefViewChildren(L"filldone:", *reinterpret_cast<HWND*>(reinterpret_cast<BYTE*>(self) + 0x268));
    return r;
}

using ShowHideFn = void(__fastcall*)(void*);
ShowHideFn g_realShowHideListView = nullptr;
void __fastcall HookedShowHideListView(void* self) {
    HWND view = *reinterpret_cast<HWND*>(reinterpret_cast<BYTE*>(self) + 0x268);
    DumpDefViewChildren(L"showhide-before:", view);
    g_realShowHideListView(self);
    DumpDefViewChildren(L"showhide-after:", view);
}

using ShouldSuppressFn = int(__fastcall*)(void*);
using UseItemsViewFn = int(__fastcall*)(void*);
ShouldSuppressFn g_realShouldSuppress = nullptr;
UseItemsViewFn g_realUseItemsView = nullptr;
int __fastcall HookedShouldSuppress(void* self) {
    const int r = g_realShouldSuppress(self);
    if (InterlockedDecrement(&g_enumLog) > 0) KEEL_INFO(L"nsenum; CDefView::_ShouldSuppressCollection -> %d", r);
    return r;
}
int __fastcall HookedUseItemsView(void* self) {
    const int r = g_realUseItemsView(self);
    if (InterlockedDecrement(&g_enumLog) > 0) KEEL_INFO(L"nsenum; CDefView::_UseItemsView -> %d", r);
    return r;
}

using SetItemCollectionFn = long(__fastcall*)(void*, void*);
using ResetRootFn = long(__fastcall*)(void*, void*, void*);
SetItemCollectionFn g_realSetItemCollection = nullptr;
ResetRootFn g_realResetRoot = nullptr;
volatile LONG g_ivLog = 40;
long __fastcall HookedSetItemCollection(void* self, void* coll) {
    const long hr = g_realSetItemCollection(self, coll);
    if (InterlockedDecrement(&g_ivLog) > 0)
        KEEL_INFO(L"itemsview; CItemsView::SetItemCollection(coll=%p) -> hr=0x%08lX", coll, (unsigned long)hr);
    return hr;
}
long __fastcall HookedResetRoot(void* view, void* rootItem, void* coll) {
    const long hr = g_realResetRoot(view, rootItem, coll);
    if (InterlockedDecrement(&g_ivLog) > 0)
        KEEL_INFO(L"itemsview; UIItemsView::_ResetRoot(root=%p coll=%p) -> hr=0x%08lX", rootItem, coll, (unsigned long)hr);
    return hr;
}

using NscAppendRootFn = long(__fastcall*)(void*, void*, ULONG, ULONG, void*);
using NscInsertRootFn = long(__fastcall*)(void*, int, void*, ULONG, ULONG, void*);
using NscInsertRootInternalFn = long(__fastcall*)(void*, void*, void*, ULONG, ULONG, void*);
NscAppendRootFn g_realNscAppendRoot = nullptr;
NscInsertRootFn g_realNscInsertRootPub = nullptr;
NscInsertRootInternalFn g_realNscInsertRootInt = nullptr;
volatile LONG g_nscLog = 60;
void ShellItemDisplayName(void* psi, wchar_t* out, size_t cch) {
    wcscpy_s(out, cch, L"(null)"); if (!psi) return;
    struct SiVtbl { void* QI; void* AddRef; void* Release; void* BindToHandler; void* GetParent; long(__stdcall* GetDisplayName)(void*, ULONG, wchar_t**); };
    __try {
        wchar_t* name = nullptr;
        if ((*reinterpret_cast<SiVtbl**>(psi))->GetDisplayName(psi, 0 , &name) == 0 && name) { wcsncpy_s(out, cch, name, _TRUNCATE); CoTaskMemFree(name); }
        else wcscpy_s(out, cch, L"(no name)");
    } __except (EXCEPTION_EXECUTE_HANDLER) { wcscpy_s(out, cch, L"(fault)"); }
}
long __fastcall HookedNscInsertRootInt(void* self, void* after, void* psi, ULONG enumFlags, ULONG style, void* filter) {
    void* ra = _ReturnAddress();
    const long hr = g_realNscInsertRootInt(self, after, psi, enumFlags, style, filter);
    if (InterlockedDecrement(&g_nscLog) > 0) {
        wchar_t nm[128]; ShellItemDisplayName(psi, nm, 128); wchar_t from[96]; FormatAddr(ra, from, 96);
        KEEL_INFO(L"nsc; CNscTree::_InsertRoot('%s' enum=0x%lX style=0x%lX) -> hr=0x%08lX from %s", nm, enumFlags, style, (unsigned long)hr, from);
    }
    return hr;
}
long __fastcall HookedNscAppendRoot(void* self, void* psi, ULONG enumFlags, ULONG style, void* filter) {
    void* ra = _ReturnAddress();
    const long hr = g_realNscAppendRoot(self, psi, enumFlags, style, filter);
    if (InterlockedDecrement(&g_nscLog) > 0) { wchar_t from[96]; FormatAddr(ra, from, 96); KEEL_INFO(L"nsc; CNscTree::AppendRoot -> hr=0x%08lX from %s", (unsigned long)hr, from); }
    return hr;
}
long __fastcall HookedNscInsertRootPub(void* self, int index, void* psi, ULONG enumFlags, ULONG style, void* filter) {
    void* ra = _ReturnAddress();
    const long hr = g_realNscInsertRootPub(self, index, psi, enumFlags, style, filter);
    if (InterlockedDecrement(&g_nscLog) > 0) { wchar_t from[96]; FormatAddr(ra, from, 96); KEEL_INFO(L"nsc; CNscTree::InsertRoot(index=%d) -> hr=0x%08lX from %s", index, (unsigned long)hr, from); }
    return hr;
}

using ShouldPinItemFn = int(__fastcall*)(void*, void*, UINT);
ShouldPinItemFn g_realShouldPinItem = nullptr;
volatile LONG g_pinLog = 60;
void ChildDisplayName(void* psf, void* pidl, wchar_t* out, size_t cch) {
    wcscpy_s(out, cch, L"(?)"); if (!psf || !pidl) return;
    struct SfVtbl { void* q; void* a; void* r; void* parse; void* enumo; void* bto; void* bts; void* cmp; void* cvo; void* gao; void* guio;
                    long(__stdcall* GetDisplayNameOf)(void*, void*, DWORD, void*); };
    using StrRetToBufWFn = long(__stdcall*)(void*, void*, wchar_t*, UINT);
    static StrRetToBufWFn strRetToBuf = nullptr;
    if (!strRetToBuf) { if (HMODULE s = GetModuleHandleW(L"shlwapi.dll")) strRetToBuf = reinterpret_cast<StrRetToBufWFn>(GetProcAddress(s, "StrRetToBufW")); }
    if (!strRetToBuf) return;
    __try {
        BYTE strret[272]{};
        if ((*reinterpret_cast<SfVtbl**>(psf))->GetDisplayNameOf(psf, pidl, 0 , strret) == 0)
            strRetToBuf(strret, pidl, out, static_cast<UINT>(cch));
    } __except (EXCEPTION_EXECUTE_HANDLER) { wcscpy_s(out, cch, L"(fault)"); }
}
int __fastcall HookedShouldPinItem(void* psf, void* pidl, UINT flag) {
    const int r = g_realShouldPinItem(psf, pidl, flag);
    if (InterlockedDecrement(&g_pinLog) > 0) { wchar_t nm[128]; ChildDisplayName(psf, pidl, nm, 128); KEEL_INFO(L"nsc; ShouldPinItem('%s', flag=%u) -> %d", nm, flag, r); }
    return r;
}

void InstallItemsViewProbe(HMODULE expframe) {
    if (g_realSetItemCollection || !expframe) return;
    BYTE* b = reinterpret_cast<BYTE*>(expframe);
    g_realSetItemCollection = reinterpret_cast<SetItemCollectionFn>(b + 0x34bb8);
    g_realResetRoot = reinterpret_cast<ResetRootFn>(b + 0x33e5c);
    g_realNscAppendRoot = reinterpret_cast<NscAppendRootFn>(b + 0x3d390);
    g_realNscInsertRootPub = reinterpret_cast<NscInsertRootFn>(b + 0xcf530);
    g_realNscInsertRootInt = reinterpret_cast<NscInsertRootInternalFn>(b + 0x3d3c8);
    g_realShouldPinItem = reinterpret_cast<ShouldPinItemFn>(b + 0x3e920);
    DetourAttach(reinterpret_cast<PVOID*>(&g_realShouldPinItem), reinterpret_cast<PVOID>(HookedShouldPinItem));
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realSetItemCollection), reinterpret_cast<PVOID>(HookedSetItemCollection));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realResetRoot), reinterpret_cast<PVOID>(HookedResetRoot));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNscAppendRoot), reinterpret_cast<PVOID>(HookedNscAppendRoot));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNscInsertRootPub), reinterpret_cast<PVOID>(HookedNscInsertRootPub));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNscInsertRootInt), reinterpret_cast<PVOID>(HookedNscInsertRootInt));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"itemsview; population probe installed (commit=%ld)", e);
}

using EnumNextFn = long(__fastcall*)(void*, ULONG, void**, ULONG*);
using EnumToDpaFn = long(__fastcall*)(void*, void*, void*, void*, int, void*);
using PushBatchFn = void(__fastcall*)(void*, void*, void*, void*, void*);
using TaskFilterFn = int(__fastcall*)(void*, void*, void*, void*);
using LoadCplFn = void*(__fastcall*)(const wchar_t*, int);
using GetModulesFn = int(__fastcall*)(void*);
EnumNextFn g_realCplNext = nullptr, g_realRegEnumNext = nullptr;
EnumToDpaFn g_realEnumToDpa = nullptr;
PushBatchFn g_realPushBatch = nullptr;
TaskFilterFn g_realTaskFilter = nullptr;
LoadCplFn g_realLoadCpl = nullptr;
GetModulesFn g_realGetModules = nullptr;
volatile LONG g_fillLog = 200;
volatile LONG g_cplNextOk = 0, g_regNextOk = 0, g_filteredOut = 0, g_filterCalls = 0;
int DsaCount(void* cdsa) {
    if (!cdsa) return -1;
    void* h = *reinterpret_cast<void**>(cdsa);
    return h ? *reinterpret_cast<int*>(h) : -2;
}
long __fastcall HookedCplNext(void* self, ULONG celt, void** rgelt, ULONG* fetched) {
    const long hr = g_realCplNext(self, celt, rgelt, fetched);
    if (hr == 0) { const LONG n = InterlockedIncrement(&g_cplNextOk); if (n <= 3 && InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CControlPanelEnum::Next -> S_OK (#%ld)", n); }
    else if (InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CControlPanelEnum::Next -> 0x%08lX after %ld items", (unsigned long)hr, g_cplNextOk);
    return hr;
}
long __fastcall HookedRegEnumNext(void* self, ULONG celt, void** rgelt, ULONG* fetched) {
    const long hr = g_realRegEnumNext(self, celt, rgelt, fetched);
    if (hr == 0) { const LONG n = InterlockedIncrement(&g_regNextOk); if (n <= 3 && InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CRegFolderEnum::Next -> S_OK (#%ld)", n); }
    else if (InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CRegFolderEnum::Next -> 0x%08lX after %ld items", (unsigned long)hr, g_regNextOk);
    return hr;
}
long __fastcall HookedEnumToDpa(void* self, void* pe, void* store, void* folder, int filter, void* out) {
    const long hr = g_realEnumToDpa(self, pe, store, folder, filter, out);
    if (InterlockedDecrement(&g_fillLog) > 0)
        KEEL_INFO(L"fill; CEnumTask::_EnumItemsToDPA(filter=%d) -> hr=0x%08lX items=%d (filtered %ld of %ld)", filter, (unsigned long)hr, DsaCount(out), g_filteredOut, g_filterCalls);
    return hr;
}
void __fastcall HookedPushBatch(void* self, void* folder, void* a, void* b, void* store) {
    if (InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CEnumTask::_PushBatchToView(items=%d, items2=%d)", DsaCount(a), DsaCount(b));
    g_realPushBatch(self, folder, a, b, store);
}
int __fastcall HookedTaskFilter(void* self, void* store, void* key, void* folder) {
    const int r = g_realTaskFilter(self, store, key, folder);
    InterlockedIncrement(&g_filterCalls); if (r) InterlockedIncrement(&g_filteredOut);
    return r;
}
void* __fastcall HookedLoadCpl(const wchar_t* path, int flag) {
    const ULONGLONG t0 = GetTickCount64();
    void* m = g_realLoadCpl(path, flag);
    if (InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CPL_LoadCPLModule('%s') -> %p in %llu ms", path ? path : L"(null)", m, GetTickCount64() - t0);
    return m;
}
int __fastcall HookedGetModules(void* cd) {
    const int r = g_realGetModules(cd);
    int n = -1; if (cd) { void* h = *reinterpret_cast<void**>(reinterpret_cast<BYTE*>(cd) + 8); if (h) n = *reinterpret_cast<int*>(h); }
    if (InterlockedDecrement(&g_fillLog) > 0) KEEL_INFO(L"fill; CPLD_GetModules -> %d, modules=%d", r, n);
    return r;
}

using QiStartedFn = long(__fastcall*)(void*, ULONG, long);

using QiBatchFn = long(__fastcall*)(void*, ULONG, void*, void*, void*, void*, void*, int, void*);
using QiCompletedFn = long(__fastcall*)(void*, ULONG, long);
using VoidThisFn = void(__fastcall*)(void*);
using SinkPrepareDoneFn = long(__fastcall*)(void*, UINT, long);
using SinkCountDoneFn = long(__fastcall*)(void*, UINT, int, long);
using CollWndProcFn = __int64(__fastcall*)(HWND, UINT, WPARAM, LPARAM);
using OnCollCreatedFn = long(__fastcall*)(void*);
QiStartedFn g_realQiStarted = nullptr;
QiBatchFn g_realQiBatch = nullptr;
QiCompletedFn g_realQiCompleted = nullptr;
VoidThisFn g_realFireGetCountDone = nullptr, g_realDsvDispatch = nullptr;
SinkPrepareDoneFn g_realSinkPrepareDone = nullptr;
SinkCountDoneFn g_realSinkCountDone = nullptr;
CollWndProcFn g_realCollWndProc = nullptr;
OnCollCreatedFn g_realOnCollCreated = nullptr;
volatile LONG g_collLog = 120, g_dsvDispatch = 0, g_collMsg4a2 = 0;
void DescribeHwnd(HWND h, wchar_t* out, size_t cch) {
    DWORD pid = 0; const DWORD tid = h ? GetWindowThreadProcessId(h, &pid) : 0;
    swprintf_s(out, cch, L"hwnd=%p valid=%d ownerTid=%lu curTid=%lu", h, h ? IsWindow(h) : 0, tid, GetCurrentThreadId());
}
long __fastcall HookedQiStarted(void* self, ULONG op, long hr) {
    const long r = g_realQiStarted(self, op, hr);
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; OnQIOperationStarted(op=%lu hr=0x%08lX) -> 0x%08lX", op, (unsigned long)hr, (unsigned long)r);
    return r;
}
long __fastcall HookedQiBatch(void* self, ULONG op, void* a, void* b, void* chg, void* cats, void* pkey, int g, void* guid) {
    const long r = g_realQiBatch(self, op, a, b, chg, cats, pkey, g, guid);
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; OnQIOperationNextBatch(op=%lu items=%d items2=%d) -> 0x%08lX", op, DsaCount(a), DsaCount(b), (unsigned long)r);
    return r;
}
long __fastcall HookedQiCompleted(void* self, ULONG op, long hr) {
    const long r = g_realQiCompleted(self, op, hr);
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; OnQIOperationCompleted(op=%lu hr=0x%08lX) -> 0x%08lX", op, (unsigned long)hr, (unsigned long)r);
    return r;
}
void __fastcall HookedFireGetCountDone(void* self) {
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; CDefCollection::_FireGetCountDone");
    g_realFireGetCountDone(self);
}
void __fastcall HookedDsvDispatch(void* self) {
    const LONG n = InterlockedIncrement(&g_dsvDispatch);
    if ((n <= 5 || n % 50 == 0) && InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; _OnDSVDispatchQueueItem #%ld", n);
    g_realDsvDispatch(self);
}
long __fastcall HookedSinkPrepareDone(void* self, UINT a, long hr) {
    wchar_t d[128]; DescribeHwnd(*reinterpret_cast<HWND*>(reinterpret_cast<BYTE*>(self) + 0x18), d, 128);
    const long r = g_realSinkPrepareDone(self, a, hr);
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; CDefViewSink::OnPrepareDone(hr=0x%08lX) posts 0x4ad to %s", (unsigned long)hr, d);
    return r;
}
long __fastcall HookedSinkCountDone(void* self, UINT a, int type, long hr) {
    wchar_t d[128]; DescribeHwnd(*reinterpret_cast<HWND*>(reinterpret_cast<BYTE*>(self) + 0x18), d, 128);
    const long r = g_realSinkCountDone(self, a, type, hr);
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; CDefViewSink::OnGetCountDone(count=%u type=%d) posts to %s", a, type, d);
    return r;
}
__int64 __fastcall HookedCollWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == 0x4a2) { const LONG n = InterlockedIncrement(&g_collMsg4a2); if (n <= 3 && InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; CDefCollection window got 0x4a2 #%ld (tid %lu)", n, GetCurrentThreadId()); }
    return g_realCollWndProc(h, m, w, l);
}

using GetItemCountFn = unsigned int(__fastcall*)(void*, int);
GetItemCountFn g_realGetItemCount = nullptr;

using IncludeItemFn = int(__fastcall*)(void*, void*, void*);
using CollFilterItemFn = void(__fastcall*)(void*, unsigned long long);
using ContentsChangedFn = void(__fastcall*)(void*, int);
IncludeItemFn g_realIncludeItem = nullptr;
CollFilterItemFn g_realCollFilterItem = nullptr;
ContentsChangedFn g_realContentsChanged = nullptr;
volatile LONG g_includeYes = 0, g_includeNo = 0, g_collFilterCalls = 0;
int __fastcall HookedIncludeItem(void* self, void* store, void* key) {
    const int r = g_realIncludeItem(self, store, key);
    InterlockedIncrement(r ? &g_includeYes : &g_includeNo);
    return r;
}
void __fastcall HookedCollFilterItem(void* self, unsigned long long key) {
    InterlockedIncrement(&g_collFilterCalls);
    g_realCollFilterItem(self, key);
}
void __fastcall HookedContentsChanged(void* self, int flags) {
    if (InterlockedDecrement(&g_collLog) > 0) KEEL_INFO(L"coll; CDefView::_OnContentsChanged(flags=%d) (tid %lu)", flags, GetCurrentThreadId());
    g_realContentsChanged(self, flags);
}
long __fastcall HookedOnCollCreated(void* self) {
    BYTE* p = reinterpret_cast<BYTE*>(self);
    void* host = *reinterpret_cast<void**>(p + 0x4b8);
    const unsigned int n0 = (host && g_realGetItemCount) ? g_realGetItemCount(host, 0) : 0xFFFFFFFF;
    const DWORD before = *reinterpret_cast<DWORD*>(p + 0x310);
    const long r = g_realOnCollCreated(self);
    const DWORD after = *reinterpret_cast<DWORD*>(p + 0x310);
    const unsigned int n1 = (host && g_realGetItemCount) ? g_realGetItemCount(host, 0) : 0xFFFFFFFF;
    if (InterlockedDecrement(&g_collLog) > 0)
        KEEL_INFO(L"coll; CDefView::_OnCollectionCreated -> 0x%08lX host=%p hostItems before=%u after=%u flags before=0x%08lX after=0x%08lX | include yes=%ld no=%ld filterItem=%ld (tid %lu)",
                  (unsigned long)r, host, n0, n1, before, after, g_includeYes, g_includeNo, g_collFilterCalls, GetCurrentThreadId());
    return r;
}

using DuiCreateElementFn = long(__fastcall*)(void*, const wchar_t*, void*, void*, DWORD*, void**);
using DuiSetXmlIdFn = long(__fastcall*)(void*, UINT, HINSTANCE, HINSTANCE);
using DuiSetXmlNameFn = long(__fastcall*)(void*, const wchar_t*, HINSTANCE, HINSTANCE);
DuiCreateElementFn g_realDuiCreateElement = nullptr;
DuiSetXmlIdFn g_realDuiSetXmlId = nullptr;
DuiSetXmlNameFn g_realDuiSetXmlName = nullptr;
volatile LONG g_duiLog = 160;
void ModuleLeaf(HINSTANCE h, wchar_t* out, size_t cch) {
    wchar_t path[MAX_PATH]{}; out[0] = 0;
    if (h && GetModuleFileNameW(h, path, MAX_PATH)) { const wchar_t* l = wcsrchr(path, L'\\'); wcscpy_s(out, cch, l ? l + 1 : path); }
    else swprintf_s(out, cch, L"%p", h);
}

void SafeStr(const wchar_t* s, wchar_t* out, size_t cch) {
    if (!s) { wcscpy_s(out, cch, L"(null)"); return; }
    if ((reinterpret_cast<ULONG_PTR>(s) >> 16) == 0) { swprintf_s(out, cch, L"#%u", (unsigned)reinterpret_cast<ULONG_PTR>(s)); return; }
    __try { wcsncpy_s(out, cch, s, _TRUNCATE); } __except (EXCEPTION_EXECUTE_HANDLER) { swprintf_s(out, cch, L"(bad %p)", s); }
}
long __fastcall HookedDuiCreateElement(void* self, const wchar_t* resid, void* subst, void* parent, DWORD* cookie, void** out) {
    const long hr = g_realDuiCreateElement(self, resid, subst, parent, cookie, out);
    wchar_t r[96]; SafeStr(resid, r, 96);
    const bool interesting = wcsstr(r, L"ControlPanel") || wcsstr(r, L"AllItems") || wcsstr(r, L"HomePage") || wcsstr(r, L"Applet") || wcsstr(r, L"Category") || wcsstr(r, L"NavPane") || wcsstr(r, L"main") || wcsstr(r, L"Frame") || wcsstr(r, L"Layout") || wcsstr(r, L"Panel");
    if ((hr < 0 || interesting) && InterlockedDecrement(&g_duiLog) > 0)
        KEEL_INFO(L"dui; CreateElement('%s') -> hr=0x%08lX elem=%p (tid %lu)", r, (unsigned long)hr, out ? *out : nullptr, GetCurrentThreadId());
    return hr;
}
long __fastcall HookedDuiSetXmlId(void* self, UINT id, HINSTANCE hRes, HINSTANCE hTheme) {
    const long hr = g_realDuiSetXmlId(self, id, hRes, hTheme);
    if (InterlockedDecrement(&g_duiLog) > 0) { wchar_t m[64], t[64]; ModuleLeaf(hRes, m, 64); ModuleLeaf(hTheme, t, 64); KEEL_INFO(L"dui; SetXMLFromResource(#%u of %s, theme %s) -> hr=0x%08lX", id, m, t, (unsigned long)hr); }
    return hr;
}
long __fastcall HookedDuiSetXmlName(void* self, const wchar_t* name, HINSTANCE hRes, HINSTANCE hTheme) {
    const long hr = g_realDuiSetXmlName(self, name, hRes, hTheme);
    if (InterlockedDecrement(&g_duiLog) > 0) { wchar_t m[64], n[96]; ModuleLeaf(hRes, m, 64); SafeStr(name, n, 96); KEEL_INFO(L"dui; SetXMLFromResource('%s' of %s) -> hr=0x%08lX", n, m, (unsigned long)hr); }
    return hr;
}

using DuiSendParseErrorFn = void(__fastcall*)(void*, const wchar_t*, const wchar_t*, int, int, long);
DuiSendParseErrorFn g_realDuiSendParseError = nullptr;
void LogThemeState();
void __fastcall HookedDuiSendParseError(void* self, const wchar_t* msg, const wchar_t* detail, int line, int col, long hr) {
    if (InterlockedDecrement(&g_duiLog) > 0)
        KEEL_WARN(L"dui; PARSE ERROR '%s' detail '%s' at %d:%d hr=0x%08lX parser+0x64=%d (tid %lu)", msg ? msg : L"", detail ? detail : L"", line, col, (unsigned long)hr,
                  self ? *reinterpret_cast<int*>(reinterpret_cast<BYTE*>(self) + 0x64) : -1, GetCurrentThreadId());
    static LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0) LogThemeState();
    g_realDuiSendParseError(self, msg, detail, line, col, hr);
}
void InstallDuiProbe(HMODULE dui70) {
    if (g_realDuiCreateElement || !dui70) return;
    BYTE* b = reinterpret_cast<BYTE*>(dui70);
    g_realDuiCreateElement = reinterpret_cast<DuiCreateElementFn>(b + 0xa624);
    g_realDuiSetXmlId = reinterpret_cast<DuiSetXmlIdFn>(b + 0x1effc);
    g_realDuiSetXmlName = reinterpret_cast<DuiSetXmlNameFn>(b + 0x1ee00);
    g_realDuiSendParseError = reinterpret_cast<DuiSendParseErrorFn>(b + 0x2e9f8);
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDuiCreateElement), reinterpret_cast<PVOID>(HookedDuiCreateElement));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDuiSetXmlId), reinterpret_cast<PVOID>(HookedDuiSetXmlId));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDuiSetXmlName), reinterpret_cast<PVOID>(HookedDuiSetXmlName));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDuiSendParseError), reinterpret_cast<PVOID>(HookedDuiSendParseError));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"dui; parser probe installed (commit=%ld)", e);
}

using GetCatOfPageFn = long(__cdecl*)(void*, int*);
using AddAppletsFn = long(__fastcall*)(void*, void*, void*, bool);
using ExecAppletFn = long(__fastcall*)(void*, void*);
GetCatOfPageFn g_realGetCatOfPage = nullptr;
AddAppletsFn g_realAddApplets = nullptr;
ExecAppletFn g_realExecApplet = nullptr;
volatile LONG g_catLog = 80;
void PidlName(void* pidl, wchar_t* out, size_t cch) {
    wcscpy_s(out, cch, L"(?)"); if (!pidl) return;
    using SHGetNameFn = long(__stdcall*)(void*, DWORD, wchar_t**);
    static SHGetNameFn getName = nullptr;
    if (!getName) { HMODULE s = GetModuleHandleW(L"shell32.dll"); if (s) getName = reinterpret_cast<SHGetNameFn>(GetProcAddress(s, "SHGetNameFromIDList")); }
    if (!getName) return;
    __try { wchar_t* n = nullptr; if (getName(pidl, 0x00028000 , &n) == 0 && n) { wcsncpy_s(out, cch, n, _TRUNCATE); CoTaskMemFree(n); } }
    __except (EXCEPTION_EXECUTE_HANDLER) { wcscpy_s(out, cch, L"(fault)"); }
}
long __cdecl HookedGetCatOfPage(void* pidl, int* cat) {
    const long hr = g_realGetCatOfPage(pidl, cat);
    if (InterlockedDecrement(&g_catLog) > 0) {
        wchar_t nm[260]; PidlName(pidl, nm, 260);
        KEEL_INFO(L"cpl; CPL_GetCategoryOfPage('%s') -> hr=0x%08lX category=%d", nm, (unsigned long)hr, cat ? *cat : -999);
    }
    return hr;
}
long __fastcall HookedAddApplets(void* self, void* psf, void* pe, bool slow) {
    const long hr = g_realAddApplets(self, psf, pe, slow);
    if (InterlockedDecrement(&g_catLog) > 0) {
        BYTE* p = reinterpret_cast<BYTE*>(self);
        wchar_t line[400]; int n = swprintf_s(line, L"cpl; _AddAppletsToCategories(slow=%d) -> hr=0x%08lX per-category counts", (int)slow, (unsigned long)hr);
        for (int c = 0; c < 12 && n < 340; ++c) {
            void* h = *reinterpret_cast<void**>(p + 0x20 + c * 8);
            n += swprintf_s(line + n, 400 - n, L" [%d]=%d", c, h ? *reinterpret_cast<int*>(h) : -1);
        }
        KEEL_INFO(L"%s", line);
    }
    return hr;
}
long __fastcall HookedExecApplet(void* self, void* pidl) {
    wchar_t nm[260]; PidlName(pidl, nm, 260);
    const long hr = g_realExecApplet(self, pidl);
    if (InterlockedDecrement(&g_catLog) > 0) KEEL_INFO(L"cpl; _ExecuteApplet('%s') -> hr=0x%08lX", nm, (unsigned long)hr);
    return hr;
}

using DuiOnInputFn = void(__fastcall*)(void*, void*);
using DuiOnEventFn = void(__fastcall*)(void*, void*);
using CatNavigateFn = long(__fastcall*)(void*, void*);
using NavNavigateFn = void(__fastcall*)(void*, void*);
DuiOnInputFn g_realCplLinkOnInput = nullptr;
DuiOnEventFn g_realCatOnEvent = nullptr, g_realNavOnEvent = nullptr;
CatNavigateFn g_realCatNavigate = nullptr;
NavNavigateFn g_realNavNavigate = nullptr;
volatile LONG g_clickLog = 120;
void __fastcall HookedCplLinkOnInput(void* self, void* ie) {
    if (ie && InterlockedDecrement(&g_clickLog) > 0) {
        int* p = reinterpret_cast<int*>(ie);
        KEEL_INFO(L"click; CControlPanelLink::OnInput stage=%d device=%d code=%d pt=(%d,%d)", p[3], p[4], p[5], p[8], p[9]);
    }
    g_realCplLinkOnInput(self, ie);
}
void __fastcall HookedCatOnEvent(void* self, void* ev) {
    if (ev && InterlockedDecrement(&g_clickLog) > 0) {
        int* p = reinterpret_cast<int*>(ev);
        KEEL_INFO(L"click; CategoryModule::OnEvent type=%d handled=%d button=%d", p[5], p[4], p[8]);
    }
    g_realCatOnEvent(self, ev);
}
void __fastcall HookedNavOnEvent(void* self, void* ev) {
    if (ev && InterlockedDecrement(&g_clickLog) > 0) {
        int* p = reinterpret_cast<int*>(ev);
        KEEL_INFO(L"click; NavModule::OnEvent type=%d handled=%d button=%d", p[5], p[4], p[8]);
    }
    g_realNavOnEvent(self, ev);
}
long __fastcall HookedCatNavigate(void* self, void* pidl) {
    wchar_t nm[260]; PidlName(pidl, nm, 260);
    const long hr = g_realCatNavigate(self, pidl);
    if (InterlockedDecrement(&g_clickLog) > 0) KEEL_INFO(L"click; CategoryModule::_Navigate('%s') -> hr=0x%08lX", nm, (unsigned long)hr);
    return hr;
}
void __fastcall HookedNavNavigate(void* self, void* pidl) {
    wchar_t nm[260]; PidlName(pidl, nm, 260);
    g_realNavNavigate(self, pidl);
    if (InterlockedDecrement(&g_clickLog) > 0) KEEL_INFO(L"click; NavModule::_Navigate('%s')", nm);
}

using UpdateWowCacheFn = long(__fastcall*)(void*);
using GetRegModulesFn = void(__fastcall*)(int, void*);
UpdateWowCacheFn g_realUpdateWowCache = nullptr;
GetRegModulesFn g_realGetRegModules = nullptr;
volatile LONG g_wowLog = 8;
long __fastcall HookedUpdateWowCache(void* self) {
    const long hr = g_realUpdateWowCache(self);
    if (hr >= 0 || !g_realGetRegModules) return hr;
    BYTE* p = reinterpret_cast<BYTE*>(self);
    if (GetSystemMetrics(67) == 0) g_realGetRegModules(1, p + 0x78);
    p[0xa4] = 1;
    if (InterlockedDecrement(&g_wowLog) > 0)
        KEEL_INFO(L"nsenum; _UpdateWowCache failed 0x%08lX (no 32-bit CPL host) so loaded the registry applets instead", (unsigned long)hr);
    return 0;
}

void InstallShellEnumProbe(HMODULE shell32) {
    if (g_realCplEnumObjects || !shell32) return;
    BYTE* b = reinterpret_cast<BYTE*>(shell32);
    g_realCplEnumObjects = reinterpret_cast<EnumObjectsFn>(b + 0xe5d54);
    g_realRegEnumObjects = reinterpret_cast<EnumObjectsFn>(b + 0x371c8);
    g_realDeskEnumObjects = reinterpret_cast<EnumObjectsFn>(b + 0x3f120);
    g_realCplCreateView = reinterpret_cast<CreateViewObjectFn>(b + 0xd65f0);
    g_realGetEnumFlags = reinterpret_cast<GetEnumFlagsFn>(b + 0x38b94);
    g_realDefViewOnCreate = reinterpret_cast<DefViewOnCreateFn>(b + 0x3947c);
    g_realFillDone = reinterpret_cast<FillDoneFn>(b + 0x47fd0);
    g_realShouldSuppress = reinterpret_cast<ShouldSuppressFn>(b + 0x37350);
    g_realUseItemsView = reinterpret_cast<UseItemsViewFn>(b + 0x14b704);
    g_realUpdateWowCache = reinterpret_cast<UpdateWowCacheFn>(b + 0xecac4);
    g_realGetRegModules = reinterpret_cast<GetRegModulesFn>(b + 0xe9478);
    g_realCplLinkOnInput = reinterpret_cast<DuiOnInputFn>(b + 0xd05f0);
    g_realCatOnEvent = reinterpret_cast<DuiOnEventFn>(b + 0xcf534);
    g_realNavOnEvent = reinterpret_cast<DuiOnEventFn>(b + 0xcbf60);
    g_realCatNavigate = reinterpret_cast<CatNavigateFn>(b + 0xccb30);
    g_realNavNavigate = reinterpret_cast<NavNavigateFn>(b + 0x33e0f4);
    g_realGetCatOfPage = reinterpret_cast<GetCatOfPageFn>(b + 0xe7da8);
    g_realAddApplets = reinterpret_cast<AddAppletsFn>(b + 0xe9090);
    g_realExecApplet = reinterpret_cast<ExecAppletFn>(b + 0xcff4c);
    g_realCplNext = reinterpret_cast<EnumNextFn>(b + 0xe97a8);
    g_realRegEnumNext = reinterpret_cast<EnumNextFn>(b + 0x36d60);
    g_realEnumToDpa = reinterpret_cast<EnumToDpaFn>(b + 0x38b784);
    g_realPushBatch = reinterpret_cast<PushBatchFn>(b + 0x345cc);
    g_realTaskFilter = reinterpret_cast<TaskFilterFn>(b + 0x3e79c);
    g_realLoadCpl = reinterpret_cast<LoadCplFn>(b + 0xecefc);
    g_realGetModules = reinterpret_cast<GetModulesFn>(b + 0xe5f04);
    g_realQiStarted = reinterpret_cast<QiStartedFn>(b + 0x3f6f0);
    g_realQiBatch = reinterpret_cast<QiBatchFn>(b + 0x3f8c0);
    g_realQiCompleted = reinterpret_cast<QiCompletedFn>(b + 0x41640);
    g_realFireGetCountDone = reinterpret_cast<VoidThisFn>(b + 0x466f0);
    g_realDsvDispatch = reinterpret_cast<VoidThisFn>(b + 0x454b4);
    g_realSinkPrepareDone = reinterpret_cast<SinkPrepareDoneFn>(b + 0x3f630);
    g_realSinkCountDone = reinterpret_cast<SinkCountDoneFn>(b + 0x49600);
    g_realCollWndProc = reinterpret_cast<CollWndProcFn>(b + 0x4cc30);
    g_realOnCollCreated = reinterpret_cast<OnCollCreatedFn>(b + 0x47ee8);
    g_realShowHideListView = reinterpret_cast<ShowHideFn>(b + 0x43b68);
    g_realGetItemCount = reinterpret_cast<GetItemCountFn>(b + 0x4a988);
    g_realIncludeItem = reinterpret_cast<IncludeItemFn>(b + 0x3f570);
    g_realCollFilterItem = reinterpret_cast<CollFilterItemFn>(b + 0x24330);
    g_realContentsChanged = reinterpret_cast<ContentsChangedFn>(b + 0x46070);
    g_realSHRestricted   = reinterpret_cast<SHRestrictedFn>(GetProcAddress(shell32, MAKEINTRESOURCEA(100)));
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCplEnumObjects), reinterpret_cast<PVOID>(HookedCplEnumObjects));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realRegEnumObjects), reinterpret_cast<PVOID>(HookedRegEnumObjects));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDeskEnumObjects), reinterpret_cast<PVOID>(HookedDeskEnumObjects));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCplCreateView), reinterpret_cast<PVOID>(HookedCplCreateView));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realGetEnumFlags), reinterpret_cast<PVOID>(HookedGetEnumFlags));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDefViewOnCreate), reinterpret_cast<PVOID>(HookedDefViewOnCreate));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realFillDone), reinterpret_cast<PVOID>(HookedFillDone));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realShouldSuppress), reinterpret_cast<PVOID>(HookedShouldSuppress));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realUseItemsView), reinterpret_cast<PVOID>(HookedUseItemsView));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realUpdateWowCache), reinterpret_cast<PVOID>(HookedUpdateWowCache));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCplLinkOnInput), reinterpret_cast<PVOID>(HookedCplLinkOnInput));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCatOnEvent), reinterpret_cast<PVOID>(HookedCatOnEvent));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNavOnEvent), reinterpret_cast<PVOID>(HookedNavOnEvent));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCatNavigate), reinterpret_cast<PVOID>(HookedCatNavigate));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNavNavigate), reinterpret_cast<PVOID>(HookedNavNavigate));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realGetCatOfPage), reinterpret_cast<PVOID>(HookedGetCatOfPage));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realAddApplets), reinterpret_cast<PVOID>(HookedAddApplets));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realExecApplet), reinterpret_cast<PVOID>(HookedExecApplet));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCplNext), reinterpret_cast<PVOID>(HookedCplNext));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realRegEnumNext), reinterpret_cast<PVOID>(HookedRegEnumNext));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realEnumToDpa), reinterpret_cast<PVOID>(HookedEnumToDpa));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realPushBatch), reinterpret_cast<PVOID>(HookedPushBatch));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realTaskFilter), reinterpret_cast<PVOID>(HookedTaskFilter));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realLoadCpl), reinterpret_cast<PVOID>(HookedLoadCpl));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realGetModules), reinterpret_cast<PVOID>(HookedGetModules));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realQiStarted), reinterpret_cast<PVOID>(HookedQiStarted));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realQiBatch), reinterpret_cast<PVOID>(HookedQiBatch));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realQiCompleted), reinterpret_cast<PVOID>(HookedQiCompleted));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realFireGetCountDone), reinterpret_cast<PVOID>(HookedFireGetCountDone));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDsvDispatch), reinterpret_cast<PVOID>(HookedDsvDispatch));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realSinkPrepareDone), reinterpret_cast<PVOID>(HookedSinkPrepareDone));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realSinkCountDone), reinterpret_cast<PVOID>(HookedSinkCountDone));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCollWndProc), reinterpret_cast<PVOID>(HookedCollWndProc));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realOnCollCreated), reinterpret_cast<PVOID>(HookedOnCollCreated));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realShowHideListView), reinterpret_cast<PVOID>(HookedShowHideListView));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realIncludeItem), reinterpret_cast<PVOID>(HookedIncludeItem));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCollFilterItem), reinterpret_cast<PVOID>(HookedCollFilterItem));
    DetourAttach(reinterpret_cast<PVOID*>(&g_realContentsChanged), reinterpret_cast<PVOID>(HookedContentsChanged));
    if (g_realSHRestricted) DetourAttach(reinterpret_cast<PVOID*>(&g_realSHRestricted), reinterpret_cast<PVOID>(HookedSHRestricted));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"nsenum; namespace enumeration probe installed (commit=%ld, SHRestricted=%p)", e, g_realSHRestricted);
}

void InstallDefViewProbe(HMODULE shell32) {
    if (g_realDefViewWndProc || !shell32) return;

    BYTE* p = reinterpret_cast<BYTE*>(shell32) + 0xa0ca0;
    static const BYTE kPro[] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08 };
    if (memcmp(p, kPro, sizeof(kPro)) != 0) { KEEL_WARN(L"wm34; shell32!CDefView::s_WndProc prologue mismatch at %p so probe not installed", p); return; }
    g_realDefViewWndProc = reinterpret_cast<DefViewWndProcFn>(p);
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realDefViewWndProc), reinterpret_cast<PVOID>(HookedDefViewWndProc));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"wm34; CDefView::s_WndProc probe @%p (commit=%ld)", p, e);
}

PVOID g_realTextInputHostCreate = nullptr, g_realTsfOneCreate = nullptr;
volatile LONG g_tifStubLog = 6;
long WINAPI StubTextInputHostCreate() { if (InterlockedDecrement(&g_tifStubLog) > 0) KEEL_INFO(L"tsf; TextInputHostCreate -> E_NOTIMPL (no TextInputHost under keeldwm)"); return (long)0x80004001; }
long WINAPI StubTsfOneCreate()        { if (InterlockedDecrement(&g_tifStubLog) > 0) KEEL_INFO(L"tsf; TsfOneCreate -> E_NOTIMPL (no TextInputHost under keeldwm)"); return (long)0x80004001; }

struct KLDR_DLL_NOTIFICATION_DATA { ULONG Flags; const KUNICODE_STRING* FullDllName; const KUNICODE_STRING* BaseDllName; PVOID DllBase; ULONG SizeOfImage; };
using LdrDllNotificationFn = VOID(CALLBACK*)(ULONG, const KLDR_DLL_NOTIFICATION_DATA*, PVOID);
using LdrRegisterDllNotificationFn = long(NTAPI*)(ULONG, LdrDllNotificationFn, PVOID, PVOID*);
VOID CALLBACK KeelDllNotification(ULONG reason, const KLDR_DLL_NOTIFICATION_DATA* d, PVOID) {
    if (reason != 1  || !d || !d->BaseDllName || !d->BaseDllName->Buffer) return;
    if (_wcsnicmp(d->BaseDllName->Buffer, L"textinputframework.dll", d->BaseDllName->Length / 2) == 0)
        InstallTextInputHostStubs((HMODULE)d->DllBase);
}
void WatchTextInputFramework() {
    if (HMODULE m = GetModuleHandleW(L"textinputframework.dll")) InstallTextInputHostStubs(m);
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto reg = nt ? (LdrRegisterDllNotificationFn)GetProcAddress(nt, "LdrRegisterDllNotification") : nullptr;
    PVOID cookie = nullptr;
    const long st = reg ? reg(0, KeelDllNotification, nullptr, &cookie) : -1;
    KEEL_INFO(L"tsf; LdrRegisterDllNotification -> 0x%08lX (watching for textinputframework.dll)", (unsigned long)st);
}

void InstallTextInputHostStubs(HMODULE tif) {
    if (g_realTextInputHostCreate || !tif) return;
    wchar_t p[MAX_PATH]{}; GetModuleFileNameW(tif, p, MAX_PATH);
    const wchar_t* leaf = wcsrchr(p, L'\\'); leaf = leaf ? leaf + 1 : p;
    if (_wcsicmp(leaf, L"textinputframework.dll") != 0) return;
    g_realTextInputHostCreate = GetProcAddress(tif, "TextInputHostCreate");
    g_realTsfOneCreate = GetProcAddress(tif, "TsfOneCreate");
    if (!g_realTextInputHostCreate) { KEEL_WARN(L"tsf; textinputframework!TextInputHostCreate not found so hang guard not installed"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(&g_realTextInputHostCreate, (PVOID)StubTextInputHostCreate);
    if (g_realTsfOneCreate) DetourAttach(&g_realTsfOneCreate, (PVOID)StubTsfOneCreate);
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"tsf; TextInputHostCreate/TsfOneCreate stubbed in %s (commit=%ld)", p, e);
}

struct CacheLiteral { const wchar_t* module; const wchar_t* from; const wchar_t* to; };
// Win7 and Win10 propsys and structuredquery share these caches with incompatible layouts, so the Win7 copies get their own
const CacheLiteral kWin7CacheLiterals[] = {
    { L"propsys.dll",         L"Microsoft\\Windows\\Caches",       L"Microsoft\\Windows\\Cache7" },
    { L"structuredquery.dll", L"StructuredQuerySchema.bin",        L"StructuredQuery7.bin" },
    { L"structuredquery.dll", L"StructuredQuerySchemaTrivial.bin", L"StructuredQueryTrivial7.bin" },
};

BYTE* FindWideLiteral(HMODULE m, const wchar_t* s, int* hits) {
    *hits = 0;
    BYTE* found = nullptr;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(m) + reinterpret_cast<IMAGE_DOS_HEADER*>(m)->e_lfanew);
    const size_t cb = (wcslen(s) + 1) * sizeof(wchar_t);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_READ)) continue;
        BYTE* base = reinterpret_cast<BYTE*>(m) + sec->VirtualAddress;
        const size_t size = sec->Misc.VirtualSize;
        for (size_t off = 0; off + cb <= size; off += sizeof(wchar_t)) {
            if (*reinterpret_cast<const wchar_t*>(base + off) != s[0] || memcmp(base + off, s, cb) != 0) continue;
            if (off != 0 && *reinterpret_cast<const wchar_t*>(base + off - sizeof(wchar_t)) != 0) continue;
            found = base + off;
            ++*hits;
        }
    }
    return found;
}

void IsolateWin7Caches(HMODULE m, const wchar_t* path) {
    wchar_t donor[MAX_PATH]; KeelDonorDir(donor, MAX_PATH);
    const size_t dn = wcslen(donor);
    if (!m || !path || _wcsnicmp(path, donor, dn) != 0 || path[dn] != L'\\') return;
    const wchar_t* leaf = wcsrchr(path, L'\\') + 1;
    for (const CacheLiteral& c : kWin7CacheLiterals) {
        if (_wcsicmp(leaf, c.module) != 0 || wcslen(c.to) > wcslen(c.from)) continue;
        int hits = 0, done = 0;
        FindWideLiteral(m, c.to, &done);
        if (done == 1) continue;
        BYTE* p = FindWideLiteral(m, c.from, &hits);
        if (hits != 1) { KEEL_WARN(L"cache; '%s' found %d times in %s, not isolating it", c.from, hits, path); continue; }
        const size_t cb = (wcslen(c.from) + 1) * sizeof(wchar_t);
        DWORD old = 0;
        if (!VirtualProtect(p, cb, PAGE_EXECUTE_READWRITE, &old)) { KEEL_WARN(L"cache; VirtualProtect in %s failed %lu", leaf, GetLastError()); continue; }
        memset(p, 0, cb);
        memcpy(p, c.to, (wcslen(c.to) + 1) * sizeof(wchar_t));
        VirtualProtect(p, cb, old, &old);
        KEEL_INFO(L"cache; %s now uses '%s' instead of '%s'", leaf, c.to, c.from);
    }
}

VOID CALLBACK Win7CacheDllNotification(ULONG reason, const KLDR_DLL_NOTIFICATION_DATA* d, PVOID) {
    if (reason != 1 || !d || !d->FullDllName || !d->FullDllName->Buffer) return;
    wchar_t path[MAX_PATH]{};
    const size_t n = d->FullDllName->Length / sizeof(wchar_t);
    wmemcpy(path, d->FullDllName->Buffer, n < MAX_PATH - 1 ? n : MAX_PATH - 1);
    IsolateWin7Caches(static_cast<HMODULE>(d->DllBase), path);
}

void InstallWin7CacheIsolation() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto reg = nt ? (LdrRegisterDllNotificationFn)GetProcAddress(nt, "LdrRegisterDllNotification") : nullptr;
    PVOID cookie = nullptr;
    const long st = reg ? reg(0, Win7CacheDllNotification, nullptr, &cookie) : -1;
    if (st != 0) KEEL_WARN(L"cache; LdrRegisterDllNotification -> 0x%08lX, late Win7 loads keep the shared caches", (unsigned long)st);
    HMODULE mods[512]; DWORD cb = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)) return;
    const DWORD count = cb / sizeof(HMODULE) < 512 ? cb / sizeof(HMODULE) : 512;
    for (DWORD k = 0; k < count; ++k) {
        wchar_t path[MAX_PATH]{};
        if (GetModuleFileNameW(mods[k], path, MAX_PATH)) IsolateWin7Caches(mods[k], path);
    }
}
PaintSlot g_paintSlots[64];
volatile ULONG g_paintTick = 0;
volatile LONG g_stormLog = 80;
volatile LONG g_invNullHwnd = 0;
using InvalidateRectFn = BOOL(WINAPI*)(HWND, const RECT*, BOOL);
using InvalidateRgnFn  = BOOL(WINAPI*)(HWND, HRGN, BOOL);
using RedrawWindowFn   = BOOL(WINAPI*)(HWND, const RECT*, HRGN, UINT);
InvalidateRectFn g_realInvalidateRect = nullptr;
InvalidateRgnFn  g_realInvalidateRgn  = nullptr;
RedrawWindowFn   g_realRedrawWindow   = nullptr;

PaintSlot* PaintSlotFor(HWND h);
void NoteInvalidate(HWND h, PVOID ra) {
    if (!h) { InterlockedIncrement(&g_invNullHwnd); return; }
    PaintSlot* s = PaintSlotFor(h);
    if (!s) return;
    InterlockedIncrement(&s->invalidated);
    for (PVOID& slot : s->ra) {
        if (slot == ra) break;
        if (!slot && InterlockedCompareExchangePointer(&slot, ra, nullptr) == nullptr) break;
    }

    if (s->dispatched >= 200 && InterlockedCompareExchange(&s->btTaken, 1, 0) == 0)
        RtlCaptureStackBackTrace(1, 14, s->bt, nullptr);
}
void FormatAddr(PVOID a, wchar_t* out, size_t cch) {
    HMODULE m = nullptr; wchar_t p[MAX_PATH]{};
    if (a && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)a, &m) && m) {
        GetModuleFileNameW(m, p, MAX_PATH);
        const wchar_t* leaf = wcsrchr(p, L'\\'); leaf = leaf ? leaf + 1 : p;
        swprintf_s(out, cch, L"%s+0x%llx", leaf, (unsigned long long)((BYTE*)a - (BYTE*)m));
    } else swprintf_s(out, cch, L"%p", a);
}
BOOL WINAPI HookedInvalidateRect(HWND h, const RECT* rc, BOOL erase) { NoteInvalidate(h, _ReturnAddress()); return g_realInvalidateRect(h, rc, erase); }
BOOL WINAPI HookedInvalidateRgn(HWND h, HRGN rgn, BOOL erase)       { NoteInvalidate(h, _ReturnAddress()); return g_realInvalidateRgn(h, rgn, erase); }
BOOL WINAPI HookedRedrawWindow(HWND h, const RECT* rc, HRGN rgn, UINT f) { if (f & RDW_INVALIDATE) NoteInvalidate(h, _ReturnAddress()); return g_realRedrawWindow(h, rc, rgn, f); }

PaintSlot* PaintSlotFor(HWND h) {
    for (auto& s : g_paintSlots) if (s.hwnd == h) return &s;
    for (auto& s : g_paintSlots)
        if (!s.hwnd && InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(&s.hwnd), h, nullptr) == nullptr) return &s;
    return nullptr;
}

void PaintStormTick() {
    const ULONG now = GetTickCount(), last = g_paintTick;
    if (now - last < 1000) return;
    if (InterlockedCompareExchange(&g_paintTick, now, last) != last) return;
    for (auto& s : g_paintSlots) {
        if (!s.hwnd) continue;
        const LONG d = InterlockedExchange(&s.dispatched, 0), b = InterlockedExchange(&s.begun, 0);
        const LONG inv = InterlockedExchange(&s.invalidated, 0);
        if (d >= 200 && InterlockedDecrement(&g_stormLog) > 0) {
            wchar_t cls[48]{}; GetClassNameW(s.hwnd, cls, 47);
            RECT ur{}; GetUpdateRect(s.hwnd, &ur, FALSE);
            wchar_t ra[4][80]; for (int i = 0; i < 4; ++i) FormatAddr(s.ra[i], ra[i], 80);
            KEEL_WARN(L"paintstorm; hwnd=%p '%s' WM_PAINT dispatched=%ld/s BeginPaint=%ld/s invalidated=%ld/s nullHwndInv=%ld/s PaintDesktop total=%ld update=(%ld,%ld,%ld,%ld) callers %s | %s | %s | %s",
                      s.hwnd, cls, d, b, inv, g_invNullHwnd, g_paintDeskCalls, ur.left, ur.top, ur.right, ur.bottom,
                      ra[0], ra[1], ra[2], ra[3]);
            if (s.btTaken == 1 && s.bt[0]) {
                wchar_t line[2800] = L"paintstorm; invalidation backtrace";
                for (int i = 0; i < 30 && s.bt[i]; ++i) {
                    wchar_t f[80]; FormatAddr(s.bt[i], f, 80);
                    wcscat_s(line, L" <- "); wcscat_s(line, f);
                }
                KEEL_WARN(L"%s", line);
                InterlockedExchange(&s.btTaken, 2);
            }
        }
    }
    InterlockedExchange(&g_invNullHwnd, 0);

    const LONG n34 = InterlockedExchange(&g_wm34Count, 0);
    const LONG w4 = InterlockedExchange(&g_wm34W4, 0), w5 = InterlockedExchange(&g_wm34W5, 0), wo = InterlockedExchange(&g_wm34Other, 0);
    const LONG spi = InterlockedExchange(&g_spiSetWall, 0);
    if ((n34 >= 50 || spi >= 50) && InterlockedDecrement(&g_wm34Log) > 0) {
        wchar_t ra[4][80]; for (int i = 0; i < 4; ++i) FormatAddr(g_spiWallRa[i], ra[i], 80);
        KEEL_WARN(L"wm34; DefView got WM 0x34 %ld/s (wParam4=%ld wParam5=%ld other=%ld) with SPI_SETDESKWALLPAPER calls=%ld/s from %s | %s | %s | %s",
                  n34, w4, w5, wo, spi, ra[0], ra[1], ra[2], ra[3]);
        if (g_wm34BtTaken == 1 && g_wm34Bt[0]) {
            wchar_t line[2800] = L"wm34; arrival backtrace";
            for (int i = 0; i < 30 && g_wm34Bt[i]; ++i) { wchar_t f[80]; FormatAddr(g_wm34Bt[i], f, 80); wcscat_s(line, L" <- "); wcscat_s(line, f); }
            KEEL_WARN(L"%s", line);
            InterlockedExchange(&g_wm34BtTaken, 2);
        }
    }
}

LRESULT WINAPI HookedDispatchMessageW(const MSG* m) {
    if (m && m->message == WM_PAINT) {
        if (PaintSlot* s = PaintSlotFor(m->hwnd)) InterlockedIncrement(&s->dispatched);
        PaintStormTick();
    }
    return g_realDispatchMessageW(m);
}

HDC WINAPI HookedBeginPaint(HWND h, LPPAINTSTRUCT ps) {
    if (PaintSlot* s = PaintSlotFor(h)) InterlockedIncrement(&s->begun);
    return g_realBeginPaint(h, ps);
}

bool PathIsBmp(const wchar_t* p) {
    const size_t n = wcslen(p);
    return n > 4 && _wcsicmp(p + n - 4, L".bmp") == 0;
}

BOOL WINAPI HookedSPIW(UINT act, UINT uiParam, PVOID pvParam, UINT fWin) {
    if (act == SPI_SETDESKWALLPAPER) NoteSpiSetWallpaper(_ReturnAddress());
    if (act == SPI_SETDESKWALLPAPER && pvParam) {
        const wchar_t* path = reinterpret_cast<const wchar_t*>(pvParam);
        if (path[0] && !PathIsBmp(path) && GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
            wchar_t bmp[MAX_PATH]{};
            if (TranscodeWallpaperToBmp(path, bmp, MAX_PATH)) {
                SetLastError(0);
                const BOOL r = g_realSPIW(act, uiParam, (PVOID)bmp, fWin);
                DropWallpaperCache();
                InvalidateDesktopWallpaper();
                KEEL_INFO(L"wallpaper; SPI('%s') -> transcoded -> %d err=%lu", path, r, GetLastError());
                return r;
            }
        }
    }
    return g_realSPIW(act, uiParam, pvParam, fWin);
}
BOOL WINAPI HookedSPIA(UINT act, UINT uiParam, PVOID pvParam, UINT fWin) {
    if (act == SPI_SETDESKWALLPAPER) NoteSpiSetWallpaper(_ReturnAddress());
    if (act == SPI_SETDESKWALLPAPER && pvParam) {
        wchar_t w[MAX_PATH]{};
        if (MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(pvParam), -1, w, MAX_PATH) > 0)
            return HookedSPIW(act, uiParam, w, fWin);
    }
    return g_realSPIA(act, uiParam, pvParam, fWin);
}

DWORD WINAPI ApplyDesktopWallpaperThread(LPVOID) {

    for (int attempt = 1; attempt <= 3; ++attempt) {
        Sleep(attempt == 1 ? 12000 : 15000);
        wchar_t path[MAX_PATH]{}; DWORD cb = sizeof(path);
        HKEY k{};
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, KEY_READ, &k) != ERROR_SUCCESS)
            continue;
        const LONG r = RegQueryValueExW(k, L"Wallpaper", nullptr, nullptr,
                                        reinterpret_cast<LPBYTE>(path), &cb);
        RegCloseKey(k);
        if (r != ERROR_SUCCESS || !path[0]) { KEEL_WARN(L"wallpaper; no Wallpaper value set"); return 0; }
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
            KEEL_WARN(L"wallpaper; '%s' does not exist", path); return 0;
        }
        SetLastError(0);
        const BOOL ok = SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, SPIF_UPDATEINIFILE);
        const DWORD err = GetLastError();
        KEEL_INFO(L"wallpaper; boot apply #%d '%s' -> %d err=%lu", attempt, path, ok, err);

        DWORD_PTR res = 0;
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, SPI_SETDESKWALLPAPER,
                            reinterpret_cast<LPARAM>(path),
                            SMTO_ABORTIFHUNG | SMTO_NORMAL, 1500, &res);
        InvalidateDesktopWallpaper();

        wchar_t back[MAX_PATH]{};
        if (g_realSPIW && g_realSPIW(SPI_GETDESKWALLPAPER, MAX_PATH, back, 0))
            KEEL_INFO(L"wallpaper; win32k reports '%s'", back);

        (void)ok; (void)err;
    }
    KEEL_WARN(L"wallpaper; gave up after 5 boot-apply attempts");
    return 0;
}

struct GlassMod {
    HMODULE mod = nullptr; const wchar_t* tag = L"";
    void* realExt = nullptr; void* realBlur = nullptr; void* realComp = nullptr;
    void* realSetAttr = nullptr;
};
GlassMod g_glass[2];
volatile LONG g_glassLog = 200;

using ExtFn  = HRESULT(WINAPI*)(HWND, const void*);
using BlurFn = HRESULT(WINAPI*)(HWND, const void*);
using CompFn = HRESULT(WINAPI*)(BOOL*);
using SetAttrFn = HRESULT(WINAPI*)(HWND, DWORD, LPCVOID, DWORD);
using GetAttrFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

// never rate limit the overflow flyout because the log is exhausted long before anyone opens it, so absence would prove nothing
void GlassLog(const GlassMod& g, const wchar_t* api, HWND h, HRESULT hr, const wchar_t* extra) {
    wchar_t cls[48]{}; if (h && IsWindow(h)) GetClassNameW(h, cls, 47);

    const bool always = cls[0] && _wcsicmp(cls, L"NotifyIconOverflowWindow") == 0;
    if (!always && InterlockedDecrement(&g_glassLog) <= 0) return;
    KEEL_INFO(L"glass; [%s] %s(hwnd=%p '%s'%s) -> 0x%08lX", g.tag, api, h, cls, extra, (unsigned long)hr);
}
template <int I> HRESULT WINAPI HookedExt(HWND h, const void* m) {
    const HRESULT hr = reinterpret_cast<ExtFn>(g_glass[I].realExt)(h, m);
    wchar_t ex[64]{};
    if (m) { const int* mg = reinterpret_cast<const int*>(m);
             swprintf_s(ex, L" margins=%d,%d,%d,%d", mg[0], mg[1], mg[2], mg[3]); }
    GlassLog(g_glass[I], L"DwmExtendFrameIntoClientArea", h, hr, ex);
    return hr;
}
template <int I> HRESULT WINAPI HookedBlur(HWND h, const void* bb) {
    const HRESULT hr = reinterpret_cast<BlurFn>(g_glass[I].realBlur)(h, bb);
    wchar_t ex[64]{};
    if (bb) { const DWORD* b = reinterpret_cast<const DWORD*>(bb);
              swprintf_s(ex, L" flags=0x%lX enable=%lu", b[0], b[1]); }
    GlassLog(g_glass[I], L"DwmEnableBlurBehindWindow", h, hr, ex);
    return hr;
}
template <int I> HRESULT WINAPI HookedComp(BOOL* pf) {
    const HRESULT hr = reinterpret_cast<CompFn>(g_glass[I].realComp)(pf);
    wchar_t ex[32]{}; swprintf_s(ex, L" enabled=%d", pf ? *pf : -1);
    GlassLog(g_glass[I], L"DwmIsCompositionEnabled", nullptr, hr, ex);
    return hr;
}

volatile LONG g_attrLog = 4000;
using SetWcaFn = BOOL(WINAPI*)(HWND, void*);
SetWcaFn g_realSetWca = nullptr;

struct WcaData { DWORD Attrib; DWORD pad; PVOID pvData; SIZE_T cbData; };

int Win7DwmAttrToWin10Wca(DWORD a) {
    switch (a) {
        case 12:      return 13;
        case 0x10000: return 10;

        default:      return -1;
    }
}
// Win7 WCA ids are +1 against Win10 from 9 upward, because Win10 deleted FLIP3D
bool WcaFixEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NOWCAFIX", v, 8) > 0 && v[0] == L'1') ? 0 : 1; }
    return cached == 1;
}
template <int I> HRESULT WINAPI HookedSetAttr(HWND h, DWORD attr, LPCVOID val, DWORD cb) {

    int wca = -1;
    if constexpr (I == 0) { if (WcaFixEnabled()) wca = Win7DwmAttrToWin10Wca(attr); }
    HRESULT hr;
    bool translated = false;
    if (wca >= 0 && g_realSetWca && val && cb >= sizeof(DWORD)) {
        WcaData d{}; d.Attrib = static_cast<DWORD>(wca); d.pvData = const_cast<PVOID>(val); d.cbData = cb;
        SetLastError(0);
        const BOOL ok = g_realSetWca(h, &d);
        if (ok) hr = S_OK;
        else { const DWORD e = GetLastError(); hr = e ? HRESULT_FROM_WIN32(e) : E_FAIL; }
        translated = true;
    } else {
        hr = reinterpret_cast<SetAttrFn>(g_glass[I].realSetAttr)(h, attr, val, cb);
    }
    if (InterlockedDecrement(&g_attrLog) > 0) {
        DWORD v = 0; if (val && cb >= sizeof(DWORD)) v = *static_cast<const DWORD*>(val);
        wchar_t cls[48]{}; if (h && IsWindow(h)) GetClassNameW(h, cls, 47);
        if (translated)
            KEEL_WARN(L"ncstate; [%s] DwmSetWindowAttribute(hwnd=%p '%s' attr=0x%lX value=%lu cb=%lu) "
                      L"-> WCA %d -> 0x%08lX", g_glass[I].tag, h, cls, attr, v, cb, wca, (unsigned long)hr);
        else
            KEEL_WARN(L"ncstate; [%s] DwmSetWindowAttribute(hwnd=%p '%s' attr=0x%lX value=%lu cb=%lu) "
                      L"-> 0x%08lX (untranslated)", g_glass[I].tag, h, cls, attr, v, cb, (unsigned long)hr);
    }
    return hr;
}

void HookGlassModule(int i, HMODULE m, const wchar_t* tag) {
    GlassMod& g = g_glass[i];
    if (g.mod || !m) return;
    g.mod = m; g.tag = tag;
    g.realExt  = GetProcAddress(m, "DwmExtendFrameIntoClientArea");
    g.realBlur = GetProcAddress(m, "DwmEnableBlurBehindWindow");
    g.realComp = GetProcAddress(m, "DwmIsCompositionEnabled");
    g.realSetAttr = GetProcAddress(m, "DwmSetWindowAttribute");
    if (!g_realSetWca) {

        if (HMODULE u = GetModuleHandleW(L"user32.dll"))
            g_realSetWca = reinterpret_cast<SetWcaFn>(GetProcAddress(u, "SetWindowCompositionAttribute"));
        KEEL_INFO(L"ncstate; user32!SetWindowCompositionAttribute=%p (WCA renumbering %s)",
                  g_realSetWca, g_realSetWca ? (WcaFixEnabled() ? L"on" : L"disabled by KEEL_NOWCAFIX") : L"UNAVAILABLE");
    }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    if (g.realExt)  DetourAttach(&g.realExt,  i == 0 ? (PVOID)HookedExt<0>  : (PVOID)HookedExt<1>);
    if (g.realBlur) DetourAttach(&g.realBlur, i == 0 ? (PVOID)HookedBlur<0> : (PVOID)HookedBlur<1>);
    if (g.realComp) DetourAttach(&g.realComp, i == 0 ? (PVOID)HookedComp<0> : (PVOID)HookedComp<1>);
    if (g.realSetAttr) DetourAttach(&g.realSetAttr, i == 0 ? (PVOID)HookedSetAttr<0> : (PVOID)HookedSetAttr<1>);
    const LONG e = DetourTransactionCommit();
    wchar_t p[MAX_PATH]{}; GetModuleFileNameW(m, p, MAX_PATH);
    KEEL_INFO(L"glass; hooked dwmapi [%s] %s (commit=%ld)", tag, p, e);
}

using DwmGetColorFn = HRESULT(WINAPI*)(DWORD*, BOOL*);

bool ColorPersistEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NO_COLORPERSIST", v, 8) > 0 && v[0] == L'1') ? 0 : 1; }
    return cached == 1;
}

const wchar_t* const kKeelDwmColorKey = L"SOFTWARE\\Keel\\DWM";

void WriteDwmColorTo(HKEY root, const wchar_t* subkey, DWORD color, BOOL opaque) {
    HKEY k{};
    if (RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) != ERROR_SUCCESS) return;

    const DWORD opaqueBlend = opaque ? 1u : 0u;
    RegSetValueExW(k, L"ColorizationColor",      0, REG_DWORD, reinterpret_cast<const BYTE*>(&color), sizeof(color));
    RegSetValueExW(k, L"ColorizationAfterglow",  0, REG_DWORD, reinterpret_cast<const BYTE*>(&color), sizeof(color));
    RegSetValueExW(k, L"ColorizationOpaqueBlend",0, REG_DWORD, reinterpret_cast<const BYTE*>(&opaqueBlend), sizeof(opaqueBlend));
    RegCloseKey(k);
}

void MirrorUserDwmKeyToMachine() {
    HKEY src{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", 0, KEY_READ, &src) != ERROR_SUCCESS) return;
    HKEY dst{};
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKeelDwmColorKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &dst, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(src);
        return;
    }
    for (DWORD i = 0;; ++i) {
        wchar_t name[128]; DWORD cchName = ARRAYSIZE(name);
        BYTE data[256];    DWORD cbData = sizeof(data); DWORD type = 0;
        const LSTATUS e = RegEnumValueW(src, i, name, &cchName, nullptr, &type, data, &cbData);
        if (e == ERROR_NO_MORE_ITEMS) break;
        if (e != ERROR_SUCCESS) continue;
        RegSetValueExW(dst, name, 0, type, data, cbData);
    }
    RegCloseKey(dst);
    RegCloseKey(src);
}

DWORD WINAPI ColorPersistThread(LPVOID) {
    if (!ColorPersistEnabled()) { KEEL_INFO(L"color; persistence disabled by KEEL_NO_COLORPERSIST"); return 0; }
    DwmGetColorFn get = nullptr;
    for (int pass = 0; pass < 12 && !get; ++pass) {
        HMODULE m = GetModuleHandleW(L"C:\\Keel\\rtm\\dwmapi.dll");
        if (!m) m = GetModuleHandleW(L"dwmapi.dll");
        if (m) get = reinterpret_cast<DwmGetColorFn>(GetProcAddress(m, "DwmGetColorizationColor"));
        if (!get) Sleep(5000);
    }
    if (!get) { KEEL_WARN(L"color; DwmGetColorizationColor unavailable so colour will not persist"); return 0; }

    MirrorUserDwmKeyToMachine();

    DWORD lastColor = 0; BOOL lastOpaque = -1; bool primed = false;
    for (;;) {
        DWORD color = 0; BOOL opaque = FALSE;
        if (SUCCEEDED(get(&color, &opaque))) {
            if (!primed) { lastColor = color; lastOpaque = opaque; primed = true; }
            else if (color != lastColor || opaque != lastOpaque) {
                lastColor = color; lastOpaque = opaque;

                WriteDwmColorTo(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", color, opaque);

                WriteDwmColorTo(HKEY_USERS, L".DEFAULT\\Software\\Microsoft\\Windows\\DWM", color, opaque);
                MirrorUserDwmKeyToMachine();
                KEEL_INFO(L"color; persisted ColorizationColor=0x%08lX opaque=%d (themes service not involved)",
                          color, opaque ? 1 : 0);
            }
        }
        Sleep(2000);
    }
}

using RegOpenKeyExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegGetValueWFn  = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
RegOpenKeyExWFn g_realRegOpenKeyExW = nullptr;
RegGetValueWFn  g_realRegGetValueW  = nullptr;
volatile LONG g_dwmColorReadLog = 12;

bool DwmColorReadEnabled() {
    static int cached = -1;
    if (cached < 0) { wchar_t v[8]{}; cached = (GetEnvironmentVariableW(L"KEEL_NO_DWMCOLORREAD", v, 8) > 0 && v[0] == L'1') ? 0 : 1; }
    return cached == 1;
}
bool IsDwmColorSubkey(LPCWSTR sub) {
    return sub && _wcsicmp(sub, L"Software\\Microsoft\\Windows\\DWM") == 0;
}

bool InteractiveUserDwmSubkey(wchar_t* out, size_t cch) {
    if (!g_realRegOpenKeyExW) return false;
    wchar_t name[128];
    for (DWORD idx = 0;; ++idx) {
        DWORD n = ARRAYSIZE(name);
        if (RegEnumKeyExW(HKEY_USERS, idx, name, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        if (_wcsnicmp(name, L"S-1-5-21-", 9) != 0) continue;
        const size_t len = wcslen(name);
        if (len > 8 && _wcsicmp(name + len - 8, L"_Classes") == 0) continue;
        wchar_t probe[256];
        swprintf_s(probe, L"%s\\Software\\Microsoft\\Windows\\DWM", name);
        HKEY k{};
        if (g_realRegOpenKeyExW(HKEY_USERS, probe, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) continue;
        RegCloseKey(k);
        wcscpy_s(out, cch, probe);
        return true;
    }
    return false;
}

// keeldwm reads colorization before any user hive is mounted, so the colour must live somewhere always mounted
bool KeelMachineColorKey(wchar_t* out, size_t cch) {
    if (!g_realRegOpenKeyExW) return false;
    HKEY k{};
    if (g_realRegOpenKeyExW(HKEY_LOCAL_MACHINE, kKeelDwmColorKey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, cb = sizeof(DWORD), v = 0;
    const bool ok = RegQueryValueExW(k, L"ColorizationColor", nullptr, &type,
                                     reinterpret_cast<BYTE*>(&v), &cb) == ERROR_SUCCESS;
    RegCloseKey(k);
    if (!ok) return false;
    wcscpy_s(out, cch, kKeelDwmColorKey);
    return true;
}
LSTATUS WINAPI HookedRegOpenKeyExW(HKEY key, LPCWSTR sub, DWORD opt, REGSAM sam, PHKEY res) {
    if (key == HKEY_CURRENT_USER && IsDwmColorSubkey(sub) && DwmColorReadEnabled()) {
        wchar_t path[256];
        if (KeelMachineColorKey(path, ARRAYSIZE(path))) {
            const LSTATUS r = g_realRegOpenKeyExW(HKEY_LOCAL_MACHINE, path, opt, sam, res);
            if (InterlockedDecrement(&g_dwmColorReadLog) > 0)
                KEEL_INFO(L"color; HKCU\\...\\DWM -> HKLM\\%s (r=%ld)", path, r);
            if (r == ERROR_SUCCESS) return r;
        } else if (InteractiveUserDwmSubkey(path, ARRAYSIZE(path))) {
            const LSTATUS r = g_realRegOpenKeyExW(HKEY_USERS, path, opt, sam, res);
            if (InterlockedDecrement(&g_dwmColorReadLog) > 0)
                KEEL_INFO(L"color; HKCU\\...\\DWM -> HKU\\%s (r=%ld)", path, r);
            if (r == ERROR_SUCCESS) return r;
        } else if (InterlockedDecrement(&g_dwmColorReadLog) > 0) {
            KEEL_INFO(L"color; no saved colour yet (no HKLM mirror, no user hive) so using .DEFAULT");
        }
    }
    return g_realRegOpenKeyExW(key, sub, opt, sam, res);
}
LSTATUS WINAPI HookedRegGetValueW(HKEY key, LPCWSTR sub, LPCWSTR val, DWORD flags, LPDWORD type, PVOID data, LPDWORD cb) {
    if (key == HKEY_CURRENT_USER && IsDwmColorSubkey(sub) && DwmColorReadEnabled()) {
        wchar_t path[256];
        if (KeelMachineColorKey(path, ARRAYSIZE(path))) {
            const LSTATUS r = g_realRegGetValueW(HKEY_LOCAL_MACHINE, path, val, flags, type, data, cb);
            if (InterlockedDecrement(&g_dwmColorReadLog) > 0)
                KEEL_INFO(L"color; RegGetValueW('%s') from HKLM\\%s (r=%ld)", val ? val : L"", path, r);
            if (r == ERROR_SUCCESS) return r;
        } else if (InteractiveUserDwmSubkey(path, ARRAYSIZE(path))) {
            const LSTATUS r = g_realRegGetValueW(HKEY_USERS, path, val, flags, type, data, cb);
            if (r == ERROR_SUCCESS) return r;
        }
    }
    return g_realRegGetValueW(key, sub, val, flags, type, data, cb);
}
// keeldwm runs as DWM-1, which has no profile hive, so its HKCU resolves to .DEFAULT and LocalSystem rewrites that at boot
void InstallDwmColorRead() {
    if (!IsDwmProcess() || g_realRegOpenKeyExW) return;

    HMODULE kb = GetModuleHandleW(L"kernelbase.dll"); if (!kb) kb = LoadLibraryW(L"kernelbase.dll");
    if (!kb) { KEEL_WARN(L"color; kernelbase.dll unavailable so DWM colour read not redirected"); return; }
    g_realRegOpenKeyExW = reinterpret_cast<RegOpenKeyExWFn>(GetProcAddress(kb, "RegOpenKeyExW"));
    g_realRegGetValueW  = reinterpret_cast<RegGetValueWFn>(GetProcAddress(kb, "RegGetValueW"));
    if (!g_realRegOpenKeyExW) { KEEL_WARN(L"color; kernelbase!RegOpenKeyExW not found"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realRegOpenKeyExW), reinterpret_cast<PVOID>(HookedRegOpenKeyExW));
    if (g_realRegGetValueW) DetourAttach(reinterpret_cast<PVOID*>(&g_realRegGetValueW), reinterpret_cast<PVOID>(HookedRegGetValueW));
    const LONG e = DetourTransactionCommit();
    KEEL_INFO(L"color; DWM colorization reads redirected to the interactive user's hive (commit=%ld)", e);
}

DWORD WINAPI GlassAuditThread(LPVOID) {
    for (int pass = 0; pass < 6; ++pass) {
        HookGlassModule(0, GetModuleHandleW(L"C:\\Keel\\rtm\\dwmapi.dll"), L"win7");
        HookGlassModule(1, GetModuleHandleW(L"C:\\Windows\\System32\\dwmapi.dll"), L"win10");
        if (g_glass[0].mod && g_glass[1].mod) break;
        Sleep(5000);
    }
    return 0;
}

struct NcWatchSlot { HWND hwnd; int nc; LONG_PTR themewnd; };
NcWatchSlot g_ncWatch[24];
volatile LONG g_ncWatchInit = 0;

BOOL CALLBACK NcWatchEnum(HWND h, LPARAM lp) {
    auto* seen = reinterpret_cast<int*>(lp);
    DWORD pid = 0; GetWindowThreadProcessId(h, &pid);
    if (pid != GetCurrentProcessId() || !IsWindowVisible(h)) return TRUE;
    wchar_t cls[48]{}; GetClassNameW(h, cls, 47);
    if (wcscmp(cls, L"CabinetWClass") != 0 && wcscmp(cls, L"ExploreWClass") != 0) return TRUE;

    int nc = -1;
    if (g_glass[0].mod) {
        auto get = reinterpret_cast<GetAttrFn>(GetProcAddress(g_glass[0].mod, "DwmGetWindowAttribute"));
        if (get) { int v = -1; if (SUCCEEDED(get(h, 1, &v, sizeof(v)))) nc = v; }
    }
    const LONG_PTR tw = reinterpret_cast<LONG_PTR>(GetPropW(h, reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(0xA918))));

    NcWatchSlot* slot = nullptr;
    for (auto& s : g_ncWatch) if (s.hwnd == h) { slot = &s; break; }
    if (!slot) {
        for (auto& s : g_ncWatch) if (!s.hwnd) { s.hwnd = h; s.nc = nc; s.themewnd = tw; slot = &s; break; }
        if (slot) KEEL_INFO(L"ncstate; watching hwnd=%p '%s' ncRendering=%d themewnd=0x%llX",
                            h, cls, nc, (unsigned long long)tw);
        ++*seen; return TRUE;
    }
    if (slot->nc != nc || slot->themewnd != tw) {
        KEEL_WARN(L"ncstate; CHANGED hwnd=%p '%s' ncRendering %d -> %d, themewnd 0x%llX -> 0x%llX",
                  h, cls, slot->nc, nc, (unsigned long long)slot->themewnd, (unsigned long long)tw);
        slot->nc = nc; slot->themewnd = tw;
    }
    ++*seen; return TRUE;
}

DWORD WINAPI NcWatchThread(LPVOID) {
    for (;;) {
        Sleep(1500);
        int seen = 0;
        EnumWindows(NcWatchEnum, reinterpret_cast<LPARAM>(&seen));

        for (auto& s : g_ncWatch) if (s.hwnd && !IsWindow(s.hwnd)) { s.hwnd = nullptr; s.nc = -1; s.themewnd = 0; }
    }
}

using SLGetInfoDwordFn = HRESULT(WINAPI*)(PCWSTR, DWORD*);
SLGetInfoDwordFn g_realSLGetInfoDword = nullptr;
volatile LONG g_slLog = 60;
HRESULT WINAPI HookedSLGetInfoDword(PCWSTR name, DWORD* out) {
    const HRESULT hr = g_realSLGetInfoDword(name, out);
    wchar_t v[8]{};
    const bool fix = !(GetEnvironmentVariableW(L"KEEL_NOSLFIX", v, 8) > 0 && v[0] == L'1');
    HRESULT ret = hr;
    if (fix && name && out && _wcsicmp(name, L"ChangeDesktopBackground-Enabled") == 0) {
        *out = 1; ret = S_OK;
    }
    if (InterlockedDecrement(&g_slLog) > 0)
        KEEL_INFO(L"slc; SLGetWindowsInformationDWORD('%s') real=0x%08lX val=%lu -> returned 0x%08lX val=%lu",
                  name ? name : L"(null)", (unsigned long)hr, (out && SUCCEEDED(hr)) ? *out : 0,
                  (unsigned long)ret, out ? *out : 0);
    return ret;
}
void HookSlc() {
    HMODULE m = GetModuleHandleW(L"slc.dll");
    if (!m) m = LoadLibraryW(L"slc.dll");
    if (!m) { KEEL_WARN(L"slc; slc.dll not loadable"); return; }
    g_realSLGetInfoDword = (SLGetInfoDwordFn)GetProcAddress(m, "SLGetWindowsInformationDWORD");
    if (!g_realSLGetInfoDword) { KEEL_WARN(L"slc; SLGetWindowsInformationDWORD not exported"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realSLGetInfoDword), reinterpret_cast<PVOID>(HookedSLGetInfoDword));
    const LONG e = DetourTransactionCommit();
    wchar_t p[MAX_PATH]{}; GetModuleFileNameW(m, p, MAX_PATH);
    KEEL_INFO(L"slc; hooked SLGetWindowsInformationDWORD in %s (commit=%ld)", p, e);
}

bool IsExplorerProcess() {
    wchar_t p[MAX_PATH]{}; GetModuleFileNameW(nullptr, p, MAX_PATH);
    for (wchar_t* s = p; *s; ++s) *s = (wchar_t)towlower(*s);
    return wcsstr(p, L"explorer.exe") != nullptr;
}

void InstallComExitDiagnostics() {
    wchar_t v[8]{};
    g_comLogAll = (GetEnvironmentVariableW(L"KEEL_COMLOG", v, 8) > 0 && v[0] == L'1');
    if (!g_comLogAll && !IsExplorerProcess()) return;
    HMODULE cb = GetModuleHandleW(L"combase.dll"); if (!cb) cb = LoadLibraryW(L"combase.dll");
    HMODULE u32 = g_comLogAll ? GetModuleHandleW(L"user32.dll") : nullptr;
    // the exit is always hooked in explorer, a shell that quits leaves no taskbar and nothing else in the log
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (cb) {
        g_realCoCreateInstance   = (CoCreateInstanceFn)GetProcAddress(cb, "CoCreateInstance");
        g_realCoCreateInstanceEx = (CoCreateInstanceExFn)GetProcAddress(cb, "CoCreateInstanceEx");
        g_realCoGetClassObject   = (CoGetClassObjectFn)GetProcAddress(cb, "CoGetClassObject");
        if (g_realCoCreateInstance)   DetourAttach(reinterpret_cast<PVOID*>(&g_realCoCreateInstance),   (PVOID)HookedCoCreateInstance);
        if (g_realCoCreateInstanceEx) DetourAttach(reinterpret_cast<PVOID*>(&g_realCoCreateInstanceEx), (PVOID)HookedCoCreateInstanceEx);
        if (g_realCoGetClassObject)   DetourAttach(reinterpret_cast<PVOID*>(&g_realCoGetClassObject),   (PVOID)HookedCoGetClassObject);
    }
    if (nt)  { g_realRtlExitUserProcess = (RtlExitUserProcessFn)GetProcAddress(nt, "RtlExitUserProcess");
               if (g_realRtlExitUserProcess) DetourAttach(reinterpret_cast<PVOID*>(&g_realRtlExitUserProcess), (PVOID)HookedRtlExitUserProcess); }
    if (u32) { g_realMessageBoxW = (MessageBoxWFn)GetProcAddress(u32, "MessageBoxW");
               if (g_realMessageBoxW) DetourAttach(reinterpret_cast<PVOID*>(&g_realMessageBoxW), (PVOID)HookedMessageBoxW);
               g_realCreateWindowExW = (CreateWindowExWFn)GetProcAddress(u32, "CreateWindowExW");
               if (g_realCreateWindowExW) DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateWindowExW), (PVOID)HookedCreateWindowExW); }
    KEEL_INFO(L"com/exit diagnostics installed (combase=%p ntdll=%p user32=%p explorer=%d)", cb, nt, u32, (int)IsExplorerProcess());
}

struct HookEntry {
    const wchar_t* name;
    PVOID* real;
    PVOID hook;
};

HookEntry g_hooks[] = {
    {L"kernel32!GetVersionExW", reinterpret_cast<PVOID*>(&g_realGetVersionExW), reinterpret_cast<PVOID>(HookedGetVersionExW)},
};

void InstallDwmRedirTrace(HMODULE redir) {
    if (!redir || g_rKernelAsync) return;
    g_rKernelAsync = reinterpret_cast<KAsyncFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_KernelAsync);
    g_rMgrDispatch = (RDispatchFn)GetProcAddress(redir, "DwmRedirectionManagerDispatchMessage");
    g_realCreateSurface = reinterpret_cast<CreateSurfaceFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_CreateSurface);
    g_realNotifyBlur = reinterpret_cast<NotifyBlurFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_NotifyBlurBehind);

    wchar_t clipTrace[8]{};
    const bool wantClipTrace =
        GetEnvironmentVariableW(L"KEEL_CLIPTRACE", clipTrace, 8) != 0 && clipTrace[0] == L'1';
    if (wantClipTrace) {
        g_realSetGdiImg  = reinterpret_cast<SetGdiImgFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_SetGDISpriteImage);
        g_realNodeSetImg = reinterpret_cast<NodeSetImgFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_NodeSetSpriteImage);
        g_realGetClipRgn = reinterpret_cast<GetClipRgnFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_GetClipRegion);
        g_realSetSpriteClip = reinterpret_cast<SetSpriteClipFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_SetSpriteClip);
        g_realCreateEmptyClip = reinterpret_cast<CreateEmptyClipFn>(reinterpret_cast<BYTE*>(redir) + RVA_Redir_CreateEmptyClip);
    }

    wchar_t noRgn[8]{};
    const bool rgnFixOff = GetEnvironmentVariableW(L"KEEL_NO_RGNFIX", noRgn, 8) != 0 && noRgn[0] == L'1';
    if (!rgnFixOff) {
        if (HMODULE u32 = GetModuleHandleW(L"user32.dll"))
            g_realSetWindowRgnEx = reinterpret_cast<SetWindowRgnExFn>(GetProcAddress(u32, "SetWindowRgnEx"));
    }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_rKernelAsync), (PVOID)HookedKernelAsync);
    DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateSurface), (PVOID)HookedCreateSurface);
    if (g_realSetGdiImg)  DetourAttach(reinterpret_cast<PVOID*>(&g_realSetGdiImg), (PVOID)HookedSetGdiImg);
    if (g_realNodeSetImg) DetourAttach(reinterpret_cast<PVOID*>(&g_realNodeSetImg), (PVOID)HookedNodeSetImg);
    if (g_realGetClipRgn) DetourAttach(reinterpret_cast<PVOID*>(&g_realGetClipRgn), (PVOID)HookedGetClipRgn);
    if (g_realSetSpriteClip)   DetourAttach(reinterpret_cast<PVOID*>(&g_realSetSpriteClip), (PVOID)HookedSetSpriteClip);
    if (g_realCreateEmptyClip) DetourAttach(reinterpret_cast<PVOID*>(&g_realCreateEmptyClip), (PVOID)HookedCreateEmptyClip);
    if (g_realSetWindowRgnEx)
        DetourAttach(reinterpret_cast<PVOID*>(&g_realSetWindowRgnEx), (PVOID)HookedSetWindowRgnEx);
    DetourAttach(reinterpret_cast<PVOID*>(&g_realNotifyBlur), (PVOID)HookedNotifyBlur);
    if (g_rMgrDispatch) DetourAttach(reinterpret_cast<PVOID*>(&g_rMgrDispatch), (PVOID)HookedRedirDispatch);
    LONG e = DetourTransactionCommit();
    KEEL_INFO(L"redir; dwmredir traced @%p (commit=%ld)", redir, e);
}

}

void InstallRedirTrace() {
    HMODULE u = GetModuleHandleW(L"user32.dll");
    if (!u) return;
    g_realGetWndCompInfo = (GetWndCompInfoFn)GetProcAddress(u, "GetWindowCompositionInfo");
    g_dwmValidateWindow  = (DwmValidateWindowFn)GetProcAddress(u, "DwmValidateWindow");
    KEEL_INFO(L"redir; user32!DwmValidateWindow=%p", g_dwmValidateWindow);
    if (!g_realGetWndCompInfo) { KEEL_INFO(L"redir; user32!GetWindowCompositionInfo not found"); return; }
    DetourTransactionBegin(); DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&g_realGetWndCompInfo), (PVOID)HookedGetWndCompInfo);
    LONG e = DetourTransactionCommit();
    KEEL_INFO(L"redir; traced user32!GetWindowCompositionInfo @%p (commit=%ld)", g_realGetWndCompInfo, e);

    if (HMODULE r = GetModuleHandleW(L"dwmredir.dll")) {
        wchar_t p[MAX_PATH]{}; GetModuleFileNameW(r, p, MAX_PATH);
        KEEL_INFO(L"redir; dwmredir already loaded @%p (%s)", r, p);
        InstallDwmRedirTrace(r);
    } else {
        KEEL_INFO(L"redir; dwmredir not yet loaded at init");
    }
    InstallMilFailureTrace();
    InstallGdiTrace();

    if (HANDLE t = CreateThread(nullptr, 0, SurfaceProbeThread, nullptr, 0, nullptr)) CloseHandle(t);
    if (HANDLE t = CreateThread(nullptr, 0, ComposedAuditThread, nullptr, 0, nullptr)) CloseHandle(t);
}

DWORD InstallHooks(DWORD& installed) {
    installed = 0;

    if (HMODULE lpk = LoadLibraryW(L"lpk.dll")) KEEL_INFO(L"lpk; resident @%p (Win7 comctl32 edit callouts)", lpk);
    else KEEL_WARN(L"lpk; LoadLibrary(lpk.dll) failed err=%lu", GetLastError());
    DetourRestoreAfterWith();
    LONG err = DetourTransactionBegin();
    if (err != NO_ERROR) return static_cast<DWORD>(err);
    DetourUpdateThread(GetCurrentThread());
    for (auto& h : g_hooks) {
        err = DetourAttach(h.real, h.hook);
        if (err != NO_ERROR) {
            KEEL_ERROR(L"DetourAttach(%s) failed: %ld", h.name, err);
            DetourTransactionAbort();
            return static_cast<DWORD>(err);
        }
        ++installed;
    }

    {
        HMODULE ntl = GetModuleHandleW(L"ntdll.dll");
        g_realLdrLoadDll = reinterpret_cast<LdrLoadDllFn>(GetProcAddress(ntl, "LdrLoadDll"));
        if (g_realLdrLoadDll) DetourAttach(reinterpret_cast<PVOID*>(&g_realLdrLoadDll), reinterpret_cast<PVOID>(HookedLdrLoadDll));
    }

    if (IsDwmProcess()) {
        PVOID base = (PVOID)GetModuleHandleW(nullptr);
        g_realInitSessionPort = reinterpret_cast<InitSessionPortFn>((PBYTE)base + 0x5890);
        DetourAttach(reinterpret_cast<PVOID*>(&g_realInitSessionPort), reinterpret_cast<PVOID>(HookedInitSessionPort));
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        g_realNtAlpcConnectPort = reinterpret_cast<NtAlpcConnectPortFn>(GetProcAddress(nt, "NtAlpcConnectPort"));
        if (g_realNtAlpcConnectPort) DetourAttach(reinterpret_cast<PVOID*>(&g_realNtAlpcConnectPort), reinterpret_cast<PVOID>(HookedNtAlpcConnectPort));

        g_realNtCreateWaitablePort = reinterpret_cast<NtCreateWaitablePortFn>(GetProcAddress(nt, "NtCreateWaitablePort"));
        if (g_realNtCreateWaitablePort) DetourAttach(reinterpret_cast<PVOID*>(&g_realNtCreateWaitablePort), reinterpret_cast<PVOID>(HookedNtCreateWaitablePort));

        wchar_t noDpi[8]{};
        const bool dpiFixOff = GetEnvironmentVariableW(L"KEEL_NO_DPIFIX", noDpi, 8) != 0 && noDpi[0] == L'1';
        if (!dpiFixOff) {
            HMODULE g = GetModuleHandleW(L"gdi32.dll"); if (!g) g = LoadLibraryW(L"gdi32.dll");
            g_realGetDeviceCaps = g ? reinterpret_cast<GetDeviceCapsFn>(GetProcAddress(g, "GetDeviceCaps")) : nullptr;
            if (g_realGetDeviceCaps) {
                LONG a = DetourAttach(reinterpret_cast<PVOID*>(&g_realGetDeviceCaps), (PVOID)HookedGetDeviceCaps);
                KEEL_INFO(L"dpi; gdi32!GetDeviceCaps @%p hooked, LOGPIXELSX/Y pinned to 96 (attach=%ld)",
                          g_realGetDeviceCaps, a);
            } else {
                KEEL_WARN(L"dpi; gdi32!GetDeviceCaps not resolved so the compositor will scale by LOGPIXELS/96");
            }
        } else {
            KEEL_WARN(L"dpi; KEEL_NO_DPIFIX=1 so the compositor keeps the host LOGPIXELS");
        }
        AttachKmtHooks();
        AttachTransportHooks();
        AttachMilTraceHooks(GetModuleHandleW(L"dwmcore.dll"));
        PatchReturnTrue((PBYTE)base + 0x3440, L"VerifyGraphicsAssesment");
        KEEL_INFO(L"dwm; installed InitializeSessionPort + connect-syscall + D3DKMT + transport diagnostics");

        StartUxSmsServer();
    }

    if (HMODULE nt = GetModuleHandleW(L"ntdll.dll")) {
        g_realNtConnectPort = reinterpret_cast<NtConnectPortFn>(GetProcAddress(nt, "NtConnectPort"));
        if (g_realNtConnectPort) DetourAttach(reinterpret_cast<PVOID*>(&g_realNtConnectPort), reinterpret_cast<PVOID>(HookedNtConnectPort));
    }
    InstallComExitDiagnostics();

    if (HMODULE u32h = GetModuleHandleW(L"user32.dll")) {
        g_realSPIW = (SPIWFn)GetProcAddress(u32h, "SystemParametersInfoW");
        g_realSPIA = (SPIWFn)GetProcAddress(u32h, "SystemParametersInfoA");
        if (g_realSPIW) DetourAttach(reinterpret_cast<PVOID*>(&g_realSPIW), reinterpret_cast<PVOID>(HookedSPIW));
        if (g_realSPIA) DetourAttach(reinterpret_cast<PVOID*>(&g_realSPIA), reinterpret_cast<PVOID>(HookedSPIA));

        g_realPaintDesktop = (PaintDesktopFn)GetProcAddress(u32h, "PaintDesktop");
        if (g_realPaintDesktop)
            DetourAttach(reinterpret_cast<PVOID*>(&g_realPaintDesktop), reinterpret_cast<PVOID>(HookedPaintDesktop));
        g_realPaintMonitor = (PaintMonitorFn)GetProcAddress(u32h, "PaintMonitor");
        if (g_realPaintMonitor)
            DetourAttach(reinterpret_cast<PVOID*>(&g_realPaintMonitor), reinterpret_cast<PVOID>(HookedPaintMonitor));
        if (IsExplorerProcess()) {
            g_realDispatchMessageW = (DispatchMessageWFn)GetProcAddress(u32h, "DispatchMessageW");
            g_realBeginPaint = (BeginPaintFn)GetProcAddress(u32h, "BeginPaint");
            if (g_realDispatchMessageW) DetourAttach(reinterpret_cast<PVOID*>(&g_realDispatchMessageW), reinterpret_cast<PVOID>(HookedDispatchMessageW));
            if (g_realBeginPaint) DetourAttach(reinterpret_cast<PVOID*>(&g_realBeginPaint), reinterpret_cast<PVOID>(HookedBeginPaint));
            g_realInvalidateRect = (InvalidateRectFn)GetProcAddress(u32h, "InvalidateRect");
            g_realInvalidateRgn  = (InvalidateRgnFn)GetProcAddress(u32h, "InvalidateRgn");
            g_realRedrawWindow   = (RedrawWindowFn)GetProcAddress(u32h, "RedrawWindow");
            if (g_realInvalidateRect) DetourAttach(reinterpret_cast<PVOID*>(&g_realInvalidateRect), reinterpret_cast<PVOID>(HookedInvalidateRect));
            if (g_realInvalidateRgn)  DetourAttach(reinterpret_cast<PVOID*>(&g_realInvalidateRgn),  reinterpret_cast<PVOID>(HookedInvalidateRgn));
            if (g_realRedrawWindow)   DetourAttach(reinterpret_cast<PVOID*>(&g_realRedrawWindow),   reinterpret_cast<PVOID>(HookedRedrawWindow));
        }
    }
    const bool isExplorer = IsExplorerProcess();
    if (isExplorer) {

        if (GetEnvironmentVariableW(L"KEEL_SECONDARY", nullptr, 0) == 0)
            PatchReturnOne((PBYTE)GetModuleHandleW(nullptr) + 0x2bc40, L"explorer!ShouldStartDesktopAndTray -> 1 (shell path; see comment)");
        else
            KEEL_INFO(L"shell; secondary explorer (KEEL_SECONDARY) -> ShouldStartDesktopAndTray left to Win7");
    }
    err = DetourTransactionCommit();
    if (err != NO_ERROR) {
        KEEL_ERROR(L"DetourTransactionCommit failed: %ld", err);
        installed = 0;
        return static_cast<DWORD>(err);
    }

    InstallShellStyleRedirect();
    InstallDwmColorRead();
    InstallDonorPathFix();
    InstallWin7CacheIsolation();
    InstallOrbTrace();
    if (isExplorer) {

        if (HMODULE s32 = GetModuleHandleW(L"shell32.dll")) { InstallDefViewProbe(s32); InstallShellEnumProbe(s32); }
        if (HMODULE ef = GetModuleHandleW(L"explorerframe.dll")) InstallItemsViewProbe(ef);
        if (HMODULE dui = GetModuleHandleW(L"dui70.dll")) InstallDuiProbe(dui);
        if (HANDLE t = CreateThread(nullptr, 0, ThemeWatchdog, nullptr, 0, nullptr)) CloseHandle(t);
        WatchTextInputFramework();
        HookSlc();
        if (HANDLE t = CreateThread(nullptr, 0, ApplyDesktopWallpaperThread, nullptr, 0, nullptr)) CloseHandle(t);
        if (HANDLE t = CreateThread(nullptr, 0, GlassAuditThread, nullptr, 0, nullptr)) CloseHandle(t);
        if (HANDLE t = CreateThread(nullptr, 0, ColorPersistThread, nullptr, 0, nullptr)) CloseHandle(t);
        if (HANDLE t = CreateThread(nullptr, 0, NcWatchThread, nullptr, 0, nullptr)) CloseHandle(t);
        if (HANDLE t = CreateThread(nullptr, 0, ShellPatchThread, nullptr, 0, nullptr)) CloseHandle(t);
    }
    return ERROR_SUCCESS;
}

}
