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
#include <d3d11.h>
#include <dxgi1_3.h>
#include <dcomp.h>

#include <stdio.h>

#include "keel/log.h"

namespace {

constexpr UINT kSurfW = 256, kSurfH = 256;

LARGE_INTEGER g_freq{};

volatile LONG        g_stepSeq = 0;
const char* volatile g_stepName = "start";

void Emit(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    fflush(stdout);
    KEEL_INFO(L"%S", buf);
}

struct Step {
    const char*   name;
    LARGE_INTEGER t0{};

    explicit Step(const char* n) : name(n) {
        g_stepName = n;
        InterlockedIncrement(&g_stepSeq);
        Emit("BEGIN %s", n);
        QueryPerformanceCounter(&t0);
    }

    HRESULT End(HRESULT hr) {
        LARGE_INTEGER t1;
        QueryPerformanceCounter(&t1);
        const double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)g_freq.QuadPart;
        Emit("END   %-44s hr=0x%08lX  %8.2f ms%s", name, (unsigned long)hr, ms,
             SUCCEEDED(hr) ? "" : "   <-- FAILED");
        return hr;
    }
};

using CreateDevFn = HRESULT(WINAPI*)(IUnknown*, REFIID, void**);
CreateDevFn g_createDevice = nullptr;
CreateDevFn g_createDevice3 = nullptr;

bool BindRealDComp() {
    const wchar_t* candidates[] = { L"dcomp10.dll", L"dcomp.dll" };
    for (const wchar_t* name : candidates) {
        HMODULE m = LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!m) continue;
        auto c1 = (CreateDevFn)GetProcAddress(m, "DCompositionCreateDevice");
        auto c3 = (CreateDevFn)GetProcAddress(m, "DCompositionCreateDevice3");
        if (!c1) { continue; }
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameW(m, path, MAX_PATH);
        Emit("DComp implementation: %S", path);
        g_createDevice = c1;
        g_createDevice3 = c3;
        return true;
    }
    return false;
}

HWND MakeWindow() {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"KeelDcProbe";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wc);
    HWND h = CreateWindowExW(0, L"KeelDcProbe", L"keeldcprobe", WS_OVERLAPPEDWINDOW,
                             80, 80, 360, 300, nullptr, nullptr, wc.hInstance, nullptr);
    if (h) ShowWindow(h, SW_SHOW);
    return h;
}

ID3D11Device* MakeD3D11() {

    const D3D_FEATURE_LEVEL want[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1 };
    const D3D_DRIVER_TYPE types[] = { D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP };
    for (D3D_DRIVER_TYPE dt : types) {
        ID3D11Device* dev = nullptr;
        const HRESULT hr = D3D11CreateDevice(nullptr, dt, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                                             want, ARRAYSIZE(want), D3D11_SDK_VERSION, &dev, nullptr, nullptr);
        if (SUCCEEDED(hr) && dev) {
            Emit("d3d11 device: %s", dt == D3D_DRIVER_TYPE_HARDWARE ? "HARDWARE" : "WARP");
            return dev;
        }
    }
    return nullptr;
}

DWORD WINAPI Worker(LPVOID param) {
    HWND hwnd = (HWND)param;

    if (!BindRealDComp()) { Emit("!FATAL! could not bind to dcomp10.dll or dcomp.dll"); return 4; }

    ID3D11Device* d3d = MakeD3D11();
    if (!d3d) { Emit("FATAL: no D3D11 device at all"); return 1; }

    IDXGIDevice* dxgi = nullptr;
    d3d->QueryInterface(IID_PPV_ARGS(&dxgi));

    IDCompositionDevice* dev = nullptr;
    {
        Step s("DCompositionCreateDevice");
        const HRESULT hr = s.End(g_createDevice(dxgi, IID_PPV_ARGS(&dev)));
        if (FAILED(hr) || !dev) {
            Emit("!FATAL! no DComp device (hr=0x%08lX) from the actual implementation.", (unsigned long)hr);
            Emit("0x887A0004 here is the kernel runtime refusal; specifically not any code fault.");
            return 3;
        }
    }

    IDCompositionSurface* surf = nullptr;
    {
        Step s("IDCompositionDevice::CreateSurface");
        s.End(dev->CreateSurface(kSurfW, kSurfH, DXGI_FORMAT_B8G8R8A8_UNORM,
                                 DXGI_ALPHA_MODE_PREMULTIPLIED, &surf));
    }

    if (surf) {
        ID3D11Texture2D* tex = nullptr;
        POINT off{};
        {
            Step s("IDCompositionSurface::BeginDraw  <== THE ROUND TRIP");
            const HRESULT hr = s.End(surf->BeginDraw(nullptr, IID_PPV_ARGS(&tex), &off));
            if (SUCCEEDED(hr)) Emit("       atlas offset = (%ld,%ld)", off.x, off.y);
        }
        if (tex) tex->Release();
        { Step s("IDCompositionSurface::EndDraw"); s.End(surf->EndDraw()); }
    }

    IDCompositionVirtualSurface* vsurf = nullptr;
    {
        Step s("IDCompositionDevice::CreateVirtualSurface");
        s.End(dev->CreateVirtualSurface(1024, 1024, DXGI_FORMAT_B8G8R8A8_UNORM,
                                        DXGI_ALPHA_MODE_PREMULTIPLIED, &vsurf));
    }

    IDCompositionTarget* target = nullptr;
    { Step s("CreateTargetForHwnd"); s.End(dev->CreateTargetForHwnd(hwnd, TRUE, &target)); }

    IDCompositionVisual* vis = nullptr;
    { Step s("CreateVisual"); s.End(dev->CreateVisual(&vis)); }

    if (vis && surf) { Step s("Visual::SetContent(surface)"); s.End(vis->SetContent(surf)); }
    if (target && vis) { Step s("Target::SetRoot"); s.End(target->SetRoot(vis)); }

    { Step s("IDCompositionDevice::Commit"); s.End(dev->Commit()); }

    { Step s("WaitForCommitCompletion  <== EXPLICIT ROUND TRIP"); s.End(dev->WaitForCommitCompletion()); }

    DCOMPOSITION_FRAME_STATISTICS fs{};
    { Step s("GetFrameStatistics"); s.End(dev->GetFrameStatistics(&fs)); }
    Emit("       lastFrameTime=%lld  currentTime=%lld  rate=%u/%u",
         fs.lastFrameTime.QuadPart, fs.currentTime.QuadPart,
         fs.currentCompositionRate.Numerator, fs.currentCompositionRate.Denominator);

    IDCompositionDesktopDevice* desk = nullptr;
    if (g_createDevice3) {
        Step s("DCompositionCreateDevice3 -> IDCompositionDesktopDevice");
        s.End(g_createDevice3(d3d, IID_PPV_ARGS(&desk)));
    }
    if (desk) {
        IDCompositionTarget* t2 = nullptr;
        { Step s("DesktopDevice::CreateTargetForHwnd"); s.End(desk->CreateTargetForHwnd(hwnd, TRUE, &t2)); }
        if (t2) t2->Release();
        desk->Release();
    }

    {
        HMODULE w32u = LoadLibraryExW(L"win32u.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!w32u) {
            Emit("win32u.dll not loadable therefore cannot probe DWM");
        } else {
            using Conn3Fn = LONG(NTAPI*)(void*, void*, void*);
            using Dwm6Fn  = LONG(NTAPI*)(void*, void*, void*, void*, void*, void*);

            auto createConn = (Conn3Fn)GetProcAddress(w32u, "NtDCompositionCreateConnection");
            auto createDwm  = (Dwm6Fn)GetProcAddress(w32u, "NtDCompositionCreateDwmChannel");
            Emit("");
            Emit("! non-dwm.exe process bind check !");
            Emit("       NtDCompositionCreateConnection  = %p", (void*)createConn);
            Emit("       NtDCompositionCreateDwmChannel  = %p", (void*)createDwm);

            if (createConn) {
                Step s("win32u!NtDCompositionCreateConnection(0,0,0)");
                const LONG st = createConn(nullptr, nullptr, nullptr);
                s.End((HRESULT)st);
                Emit("       NTSTATUS = 0x%08lX %s", (unsigned long)st,
                     st == 0 ? "(SUCCESS)" : (st == (LONG)0xC0000022 ? "(STATUS_ACCESS_DENIED likely gated)" : ""));
            }
            if (createDwm) {
                ULONGLONG handle = 0;
                Step s("win32u!NtDCompositionCreateDwmChannel(&h,...)");
                const LONG st = createDwm(&handle, nullptr, nullptr, nullptr, nullptr, nullptr);
                s.End((HRESULT)st);
                Emit("       NTSTATUS = 0x%08lX  handle=0x%llX %s", (unsigned long)st, handle,
                     st == 0 ? "(binding SUCCESS to DWM process)"
                             : (st == (LONG)0xC0000022 ? "(STATUS_ACCESS_DENIED gated to registered DWM)" : ""));
            }
        }
    }

    Emit("");
    Emit("COMPLETE NO HANG.");

    if (vsurf) vsurf->Release();
    if (vis) vis->Release();
    if (target) target->Release();
    if (surf) surf->Release();
    if (dev) dev->Release();
    if (dxgi) dxgi->Release();
    d3d->Release();
    return 0;
}

}

int main(int argc, char** argv) {
    int timeoutSec = 30;
    for (int i = 1; i < argc; ++i)
        if (!strcmp(argv[i], "--seconds") && i + 1 < argc) timeoutSec = atoi(argv[++i]);

    keel::LogInit(L"keeldcprobe");
    QueryPerformanceFrequency(&g_freq);

    Emit("keeldcprobe P1 Q2 check is the DComp protocol bidirectional?");
    Emit("watchdog timeout = %d s", timeoutSec);
    Emit("");

    HWND hwnd = MakeWindow();
    if (!hwnd) { Emit("!FATAL! CreateWindowEx failed (%lu)", GetLastError()); return 1; }

    DWORD tid = 0;
    HANDLE th = CreateThread(nullptr, 0, Worker, hwnd, 0, &tid);
    if (!th) { Emit("!FATAL! CreateThread failed"); return 1; }

    const DWORD deadline = GetTickCount() + (DWORD)timeoutSec * 1000;
    for (;;) {
        const DWORD w = MsgWaitForMultipleObjects(1, &th, FALSE,
                                                  (deadline > GetTickCount()) ? deadline - GetTickCount() : 0,
                                                  QS_ALLINPUT);
        if (w == WAIT_OBJECT_0) break;
        if (w == WAIT_OBJECT_0 + 1) {
            MSG m;
            while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessageW(&m); }
            continue;
        }

        Emit("");
        Emit("*** WATCHDOG FIRED after %d s ***", timeoutSec);
        Emit("*** HUNG IN %s", g_stepName);
        Emit("*** DWM-side consumer is MANDATORY for a call never returning");
        fflush(stdout);
        TerminateProcess(GetCurrentProcess(), 9);
    }

    DWORD rc = 0;
    GetExitCodeThread(th, &rc);
    CloseHandle(th);
    Emit("worker exit = %lu", rc);
    return (int)rc;
}
