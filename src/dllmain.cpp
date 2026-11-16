#include "host_abi.h"
#include <cstring>

// Exported function pointers read by MASM jump thunks in exports_thunk.asm
extern "C" {
    FARPROC g_pfn_vSetDdrawflag  = nullptr;
    FARPROC g_pfn_AlphaBlend     = nullptr;
    FARPROC g_pfn_DllInitialize  = nullptr;
    FARPROC g_pfn_GradientFill   = nullptr;
    FARPROC g_pfn_TransparentBlt = nullptr;
}

namespace {

INIT_ONCE g_msimgInitOnce = INIT_ONCE_STATIC_INIT;
HMODULE   g_realMsimg32   = nullptr;

BOOL CALLBACK LoadRealMsimg32Callback(PINIT_ONCE, PVOID, PVOID*) noexcept {
    wchar_t sysDir[MAX_PATH + 32]{};
    const UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return FALSE;
    }
    wcscat_s(sysDir, L"\\msimg32.dll");

    // Load full path from System32 and verify we did not resolve back to our own proxy carrier!
    HMODULE hMod = LoadLibraryExW(sysDir, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!hMod || hMod == hotfix::g_selfModule) {
        return FALSE;
    }
    g_realMsimg32        = hMod;
    g_pfn_vSetDdrawflag  = GetProcAddress(hMod, "vSetDdrawflag");
    g_pfn_AlphaBlend     = GetProcAddress(hMod, "AlphaBlend");
    g_pfn_DllInitialize  = GetProcAddress(hMod, "DllInitialize");
    g_pfn_GradientFill   = GetProcAddress(hMod, "GradientFill");
    g_pfn_TransparentBlt = GetProcAddress(hMod, "TransparentBlt");
    return (g_pfn_AlphaBlend != nullptr && g_pfn_TransparentBlt != nullptr) ? TRUE : FALSE;
}

using InitInstanceFn = int64_t (__fastcall*)(void* thisApp);
using ExitInstanceFn = int64_t (__fastcall*)(void* thisApp);

InitInstanceFn g_origInitInstance = nullptr;
ExitInstanceFn g_origExitInstance = nullptr;

void InstallAllHotfixesOnMainThread() noexcept {
    using namespace hotfix;

    // 1. Eagerly load C:\Windows\System32\msimg32.dll outside Loader Lock
    InitOnceExecuteOnce(&g_msimgInitOnce, &LoadRealMsimg32Callback, nullptr, nullptr);

    // 2. Allocate positive-RVA trampoline + unwind slab strictly above exeBase
    if (!InitTrampolineSlab(g_exeBase, kExpectedSizeOfImage)) {
        return;
    }

    // 3. Install all verified binary fixes while process is still single-threaded (before Winsock/UI/WFP threads start!)
    const bool ok =
        InstallUdpSocketCloseFix() &&
        InstallWinsockFixes() &&
        InstallCacheAndTimestampFixes() &&
        InstallDnsSynthesizerFix() &&
        InstallWfpPoolAndEventCacheFixes() &&
        InstallUiAndSeedFixes() &&
        FinalizeTrampolineUnwindTable();

    if (ok) {
        g_diag.patchesInstalled.store(true, std::memory_order_release);
    }
}

int64_t __fastcall Hook_InitInstance(void* thisApp) {
    InstallAllHotfixesOnMainThread();
    return g_origInitInstance(thisApp);
}

int64_t __fastcall Hook_ExitInstance(void* thisApp) {
    // 1. Disarm UI timers and wake any blocked worker/pump waits BEFORE host ExitInstance sends IOCTL 0x120008
    hotfix::DisarmUiTimersOnShutdown();
    hotfix::OnPreDriverStopShutdown();

    // 2. Run original ExitInstance (sends driver-stop IOCTL 0x120008 at 0x7E096 and joins host pump thread)
    const int64_t ret = g_origExitInstance(thisApp);

    // 3. Join all persistent + overflow worker threads while pumping QS_SENDMESSAGE before CRT global teardown!
    hotfix::OnPostDriverStopShutdown();
    hotfix::ShutdownWinsockProviderWatch();
    return ret;
}

bool VerifyTargetProxifierExecutable(uintptr_t base) noexcept {
    if (!base) {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage != hotfix::kExpectedSizeOfImage)
    {
        return false;
    }

    // Verify CProxifierApp vtable slots for InitInstance (`0x7C550`) and ExitInstance (`0x7DF60`)
    const uintptr_t expectedInit = base + hotfix::rva::kInitInstance;
    const uintptr_t expectedExit = base + hotfix::rva::kExitInstance;
    const uintptr_t actualInit = *reinterpret_cast<const uintptr_t*>(base + hotfix::rva::kVtableInitInstance);
    const uintptr_t actualExit = *reinterpret_cast<const uintptr_t*>(base + hotfix::rva::kVtableExitInstance);
    return (actualInit == expectedInit && actualExit == expectedExit);
}

void BootstrapVtableHooksInDllMain(HMODULE hinstDLL) noexcept {
    hotfix::g_selfModule = hinstDLL;

    // Pin our proxy DLL in memory for the lifetime of the process so worker/UI callbacks can never unload mid-flight
    HMODULE pinned = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(hinstDLL),
        &pinned);

    const uintptr_t exeBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    if (!VerifyTargetProxifierExecutable(exeBase)) {
        // Fail-open cleanly if loaded into any non-matching process or future Proxifier build!
        return;
    }

    hotfix::g_exeBase = exeBase;

    auto* vtblInitSlot = hotfix::RvaPtr<InitInstanceFn*>(hotfix::rva::kVtableInitInstance);
    auto* vtblExitSlot = hotfix::RvaPtr<ExitInstanceFn*>(hotfix::rva::kVtableExitInstance);

    g_origInitInstance = *vtblInitSlot;
    g_origExitInstance = *vtblExitSlot;

    const InitInstanceFn newInit = &Hook_InitInstance;
    const ExitInstanceFn newExit = &Hook_ExitInstance;
    hotfix::WriteMemoryPatch(vtblInitSlot, &newInit, sizeof(newInit));
    hotfix::WriteMemoryPatch(vtblExitSlot, &newExit, sizeof(newExit));
}

} // namespace

extern "C" void EnsureMsimg32Loaded() noexcept {
    InitOnceExecuteOnce(&g_msimgInitOnce, &LoadRealMsimg32Callback, nullptr, nullptr);
}

extern "C" __declspec(dllexport) const hotfix::HotfixDiagnostics* __cdecl ProxifierHotfixGetDiagnostics() noexcept {
    return &hotfix::g_diag;
}

BOOL APIENTRY DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/) {
    // Do NOT call DisableThreadLibraryCalls — we need DLL_THREAD_DETACH to close cached TLS overlapped events!
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Zero LoadLibrary, zero thread creation, zero heap/CRT work under Loader Lock!
        BootstrapVtableHooksInDllMain(hinstDLL);
    } else if (fdwReason == DLL_THREAD_DETACH) {
        hotfix::OnThreadDetachCleanup();
    }
    return TRUE;
}
