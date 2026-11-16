#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <atomic>

namespace hotfix {

// Target Proxifier.exe v4.14.0.1 x64 constants
constexpr uint32_t kExpectedSizeOfImage = 0x674000;

// Host RVAs
namespace rva {
    // Lifecycle & Vtable
    constexpr uintptr_t kVtableInitInstance   = 0x370400; // -> 0x7C550
    constexpr uintptr_t kVtableExitInstance   = 0x370430; // -> 0x7DF60
    constexpr uintptr_t kInitInstance         = 0x07C550;
    constexpr uintptr_t kExitInstance         = 0x07DF60;
    constexpr uintptr_t kExitDriverStopCall   = 0x07E096; // call sub_140003CF0 (0x120008)

    // Host CRT & STL Helpers (MUST use host's static CRT heap!)
    constexpr uintptr_t kHostOperatorNew      = 0x0BA6F4; // void* (*)(size_t) (throws CMemoryException* on OOM)
    constexpr uintptr_t kHostFree             = 0x00C6F0; // void (*)(void*) (j_j_free)
    constexpr uintptr_t kHostMtxLock          = 0x2737CC; // int (*)(void*)
    constexpr uintptr_t kHostMtxUnlock        = 0x2737F0; // int (*)(void*)
    constexpr uintptr_t kHostMtxDoLock        = 0x2734F4; // int (*)(void*, const void* xtime)
    constexpr uintptr_t kHostThrowCError      = 0x2738FC; // void (*)(int)
    constexpr uintptr_t kHostWstringTidy      = 0x003C70; // void (*)(void* wstring)
    constexpr uintptr_t kHostWstringAssignZ   = 0x003570; // void* (*)(void* dst, const wchar_t* src, int64_t unused)
    constexpr uintptr_t kHostWstringAssignN   = 0x003A10; // void* (*)(void* dst, const void* src, size_t count)
    constexpr uintptr_t kHostStringAppend     = 0x00A2A0; // void* (*)(void* dst, const char* src, size_t count)

    // IAT slots
    constexpr uintptr_t kIatGetTickCount64    = 0x2E3B58;
    constexpr uintptr_t kIatClosesocket       = 0x2E46B8;

    // Fix 1: UDP Resolver Socket Leak in sub_14003BBF0
    constexpr uintptr_t kUdpResolverPatchSite = 0x03C002; // 10 bytes: 49 8B 0F 49 8B 57 08 48 3B CA

    // Fix 2: Winsock Wrapper Ownership, Provider Cache & getsockname Backoff
    constexpr uintptr_t kCreateSockObj        = 0x0ABDC0;
    constexpr uintptr_t kAcceptRedirectedTcp  = 0x02B490;
    constexpr uintptr_t kInitRedirectSock     = 0x029D10;
    constexpr uintptr_t kDestroySockObj       = 0x0258E0; // void (*)(void* block, int a2)
    constexpr uintptr_t kCleanupFailedAccept  = 0x0262E0; // void (*)(int64_t conn)
    constexpr uintptr_t kAcceptConditionFn    = 0x005E50; // LPCONDITIONPROC
    constexpr uintptr_t kGetsocknameBackoff   = 0x029F45; // 8 bytes: 8B C3 0F AF C3 6B C8 32

    // Fix 3 & 4: 64-bit Cache Timestamps, Real-IP Expiry, and Fake-IP Allocator Lock
    constexpr uintptr_t kTickSite1            = 0x0336AB;
    constexpr uintptr_t kTickSite2            = 0x033859;
    constexpr uintptr_t kTickSite3            = 0x033986;
    constexpr uintptr_t kTickSite4            = 0x034203;
    constexpr uintptr_t kTickSite5            = 0x035093;
    constexpr uintptr_t kRealIpReverseInsert  = 0x033670;
    constexpr uintptr_t kRealIpFloorMov       = 0x0336B8; // BF 80 51 01 00
    constexpr uintptr_t kRealIpAdd1000        = 0x03372B; // 8D BE E8 03 00 00
    constexpr uintptr_t kReverseIpLookup      = 0x033C90;
    constexpr uintptr_t kFakeIpAllocate       = 0x034080;
    constexpr uintptr_t kIsFakeIpv4           = 0x0343E0; // bool (*)(const uint32_t* net_ip)
    constexpr uintptr_t kIsFakeIpv6           = 0x034440; // bool (*)(const uint32_t* ip6_words)
    constexpr uintptr_t kSockAddrLess         = 0x03A470; // bool (*)(const void* a, const void* b)
    constexpr uintptr_t kCopyVecBytes         = 0x02BDC0; // void (*)(void* dst_vec, uint64_t begin, uint64_t end)
    constexpr uintptr_t kDnsCacheMutex        = 0x412460; // _Mtx_t unk_140412460
    constexpr uintptr_t kReverseCacheMapHead  = 0x4124B0; // qword_1404124B0

    // Fix 5: DNS Synthesizer & Call Site
    constexpr uintptr_t kIncludeAnswerInDns   = 0x05D7C0;
    constexpr uintptr_t kDnsSynthCallSite     = 0x037261; // call sub_14005D7C0 in sub_1400366F0

    // Fix 6a: Overlapped Event Cache in sub_140003CF0
    constexpr uintptr_t kIoctlCreateEventCall = 0x003D56; // 6 bytes: FF 15 E4 FE 2D 00
    constexpr uintptr_t kIoctlCloseHandleCall = 0x003F26; // 6 bytes: FF 15 8C FA 2D 00
    constexpr uintptr_t kIoctlEhCloseHelper   = 0x003F50; // sub_140003F50(HANDLE* ph)

    // Fix 6b: Sharded Flow/DNS Workers + Bounded ALE Pool in sub_1400640A0
    constexpr uintptr_t kWfpCase2Start        = 0x0641A6; // Case 2 (ALE Connect Redirect) -> jump to 0x6482F
    constexpr uintptr_t kWfpCase4Start        = 0x0642CA; // Case 4 (FLOW_ESTABLISHED) -> jump to 0x6482F
    constexpr uintptr_t kWfpCase5Start        = 0x064370; // Case 5 (FLOW_DELETE) -> jump to 0x6482F
    constexpr uintptr_t kWfpCase3Start        = 0x0647D7; // Case 3 (DATAGRAM_DATA DNS) -> jump to 0x6482F
    constexpr uintptr_t kHandleAleRedirect    = 0x0658B0; // void (*)(void* cnfe_event_vec)
    constexpr uintptr_t kHandleDnsDatagram    = 0x065DB0; // void (*)(void* cnfe_event_vec)
    constexpr uintptr_t kCopyCnfeEvent        = 0x004BF0; // void* (*)(void* dst_vec, const void* src_vec)
    constexpr uintptr_t kFlowMapMutex         = 0x412650; // unk_140412650
    constexpr uintptr_t kFlowMapHead          = 0x4126A0; // qword_1404126A0
    constexpr uintptr_t kFlowMapOperatorIdx   = 0x0665D0; // void* (*)(uint64_t unused, const uint64_t* key)
    constexpr uintptr_t kRbTreeErase          = 0x0349F0; // void* (*)(void* map_ptr, void* node)
    constexpr uintptr_t kProxyAuthEventHandle = 0x412A90; // HANDLE hHandle

    // Fix 7: High-Entropy Thread-Local Seed Mixing
    constexpr uintptr_t kSeedSite1            = 0x0B393A; // 17 bytes before call srand at 0xB394B
    constexpr uintptr_t kSeedSite2            = 0x0B796A; // 17 bytes before call srand at 0xB797B

    // Fix 8a: Trailing-Edge Log Coalescer & Bounded UI Drain
    constexpr uintptr_t kLogProducerRateBlock = 0x0445B1; // 0x445B1..0x44645 (148 bytes)
    constexpr uintptr_t kLogProducerHook      = 0x0444B0; // sub_1400444B0
    constexpr uintptr_t kLogListSplice        = 0x044690; // sub_140044690
    constexpr uintptr_t kLogUiDrain           = 0x0498C0; // sub_1400498C0
    constexpr uintptr_t kLogSecondaryPoster   = 0x04A240; // sub_14004A240
    constexpr uintptr_t kLogSecondaryPostBlk  = 0x04A273; // 0x4A273..0x4A292 (31 bytes)
    constexpr uintptr_t kLogMutex             = 0x412570; // unk_140412570
    constexpr uintptr_t kLogFileListHead      = 0x412550; // qword_140412550
    constexpr uintptr_t kLogFileListSize      = 0x412558; // qword_140412558
    constexpr uintptr_t kLogUiListHead        = 0x412560; // qword_140412560
    constexpr uintptr_t kLogUiListSize        = 0x412568; // qword_140412568
    constexpr uintptr_t kLogHwndGlobal        = 0x411AA0; // HWND hWnd (RichEdit child; parent receives 0x464? Wait: check!)
    constexpr uintptr_t kAppExitingByte       = 0x412BA8; // byte_140412BA8

    // Fix 8b: UI Timer Non-Blocking Trylock & Status Bar Plain Loads
    constexpr uintptr_t kUiTimerConnList      = 0x02DEF0; // sub_14002DEF0
    constexpr uintptr_t kUiConnTrylockPatch   = 0x02DFDD; // 17 bytes: 0x2DFDD..0x2DFEE
    constexpr uintptr_t kUiTimerStatusBar     = 0x04EB00; // sub_14004EB00
    constexpr uintptr_t kStatusBarLock1       = 0x04EB73; // 0x4EB73..0x4EBA9 (54 bytes)
    constexpr uintptr_t kStatusBarLock2       = 0x04F0A3; // 0x4F0A3..0x4F0D9 (54 bytes)
    constexpr uintptr_t kConnListMutex        = 0x412330; // unk_140412330
    constexpr uintptr_t kActiveConnCount      = 0x412388; // qword_140412388
    constexpr uintptr_t kDnsModeMutex         = 0x4129F0; // unk_1404129F0
    constexpr uintptr_t kDnsModeByte          = 0x412921; // byte_140412921
    constexpr uintptr_t kMainFrameGlobal      = 0x412750; // qword_140412750
} // namespace rva

// Global state populated at bootstrap
extern uintptr_t g_exeBase;
extern HMODULE   g_selfModule;

template <typename T = void*>
inline T RvaPtr(uintptr_t offset) noexcept {
    return reinterpret_cast<T>(g_exeBase + offset);
}

// Host allocator / helper wrappers
void* HostOperatorNew(size_t sz);
void  HostFree(void* p) noexcept;
void  HostFreeVectorBuffer(void* beginPtr, void* endCapPtr) noexcept;
void  HostLockMutex(void* mtx);
void  HostUnlockMutex(void* mtx);
int   HostTryLockMutex(void* mtx) noexcept;
void  HostWstringTidy(void* wstr) noexcept;

// Diagnostics counters (readable by tests / live verification)
struct HotfixDiagnostics {
    std::atomic<uint64_t> udpSocketsClosed{0};
    std::atomic<uint64_t> providerCacheHits{0};
    std::atomic<uint64_t> providerCacheMisses{0};
    std::atomic<uint64_t> dnsSynthesizedOk{0};
    std::atomic<uint64_t> dnsSynthesizedErrorResp{0};
    std::atomic<uint64_t> tlsEventReuses{0};
    std::atomic<uint64_t> aleEventsDispatched{0};
    std::atomic<uint64_t> flowEventsDispatched{0};
    std::atomic<uint64_t> uiLogsCoalesced{0};
    std::atomic<uint64_t> uiTrylockSkipped{0};
    std::atomic<bool>     patchesInstalled{false};
};

extern HotfixDiagnostics g_diag;

// Subsystem installation entrypoints
bool InitTrampolineSlab(uintptr_t exeBase, size_t imageSize) noexcept;
uint8_t* AllocTrampolineCode(size_t size, size_t align = 16) noexcept;
bool RegisterLeafThunkUnwind(uint8_t* codeBegin, uint8_t* codeEnd, uint8_t prologSize, uint8_t stackAllocSlots) noexcept;
bool FinalizeTrampolineUnwindTable() noexcept;
bool WriteMemoryPatch(void* addr, const void* data, size_t len) noexcept;
bool InstallDetour(uintptr_t targetRva, void* detourFn, void** outOriginal, size_t stolenLen) noexcept;

bool InstallUdpSocketCloseFix() noexcept;
bool InstallWinsockFixes() noexcept;
bool InstallCacheAndTimestampFixes() noexcept;
bool InstallDnsSynthesizerFix() noexcept;
bool InstallWfpPoolAndEventCacheFixes() noexcept;
bool InstallUiAndSeedFixes() noexcept;

// Shutdown coordination
void OnPreDriverStopShutdown() noexcept;
void OnPostDriverStopShutdown() noexcept;
void OnThreadDetachCleanup() noexcept;
void ShutdownWinsockProviderWatch() noexcept;
void DisarmUiTimersOnShutdown() noexcept;

extern "C" __declspec(dllexport) const HotfixDiagnostics* __cdecl ProxifierHotfixGetDiagnostics() noexcept;

} // namespace hotfix
