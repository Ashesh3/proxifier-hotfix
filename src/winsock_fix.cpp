#include "host_abi.h"
#include <cstring>
#include <mutex>
#include <vector>

namespace hotfix {

namespace {

// ============================================================================
// Fix 1: UDP DNS Resolver Socket Closure (sub_14003BBF0 @ RVA 0x3C002)
// ============================================================================
void __fastcall CloseUdpSocketHelper(SOCKET s) noexcept {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        g_diag.udpSocketsClosed.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================================
// Fix 2: Base-Provider Cache + Pre-Allocated Socket Wrappers
// ============================================================================
struct ProviderCacheEntry {
    int af;
    int type;
    int protocol;
    WSAPROTOCOL_INFOW info;
};

SRWLOCK g_provLock = SRWLOCK_INIT;
std::atomic<uint64_t> g_provGeneration{1};
std::vector<ProviderCacheEntry> g_provCache;

HANDLE g_provNotifyEvent = nullptr;
HANDLE g_provWaitObject  = nullptr;
OVERLAPPED g_provOverlapped{};
std::atomic<bool> g_provWatchInitialized{false};
std::atomic<bool> g_provShuttingDown{false};

HANDLE g_provChangeHandle = nullptr;

VOID CALLBACK OnProviderConfigChanged(PVOID /*lpParameter*/, BOOLEAN /*TimerOrWaitFired*/) {
    if (g_provShuttingDown.load(std::memory_order_acquire)) {
        return;
    }
    g_provGeneration.fetch_add(1, std::memory_order_acq_rel);
    AcquireSRWLockExclusive(&g_provLock);
    g_provCache.clear();
    ReleaseSRWLockExclusive(&g_provLock);

    // Re-arm BEFORE next enumeration
    if (g_provChangeHandle && g_provNotifyEvent && !g_provShuttingDown.load(std::memory_order_acquire)) {
        std::memset(&g_provOverlapped, 0, sizeof(g_provOverlapped));
        g_provOverlapped.hEvent = g_provNotifyEvent;
        WSAProviderConfigChange(&g_provChangeHandle, &g_provOverlapped, nullptr);
    }
}

void EnsureProviderWatcherStarted() noexcept {
    bool expected = false;
    if (!g_provWatchInitialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    g_provNotifyEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_provNotifyEvent) {
        return;
    }
    std::memset(&g_provOverlapped, 0, sizeof(g_provOverlapped));
    g_provOverlapped.hEvent = g_provNotifyEvent;
    g_provChangeHandle = nullptr;
    const int rc = WSAProviderConfigChange(&g_provChangeHandle, &g_provOverlapped, nullptr);
    if (rc == 0 || WSAGetLastError() == WSA_IO_PENDING) {
        RegisterWaitForSingleObject(
            &g_provWaitObject,
            g_provNotifyEvent,
            &OnProviderConfigChanged,
            nullptr,
            INFINITE,
            WT_EXECUTEDEFAULT);
    }
}

bool LookupCachedProvider(int af, int type, int protocol, WSAPROTOCOL_INFOW& outInfo, uint64_t& outGen) noexcept {
    outGen = g_provGeneration.load(std::memory_order_acquire);
    AcquireSRWLockShared(&g_provLock);
    for (const auto& entry : g_provCache) {
        if (entry.af == af && entry.type == type && entry.protocol == protocol) {
            outInfo = entry.info;
            ReleaseSRWLockShared(&g_provLock);
            return true;
        }
    }
    ReleaseSRWLockShared(&g_provLock);
    return false;
}

void InvalidateCachedProvider(uint64_t observedGen) noexcept {
    uint64_t cur = observedGen;
    g_provGeneration.compare_exchange_strong(cur, observedGen + 1, std::memory_order_acq_rel);
    AcquireSRWLockExclusive(&g_provLock);
    g_provCache.clear();
    ReleaseSRWLockExclusive(&g_provLock);
}

// Enumerates Winsock catalog with exact original matching rules:
// - lpiProtocols = (protocol != 0) ? {protocol, 0} : nullptr
// - First entry with ProtocolChain.ChainLen == 1 && iAddressFamily == af && iSocketType == type
// - Sets WSAEPROTONOSUPPORT (10043) if no entry matches
bool EnumerateBaseProviderLive(int af, int type, int protocol, WSAPROTOCOL_INFOW& outInfo, bool allowCacheInsert) noexcept {
    EnsureProviderWatcherStarted();
    const uint64_t genBefore = g_provGeneration.load(std::memory_order_acquire);

    INT protoFilter[2] = { protocol, 0 };
    LPINT lpiProtocols = (protocol != 0) ? protoFilter : nullptr;

    // Pre-size stack buffer for 32 entries (~20 KB) so we never trigger the guaranteed WSAENOBUFS double-call!
    constexpr DWORD kStackEntries = 32;
    WSAPROTOCOL_INFOW stackBuf[kStackEntries];
    DWORD bufLen = sizeof(stackBuf);
    WSAPROTOCOL_INFOW* buf = stackBuf;
    std::vector<uint8_t> heapBuf;

    int count = WSAEnumProtocolsW(lpiProtocols, buf, &bufLen);
    if (count == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        if (err != WSAENOBUFS) {
            WSASetLastError(err);
            return false;
        }
        try {
            heapBuf.resize(bufLen);
        } catch (...) {
            WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
            return false;
        }
        buf = reinterpret_cast<WSAPROTOCOL_INFOW*>(heapBuf.data());
        count = WSAEnumProtocolsW(lpiProtocols, buf, &bufLen);
        if (count == SOCKET_ERROR) {
            return false;
        }
    }

    const WSAPROTOCOL_INFOW* matched = nullptr;
    for (int i = 0; i < count; ++i) {
        if (buf[i].ProtocolChain.ChainLen == 1 &&
            buf[i].iAddressFamily == af &&
            buf[i].iSocketType == type)
        {
            matched = &buf[i];
            break;
        }
    }

    if (!matched) {
        WSASetLastError(WSAEPROTONOSUPPORT); // 10043, exact match to 0x1400ABE93
        return false;
    }

    outInfo = *matched;

    if (allowCacheInsert) {
        AcquireSRWLockExclusive(&g_provLock);
        if (g_provGeneration.load(std::memory_order_relaxed) == genBefore) {
            bool exists = false;
            for (auto& e : g_provCache) {
                if (e.af == af && e.type == type && e.protocol == protocol) {
                    e.info = outInfo;
                    exists = true;
                    break;
                }
            }
            if (!exists && g_provCache.size() < 64) {
                try {
                    g_provCache.push_back(ProviderCacheEntry{af, type, protocol, outInfo});
                } catch (...) {
                    // Non-fatal: skip caching on OOM
                }
            }
        }
        ReleaseSRWLockExclusive(&g_provLock);
    }
    return true;
}

// Replacement for sub_1400ABDC0 (CreateSockObj):
// Pre-allocates the 16-byte wrapper via host operator new BEFORE WSASocketW so neither CMemoryException*
// nor NULL return can ever leak a SOCKET handle!
uint16_t* __fastcall Detour_CreateSockObj(int af, int type, int protocol) {
    // 1. Pre-allocate 16-byte host wrapper FIRST (if MFC throws CMemoryException*, no socket exists yet)
    auto* wrapper = static_cast<uint8_t*>(HostOperatorNew(0x10));
    if (!wrapper) {
        WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
        return nullptr;
    }
    // Exact layout from 0x1400ABF31..0x1400ABF41:
    *reinterpret_cast<uint64_t*>(wrapper)      = static_cast<uint64_t>(INVALID_SOCKET);
    *reinterpret_cast<uint16_t*>(wrapper + 8)  = 0;
    *reinterpret_cast<uint8_t*>(wrapper + 10)  = 0;

    WSAPROTOCOL_INFOW protoInfo{};
    uint64_t gen = 0;
    SOCKET s = INVALID_SOCKET;

    if (LookupCachedProvider(af, type, protocol, protoInfo, gen)) {
        g_diag.providerCacheHits.fetch_add(1, std::memory_order_relaxed);
        s = WSASocketW(af, type, protocol, &protoInfo, 0, WSA_FLAG_OVERLAPPED);
        if (s == INVALID_SOCKET) {
            const int err = WSAGetLastError();
            if (err == WSAEINVAL || err == WSAEINVALIDPROVIDER || err == WSAEPROVIDERFAILEDINIT) {
                InvalidateCachedProvider(gen);
                if (EnumerateBaseProviderLive(af, type, protocol, protoInfo, true)) {
                    s = WSASocketW(af, type, protocol, &protoInfo, 0, WSA_FLAG_OVERLAPPED);
                }
            } else {
                WSASetLastError(err);
            }
        }
    } else {
        g_diag.providerCacheMisses.fetch_add(1, std::memory_order_relaxed);
        if (EnumerateBaseProviderLive(af, type, protocol, protoInfo, true)) {
            s = WSASocketW(af, type, protocol, &protoInfo, 0, WSA_FLAG_OVERLAPPED);
        }
    }

    if (s == INVALID_SOCKET) {
        const int savedErr = WSAGetLastError();
        HostFree(wrapper);
        WSASetLastError(savedErr);
        return nullptr;
    }

    *reinterpret_cast<SOCKET*>(wrapper) = s;
    return reinterpret_cast<uint16_t*>(wrapper);
}

// Replacement for sub_14002B490 (AcceptRedirectedTcp):
// Pre-allocates the 16-byte wrapper BEFORE WSAAccept and frees it on every non-accepted exit.
char __fastcall Detour_AcceptRedirectedTcp(int64_t* a1) {
    sockaddr_storage addr{};
    const int64_t conn = a1[24];
    int addrlen = (*reinterpret_cast<const int32_t*>(conn + 200) == 23 ||
                   *reinterpret_cast<const uint8_t*>(conn + 233) != 0) ? 28 : 16;

    SOCKET* listenWrapper = reinterpret_cast<SOCKET*>(a1[26]);
    fd_set readfds{};
    readfds.fd_count = 1;
    readfds.fd_array[0] = *listenWrapper;
    timeval timeout{10, 0};

    // Pre-allocate 16-byte wrapper BEFORE select/WSAAccept so CMemoryException* cannot leak an accepted socket!
    auto* wrapper = static_cast<uint8_t*>(HostOperatorNew(0x10));
    if (wrapper) {
        *reinterpret_cast<uint64_t*>(wrapper)     = static_cast<uint64_t>(INVALID_SOCKET);
        *reinterpret_cast<uint16_t*>(wrapper + 8) = 0;
        *reinterpret_cast<uint8_t*>(wrapper + 10) = 0;
    }

    uint8_t* assignedWrapper = nullptr;
    const int sel = select(0, &readfds, nullptr, nullptr, &timeout);
    if (sel == 0) {
        HostFree(wrapper);
        WSASetLastError(WSAETIMEDOUT); // 10060
    } else if (sel == 1) {
        if (!wrapper) {
            WSASetLastError(WSA_NOT_ENOUGH_MEMORY);
        } else {
            auto condFn = RvaPtr<LPCONDITIONPROC>(rva::kAcceptConditionFn);
            SOCKET accepted = WSAAccept(
                *listenWrapper,
                reinterpret_cast<sockaddr*>(&addr),
                &addrlen,
                condFn,
                0);
            if (accepted != INVALID_SOCKET) {
                *reinterpret_cast<SOCKET*>(wrapper) = accepted;
                assignedWrapper = wrapper;
                wrapper = nullptr; // ownership transferred to conn + 216
            } else {
                const int savedErr = WSAGetLastError();
                HostFree(wrapper);
                wrapper = nullptr;
                WSASetLastError(savedErr);
            }
        }
    } else {
        const int savedErr = WSAGetLastError();
        HostFree(wrapper);
        wrapper = nullptr;
        WSASetLastError(savedErr);
    }

    const int64_t connNow = a1[24];
    *reinterpret_cast<uint8_t**>(connNow + 216) = assignedWrapper;

    if (assignedWrapper != nullptr) {
        int fam = (*reinterpret_cast<const uint8_t*>(connNow + 233) != 0)
            ? 23
            : static_cast<uint16_t>(*reinterpret_cast<const uint32_t*>(connNow + 200));
        const uint16_t netPort = *reinterpret_cast<const uint16_t*>(reinterpret_cast<const char*>(&addr) + 2);
        *reinterpret_cast<uint32_t*>(connNow + 208) = static_cast<uint32_t>(fam) | (static_cast<uint32_t>(netPort) << 16);

        void* oldListen = reinterpret_cast<void*>(a1[26]);
        if (oldListen != nullptr) {
            using DestroySockFn = void (__fastcall*)(void*, int);
            RvaPtr<DestroySockFn>(rva::kDestroySockObj)(oldListen, fam);
        }
        a1[26] = 0;

        uint32_t keepAliveIn[3] = { 1u, 30000u, 1000u };
        DWORD bytesRet = 0;
        const SOCKET sAccepted = **reinterpret_cast<SOCKET**>(a1[24] + 216);
        if (WSAIoctl(sAccepted, 0x98000004u /*SIO_KEEPALIVE_VALS*/,
                     keepAliveIn, sizeof(keepAliveIn),
                     nullptr, 0, &bytesRet, nullptr, nullptr) == SOCKET_ERROR)
        {
            using LogErrFn = void (__fastcall*)(int64_t*, const wchar_t*, int64_t, int64_t);
            const auto vtbl = *reinterpret_cast<uintptr_t*>(a1);
            reinterpret_cast<LogErrFn>(*reinterpret_cast<uintptr_t*>(vtbl + 16))(
                a1, L"Ioctl() failed with error ", 1, 0);
            return 0;
        }
        return 1;
    }

    // Failure / timeout reporting path (exact match to 0x14002B57D..0x14002B656)
    const int err = WSAGetLastError();
    using LogErrFn = void (__fastcall*)(int64_t*, const wchar_t*, int64_t, int64_t);
    using CleanupFn = void (__fastcall*)(int64_t);
    const auto vtbl = *reinterpret_cast<uintptr_t*>(a1);
    auto logFn = reinterpret_cast<LogErrFn>(*reinterpret_cast<uintptr_t*>(vtbl + 16));

    if (err == WSAETIMEDOUT) {
        logFn(a1, L"A connection request was canceled (timed out) before the completion.", 0, 1);
    } else if (err == WSAECONNRESET) {
        logFn(a1, L"A connection request was canceled before the completion.", 0, 1);
    } else {
        WSASetLastError(err);
        logFn(a1, L"Accept() failed with error", 1, 0);
    }
    RvaPtr<CleanupFn>(rva::kCleanupFailedAccept)(a1[24]);
    return 0;
}

// Detour wrapper for sub_140029D10 (InitRedirectSock):
// Releases *(a1 + 208) immediately if bind/listen/getsockname fails so ephemeral ports aren't held until CRedirectSession dtor.
using InitRedirectSockFn = char (__fastcall*)(int64_t, uint32_t*, int);
InitRedirectSockFn g_origInitRedirectSock = nullptr;

char __fastcall Detour_InitRedirectSock(int64_t a1, uint32_t* a2, int a3) {
    const char ok = g_origInitRedirectSock(a1, a2, a3);
    if (!ok) {
        void* sockObj = *reinterpret_cast<void**>(a1 + 208);
        if (sockObj != nullptr) {
            using DestroySockFn = void (__fastcall*)(void*, int);
            RvaPtr<DestroySockFn>(rva::kDestroySockObj)(sockObj, 0);
            *reinterpret_cast<void**>(a1 + 208) = nullptr;
        }
    }
    return ok;
}

} // namespace

bool InstallUdpSocketCloseFix() noexcept {
    // Verify exact 10 bytes at 0x14003C002:
    //   49 8B 0F        mov rcx, [r15]
    //   49 8B 57 08     mov rdx, [r15+8]
    //   48 3B CA        cmp rcx, rdx
    static const uint8_t kExpected[10] = {
        0x49, 0x8B, 0x0F,
        0x49, 0x8B, 0x57, 0x08,
        0x48, 0x3B, 0xCA
    };
    uint8_t* site = RvaPtr<uint8_t*>(rva::kUdpResolverPatchSite);
    if (std::memcmp(site, kExpected, sizeof(kExpected)) != 0) {
        return false;
    }

    // Build clean non-chained leaf call thunk (Opus 5.5 §1 #5 recommendation):
    // Patch 0x3C002 with `E8 rel32` (5 bytes) + `0F 1F 44 00 00` (5-byte NOP) -> returns to 0x3C007 -> 0x3C00C (`jz`)!
    // Inside thunk (entered via `call` so RSP = parent_aligned_rsp - 8):
    //   48 83 EC 28              sub rsp, 28h            ; 40B -> RSP 16B-aligned + 32B shadow space!
    //   48 8B CF                 mov rcx, rdi            ; s
    //   FF 15 <disp_abs>         call qword ptr [rip+...] -> CloseUdpSocketHelper
    //   49 8B 0F                 mov rcx, [r15]
    //   49 8B 57 08              mov rdx, [r15+8]
    //   48 3B CA                 cmp rcx, rdx            ; sets ZF for `jz loc_14003C31E` at 0x3C00C!
    //   48 8D 64 24 28           lea rsp, [rsp+28h]      ; restores RSP WITHOUT touching RFLAGS!
    //   C3                       ret
    uint8_t* thunk = AllocTrampolineCode(48, 16);
    if (!thunk) {
        return false;
    }

    size_t p = 0;
    // sub rsp, 28h (4 bytes, 5 stack slots: 5*8 = 40 = 0x28)
    thunk[p++] = 0x48; thunk[p++] = 0x83; thunk[p++] = 0xEC; thunk[p++] = 0x28;
    // mov rcx, rdi
    thunk[p++] = 0x48; thunk[p++] = 0x8B; thunk[p++] = 0xCF;
    // call qword ptr [rip + disp32] (6 bytes)
    thunk[p++] = 0xFF; thunk[p++] = 0x15;
    const size_t dispPos = p;
    p += 4;
    // mov rcx, [r15]; mov rdx, [r15+8]; cmp rcx, rdx
    const uint8_t postCmp[] = {
        0x49, 0x8B, 0x0F,
        0x49, 0x8B, 0x57, 0x08,
        0x48, 0x3B, 0xCA,
        0x48, 0x8D, 0x64, 0x24, 0x28, // lea rsp, [rsp+28h] (preserves ZF!)
        0xC3                          // ret
    };
    std::memcpy(thunk + p, postCmp, sizeof(postCmp));
    p += sizeof(postCmp);
    const size_t codeEnd = p;

    // Align target pointer to 8 bytes right after `ret` (outside [BeginAddress, EndAddress))
    const size_t ptrOff = (p + 7u) & ~size_t(7u);
    const uintptr_t helperAddr = reinterpret_cast<uintptr_t>(&CloseUdpSocketHelper);
    std::memcpy(thunk + ptrOff, &helperAddr, sizeof(helperAddr));

    const int32_t ripDisp = static_cast<int32_t>((thunk + ptrOff) - (thunk + dispPos + 4));
    std::memcpy(thunk + dispPos, &ripDisp, sizeof(ripDisp));

    // Register own non-chained UNWIND_INFO: prologSize = 4, stackAllocSlots = 5 (0x28 bytes)
    if (!RegisterLeafThunkUnwind(thunk, thunk + codeEnd, 4, 5)) {
        return false;
    }

    // Patch 0x3C002..0x3C00B (10 bytes): E8 <rel32> 0F 1F 44 00 00
    const intptr_t rel = reinterpret_cast<intptr_t>(thunk) - reinterpret_cast<intptr_t>(site + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        return false;
    }
    uint8_t patch[10] = { 0xE8, 0, 0, 0, 0, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    const int32_t rel32 = static_cast<int32_t>(rel);
    std::memcpy(patch + 1, &rel32, sizeof(rel32));
    return WriteMemoryPatch(site, patch, sizeof(patch));
}

bool InstallWinsockFixes() noexcept {
    // 1. Verify & patch getsockname retry backoff at 0x29F45 (8 bytes):
    // Original: 8B C3 0F AF C3 6B C8 32  (mov eax, ebx; imul eax, ebx; imul ecx, eax, 50)
    // Replacement: 6B CB 05 0F 1F 44 00 00 (imul ecx, ebx, 5; nop dword ptr [rax+rax+00h])
    static const uint8_t kExpectedBackoff[8] = {
        0x8B, 0xC3, 0x0F, 0xAF, 0xC3, 0x6B, 0xC8, 0x32
    };
    static const uint8_t kNewBackoff[8] = {
        0x6B, 0xCB, 0x05, 0x0F, 0x1F, 0x44, 0x00, 0x00
    };
    if (std::memcmp(RvaPtr(rva::kGetsocknameBackoff), kExpectedBackoff, 8) != 0) {
        return false;
    }
    if (!WriteMemoryPatch(RvaPtr(rva::kGetsocknameBackoff), kNewBackoff, 8)) {
        return false;
    }

    // 2. Detour CreateSockObj (0xABDC0, 5-byte prologue `48 89 5C 24 20`)
    static const uint8_t kCreateSockPrologue[5] = { 0x48, 0x89, 0x5C, 0x24, 0x20 };
    if (std::memcmp(RvaPtr(rva::kCreateSockObj), kCreateSockPrologue, 5) != 0) {
        return false;
    }
    void* unused1 = nullptr;
    if (!InstallDetour(rva::kCreateSockObj, reinterpret_cast<void*>(&Detour_CreateSockObj), &unused1, 5)) {
        return false;
    }

    // 3. Detour AcceptRedirectedTcp (0x2B490, 5-byte prologue `48 89 5C 24 10`)
    static const uint8_t kAcceptPrologue[5] = { 0x48, 0x89, 0x5C, 0x24, 0x10 };
    if (std::memcmp(RvaPtr(rva::kAcceptRedirectedTcp), kAcceptPrologue, 5) != 0) {
        return false;
    }
    void* unused2 = nullptr;
    if (!InstallDetour(rva::kAcceptRedirectedTcp, reinterpret_cast<void*>(&Detour_AcceptRedirectedTcp), &unused2, 5)) {
        return false;
    }

    // 4. Detour InitRedirectSock (0x29D10, 6-byte boundary: `40 55 56 57 41 54`)
    static const uint8_t kInitRedirPrologue[6] = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54 };
    if (std::memcmp(RvaPtr(rva::kInitRedirectSock), kInitRedirPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kInitRedirectSock, reinterpret_cast<void*>(&Detour_InitRedirectSock),
                       reinterpret_cast<void**>(&g_origInitRedirectSock), 6))
    {
        return false;
    }

    return true;
}

void ShutdownWinsockProviderWatch() noexcept {
    g_provShuttingDown.store(true, std::memory_order_release);
    if (g_provWaitObject) {
        UnregisterWaitEx(g_provWaitObject, INVALID_HANDLE_VALUE);
        g_provWaitObject = nullptr;
    }
    if (g_provChangeHandle) {
        CloseHandle(g_provChangeHandle);
        g_provChangeHandle = nullptr;
    }
    if (g_provNotifyEvent) {
        CloseHandle(g_provNotifyEvent);
        g_provNotifyEvent = nullptr;
    }
}

} // namespace hotfix
