#include "host_abi.h"
#include "dns_synthesizer.h"
#include <cstring>

namespace hotfix {

namespace {

// ============================================================================
// Dedicated SRWLOCK protecting Fake-IP allocator sub_140034080 (`dword_1404124D0`)
// ============================================================================
SRWLOCK g_fakeIpAllocLock = SRWLOCK_INIT;

using FakeIpAllocateFn = void (__fastcall*)(int, const char*, int, void*, void**, int64_t);
FakeIpAllocateFn g_origFakeIpAllocate = nullptr;

struct SrwExclusiveGuard {
    SRWLOCK* lock;
    explicit SrwExclusiveGuard(SRWLOCK* l) noexcept : lock(l) { AcquireSRWLockExclusive(lock); }
    ~SrwExclusiveGuard() noexcept { ReleaseSRWLockExclusive(lock); }
};

void __fastcall Detour_FakeIpAllocate(int a1, const char* a2, int a3, void* a4, void** a5, int64_t a6) {
    SrwExclusiveGuard guard(&g_fakeIpAllocLock);
    g_origFakeIpAllocate(a1, a2, a3, a4, a5, a6);
}

// ============================================================================
// Fix 4a: Real-IP Reverse-DNS Cache Insert TTL Clamp (sub_140033670)
// ============================================================================
using RealIpReverseInsertFn = void (__fastcall*)(int64_t, int64_t, const char*, int);
RealIpReverseInsertFn g_origRealIpReverseInsert = nullptr;

void __fastcall Detour_RealIpReverseInsert(int64_t a1, int64_t a2, const char* a3, int rawTtl) {
    // RFC 2181 §8 + Windows MaxCacheTtl (86400s):
    // ttl == 0 || (ttl & 0x80000000u) -> 15s; else clamp(ttl, 0..86400) + 15s with 60s floor.
    const uint32_t clampedTtl = ComputeRealIpReverseTtlSec(static_cast<uint32_t>(rawTtl));
    g_origRealIpReverseInsert(a1, a2, a3, static_cast<int>(clampedTtl));
}

// ============================================================================
// Fix 4b: Reverse-DNS Cache Lookup (sub_140033C90)
// - Normalizes IPv4-mapped IPv6 `::ffff:a.b.c.d` BEFORE classifying Fake-IP vs Real-IP
// - Uses host predicates `sub_1400343E0` (IPv4) & `sub_140034440` (IPv6)
// - Performs expiry check (`now > entry->ts + 1000ULL * entry->ttl_sec`) under `unk_140412460`
// - Refreshes `entry->ts = now` ONLY for Fake-IPs; Real-IPs strictly honor insertion TTL!
// ============================================================================
struct HostMutexGuard {
    void* mtx;
    explicit HostMutexGuard(void* m) {
        mtx = m;
        HostLockMutex(mtx);
    }
    ~HostMutexGuard() noexcept {
        if (mtx) {
            HostUnlockMutex(mtx);
        }
    }
};

bool IsHostFakeIpAfterNormalize(const uint8_t* normAddr28) noexcept {
    const uint16_t family = *reinterpret_cast<const uint16_t*>(normAddr28);
    if (family == AF_INET) {
        // sockaddr_in.sin_addr at byte offset +4
        using IsFakeV4Fn = bool (__fastcall*)(const uint32_t*);
        return RvaPtr<IsFakeV4Fn>(rva::kIsFakeIpv4)(reinterpret_cast<const uint32_t*>(normAddr28 + 4));
    }
    if (family == AF_INET6) {
        // sockaddr_in6.sin6_addr at byte offset +8
        using IsFakeV6Fn = bool (__fastcall*)(const uint32_t*);
        return RvaPtr<IsFakeV6Fn>(rva::kIsFakeIpv6)(reinterpret_cast<const uint32_t*>(normAddr28 + 8));
    }
    return false;
}

uint8_t __fastcall Detour_ReverseIpLookup(
    int64_t /*a1*/,
    const uint8_t* a2,
    void* outHostnameStr,
    uint8_t* outAddr28,
    void* outVec)
{
    // Copy 28-byte SockAddrInet key & normalize IPv4-mapped IPv6 (`::ffff:x.x.x.x`) exactly as 0x140033CCA..0x140033D40
    alignas(16) uint8_t key[28]{};
    std::memcpy(key, a2, 28);

    const auto* w = reinterpret_cast<const uint16_t*>(a2);
    if (w[0] == AF_INET6 &&
        w[4] == 0 && w[5] == 0 && w[6] == 0 && w[7] == 0 && w[8] == 0 && w[9] == 0xFFFFu)
    {
        std::memset(key, 0, sizeof(key));
        *reinterpret_cast<uint16_t*>(key + 0) = AF_INET;
        *reinterpret_cast<uint16_t*>(key + 2) = w[1]; // port
        *reinterpret_cast<uint32_t*>(key + 4) = *reinterpret_cast<const uint32_t*>(a2 + 20);
    }

    const bool isFakeIp = IsHostFakeIpAfterNormalize(key);

    void* cacheMtx = RvaPtr(rva::kDnsCacheMutex);
    HostMutexGuard lock(cacheMtx);

    uint8_t* head = *RvaPtr<uint8_t**>(rva::kReverseCacheMapHead);
    uint8_t* candidate = head;
    uint8_t* node = *reinterpret_cast<uint8_t**>(head + 8); // root

    using SockAddrLessFn = uint8_t (__fastcall*)(const void*, const void*);
    auto lessFn = RvaPtr<SockAddrLessFn>(rva::kSockAddrLess);

    while (node[25] == 0) { // !_Isnil
        if (lessFn(node + 32, key) != 0) {
            node = *reinterpret_cast<uint8_t**>(node + 16); // right
        } else {
            candidate = node;
            node = *reinterpret_cast<uint8_t**>(node + 0);  // left
        }
    }

    if (candidate == head || lessFn(key, candidate + 32) != 0) {
        return 0;
    }

    // Node layout verified in sub_140033C90 & sub_140032F20:
    //   +64 (QWORD* + 8) : uint64_t timestamp_ms
    //   +72 (DWORD* + 18): uint32_t ttl_sec
    //   +80              : std::string hostname
    //   +112             : 28-byte SockAddr
    //   +144             : std::vector<uint8_t> raw_dns
    const uint64_t nowMs = GetTickCount64();
    const uint64_t entryTsMs = *reinterpret_cast<const uint64_t*>(candidate + 64);
    const uint32_t entryTtlSec = *reinterpret_cast<const uint32_t*>(candidate + 72);
    const uint64_t ttlMs = static_cast<uint64_t>(entryTtlSec) * 1000ULL;

    if (!isFakeIp) {
        // Real-IP: enforce strict insertion-time expiry and DO NOT slide timestamp!
        if (nowMs - entryTsMs > ttlMs) {
            return 0;
        }
    } else {
        // Fake-IP: check expiry first (if already expired before lookup, miss; otherwise slide 24h window)
        if (nowMs - entryTsMs > ttlMs) {
            return 0;
        }
        *reinterpret_cast<uint64_t*>(candidate + 64) = nowMs;
    }

    // Copy hostname std::string via host's std::string::_Append<char>
    uint8_t* entryStr = candidate + 80;
    if (outHostnameStr != entryStr) {
        const char* srcChars = reinterpret_cast<const char*>(entryStr);
        const uint64_t strSize = *reinterpret_cast<const uint64_t*>(entryStr + 16);
        const uint64_t strCap  = *reinterpret_cast<const uint64_t*>(entryStr + 24);
        if (strCap >= 0x10u) {
            srcChars = *reinterpret_cast<const char* const*>(entryStr);
        }
        using StrAppendFn = void* (__fastcall*)(void*, const char*, size_t);
        RvaPtr<StrAppendFn>(rva::kHostStringAppend)(outHostnameStr, srcChars, static_cast<size_t>(strSize));
    }

    // Copy 28-byte SockAddr at candidate + 112
    std::memcpy(outAddr28, candidate + 112, 28);

    // Copy vector at candidate + 144
    uint8_t* entryVec = candidate + 144;
    if (outVec != entryVec) {
        using CopyVecFn = void (__fastcall*)(void*, uint64_t, uint64_t);
        RvaPtr<CopyVecFn>(rva::kCopyVecBytes)(
            outVec,
            *reinterpret_cast<const uint64_t*>(entryVec + 0),
            *reinterpret_cast<const uint64_t*>(entryVec + 8));
    }

    return 1;
}

bool PatchGetTickCountTo64(uintptr_t callSiteRva, uintptr_t postInstrRva, bool isMovR14) noexcept {
    uint8_t* callSite = RvaPtr<uint8_t*>(callSiteRva);
    if (callSite[0] != 0xFF || callSite[1] != 0x15) {
        return false;
    }
    uint8_t* postSite = RvaPtr<uint8_t*>(postInstrRva);
    if (isMovR14) {
        // 44 8B F0 (mov r14d, eax) -> 4C 8B F0 (mov r14, rax)
        if (postSite[0] != 0x44 || postSite[1] != 0x8B || postSite[2] != 0xF0) {
            return false;
        }
    } else {
        // 8B C0 (mov eax, eax) -> 66 90 (2-byte nop)
        if (postSite[0] != 0x8B || postSite[1] != 0xC0) {
            return false;
        }
    }

    const intptr_t disp = reinterpret_cast<intptr_t>(RvaPtr(rva::kIatGetTickCount64)) -
                          reinterpret_cast<intptr_t>(callSite + 6);
    if (disp < INT32_MIN || disp > INT32_MAX) {
        return false;
    }
    uint8_t callPatch[6] = { 0xFF, 0x15, 0, 0, 0, 0 };
    const int32_t disp32 = static_cast<int32_t>(disp);
    std::memcpy(callPatch + 2, &disp32, sizeof(disp32));
    if (!WriteMemoryPatch(callSite, callPatch, sizeof(callPatch))) {
        return false;
    }

    if (isMovR14) {
        const uint8_t movR14[3] = { 0x4C, 0x8B, 0xF0 };
        return WriteMemoryPatch(postSite, movR14, sizeof(movR14));
    } else {
        const uint8_t nop2[2] = { 0x66, 0x90 };
        return WriteMemoryPatch(postSite, nop2, sizeof(nop2));
    }
}

} // namespace

bool InstallCacheAndTimestampFixes() noexcept {
    // 1. Patch all 5 DNS cache insertion sites from 32-bit GetTickCount to 64-bit GetTickCount64:
    if (!PatchGetTickCountTo64(rva::kTickSite1, 0x0336B1, true))  return false;
    if (!PatchGetTickCountTo64(rva::kTickSite2, 0x033868, false)) return false;
    if (!PatchGetTickCountTo64(rva::kTickSite3, 0x03398C, false)) return false;
    if (!PatchGetTickCountTo64(rva::kTickSite4, 0x034209, false)) return false;
    if (!PatchGetTickCountTo64(rva::kTickSite5, 0x0350A0, false)) return false;

    // 2. Patch sub_140033670 internal 86400s floor -> 15s (`BF 0F 00 00 00`) and `+1000s` -> `mov edi, esi; nop4`
    static const uint8_t kExpectedFloor[5]   = { 0xBF, 0x80, 0x51, 0x01, 0x00 };
    static const uint8_t kNewFloor[5]        = { 0xBF, 0x0F, 0x00, 0x00, 0x00 };
    static const uint8_t kExpectedAdd1000[6] = { 0x8D, 0xBE, 0xE8, 0x03, 0x00, 0x00 };
    static const uint8_t kNewMovEdiEsi[6]    = { 0x8B, 0xFE, 0x0F, 0x1F, 0x40, 0x00 };

    if (std::memcmp(RvaPtr(rva::kRealIpFloorMov), kExpectedFloor, 5) != 0 ||
        std::memcmp(RvaPtr(rva::kRealIpAdd1000), kExpectedAdd1000, 6) != 0)
    {
        return false;
    }
    if (!WriteMemoryPatch(RvaPtr(rva::kRealIpFloorMov), kNewFloor, 5) ||
        !WriteMemoryPatch(RvaPtr(rva::kRealIpAdd1000), kNewMovEdiEsi, 6))
    {
        return false;
    }

    // 3. Detour sub_140033670 (RealIpReverseCacheInsert, 5-byte boundary: `40 55 56 57 41 56` -> 6 bytes!)
    static const uint8_t kRealIpInsertPrologue[6] = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x56 };
    if (std::memcmp(RvaPtr(rva::kRealIpReverseInsert), kRealIpInsertPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kRealIpReverseInsert, reinterpret_cast<void*>(&Detour_RealIpReverseInsert),
                       reinterpret_cast<void**>(&g_origRealIpReverseInsert), 6))
    {
        return false;
    }

    // 4. Detour sub_140033C90 (ReverseIpLookup, 6-byte boundary: `4C 8B DC 55 56 57`)
    static const uint8_t kRevLookupPrologue[6] = { 0x4C, 0x8B, 0xDC, 0x55, 0x56, 0x57 };
    if (std::memcmp(RvaPtr(rva::kReverseIpLookup), kRevLookupPrologue, 6) != 0) {
        return false;
    }
    void* unusedLookupOrig = nullptr;
    if (!InstallDetour(rva::kReverseIpLookup, reinterpret_cast<void*>(&Detour_ReverseIpLookup),
                       &unusedLookupOrig, 6))
    {
        return false;
    }

    // 5. Detour sub_140034080 (FakeIpAllocate, 6-byte boundary: `40 55 56 57 41 54`) to serialize Fake-IP counter!
    static const uint8_t kFakeAllocPrologue[6] = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54 };
    if (std::memcmp(RvaPtr(rva::kFakeIpAllocate), kFakeAllocPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kFakeIpAllocate, reinterpret_cast<void*>(&Detour_FakeIpAllocate),
                       reinterpret_cast<void**>(&g_origFakeIpAllocate), 6))
    {
        return false;
    }

    return true;
}

} // namespace hotfix
