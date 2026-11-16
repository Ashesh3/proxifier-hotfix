#include "host_abi.h"
#include <process.h>
#include <deque>
#include <vector>
#include <cstring>

namespace hotfix {

namespace {

// ============================================================================
// Fix 6a: Exception-Safe Thread-Local Overlapped Event Cache (sub_140003CF0)
// ============================================================================
struct TlsEventSlot {
    HANDLE hEvent = nullptr;
    bool   inUse  = false;
};

DWORD g_tlsEventSlotIdx = TLS_OUT_OF_INDEXES;

HANDLE __fastcall AcquireTlsIoctlEvent() noexcept {
    if (g_tlsEventSlotIdx != TLS_OUT_OF_INDEXES) {
        auto* slot = static_cast<TlsEventSlot*>(TlsGetValue(g_tlsEventSlotIdx));
        if (!slot) {
            slot = static_cast<TlsEventSlot*>(
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TlsEventSlot)));
            if (slot) {
                if (!TlsSetValue(g_tlsEventSlotIdx, slot)) {
                    HeapFree(GetProcessHeap(), 0, slot);
                    slot = nullptr;
                }
            }
        }
        if (slot && !slot->inUse) {
            if (!slot->hEvent) {
                slot->hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (!slot->hEvent) {
                    // Preserve exact GetLastError() for caller at 0x140003D68!
                    return nullptr;
                }
            }
            slot->inUse = true;
            g_diag.tlsEventReuses.fetch_add(1, std::memory_order_relaxed);
            return slot->hEvent;
        }
    }
    // Nested / fallback call: create fresh auto-reset event
    return CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

BOOL __fastcall ReleaseTlsIoctlEvent(HANDLE h) noexcept {
    if (!h) {
        return TRUE;
    }
    if (g_tlsEventSlotIdx != TLS_OUT_OF_INDEXES) {
        const DWORD savedErr = GetLastError();
        auto* slot = static_cast<TlsEventSlot*>(TlsGetValue(g_tlsEventSlotIdx));
        SetLastError(savedErr);
        if (slot && h == slot->hEvent) {
            slot->inUse = false;
            return TRUE;
        }
    }
    return CloseHandle(h);
}

BOOL __fastcall Detour_IoctlEhCloseHelper(HANDLE* ph) noexcept {
    if (!ph || !*ph) {
        return TRUE;
    }
    return ReleaseTlsIoctlEvent(*ph);
}

// ============================================================================
// Fix 6b: Causal Sharded Flow/DNS Workers + Dynamic-Overflow ALE Redirect Pool
// ============================================================================
struct HostByteVector {
    uint8_t* begin  = nullptr;
    uint8_t* end    = nullptr;
    uint8_t* endCap = nullptr;
};

constexpr size_t kNumDnsShards        = 4;
constexpr size_t kMaxShardQueueItems  = 1024;
constexpr size_t kNumAleBaseThreads   = 32;
constexpr size_t kMaxAleOverflowTotal = 192; // up to 160 overflow threads if proxies/dialogs stall
constexpr size_t kMaxAleQueueItems    = 512;

inline uint64_t Mix64(uint64_t x) noexcept {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}

struct AleQueueItem {
    HostByteVector ev{};
    uint64_t       enqueueTickMs = 0;
};

struct AlePool {
    SRWLOCK                  lock = SRWLOCK_INIT;
    CONDITION_VARIABLE       notEmpty = CONDITION_VARIABLE_INIT;
    CONDITION_VARIABLE       notFull  = CONDITION_VARIABLE_INIT;
    std::deque<AleQueueItem> queue;
    std::vector<HANDLE>      threads;
    uint32_t                 idleWorkers = 0;
    uint32_t                 totalSpawned = 0;
    bool                     stopping = false;
};

struct FlowShard {
    SRWLOCK                    lock = SRWLOCK_INIT;
    CONDITION_VARIABLE         notEmpty = CONDITION_VARIABLE_INIT;
    CONDITION_VARIABLE         notFull  = CONDITION_VARIABLE_INIT;
    std::deque<HostByteVector> queue;
    HANDLE                     thread = nullptr;
    bool                       stopping = false;
};

AlePool   g_alePool;
FlowShard g_flowShards[kNumDnsShards];
std::atomic<bool> g_poolsRunning{false};
std::atomic<bool> g_shuttingDown{false};

void FreeHostByteVector(HostByteVector& v) noexcept {
    if (v.begin) {
        HostFreeVectorBuffer(v.begin, v.endCap);
        v.begin = v.end = v.endCap = nullptr;
    }
}

// Clones the pump's `v72` (`CNfeEvent`) using the host's `sub_140004BF0`
bool CloneHostCnfeEvent(const HostByteVector* src, HostByteVector& dst) {
    dst = {};
    using CopyEventFn = void* (__fastcall*)(HostByteVector*, const HostByteVector*);
    RvaPtr<CopyEventFn>(rva::kCopyCnfeEvent)(&dst, src);
    return (src->begin == src->end) || (dst.begin != nullptr);
}

// Executes Event 2 (`ALE_CONNECT_REDIRECT`) via host `sub_1400658B0`.
// Moves `HostByteVector` into a local 24-byte copy so `sub_1400658B0` owns and frees it cleanly.
void ExecuteAleEvent(HostByteVector& ev) noexcept {
    HostByteVector localEv = ev;
    ev = {};
    try {
        using AleHandlerFn = void (__fastcall*)(HostByteVector*);
        RvaPtr<AleHandlerFn>(rva::kHandleAleRedirect)(&localEv);
    } catch (...) {
        // If an exception escaped before sub_1400658B0 freed localEv, free it safely
    }
    FreeHostByteVector(localEv);
}

// Executes Event 4 (`FLOW_ESTABLISHED`) identically to `0x1400642CA..0x14006435D`
void ExecuteFlowEstablishEvent(const HostByteVector& ev) noexcept {
    uint8_t* data = ev.begin;
    if (!data) return;

    // 32-byte MSVC std::wstring SSO initialized empty (`size=0, cap=7`)
    alignas(8) uint64_t wstr[4] = { 0, 0, 0, 7 };
    *reinterpret_cast<uint16_t*>(wstr) = 0;

    void* flowMtx = RvaPtr(rva::kFlowMapMutex);
    bool locked = false;
    try {
        HostLockMutex(flowMtx);
        locked = true;

        const uint32_t evType = *reinterpret_cast<const uint32_t*>(data + 32);
        constexpr uint32_t kMask = 0x94u; // 148 (`1<<2 | 1<<4 | 1<<7`)
        if (evType <= 7 && ((kMask >> evType) & 1u) != 0) {
            if (*reinterpret_cast<const uint32_t*>(data + 28) != 0) {
                using AssignZFn = void* (__fastcall*)(void*, const wchar_t*, int64_t);
                RvaPtr<AssignZFn>(rva::kHostWstringAssignZ)(
                    wstr, reinterpret_cast<const wchar_t*>(data + 304), 0);
            }
            const auto* keyPtr = reinterpret_cast<const uint64_t*>(data + 168);
            using MapIdxFn = uint8_t* (__fastcall*)(uint64_t, const uint64_t*);
            uint8_t* dstWstr = RvaPtr<MapIdxFn>(rva::kFlowMapOperatorIdx)(0, keyPtr);
            if (reinterpret_cast<void*>(dstWstr) != reinterpret_cast<void*>(wstr)) {
                const void* srcChars = (wstr[3] >= 8)
                    ? reinterpret_cast<const void*>(wstr[0])
                    : reinterpret_cast<const void*>(wstr);
                using AssignNFn = void* (__fastcall*)(void*, const void*, size_t);
                RvaPtr<AssignNFn>(rva::kHostWstringAssignN)(dstWstr, srcChars, static_cast<size_t>(wstr[2]));
            }
        }
        HostUnlockMutex(flowMtx);
        locked = false;
    } catch (...) {
        if (locked) {
            HostUnlockMutex(flowMtx);
        }
    }
    HostWstringTidy(wstr);
}

// Executes Event 5 (`FLOW_DELETE`) identically to `0x140064370..0x140064440`
void ExecuteFlowDeleteEvent(const HostByteVector& ev) noexcept {
    uint8_t* data = ev.begin;
    if (!data) return;

    void* flowMtx = RvaPtr(rva::kFlowMapMutex);
    bool locked = false;
    try {
        HostLockMutex(flowMtx);
        locked = true;

        void* mapContainerPtr = RvaPtr(rva::kFlowMapHead);
        uint8_t* head = *reinterpret_cast<uint8_t**>(mapContainerPtr);
        uint8_t* candidate = head;
        uint8_t* node = *reinterpret_cast<uint8_t**>(head + 8); // root
        const uint64_t key = *reinterpret_cast<const uint64_t*>(data + 168);

        while (node[25] == 0) {
            const uint64_t nodeKey = *reinterpret_cast<const uint64_t*>(node + 32);
            if (nodeKey >= key) {
                candidate = node;
                node = *reinterpret_cast<uint8_t**>(node + 0);
            } else {
                node = *reinterpret_cast<uint8_t**>(node + 16);
            }
        }
        if (candidate != head && key >= *reinterpret_cast<const uint64_t*>(candidate + 32)) {
            // Unlink node via host `sub_1400349F0(rcx = &qword_1404126A0, rdx = candidate)`
            using EraseFn = uint8_t* (__fastcall*)(void*, void*);
            uint8_t* erased = RvaPtr<EraseFn>(rva::kRbTreeErase)(mapContainerPtr, candidate);
            HostWstringTidy(erased + 40);
            HostFree(erased);
        }

        HostUnlockMutex(flowMtx);
        locked = false;
    } catch (...) {
        if (locked) {
            HostUnlockMutex(flowMtx);
        }
    }
}

// Executes Event 3 (`DATAGRAM_DATA` UDP 53) via host `sub_140065DB0`
void ExecuteDnsDatagramEvent(HostByteVector& ev) noexcept {
    try {
        using DnsHandlerFn = void (__fastcall*)(HostByteVector*);
        RvaPtr<DnsHandlerFn>(rva::kHandleDnsDatagram)(&ev);
    } catch (...) {
    }
    // sub_140065DB0 only reads `ev`; caller owns and frees `ev`!
    FreeHostByteVector(ev);
}

void ExecuteFlowOrDnsItem(HostByteVector& ev) noexcept {
    if (!ev.begin) {
        return;
    }
    const uint32_t evType = *reinterpret_cast<const uint32_t*>(ev.begin + 32);
    if (evType == 4) {
        ExecuteFlowEstablishEvent(ev);
        FreeHostByteVector(ev);
    } else if (evType == 5) {
        ExecuteFlowDeleteEvent(ev);
        FreeHostByteVector(ev);
    } else if (evType == 3) {
        ExecuteDnsDatagramEvent(ev);
    } else {
        FreeHostByteVector(ev);
    }
}

unsigned __stdcall AleWorkerProc(void* param) {
    const bool isOverflow = (param != nullptr);
    while (true) {
        AleQueueItem item{};
        AcquireSRWLockExclusive(&g_alePool.lock);
        g_alePool.idleWorkers++;
        while (g_alePool.queue.empty() && !g_alePool.stopping) {
            if (isOverflow) {
                // Dynamic overflow worker exits cleanly after 5 seconds idle
                if (!SleepConditionVariableSRW(&g_alePool.notEmpty, &g_alePool.lock, 5000, 0)) {
                    if (g_alePool.queue.empty()) {
                        g_alePool.idleWorkers--;
                        ReleaseSRWLockExclusive(&g_alePool.lock);
                        return 0;
                    }
                }
            } else {
                SleepConditionVariableSRW(&g_alePool.notEmpty, &g_alePool.lock, INFINITE, 0);
            }
        }
        g_alePool.idleWorkers--;

        if (g_alePool.stopping) {
            // During shutdown, driver stop aborts pending ALE redirects; drain & free remaining buffers fast
            while (!g_alePool.queue.empty()) {
                AleQueueItem rem = g_alePool.queue.front();
                g_alePool.queue.pop_front();
                FreeHostByteVector(rem.ev);
            }
            WakeAllConditionVariable(&g_alePool.notFull);
            ReleaseSRWLockExclusive(&g_alePool.lock);
            return 0;
        }

        item = g_alePool.queue.front();
        g_alePool.queue.pop_front();
        WakeConditionVariable(&g_alePool.notFull);
        ReleaseSRWLockExclusive(&g_alePool.lock);

        ExecuteAleEvent(item.ev);
    }
}

unsigned __stdcall FlowShardWorkerProc(void* param) {
    auto* shard = static_cast<FlowShard*>(param);
    while (true) {
        HostByteVector ev{};
        AcquireSRWLockExclusive(&shard->lock);
        while (shard->queue.empty() && !shard->stopping) {
            SleepConditionVariableSRW(&shard->notEmpty, &shard->lock, INFINITE, 0);
        }
        if (shard->queue.empty() && shard->stopping) {
            ReleaseSRWLockExclusive(&shard->lock);
            return 0;
        }
        ev = shard->queue.front();
        shard->queue.pop_front();
        WakeConditionVariable(&shard->notFull);
        ReleaseSRWLockExclusive(&shard->lock);

        // If shutting down, skip UDP DNS injection (Event 3) after driver stop, but still settle flow map cleanups
        if (g_shuttingDown.load(std::memory_order_acquire) && ev.begin &&
            *reinterpret_cast<const uint32_t*>(ev.begin + 32) == 3)
        {
            FreeHostByteVector(ev);
            continue;
        }
        ExecuteFlowOrDnsItem(ev);
    }
}

void StartWorkerPoolsOnce() noexcept {
    bool expected = false;
    if (!g_poolsRunning.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    for (size_t i = 0; i < kNumDnsShards; ++i) {
        uintptr_t th = _beginthreadex(nullptr, 0, &FlowShardWorkerProc, &g_flowShards[i], 0, nullptr);
        if (th != 0) {
            g_flowShards[i].thread = reinterpret_cast<HANDLE>(th);
        }
    }

    AcquireSRWLockExclusive(&g_alePool.lock);
    g_alePool.threads.reserve(kMaxAleOverflowTotal);
    for (size_t i = 0; i < kNumAleBaseThreads; ++i) {
        uintptr_t th = _beginthreadex(nullptr, 0, &AleWorkerProc, nullptr, 0, nullptr);
        if (th != 0) {
            g_alePool.threads.push_back(reinterpret_cast<HANDLE>(th));
            g_alePool.totalSpawned++;
        }
    }
    ReleaseSRWLockExclusive(&g_alePool.lock);
}

// Dispatches Event 2 (`ALE_CONNECT_REDIRECT`) from `sub_1400640A0`.
// Never throws across ABI boundary; spawns bounded overflow worker if all 32 base workers are busy
// and oldest queued item is >= 50 ms old; falls back inline only if allocation fails.
void __fastcall DispatchAleEventFromPump(HostByteVector* pumpVec) noexcept {
    if (!pumpVec || !pumpVec->begin) {
        return;
    }
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        return;
    }
    StartWorkerPoolsOnce();
    g_diag.aleEventsDispatched.fetch_add(1, std::memory_order_relaxed);

    HostByteVector cloned{};
    try {
        if (!CloneHostCnfeEvent(pumpVec, cloned)) {
            return;
        }
    } catch (...) {
        // OOM during clone: execute inline on a move of pumpVec? No, pumpVec is reused by pump loop (`v72`),
        // so pass a stack view or skip only on hard OOM after freeing partial buffer.
        FreeHostByteVector(cloned);
        return;
    }

    const uint64_t nowMs = GetTickCount64();
    AcquireSRWLockExclusive(&g_alePool.lock);
    if (g_alePool.stopping) {
        ReleaseSRWLockExclusive(&g_alePool.lock);
        FreeHostByteVector(cloned);
        return;
    }

    // Starvation defense (Opus 5.5 §5 #18): if no worker is idle and queue head is >= 50ms old (or queue near full),
    // spawn a dynamic overflow worker (tracked & joined on shutdown, capped at kMaxAleOverflowTotal).
    const bool needOverflow = (g_alePool.idleWorkers == 0) &&
                              (!g_alePool.queue.empty() && (nowMs - g_alePool.queue.front().enqueueTickMs >= 50)) &&
                              (g_alePool.totalSpawned < kMaxAleOverflowTotal);
    if (needOverflow) {
        uintptr_t th = _beginthreadex(nullptr, 0, &AleWorkerProc, reinterpret_cast<void*>(1), 0, nullptr);
        if (th != 0) {
            try {
                g_alePool.threads.push_back(reinterpret_cast<HANDLE>(th));
                g_alePool.totalSpawned++;
            } catch (...) {
                CloseHandle(reinterpret_cast<HANDLE>(th));
            }
        }
    }

    while (g_alePool.queue.size() >= kMaxAleQueueItems && !g_alePool.stopping) {
        SleepConditionVariableSRW(&g_alePool.notFull, &g_alePool.lock, 50, 0);
        if (g_alePool.idleWorkers == 0 && g_alePool.totalSpawned < kMaxAleOverflowTotal) {
            uintptr_t th = _beginthreadex(nullptr, 0, &AleWorkerProc, reinterpret_cast<void*>(1), 0, nullptr);
            if (th != 0) {
                try {
                    g_alePool.threads.push_back(reinterpret_cast<HANDLE>(th));
                    g_alePool.totalSpawned++;
                } catch (...) {
                    CloseHandle(reinterpret_cast<HANDLE>(th));
                }
            }
        }
    }

    if (g_alePool.stopping) {
        ReleaseSRWLockExclusive(&g_alePool.lock);
        FreeHostByteVector(cloned);
        return;
    }

    try {
        g_alePool.queue.push_back(AleQueueItem{cloned, nowMs});
        cloned = {};
    } catch (...) {
        ReleaseSRWLockExclusive(&g_alePool.lock);
        ExecuteAleEvent(cloned);
        return;
    }
    WakeConditionVariable(&g_alePool.notEmpty);
    ReleaseSRWLockExclusive(&g_alePool.lock);
}

// Dispatches Events 4 (`FLOW_ESTABLISHED`), 3 (`DATAGRAM_DATA`), and 5 (`FLOW_DELETE`) onto the causal shard
// `Mix64(flowContext) & (kNumDnsShards - 1)`.
// Preserves strict per-flow ordering even on OOM fallback by draining the shard before running inline!
void __fastcall DispatchFlowOrDnsEventFromPump(HostByteVector* pumpVec) noexcept {
    if (!pumpVec || !pumpVec->begin) {
        return;
    }
    StartWorkerPoolsOnce();
    g_diag.flowEventsDispatched.fetch_add(1, std::memory_order_relaxed);

    const uint64_t flowContext = *reinterpret_cast<const uint64_t*>(pumpVec->begin + 168);
    const size_t shardIdx = static_cast<size_t>(Mix64(flowContext) & (kNumDnsShards - 1));
    FlowShard& shard = g_flowShards[shardIdx];

    if (!shard.thread || g_shuttingDown.load(std::memory_order_acquire)) {
        // Inline execution when shutting down (skipping Event 3 UDP injection)
        const uint32_t evType = *reinterpret_cast<const uint32_t*>(pumpVec->begin + 32);
        if (evType == 4) {
            ExecuteFlowEstablishEvent(*pumpVec);
        } else if (evType == 5) {
            ExecuteFlowDeleteEvent(*pumpVec);
        }
        return;
    }

    HostByteVector cloned{};
    bool cloneOk = false;
    try {
        cloneOk = CloneHostCnfeEvent(pumpVec, cloned);
    } catch (...) {
        FreeHostByteVector(cloned);
        cloneOk = false;
    }

    if (!cloneOk) {
        // OOM fallback: wait until shard queue drains so causal order (4 -> 3 -> 5) is NEVER violated!
        AcquireSRWLockExclusive(&shard.lock);
        while (!shard.queue.empty() && !shard.stopping) {
            SleepConditionVariableSRW(&shard.notFull, &shard.lock, 10, 0);
        }
        ReleaseSRWLockExclusive(&shard.lock);

        const uint32_t evType = *reinterpret_cast<const uint32_t*>(pumpVec->begin + 32);
        if (evType == 4) {
            ExecuteFlowEstablishEvent(*pumpVec);
        } else if (evType == 5) {
            ExecuteFlowDeleteEvent(*pumpVec);
        } else if (evType == 3 && !g_shuttingDown.load(std::memory_order_acquire)) {
            try {
                using DnsHandlerFn = void (__fastcall*)(HostByteVector*);
                RvaPtr<DnsHandlerFn>(rva::kHandleDnsDatagram)(pumpVec);
            } catch (...) {
            }
        }
        return;
    }

    AcquireSRWLockExclusive(&shard.lock);
    while (shard.queue.size() >= kMaxShardQueueItems && !shard.stopping) {
        SleepConditionVariableSRW(&shard.notFull, &shard.lock, INFINITE, 0);
    }
    if (shard.stopping) {
        ReleaseSRWLockExclusive(&shard.lock);
        if (*reinterpret_cast<const uint32_t*>(cloned.begin + 32) != 3) {
            ExecuteFlowOrDnsItem(cloned);
        } else {
            FreeHostByteVector(cloned);
        }
        return;
    }

    try {
        shard.queue.push_back(cloned);
        cloned = {};
    } catch (...) {
        while (!shard.queue.empty() && !shard.stopping) {
            SleepConditionVariableSRW(&shard.notFull, &shard.lock, 10, 0);
        }
        ReleaseSRWLockExclusive(&shard.lock);
        ExecuteFlowOrDnsItem(cloned);
        return;
    }
    WakeConditionVariable(&shard.notEmpty);
    ReleaseSRWLockExclusive(&shard.lock);
}

// Helper to patch a case block inside `sub_1400640A0` so it executes:
//   lea rcx, [rbp - 8]        ; 48 8D 4D F8 (`&v72`, CNfeEvent vector)
//   call <relay_to_dispatch>  ; E8 <rel32>  (return address stays inside sub_1400640A0's EH state 1!)
//   jmp loc_14006482F         ; E9 <rel32> or EB <rel8>
bool PatchPumpCaseToDispatch(uintptr_t caseStartRva, void* dispatchFn, bool useShortJmp82F) noexcept {
    uint8_t* site = RvaPtr<uint8_t*>(caseStartRva);
    uint8_t* relay = AllocTrampolineCode(16, 16);
    if (!relay) {
        return false;
    }
    relay[0] = 0xFF; relay[1] = 0x25;
    relay[2] = 0x00; relay[3] = 0x00; relay[4] = 0x00; relay[5] = 0x00;
    const uintptr_t fnAddr = reinterpret_cast<uintptr_t>(dispatchFn);
    std::memcpy(relay + 6, &fnAddr, sizeof(fnAddr));

    uint8_t buf[16]{};
    // lea rcx, [rbp - 8] (4 bytes)
    buf[0] = 0x48; buf[1] = 0x8D; buf[2] = 0x4D; buf[3] = 0xF8;
    // call relay (5 bytes, return address = site + 9, strictly inside parent EH state 1!)
    buf[4] = 0xE8;
    const int32_t callRel = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(relay) - reinterpret_cast<intptr_t>(site + 9));
    std::memcpy(buf + 5, &callRel, sizeof(callRel));

    size_t totalBytes = 0;
    if (useShortJmp82F) {
        // Case 3 at 0x647D7 is only 11 bytes (`48 8D 4D F8 E8 D0 15 00 00 EB 4D`)!
        buf[9] = 0xEB;
        const intptr_t jmpRel8 = reinterpret_cast<intptr_t>(RvaPtr(0x06482F)) - reinterpret_cast<intptr_t>(site + 11);
        if (jmpRel8 < -128 || jmpRel8 > 127) {
            return false;
        }
        buf[10] = static_cast<uint8_t>(static_cast<int8_t>(jmpRel8));
        totalBytes = 11;
    } else {
        buf[9] = 0xE9;
        const int32_t jmpRel32 = static_cast<int32_t>(
            reinterpret_cast<intptr_t>(RvaPtr(0x06482F)) - reinterpret_cast<intptr_t>(site + 14));
        std::memcpy(buf + 10, &jmpRel32, sizeof(jmpRel32));
        totalBytes = 14;
    }
    return WriteMemoryPatch(site, buf, totalBytes);
}

bool Patch6ByteCallToRelay(uintptr_t callSiteRva, void* targetFn) noexcept {
    uint8_t* site = RvaPtr<uint8_t*>(callSiteRva);
    if (site[0] != 0xFF || site[1] != 0x15) {
        return false;
    }
    uint8_t* slot = AllocTrampolineCode(8, 8);
    if (!slot) {
        return false;
    }
    const uintptr_t addr = reinterpret_cast<uintptr_t>(targetFn);
    std::memcpy(slot, &addr, sizeof(addr));

    const intptr_t disp = reinterpret_cast<intptr_t>(slot) - reinterpret_cast<intptr_t>(site + 6);
    if (disp < INT32_MIN || disp > INT32_MAX) {
        return false;
    }
    uint8_t patch[6] = { 0xFF, 0x15, 0, 0, 0, 0 };
    const int32_t disp32 = static_cast<int32_t>(disp);
    std::memcpy(patch + 2, &disp32, sizeof(disp32));
    return WriteMemoryPatch(site, patch, sizeof(patch));
}

void JoinHandlesPumpingSentMessages(const std::vector<HANDLE>& handles, DWORD timeoutMs) noexcept {
    const uint64_t deadline = GetTickCount64() + timeoutMs;
    for (HANDLE h : handles) {
        if (!h) continue;
        while (true) {
            const uint64_t now = GetTickCount64();
            const DWORD rem = (now >= deadline) ? 0u : static_cast<DWORD>(deadline - now);
            const DWORD wr = MsgWaitForMultipleObjectsEx(
                1, &h, rem, QS_SENDMESSAGE, MWMO_INPUTAVAILABLE);
            if (wr == WAIT_OBJECT_0 || wr == WAIT_FAILED) {
                break;
            }
            if (wr == WAIT_OBJECT_0 + 1) {
                // Dispatch cross-thread SendMessageW calls so worker threads in sub_1400B5D40 never deadlock!
                MSG msg{};
                PeekMessageW(&msg, nullptr, 0, 0, PM_NOREMOVE | PM_QS_SENDMESSAGE);
                continue;
            }
            if (wr == WAIT_TIMEOUT) {
                // Never return into CRT global destructor teardown while a worker thread is still alive!
                TerminateProcess(GetCurrentProcess(), 0);
            }
        }
        CloseHandle(h);
    }
}

} // namespace

bool InstallWfpPoolAndEventCacheFixes() noexcept {
    g_tlsEventSlotIdx = TlsAlloc();
    if (g_tlsEventSlotIdx == TLS_OUT_OF_INDEXES) {
        return false;
    }

    // 1. Verify & install TLS event cache hooks at 0x3D56, 0x3F26, and EH cleanup helper 0x3F50
    static const uint8_t kExpectedEhHelper[8] = {
        0x48, 0x8B, 0x09, 0x48, 0x85, 0xC9, 0x74, 0x07
    };
    if (std::memcmp(RvaPtr(rva::kIoctlEhCloseHelper), kExpectedEhHelper, 8) != 0) {
        return false;
    }
    if (!Patch6ByteCallToRelay(rva::kIoctlCreateEventCall, reinterpret_cast<void*>(&AcquireTlsIoctlEvent))) {
        return false;
    }
    if (!Patch6ByteCallToRelay(rva::kIoctlCloseHandleCall, reinterpret_cast<void*>(&ReleaseTlsIoctlEvent))) {
        return false;
    }
    void* unusedEhOrig = nullptr;
    if (!InstallDetour(rva::kIoctlEhCloseHelper, reinterpret_cast<void*>(&Detour_IoctlEhCloseHelper), &unusedEhOrig, 6)) {
        return false;
    }

    // 2. Verify exact bytes of WFP pump switch cases 2, 4, 5, 3 in sub_1400640A0
    static const uint8_t kExpectedCase2[8] = { 0x8D, 0x48, 0x1E, 0xE8, 0x46, 0x65, 0x05, 0x00 };
    static const uint8_t kExpectedCase4[8] = { 0x48, 0x89, 0x75, 0xE8, 0x48, 0xC7, 0x45, 0xF0 };
    static const uint8_t kExpectedCase5[8] = { 0x49, 0x8B, 0xCE, 0xE8, 0x54, 0xF4, 0x20, 0x00 };
    static const uint8_t kExpectedCase3[11] = {
        0x48, 0x8D, 0x4D, 0xF8, 0xE8, 0xD0, 0x15, 0x00, 0x00, 0xEB, 0x4D
    };

    if (std::memcmp(RvaPtr(rva::kWfpCase2Start), kExpectedCase2, 8) != 0 ||
        std::memcmp(RvaPtr(rva::kWfpCase4Start), kExpectedCase4, 8) != 0 ||
        std::memcmp(RvaPtr(rva::kWfpCase5Start), kExpectedCase5, 8) != 0 ||
        std::memcmp(RvaPtr(rva::kWfpCase3Start), kExpectedCase3, 11) != 0)
    {
        return false;
    }

    if (!PatchPumpCaseToDispatch(rva::kWfpCase2Start, reinterpret_cast<void*>(&DispatchAleEventFromPump), false)) {
        return false;
    }
    if (!PatchPumpCaseToDispatch(rva::kWfpCase4Start, reinterpret_cast<void*>(&DispatchFlowOrDnsEventFromPump), false)) {
        return false;
    }
    if (!PatchPumpCaseToDispatch(rva::kWfpCase5Start, reinterpret_cast<void*>(&DispatchFlowOrDnsEventFromPump), false)) {
        return false;
    }
    if (!PatchPumpCaseToDispatch(rva::kWfpCase3Start, reinterpret_cast<void*>(&DispatchFlowOrDnsEventFromPump), true)) {
        return false;
    }

    return true;
}

void OnPreDriverStopShutdown() noexcept {
    // 1. Set stopping flags BEFORE host ExitInstance calls driver stop (0x120008) and joins pump thread,
    //    so a pump parked on `notFull` wakes up immediately and never deadlocks `_Thrd_join`!
    g_shuttingDown.store(true, std::memory_order_release);

    // Release any ALE worker blocked on the proxy-auth dialog event (`hHandle` @ 0x412A90)
    HANDLE authEvent = *RvaPtr<HANDLE*>(rva::kProxyAuthEventHandle);
    if (authEvent != nullptr) {
        SetEvent(authEvent);
    }

    AcquireSRWLockExclusive(&g_alePool.lock);
    g_alePool.stopping = true;
    WakeAllConditionVariable(&g_alePool.notEmpty);
    WakeAllConditionVariable(&g_alePool.notFull);
    ReleaseSRWLockExclusive(&g_alePool.lock);

    for (size_t i = 0; i < kNumDnsShards; ++i) {
        AcquireSRWLockExclusive(&g_flowShards[i].lock);
        g_flowShards[i].stopping = true;
        WakeAllConditionVariable(&g_flowShards[i].notEmpty);
        WakeAllConditionVariable(&g_flowShards[i].notFull);
        ReleaseSRWLockExclusive(&g_flowShards[i].lock);
    }
}

void OnPostDriverStopShutdown() noexcept {
    if (!g_poolsRunning.load(std::memory_order_acquire)) {
        return;
    }

    std::vector<HANDLE> toJoin;
    AcquireSRWLockExclusive(&g_alePool.lock);
    g_alePool.stopping = true;
    WakeAllConditionVariable(&g_alePool.notEmpty);
    WakeAllConditionVariable(&g_alePool.notFull);
    toJoin.swap(g_alePool.threads);
    ReleaseSRWLockExclusive(&g_alePool.lock);

    for (size_t i = 0; i < kNumDnsShards; ++i) {
        AcquireSRWLockExclusive(&g_flowShards[i].lock);
        g_flowShards[i].stopping = true;
        WakeAllConditionVariable(&g_flowShards[i].notEmpty);
        WakeAllConditionVariable(&g_flowShards[i].notFull);
        if (g_flowShards[i].thread) {
            toJoin.push_back(g_flowShards[i].thread);
            g_flowShards[i].thread = nullptr;
        }
        ReleaseSRWLockExclusive(&g_flowShards[i].lock);
    }

    // Join all persistent + overflow workers while pumping QS_SENDMESSAGE!
    JoinHandlesPumpingSentMessages(toJoin, 15000);
}

void OnThreadDetachCleanup() noexcept {
    if (g_tlsEventSlotIdx != TLS_OUT_OF_INDEXES) {
        auto* slot = static_cast<TlsEventSlot*>(TlsGetValue(g_tlsEventSlotIdx));
        if (slot) {
            // Thread is exiting, so any overlapped I/O on its stack has already settled or unwound;
            // close the handle unconditionally (Opus 5.5 §5.1 #23) and free the slot!
            if (slot->hEvent) {
                CloseHandle(slot->hEvent);
                slot->hEvent = nullptr;
            }
            HeapFree(GetProcessHeap(), 0, slot);
            TlsSetValue(g_tlsEventSlotIdx, nullptr);
        }
    }
}

} // namespace hotfix
