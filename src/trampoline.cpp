#include "host_abi.h"
#include <cstring>
#include <algorithm>

namespace hotfix {

uintptr_t g_exeBase = 0;
HMODULE   g_selfModule = nullptr;
HotfixDiagnostics g_diag{};

#ifndef HOTFIX_UNIT_TEST
void* HostOperatorNew(size_t sz) {
    using Fn = void* (__fastcall*)(size_t);
    return RvaPtr<Fn>(rva::kHostOperatorNew)(sz);
}

void HostFree(void* p) noexcept {
    if (!p) return;
    using Fn = void (__fastcall*)(void*);
    RvaPtr<Fn>(rva::kHostFree)(p);
}

// Matches MSVC x64 std::vector::_Tidy deallocation with >= 0x1000 _Big_allocation_threshold alignment header
void HostFreeVectorBuffer(void* beginPtr, void* endCapPtr) noexcept {
    if (!beginPtr) return;
    auto* raw = static_cast<uint8_t*>(beginPtr);
    const auto capBytes = static_cast<size_t>(static_cast<uint8_t*>(endCapPtr) - raw);
    if (capBytes >= 0x1000u) {
        void* realBlock = reinterpret_cast<void**>(raw)[-1];
        const uintptr_t delta = reinterpret_cast<uintptr_t>(raw) - reinterpret_cast<uintptr_t>(realBlock) - sizeof(void*);
        if (delta <= 0x1Fu) {
            HostFree(realBlock);
            return;
        }
    }
    HostFree(raw);
}

void HostLockMutex(void* mtx) {
    using Fn = int (__fastcall*)(void*);
    const int rc = RvaPtr<Fn>(rva::kHostMtxLock)(mtx);
    if (rc != 0) {
        using ThrowFn = void (__fastcall*)(int);
        RvaPtr<ThrowFn>(rva::kHostThrowCError)(rc);
    }
}

void HostUnlockMutex(void* mtx) {
    using Fn = int (__fastcall*)(void*);
    const int rc = RvaPtr<Fn>(rva::kHostMtxUnlock)(mtx);
    if (rc != 0) {
        using ThrowFn = void (__fastcall*)(int);
        RvaPtr<ThrowFn>(rva::kHostThrowCError)(rc);
    }
}

struct HostXtime {
    int64_t sec;
    int32_t nsec;
    int32_t pad;
};

int HostTryLockMutex(void* mtx) noexcept {
    // Verify mutex type is not plain type-1 (which blocks even on zero xtime in mtx_do_lock)
    const uint32_t mtxType = *reinterpret_cast<const uint32_t*>(mtx);
    if ((mtxType & 0xFFFFFEFFu) == 1u) {
        return 3; // treat unexpected type-1 as busy rather than blocking UI
    }
    static constexpr HostXtime kZeroXtime{0, 0, 0};
    using Fn = int (__fastcall*)(void*, const HostXtime*);
    return RvaPtr<Fn>(rva::kHostMtxDoLock)(mtx, &kZeroXtime);
}

void HostWstringTidy(void* wstr) noexcept {
    using Fn = void (__fastcall*)(void*);
    RvaPtr<Fn>(rva::kHostWstringTidy)(wstr);
}
#endif

namespace {

constexpr size_t kCodeRegionSize = 32 * 1024; // 32 KiB RX code
constexpr size_t kDataRegionSize = 32 * 1024; // 32 KiB R  unwind metadata + RUNTIME_FUNCTION table
constexpr size_t kTotalSlabSize  = kCodeRegionSize + kDataRegionSize;
constexpr size_t kMaxRuntimeFns  = 64;

uint8_t* g_slabBase     = nullptr;
uintptr_t g_slabExeBase = 0;
size_t   g_codeOffset   = 0;
size_t   g_dataOffset   = 0;

RUNTIME_FUNCTION* g_rtFuncTable = nullptr;
uint32_t          g_rtFuncCount = 0;
bool              g_tableRegistered = false;

} // namespace

bool InitTrampolineSlab(uintptr_t exeBase, size_t imageSize) noexcept {
    if (g_slabBase != nullptr) {
        return true;
    }
    g_slabExeBase = exeBase;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000u;

    uintptr_t searchAddr = (exeBase + imageSize + gran - 1) & ~(gran - 1);
    const uintptr_t maxAddr = exeBase + 0x7EFF0000ULL; // safely within +2 GB signed rel32 & RVA reach

    while (searchAddr + kTotalSlabSize < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(searchAddr), &mbi, sizeof(mbi)) == 0) {
            break;
        }
        if (mbi.State == MEM_FREE) {
            const uintptr_t candidate = (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + gran - 1) & ~(gran - 1);
            const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (candidate >= searchAddr && candidate + kTotalSlabSize <= regionEnd && candidate + kTotalSlabSize < maxAddr) {
                void* mem = VirtualAlloc(
                    reinterpret_cast<LPVOID>(candidate),
                    kTotalSlabSize,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE);
                if (mem != nullptr) {
                    g_slabBase = static_cast<uint8_t*>(mem);
                    std::memset(g_slabBase, 0xCC, kCodeRegionSize);
                    std::memset(g_slabBase + kCodeRegionSize, 0, kDataRegionSize);
                    g_codeOffset = 0;
                    g_rtFuncTable = reinterpret_cast<RUNTIME_FUNCTION*>(g_slabBase + kCodeRegionSize);
                    g_dataOffset = sizeof(RUNTIME_FUNCTION) * kMaxRuntimeFns;
                    g_rtFuncCount = 0;
                    return true;
                }
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        searchAddr = (next + gran - 1) & ~(gran - 1);
    }
    return false;
}

uint8_t* AllocTrampolineCode(size_t size, size_t align) noexcept {
    if (!g_slabBase || align == 0) {
        return nullptr;
    }
    const size_t aligned = (g_codeOffset + align - 1) & ~(align - 1);
    if (aligned + size > kCodeRegionSize) {
        return nullptr;
    }
    uint8_t* ptr = g_slabBase + aligned;
    g_codeOffset = aligned + size;
    return ptr;
}

bool RegisterLeafThunkUnwind(
    uint8_t* codeBegin,
    uint8_t* codeEnd,
    uint8_t prologSize,
    uint8_t stackAllocSlots) noexcept
{
    if (!g_slabBase || g_rtFuncCount >= kMaxRuntimeFns || codeEnd <= codeBegin) {
        return false;
    }
    // 4-byte align UNWIND_INFO in data region
    const size_t alignedData = (g_dataOffset + 3u) & ~size_t(3u);
    const size_t unwindBytes = (stackAllocSlots > 0) ? 8u : 4u;
    if (alignedData + unwindBytes > kDataRegionSize) {
        return false;
    }

    uint8_t* uw = g_slabBase + kCodeRegionSize + alignedData;
    g_dataOffset = alignedData + unwindBytes;

    uw[0] = 0x01; // Version = 1, Flags = 0 (non-chained)
    uw[1] = prologSize;
    if (stackAllocSlots > 0) {
        // Single UWOP_ALLOC_SMALL (op = 2), OpInfo = stackAllocSlots - 1
        uw[2] = 1; // CountOfCodes = 1
        uw[3] = 0; // FrameRegister = 0
        uw[4] = prologSize; // CodeOffset
        uw[5] = static_cast<uint8_t>(((stackAllocSlots - 1) << 4) | 2u);
        uw[6] = 0;
        uw[7] = 0;
    } else {
        uw[2] = 0;
        uw[3] = 0;
    }

    RUNTIME_FUNCTION& rf = g_rtFuncTable[g_rtFuncCount++];
    rf.BeginAddress = static_cast<DWORD>(reinterpret_cast<uintptr_t>(codeBegin) - g_slabExeBase);
    rf.EndAddress   = static_cast<DWORD>(reinterpret_cast<uintptr_t>(codeEnd) - g_slabExeBase);
    rf.UnwindData   = static_cast<DWORD>(reinterpret_cast<uintptr_t>(uw) - g_slabExeBase);
    return true;
}

bool FinalizeTrampolineUnwindTable() noexcept {
    if (!g_slabBase) {
        return false;
    }
    if (g_rtFuncCount > 1) {
        std::sort(g_rtFuncTable, g_rtFuncTable + g_rtFuncCount,
            [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) {
                return a.BeginAddress < b.BeginAddress;
            });
        // Verify strictly non-overlapping
        for (uint32_t i = 1; i < g_rtFuncCount; ++i) {
            if (g_rtFuncTable[i].BeginAddress < g_rtFuncTable[i - 1].EndAddress) {
                return false;
            }
        }
    }

    // Set final W^X protections: RX for code region, R for unwind metadata region
    DWORD oldProt = 0;
    if (!VirtualProtect(g_slabBase, kCodeRegionSize, PAGE_EXECUTE_READ, &oldProt)) {
        return false;
    }
    if (!VirtualProtect(g_slabBase + kCodeRegionSize, kDataRegionSize, PAGE_READONLY, &oldProt)) {
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), g_slabBase, kCodeRegionSize);

    if (g_rtFuncCount > 0 && !g_tableRegistered) {
        if (!RtlAddFunctionTable(g_rtFuncTable, g_rtFuncCount, g_slabExeBase)) {
            return false;
        }
        g_tableRegistered = true;

        // Self-verify RtlLookupFunctionEntry resolves every registered thunk
        for (uint32_t i = 0; i < g_rtFuncCount; ++i) {
            DWORD64 imgBase = 0;
            const DWORD64 pc = g_slabExeBase + g_rtFuncTable[i].BeginAddress;
            RUNTIME_FUNCTION* found = RtlLookupFunctionEntry(pc, &imgBase, nullptr);
            if (!found || imgBase != g_slabExeBase || found->BeginAddress != g_rtFuncTable[i].BeginAddress) {
                return false;
            }
        }
    }
    return true;
}

bool WriteMemoryPatch(void* addr, const void* data, size_t len) noexcept {
    if (!addr || !data || len == 0) {
        return false;
    }
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    std::memcpy(addr, data, len);
    DWORD dummy = 0;
    VirtualProtect(addr, len, oldProt, &dummy);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

#ifndef HOTFIX_UNIT_TEST
// Installs a 5-byte E9 rel32 detour (padded with NOPs up to stolenLen >= 5).
// Allocates both the relay jump (`FF 25 00 00 00 00 <detourFn>`) and the original-prologue gateway
// (`stolenBytes` + `E9 rel32` to `target + stolenLen`) in the near trampoline slab.
// Note: Call BEFORE FinalizeTrampolineUnwindTable() writes RX on the slab, or temporarily re-protects slab!
// Even cleaner: we separate slab preparation from target patching, or allow InstallDetour to VirtualProtect slab if needed.
bool InstallDetour(uintptr_t targetRva, void* detourFn, void** outOriginal, size_t stolenLen) noexcept {
    if (stolenLen < 5 || stolenLen > 16 || !g_slabBase) {
        return false;
    }
    uint8_t* target = RvaPtr<uint8_t*>(targetRva);

    // 1. Allocate 14-byte relay thunk: jmp qword ptr [rip+0] -> detourFn
    uint8_t* relay = AllocTrampolineCode(16, 16);
    // 2. Allocate gateway for calling original: stolenLen + 5-byte E9 rel32 back to target + stolenLen
    uint8_t* gateway = AllocTrampolineCode(stolenLen + 8, 16);
    if (!relay || !gateway) {
        return false;
    }

    // Ensure slab is writable while populating relay + gateway
    DWORD oldSlabProt = 0;
    VirtualProtect(g_slabBase, kCodeRegionSize, PAGE_EXECUTE_READWRITE, &oldSlabProt);

    relay[0] = 0xFF;
    relay[1] = 0x25;
    relay[2] = 0x00;
    relay[3] = 0x00;
    relay[4] = 0x00;
    relay[5] = 0x00;
    const uintptr_t fnAddr = reinterpret_cast<uintptr_t>(detourFn);
    std::memcpy(relay + 6, &fnAddr, sizeof(fnAddr));

    std::memcpy(gateway, target, stolenLen);
    const intptr_t backDisp = (reinterpret_cast<intptr_t>(target + stolenLen)) -
                              (reinterpret_cast<intptr_t>(gateway + stolenLen + 5));
    if (backDisp < INT32_MIN || backDisp > INT32_MAX) {
        return false;
    }
    gateway[stolenLen] = 0xE9;
    const int32_t backRel32 = static_cast<int32_t>(backDisp);
    std::memcpy(gateway + stolenLen + 1, &backRel32, sizeof(backRel32));

    if (oldSlabProt != PAGE_EXECUTE_READWRITE && oldSlabProt != 0) {
        DWORD dummy = 0;
        VirtualProtect(g_slabBase, kCodeRegionSize, oldSlabProt, &dummy);
    }
    FlushInstructionCache(GetCurrentProcess(), relay, 16);
    FlushInstructionCache(GetCurrentProcess(), gateway, stolenLen + 8);

    if (outOriginal) {
        *outOriginal = gateway;
    }

    // Build patch bytes for target: E9 <rel32 to relay> + NOPs
    const intptr_t fwdDisp = reinterpret_cast<intptr_t>(relay) - reinterpret_cast<intptr_t>(target + 5);
    if (fwdDisp < INT32_MIN || fwdDisp > INT32_MAX) {
        return false;
    }
    uint8_t patch[16];
    std::memset(patch, 0x90, stolenLen);
    patch[0] = 0xE9;
    const int32_t fwdRel32 = static_cast<int32_t>(fwdDisp);
    std::memcpy(patch + 1, &fwdRel32, sizeof(fwdRel32));

    return WriteMemoryPatch(target, patch, stolenLen);
}
#endif

} // namespace hotfix
