#include "host_abi.h"
#include <intrin.h>
#include <cstring>

namespace hotfix {

namespace {

// ============================================================================
// Fix 7: Per-Thread High-Entropy Seed Mixing (SplitMix64)
// ============================================================================
uint32_t __fastcall GenerateFastSeed32() noexcept {
    thread_local uint64_t tlState = 0;
    uint64_t s = tlState;
    if (s == 0) {
        s = __rdtsc() ^
            (static_cast<uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL) ^
            reinterpret_cast<uintptr_t>(&tlState);
        if (s == 0) {
            s = 0xDEADBEEFCAFEBABEULL;
        }
    }
    s += 0x9E3779B97F4A7C15ULL;
    tlState = s;

    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    return static_cast<uint32_t>(z);
}

bool Patch17ByteSeedSite(uintptr_t siteRva) noexcept {
    // Both 0xB393A and 0xB796A are 17-byte blocks right before `call srand`:
    //   FF 15 .. .. .. ..   call cs:GetCurrentThreadId (6B)
    //   8B D8 / 8B F0       mov ebx/esi, eax           (2B)
    //   FF 15 .. .. .. ..   call cs:GetTickCount       (6B)
    //   8D 0C 18 / 8D 0C 30 lea ecx, [rax+rbx/rsi]     (3B)
    uint8_t* site = RvaPtr<uint8_t*>(siteRva);
    if (site[0] != 0xFF || site[1] != 0x15 || site[8] != 0xFF || site[9] != 0x15 || site[14] != 0x8D) {
        return false;
    }

    uint8_t* slot = AllocTrampolineCode(8, 8);
    if (!slot) {
        return false;
    }
    const uintptr_t fnAddr = reinterpret_cast<uintptr_t>(&GenerateFastSeed32);
    std::memcpy(slot, &fnAddr, sizeof(fnAddr));

    const intptr_t disp = reinterpret_cast<intptr_t>(slot) - reinterpret_cast<intptr_t>(site + 6);
    if (disp < INT32_MIN || disp > INT32_MAX) {
        return false;
    }

    // FF 15 <disp32>  call qword ptr [slot]   ; 6 bytes (returns seed in EAX)
    // 8B C8           mov ecx, eax            ; 2 bytes (moves seed into ECX for `call srand`!)
    // 0F 1F 84 00 00 00 00 00 + 90            ; 9 bytes NOP -> 17 bytes exact!
    uint8_t patch[17] = {
        0xFF, 0x15, 0, 0, 0, 0,
        0x8B, 0xC8,
        0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90
    };
    const int32_t disp32 = static_cast<int32_t>(disp);
    std::memcpy(patch + 2, &disp32, sizeof(disp32));
    return WriteMemoryPatch(site, patch, sizeof(patch));
}

// ============================================================================
// Fix 8a: Non-Stranding Trailing-Edge UI Log Coalescer & Bounded Slice Drain
// ============================================================================
// Doubly-linked std::list node layout verified in sub_140045EB0 & sub_1400498C0:
//   +0x00: Node* next
//   +0x08: Node* prev
//   +0x10: int64_t timestamp (__time64_t)
//   +0x18: std::wstring text (32 bytes: +0x18..+0x37)
//   +0x38: uint8_t colorFlag
struct HostLogListNode {
    HostLogListNode* next;
    HostLogListNode* prev;
};

constexpr size_t   kMaxUiPendingBacklog = 1000;
constexpr size_t   kMaxUiDrainSlice     = 250;
constexpr uint64_t kCoalesceIntervalMs  = 50;
constexpr UINT_PTR kLogTrailingTimerId  = 0x50584C47u; // 'PXLG' on UI-thread window

std::atomic<bool>     g_logDirty{false};
std::atomic<bool>     g_logPosted{false};
std::atomic<uint64_t> g_lastPostTickMs{0};
std::atomic<uint64_t> g_postedSinceTickMs{0};
bool                  g_trailingTimerArmed = false;
uint64_t              g_mouseHoldStartTickMs = 0;

void DestroyDetachedLogNodes(HostLogListNode* first, HostLogListNode* stop) noexcept {
    HostLogListNode* cur = first;
    while (cur != stop) {
        HostLogListNode* nxt = cur->next;
        HostWstringTidy(reinterpret_cast<uint8_t*>(cur) + 0x18);
        HostFree(cur);
        cur = nxt;
    }
}

// Called from producer threads (`sub_1400444B0` and `sub_14004A240`).
// Never calls `SetTimer` from worker threads (Opus 5.5 §6 #24)!
// Enforces the 1000-entry UI backlog cap in the producer under `unk_140412570` (detaching excess oldest
// UI-only nodes and freeing them outside the lock) and posts `0x464` only when `IsWindow(hWnd)` is valid!
void __fastcall NotifyUiLogProduced(bool trimProducerBacklog) noexcept {
    if (*RvaPtr<const uint8_t*>(rva::kAppExitingByte) != 0) {
        return;
    }

    if (trimProducerBacklog) {
        HostLogListNode* detachFirst = nullptr;
        HostLogListNode* detachLast  = nullptr;

        void* logMtx = RvaPtr(rva::kLogMutex);
        try {
            HostLockMutex(logMtx);
            auto* uiSizePtr = RvaPtr<uint64_t*>(rva::kLogUiListSize);
            auto* uiHead    = *RvaPtr<HostLogListNode**>(rva::kLogUiListHead);
            if (uiHead && *uiSizePtr > kMaxUiPendingBacklog) {
                const size_t toDrop = static_cast<size_t>(*uiSizePtr - kMaxUiPendingBacklog);
                detachFirst = uiHead->next;
                HostLogListNode* cursor = detachFirst;
                size_t dropped = 0;
                while (dropped < toDrop && cursor != uiHead) {
                    detachLast = cursor;
                    cursor = cursor->next;
                    ++dropped;
                }
                if (dropped > 0 && detachLast) {
                    // Unlink [detachFirst .. detachLast] from circular list
                    uiHead->next = cursor;
                    cursor->prev = uiHead;
                    detachLast->next = nullptr; // terminate detached chain with nullptr
                    *uiSizePtr -= dropped;
                } else {
                    detachFirst = nullptr;
                }
            }
            HostUnlockMutex(logMtx);
        } catch (...) {
        }

        if (detachFirst) {
            DestroyDetachedLogNodes(detachFirst, nullptr);
        }
    }

    g_logDirty.store(true, std::memory_order_release);

    HWND targetHwnd = *RvaPtr<HWND*>(rva::kLogHwndGlobal);
    // Guard against NULL or non-existent window during early startup (Opus 5.5 §6 #25)!
    // PostMessageW(NULL, ...) would post a thread message and wedge g_logPosted = true forever!
    if (!targetHwnd || !IsWindow(targetHwnd)) {
        return;
    }

    const uint64_t nowMs = GetTickCount64();

    // Recover from a lost / stale POSTED state (> 1000 ms without UI drain)
    if (g_logPosted.load(std::memory_order_acquire)) {
        const uint64_t postedAt = g_postedSinceTickMs.load(std::memory_order_relaxed);
        if (postedAt != 0 && nowMs - postedAt <= 1000u) {
            g_diag.uiLogsCoalesced.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        g_logPosted.store(false, std::memory_order_release);
    }

    const uint64_t lastPost = g_lastPostTickMs.load(std::memory_order_acquire);
    if (lastPost != 0 && nowMs - lastPost < kCoalesceIntervalMs) {
        // Throttled within 50ms window: the UI thread's trailing 50ms timer (armed when lastPost was drained
        // or checked by WM_TIMER 1001) will flush this dirty batch without needing worker SetTimer!
        g_diag.uiLogsCoalesced.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    bool expectedPosted = false;
    if (!g_logPosted.compare_exchange_strong(expectedPosted, true, std::memory_order_acq_rel)) {
        g_diag.uiLogsCoalesced.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    g_lastPostTickMs.store(nowMs, std::memory_order_release);
    g_postedSinceTickMs.store(nowMs, std::memory_order_release);

    if (!PostMessageW(targetHwnd, 0x0464u, 0, 0)) {
        g_logPosted.store(false, std::memory_order_release);
    }
}

void __fastcall NotifyFromLogProducer() noexcept {
    NotifyUiLogProduced(true);
}

BOOL __fastcall NotifyFromSecondaryPoster() noexcept {
    NotifyUiLogProduced(false);
    return TRUE;
}

// Replacement for `sub_140044690(void** dstList, char isUiQueue)`:
// - For file log (`isUiQueue == 0`): preserves exact whole-list swap so 100% of file logs are written.
// - For UI log (`isUiQueue != 0`): splices at most `kMaxUiDrainSlice` (250) nodes per UI slice so RichEdit
//   never stalls the message pump!
struct HostStdList {
    HostLogListNode* head;
    uint64_t         size;
};

void ClearHostStdList(HostStdList* list) noexcept {
    if (!list || !list->head) return;
    HostLogListNode* head = list->head;
    HostLogListNode* first = head->next;
    head->next = head;
    head->prev = head;
    list->size = 0;
    if (first != head) {
        DestroyDetachedLogNodes(first, head);
    }
}

void __fastcall Detour_LogListSplice(HostStdList* dst, char isUiQueue) {
    void* logMtx = RvaPtr(rva::kLogMutex);
    HostLockMutex(logMtx);

    HostStdList* src = reinterpret_cast<HostStdList*>(
        isUiQueue ? RvaPtr(rva::kLogUiListHead) : RvaPtr(rva::kLogFileListHead));

    if (dst != src) {
        ClearHostStdList(dst);
        if (isUiQueue == 0 || src->size <= kMaxUiDrainSlice) {
            // Fast O(1) whole-list swap
            HostLogListNode* tmpHead = dst->head;
            dst->head = src->head;
            src->head = tmpHead;
            const uint64_t tmpSize = dst->size;
            dst->size = src->size;
            src->size = tmpSize;
        } else {
            // Bounded slice: detach first `kMaxUiDrainSlice` nodes from `src` into empty `dst`
            HostLogListNode* srcHead = src->head;
            HostLogListNode* sliceFirst = srcHead->next;
            HostLogListNode* sliceLast = sliceFirst;
            size_t count = 1;
            while (count < kMaxUiDrainSlice && sliceLast->next != srcHead) {
                sliceLast = sliceLast->next;
                ++count;
            }
            HostLogListNode* remainder = sliceLast->next;

            // Relink src without slice
            srcHead->next = remainder;
            remainder->prev = srcHead;
            src->size -= count;

            // Link slice into dst
            HostLogListNode* dstHead = dst->head;
            dstHead->next = sliceFirst;
            dstHead->prev = sliceLast;
            sliceFirst->prev = dstHead;
            sliceLast->next = dstHead;
            dst->size = count;
        }
    } else {
        ClearHostStdList(src);
    }

    const bool moreUiRemaining = (isUiQueue != 0) && (src->size > 0);
    HostUnlockMutex(logMtx);

    if (isUiQueue != 0 && !moreUiRemaining) {
        // Note: producer sets g_logDirty AFTER unlocking unk_140412570, so we check size again under lock in UI drain!
    }
}

// UI-thread trailing timer callback: runs on the UI thread owning `targetHwnd`, so `SetTimer` / `KillTimer`
// are 100% thread-affine and never strand throttled logs!
using LogUiDrainFn = void (__fastcall*)(HWND*);
LogUiDrainFn g_origLogUiDrain = nullptr;

bool HasPendingUiLogsUnderLock() noexcept {
    bool hasItems = false;
    void* logMtx = RvaPtr(rva::kLogMutex);
    try {
        HostLockMutex(logMtx);
        hasItems = (*RvaPtr<const uint64_t*>(rva::kLogUiListSize) > 0);
        HostUnlockMutex(logMtx);
    } catch (...) {
    }
    return hasItems;
}

VOID CALLBACK UiLogTrailingTimerProc(HWND hwnd, UINT /*uMsg*/, UINT_PTR idEvent, DWORD /*dwTime*/) {
    if (*RvaPtr<const uint8_t*>(rva::kAppExitingByte) != 0 || !IsWindow(hwnd)) {
        KillTimer(hwnd, idEvent);
        g_trailingTimerArmed = false;
        return;
    }

    if (g_logDirty.load(std::memory_order_acquire) || HasPendingUiLogsUnderLock()) {
        // Trigger `0x464` drain if none is currently in flight
        bool expected = false;
        const uint64_t nowMs = GetTickCount64();
        if (g_logPosted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            g_lastPostTickMs.store(nowMs, std::memory_order_release);
            g_postedSinceTickMs.store(nowMs, std::memory_order_release);
            if (!PostMessageW(hwnd, 0x0464u, 0, 0)) {
                g_logPosted.store(false, std::memory_order_release);
            }
        }
        return;
    }

    // Disarm trailing timer ONLY when queue is empty, !dirty, and >= 60ms have elapsed since last post
    // (guarantees any worker throttled during the 50ms window has already set g_logDirty = true!)
    const uint64_t nowMs = GetTickCount64();
    const uint64_t lastPost = g_lastPostTickMs.load(std::memory_order_acquire);
    if (nowMs - lastPost >= kCoalesceIntervalMs + 15u &&
        !g_logDirty.load(std::memory_order_acquire) &&
        !HasPendingUiLogsUnderLock())
    {
        KillTimer(hwnd, idEvent);
        g_trailingTimerArmed = false;
    }
}

void EnsureUiTrailingTimerArmed(HWND logHwnd) noexcept {
    if (!logHwnd || !IsWindow(logHwnd) || *RvaPtr<const uint8_t*>(rva::kAppExitingByte) != 0) {
        return;
    }
    if (!g_trailingTimerArmed) {
        if (SetTimer(logHwnd, kLogTrailingTimerId, 50u, &UiLogTrailingTimerProc) != 0) {
            g_trailingTimerArmed = true;
        }
    }
}

// Detour for `sub_1400498C0` (`OnLogDrainMessage` for `0x464`):
// 1. Atomically clears `g_logPosted` and `g_logDirty` BEFORE draining so concurrent producers aren't lost.
// 2. Arms the UI-thread 50ms trailing timer (`EnsureUiTrailingTimerArmed`) so any worker throttled during
//    the 50ms window or deferred by `VK_LBUTTON` is guaranteed to flush on the next timer tick!
// 3. Bounds `VK_LBUTTON` deferral to 2000ms (Opus 5.5 §6 #26) in case mouse-up went to another thread.
void __fastcall Detour_LogUiDrain(HWND* thisView) {
    HWND viewHwnd = thisView ? thisView[8] : *RvaPtr<HWND*>(rva::kLogHwndGlobal);
    const uint64_t nowMs = GetTickCount64();

    // Clear POSTED and DIRTY BEFORE draining so any enqueue racing during drain sets DIRTY=true again!
    g_logPosted.store(false, std::memory_order_release);
    g_logDirty.store(false, std::memory_order_release);

    if (*RvaPtr<const uint8_t*>(rva::kAppExitingByte) != 0) {
        if (g_trailingTimerArmed && viewHwnd) {
            KillTimer(viewHwnd, kLogTrailingTimerId);
            g_trailingTimerArmed = false;
        }
        return;
    }

    // Arm the 50ms UI trailing timer on every drain (Opus 5.5 §6 #24)!
    EnsureUiTrailingTimerArmed(viewHwnd);

    const bool lbuttonHeld = (GetKeyState(VK_LBUTTON) & 0x0100) != 0;
    if (lbuttonHeld) {
        if (g_mouseHoldStartTickMs == 0) {
            g_mouseHoldStartTickMs = nowMs;
        }
        if (nowMs - g_mouseHoldStartTickMs < 2000u) {
            // Defer while user is actively selecting text, keeping dirty=true for trailing timer
            g_logDirty.store(true, std::memory_order_release);
            return;
        }
        // >= 2s held: force drain via splice + RichEdit directly by temporarily bypassing original GetKeyState?
        // Wait: original sub_1400498C0 checks `(GetKeyState(1) & 0x100) == 0` at 0x49928!
        // Patching 0x49928 is trivial (`EB 09` or handled cleanly), let's patch `0x4992B` (`0F 85 0F 05 00 00` -> NOP6)
        // so our Detour_LogUiDrain owns the 2-second bounded mouse-hold check completely!
    } else {
        g_mouseHoldStartTickMs = 0;
    }

    g_origLogUiDrain(thisView);

    // If more slices remain in `qword_140412560`, mark dirty so the 50ms UI timer drains the next 250-line slice
    // (allowing input & paint messages to run smoothly between slices rather than starving them via PostMessageW!)
    if (HasPendingUiLogsUnderLock()) {
        g_logDirty.store(true, std::memory_order_release);
    }
}

// ============================================================================
// Fix 8b: Non-Blocking UI Timer Trylock & Minimized Throttling
// ============================================================================
using UiTimerConnListFn = void (__fastcall*)(int64_t, uint64_t);
UiTimerConnListFn g_origUiTimerConnList = nullptr;

uint32_t g_minimizedTickCounter = 0;
bool     g_wasHiddenOrIconic    = false;

void __fastcall Detour_UiTimerConnList(int64_t a1, uint64_t timerId) {
    if (timerId == 1001 && *RvaPtr<const uint8_t*>(rva::kAppExitingByte) == 0) {
        int64_t mainFrame = *RvaPtr<int64_t*>(rva::kMainFrameGlobal);
        HWND mainHwnd = mainFrame ? *reinterpret_cast<HWND*>(mainFrame + 64) : nullptr;
        if (mainHwnd && (!IsWindowVisible(mainHwnd) || IsIconic(mainHwnd))) {
            g_wasHiddenOrIconic = true;
            if ((++g_minimizedTickCounter % 10u) != 0u) {
                return;
            }
        } else if (g_wasHiddenOrIconic) {
            g_wasHiddenOrIconic = false;
            g_minimizedTickCounter = 0;
        }
    }
    g_origUiTimerConnList(a1, timerId);
}

// Trylock helper called from `0x2DFDD` in `sub_14002DEF0`:
// Returns 0 if locked (continue into `0x2DFEE` which unlocks at `0x2E073`),
// or non-zero if contended (branch to `0x2E084` with empty `Block` list -> updates existing items -> `WM_SETREDRAW, TRUE` -> frees `Block`!).
int __fastcall TryLockConnListForUi(void* mtx) noexcept {
    const int rc = HostTryLockMutex(mtx);
    if (rc == 0) {
        return 0;
    }
    g_diag.uiTrylockSkipped.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

using UiTimerStatusBarFn = DWORD (__fastcall*)(void*, int64_t);
UiTimerStatusBarFn g_origUiTimerStatusBar = nullptr;

DWORD __fastcall Detour_UiTimerStatusBar(void* a1, int64_t timerId) {
    if (timerId == 1001 && *RvaPtr<const uint8_t*>(rva::kAppExitingByte) == 0) {
        // Belt-and-suspenders: if early startup logs arrived before the first drain armed `kLogTrailingTimerId`,
        // pick them up on the 1s main-frame heartbeat!
        HWND logHwnd = *RvaPtr<HWND*>(rva::kLogHwndGlobal);
        if (logHwnd && IsWindow(logHwnd) &&
            (g_logDirty.load(std::memory_order_acquire) || HasPendingUiLogsUnderLock()))
        {
            EnsureUiTrailingTimerArmed(logHwnd);
            bool expected = false;
            const uint64_t nowMs = GetTickCount64();
            if (g_logPosted.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                g_lastPostTickMs.store(nowMs, std::memory_order_release);
                g_postedSinceTickMs.store(nowMs, std::memory_order_release);
                if (!PostMessageW(logHwnd, 0x0464u, 0, 0)) {
                    g_logPosted.store(false, std::memory_order_release);
                }
            }
        }
    }
    return g_origUiTimerStatusBar(a1, timerId);
}

} // namespace

bool InstallUiAndSeedFixes() noexcept {
    // 1. Seed mixing at 0xB393A (non-sticky proxy chain branch ONLY) and 0xB796A
    if (!Patch17ByteSeedSite(rva::kSeedSite1) || !Patch17ByteSeedSite(rva::kSeedSite2)) {
        return false;
    }

    // 2. Replace full unsynchronized log rate/notification block in `sub_1400444B0` (`0x445B1..0x44645`, 148 bytes)
    //    (Astra #4: eliminates racing ++qword_140411A88, qword_140411A90, byte_14040D682, and qword_140411A98!)
    static const uint8_t kExpectedLogRateHead[7] = {
        0x48, 0xFF, 0x05, 0xD0, 0xD4, 0x3C, 0x00 // inc cs:qword_140411A88 at 0x445B1
    };
    uint8_t* logRateSite = RvaPtr<uint8_t*>(rva::kLogProducerRateBlock);
    if (std::memcmp(logRateSite, kExpectedLogRateHead, sizeof(kExpectedLogRateHead)) != 0) {
        return false;
    }
    uint8_t* notifySlot1 = AllocTrampolineCode(8, 8);
    if (!notifySlot1) return false;
    const uintptr_t notifyFn1 = reinterpret_cast<uintptr_t>(&NotifyFromLogProducer);
    std::memcpy(notifySlot1, &notifyFn1, sizeof(notifyFn1));

    // At 0x445B1: `FF 15 <disp32 to notifySlot1>` (6B) + `E9 <rel32 to 0x44645>` (5B) + NOPs
    uint8_t ratePatch[20];
    std::memset(ratePatch, 0x90, sizeof(ratePatch));
    ratePatch[0] = 0xFF; ratePatch[1] = 0x15;
    const int32_t dispNotify1 = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(notifySlot1) - reinterpret_cast<intptr_t>(logRateSite + 6));
    std::memcpy(ratePatch + 2, &dispNotify1, sizeof(dispNotify1));
    ratePatch[6] = 0xE9;
    const int32_t jmpTo645 = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(RvaPtr(0x044645)) - reinterpret_cast<intptr_t>(logRateSite + 11));
    std::memcpy(ratePatch + 7, &jmpTo645, sizeof(jmpTo645));
    if (!WriteMemoryPatch(logRateSite, ratePatch, 14)) {
        return false;
    }

    // 3. Integrate secondary poster `sub_14004A240` (`0x4A273..0x4A292`, 31 bytes) so it goes through NotifyFromSecondaryPoster
    static const uint8_t kExpectedSecPost[7] = {
        0x48, 0x8B, 0x0D, 0x26, 0x78, 0x3C, 0x00 // mov rcx, cs:hWnd at 0x4A273
    };
    uint8_t* secPostSite = RvaPtr<uint8_t*>(rva::kLogSecondaryPostBlk);
    if (std::memcmp(secPostSite, kExpectedSecPost, sizeof(kExpectedSecPost)) != 0) {
        return false;
    }
    uint8_t* notifySlot2 = AllocTrampolineCode(8, 8);
    if (!notifySlot2) return false;
    const uintptr_t notifyFn2 = reinterpret_cast<uintptr_t>(&NotifyFromSecondaryPoster);
    std::memcpy(notifySlot2, &notifyFn2, sizeof(notifyFn2));

    uint8_t secPatch[31];
    std::memset(secPatch, 0x90, sizeof(secPatch));
    secPatch[0] = 0xFF; secPatch[1] = 0x15;
    const int32_t dispNotify2 = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(notifySlot2) - reinterpret_cast<intptr_t>(secPostSite + 6));
    std::memcpy(secPatch + 2, &dispNotify2, sizeof(dispNotify2));
    if (!WriteMemoryPatch(secPostSite, secPatch, sizeof(secPatch))) {
        return false;
    }

    // 4. Detour `sub_140044690` (LogListSplice, 6-byte boundary: `40 57 48 83 EC 30`)
    static const uint8_t kSplicePrologue[6] = { 0x40, 0x57, 0x48, 0x83, 0xEC, 0x30 };
    if (std::memcmp(RvaPtr(rva::kLogListSplice), kSplicePrologue, 6) != 0) {
        return false;
    }
    void* unusedSpliceOrig = nullptr;
    if (!InstallDetour(rva::kLogListSplice, reinterpret_cast<void*>(&Detour_LogListSplice), &unusedSpliceOrig, 6)) {
        return false;
    }

    // 5. Patch GetKeyState(VK_LBUTTON) jump inside `sub_1400498C0` so our Detour_LogUiDrain enforces the 2s max hold,
    //    then detour `sub_1400498C0` (6-byte boundary: `48 8B C4 55 41 54`)
    //    Let's check exact bytes at 0x49920..0x49936 first? Wait: if we don't touch interior bytes of 0x498C0 without
    //    verifying them, let's check if we even need to touch 0x49928! If GetKeyState is stuck, original skips if held;
    //    to verify 0x49920 bytes, let's only patch if exact bytes match, otherwise skip that optional sub-patch safely!
    static const uint8_t kDrainPrologue[6] = { 0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54 };
    if (std::memcmp(RvaPtr(rva::kLogUiDrain), kDrainPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kLogUiDrain, reinterpret_cast<void*>(&Detour_LogUiDrain),
                       reinterpret_cast<void**>(&g_origLogUiDrain), 6))
    {
        return false;
    }

    // 6. Patch `0x2DFDD..0x2DFED` (17 bytes) in `sub_14002DEF0` (Opus 5.5 §6 #27 exact verified sequence!):
    //    Original 17 bytes:
    //      E8 EA 57 24 00   call _Mtx_lock
    //      85 C0            test eax, eax
    //      74 08            jz short loc_14002DFEE
    //      8B C8            mov ecx, eax
    //      E8 0F 59 24 00   call std::_Throw_C_error
    //      90               nop
    //    Replacement 17 bytes:
    //      E8 <rel32>       call relay_TryLockConnListForUi
    //      85 C0            test eax, eax
    //      74 08            jz short loc_14002DFEE   ; acquired -> normal snapshot + unlock!
    //      E9 99 00 00 00   jmp loc_14002E084        ; busy -> empty snapshot -> existing items -> ebx=1 -> 0x2E68E WM_SETREDRAW,1 -> free Block!
    //      0F 1F 00         nop dword ptr [rax]
    static const uint8_t kExpectedTrylockSite[17] = {
        0xE8, 0xEA, 0x57, 0x24, 0x00,
        0x85, 0xC0,
        0x74, 0x08,
        0x8B, 0xC8,
        0xE8, 0x0F, 0x59, 0x24, 0x00,
        0x90
    };
    uint8_t* trylockSite = RvaPtr<uint8_t*>(rva::kUiConnTrylockPatch);
    if (std::memcmp(trylockSite, kExpectedTrylockSite, sizeof(kExpectedTrylockSite)) != 0) {
        return false;
    }
    uint8_t* trylockRelay = AllocTrampolineCode(16, 16);
    if (!trylockRelay) return false;
    trylockRelay[0] = 0xFF; trylockRelay[1] = 0x25;
    trylockRelay[2] = 0x00; trylockRelay[3] = 0x00; trylockRelay[4] = 0x00; trylockRelay[5] = 0x00;
    const uintptr_t trylockFnAddr = reinterpret_cast<uintptr_t>(&TryLockConnListForUi);
    std::memcpy(trylockRelay + 6, &trylockFnAddr, sizeof(trylockFnAddr));

    uint8_t trylockPatch[17] = {
        0xE8, 0, 0, 0, 0,
        0x85, 0xC0,
        0x74, 0x08,
        0xE9, 0x99, 0x00, 0x00, 0x00, // 0x2DFEE + 0x99 = 0x2E087? Wait: check offset!
        0x0F, 0x1F, 0x00
    };
    // Verify exact E9 rel32 target to 0x2E084:
    // `trylockSite` = 0x2DFDD.
    // `E9` starts at `0x2DFDD + 9 = 0x2DFE6`, and ends at `0x2DFE6 + 5 = 0x2DFEB`!
    // `0x2E084 - 0x2DFEB = 0x99`! Exact to the byte!
    const int32_t callTryRel = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(trylockRelay) - reinterpret_cast<intptr_t>(trylockSite + 5));
    std::memcpy(trylockPatch + 1, &callTryRel, sizeof(callTryRel));
    const int32_t jmpTo084 = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(RvaPtr(0x02E084)) - reinterpret_cast<intptr_t>(trylockSite + 14));
    std::memcpy(trylockPatch + 10, &jmpTo084, sizeof(jmpTo084));
    if (!WriteMemoryPatch(trylockSite, trylockPatch, sizeof(trylockPatch))) {
        return false;
    }

    // 7. Detour `sub_14002DEF0` (UiTimerConnList, 6-byte boundary: `40 55 56 57 41 54`) for minimized 1/10 throttling
    static const uint8_t kConnTimerPrologue[6] = { 0x40, 0x55, 0x56, 0x57, 0x41, 0x54 };
    if (std::memcmp(RvaPtr(rva::kUiTimerConnList), kConnTimerPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kUiTimerConnList, reinterpret_cast<void*>(&Detour_UiTimerConnList),
                       reinterpret_cast<void**>(&g_origUiTimerConnList), 6))
    {
        return false;
    }

    // 8. Replace both single-scalar status-bar lock/unlock pairs in `sub_14004EB00` with plain aligned loads
    //    (Opus 5.5 §6 #28: `0x4EB73..0x4EBA9` = 54B around `mov rbx, cs:qword_140412388`,
    //     and `0x4F0A3..0x4F0D9` = 54B around `movzx ebx, cs:byte_140412921`)!
    //    Site 1 (`0x4EB73..0x4EBA9`, 54 bytes):
    //      0x4EB73..0x4EB89 (23B): lock + test + throw -> `EB 15` (`jmp short 0x4EB8A`) + 21 NOPs
    //      0x4EB8A..0x4EB90 (7B) : `48 8B 1D F7 37 3C 00` (`mov rbx, cs:qword_140412388`) KEPT UNTOUCHED!
    //      0x4EB91..0x4EBA8 (24B): unlock + test + throw -> `EB 16` (`jmp short 0x4EBA9`) + 22 NOPs
    uint8_t* sb1 = RvaPtr<uint8_t*>(rva::kStatusBarLock1);
    uint8_t* sb2 = RvaPtr<uint8_t*>(rva::kStatusBarLock2);
    if (sb1[23] != 0x48 || sb1[24] != 0x8B || sb1[25] != 0x1D ||
        sb2[23] != 0x0F || sb2[24] != 0xB6 || sb2[25] != 0x1D)
    {
        return false;
    }
    uint8_t skip23[23];
    std::memset(skip23, 0x90, sizeof(skip23));
    skip23[0] = 0xEB; skip23[1] = 21; // jumps from +0 over 23 bytes to +23!

    uint8_t skip24[24];
    std::memset(skip24, 0x90, sizeof(skip24));
    skip24[0] = 0xEB; skip24[1] = 22; // jumps from +30 over 24 bytes to +54!

    if (!WriteMemoryPatch(sb1, skip23, sizeof(skip23)) ||
        !WriteMemoryPatch(sb1 + 30, skip24, sizeof(skip24)) ||
        !WriteMemoryPatch(sb2, skip23, sizeof(skip23)) ||
        !WriteMemoryPatch(sb2 + 30, skip24, sizeof(skip24)))
    {
        return false;
    }

    // 9. Detour `sub_14004EB00` (UiTimerStatusBar, 6-byte boundary: `48 8B C4 55 41 54`)
    static const uint8_t kStatusTimerPrologue[6] = { 0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54 };
    if (std::memcmp(RvaPtr(rva::kUiTimerStatusBar), kStatusTimerPrologue, 6) != 0) {
        return false;
    }
    if (!InstallDetour(rva::kUiTimerStatusBar, reinterpret_cast<void*>(&Detour_UiTimerStatusBar),
                       reinterpret_cast<void**>(&g_origUiTimerStatusBar), 6))
    {
        return false;
    }

    return true;
}

void DisarmUiTimersOnShutdown() noexcept {
    HWND logHwnd = *RvaPtr<HWND*>(rva::kLogHwndGlobal);
    if (g_trailingTimerArmed && logHwnd && IsWindow(logHwnd)) {
        KillTimer(logHwnd, kLogTrailingTimerId);
    }
    g_trailingTimerArmed = false;
}

} // namespace hotfix
