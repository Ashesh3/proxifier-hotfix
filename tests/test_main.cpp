#include "dns_synthesizer.h"
#include "host_abi.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cassert>

using namespace hotfix;

namespace {

int g_testsRun = 0;
int g_testsFailed = 0;

#define CHECK(cond, msg) do { \
    ++g_testsRun; \
    if (!(cond)) { \
        std::fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
        ++g_testsFailed; \
    } \
} while (0)

uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t ReadU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

std::vector<uint8_t> BuildSimpleDnsQuery(
    uint16_t id,
    const char* host,
    uint16_t qtype,
    uint16_t qclass = 1,
    bool withEdns = false,
    uint8_t ednsVer = 0,
    bool doBit = false,
    const std::vector<uint8_t>& optRdata = {})
{
    std::vector<uint8_t> pkt(12, 0);
    pkt[0] = static_cast<uint8_t>(id >> 8);
    pkt[1] = static_cast<uint8_t>(id & 0xFF);
    pkt[2] = 0x01; // RD=1
    pkt[3] = 0x10; // CD=1 (test CD preservation)
    pkt[5] = 1;    // QDCOUNT=1
    pkt[11] = withEdns ? 1 : 0; // ARCOUNT

    const char* p = host;
    while (*p) {
        const char* dot = std::strchr(p, '.');
        const size_t len = dot ? static_cast<size_t>(dot - p) : std::strlen(p);
        pkt.push_back(static_cast<uint8_t>(len));
        pkt.insert(pkt.end(), p, p + len);
        if (!dot) break;
        p = dot + 1;
    }
    pkt.push_back(0); // root

    pkt.push_back(static_cast<uint8_t>(qtype >> 8));
    pkt.push_back(static_cast<uint8_t>(qtype & 0xFF));
    pkt.push_back(static_cast<uint8_t>(qclass >> 8));
    pkt.push_back(static_cast<uint8_t>(qclass & 0xFF));

    if (withEdns) {
        pkt.push_back(0x00); // root owner
        pkt.push_back(0x00); pkt.push_back(41); // OPT
        pkt.push_back(0x10); pkt.push_back(0x00); // UDP payload 4096
        pkt.push_back(0x00); // ext rcode
        pkt.push_back(ednsVer);
        pkt.push_back(doBit ? 0x80 : 0x00);
        pkt.push_back(0x00);
        pkt.push_back(static_cast<uint8_t>(optRdata.size() >> 8));
        pkt.push_back(static_cast<uint8_t>(optRdata.size() & 0xFF));
        pkt.insert(pkt.end(), optRdata.begin(), optRdata.end());
    }
    return pkt;
}

void TestDnsSynthesizerRfcCompliance() {
    sockaddr_in fake4{};
    fake4.sin_family = AF_INET;
    fake4.sin_addr.S_un.S_un_b = {127, 8, 0, 42};

    sockaddr_in6 fake6{};
    fake6.sin6_family = AF_INET6;
    fake6.sin6_addr.u.Byte[0] = 0xFD;
    fake6.sin6_addr.u.Byte[15] = 0x2A;

    // 1. Standard IPv4 A query with 0x20 mixed-case QNAME + EDNS0 + DO=1 + valid OPT cookie option
    std::vector<uint8_t> validOpt = { 0x00, 0x0A, 0x00, 0x08, 1,2,3,4,5,6,7,8 };
    auto q1 = BuildSimpleDnsQuery(0xBEEF, "ExAmPlE.CoM", 1, 1, true, 0, true, validOpt);
    uint8_t buf[512]{};
    std::memcpy(buf, q1.data(), q1.size());
    size_t ioLen = q1.size();

    char rc = SynthesizeDnsFakeIpResponse(buf, &ioLen, sizeof(buf), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 1, "IPv4 + EDNS0 + DO=1 synthesis succeeds");
    CHECK(ReadU16(buf) == 0xBEEF, "ID preserved");
    CHECK((buf[2] & 0x80) != 0 && (buf[2] & 0x01) != 0, "QR=1 and RD=1");
    CHECK((buf[3] & 0x80) != 0 && (buf[3] & 0x10) != 0 && (buf[3] & 0x20) == 0 && (buf[3] & 0x0F) == 0,
          "RA=1, CD=1 preserved, AD=0 cleared, RCODE=0");
    CHECK(ReadU16(buf + 4) == 1 && ReadU16(buf + 6) == 1 && ReadU16(buf + 8) == 0 && ReadU16(buf + 10) == 1,
          "QD=1, AN=1, NS=0, AR=1");
    // Verify 0x20 case preserved at offset 12 ("\x07ExAmPlE\x03CoM\x00" = 13 bytes)
    CHECK(std::memcmp(buf + 12, "\x07" "ExAmPlE" "\x03" "CoM", 13) == 0, "0x20 QNAME case preserved");
    // Answer RR at offset 12 + 13 + 4 = 29: 0xC0 0x0C, TYPE=1, CLASS=1, TTL=30, RDLEN=4, 127.8.0.42
    CHECK(buf[29] == 0xC0 && buf[30] == 0x0C, "Answer RR uses 0xC0 0x0C compression pointer");
    CHECK(ReadU32(buf + 35) == 30u, "Answer wire TTL is 30s (not 65792s)");
    CHECK(buf[41] == 127 && buf[42] == 8 && buf[43] == 0 && buf[44] == 42, "Answer RDATA matches Fake-IP");
    // OPT RR strictly AFTER Answer RR at offset 45 (11 bytes -> total 56 bytes)
    CHECK(ioLen == 56, "Exact wire length for A + OPT");
    CHECK(buf[45] == 0x00 && ReadU16(buf + 46) == 41, "OPT RR follows Answer RR in Additional");
    CHECK(ReadU16(buf + 48) == 1232, "OPT advertises 1232 UDP payload size");
    CHECK(ReadU32(buf + 50) == 0x00008000u, "OPT preserves DO bit and VERSION=0");

    // 2. EDNS VERSION = 1 -> RFC 6891 BADVERS (header RCODE = 0, OPT ext-RCODE = 1 -> extended RCODE 16, ANCOUNT = 0)
    auto qBadVer = BuildSimpleDnsQuery(0x1234, "corp.internal", 1, 1, true, 1, true);
    std::memcpy(buf, qBadVer.data(), qBadVer.size());
    ioLen = qBadVer.size();
    rc = SynthesizeDnsFakeIpResponse(buf, &ioLen, sizeof(buf), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 1, "BADVERS returns 1 with valid DNS error packet");
    CHECK((buf[3] & 0x0F) == 0, "BADVERS header RCODE nibble is 0 (CD bit NOT corrupted!)");
    CHECK(ReadU16(buf + 6) == 0 && ReadU16(buf + 10) == 1, "BADVERS has ANCOUNT=0 and ARCOUNT=1");
    const size_t optOff = ioLen - 11;
    CHECK(ReadU16(buf + optOff + 1) == 41, "BADVERS includes OPT RR");
    CHECK(ReadU32(buf + optOff + 5) == 0x01008000u, "BADVERS OPT TTL encodes ext-RCODE=1, VERSION=0, DO=1");

    // 3. Malformed OPT RDATA tuple (option length exceeds RDLEN) -> FORMERR (RCODE = 1)
    std::vector<uint8_t> badOpt = { 0x00, 0x0A, 0x00, 0x20, 1, 2 }; // claims 32 bytes inside 6-byte RDATA
    auto qBadOpt = BuildSimpleDnsQuery(0x2222, "test.local", 1, 1, true, 0, false, badOpt);
    std::memcpy(buf, qBadOpt.data(), qBadOpt.size());
    ioLen = qBadOpt.size();
    rc = SynthesizeDnsFakeIpResponse(buf, &ioLen, sizeof(buf), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 1 && (buf[3] & 0x0F) == 1, "Malformed OPT RDATA tuple emits FORMERR");

    // 4. Compression pointer in Question #1 -> FORMERR (RCODE = 1)
    uint8_t qPtr[20] = {
        0x33, 0x44, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, // self-loop pointer at offset 12!
        0x00, 0x01, 0x00, 0x01
    };
    ioLen = sizeof(qPtr);
    std::memcpy(buf, qPtr, ioLen);
    rc = SynthesizeDnsFakeIpResponse(buf, &ioLen, sizeof(buf), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 1 && (buf[3] & 0x0F) == 1, "Self-pointer in Question #1 rejected with FORMERR");

    // 5. Type/AF mismatch (AAAA query with AF_INET fake_addr) -> NOERROR NODATA (RCODE=0, ANCOUNT=0)
    auto qMismatch = BuildSimpleDnsQuery(0x5555, "ipv4only.corp", 28, 1, true, 0, false);
    std::memcpy(buf, qMismatch.data(), qMismatch.size());
    ioLen = qMismatch.size();
    rc = SynthesizeDnsFakeIpResponse(buf, &ioLen, sizeof(buf), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 1 && (buf[3] & 0x0F) == 0 && ReadU16(buf + 6) == 0 && ReadU16(buf + 10) == 1,
          "AAAA query with AF_INET fake_addr emits clean NOERROR NODATA with OPT");

    // 6. Truncated < 12-byte packet -> returns 0 without mutating buffer
    uint8_t tiny[8] = {1,2,3,4,5,6,7,8};
    size_t tinyLen = 8;
    rc = SynthesizeDnsFakeIpResponse(tiny, &tinyLen, sizeof(tiny), reinterpret_cast<const sockaddr*>(&fake4));
    CHECK(rc == 0 && tinyLen == 8 && tiny[0] == 1, "<12 byte packet returns 0 untouched");
}

void TestRealIpTtlClamping() {
    CHECK(ComputeRealIpReverseTtlSec(0) == 15u, "TTL=0 -> 15s immediate connect grace");
    CHECK(ComputeRealIpReverseTtlSec(0x80000000u) == 15u, "RFC 2181 MSB-set negative TTL -> 15s");
    CHECK(ComputeRealIpReverseTtlSec(0xFFFFFFFFu) == 15u, "UINT32_MAX MSB-set TTL -> 15s (no signed overflow!)");
    CHECK(ComputeRealIpReverseTtlSec(0x7FFFFFFFu) == 86415u, "INT_MAX TTL -> 86415s (no signed overflow!)");
    CHECK(ComputeRealIpReverseTtlSec(10) == 60u, "10s TTL -> 60s floor");
    CHECK(ComputeRealIpReverseTtlSec(3600) == 3615u, "3600s TTL preserved above 1800s (matches OS Dnscache!)");
    CHECK(ComputeRealIpReverseTtlSec(86400) == 86415u, "86400s MaxCacheTtl + 15s grace");
}

// Maps `Proxifier.exe` sections into virtual memory (when installed or provided via PROXIFIER_EXE_PATH)
// and runs every patch installer, unwind verifier, CreateSockObj provider cache, and carrier export test.
void TestFullBinaryInstallAndLiveHooks() {
    // 1. Load sibling `msimg32.dll` next to `hotfix_tests.exe` and verify all 5 forwarded Win32 exports!
    wchar_t selfPath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    wchar_t* lastSlash = std::wcsrchr(selfPath, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    wchar_t dllPath[MAX_PATH]{};
    wcscpy_s(dllPath, selfPath);
    wcscat_s(dllPath, L"msimg32.dll");

    HMODULE hBuiltDll = LoadLibraryExW(dllPath, nullptr, 0);
    CHECK(hBuiltDll != nullptr, "LoadLibrary built msimg32.dll");
    if (hBuiltDll) {
        auto pAlpha = GetProcAddress(hBuiltDll, "AlphaBlend");
        auto pTrans = GetProcAddress(hBuiltDll, "TransparentBlt");
        auto pGrad  = GetProcAddress(hBuiltDll, "GradientFill");
        auto pDiag  = reinterpret_cast<const HotfixDiagnostics* (__cdecl*)()>(
            GetProcAddress(hBuiltDll, "ProxifierHotfixGetDiagnostics"));
        CHECK(pAlpha && pTrans && pGrad && pDiag, "All msimg32 exports + diagnostics symbol present");

        using AlphaBlendFn = BOOL (WINAPI*)(HDC, int, int, int, int, HDC, int, int, int, int, BLENDFUNCTION);
        BLENDFUNCTION bf{};
        BOOL abRes = reinterpret_cast<AlphaBlendFn>(pAlpha)(nullptr, 0, 0, 0, 0, nullptr, 0, 0, 0, 0, bf);
        CHECK(abRes == FALSE, "Forwarded AlphaBlend thunk resolves real System32\\msimg32.dll and executes cleanly");
        CHECK(pDiag() != nullptr, "ProxifierHotfixGetDiagnostics returns valid struct");
        FreeLibrary(hBuiltDll);
    }

    // 2. Locate Proxifier.exe via PROXIFIER_EXE_PATH env var or standard Program Files (x86) paths
    wchar_t envExePath[MAX_PATH]{};
    const DWORD envLen = GetEnvironmentVariableW(L"PROXIFIER_EXE_PATH", envExePath, MAX_PATH);
    const wchar_t* candidates[] = {
        (envLen > 0 && envLen < MAX_PATH) ? envExePath : nullptr,
        L"C:\\Program Files (x86)\\Proxifier\\Proxifier.exe",
    };

    HANDLE hFile = INVALID_HANDLE_VALUE;
    for (const wchar_t* cand : candidates) {
        if (!cand) continue;
        hFile = CreateFileW(cand, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) break;
    }
    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("[SKIP] Proxifier.exe v4.14.0.1 not found locally (set PROXIFIER_EXE_PATH to run binary-image harness)\n");
        return;
    }

    LARGE_INTEGER fileSize{};
    GetFileSizeEx(hFile, &fileSize);
    std::vector<uint8_t> rawPe(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    BOOL rdOk = ReadFile(hFile, rawPe.data(), static_cast<DWORD>(rawPe.size()), &bytesRead, nullptr);
    CloseHandle(hFile);
    CHECK(rdOk && bytesRead == rawPe.size(), "Read Proxifier.exe bytes");

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(rawPe.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(rawPe.data() + dos->e_lfanew);
    CHECK(nt->OptionalHeader.SizeOfImage == kExpectedSizeOfImage, "Proxifier.exe SizeOfImage == 0x674000");

    uint8_t* mapped = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, kExpectedSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    CHECK(mapped != nullptr, "VirtualAlloc mapped Proxifier.exe image");
    if (!mapped) return;

    // Copy PE headers + all sections to exact RVAs
    std::memcpy(mapped, rawPe.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const DWORD copyLen = (sec[i].SizeOfRawData < sec[i].Misc.VirtualSize)
            ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (copyLen > 0 && sec[i].PointerToRawData + copyLen <= rawPe.size()) {
            std::memcpy(mapped + sec[i].VirtualAddress, rawPe.data() + sec[i].PointerToRawData, copyLen);
        }
    }

    auto writeAbsJmp = [](uint8_t* dst, void* fn) {
        dst[0] = 0xFF; dst[1] = 0x25;
        dst[2] = 0; dst[3] = 0; dst[4] = 0; dst[5] = 0;
        const uintptr_t p = reinterpret_cast<uintptr_t>(fn);
        std::memcpy(dst + 6, &p, sizeof(p));
    };

    g_exeBase = reinterpret_cast<uintptr_t>(mapped);

    // Verify CProxifierApp vtable slots BEFORE patching
    const uintptr_t origVtblInit = *reinterpret_cast<const uintptr_t*>(mapped + rva::kVtableInitInstance);
    const uintptr_t origVtblExit = *reinterpret_cast<const uintptr_t*>(mapped + rva::kVtableExitInstance);
    CHECK(origVtblInit == 0x140000000ULL + rva::kInitInstance, "Vtable slot 0x370400 == InitInstance (0x14007C550)");
    CHECK(origVtblExit == 0x140000000ULL + rva::kExitInstance, "Vtable slot 0x370430 == ExitInstance (0x14007DF60)");

    // Run EVERY hotfix installer against the real Proxifier.exe bytes!
    CHECK(InitTrampolineSlab(g_exeBase, kExpectedSizeOfImage), "InitTrampolineSlab above mapped Proxifier.exe");
    CHECK(InstallUdpSocketCloseFix(), "InstallUdpSocketCloseFix on real 0x3C002 bytes");
    CHECK(InstallWinsockFixes(), "InstallWinsockFixes on real 0x29F45, 0xABDC0, 0x2B490, 0x29D10 bytes");
    CHECK(InstallCacheAndTimestampFixes(), "InstallCacheAndTimestampFixes on all 5 GetTickCount + 3 cache sites");
    CHECK(InstallDnsSynthesizerFix(), "InstallDnsSynthesizerFix on real 0x5D7C0 + 0x37318 bytes");
    CHECK(InstallWfpPoolAndEventCacheFixes(), "InstallWfpPoolAndEventCacheFixes on 0x3D56, 0x3F26, 0x3F50, and 4 pump cases");
    CHECK(InstallUiAndSeedFixes(), "InstallUiAndSeedFixes on seed sites, log coalescer, UI trylock, and status bar");
    CHECK(FinalizeTrampolineUnwindTable(), "FinalizeTrampolineUnwindTable + RtlAddFunctionTable");

    // Verify exact patched machine instructions at critical sites:
    CHECK(mapped[rva::kUdpResolverPatchSite] == 0xE8 &&
          mapped[rva::kUdpResolverPatchSite + 5] == 0x0F &&
          mapped[rva::kUdpResolverPatchSite + 6] == 0x1F,
          "0x3C002 patched to call thunk + 5-byte NOP");

    // Verify RtlVirtualUnwind on the actual installed 0x3C002 UDP socket-close thunk!
    int32_t udpCallRel = 0;
    std::memcpy(&udpCallRel, mapped + rva::kUdpResolverPatchSite + 1, 4);
    uint8_t* udpThunk = mapped + rva::kUdpResolverPatchSite + 5 + udpCallRel;
    DWORD64 uwBase = 0;
    const DWORD64 udpThunkMidPc = reinterpret_cast<DWORD64>(udpThunk + 13);
    RUNTIME_FUNCTION* udpRf = RtlLookupFunctionEntry(udpThunkMidPc, &uwBase, nullptr);
    CHECK(udpRf != nullptr && uwBase == g_exeBase, "RtlLookupFunctionEntry resolves installed 0x3C002 thunk");
    if (udpRf) {
        alignas(16) uint64_t fakeStack[16]{};
        const uint64_t expectedRet = g_exeBase + 0x03C007ULL;
        fakeStack[5] = expectedRet;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        ctx.Rip = udpThunkMidPc;
        ctx.Rsp = reinterpret_cast<DWORD64>(&fakeStack[0]);
        PVOID hData = nullptr;
        DWORD64 est = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, uwBase, udpThunkMidPc, udpRf, &ctx, &hData, &est, nullptr);
        CHECK(ctx.Rip == expectedRet && ctx.Rsp == reinterpret_cast<DWORD64>(&fakeStack[6]),
              "RtlVirtualUnwind on installed 0x3C002 thunk restores exact parent RIP (0x3C007) and RSP");
    }

    const uint8_t expectedBackoff[8] = { 0x6B, 0xCB, 0x05, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
    CHECK(std::memcmp(mapped + rva::kGetsocknameBackoff, expectedBackoff, 8) == 0,
          "0x29F45 patched to exact 6B CB 05 (`imul ecx, ebx, 5`)");

    CHECK(mapped[rva::kUiConnTrylockPatch] == 0xE8 &&
          mapped[rva::kUiConnTrylockPatch + 9] == 0xE9 &&
          mapped[rva::kUiConnTrylockPatch + 10] == 0x99 &&
          mapped[rva::kUiConnTrylockPatch + 11] == 0x00,
          "0x2DFDD UI trylock branches to exact 0x2E084 (`E9 99 00 00 00`) on contention");

    // Execute patched `CreateSockObj` (`mapped + 0xABDC0`) live against real Winsock2!
    writeAbsJmp(mapped + rva::kHostOperatorNew, reinterpret_cast<void*>(&std::malloc));
    writeAbsJmp(mapped + rva::kHostFree, reinterpret_cast<void*>(&std::free));
    FlushInstructionCache(GetCurrentProcess(), mapped, kExpectedSizeOfImage);

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    using CreateSockFn = uint16_t* (__fastcall*)(int, int, int);
    auto createSock = reinterpret_cast<CreateSockFn>(mapped + rva::kCreateSockObj);

    uint16_t* w1 = createSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(w1 != nullptr && *reinterpret_cast<SOCKET*>(w1) != INVALID_SOCKET, "Patched CreateSockObj creates TCP socket #1");
    uint16_t* w2 = createSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(w2 != nullptr && *reinterpret_cast<SOCKET*>(w2) != INVALID_SOCKET, "Patched CreateSockObj creates TCP socket #2 from cache");
    CHECK(g_diag.providerCacheMisses.load() == 1 && g_diag.providerCacheHits.load() == 1,
          "WSAPROTOCOL_INFOW base-provider cache records 1 miss then 1 hit");

    uint16_t* wUdp = createSock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(wUdp != nullptr && *reinterpret_cast<SOCKET*>(wUdp) != INVALID_SOCKET, "Patched CreateSockObj creates UDP socket");
    if (w1)   { closesocket(*reinterpret_cast<SOCKET*>(w1));   std::free(w1); }
    if (w2)   { closesocket(*reinterpret_cast<SOCKET*>(w2));   std::free(w2); }
    if (wUdp) { closesocket(*reinterpret_cast<SOCKET*>(wUdp)); std::free(wUdp); }

    // Execute patched TLS Overlapped Event Acquire/Release (`0x3D56`, `0x3F26`, `0x3F50`)!
    int32_t acqDisp = 0, relDisp = 0;
    std::memcpy(&acqDisp, mapped + rva::kIoctlCreateEventCall + 2, 4);
    std::memcpy(&relDisp, mapped + rva::kIoctlCloseHandleCall + 2, 4);
    auto acqFn = *reinterpret_cast<HANDLE (__fastcall**)(void)>(mapped + rva::kIoctlCreateEventCall + 6 + acqDisp);
    auto relFn = *reinterpret_cast<BOOL (__fastcall**)(HANDLE)>(mapped + rva::kIoctlCloseHandleCall + 6 + relDisp);
    auto ehRelFn = reinterpret_cast<BOOL (__fastcall*)(HANDLE*)>(mapped + rva::kIoctlEhCloseHelper);

    HANDLE ev1 = acqFn();
    CHECK(ev1 != nullptr, "TLS Ioctl Event acquire #1");
    HANDLE evNested = acqFn();
    CHECK(evNested != nullptr && evNested != ev1, "Nested TLS Ioctl Event acquire returns distinct handle");
    CHECK(relFn(evNested) == TRUE, "Nested handle closed cleanly");
    CHECK(ehRelFn(&ev1) == TRUE, "EH cleanup helper releases cached handle without closing it");
    HANDLE ev2 = acqFn();
    CHECK(ev2 == ev1 && g_diag.tlsEventReuses.load() >= 2, "Subsequent acquire reuses exact same cached HANDLE!");
    relFn(ev2);
    OnThreadDetachCleanup();

    ShutdownWinsockProviderWatch();

    // DLL export checks already executed above
    WSACleanup();
}

} // namespace

int main() {
    TestDnsSynthesizerRfcCompliance();
    TestRealIpTtlClamping();
    TestFullBinaryInstallAndLiveHooks();

    std::printf("hotfix_tests: %d/%d assertions passed (%d failed)\n",
                g_testsRun - g_testsFailed, g_testsRun, g_testsFailed);
    return (g_testsFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
