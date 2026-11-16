#include "dns_synthesizer.h"
#ifndef HOTFIX_UNIT_TEST
#include "host_abi.h"
#endif
#include <cstring>
#include <algorithm>

namespace hotfix {

namespace {

constexpr uint16_t kDnsTypeA    = 1;
constexpr uint16_t kDnsTypeAAAA = 28;
constexpr uint16_t kDnsTypeOPT  = 41;
constexpr uint16_t kDnsClassIN  = 1;

constexpr uint8_t kRcodeNoError = 0;
constexpr uint8_t kRcodeFormErr = 1;
constexpr uint8_t kRcodeServFail = 2;
constexpr uint8_t kRcodeNotImp  = 4;
constexpr uint8_t kRcodeRefused = 5;

constexpr uint16_t kEdnsAdvertisedUdpSize = 1232; // Safe IPv4/IPv6 DNS Flag Day 2020 MTU
constexpr uint32_t kFakeIpWireTtlSec      = 30;

inline uint16_t ReadU16BE(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t ReadU32BE(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

inline void WriteU16BE(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

inline void WriteU32BE(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

// Parse QNAME in Question #1 starting at offset 12.
// Rejects compression pointers (0xC0) and extended label types (0x40, 0x80) because
// no prior domain name exists before offset 12 in a DNS message.
// Copies exact wire octets (preserving 0x20 bit-case randomization) into qnameOut.
bool ParseUncompressedQnameAt12(
    const uint8_t* pkt,
    size_t pktLen,
    uint8_t (&qnameOut)[256],
    size_t& qnameLenOut,
    size_t& nameWireEndOut) noexcept
{
    size_t pos = 12;
    size_t outPos = 0;

    while (true) {
        if (pos >= pktLen) {
            return false;
        }
        const uint8_t labelLen = pkt[pos];
        if (labelLen == 0) {
            if (outPos + 1 > 255) {
                return false;
            }
            qnameOut[outPos++] = 0;
            qnameLenOut = outPos;
            nameWireEndOut = pos + 1;
            return true;
        }
        // Top two bits must be 00 (standard label 1..63). Reject 0xC0, 0x80, 0x40.
        if ((labelLen & 0xC0u) != 0) {
            return false;
        }
        if (pos + 1 + labelLen > pktLen) {
            return false;
        }
        // RFC 1035: total wire domain name length including length octets and root <= 255.
        if (outPos + 1 + labelLen + 1 > 255) {
            return false;
        }
        std::memcpy(&qnameOut[outPos], &pkt[pos], 1 + labelLen);
        outPos += 1 + labelLen;
        pos += 1 + labelLen;
    }
}

// Skip an RR owner name in Answer/Authority/Additional sections (compression pointers allowed
// as long as target < current offset, >= 12, and total wire octets <= 255).
bool SkipWireOwnerName(const uint8_t* pkt, size_t pktLen, size_t& cursor, bool& isRootOut) noexcept {
    isRootOut = false;
    if (cursor >= pktLen) {
        return false;
    }
    if (pkt[cursor] == 0) {
        isRootOut = true;
        cursor += 1;
        return true;
    }

    size_t pos = cursor;
    size_t wireEnd = 0;
    bool jumped = false;
    size_t expandedBytes = 0;
    int hops = 0;

    while (true) {
        if (pos >= pktLen) {
            return false;
        }
        const uint8_t b = pkt[pos];
        if (b == 0) {
            expandedBytes += 1;
            if (expandedBytes > 255) {
                return false;
            }
            if (!jumped) {
                wireEnd = pos + 1;
            }
            cursor = wireEnd;
            return true;
        }
        const uint8_t top = b & 0xC0u;
        if (top == 0xC0u) {
            if (pos + 1 >= pktLen) {
                return false;
            }
            const uint16_t target = static_cast<uint16_t>(((b & 0x3Fu) << 8) | pkt[pos + 1]);
            // Pointer must reference an earlier offset >= 12 (never header or forward/self).
            if (target < 12 || target >= pos) {
                return false;
            }
            if (!jumped) {
                wireEnd = pos + 2;
                jumped = true;
            }
            if (++hops > 16) {
                return false;
            }
            pos = target;
        } else if (top == 0) {
            if (pos + 1 + b > pktLen) {
                return false;
            }
            expandedBytes += 1 + b;
            if (expandedBytes >= 255) {
                return false;
            }
            pos += 1 + b;
        } else {
            // Extended label types 0x40 / 0x80 rejected
            return false;
        }
    }
}

bool ValidateOptRdataTuples(const uint8_t* rdata, uint16_t rdlen) noexcept {
    size_t off = 0;
    while (off < rdlen) {
        if (off + 4 > rdlen) {
            return false;
        }
        const uint16_t optLen = ReadU16BE(rdata + off + 2);
        off += 4;
        if (off + optLen > rdlen) {
            return false;
        }
        off += optLen;
    }
    return off == rdlen;
}

size_t EmitErrorOrNodataResponse(
    uint8_t* outBuf,
    size_t maxLen,
    const uint8_t* reqHdr,
    uint8_t headerRcode,
    const uint8_t* qname,
    size_t qnameLen,
    uint16_t qtype,
    uint16_t qclass,
    bool includeQuestion,
    bool includeOpt,
    uint8_t extRcodeHigh8,
    bool doBit) noexcept
{
    const size_t questionBytes = includeQuestion ? (qnameLen + 4) : 0;
    const size_t optBytes = includeOpt ? 11 : 0;
    const size_t totalLen = 12 + questionBytes + optBytes;
    if (totalLen > maxLen || totalLen > 512) {
        if (maxLen < 12) {
            return 0;
        }
        // Minimal 12-byte header-only fallback
        outBuf[0] = reqHdr[0];
        outBuf[1] = reqHdr[1];
        outBuf[2] = static_cast<uint8_t>(0x80u | (reqHdr[2] & 0x79u)); // QR=1, preserve OPCODE & RD
        outBuf[3] = static_cast<uint8_t>(0x80u | (reqHdr[3] & 0x10u) | (headerRcode & 0x0Fu));
        std::memset(outBuf + 4, 0, 8);
        return 12;
    }

    outBuf[0] = reqHdr[0];
    outBuf[1] = reqHdr[1];
    outBuf[2] = static_cast<uint8_t>(0x80u | (reqHdr[2] & 0x79u)); // QR=1, AA=0, TC=0, preserve OPCODE + RD
    outBuf[3] = static_cast<uint8_t>(0x80u | (reqHdr[3] & 0x10u) | (headerRcode & 0x0Fu)); // RA=1, Z=0, AD=0, CD=req_cd
    WriteU16BE(outBuf + 4, includeQuestion ? 1 : 0);
    WriteU16BE(outBuf + 6, 0); // ANCOUNT = 0
    WriteU16BE(outBuf + 8, 0); // NSCOUNT = 0
    WriteU16BE(outBuf + 10, includeOpt ? 1 : 0);

    size_t pos = 12;
    if (includeQuestion) {
        std::memcpy(outBuf + pos, qname, qnameLen);
        pos += qnameLen;
        WriteU16BE(outBuf + pos, qtype);
        WriteU16BE(outBuf + pos + 2, qclass);
        pos += 4;
    }
    if (includeOpt) {
        outBuf[pos] = 0x00; // root owner
        WriteU16BE(outBuf + pos + 1, kDnsTypeOPT);
        WriteU16BE(outBuf + pos + 3, kEdnsAdvertisedUdpSize);
        const uint32_t optTtl = (static_cast<uint32_t>(extRcodeHigh8) << 24) |
                                (doBit ? 0x00008000u : 0u); // VERSION = 0
        WriteU32BE(outBuf + pos + 5, optTtl);
        WriteU16BE(outBuf + pos + 9, 0); // RDLEN = 0
        pos += 11;
    }
    return pos;
}

} // namespace

char __fastcall SynthesizeDnsFakeIpResponse(
    uint8_t* pkt,
    size_t* io_len,
    size_t max_len,
    const sockaddr* fake_addr) noexcept
{
    if (!pkt || !io_len || !fake_addr) {
        return 0;
    }
    const size_t inLen = *io_len;
    if (inLen < 12 || max_len < 12 || inLen > max_len) {
        return 0;
    }

    uint8_t out[512];
    const uint8_t flags0 = pkt[2];
    const uint8_t opcode = static_cast<uint8_t>((flags0 >> 3) & 0x0Fu);
    const bool isResponse = (flags0 & 0x80u) != 0;

    const uint16_t qdcount = ReadU16BE(pkt + 4);
    const uint16_t ancount = ReadU16BE(pkt + 6);
    const uint16_t nscount = ReadU16BE(pkt + 8);
    const uint16_t arcount = ReadU16BE(pkt + 10);

    if (isResponse) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeFormErr, nullptr, 0, 0, 0, false, false, 0, false);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    if (opcode != 0) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeNotImp, nullptr, 0, 0, 0, false, false, 0, false);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    if (qdcount != 1) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeFormErr, nullptr, 0, 0, 0, false, false, 0, false);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    uint8_t qname[256];
    size_t qnameLen = 0;
    size_t nameWireEnd = 0;
    if (!ParseUncompressedQnameAt12(pkt, inLen, qname, qnameLen, nameWireEnd) ||
        nameWireEnd + 4 > inLen)
    {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeFormErr, nullptr, 0, 0, 0, false, false, 0, false);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    const uint16_t qtype  = ReadU16BE(pkt + nameWireEnd);
    const uint16_t qclass = ReadU16BE(pkt + nameWireEnd + 2);
    const size_t questionEnd = nameWireEnd + 4;
    size_t rrCursor = questionEnd;

    // Walk ANCOUNT + NSCOUNT + ARCOUNT using uint32_t to prevent uint16_t overflow.
    const uint32_t nonAdditionalCount = static_cast<uint32_t>(ancount) + static_cast<uint32_t>(nscount);
    const uint32_t totalRrs = nonAdditionalCount + static_cast<uint32_t>(arcount);

    bool hasEdns = false;
    uint16_t clientUdpSize = 512;
    uint8_t ednsVersion = 0;
    bool ednsDoBit = false;

    for (uint32_t idx = 0; idx < totalRrs; ++idx) {
        bool isRootOwner = false;
        if (!SkipWireOwnerName(pkt, inLen, rrCursor, isRootOwner)) {
            const size_t n = EmitErrorOrNodataResponse(
                out, max_len, pkt, kRcodeFormErr, qname, qnameLen, qtype, qclass, true, false, 0, false);
            std::memcpy(pkt, out, n);
            *io_len = n;
#ifndef HOTFIX_UNIT_TEST
            g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
            return 1;
        }
        if (rrCursor + 10 > inLen) {
            const size_t n = EmitErrorOrNodataResponse(
                out, max_len, pkt, kRcodeFormErr, qname, qnameLen, qtype, qclass, true, false, 0, false);
            std::memcpy(pkt, out, n);
            *io_len = n;
#ifndef HOTFIX_UNIT_TEST
            g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
            return 1;
        }
        const uint16_t rrType  = ReadU16BE(pkt + rrCursor);
        const uint16_t rrClass = ReadU16BE(pkt + rrCursor + 2);
        const uint32_t rrTtl   = ReadU32BE(pkt + rrCursor + 4);
        const uint16_t rdLen   = ReadU16BE(pkt + rrCursor + 8);
        rrCursor += 10;
        if (rrCursor + rdLen > inLen) {
            const size_t n = EmitErrorOrNodataResponse(
                out, max_len, pkt, kRcodeFormErr, qname, qnameLen, qtype, qclass, true, false, 0, false);
            std::memcpy(pkt, out, n);
            *io_len = n;
#ifndef HOTFIX_UNIT_TEST
            g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
            return 1;
        }

        if (rrType == kDnsTypeOPT) {
            // RFC 6891 §6.1.1: OPT MUST only appear in Additional section, at most once, with root owner (0x00).
            if (idx < nonAdditionalCount || hasEdns || !isRootOwner ||
                !ValidateOptRdataTuples(pkt + rrCursor, rdLen))
            {
                const size_t n = EmitErrorOrNodataResponse(
                    out, max_len, pkt, kRcodeFormErr, qname, qnameLen, qtype, qclass, true, false, 0, false);
                std::memcpy(pkt, out, n);
                *io_len = n;
#ifndef HOTFIX_UNIT_TEST
                g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
                return 1;
            }
            hasEdns = true;
            clientUdpSize = (rrClass < 512) ? 512 : rrClass;
            ednsVersion = static_cast<uint8_t>((rrTtl >> 16) & 0xFFu);
            ednsDoBit = (rrTtl & 0x00008000u) != 0;
        }
        rrCursor += rdLen;
    }

    // RFC 6891 §6.1.3: Unsupported EDNS version -> BADVERS (extended RCODE 16: hdr RCODE=0, OPT ext-RCODE=1, ver=0)
    if (hasEdns && ednsVersion != 0) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeNoError, qname, qnameLen, qtype, qclass, true, true, 1, ednsDoBit);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    if (qtype == 0) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeFormErr, qname, qnameLen, qtype, qclass, true, hasEdns, 0, ednsDoBit);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    if (qclass != kDnsClassIN) {
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeRefused, qname, qnameLen, qtype, qclass, true, hasEdns, 0, ednsDoBit);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    const uint16_t addrFamily = fake_addr->sa_family;
    const bool matchIpv4 = (qtype == kDnsTypeA && addrFamily == AF_INET);
    const bool matchIpv6 = (qtype == kDnsTypeAAAA && addrFamily == AF_INET6);

    if (!matchIpv4 && !matchIpv6) {
        // Type/family mismatch or non-A/AAAA query -> RFC 2308 NOERROR NODATA (ANCOUNT=0)
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeNoError, qname, qnameLen, qtype, qclass, true, hasEdns, 0, ednsDoBit);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    const uint16_t rdataLen = matchIpv4 ? 4 : 16;
    const size_t answerBytes = 12 + rdataLen; // 0xC0 0x0C (2) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA
    const size_t optBytes = hasEdns ? 11 : 0;
    const size_t outLen = 12 + qnameLen + 4 + answerBytes + optBytes;
    const size_t maxAllowedPayload = std::min<size_t>(max_len, hasEdns ? clientUdpSize : 512u);

    if (outLen > maxAllowedPayload || outLen > sizeof(out)) {
        // Never set TC=1 (TCP retry would bypass UDP 53 interceptor); emit SERVFAIL instead.
        const size_t n = EmitErrorOrNodataResponse(
            out, max_len, pkt, kRcodeServFail, qname, qnameLen, qtype, qclass, true, hasEdns, 0, ednsDoBit);
        std::memcpy(pkt, out, n);
        *io_len = n;
#ifndef HOTFIX_UNIT_TEST
        g_diag.dnsSynthesizedErrorResp.fetch_add(1, std::memory_order_relaxed);
#endif
        return 1;
    }

    // Header: preserve ID, QR=1, OPCODE=0, AA=0, TC=0, RD=req_rd; RA=1, Z=0, AD=0, CD=req_cd, RCODE=0
    out[0] = pkt[0];
    out[1] = pkt[1];
    out[2] = static_cast<uint8_t>(0x80u | (pkt[2] & 0x01u));
    out[3] = static_cast<uint8_t>(0x80u | (pkt[3] & 0x10u));
    WriteU16BE(out + 4, 1); // QDCOUNT = 1
    WriteU16BE(out + 6, 1); // ANCOUNT = 1
    WriteU16BE(out + 8, 0); // NSCOUNT = 0
    WriteU16BE(out + 10, hasEdns ? 1 : 0);

    size_t pos = 12;
    // Question #1 (uncompressed at offset 12 so 0xC0 0x0C in Answer RR is 100% valid)
    std::memcpy(out + pos, qname, qnameLen);
    pos += qnameLen;
    WriteU16BE(out + pos, qtype);
    WriteU16BE(out + pos + 2, qclass);
    pos += 4;

    // Answer RR
    out[pos]     = 0xC0;
    out[pos + 1] = 0x0C;
    WriteU16BE(out + pos + 2, qtype);
    WriteU16BE(out + pos + 4, kDnsClassIN);
    WriteU32BE(out + pos + 6, kFakeIpWireTtlSec);
    WriteU16BE(out + pos + 10, rdataLen);
    pos += 12;

    if (matchIpv4) {
        const auto* sin4 = reinterpret_cast<const sockaddr_in*>(fake_addr);
        std::memcpy(out + pos, &sin4->sin_addr, 4);
        pos += 4;
    } else {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(fake_addr);
        std::memcpy(out + pos, &sin6->sin6_addr, 16);
        pos += 16;
    }

    // Additional RR: EDNS0 OPT placed strictly AFTER Answer RR
    if (hasEdns) {
        out[pos] = 0x00; // root owner
        WriteU16BE(out + pos + 1, kDnsTypeOPT);
        WriteU16BE(out + pos + 3, kEdnsAdvertisedUdpSize);
        WriteU32BE(out + pos + 5, ednsDoBit ? 0x00008000u : 0u);
        WriteU16BE(out + pos + 9, 0);
        pos += 11;
    }

    std::memcpy(pkt, out, pos);
    *io_len = pos;
#ifndef HOTFIX_UNIT_TEST
    g_diag.dnsSynthesizedOk.fetch_add(1, std::memory_order_relaxed);
#endif
    return 1;
}

#ifndef HOTFIX_UNIT_TEST
bool InstallDnsSynthesizerFix() noexcept {
    // Verify original prologue of sub_14005D7C0 (16 bytes: 48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57)
    static const uint8_t kExpectedPrologue[16] = {
        0x48, 0x89, 0x5C, 0x24, 0x18, 0x55, 0x56, 0x57,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
    };
    if (std::memcmp(RvaPtr(rva::kIncludeAnswerInDns), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        return false;
    }
    void* unusedOrig = nullptr;
    if (!InstallDetour(rva::kIncludeAnswerInDns, reinterpret_cast<void*>(&SynthesizeDnsFakeIpResponse), &unusedOrig, 16)) {
        return false;
    }

    // Also patch 0x140037318 (`jmp loc_140037458`, 5 bytes: E9 3B 01 00 00) on the return-0 error path of sub_14005D7C0
    // so `*a8 = 1` (`[rbp + 148h] = 1`) is set before jumping to `loc_140037458` — guaranteeing `sub_140065DB0` NEVER
    // injects a raw 5000-byte query even if `SynthesizeDnsFakeIpResponse` returns 0 on a <12-byte truncated datagram.
    static const uint8_t kExpectedJmp[5] = { 0xE9, 0x3B, 0x01, 0x00, 0x00 };
    uint8_t* failJmpSite = RvaPtr<uint8_t*>(0x037318);
    if (std::memcmp(failJmpSite, kExpectedJmp, sizeof(kExpectedJmp)) != 0) {
        return false;
    }
    uint8_t* stub = AllocTrampolineCode(32, 16);
    if (!stub) {
        return false;
    }
    size_t p = 0;
    const uint8_t seq[] = { 0x48, 0x8B, 0x85, 0x48, 0x01, 0x00, 0x00, 0xC6, 0x00, 0x01 };
    std::memcpy(stub + p, seq, sizeof(seq));
    p += sizeof(seq);
    stub[p] = 0xE9;
    const int32_t to458 = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(RvaPtr(0x037458)) - reinterpret_cast<intptr_t>(stub + p + 5));
    std::memcpy(stub + p + 1, &to458, sizeof(to458));
    p += 5;
    if (!RegisterLeafThunkUnwind(stub, stub + p, 0, 0)) {
        return false;
    }
    uint8_t jmpPatch[5];
    jmpPatch[0] = 0xE9;
    const int32_t toStub = static_cast<int32_t>(
        reinterpret_cast<intptr_t>(stub) - reinterpret_cast<intptr_t>(failJmpSite + 5));
    std::memcpy(jmpPatch + 1, &toStub, sizeof(toStub));
    return WriteMemoryPatch(failJmpSite, jmpPatch, sizeof(jmpPatch));
}
#endif

} // namespace hotfix
