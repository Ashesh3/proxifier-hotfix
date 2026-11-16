#pragma once

#include <cstdint>
#include <cstddef>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace hotfix {

// RFC 1035 / RFC 6891 / RFC 3225 wire-safe DNS response synthesizer.
// Matches Proxifier's IncludeAnswerIntoDnsPacket signature:
//   char __fastcall sub_14005D7C0(uint8_t* pkt, size_t* io_len, size_t max_len, const sockaddr* fake_addr)
//
// Guarantees:
// - If pkt == nullptr || io_len == nullptr || *io_len < 12 || max_len < 12 || *io_len > max_len:
//     returns 0 without modifying pkt (caller patched to set *a8 = 1 so no raw query is injected).
// - For any packet of >= 12 bytes, ALWAYS emits a valid DNS response (QR = 1) and returns 1:
//     * OPCODE != 0                 -> NOTIMP  (RCODE = 4)
//     * QDCOUNT != 1 or bad QNAME   -> FORMERR (RCODE = 1)
//     * Compression ptr in Q1       -> FORMERR (RCODE = 1)
//     * Bad/duplicate/misplaced OPT -> FORMERR (RCODE = 1)
//     * Malformed OPT option tuples -> FORMERR (RCODE = 1)
//     * EDNS version != 0           -> BADVERS (header RCODE = 0, OPT ext-RCODE = 1, VERSION = 0)
//     * QTYPE == 0                  -> FORMERR (RCODE = 1)
//     * QCLASS != IN (1)            -> REFUSED (RCODE = 5)
//     * QTYPE/AF mismatch           -> NOERROR NODATA (RCODE = 0, ANCOUNT = 0)
//     * Valid A / AAAA Fake-IP      -> NOERROR + 30s Answer RR (0xC0 0x0C) + optional OPT (1232B, DO preserved)
char __fastcall SynthesizeDnsFakeIpResponse(
    uint8_t* pkt,
    size_t* io_len,
    size_t max_len,
    const sockaddr* fake_addr) noexcept;

// Pure TTL clamping helper (RFC 2181 §8 + Windows MaxCacheTtl 86400s):
//   ttl == 0 || (ttl & 0x80000000u) ? 15u : max(60u, min<uint32_t>(ttl, 86400u) + 15u)
inline constexpr uint32_t ComputeRealIpReverseTtlSec(uint32_t raw_dns_ttl) noexcept {
    if (raw_dns_ttl == 0 || (raw_dns_ttl & 0x80000000u) != 0) {
        return 15u;
    }
    const uint32_t capped = (raw_dns_ttl > 86400u) ? 86400u : raw_dns_ttl;
    const uint32_t with_grace = capped + 15u;
    return (with_grace < 60u) ? 60u : with_grace;
}

} // namespace hotfix
