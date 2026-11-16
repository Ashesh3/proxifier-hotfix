# Proxifier v4.14.0.1 (x64) Reliability & Performance Hotfix (`msimg32.dll`)

Drop-in x64 proxy DLL (`msimg32.dll`) that patches **8 reliability, DNS, socket-leak, and UI-stall bugs** in **Proxifier for Windows v4.14.0.1 (x64)** (`Proxifier.exe`) in memory at startup—without modifying `Proxifier.exe` or `ProxifierDrv.sys` on disk.

---

## Target Binary Compatibility

| Field | Expected Value |
|---|---|
| **Executable** | `Proxifier.exe` (PE32+ `x86_64`) |
| **Version** | `4.14.0.1` |
| **SizeOfImage** | `0x674000` (`6,687,992` bytes on disk) |
| **SHA-256** | `8C06F7CBD971405FF269B42AEAFA09A79881818E723397FB531728B36E033F79` |

> **Fail-Open Safety:** Before writing a single byte, the plugin verifies `SizeOfImage`, `CProxifierApp` virtual table targets (`InitInstance` / `ExitInstance`), and the exact original instruction bytes at every patch site. If loaded into any other process or a different Proxifier version, it transparently forwards `msimg32.dll` exports to `System32\msimg32.dll` and leaves the host process untouched.

---

## Root Causes & Fixes Included

### 1. UDP Ephemeral Socket Leak in Local DNS Resolver (`RVA 0x3C002`)
- **Bug:** `ResolveViaLocalDnsUdp` (`0x14003BBF0`) creates a UDP socket (`rdi`) for every non-proxied DNS query intercepted by `ProxifierDrv.sys`, calls `connect()` + `send()` + `recv()`, and then overwrites `rdi` at `0x14003C04B` **without calling `closesocket(rdi)`** on both the successful reply path and the 3-retry timeout path (`WSAETIMEDOUT`). Over hours/days of normal browsing, `Proxifier.exe` leaks thousands of bound UDP endpoints until Windows exhausts the dynamic UDP port pool (`16,384` ports), causing system-wide DNS and QUIC failures across all applications.
- **Fix:** Patches `0x3C002..0x3C00B` to call a `.pdata`-unwound thunk (`RtlAddFunctionTable`) that closes `rdi` via `closesocket()` before `rdi` is reused, preserving `RFLAGS` (`ZF`) and native C++ exception-handling unwind state.

### 2. Winsock Catalog Enumeration Storm, OOM Socket Leaks & `2.75s` `getsockname` Stall (`RVA 0xABDC0`, `0x2B490`, `0x29D10`, `0x29F45`)
- **Bug:**
  1. `CreateSockObj` (`0x1400ABDC0`) calls `WSAEnumProtocolsW` twice on **every single TCP/UDP socket creation** (passing a 1-entry buffer that always fails with `WSAENOBUFS`, `malloc`-ing without a `NULL` check, and enumerating the entire Winsock catalog) just to locate the base provider (`ProtocolChain.ChainLen == 1`).
  2. Both `CreateSockObj` (`0xABDC0`) and `AcceptRedirectedTcp` (`0x2B490`) allocate their 16-byte wrapper via MFC `operator new` *after* creating/accepting the `SOCKET`—leaking the handle if `CMemoryException*` is thrown.
  3. `InitRedirectSock` (`0x29D10`) backs off on `WSAEINVAL` (`10022`) from `getsockname()` using `50 * i * i` ms (`50 + 200 + 450 + 800 + 1250 = 2,750 ms`), and leaves `*(a1 + 208)` open on early `bind`/`listen`/`getsockname` failure.
- **Fix:**
  - Caches base-provider `WSAPROTOCOL_INFOW` entries per `(af, type, protocol)` with `WSAProviderConfigChange` automatic invalidation.
  - Pre-allocates the 16-byte host wrapper *before* `WSASocketW` / `WSAAccept` (freeing via the host's CRT `free` while preserving `WSAGetLastError()`), and immediately closes `*(a1 + 208)` if `InitRedirectSock` fails.
  - Reduces `getsockname()` retry backoff at `0x29F45` to `5 * i` ms (`75 ms` nominal total).

### 3. 49.7-Day `GetTickCount()` Uptime Truncation Bug (`RVA 0x336AB`, `0x33859`, `0x33986`, `0x34203`, `0x35093`)
- **Bug:** All 5 DNS cache insertion paths store timestamps using 32-bit `GetTickCount()` zero-extended into a 64-bit `uint64_t`, while all lookup and GC readers compare against 64-bit `GetTickCount64()`. Once Windows uptime exceeds **49.7 days** (`2^32` ms), every newly inserted forward, reverse, and Fake-IP DNS entry is born `> 4.29 billion ms` old and immediately treated as expired.
- **Fix:** Rewires all 5 insertion sites to `GetTickCount64` and stores the full 64-bit `RAX` value.

### 4. Real-IP Reverse-DNS Cache 24h Poisoning & Unlocked Fake-IP Counter (`RVA 0x33670`, `0x33C90`, `0x34080`)
- **Bug:**
  1. `RealIpReverseCacheInsert` (`0x33670`) forces a minimum TTL of `86,400s` (24 hours) on real DNS answers, and `ReverseIpLookup` (`0x33C90`) refreshes `entry->timestamp = GetTickCount64()` on every lookup without checking expiration—turning shared CDN/Anycast IPs into permanent stale-hostname mappings.
  2. `FakeIpAllocate` (`0x34080`) increments `dword_1404124D0` (`127.8.0.0/8` / `fd00:696e:6974:6578::/96` index) outside any lock.
- **Fix:**
  - Clamps Real-IP reverse TTLs to `15s` when `ttl == 0` (or MSB-set per RFC 2181 §8), else `max(60, min(ttl, 86400) + 15)` seconds (matching Windows `Dnscache` `MaxCacheTtl`).
  - Normalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`) before classifying Fake-IP vs Real-IP via host predicates (`0x343E0` / `0x34440`): enforces strict non-sliding insertion expiry on Real-IPs while keeping sliding 24h refresh on Fake-IPs.
  - Serializes `FakeIpAllocate` (`0x34080`) under an exclusive `SRWLOCK`.

### 5. Malformed Fake-IP Wire DNS / EDNS0 Synthesis (`RVA 0x5D7C0`, `0x37318`)
- **Bug:** `IncludeAnswerIntoDnsPacket` (`0x5D7C0`) hardcodes a `65,792s` (`0x00010100`) wire TTL (poisoning Windows `Dnscache` with `127.x.x.x` Fake-IPs long after Proxifier exits), appends the Answer RR *after* the client's EDNS0 `OPT` record in the Additional section, leaves `ANCOUNT = 0` whenever `ARCOUNT > 0`, and—when returning `0`—causes `0x65DB0` to inject a raw 5,000-byte `QR = 0` buffer back to the application.
- **Fix:** Replaces `0x5D7C0` with a zero-heap RFC 1035 / 6891 / 3225 / 2308 synthesizer:
  - Preserves `0x20` QNAME bit-case, writes a `30s` wire TTL Answer RR (`0xC0 0x0C`), and places a clean `OPT` RR (`1232B` UDP payload, `DO` bit preserved, `AD = 0`) strictly in Additional.
  - Validates `{OPTION-CODE, OPTION-LENGTH}` tuples and emits RFC-compliant `FORMERR`, `NOTIMP`, `REFUSED`, `NOERROR` NODATA, or `BADVERS` (extended RCODE 16) responses for any `>= 12B` datagram, while setting `*a8 = 1` at `0x37318` if `< 12B`.

### 6. Overlapped IOCTL Event Churn & Unbounded WFP Thread Spawning (`RVA 0x3CF0`, `0x640A0`)
- **Bug:**
  1. `DeviceIoControlWrapper` (`0x3CF0`) calls `CreateEventW` + `CloseHandle` on every single kernel IOCTL (`GetEvent`, `ProcessRedirect`, `InjectUdp`).
  2. `WfpEventLoop` (`0x640A0`) spawns and detaches a brand-new `std::thread` for every `ALE_CONNECT_REDIRECT` (`Event 2`) connection while executing `FLOW_ESTABLISHED (4)`, `DATAGRAM_DATA (3)`, and `FLOW_DELETE (5)` synchronously on the single reader thread—stalling kernel event draining whenever a local UDP DNS timeout occurs.
- **Fix:**
  - Caches one auto-reset `HANDLE` per thread via `TlsAlloc` across normal acquire (`0x3D56`), normal release (`0x3F26`), C++ exception unwind (`0x3F50`), and `DLL_THREAD_DETACH`.
  - Routes `Events 4, 3, 5` onto **4 causal single-consumer FIFO shards** keyed by `Mix64(flowContext) & 3` (strictly preserving `FLOW_ESTABLISHED -> DATAGRAM_DATA -> FLOW_DELETE` order per flow) and routes `Event 2` onto a **32-thread persistent worker pool** (with bounded dynamic overflow workers when proxy handshakes or auth dialogs block, plus `QS_SENDMESSAGE`-aware shutdown synchronization).

### 7. Predictable Low-Entropy `srand` Seeding (`RVA 0xB393A`, `0xB796A`)
- **Bug:** Non-sticky proxy chain load-balancing (`0xB393A`) and `?nocache=` URL generation (`0xB796A`) re-seed `srand(GetCurrentThreadId() + GetTickCount())` on every call, causing bursts within the same 15.6 ms tick to pick identical proxies/tokens.
- **Fix:** Replaces both sites with `thread_local` SplitMix64 seeding while leaving sticky affinity (`[r12+2Ch]`) untouched.

### 8. UI `PostMessageW(0x464)` Floods & Mutex Contention Stalls (`RVA 0x444B0`, `0x498C0`, `0x2DEF0`, `0x4EB00`)
- **Bug:** Log producers race on unsynchronized rate counters and flood the main window queue with `WM_USER+100` (`0x464`) messages while RichEdit drains unbounded lists on the UI thread; meanwhile, 1-second UI timers (`0x2DEF0`, `0x4EB00`) block the UI thread on worker mutexes (`unk_140412330`, `unk_1404129F0`).
- **Fix:**
  - Coalesces `0x464` notifications to `20 Hz` (`50 ms`) with a UI-thread trailing `SetTimer` flush (never stranding final log lines), caps UI-only pending backlog at `1,000` entries (never dropping file logs), and drains at most `250` lines per UI slice.
  - Converts `0x2DFDD` in `UiTimerConnList` (`0x2DEF0`) to a non-blocking trylock (safely restoring `WM_SETREDRAW = TRUE` on contention), throttles hidden/minimized list refreshes `10x`, and replaces status-bar single-scalar mutex lock/unlock pairs in `0x4EB00` with aligned loads.

---

## Installation

1. Verify your `Proxifier.exe` matches **v4.14.0.1 (x64)**:
   ```powershell
   (Get-FileHash "C:\Program Files (x86)\Proxifier\Proxifier.exe" -Algorithm SHA256).Hash
   # Expected: 8C06F7CBD971405FF269B42AEAFA09A79881818E723397FB531728B36E033F79
   ```
2. Exit Proxifier completely (`File -> Exit` from the system tray).
3. Copy `msimg32.dll` into the Proxifier installation directory (next to `Proxifier.exe`), then flush the Windows DNS cache:
   ```powershell
   Copy-Item .\msimg32.dll "C:\Program Files (x86)\Proxifier\msimg32.dll" -Force
   ipconfig /flushdns
   ```
4. Launch `Proxifier.exe` normally.

> **Uninstall:** Exit `Proxifier.exe` and delete `msimg32.dll` from the Proxifier folder.

---

## Building from Source

Requires **Visual Studio 2022+ (x64 C++20 + MASM `ml64.exe`)** and **CMake 3.24+**. Builds with `/MT` (static CRT—zero runtime redistributable dependencies).

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
.\build\hotfix_tests.exe
```

---

## Live Diagnostics Telemetry

`msimg32.dll` exports `ProxifierHotfixGetDiagnostics()` returning a lock-free `HotfixDiagnostics` struct (`udpSocketsClosed`, `providerCacheHits`, `providerCacheMisses`, `dnsSynthesizedOk`, `dnsSynthesizedErrorResp`, `tlsEventReuses`, `aleEventsDispatched`, `flowEventsDispatched`, `uiLogsCoalesced`, `uiTrylockSkipped`, `patchesInstalled`).
