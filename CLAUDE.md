# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and test

Use `./build.sh` (wrapper around CMake). Builds go under `build/<target>/`, where target is `debug`, `release`, `relwithdebinfo`, or `minsizerel` (defaults to `debug` when only flags are given).

Common invocations:

- `./build.sh debug` — build debug
- `./build.sh debug --test` — build and run the full unit test binary
- `./build.sh debug --test RudpSuite` — run a single Boost.Test suite
- `./build.sh debug --test */TestRudpHandshakeHappyPath` — run a single test case
- `./build.sh debug --asan --test` — AddressSanitizer build + tests
- `./build.sh debug --clean` / `./build.sh rm` — soft clean / wipe `build/`

The test binary is produced at `build/<target>/tests/minxtests` and is a standard Boost.Test executable. Run it directly with Boost.Test flags (`--run_test=<suite>`, `--log_level=test_suite`, `--color_output=yes`) for finer control than `--test` gives. Current suites: `RudpSuite`, `RudpStreamSuite`, `TcpServerSuite`, `MinxProxySuite`, `MinxMockValidationSuite`, `MinxPoWCacheSuite`, `SpamFilterSuite`, `UtilsSuite`.

Examples live under `examples/` (hello, verify, startstop, proxy) and get built automatically when `MINX_BUILD_EXAMPLES=ON` (the default). Binaries land in `build/<target>/examples/<name>/`.

## Development practices

- Always run builds and tests through `build.sh` — don't invoke `cmake` / `ctest` / the test binary ad-hoc. The wrapper encodes the debug/release/asan variants and the test-filter semantics; sidestepping it drifts config between runs.
- Always redirect `build.sh` output to a file and inspect it afterwards with `grep`/`tail`/`head`. Don't pipe `build.sh` directly into filters in the same command — the output is long, interleaves CMake + compile + test logs, and you usually need to look at it from more than one angle (failures, warnings, a specific test case). Example: `./build.sh debug --test > /tmp/minx-build.log 2>&1` then `grep -E "(FAILED|error:)" /tmp/minx-build.log`.
- `./build.sh --test <filter>` forwards the filter verbatim to Boost.Test's `--run_test=`, so any Boost.Test filter syntax works: `RudpSuite` (one suite), `RudpSuite/*` (suite wildcard), `*/TestRudpHandshakeHappyPath` (one case across any suite), `RudpSuite/TestA:RudpSuite/TestB` (multiple cases, colon-separated).

## Dependencies

- **Boost ≥ 1.83** (system-installed, not fetched): `system`, `log`, `log_setup`, `unit_test_framework`. ASIO is used header-only (`BOOST_ASIO_HEADER_ONLY`).
- **RandomX** (FetchContent from tevador/RandomX@master) — compiled with `ARCH=native` for the local CPU by default; comment that line in `CMakeLists.txt` if you need portable binaries.
- **logkv** (FetchContent from fcecin/logkv@main) — header-only (`INTERFACE` target). Minx only uses `logkv::encodeHex` / `decodeHex` (types.h) and `logkv::Reader` / `Writer` / `serializer` / `insufficient_buffer` (buffer.h). Minx does not use logkv's persistent `Store`; logkv is used mostly for deser.

## Protocol and wire format

The canonical wire-format and protocol specification lives in `README.md` (message codes `0xFA..0xFF`, ticket exchange, PoW puzzle layout, default RandomX engine). Don't duplicate that here; read it when touching anything that handles bytes on the wire.

Message codes `[0x00..0xF9]` are application-defined passthrough; `0xFF` is the EXTENSION lane used by MinxStdExtensions and RUDP.

## Architecture

Three layered concerns. Understanding where a change belongs requires seeing all three.

### 1. Core protocol engine — `Minx` (src/minx.cpp, include/minx/minx.h)

Owns the UDP socket and all MINX protocol state: ticket generation/spending (`BucketCache<uint64_t>`), RandomX-based PoW verification, double-spend table (sliding 1-hour slots), IP ban filter (`IPFilter`, /24 or /56 prefixes), and amplification-defense spam filter (`SpamFilter`, count-min sketch over IP prefixes).

`Minx` does NOT own threads. Callers provide two `boost::asio::io_context`s via `openSocket(addr, netIO, taskIO)`:
- `netIO` — UDP send/recv. Serialized via an internal strand; running multiple threads on it is pointless.
- `taskIO` — invokes `MinxListener` callbacks and runs PoW verification via `verifyPoWs()`. **Listener callbacks are NOT thread-safe** — if `taskIO` has multiple threads, the listener must handle concurrency itself.

`MinxRunner` (include/minx/minxrunner.h) is the convenience wrapper that owns both io_contexts plus net/task/pow thread pools. Use it when you want a batteries-included instance; use raw `Minx` when you need to multiplex io_contexts across other subsystems (as `MinxProxy` does).

PoW verification is key-scoped: each `Hash` server key gets one `PoWEngine` (cache + optional dataset + VM pool). Full dataset = ~2GB RAM and faster verify; cache-only = ~256MB and slower. Toggle via `Minx::setUseDataset(bool)`.

### 2. Extension / transport layers (on top of Minx)

- **`MinxStdExtensions` (stdext.h)** — routes MINX EXTENSION (0xFF) packets by 8-byte key: upper 2 bytes = caller-defined "meta", lower 6 bytes = family ID. Build-once, move-into `Minx::setExtensionHandler(std::move(ext).build())`.
- **`Rudp` (rudp/rudp.h)** — reliable+unreliable transport riding on MinxStdExtensions (family `0xFAB1CEC14742`). **Passive state machine**: no threads, no timers. Application drives time via `tick(now_us)` and feeds inbound wire bytes via `onPacket(...)`. Emits via a `SendFn` callback that the glue code normally forwards to `Minx::sendExtension`. Per-channel token bucket; handshake nonce-exchange derives a session token; 32-bit SACK porosity over a contiguous ack.
- **`RudpStream` (rudp/rudp_stream.h)** — Asio AsyncStream adapter so Boost.Beast (HTTP/WebSocket) or any Asio-generic byte-stream can run over one RUDP channel. Not thread-safe; single io_context only.
- **RUDP caveat**: the RUDP code and its docstrings are partly machine-generated and marked experimental. When touching it, prefer behavior confirmed by `tests/test_rudp.cpp` over docstring assertions.

### 3. TCP proxy (proxy/)

`MinxProxy` (proxy/minxproxy.h) is a TCP-to-UDP bridge: clients connect over TCP using 2-byte length-prefixed frames (`TcpServer` / `TcpSession`); the proxy rewrites tickets and forwards to a single upstream UDP MINX server over N parallel ticket "channels". `GET_INFO` is answered from cache; `INIT` is swallowed; everything else is forwarded. The proxy owns its own io_context + thread.

`MinxProxyClient` (proxy/minxproxyclient.h) is the client-side counterpart — drop-in replacement for `Minx` on the client, talks to a `MinxProxy` over TCP, provides its own local PoW mining pipeline. `MinxClientTransport` (proxy/minxclienttransport.h) is the unified facade that picks UDP direct or TCP-via-proxy based on the endpoint type passed to its constructor.

### Cross-cutting

- **Types (types.h)** — `Hash = array<uint8_t, 32>`, `Bytes = boost::container::static_vector<char, 1280>` (note `MAX_DATA_SIZE = 1280`, the IPv6 MTU), `SockAddr = boost::asio::ip::udp::endpoint`.
- **Logging (blog.h)** — a `Boost.Log` façade. Use `LOGINFO << "..." << VAR(x);` patterns. Per-module severity via `LOG_MODULE("mymod")` in a cpp file and `blog::set_level("mymod", blog::trace)` at runtime. Classes opt into instance-name tagging via `MINX_LOG_INSTANCE_STANDARD_BOILERPLATE` / `LOG_INSTANCE_NAME(expr)`.
- **`Csprng` (csprng.h)** — SipHash counter-mode CSPRNG, seeded from `std::random_device` by default; `Csprng(k0, k1)` is the deterministic constructor for tests.

## Test patterns

- `tests/minx_mock.h` provides `MinxMockListener` (callback stats + std::function hooks) and `TestNode` / `MinxMockFixture` for multi-node Minx tests that drive `netio`/`taskio` via `poll()` instead of real threads.
- RUDP tests typically instantiate two `Rudp` objects and hand-wire their `SendFn` callbacks into each other's `onPacket`, manipulating simulated time in microseconds — no sockets, no real io_context.
- Long-running tests (proxy stress, full RandomX init) are slow; prefer `--run_test=SuiteName/TestCase` during iteration and reserve the full suite for pre-commit.
