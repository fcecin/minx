# RUDP manual

Audience: AI agents working on or with the MINX RUDP layer.

---

## Overview

**RUDP** is a reliable + unreliable transport for MINX, layered as a
MINX_EXTENSION suite. It rides on top of MINX's connectionless UDP
substrate and adds:

- A short handshake (OPEN / ACCEPT) that establishes per-channel
  session tokens between two peers, defending against off-path
  injection.
- A reliable in-order message stream per channel (cumulative ack +
  32-bit SACK porosity bitmap).
- An optional unreliable datagram tail riding alongside each channel
  packet, out-of-band to the reliable bytes.
- Per-channel token-bucket pacing (frozen at handshake completion).
- A passive state machine: no threads, no timers, no `io_context`.
  Time and packet input come in from the application.

**What it is NOT:**

- Not a TCP replacement. Channels are message-oriented (≤ 1241 bytes
  per reliable message); the byte-stream view is a layer on top
  (`RudpStream`).
- Not connection-multiplexing. Each (peer_addr, channel_id) is a
  distinct channel. The application picks `channel_id`s out-of-band.
- Not adaptive. The token bucket uses static, peer-advertised rates.
  No AIMD, no congestion control loop.
- Not encrypted. Off-path injection is gated by a 64-bit session
  token derived from a pair of 8-byte nonces exchanged in the
  handshake. RUDP's CRC32C wire trailer catches corruption; nothing
  catches a deliberate on-path attacker who can read traffic.

---

## Implementation organization

```
include/minx/rudp/
  rudp.h           Rudp class, Listener, ChannelHandler, public types
  rudp_stream.h    RudpStream — Asio AsyncStream adapter (a ChannelHandler)

src/
  rudp.cpp         Rudp implementation (all the protocol logic)
  rudp_stream.cpp  RudpStream implementation

tests/
  test_rudp.cpp        RudpSuite — FakeWire-based unit + integration tests
  test_rudp_stream.cpp RudpStreamSuite — end-to-end RudpStream tests, two
                       Rudp instances wired via a StreamWire glue, driven
                       by a real io_context
```

External dependencies (RUDP layer only):

- `<minx/types.h>` — `Bytes` (static_vector<char, 1280>), `SockAddr`.
- `<minx/buffer.h>` — `Buffer` / `ConstBuffer` for BE serialization.
- `<minx/stdext.h>` — `MinxStdExtensions` for routing-key composition.
- `<minx/csprng.h>` — for nonce generation.
- `<minx/minx.h>` — only in `rudp.cpp`, only for `Minx::banAddress` /
  `checkSpam` on the abuse-feedback path. `rudp.h` only forward-
  declares `class Minx`.
- `crc32c/crc32c.h` (system) — wire-trailer CRC.

---

## Glossary

- **Channel** — a `(peer_addr, channel_id)` tuple with its own
  handshake, session token, send / reorder buffers, and metrics.
- **Channel handler** — per-channel app object (subclass of
  `Rudp::ChannelHandler`) that receives `onOpened` /
  `onEstablished` / `onReliableMessage` / etc.
- **Listener** — singleton bound at construction, carries the
  non-channel events: `onSend`, `onAccept` (predicate + factory for
  inbound channels), `onAbuse`.
- **Pulse** — Rudp's heartbeat. Advances memory integrals, runs idle
  GC, fires handshake retries, emits packets. Triggered from
  `tick()` and `onPacket()` based on a deadline cadence.
- **Session token** — 64-bit value derived from both sides' nonces
  at handshake completion. Authenticates every CHANNEL packet and
  HS_CLOSE.
- **Wire trailer** — CRC32C over `[routing_key | body]` on every
  RUDP datagram. Corrupted datagrams are dropped pre-parse.

---

## Design decisions

Load-bearing choices that explain why the API looks the way it does.
Pure API surface details live in the API reference below.

- **Listener is global, ChannelHandler is per-channel.** Listener
  carries the events with no natural per-channel home (`onSend`,
  `onAccept`, `onAbuse`). Everything channel-scoped lives on the
  per-channel handler so the application doesn't maintain a
  parallel `(peer, cid) → state` map.
- **Pairing invariant on the channel handler.** Every channel that
  successfully registers (via `registerChannel` outbound or
  `onAccept`-returns-non-null inbound) gets exactly one `onOpened`
  and exactly one `onClosed`. Channels rejected by `onAccept`
  produce zero events. `onEstablished` is intermediate and may not
  fire if the channel dies before the handshake completes.
- **shared_ptr ownership of the handler.** Rudp holds one ref while
  the channel exists and drops it AFTER `onClosed` returns (so the
  handler can rely on being alive throughout its own `onClosed`).
  The app may hold its own ref independently; the handler can
  outlive Rudp's ref.
- **`push()` does NOT auto-create channels.** Caller registers
  first. This guarantees every channel always has a handler — no
  events ever get dispatched into the void.
- **`closeChannel` carries a `CloseReason` and an optional
  SO_LINGER-style `timeout`.** RUDP only enumerates reasons it can
  itself produce. Application-level "why am I closing" (billing,
  policy, abuse decision) stays in the application's bookkeeping.
  The `timeout` distinguishes immediate (RST) from graceful-drain
  (FIN equivalent).
- **CloseReason crosses the listener boundary, not the wire.** The
  reason the closing side passes is visible only to that side's
  handler. The peer always sees `PEER_CLOSED`. The HS_CLOSE packet
  carries only the session token to authenticate the close.
- **Per-channel metering is pure measurement, not policy.** Rudp
  tracks `bytesSent` / `bytesReceived` / `memoryByteSeconds` /
  `openedAtUs` and exposes them via `metricsFor`; deciding what to
  bill for is the application's job. `bytesReceived` is charged
  BEFORE CRC verification, closing the attack vector where
  deliberate corruption would otherwise consume bandwidth + CPU for
  free.
- **Abuse feedback is two-track.** Strong signals (forged tokens,
  reorder cap breach) → `Minx::banAddress`. Soft (CRC failure,
  stray packets, truncated headers) → `Minx::checkSpam`. The
  `Listener::onAbuse` hook fires for both regardless of whether a
  `Minx*` was provided at construction.
- **Unreliable bytes don't enter `RudpStream`'s read path.** The
  reliable byte stream is the contract; unreliable arrivals are
  out-of-band to it. By default they're dropped; the application
  can opt in via `setUnreliableSink`.

---

## API reference — RUDP layer

### `class Rudp`

```cpp
Rudp(Listener* listener, RudpConfig config = {}, Minx* minx = nullptr);
```

- `listener` is mandatory and asserted non-null at construction.
  Must outlive the `Rudp`.
- `minx` is optional. When non-null, RUDP feeds abuse signals to its
  filters automatically. When null, only the `Listener::onAbuse`
  hook fires; no IP-level action is taken (used by tests).

Non-copyable, non-movable.

### `struct RudpConfig`

| Field | Default | Meaning |
|---|---|---|
| `perChannelBytesPerSecond` | unlimited | Token-bucket refill rate (R) |
| `perChannelBurstBytes` | unlimited | Token-bucket capacity (C) |
| `maxChannelsPerPeer` | 1 | Hard cap on channels per peer addr |
| `maxReorderMessagesPerChannel` | 1024 | Reorder buffer message cap |
| `maxReorderBytesPerChannel` | 1 MB | Reorder buffer byte cap |
| `channelInactivityTimeout` | 60 s | Idle GC threshold |
| `handshakeRetryInterval` | 200 ms | OPEN retry interval |
| `handshakeMaxRetries` | 3 | Max OPEN retransmits |
| `rngSeed` | 0 (= /dev/urandom) | Deterministic RNG seed for tests |
| `baseTickInterval` | 100 ms | Pulse cadence |

Both ends advertise their `perChannel*` config in the handshake;
the channel's effective bucket is `min(local, peer)` per parameter.

### `struct Rudp::ChannelHandler` (virtual base)

```cpp
struct ChannelHandler {
  virtual ~ChannelHandler() = default;
  virtual void onOpened() {}
  virtual void onEstablished() {}
  virtual void onReliableMessage(const Bytes&) {}
  virtual void onUnreliableMessage(const Bytes&) {}
  virtual void onWritable() {}
  virtual void onClosed(CloseReason) {}
protected:
  Rudp* rudp() const noexcept;
  const SockAddr& peer() const noexcept;
  uint32_t channelId() const noexcept;
};
```

Subclass for per-channel state. Override only the events you care
about. The protected accessors are populated by Rudp at registration
time and are valid from the start of `onOpened()` onward.

| Callback | When it fires |
|---|---|
| `onOpened` | Right after Rudp wires this handler into its tracking. Earliest event. |
| `onEstablished` | Handshake complete; end-to-end I/O is reliable. May not fire if the channel dies first. |
| `onReliableMessage` | Reliable message delivered in order. |
| `onUnreliableMessage` | Optional datagram tail of an inbound CHANNEL packet (fires once per inbound CHANNEL packet that carries a non-empty unreliable section). |
| `onWritable` | `sendBuf` shrank; back-pressure has cleared. |
| `onClosed(reason)` | Final event. Fires exactly once after `onOpened`, regardless of how the channel ended. |

**Idiomatic shape:**

```cpp
class MyChannel : public Rudp::ChannelHandler {
public:
  void onEstablished() override {
    rudp()->push(peer(), channelId(), greeting_, /*reliable=*/true);
  }
  void onReliableMessage(const Bytes& msg) override { /* ... */ }
  void onWritable() override { /* resume any deferred send */ }
  void onClosed(Rudp::CloseReason r) override { /* ... */ }
};
```

### `struct Rudp::Listener`

```cpp
struct Listener {
  virtual ~Listener() = default;
  virtual void onSend(const SockAddr& peer, const Bytes& bytes) = 0;
  virtual std::shared_ptr<ChannelHandler> onAccept(
    const SockAddr& peer, uint32_t channel_id) { return nullptr; }
  virtual void onAbuse(const SockAddr& peer, uint32_t channel_id,
                       AbuseSignal signal) {}
};
```

- **`onSend`** is mandatory. Rudp has bytes to put on the wire. The
  bytes already start with the 8-byte stdext routing key — no
  further wrapping needed; glue typically forwards to
  `minx->sendExtension(peer, bytes)`.
- **`onAccept`** is both the inbound predicate and the handler
  factory. Returning `nullptr` rejects the inbound channel silently.
  Returning a non-null `shared_ptr<ChannelHandler>` accepts and
  binds it. Default implementation returns `nullptr` (reject all).
  Fires on:
  - a FRESH inbound `HS_OPEN` (no existing channel state for the
    tuple), and
  - a peer-restart: an HS_OPEN on an existing channel carrying a
    NEW nonce. The old session is torn down first (firing the old
    handler's `onClosed(PEER_RESTART)`); then `onAccept` is re-run
    to decide whether to accept the fresh logical session.

  Does NOT fire on duplicate / retransmitted HS_OPEN (ACCEPT is
  just re-emitted idempotently), or on simultaneous-open where the
  app already committed via `registerChannel` (the handler is
  already wired).
- **`onAbuse`** reports wire-level peer behavior. `channel_id` may
  be 0 when the signal can't be attributed to a specific channel.
  Fires regardless of whether a `Minx*` was provided. See
  `AbuseSignal` below.

### `enum class Rudp::CloseReason`

| Value | Trigger |
|---|---|
| `APPLICATION` | `closeChannel()` default |
| `IDLE` | Idle GC fired (channel inactivity timeout) |
| `HANDSHAKE_FAILED` | Sent OPEN, never got ACCEPT (`handshakeMaxRetries` exhausted) |
| `REORDER_BREACH` | Peer overran our reorder buffer (resource attack) |
| `PEER_CLOSED` | Peer sent a valid HS_CLOSE |
| `PEER_RESTART` | Peer sent HS_OPEN with a different nonce on an established channel |

Stream operator: `operator<<(std::ostream&, CloseReason)` prints
the enum name (e.g. `"PEER_CLOSED"`).

### `enum class Rudp::AbuseSignal`

Strong (`isStrongAbuseSignal(s) == true`):

| Value | Meaning |
|---|---|
| `FORGED_SESSION_TOKEN_CHANNEL` | CHANNEL packet with right cid but wrong token |
| `FORGED_SESSION_TOKEN_HS_CLOSE` | HS_CLOSE on existing ESTABLISHED channel with wrong token |
| `REORDER_CAP_BREACH` | Peer overran reorder buffer |

Soft (`isStrongAbuseSignal(s) == false`):

| Value | Meaning |
|---|---|
| `CRC_FAILURE` | CRC32C trailer didn't match |
| `STRAY_HS_CLOSE` | HS_CLOSE for unknown / non-ESTABLISHED channel |
| `STRAY_CHANNEL_PACKET` | CHANNEL packet for unknown / non-ESTABLISHED channel |
| `TRUNCATED_PACKET` | Packet too short to contain its sub-protocol's fixed header |

When a non-null `Minx*` was passed at construction, strong signals
invoke `minx->banAddress(peer.address())` and soft signals invoke
`minx->checkSpam(peer.address(), /*alsoUpdate=*/true)`.
`isStrongAbuseSignal(s)` is a `static constexpr bool` for consumers
that want to apply the same severity split for their own metrics.

`operator<<(std::ostream&, AbuseSignal)` prints the enum name.

### `struct Rudp::ChannelMetrics`

```cpp
struct ChannelMetrics {
  uint64_t bytesSent = 0;
  uint64_t bytesReceived = 0;
  uint64_t memoryByteSeconds = 0;
  uint64_t openedAtUs = 0;
};
```

- `bytesSent` / `bytesReceived` are full datagram sizes (including
  the 8-byte routing key and 4-byte CRC trailer), cumulative
  monotone. `bytesReceived` is charged BEFORE CRC verify / token
  check / sub-protocol parsing; corrupted, wrong-token, and
  truncated-but-channel-id-readable packets all bill the addressed
  channel.
- `memoryByteSeconds` is the cumulative integral of "current buffer
  bytes × elapsed seconds." Buffers counted: reorder buffer, send
  buffer, preEstablished queue, pending unreliable. Updated lazily
  on each pulse and once at destruction; reads in between can lag
  by up to one pulse interval.
- `openedAtUs` is the application-wall-clock value at the
  ESTABLISHED transition. Zero for channels that never reached
  ESTABLISHED.

### Application input verbs

```cpp
bool registerChannel(const SockAddr& peer, uint32_t channel_id,
                     std::shared_ptr<ChannelHandler> handler);
```

Outbound's "Opened" trigger. Adopts a per-channel handler.

- Creates the channel state if absent.
- Injects `rudp` / `peer` / `cid` back-references into `*handler`.
- Stores the `shared_ptr` on the channel and fires
  `handler->onOpened()`.
- Picks a local nonce, transitions the channel to `OPEN_SENT`,
  resets the handshake retry counter. The OPEN packet itself goes
  out on the next pulse (from `tick()` / `onPacket()` / `flush()`).

Returns `false` if:
- the per-peer channel cap is exhausted, or
- the (peer, cid) is already registered (programmer error — use
  `channelHandler()` to inspect the existing one).

```cpp
std::shared_ptr<ChannelHandler> channelHandler(
  const SockAddr& peer, uint32_t channel_id) const;
```

Returns the handler bound to (peer, cid), or `nullptr` if the
channel doesn't exist or has no handler.

```cpp
bool push(const SockAddr& peer, uint32_t channel_id,
          const Bytes& msg, bool reliable);
```

Enqueue an outbound message on an existing channel. Channel MUST
have been registered (push does NOT auto-create).

Returns `false` if:
- `msg.size() > MAX_MESSAGE_SIZE`,
- the channel doesn't exist (not registered),
- `reliable=true` and the per-channel send buffer is full
  (back-pressure — caller should defer; `onWritable()` will fire
  on the handler when capacity returns).

For unreliable: there is one "pending unreliable" slot per channel.
A subsequent unreliable push overwrites the pending one — only the
latest survives until the next emit.

```cpp
void flush();
```

Drain pending packets through `Listener::onSend` right now. No time
advance. Called after `push()` for minimum latency, or implicitly
from `tick()`.

```cpp
void tick(uint64_t now_us);
```

Advance time. Run handshake retries, idle GC, then a pulse.

```cpp
void onPacket(const SockAddr& peer, uint64_t key,
              const Bytes& payload, uint64_t now_us);
```

Inbound from the wire. The application's stdext handler calls this
when an EXTENSION packet routed to RUDP arrives.

- `payload` is the bytes after the 8-byte stdext routing key (which
  `MinxStdExtensions` has already consumed).
- `key` is the full unmasked routing key.
- `now_us` advances RUDP's internal clock. `onPacket` may fire a
  pulse INLINE if the deadline has elapsed — the application does
  NOT need to call `tick()` right after.

```cpp
uint64_t nextDeadlineUs() const noexcept;
```

The absolute timestamp by which the application's scheduler should
call `tick()` at the latest if no `onPacket()` arrives in the
meantime. Use to set the next fire of a `boost::asio::steady_timer`.

```cpp
void closeChannel(const SockAddr& peer, uint32_t channel_id,
                  CloseReason reason = CloseReason::APPLICATION,
                  std::chrono::microseconds timeout =
                    std::chrono::microseconds(0));
```

Drop a single channel. SO_LINGER-shaped.

**`timeout == 0` (default) — immediate (RST):**

- If ESTABLISHED, emits a single HS_CLOSE to the peer (fire-and-
  forget, no retry).
- Pending bytes in `sendBuf` are dropped.
- Fires `handler->onClosed(reason)`, drops Rudp's `shared_ptr` ref,
  erases the channel.

**`timeout > 0` — graceful (drain then close):**

- Marks the channel and returns immediately.
- The channel keeps pulsing normally: in-flight reliable bytes keep
  retransmitting, ACKs keep being processed.
- When `sendBuf` and `pendingUnreliable` empty, OR `timeout`
  elapses (whichever first), HS_CLOSE fires and the channel tears
  down via the normal path.
- Only meaningful for ESTABLISHED channels; other states fall
  through to the immediate path.
- A second `closeChannel` call on an already-marked channel
  escalates to immediate teardown (RST).
- The application is expected to stop calling `push()` on this
  channel — RUDP does not gate new writes itself.

No-op if the channel doesn't exist.

```cpp
size_t gc(std::chrono::microseconds idleThreshold);
```

Evict every channel whose last activity is older than the
threshold. Returns the number actually evicted. Each fires
`handler->onClosed(IDLE)`. Does NOT emit HS_CLOSE.

### Read-only inspection

```cpp
std::optional<ChannelMetrics> metricsFor(
  const SockAddr& peer, uint32_t channel_id) const;
```

Snapshot by value; safe to hold across mutating Rudp calls.
`memoryByteSeconds` lags by up to one pulse interval; call `tick()`
first if a tight snapshot is needed.

### Debug / test inspection

```cpp
size_t peerCount() const;
size_t channelCount(const SockAddr& peer) const;
bool isEstablished(const SockAddr& peer, uint32_t channel_id) const;
uint64_t sessionToken(const SockAddr& peer, uint32_t channel_id) const;
```

Not part of the production API contract.

### Wire identity constants

```cpp
static constexpr uint64_t EXTENSION_ID = 0xFAB1CEC14742ULL;
static constexpr uint8_t  VERSION_V0 = 0x00;
static constexpr uint8_t  SUBPROTO_HANDSHAKE = 0x00;
static constexpr uint8_t  SUBPROTO_CHANNEL = 0x01;
static constexpr uint64_t KEY_V0_HANDSHAKE = ...;
static constexpr uint64_t KEY_V0_CHANNEL = ...;
static constexpr uint64_t KEY_V0 = KEY_V0_CHANNEL; // alias for stdext registration
static constexpr const char* NAME = "MINX-RUDP";
```

Wire size constants: `MAX_PACKET_SIZE = 1280`, `CRC_SIZE = 4`,
`CHANNEL_HEADER_SIZE = 29`, `RELIABLE_MESSAGE_OVERHEAD = 6`,
`MAX_PAYLOAD_PER_PACKET = 1247`, `MAX_MESSAGE_SIZE = 1241`,
`MAX_RELIABLE_PER_PACKET = 255`.

### Threading

RUDP itself is single-threaded by contract. All callbacks
(`Listener` methods, `ChannelHandler` methods) run inline on
whichever thread drove the triggering call (`tick`, `onPacket`,
`closeChannel`, `push`, `registerChannel`).

Callbacks may call back into Rudp on the same channel (push,
closeChannel, etc.) — except from inside `onClosed`, which is the
final notification before Rudp drops its `shared_ptr` ref.

---

## API reference — RudpStream layer

`RudpStream` is a `Rudp::ChannelHandler` subclass that adapts one
RUDP channel into a `boost::asio::AsyncStream`. Any Asio-based
byte-stream library (Boost.Beast HTTP / WebSocket, in-memory pipes,
ad-hoc serializers) can read / write through it without knowing
RUDP's wire format.

### Construction

```cpp
explicit RudpStream(boost::asio::any_io_executor ex);
```

Constructed unbound. Bind by either:

1. **Outbound**: pass the `shared_ptr<RudpStream>` to
   `rudp.registerChannel(peer, cid, stream)`.
2. **Inbound**: return the `shared_ptr<RudpStream>` from the
   application's `Rudp::Listener::onAccept`.

In both cases Rudp injects `rudp()` / `peer()` / `channelId()` and
fires `onOpened()`.

Non-copyable, non-movable.

### `ChannelHandler` overrides (wired by Rudp; the app doesn't call them)

- `onOpened` — placeholder hook; subclasses may override + chain.
- `onReliableMessage` — appends bytes to the internal read buffer
  and completes any pending `async_read_some`.
- `onUnreliableMessage` — does NOT enter the byte stream's read
  path. Routes to the optional `UnreliableSink` (see below);
  default is silent drop.
- `onWritable` — resumes a deferred `async_write_some` if one is
  pending.
- `onClosed` — marks the stream closed, stores the reason,
  completes pending handlers with a mapped `error_code`.

### Application controls

```cpp
using UnreliableSink = std::function<void(const Bytes& msg)>;
void setUnreliableSink(UnreliableSink sink);
```

Install a sink for unreliable bytes. Default: silent drop.

```cpp
void close();
```

RST-equivalent. Marks the stream closed AND tears down the
underlying RUDP channel via
`rudp()->closeChannel(peer(), channelId(), APPLICATION)` (zero
timeout). Pending handlers complete with `eof`. Idempotent.

```cpp
void shutdown(std::chrono::microseconds timeout);
```

FIN-equivalent. Stops accepting new writes: subsequent
`async_write_some` calls complete with `eof`. Any already-in-flight
`async_write_some` is allowed to drain into Rudp's `sendBuf` before
the deferred close is scheduled. Asks Rudp to fire HS_CLOSE only
after `sendBuf` empties — or after `timeout` elapses, whichever
comes first (timeout falls back to RST). Pending reads stay live
until Rudp fires `onClosed`. Idempotent.

Use when "the peer should see EOF *after* my final bytes" matters
(e.g. an HTTP server flushing its last response chunk before
closing). For fire-and-forget teardown, use `close()` instead.

Internally implemented as `rudp()->closeChannel(peer(),
channelId(), APPLICATION, timeout)` — called immediately if no
write is in flight at `shutdown()` time, otherwise deferred until
the in-flight write's bytes are fully pushed into `sendBuf`.

```cpp
void detach();
```

Same as `close()` but does NOT tear down the underlying RUDP
channel. Rare; for keep-alive scenarios where another consumer
still drives the channel.

```cpp
bool is_open() const noexcept;
std::optional<Rudp::CloseReason> getCloseReason() const noexcept;
std::size_t available() const noexcept; // test/debug only
```

`getCloseReason()` is populated when `onClosed` fired (i.e. the
underlying channel ended on its own). `close()`, `shutdown()`, and
`detach()` leave it `nullopt`.

### Asio AsyncStream concept

```cpp
boost::asio::any_io_executor get_executor() const noexcept;

template <typename MutableBufferSequence, typename ReadHandler>
auto async_read_some(const MutableBufferSequence&, ReadHandler&&);

template <typename ConstBufferSequence, typename WriteHandler>
auto async_write_some(const ConstBufferSequence&, WriteHandler&&);
```

Standard Asio shape. Move-only handlers (e.g. Beast's internal
operations) are supported — internally erased to `std::function`
via a `shared_ptr` holder.

### CloseReason → error_code mapping

When `onClosed` fires with a pending `async_read_some` /
`async_write_some` handler, it completes with:

| `CloseReason` | `error_code` |
|---|---|
| `PEER_CLOSED` | `boost::asio::error::eof` |
| Everything else | `boost::asio::error::operation_aborted` |

Rationale: `PEER_CLOSED` is the clean remote-disconnect (TCP-style
eof); everything else means the underlying transport was pulled
out from under the stream. The application can call
`getCloseReason()` to recover the specific cause.

When `close()` (user-driven) is called with pending handlers, they
complete with `eof` regardless of `CloseReason` — classic "user
shut down the stream cleanly" semantic.

### Threading

NOT thread-safe. The `RudpStream`, the `Rudp` it's bound to, and
the Asio handler completions all run on the same thread (typically
a single `io_context`).

---

## End-to-end usage pattern

Outbound (we initiate):

```cpp
class MyHandler : public Rudp::ChannelHandler { /* ... */ };
class MyListener : public Rudp::Listener {
public:
  void onSend(const SockAddr& peer, const Bytes& bytes) override {
    minx_->sendExtension(peer, bytes); // glue to MINX
  }
};

MyListener listener;
Rudp rudp(&listener, RudpConfig{}, &minx);

auto handler = std::make_shared<MyHandler>(/* ... */);
if (!rudp.registerChannel(peer, /*cid=*/1, handler)) {
  // cap exhausted or already registered
}
rudp.push(peer, 1, payload, /*reliable=*/true);

// Drive the loop:
while (running) {
  rudp.tick(now_us());
  // ... or onPacket(...) when MINX delivers an EXTENSION packet
}
```

Inbound (peer initiates):

```cpp
class MyListener : public Rudp::Listener {
public:
  void onSend(const SockAddr& peer, const Bytes& bytes) override {
    minx_->sendExtension(peer, bytes);
  }
  std::shared_ptr<Rudp::ChannelHandler> onAccept(
    const SockAddr& peer, uint32_t cid) override {
    if (!shouldAccept(peer, cid)) return nullptr; // reject
    return std::make_shared<MyHandler>(/* ... */);
  }
};
```

That's the whole shape. The handler subclass receives all per-
channel events directly; the application does not maintain a
parallel `(peer, cid) → handler` map.

---

## Common gotchas

Things easy to get wrong but not obvious from the API alone.

- **`close()` vs `shutdown(timeout)` vs `detach()` on RudpStream.**
  `close()` is RST: pending `sendBuf` bytes drop on the floor.
  `shutdown(timeout)` is FIN: in-flight writes finish pushing into
  `sendBuf`, then HS_CLOSE fires after the buffer drains (or
  `timeout` elapses). `detach()` closes only the stream view; the
  underlying channel keeps running.
- **`push()` is not gated after `closeChannel(timeout > 0)`.** The
  application must stop its own writes (e.g. `RudpStream::shutdown`
  does this by flipping a private `shutdownPending_` flag that
  makes subsequent `async_write_some` calls return `eof`). Pushing
  past a deferred close just adds bytes that may or may not make it
  out before the deadline.
- **Handler accessors after `onClosed`.** After `onClosed` returns,
  Rudp drops its `shared_ptr` ref. If the application still holds
  one, the handler is alive but `rudp()` may dangle if the `Rudp`
  itself is destroyed first. Don't push from a stale handler
  post-close.
- **`CloseReason` doesn't traverse the wire.** Whatever you pass to
  `closeChannel(..., reason)` is visible only to your own handler's
  `onClosed`. The peer always sees `PEER_CLOSED`.
- **Per-peer channel cap defaults to 1.** Bump
  `RudpConfig::maxChannelsPerPeer` if multiple concurrent channels
  per peer are needed.
- **`MAX_MESSAGE_SIZE = 1241`.** Larger payloads must be chunked by
  the caller (or use `RudpStream`, which chunks internally).
