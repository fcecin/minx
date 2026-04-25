# RUDP manual

Audience: AI agents working on or with the MINX RUDP layer. Direct
prose, no marketing.

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
  packet — the application's "skipping ack" lane, semantically a
  per-channel datagram socket.
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
- Not encrypted. Off-path injection is gated by session token only
  (16 bytes of secret-shared randomness). MINX's wire integrity
  (CRC32C) catches corruption; nothing catches a deliberate on-path
  attacker who can read traffic.

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
  test_rudp.cpp        RudpSuite — unit + integration tests, FakeWire-based
  test_rudp_stream.cpp RudpStreamSuite — DISABLED, awaiting full rewrite
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

## Core abstractions

- **Channel** — a `(peer_addr, channel_id)` tuple. Created lazily
  (via `registerChannel` outbound, or `Listener::onAccept` inbound),
  destroyed via any of: caller `closeChannel`, idle GC, peer
  `HS_CLOSE`, peer-restart, handshake exhaustion, reorder cap breach.
- **Channel handler** (`Rudp::ChannelHandler`) — application-owned
  object that receives all per-channel events. Application
  inherits, overrides what it cares about, hands `shared_ptr` to
  Rudp. Carries `rudp() / peer() / channelId()` back-references that
  Rudp injects at registration time.
- **Listener** (`Rudp::Listener`) — single global object, bound at
  construction. Carries the four non-channel events: `onSend`,
  `onAccept`, `onAbuse`. `onAccept` doubles as the per-channel
  factory for INBOUND channels.
- **Pulse** — Rudp's heartbeat. Each pulse: advance memory integrals,
  GC stale channels, fire handshake retries, emit packets for
  channels with data. Pulses fire from `tick(now_us)` and
  `onPacket(...)` based on a deadline cadence.
- **Session token** — 64-bit integer derived from both sides' nonces
  at handshake completion. Authenticates every CHANNEL packet and
  HS_CLOSE.
- **Wire trailer** — every datagram carries a CRC32C trailer over
  `[routing_key | body]`. Corrupted datagrams are dropped before
  any parsing. CRC failures emit a soft abuse signal.

---

## Design decisions (bullet form)

- **Listener is global, ChannelHandler is per-channel.** Listener
  carries the irreducible global ports (`onSend`, `onAccept`,
  `onAbuse`). Per-channel events live on per-channel objects so the
  application doesn't maintain a parallel `(peer, cid) → state` map.
- **Lifecycle is `Opened → [Established] → Closed`** (WebSocket
  shape). `onOpened` fires when the handler is wired into Rudp's
  tracking — earliest possible event. `onClosed` fires exactly once
  per registered channel, regardless of whether the handshake ever
  completed. `onEstablished` is the intermediate ESTABLISHED event;
  may not fire if the channel dies before the handshake completes.
- **Pairing invariant**: every registered channel gets exactly one
  `onOpened` and exactly one `onClosed`. Channels rejected by
  `onAccept` (returning `nullptr`) produce zero events.
- **`registerChannel` for outbound, `onAccept`-returns-handler for
  inbound.** Both paths funnel into the same chokepoint: Rudp injects
  back-references, fires `handler->onOpened()`, then proceeds.
- **`push()` does NOT auto-create channels.** Caller must register
  first. This guarantees every channel always has a handler — no
  events get dispatched into the void.
- **shared_ptr ownership.** Rudp holds one ref while the channel
  exists, drops AFTER `onClosed` returns. App can hold its own ref
  independently. The handler can survive Rudp dropping its ref.
- **`closeChannel` takes a `CloseReason`.** RUDP enumerates only
  reasons it can itself produce (`APPLICATION` for caller-driven,
  plus internal: `IDLE` / `HANDSHAKE_FAILED` / `REORDER_BREACH` /
  `PEER_CLOSED` / `PEER_RESTART`). Application-level "why am I
  closing" (billing, abuse policy) stays in the application's
  bookkeeping — RUDP doesn't enumerate domain reasons.
- **CloseReason crosses the listener boundary, not the wire.** The
  reason the closing side passes to `closeChannel` is visible only
  to that side's handler. The peer sees `PEER_CLOSED`. The HS_CLOSE
  packet doesn't carry a reason; it carries only the session token
  to authenticate the close.
- **Per-channel `ChannelMetrics`** for upper-layer billing /
  accounting: `bytesSent`, `bytesReceived`, `memoryByteSeconds`
  (cumulative integral of buffer bytes × elapsed seconds),
  `openedAtUs`. Billing is the upper layer's policy; RUDP is pure
  measurement. `bytesReceived` is charged BEFORE CRC verification
  (closes the attack vector where deliberate corruption would
  otherwise consume bandwidth + CPU for free).
- **Abuse signals** fed back to MINX. Strong (forged session token,
  reorder cap breach) → `Minx::banAddress`. Soft (CRC failure, stray
  packets, truncated headers) → `Minx::checkSpam`. The same signals
  also fire `Listener::onAbuse` for application-level metrics
  regardless of whether MINX was provided at construction.
- **Unreliable on a stream channel is suspicious.** `RudpStream`
  never mixes unreliable bytes into the byte-stream's read path.
  An unreliable arrival routes to an optional application-installed
  sink; default is silent drop. Receiving unreliable on a stream
  channel is plausibly an attack vector (or just garbage); the
  application decides policy.

---

## API reference — RUDP layer

### `class Rudp`

Construction:

```cpp
Rudp(Listener* listener, RudpConfig config = {}, Minx* minx = nullptr);
```

- `listener` is mandatory and asserted non-null at construction.
  Must outlive the `Rudp`.
- `minx` is optional. When non-null, RUDP feeds abuse signals to its
  filters automatically. When null, only the `Listener::onAbuse`
  hook fires; no IP-level action is taken (used by tests).
- `config` is `RudpConfig` (see below).

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

Subclass this for per-channel state. Override only the events you
care about. The protected accessors are populated by Rudp at
registration time and are valid from the start of `onOpened()` through
the end of `onClosed()` (after which the handler may still be alive
in app memory but `rudp()` may dangle if the Rudp is destroyed).

**Idiomatic shape:**

```cpp
class MyChannel : public Rudp::ChannelHandler {
public:
  void onOpened() override {
    // (peer, cid, rudp) are valid here. Set up any per-channel state
    // that needs them.
  }
  void onEstablished() override {
    // Now I can rely on end-to-end I/O. Send a hello, etc.
    rudp()->push(peer(), channelId(), greeting_, /*reliable=*/true);
  }
  void onReliableMessage(const Bytes& msg) override { /* ... */ }
  void onWritable() override { /* resume any deferred send */ }
  void onClosed(Rudp::CloseReason r) override {
    // Final event. Rudp drops its shared_ptr ref after this returns.
  }
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

- `onSend` is mandatory. RUDP has bytes to put on the wire. The
  bytes already start with the 8-byte stdext routing key; no
  further wrapping. Glue typically forwards to
  `minx->sendExtension(peer, bytes)`.
- `onAccept` is BOTH the inbound predicate AND the handler factory.
  Returning `nullptr` rejects the inbound channel silently. Returning
  a non-null `shared_ptr<ChannelHandler>` accepts and binds it as the
  channel's handler — Rudp will fire `onOpened()` on it, route per-
  channel events to it, and call `onClosed()` at the end. Default
  implementation returns `nullptr` (reject all). Fires only on FRESH
  inbound `HS_OPEN` (not on duplicate retransmits, not on
  simultaneous-open where the app already committed via push).
- `onAbuse` reports wire-level peer behavior (forged tokens, CRC
  failures, etc). `channel_id` may be 0 when the signal can't be
  attributed to a specific channel. See "AbuseSignal" below.

### `enum class Rudp::CloseReason`

| Value | Trigger |
|---|---|
| `APPLICATION` | `closeChannel()` default |
| `IDLE` | Idle GC fired (channel inactivity timeout) |
| `HANDSHAKE_FAILED` | Sent OPEN, never got ACCEPT (`handshakeMaxRetries` exhausted) |
| `REORDER_BREACH` | Peer overran our reorder buffer (resource attack) |
| `PEER_CLOSED` | Peer sent a valid HS_CLOSE |
| `PEER_RESTART` | Peer sent HS_OPEN with a different nonce on an established channel (likely process restart) |

Stream operator: `operator<<(std::ostream&, CloseReason)` prints the
enum name (e.g. `"PEER_CLOSED"`).

RUDP only enumerates reasons it can itself produce. Application-
level "why am I closing" (billing, policy, abuse decision) is the
application's own bookkeeping — call `closeChannel(p, c)` (default
APPLICATION) and remember the why locally. The peer always sees
`PEER_CLOSED`.

### `enum class Rudp::AbuseSignal`

Strong (`isStrongAbuseSignal == true`):

| Value | Meaning |
|---|---|
| `FORGED_SESSION_TOKEN_CHANNEL` | CHANNEL packet with right cid but wrong token |
| `FORGED_SESSION_TOKEN_HS_CLOSE` | HS_CLOSE on existing ESTABLISHED channel with wrong token |
| `REORDER_CAP_BREACH` | Peer overran reorder buffer |

Soft (`isStrongAbuseSignal == false`):

| Value | Meaning |
|---|---|
| `CRC_FAILURE` | CRC32C trailer didn't match |
| `STRAY_HS_CLOSE` | HS_CLOSE for unknown / non-ESTABLISHED channel |
| `STRAY_CHANNEL_PACKET` | CHANNEL packet for unknown / non-ESTABLISHED channel |
| `TRUNCATED_PACKET` | Packet too short to contain its sub-protocol's fixed header |

When a non-null `Minx*` was passed at construction:

- Strong → `minx->banAddress(peer.address())` (drops subsequent UDP
  packets from that prefix at MINX's IP filter).
- Soft → `minx->checkSpam(peer.address(), /*alsoUpdate=*/true)`
  (count-min sketch with threshold logic).

`Listener::onAbuse` fires regardless of whether `Minx*` was
provided. Use it for application-level metrics, logging, tests.

`isStrongAbuseSignal(s)` is a public `static constexpr bool` for
consumers that want to apply the same severity split for their own
metrics.

### `struct Rudp::ChannelMetrics`

```cpp
struct ChannelMetrics {
  uint64_t bytesSent = 0;
  uint64_t bytesReceived = 0;
  uint64_t memoryByteSeconds = 0;
  uint64_t openedAtUs = 0;
};
```

- `bytesSent` / `bytesReceived` are the full datagram sizes
  (including the 8-byte routing key and 4-byte CRC trailer),
  cumulative monotone. `bytesReceived` is charged BEFORE CRC verify
  / token check / sub-protocol parsing; corrupted, wrong-token, and
  truncated-but-channel-id-readable packets all bill the addressed
  channel.
- `memoryByteSeconds` is the cumulative integral of "current buffer
  bytes × elapsed seconds." Updated lazily on each pulse and once
  at destruction. Buffers counted: reorder buffer, send buffer,
  preEstablished queue, pending unreliable. Reads in between can
  lag by up to one pulse interval.
- `openedAtUs` is the `currentTimeUs_` at ESTABLISHED transition.
  Zero for channels that never reached ESTABLISHED.

### Application input verbs

```cpp
bool registerChannel(const SockAddr& peer, uint32_t channel_id,
                  std::shared_ptr<ChannelHandler> handler);
```

Adopt a per-channel handler. Outbound's "Opened" trigger.

- Creates the channel state in IDLE if absent.
- Injects `rudp/peer/cid` back-references into `*handler`.
- Stores the `shared_ptr` on the channel.
- Fires `handler->onOpened()` before returning.

Returns `false` if:
- The per-peer channel cap is exhausted, OR
- The (peer, cid) is already registered (programmer error — use
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
- The channel doesn't exist (not registered),
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
                  CloseReason reason = CloseReason::APPLICATION);
```

Drop a single channel immediately.

- If ESTABLISHED, emits a single HS_CLOSE to the peer (fire-and-
  forget, no retry) so the peer's side tears down synchronously.
- Fires `handler->onClosed(reason)`.
- Drops Rudp's `shared_ptr` ref on the handler.
- Erases the channel from internal maps.

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

Snapshot of a channel's metrics. `std::nullopt` if not tracked.
Returned by value; safe to hold across mutating Rudp calls.

The `memoryByteSeconds` field is updated on each pulse and at
destruction. Reads in between can lag by up to one pulse interval.
Call `tick()` first if a tight snapshot is needed.

### Debug / test inspection

```cpp
size_t peerCount() const;
size_t channelCount(const SockAddr& peer) const;
bool isEstablished(const SockAddr& peer, uint32_t channel_id) const;
uint64_t sessionToken(const SockAddr& peer, uint32_t channel_id) const;
```

For tests and observability. Not part of the production API contract.

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

Re-entrancy: callbacks may call back into Rudp on the same channel
(push, closeChannel, etc) — except from inside `onClosed`, which is
the final notification before Rudp drops its `shared_ptr` ref.

---

## API reference — RudpStream layer

`RudpStream` is a `Rudp::ChannelHandler` subclass that adapts one
RUDP channel into a `boost::asio::AsyncStream`. Any Asio-based
byte-stream library (Boost.Beast HTTP / WebSocket, in-memory pipes,
ad-hoc serializers) can read/write through it without knowing
anything about RUDP's wire format.

### Construction

```cpp
explicit RudpStream(boost::asio::any_io_executor ex);
```

The stream is constructed unbound. Bind it to a channel by either:

1. **Outbound**: pass the `shared_ptr<RudpStream>` to
   `rudp.registerChannel(peer, cid, stream)`.
2. **Inbound**: return the `shared_ptr<RudpStream>` from the
   application's `Rudp::Listener::onAccept`.

In both cases Rudp injects `rudp() / peer() / channelId()` and
fires `onOpened()`.

Non-copyable, non-movable.

### `ChannelHandler` overrides

```cpp
void onOpened() override;
void onReliableMessage(const Bytes& msg) override;
void onUnreliableMessage(const Bytes& msg) override;
void onWritable() override;
void onClosed(Rudp::CloseReason reason) override;
```

These are wired by Rudp; the application doesn't call them. Their
behaviors:

- `onOpened` — placeholder hook. Subclasses can override + chain.
- `onReliableMessage` — appends bytes to the internal read buffer
  and completes any pending `async_read_some`.
- `onUnreliableMessage` — does NOT enter the byte stream's read
  path. Routes to the optional `UnreliableSink` (see below).
  Default: silent drop.
- `onWritable` — resumes a deferred `async_write_some` if one is
  pending.
- `onClosed` — marks the stream closed, stores the reason,
  completes pending handlers with a mapped `error_code`.

### Application controls

```cpp
using UnreliableSink = std::function<void(const Bytes& msg)>;
void setUnreliableSink(UnreliableSink sink);
```

Install a sink for unreliable bytes. Default: silent drop. Receiving
unreliable on a stream channel is unusual and arguably suspicious;
the application can use this to log, abuse-report, force-close, or
ignore.

```cpp
void close();
```

Application-side teardown. Marks the stream closed AND tears down
the underlying RUDP channel via
`rudp()->closeChannel(peer(), channelId(), APPLICATION)`. Pending
handlers complete with `eof`. Idempotent.

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
underlying channel ended on its own). `close()` and `detach()`
leave it `nullopt` — application-driven teardown has no "reason"
beyond the call.

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

When `onClosed` fires and there's a pending `async_read_some` /
`async_write_some` handler, it completes with:

| `CloseReason` | `error_code` |
|---|---|
| `PEER_CLOSED` | `boost::asio::error::eof` |
| Everything else | `boost::asio::error::operation_aborted` |

Rationale: `PEER_CLOSED` is the clean remote-disconnect (TCP-style
eof). Every other reason indicates the underlying transport was
pulled out from under the stream — Asio's `operation_aborted` is
the canonical "cancelled" code. The application can call
`getCloseReason()` to recover the specific cause.

When `close()` (user-driven) is called with pending handlers, they
complete with `eof` regardless of `CloseReason` — it's the
classic "user shut down the stream cleanly" semantic.

### Threading

NOT thread-safe. The `RudpStream`, the `Rudp` it's bound to, and the
Asio handler completions all run on the same thread (typically a
single `io_context`).

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
  // cap exhausted
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

- **Forgetting to register before pushing.** `rudp.push(p, c, msg, r)`
  on a non-registered channel returns `false`. Always `registerChannel`
  first (or accept inbound via `onAccept`).
- **Pushing oversize messages.** `MAX_MESSAGE_SIZE = 1241`. Larger
  payloads must be chunked by the caller (or use `RudpStream`,
  which chunks internally).
- **`close()` vs `detach()` on RudpStream.** `close()` tears down
  the underlying channel (sends HS_CLOSE). `detach()` just closes
  the stream view. Default to `close()` for normal teardown.
- **Calling handler methods after `onClosed`.** After `onClosed`
  returns, Rudp drops its `shared_ptr` ref. If the application
  still holds one, the handler is alive but `rudp()` may dangle
  if the Rudp itself is destroyed. Don't push from a stale
  handler post-close.
- **Trusting `CloseReason` on the peer side.** The peer always
  sees `PEER_CLOSED`. Domain-specific reasons (billing, policy)
  don't traverse the wire.
- **Mixing reliable and unreliable on a stream channel.** RudpStream
  drops unreliable bytes by default. If the application is sending
  unreliable to a stream, install an `UnreliableSink` and decide
  policy explicitly.
- **Per-peer channel cap defaults to 1.** Bump
  `RudpConfig::maxChannelsPerPeer` if multiple concurrent channels
  per peer are needed.
