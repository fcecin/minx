# MINX

__NOTE: This is experimental software.__

MINX is a simple cooperative-economy boostrapping protocol for P2P applications that provides resistance against basic attacks, such as IP spoofing, traffic snooping and hijacking (MitM attacks), verification spam and RAM-exhaustion attacks.

This protocol is part of [Hyle](https://hyle-project.org), a [Public Computing](https://medium.com/@fcecin/public-computing-ebfb04489cb0) project.

## Quickstart

MINX is written in C++20. Most dependencies are downloaded by the build scripts. The exception is the [Boost](https://www.boost.org/) suite which must be already installed in your system (via e.g. `sudo apt install libboost-all-dev` in Ubuntu).

The provided build system is written in CMake and produces a static library in both debug and release configurations via `build.sh`.

## Rationale

Public Computing (PubCom, for short) allows nodes in Peer-to-Peer (P2P) networks (also referred to as "decentralized networks") to provide resources to each other, enabling a diverse set of applications. In a PubCom network, a node A may provide resources for a node B so that node B can run application X, and in turn, node B may provide resources for node A so that node A can run application Y. Applications need not be aware of each other, and the network is open and general-purpose, providing for any number of users and applications. Public Computing stands in contrast to Cloud Computing, where computing resources are instead provided by businesses.

MINX is a low-level protocol built to serve as a bootstrapping mechanism for computing resource sharing in a PubCom network. Its implementation is primarily intended as a foundation for higher-level, reusable PubCom middleware, although a P2P network or application could be built directly on top of it.

MINX allows peer nodes in a P2P network to send cheap Proof-of-Work (PoW) solutions to each other in a way that is already protected against several attacks. When a node A sends a PoW solution to a node B, node B records a proportional amount of computing credits to node A. That allows node A to then ask node B for computing resources in a spam-protected, rate-limited way, since the networking, computing, memory or storage expenditure at node B from node A's requests can be billed against node A's bootstrapped credit balance at node B.

Leveraging MINX, a more complex trust and anti-spam system or resource economy can be built. Such higher-level middleware would serve user-facing decentralized applications and provide richer APIs. MINX provides middleware with a basic, generic trust mechanism that securely cold-starts resource exchanges between peer nodes in an application-agnostic way, irrespective of individual peer node capabilities or application intents.

## Protocol specification

All values are encoded in network byte order (big-endian), which means the most significant byte is stored first, the second-most significant byte is stored second, and so on.

The remainder of a datagram payload is denoted by `uint8_t[]` (without a byte size number between the array brackets).

All datagrams have the following header:

- `uint8_t CODE`: Message code.

All message codes `[0xFC..0xFF]` have an additional `uint8_t VERSION` field, which is an implementation identifier. The `VERSION` field has the following format:

- Lower 4 bits: `ENGINE_ID`.
- Higher 4 bits: `FLAGS`.

The `ENGINE_ID` field can have the following known values:

- `0x0`: Default RandomX PoW engine, with 256-bit secure hashes (hashing algorithm is unspecified) and/or 256-bit public keys (public-key signing algorithm unspecified).

Implementors are free to define their own engine codes. There's no mechanism that would avoid `ENGINE_ID` collisions across different projects, but the list above should be expanded with any known IDs.

The `FLAGS` field is implementation-defined. The reference implementation reserves `FLAGS` for an extensions or capabilities bitfield.

The remainder of the datagram is the message, which depends on `CODE`. Below is the specification for all messages.

### INIT (`0xFC`)

Asks the receiver to start verification of the sender's IP address.

- `uint8_t VERSION`: Implementation identifier.
- `uint64_t CPASSWORD`: A non-zero random value, or zero if no password allocated for whatever reason. Whether the value is associated with the receiver's IP address and for how long the value is kept are up to the implementation.
- `uint8_t[] DATA`: If present, data for the MINX implementation or the application.

### INIT_ACK (`0xFD`)

Optional answer to an `INIT` message. Receiver assumes that its `VERSION` informed by the previous `INIT` message is supported by the sender.

- `uint8_t VERSION`: Implementation identifier.
- `uint64_t CPASSWORD`: The same `CPASSWORD` value from the `INIT` message that is being replied to. Whether an older but unspent `CPASSWORD` value is accepted is implementation-defined.
- `uint64_t SPASSWORD`: A non-zero random value, or zero if no password allocated for whatever reason. Whether the value is associated with the receiver's IP address and for how long the value is kept are up to the implementation.
- `uint8_t[] ENGINE_DATA`: If present, data for the MINX implementation or the application.

If `ENGINE_ID` is `0x0`, `ENGINE_DATA` has the following format:

- `uint8_t[32] SKEY`: A 256-bit secure hash over some cryptographic public key controlled by the sender (or the public key itself, if it happens to be 256 bits long).
- `uint8_t DIFFICULTY`: Minimum solution difficulty accepted by the sender, where the average number of hash lookups is in the order of `2^DIFFICULTY`.
- `uint8_t[] DATA`: If present, data for the MINX implementation or the application.

### PROVE_WORK (`0xFE`)

A message that presents a PoW solution for a PoW puzzle.

- `uint8_t VERSION`: Implementation identifier.
- `uint64_t SPASSWORD`: The `SPASSWORD` value received in the most recent `INIT_ACK` message, or zero if none. Whether an older but unspent `SPASSWORD` value is accepted is implementation-defined.
- `uint8_t[] POW_DATA`: The PoW data packet for the PoW engine to process.

The `POW_DATA` data packet's format depends on the value of `ENGINE_ID`.

If `ENGINE_ID` is `0x0` (the default engine), `POW_DATA` has the following syntax:

- `uint8_t[32] CKEY`: A 256-bit secure hash over some cryptographic public key controlled by the sender (or the public key itself, if it happens to be 256 bits long); part of the PoW puzzle.
- `uint64_t TIME`: Timestamp of the PoW puzzle.
- `uint64_t NONCE`: PoW puzzle nonce.
- `uint8_t[32] SOLUTION`: RandomX hash over the concatenation of `CKEY`, `TIME`, `NONCE`.
- `uint8_t[] DATA`: Optional application (or extension) data.

The protocol does not specify an acknowledgement or return message for `PROVE_WORK`. Such a facility can be provided by the application or a protocol extension. For example, the application can choose to check for some kind of credit balance at the remote node and just keep resubmitting proofs until it increases. Or the application can just blindly resubmit `PROVE_WORK` datagrams a certain number of times, or resort to recent proof resubmission if other operations are denied due to a lack of credit. In any case, the receiver should generally not penalise the sender for a double-spend attempt, since looking up `SOLUTION` against a record of previously spent solutions should be a fast operation.

The receiver is responsible for detecting solutions that are correct but that need to be rejected because the puzzle difficulty is not high enough to justify tracking its solution.

MINX does not specify a cryptographic signature for `PROVE_WORK` messages, as there isn't a fundamental need to authenticate any of its fields. The solution cannot be stolen, since the solution is bound to `CKEY`. As for impersonating a `CKEY` for griefing, this is prevented if the application does not penalize a `CKEY` for an invalid request (as an attacker might as well just generate disposable keypairs) and instead relies on MINX's sender address filters.

If the application has any need for cryptography or any other kind of expensive verification or decoding, it can make use of it in the `DATA` field. For example, the `DATA` field can have a cryptographic signature over the entire message, or it can contain a short encrypted message. In that case, the application can defend itself from any kind of replay or spam attack in the `DATA` field by first ensuring that the provided PoW solution is valid. The PoW double-spend check also filters regular duplicate packets.

### EXTENSION (`0xFF`)

Message code for protocol extensions. Extensions are implementation-defined.

- `uint8_t VERSION`: Implementation identifier.
- `uint8_t[] REMAINING`: Extension data.

### APPLICATION (`[0x00, 0xFB]`)

All remaining message codes denote application-defined messages. Application messages are just forwarded to the application.

## Implementation

MINX was designed to work on top of unreliable datagram networks. The reference implementation uses UDP/IP sockets. It comes with a simple networking engine written with Boost ASIO.

MINX assumes that applications will use a public-key signature scheme, but it does not specify it. MINX only handles secure hashes over public key data, freeing the application to use public-key cryptography schemes that generate public keys of any length (which is especially useful for quantum-resistant schemes).

The protocol can be extended to support any Proof-of-Work algorithm. The reference implementation uses [RandomX](https://github.com/tevador/RandomX) and assumes a 256-bit secure hash function for the specified default engine (`ENGINE_ID = 0x0`).

RandomX is a good equalizer for CPU, GPU, FPGA and ASIC miners, and it currently allows MINX to just assume that PoW solutions translate roughly to the same resource expenditure. The main trade-offs in RandomX are memory use (between 256 MB and 2 GB) and verification speed.

RandomX memory use at the verifier is optimized by using a single verifier for all incoming puzzles. PoW solution spam is mitigated by banning IP address ranges for verification failures.

Application protocols that need up to 251 datagram codes (`[0x00..0xFB]`) can just directly extend the message set, reusing the single `CODE` byte in the header. This allows the application to avoid creating its own message frame and to just use the provided networking engine and API.

Implementors can also insert another protocol between the datagram network and MINX, or they can simply replace the header's `CODE` byte with their own header, effectively creating a derived protocol.

### Default engine

The reference implementation of the default engine also serves as its specification, that is, it provides the definitive semantics for the default engine's `PROVE_WORK` message syntax.

One of the core design decisions in MINX is to have both the PoW puzzle (the base challenge or problem) and the PoW solution (the hash) be generated by the client, and having both be informed in a single `PROVE_WORK` message. The base challenge (the data to be hashed) is bound to a secure hash (`CKEY`) that is calculated over a public key controlled by the client, so PoW solutions can be securely credited at the application layer.

In the default engine, the client accomplishes this by generating the RandomX puzzle from a recent `TIME`, the  `CKEY`, as well as the `NONCE`. That prevents the same PoW solution from being spent across multiple servers. Double-spending in the same server is solved by keeping track of all previously accepted solutions. Solutions can be forgotten after a given time, since puzzles with a `TIME` that is too old are not accepted by the server.

The RandomX verifier is expensive to create, but since it depends only on a secure hash (`SKEY`) that is calculated from the server's public key at the application, a server has to create only one verifier to handle any number of clients.
