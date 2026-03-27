#ifndef _MINX_PROXY_MINXPROXY_H_
#define _MINX_PROXY_MINXPROXY_H_

/**
 * MinxProxy — TCP-to-UDP MINX proxy.
 *
 * Owns a TcpServer (client-facing) and a Minx instance (upstream-facing).
 * TCP clients send length-prefixed MINX messages; the proxy rewrites
 * tickets (gpassword/spassword), forwards via UDP, and routes responses
 * back to the originating client.
 *
 * The proxy maintains N independent ticket chains ("channels") with the
 * upstream server.  Each channel does its own GET_INFO handshake to obtain
 * a spendable password.  When a client request needs forwarding, a READY
 * channel spends its ticket, transitions to BUSY, and waits for the
 * server's response (which carries the next ticket).  If no response
 * arrives within channelTimeout, the channel re-handshakes.
 *
 * - GET_INFO from clients is served from cache (never forwarded).
 * - INIT from clients is swallowed (never forwarded).
 * - All other messages are forwarded via a channel with proper tickets.
 *
 * Subclasses can override the filter methods to inspect and reject
 * incoming client messages before they are forwarded upstream.
 * Returning false from a filter closes the client connection.
 */

#include <minx/minx.h>
#include <minx/proxy/tcp_server.h>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <random>
#include <unordered_map>
#include <vector>

namespace minx {

inline MinxConfig defaultProxyMinxConfig() {
  MinxConfig cfg;
  cfg.trustLoopback = true;
  cfg.spamThreshold = 65535;
  return cfg;
}

struct MinxProxyConfig {
  /** Maximum simultaneous TCP client connections. */
  size_t maxClients = 1000;

  /** Number of independent ticket channels to the upstream server. */
  size_t numChannels = 8;

  /** Timeout for a channel waiting for a response before re-handshaking. */
  std::chrono::seconds channelTimeout{10};

  /** Sweep interval for checking channel timeouts and cleaning queues. */
  std::chrono::seconds sweepInterval{3};

  /** Maximum queued requests waiting for a channel (0 = unlimited). */
  size_t maxQueueSize = 0;

  /** Simulated packet loss in basis points (0 = none, 10000 = 100%).
   *  For testing only. Uses evenly-spaced drops with exact math:
   *  expectedDeliveries(N, packetLossBps) gives the precise count. */
  uint16_t packetLossBps = 0;

  /** Minx configuration for the upstream connection.
   *  The proxy multiplexes many TCP clients onto one UDP upstream, so
   *  the spam threshold is maximized to avoid self-rate-limiting. */
  MinxConfig minxConfig = defaultProxyMinxConfig();
};

/**
 * Given N packets sent with the given loss rate, returns exactly how many
 * will be delivered. Matches the proxy emulator's evenly-spaced drop pattern.
 */
inline size_t expectedDeliveries(size_t packetsSent, uint16_t lossBps) {
  if (lossBps == 0 || packetsSent == 0)
    return packetsSent;
  size_t fullWindows = packetsSent / 10000;
  size_t remainder = packetsSent % 10000;
  size_t drops = fullWindows * lossBps + remainder * lossBps / 10000;
  return packetsSent - drops;
}

class MinxProxy : public TcpServerHandler, public MinxListener {
public:
  MinxProxy(boost::asio::io_context& io,
            const boost::asio::ip::tcp::endpoint& listenEp,
            const boost::asio::ip::udp::endpoint& upstreamEp,
            const MinxProxyConfig& config = {});

  virtual ~MinxProxy();

  void stop();
  size_t clientCount() const { return server_.clientCount(); }
  bool hasCachedInfo() const { return !cachedInfo_.empty(); }
  size_t pendingCount() const { return pendingResponses_.size(); }
  uint16_t port() const { return server_.port(); }
  size_t readyChannelCount() const;

protected:
  // -- Filters for incoming client messages --
  // Return true to forward, false to drop and close the connection.
  virtual bool filterMessage(const TcpSessionPtr& /*session*/,
                             const MinxMessage& /*msg*/) {
    return true;
  }
  virtual bool filterProveWork(const TcpSessionPtr& /*session*/,
                               const MinxProveWork& /*msg*/) {
    return true;
  }

private:
  // -- TcpServerHandler --
  void onConnect(const TcpSessionPtr& session) override;
  void onMessage(const TcpSessionPtr& session, const uint8_t* data,
                 size_t len) override;
  void onDisconnect(const TcpSessionPtr& session) override;

  // -- MinxListener --
  bool isConnected(const SockAddr& addr) override;
  void incomingInit(const SockAddr& addr, const MinxInit& msg) override;
  void incomingMessage(const SockAddr& addr, const MinxMessage& msg) override;
  void incomingGetInfo(const SockAddr& addr, const MinxGetInfo& msg) override;
  void incomingInfo(const SockAddr& addr, const MinxInfo& msg) override;
  void incomingProveWork(const SockAddr& addr, const MinxProveWork& msg,
                         int difficulty) override;

  // -- Channel management --
  struct Channel {
    enum class State {
      IDLE,
      HANDSHAKING,
      READY,
      BUSY
    };
    State state = State::IDLE;
    uint64_t spendable = 0;     // server's gpassword we can spend next
    uint64_t sentGPassword = 0; // the gpassword we sent, for correlation
    std::chrono::steady_clock::time_point sentAt;
  };

  void handshakeChannel(size_t idx);
  size_t findReadyChannel() const;
  void onChannelReady(size_t idx, uint64_t newSpendable);
  void tryProcessQueue();

  // -- Internal --
  bool parseAndForward(const TcpSessionPtr& session, const uint8_t* data,
                       size_t len);
  void forwardMessage(const TcpSessionPtr& session, MinxMessage&& msg);
  void forwardProveWork(const TcpSessionPtr& session, MinxProveWork&& msg);
  void buildAndSendInfo(const TcpSessionPtr& session, uint64_t clientGPassword);
  void scheduleSweep();

  boost::asio::io_context& io_;
  MinxProxyConfig config_;
  SockAddr upstreamAddr_;
  Minx minx_;
  TcpServer server_;
  boost::asio::steady_timer sweepTimer_;

  // Cached INFO response (raw MINX bytes, no framing).
  std::vector<uint8_t> cachedInfo_;

  // Upstream channels.
  std::vector<Channel> channels_;

  // Pending upstream responses keyed by the proxy's sent gpassword.
  struct PendingInfo {
    TcpSessionPtr client; // null for channel handshake GET_INFO
    uint64_t clientGPassword;
    size_t channelIdx;
    std::chrono::steady_clock::time_point createdAt;
    uint8_t msgType; // MINX_MESSAGE or MINX_PROVE_WORK
  };
  std::unordered_map<uint64_t, PendingInfo> pendingResponses_;

  // Queue for messages waiting for an available channel.
  struct QueuedRequest {
    TcpSessionPtr client;
    uint64_t clientGPassword;
    std::vector<uint8_t> data;
  };
  std::deque<QueuedRequest> queue_;

  std::mt19937_64 rng_;
  std::uniform_int_distribution<uint64_t> distrib_;

  // Packet loss emulator: two independent schedules for forward/return paths.
  // Forward: silently discard client request (channel stays READY).
  // Return: high bit of gpassword signals a "dropped" response.
  static constexpr uint64_t LOSS_BIT = uint64_t(1) << 63;
  size_t lossFwdCount_ = 0;
  size_t lossRetCount_ = 5000; // half-window offset for independence
  bool shouldDropForward();
  uint64_t generateProxyGPassword();
};

} // namespace minx

#endif
