#include <minx/proxy/minxproxyclient.h>

#include <minx/blog.h>
#include <minx/types.h>

#include <boost/endian/conversion.hpp>
#include <randomx.h>

#include <cstring>
#include <limits>
#include <mutex>

LOG_MODULE_DISABLED("minx_proxy_client")

namespace minx {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

static constexpr size_t HASH_INPUT_SIZE =
  sizeof(Hash) * 2 + sizeof(uint64_t) * 2;

// =============================================================================
// Lifecycle
// =============================================================================

MinxProxyClient::MinxProxyClient(MinxListener* listener, bool useDataset)
    : listener_(listener), useDataset_(useDataset), socket_(io_) {}

MinxProxyClient::~MinxProxyClient() { disconnect(); }

bool MinxProxyClient::connect(const tcp::endpoint& proxyEp) {
  if (connected_)
    return true;

  boost::system::error_code ec;
  socket_.connect(proxyEp, ec);
  if (ec) {
    LOGDEBUG << "connect failed" << SVAR(ec);
    return false;
  }

  connected_ = true;
  workGuard_ = std::make_unique<
    asio::executor_work_guard<asio::io_context::executor_type>>(
    io_.get_executor());

  startRead();
  ioThread_ = std::thread([this]() { io_.run(); });

  LOGDEBUG << "connected to proxy" << VAR(proxyEp);
  return true;
}

void MinxProxyClient::disconnect() {
  if (!connected_)
    return;

  connected_ = false;

  boost::system::error_code ec;
  socket_.shutdown(tcp::socket::shutdown_both, ec);
  socket_.close(ec);

  if (workGuard_) {
    workGuard_->reset();
    workGuard_.reset();
  }
  io_.stop();

  if (ioThread_.joinable())
    ioThread_.join();

  // Reset io_context for potential reuse
  io_.restart();

  LOGDEBUG << "disconnected";
}

// =============================================================================
// Send methods
// =============================================================================

void MinxProxyClient::sendGetInfo(const SockAddr& /*addr*/,
                                  const MinxGetInfo& msg) {
  std::vector<uint8_t> buf;
  appendU8(buf, MINX_GET_INFO);
  appendU8(buf, msg.version);
  appendU64(buf, msg.gpassword);
  appendBytes(buf, msg.data);
  sendRaw(buf);
}

void MinxProxyClient::sendMessage(const SockAddr& /*addr*/,
                                  const MinxMessage& msg) {
  std::vector<uint8_t> buf;
  appendU8(buf, MINX_MESSAGE);
  appendU8(buf, msg.version);
  appendU64(buf, msg.gpassword);
  appendU64(buf, msg.spassword);
  appendBytes(buf, msg.data);
  sendRaw(buf);
}

void MinxProxyClient::sendProveWork(const SockAddr& /*addr*/,
                                    const MinxProveWork& msg) {
  std::vector<uint8_t> buf;
  appendU8(buf, MINX_PROVE_WORK);
  appendU8(buf, msg.version);
  appendU64(buf, msg.gpassword);
  appendU64(buf, msg.spassword);
  appendHash(buf, msg.ckey);
  appendHash(buf, msg.hdata);
  appendU64(buf, msg.time);
  appendU64(buf, msg.nonce);
  appendHash(buf, msg.solution);
  // msg.data is std::vector<char>, convert for append
  buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(msg.data.data()),
             reinterpret_cast<const uint8_t*>(msg.data.data()) +
               msg.data.size());
  sendRaw(buf);
}

uint64_t MinxProxyClient::generatePassword() { return rng_.nextNonZero(); }

// =============================================================================
// PoW mining (local)
// =============================================================================

void MinxProxyClient::createPoWEngine(const Hash& key) {
  powEngineKey_ = key;
  powEngine_ = std::make_shared<PoWEngine>(
    std::span<const uint8_t>(key.data(), key.size()), useDataset_);
  powEngine_->initialize();
}

bool MinxProxyClient::checkPoWEngine(const Hash& key) {
  if (!powEngine_ || powEngineKey_ != key)
    return false;
  if (powEngine_->hasError())
    throw std::runtime_error("PoWEngine error: " +
                             powEngine_->getErrorMessage());
  return powEngine_->isReady();
}

std::optional<MinxProveWork> MinxProxyClient::proveWork(
  const Hash& myKey, const Hash& hdata, const Hash& targetKey, int difficulty,
  int numThreads, uint64_t startNonce, uint64_t maxIters) {
  if (!powEngine_ || powEngineKey_ != targetKey)
    throw std::runtime_error("PoWEngine not found");
  if (!powEngine_->isReady())
    throw std::runtime_error("PoWEngine not ready");

  std::atomic<bool> solution_found = false;
  std::atomic<uint64_t> nonce_counter = startNonce;
  uint64_t maxNonce =
    maxIters > 0 ? startNonce + maxIters : std::numeric_limits<uint64_t>::max();

  std::optional<MinxProveWork> result;
  std::mutex result_mutex;

  if (numThreads <= 0)
    numThreads = std::max(std::thread::hardware_concurrency(), 1u);

  std::vector<std::thread> threads;
  threads.reserve(numThreads);

  for (int i = 0; i < numThreads; ++i) {
    threads.emplace_back([&]() {
      auto releaser = powEngine_->getVM();
      randomx_vm* vm = releaser.vm();
      if (!vm)
        return;

      while (true) {
        uint64_t nonce = nonce_counter.fetch_add(1, std::memory_order_relaxed);
        if (solution_found.load(std::memory_order_relaxed) || nonce >= maxNonce)
          break;

        const uint64_t time = getSecsSinceEpoch();

        ArrayBuffer<HASH_INPUT_SIZE> input;
        input.put(myKey);
        input.put(hdata);
        input.put(time);
        input.put(nonce);
        Hash solution_hash;
        randomx_calculate_hash(vm, input.getBackingSpan().data(),
                               input.getSize(), solution_hash.data());

        if (getDifficulty(solution_hash) >= difficulty) {
          bool already =
            solution_found.exchange(true, std::memory_order_acq_rel);
          if (!already) {
            std::lock_guard<std::mutex> lock(result_mutex);
            result.emplace(MinxProveWork{
              0, 0, 0, myKey, hdata, time, nonce, solution_hash, {}});
          }
          break;
        }
      }
    });
  }

  for (auto& t : threads)
    if (t.joinable())
      t.join();

  return result;
}

// =============================================================================
// TCP framing
// =============================================================================

void MinxProxyClient::sendRaw(const std::vector<uint8_t>& data) {
  if (!connected_)
    return;

  uint8_t header[2];
  header[0] = static_cast<uint8_t>((data.size() >> 8) & 0xFF);
  header[1] = static_cast<uint8_t>(data.size() & 0xFF);

  boost::system::error_code ec;
  asio::write(socket_, asio::buffer(header, 2), ec);
  if (ec) {
    disconnect();
    return;
  }
  asio::write(socket_, asio::buffer(data), ec);
  if (ec) {
    disconnect();
    return;
  }
}

void MinxProxyClient::startRead() {
  asio::async_read(socket_, asio::buffer(headerBuf_, 2),
                   [this](boost::system::error_code ec, size_t bytes) {
                     onReadHeader(ec, bytes);
                   });
}

void MinxProxyClient::onReadHeader(boost::system::error_code ec, size_t) {
  if (ec) {
    if (ec != asio::error::operation_aborted) {
      LOGDEBUG << "read header error" << SVAR(ec);
    }
    return;
  }

  uint16_t len = (static_cast<uint16_t>(headerBuf_[0]) << 8) |
                 static_cast<uint16_t>(headerBuf_[1]);
  if (len == 0) {
    startRead();
    return;
  }

  auto buf = std::make_shared<std::vector<uint8_t>>(len);
  asio::async_read(
    socket_, asio::buffer(*buf),
    [this, buf, len](boost::system::error_code ec, size_t bytes) {
      onReadBody(ec, bytes, len);
      if (!ec)
        dispatchMessage(buf->data(), buf->size());
    });
}

void MinxProxyClient::onReadBody(boost::system::error_code ec, size_t /*bytes*/,
                                 uint16_t /*len*/) {
  if (ec) {
    if (ec != asio::error::operation_aborted) {
      LOGDEBUG << "read body error" << SVAR(ec);
    }
    return;
  }
  // Dispatch happens in the lambda that called us. Continue reading.
  startRead();
}

void MinxProxyClient::dispatchMessage(const uint8_t* data, size_t len) {
  if (len < 1)
    return;

  uint8_t code = data[0];
  size_t off = 1;

  // Fake remote address (not meaningful for proxy client)
  SockAddr fakeAddr;

  switch (code) {

  case MINX_INFO: {
    if (len < 1 + 1 + 8 + 8 + 32 + 1)
      break;
    uint8_t version = data[off++];
    uint64_t gpassword, spassword;
    std::memcpy(&gpassword, &data[off], 8);
    gpassword = boost::endian::big_to_native(gpassword);
    off += 8;
    std::memcpy(&spassword, &data[off], 8);
    spassword = boost::endian::big_to_native(spassword);
    off += 8;
    Hash skey;
    std::memcpy(skey.data(), &data[off], 32);
    off += 32;
    uint8_t difficulty = data[off++];
    Bytes extra(reinterpret_cast<const char*>(data + off),
                reinterpret_cast<const char*>(data + len));
    MinxInfo msg{version, gpassword, spassword, difficulty, skey, extra};
    listener_->incomingInfo(fakeAddr, msg);
    break;
  }

  case MINX_MESSAGE: {
    if (len < 1 + 1 + 8 + 8)
      break;
    uint8_t version = data[off++];
    uint64_t gpassword, spassword;
    std::memcpy(&gpassword, &data[off], 8);
    gpassword = boost::endian::big_to_native(gpassword);
    off += 8;
    std::memcpy(&spassword, &data[off], 8);
    spassword = boost::endian::big_to_native(spassword);
    off += 8;
    Bytes payload(reinterpret_cast<const char*>(data + off),
                  reinterpret_cast<const char*>(data + len));
    MinxMessage msg{version, gpassword, spassword, payload};
    listener_->incomingMessage(fakeAddr, msg);
    break;
  }

  case MINX_PROVE_WORK: {
    if (len < 1 + 1 + 8 + 8 + 32 + 32 + 8 + 8 + 32)
      break;
    uint8_t version = data[off++];
    uint64_t gpassword, spassword;
    std::memcpy(&gpassword, &data[off], 8);
    gpassword = boost::endian::big_to_native(gpassword);
    off += 8;
    std::memcpy(&spassword, &data[off], 8);
    spassword = boost::endian::big_to_native(spassword);
    off += 8;
    Hash ckey, pwHdata;
    std::memcpy(ckey.data(), &data[off], 32);
    off += 32;
    std::memcpy(pwHdata.data(), &data[off], 32);
    off += 32;
    uint64_t time, nonce;
    std::memcpy(&time, &data[off], 8);
    time = boost::endian::big_to_native(time);
    off += 8;
    std::memcpy(&nonce, &data[off], 8);
    nonce = boost::endian::big_to_native(nonce);
    off += 8;
    Hash solution;
    std::memcpy(solution.data(), &data[off], 32);
    off += 32;
    // MinxProveWork::data is std::vector<char>
    std::vector<char> extra(reinterpret_cast<const char*>(data + off),
                            reinterpret_cast<const char*>(data + len));
    MinxProveWork msg{version, gpassword, spassword, ckey, pwHdata,
                      time,    nonce,     solution,  extra};
    listener_->incomingProveWork(fakeAddr, msg, getDifficulty(solution));
    break;
  }

  default:
    LOGDEBUG << "unknown message code from proxy" << VAR(code);
    break;
  }
}

// =============================================================================
// Serialization helpers
// =============================================================================

void MinxProxyClient::appendU8(std::vector<uint8_t>& buf, uint8_t v) {
  buf.push_back(v);
}

void MinxProxyClient::appendU64(std::vector<uint8_t>& buf, uint64_t v) {
  uint64_t be = boost::endian::native_to_big(v);
  buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&be),
             reinterpret_cast<uint8_t*>(&be) + 8);
}

void MinxProxyClient::appendHash(std::vector<uint8_t>& buf, const Hash& h) {
  buf.insert(buf.end(), h.begin(), h.end());
}

void MinxProxyClient::appendBytes(std::vector<uint8_t>& buf, const Bytes& b) {
  buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(b.data()),
             reinterpret_cast<const uint8_t*>(b.data()) + b.size());
}

} // namespace minx
