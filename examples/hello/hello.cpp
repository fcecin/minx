#include <minx/minx.h>

#include <iostream>
#include <random>

minx::Hash generateRandomHash() {
  minx::Hash hash;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;
  for (size_t i = 0; i < hash.size() / sizeof(uint64_t); ++i) {
    reinterpret_cast<uint64_t*>(hash.data())[i] = dis(gen);
  }
  return hash;
}

int main() {
  std::cout << "🚀 Starting Minx Hello World Test..." << std::endl;

  std::atomic<bool> testFinished = false;

  // 1. Setup Network and Listeners
  // ===================================
  minx::IOContext server_ioc;
  minx::IOContext client_ioc;

  minx::SockAddr server_addr(boost::asio::ip::address::from_string("127.0.0.1"),
                             8000);
  minx::SockAddr client_addr(boost::asio::ip::address::from_string("127.0.0.1"),
                             8001);

  class ServerListener : public minx::MinxListener {
  private:
    minx::Minx* minx_instance_ = nullptr;
    std::atomic<bool>& flag_;
    minx::Hash skey_;

  public:
    ServerListener(std::atomic<bool>& flag, const minx::Hash& key)
        : flag_(flag), skey_(key) {}

    void setMinxInstance(minx::Minx* instance) { minx_instance_ = instance; }

    bool isConnected(const minx::SockAddr& addr) override { return false; }

    void incomingGetInfo(const minx::SockAddr& addr,
                      const minx::MinxGetInfo& msg) override {
      std::cout << "✅ Server: Received GET_INFO from "
                << addr.address().to_string() << ":" << addr.port()
                << std::endl;
      minx::MinxInfo ack_msg = {
        .version = 0,
        .gpassword = minx_instance_->generatePassword(),
        .spassword = msg.gpassword,
        .difficulty = minx_instance_->getMinimumDifficulty(),
        .skey = skey_,
        .data = {}};
      minx_instance_->sendInfo(addr, ack_msg);
      std::cout << "  -> Server: Sent INFO." << std::endl;
    }

    void incomingProveWork(const minx::SockAddr& addr,
                           const minx::MinxProveWork& msg,
                           const int difficulty) override {
      std::cout << "✅ Server: Received and successfully validated PROVE_WORK!"
                << std::endl;
      std::cout << "  -> PoW Difficulty: " << difficulty << std::endl;
      std::cout << "  -> Client Public Key: " << msg.ckey << std::endl;
      std::cout << "🎉 Test successful!" << std::endl;
      flag_ = true;
    }
  };

  class ClientListener : public minx::MinxListener {
  private:
    minx::Minx* minx_instance_ = nullptr;
    minx::Hash my_ckey_;
    const minx::SockAddr& server_addr_;

  public:
    ClientListener(const minx::Hash& ckey, const minx::SockAddr& srv_addr)
        : my_ckey_(ckey), server_addr_(srv_addr) {}

    void setMinxInstance(minx::Minx* instance) { minx_instance_ = instance; }

    void incomingInfo(const minx::SockAddr& addr,
                         const minx::MinxInfo& msg) override {
      std::cout << "✅ Client: Received INFO from server." << std::endl;
      std::cout << "  -> Server key: " << msg.skey << std::endl;
      std::cout << "  -> Generated password: " << msg.spassword << std::endl;

      // 1. Tell the client's Minx instance to create a VM for the server's key.
      std::cout << "  -> Client: Creating VM for server's key (this may take a "
                   "moment)..."
                << std::endl;
      minx_instance_->createVM(msg.skey);

      // 2. Wait for the client's worker thread to finish initializing the VM.
      while (!minx_instance_->checkVM(msg.skey)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      std::cout << "  -> Client: VM is ready." << std::endl;

      // 3. Now that the VM is ready, prove the work.
      int numThreads = std::max(std::thread::hardware_concurrency(),
                                static_cast<unsigned int>(1));
      std::cout << "  -> Client: Mining PoW for server's key with difficulty "
                << (int)msg.difficulty << " using " << numThreads
                << " threads..." << std::endl;
      auto start_time = std::chrono::steady_clock::now();
      auto pow_template_opt = minx_instance_->proveWork(
        my_ckey_, {}, msg.skey, msg.difficulty, numThreads);
      auto end_time = std::chrono::steady_clock::now();

      if (!pow_template_opt) {
        std::cerr << "❌ Client: Failed to mine PoW." << std::endl;
        return;
      }

      const auto& pow_template = *pow_template_opt;
      minx::MinxProveWork final_pow_msg = {.version = 0,
                                           .gpassword = 0,
                                           .spassword = msg.gpassword,
                                           .ckey = pow_template.ckey,
                                           .time = pow_template.time,
                                           .nonce = pow_template.nonce,
                                           .solution = pow_template.solution,
                                           .data = {}};

      minx_instance_->sendProveWork(server_addr_, final_pow_msg);

      auto total_duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time -
                                                              start_time);
      double avg_us_per_iter = 0.0;
      uint64_t iterations = pow_template_opt->nonce + 1;
      if (iterations > 0) {
        auto total_duration_us =
          std::chrono::duration_cast<std::chrono::microseconds>(end_time -
                                                                start_time);
        avg_us_per_iter =
          static_cast<double>(total_duration_us.count()) / iterations;
      }
      std::cout << "  -> Client: Mined and sent PROVE_WORK; nonce = "
                << final_pow_msg.nonce
                << ", diff = " << minx::getDifficulty(final_pow_msg.solution)
                << std::endl;
      std::cout << "    -> Solution: " << final_pow_msg.solution << " (binary: "
                << minx::hashToBinaryString(final_pow_msg.solution) << ")"
                << std::endl;
      std::cout << "    -> Mining Time: " << total_duration_ms.count() << " ms"
                << std::endl;
      std::cout << "    -> Avg. per Nonce: " << std::fixed
                << std::setprecision(2) << avg_us_per_iter << " µs"
                << std::endl;
    }
  };

  // 2. Initialize Server and Client
  // ==============================
  minx::Hash server_key = generateRandomHash();

  ServerListener server_listener(testFinished, server_key);
  minx::Minx server_minx(&server_listener);
  server_minx.setUseDataset(false); // server will verify hash only once
  server_listener.setMinxInstance(&server_minx);

  minx::Hash client_key = generateRandomHash();
  ClientListener client_listener(client_key, server_addr);
  minx::Minx client_minx(&client_listener);
  client_minx.setUseDataset(true); // client will hash repeatedly (hash mining)
  client_listener.setMinxInstance(&client_minx);

  try {
    server_minx.openSocket(server_ioc, server_addr);
    std::cout << "  -> Server socket opened on "
              << server_addr.address().to_string() << ":" << server_addr.port()
              << std::endl;
    client_minx.openSocket(client_ioc, client_addr);
    std::cout << "  -> Client socket opened on "
              << client_addr.address().to_string() << ":" << client_addr.port()
              << std::endl;
  } catch (const std::exception& e) {
    std::cerr << "❌ Error opening sockets: " << e.what() << std::endl;
    return 1;
  }

  // 3. Configure the Server
  // ========================
  server_minx.setMinimumDifficulty(10);
  server_minx.setServerKey(server_key);
  server_minx.createVM(server_key);
  std::cout
    << "  -> Server: Key set. Creating RandomX VM (this may take a moment)..."
    << std::endl;

  while (!server_minx.checkVM(server_key)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  std::cout << "  -> Server: VM is ready." << std::endl;

  // 4. Start the Handshake
  // ========================
  const minx::MinxGetInfo init_msg = {0, client_minx.generatePassword(), {}};
  client_minx.sendGetInfo(server_addr, init_msg);
  std::cout << "  -> Client: Sent GET_INFO." << std::endl;

  // 5. Run the Event Loop
  // =====================
  uint64_t lastError, cLastError;
  while (!testFinished) {
    server_ioc.poll();
    client_ioc.poll();

    server_minx.verifyPoWs();

    lastError = server_minx.getLastError();
    if (lastError) {
      std::cout << "ERROR (server): " << lastError << std::endl;
      break;
    }
    cLastError = client_minx.getLastError();
    if (lastError) {
      std::cout << "ERROR (client): " << cLastError << std::endl;
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  // 6. Cleanup
  // ===========
  server_minx.closeSocket();
  client_minx.closeSocket();
  std::cout << "🚪 Sockets closed. Test finished." << std::endl;

  return 0;
}