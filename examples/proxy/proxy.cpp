#include <minx/proxy/minxproxy.h>

#include <boost/asio.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

namespace asio = boost::asio;

static void usage(const char* prog) {
  std::cerr
    << "Usage: " << prog
    << " <listen-addr> <listen-port> <upstream-addr> <upstream-port>"
    << " [channels] [max-clients] [max-queue]\n"
    << "\n"
    << "  listen-addr    TCP listen address (e.g. 0.0.0.0 or ::)\n"
    << "  listen-port    TCP listen port\n"
    << "  upstream-addr  UDP upstream server address\n"
    << "  upstream-port  UDP upstream server port\n"
    << "  channels       Number of ticket channels (default: 8)\n"
    << "  max-clients    Max TCP client connections (default: 1000)\n"
    << "  max-queue      Max queued requests, 0=unlimited (default: 0)\n";
}

int main(int argc, char* argv[]) {
  if (argc < 5) {
    usage(argv[0]);
    return 1;
  }

  std::string listenAddr = argv[1];
  uint16_t listenPort = static_cast<uint16_t>(std::stoi(argv[2]));
  std::string upstreamAddr = argv[3];
  uint16_t upstreamPort = static_cast<uint16_t>(std::stoi(argv[4]));

  minx::MinxProxyConfig config;
  if (argc > 5)
    config.numChannels = static_cast<size_t>(std::stoi(argv[5]));
  if (argc > 6)
    config.maxClients = static_cast<size_t>(std::stoi(argv[6]));
  if (argc > 7)
    config.maxQueueSize = static_cast<size_t>(std::stoi(argv[7]));

  auto listenEp =
    asio::ip::tcp::endpoint(asio::ip::make_address(listenAddr), listenPort);
  auto upstreamEp =
    asio::ip::udp::endpoint(asio::ip::make_address(upstreamAddr), upstreamPort);

  asio::io_context io;

  minx::MinxProxy proxy(io, listenEp, upstreamEp, config);

  std::cout << "minxproxy listening on " << listenEp << " -> upstream "
            << upstreamEp << " (" << config.numChannels << " channels)\n";

  io.run();

  return 0;
}
