#pragma once

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/logging/xlog.h>

#include <quic/server/QuicUDPSocketFactory.h>

namespace moxygen {

struct xsk_socket_info; // forward declaration 

class XdpSocket : public folly::AsyncUDPSocket {
  public:
    XdpSocket(const XdpSocket&) = delete;
    XdpSocket& operator=(const XdpSocket&) = delete;

    explicit XdpSocket(folly::EventBase*, bool ownsXsk);
    ~XdpSocket() override;
  private:
    std::unique_ptr<xsk_socket_info> xdp_;
    bool ownsXsk_;
};

class XdpSocketFactory : public quic::QuicUDPSocketFactory {
  public:
    ~XdpSocketFactory() override = default;

    XdpSocketFactory() = default;
    
    std::unique_ptr<quic::FollyAsyncUDPSocketAlias> make(folly::EventBase* evb, int fd)
        override {
      auto sock = std::make_unique<XdpSocket>(evb, fd == -1); // listener owns the socket
      if (fd != -1) {
        sock->setFD(
            folly::NetworkSocket::fromFd(fd),
            quic::FollyAsyncUDPSocketAlias::FDOwnership::SHARED);
        sock->setDFAndTurnOffPMTU();
      }
      return sock;
    }
};

} // namespace moxygen