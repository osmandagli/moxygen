#pragma once

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/logging/xlog.h>

#include <quic/server/QuicUDPSocketFactory.h>

namespace moxygen {

class XdpSocket : public folly::AsyncUDPSocket {
  public:
    XdpSocket(const XdpSocket&) = delete;
    XdpSocket& operator=(const XdpSocket&) = delete;

    explicit XdpSocket(folly::EventBase*);
    virtual ~XdpSocket() = default;
};

class XdpSocketFactory : public quic::QuicUDPSocketFactory {
  public:
    ~XdpSocketFactory() override = default;

    XdpSocketFactory() = default;
    
    std::unique_ptr<quic::FollyAsyncUDPSocketAlias> make(folly::EventBase* evb, int fd)
        override {
      auto sock = std::make_unique<XdpSocket>(evb);
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