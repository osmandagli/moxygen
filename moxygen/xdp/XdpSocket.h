#pragma once

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/logging/xlog.h>
#include <folly/SocketAddress.h>

#include <quic/server/QuicUDPSocketFactory.h>

namespace moxygen {

struct xsk_socket_info; // forward declaration 

class XdpSocket : public folly::AsyncUDPSocket {
  public:
    XdpSocket(const XdpSocket&) = delete;
    XdpSocket& operator=(const XdpSocket&) = delete;
    
    void setSharedXsk(xsk_socket_info* sharedXsk) { sharedXsk_ = sharedXsk; }

    xsk_socket_info* getXsk() { return ownsXsk_ ? xdp_.get() : sharedXsk_; }

    int recvmmsg(struct mmsghdr* msgvec, unsigned int vlen,
               unsigned int flags, struct timespec* timeout) override;
    
    void resumeRead(folly::AsyncUDPSocket::ReadCallback* cob) override;

    ssize_t writev(const folly::SocketAddress& address, 
                   const struct iovec* vec, size_t iovec_len,
                   folly::AsyncUDPSocket::WriteOptions options) override;

    explicit XdpSocket(folly::EventBase*, bool ownsXsk);
    ~XdpSocket() override;
  private:
    std::unique_ptr<xsk_socket_info> xdp_;
    xsk_socket_info* sharedXsk_ = nullptr;
    bool ownsXsk_;
};

struct XskShared { xsk_socket_info* xsk = nullptr; };

class XdpSocketFactory : public quic::QuicUDPSocketFactory {
  public:
    ~XdpSocketFactory() override = default;

    XdpSocketFactory(std::shared_ptr<XskShared> shared) : shared_(shared) {}

    std::unique_ptr<quic::FollyAsyncUDPSocketAlias> make(folly::EventBase* evb, int fd)
        override {
      auto sock = std::make_unique<XdpSocket>(evb, fd == -1); // listener owns the socket
      if (fd != -1) {
        sock->setFD(
            folly::NetworkSocket::fromFd(fd),
            quic::FollyAsyncUDPSocketAlias::FDOwnership::SHARED);
        sock->setDFAndTurnOffPMTU();
        sock->setSharedXsk(shared_->xsk);
      } else {
        shared_->xsk = sock->getXsk();
      }
      return sock;
    }
  private:
    std::shared_ptr<XskShared> shared_ = nullptr;
};

} // namespace moxygen