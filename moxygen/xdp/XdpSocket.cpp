#include "moxygen/xdp/XdpSocket.h"
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <memory>
#include <vector>
#include <cstdint>

#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES  4096
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE

namespace moxygen {

struct XdpState {
  // UMEM region
  void* umemArea = nullptr;
  size_t umemSize = 0;
  struct xsk_umem* umem = nullptr;

  // Four rings
  struct xsk_ring_prod fill;    // userspace -> kernel: empty frames for RX
  struct xsk_ring_cons rx;      // kernel -> userspace: received frames
  struct xsk_ring_cons comp;    // kernel -> userspace: finished TX frames
  struct xsk_ring_prod tx;      // userspace -> kernel: frames to send

  struct xsk_socket* xsk = nullptr;

  std::vector<uint64_t> freeFrames; // Unused UMEM frames
  int ifindex = -1;
  int queueId = -1;
};

XdpSocket::~XdpSocket() = default;

XdpSocket::XdpSocket(folly::EventBase* evb) : folly::AsyncUDPSocket(evb) {
  xdp_ = std::make_unique<XdpState>();
  
  XLOG(INFO) << "XdpSocket constructed";
  XLOG(INFO) << "libbpf possible cpus=" << libbpf_num_possible_cpus();
  XLOG(INFO) << "libxdp linked, xsk_socket__create @"
               << reinterpret_cast<void*>(&xsk_socket__create);
}

}