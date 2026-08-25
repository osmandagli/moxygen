#include "moxygen/xdp/XdpSocket.h"
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <bpf/libbpf.h>
#include <xdp/xsk.h>

namespace moxygen {

XdpSocket::XdpSocket(folly::EventBase* evb) : folly::AsyncUDPSocket(evb) {
  XLOG(INFO) << "XdpSocket constructed";
  XLOG(INFO) << "libbpf possible cpus=" << libbpf_num_possible_cpus();
  XLOG(INFO) << "libxdp linked, xsk_socket__create @"
               << reinterpret_cast<void*>(&xsk_socket__create);
}

}