#include "moxygen/xdp/XdpSocket.h"
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <memory>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define NUM_FRAMES  4096
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE
#define INVALID_UMEM_FRAME UINT64_MAX

namespace moxygen {

struct xsk_umem_info {
	struct xsk_ring_prod fq; // userspace -> kernel: empty frames for RX
	struct xsk_ring_cons cq; // kernel -> userspace: finished TX frames
	struct xsk_umem *umem = nullptr;
	void *buffer = nullptr;
	~xsk_umem_info() {
		xsk_umem__delete(umem);
		if (buffer) free(buffer);
	}
};

struct xsk_socket_info {
  // UMEM region
  struct xsk_umem_info* umem = nullptr;

  // Four rings   
  struct xsk_ring_cons rx;      // kernel -> userspace: received frames
  struct xsk_ring_prod tx;      // userspace -> kernel: frames to send

  struct xsk_socket* xsk = nullptr;
	
  std::vector<uint64_t> umem_frame_addr; // Unused UMEM frames

  int queueId = -1;
	~xsk_socket_info() {
		if (xsk) xsk_socket__delete(xsk);
		delete umem;
	}
};

namespace {

xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	int ret;
	auto* umem = new xsk_umem_info();
	umem->buffer = buffer;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		delete umem;
		return NULL;
	}

	return umem;
}

uint64_t xsk_alloc_umem_frame(xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_addr.empty())
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr.back();
	xsk->umem_frame_addr.pop_back();
	return frame;
}

bool xsk_configure_socket(xsk_socket_info* xsk_info, const char* ifname, int queueId) {
	
	struct xsk_socket_config xsk_cfg{};
	uint32_t idx;
	int i;
	int ret;
	
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = 0;  
	xsk_cfg.libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	// veth can't zc, change XDP_COPY to XDP_ZEROCOPY when using real interface
	xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;

	xsk_info->queueId = queueId;

	ret = xsk_socket__create(&xsk_info->xsk, ifname, 
													xsk_info->queueId, xsk_info->umem->umem, &xsk_info->rx, 
													&xsk_info->tx, &xsk_cfg);
	if (ret != 0) {
		goto errno_exit;
	}

	for(i=0; i < NUM_FRAMES; i++) {
		xsk_info->umem_frame_addr.push_back(i * FRAME_SIZE);
	}

	// Reserve space for fill ring
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		goto errno_exit;
	}

	// Populate the fill ring with addrs
	for(i=0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = xsk_alloc_umem_frame(xsk_info);
	}

	// Submit the filled slots to the kernel to process them
	xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
  
	return true;

errno_exit:
	errno = -ret;
	return false;
}

}

// XdpSocket::~XdpSocket() {
//   xsk_socket__delete(xdp_->xsk);
//   if (xdp_->umem) {
//     xsk_umem__delete(xdp_->umem->umem);
//     free(xdp_->umem->buffer);
//     delete xdp_->umem;
//   }
// }
XdpSocket::~XdpSocket() = default;

XdpSocket::XdpSocket(folly::EventBase* evb, bool ownsXsk) : folly::AsyncUDPSocket(evb), ownsXsk_(ownsXsk) {

  xdp_ = std::make_unique<xsk_socket_info>();

  XLOG(INFO) << "XdpSocket constructed";
  XLOG(INFO) << "libbpf possible cpus=" << libbpf_num_possible_cpus();
  XLOG(INFO) << "libxdp linked, xsk_socket__create @"
               << reinterpret_cast<void*>(&xsk_socket__create);

  if (!ownsXsk_) return; // If doesn't own the socket don't create UMEM

	bool ret;
  void *packet_buffer;
	uint64_t packet_buffer_size;

  /* Allocate memory for NUM_FRAMES of the default XDP frame size */
  packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't allocate buffer memory");
	}
	
  /* Initialize shared packet_buffer for umem usage */
	xdp_->umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (xdp_->umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't create umem");
	}

	ret = xsk_configure_socket(xdp_.get(), "veth0", 0);
	if (!ret) {
		fprintf(stderr, "ERROR: Can't create socket \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't create socket");
	}
  
}

}