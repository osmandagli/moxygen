#include "moxygen/xdp/XdpSocket.h"
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetOps.h>

#include <memory>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <algorithm>

#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h> 
#include <netinet/in.h>     
#include <netinet/ip.h>     
#include <netinet/udp.h> 
#include <sys/socket.h>

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
	int ifindex = -1;
	bpf_object* obj = nullptr;

	~xsk_socket_info() {
		if (ifindex > 0) bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
		if (xsk) xsk_socket__delete(xsk);
		if (obj) bpf_object__close(obj);
		delete umem;
	}
};

struct _vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
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

void     xsk_free_umem_frame(xsk_socket_info* xsk, uint64_t addr) { xsk->umem_frame_addr.push_back(addr); }

uint64_t xsk_umem_free_frames(xsk_socket_info* xsk) { return xsk->umem_frame_addr.size(); }

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
  
	return 0;

errno_exit:
	errno = -ret;
	return 1;
}


} // anonymous namespace

XdpSocket::~XdpSocket() = default;

XdpSocket::XdpSocket(folly::EventBase* evb, bool ownsXsk) : folly::AsyncUDPSocket(evb), ownsXsk_(ownsXsk) {

  xdp_ = std::make_unique<xsk_socket_info>();

  XLOG(INFO) << "XdpSocket constructed";
  XLOG(INFO) << "libbpf possible cpus=" << libbpf_num_possible_cpus();
  XLOG(INFO) << "libxdp linked, xsk_socket__create @"
               << reinterpret_cast<void*>(&xsk_socket__create);

  if (!ownsXsk_) return; // If doesn't own the socket don't create UMEM

	int ret;
	int map_fd;
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
	if (ret) {
		fprintf(stderr, "ERROR: Can't create socket \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't create socket");
	}

	int ifindex = if_nametoindex("veth0");
	if (ifindex == 0) {
		fprintf(stderr, "ERROR: Can't find the interface \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't find the interface");
	}
	xdp_->ifindex = ifindex;

	bpf_object* obj = bpf_object__open_file("/local/moxygen_build/repos/github.com-facebookexperimental-moxygen.git/moxygen/xdp/XdpKernel.bpf.o", NULL);
	if (obj == NULL) {
		fprintf(stderr, "ERROR: Can't open bpf object \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't open bpf object");
	}
	xdp_->obj = obj;
  
	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "ERROR: Can't load bpf object \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't load bpf object");
	}

	bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
	if (prog == NULL) {
		fprintf(stderr, "ERROR: Can't find ebpf prog \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't find ebpf prog");
	}

	ret = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);
	if (ret) {
		fprintf(stderr, "ERROR: Can't attach ebpf prog \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't attach ebpf prog");
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: Unvalid map_fd \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Unvalid map_fd");
	}

	ret = xsk_socket__update_xskmap(xdp_->xsk, map_fd);
	if (ret) {
		fprintf(stderr, "ERROR: Can't update xskmap \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't update xskmap");
	}

}

int XdpSocket::recvmmsg(struct mmsghdr* msgvec, unsigned int vlen, unsigned int flags, struct timespec* timeout) {
	
	if (!ownsXsk_)
		return folly::AsyncUDPSocket::recvmmsg(msgvec, vlen, flags, timeout);
	
	unsigned rcvd;
	uint32_t idx_rx = 0, idx_fq = 0;
	size_t nh_off;
	__u16 h_proto;

	rcvd = xsk_ring_cons__peek(&xdp_->rx, vlen, &idx_rx);
	if (!rcvd) {
		errno = EAGAIN; // mvfst treats as "try later"
		return -1;
	}
	
	for (unsigned i = 0; i < rcvd; i++) {
		const struct xdp_desc* d = xsk_ring_cons__rx_desc(&xdp_->rx, idx_rx + i);
		uint8_t* pkt = (uint8_t*)xsk_umem__get_data(xdp_->umem->buffer, d->addr);

		// recycle the frame
		xsk_free_umem_frame(xdp_.get(), d->addr);
		
		struct ethhdr *eth = (struct ethhdr *) pkt;
		nh_off = ETH_HLEN;
		h_proto = eth->h_proto;
		if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
  	  struct _vlan_hdr *vhdr;
  	  vhdr = (struct _vlan_hdr *)(pkt + nh_off);
  	  nh_off += sizeof(struct _vlan_hdr);
  	  h_proto = vhdr->h_vlan_encapsulated_proto;
  	}
		struct iphdr *iph = (struct iphdr *) (pkt + nh_off);
		nh_off += iph->ihl * 4;
		struct udphdr *udp = (struct udphdr *) (pkt + nh_off);
		nh_off += sizeof(udphdr);

		if (d->len < nh_off) {
			msgvec[i].msg_len = 0;
			continue;
		}

		uint8_t* payload = pkt + nh_off;
		size_t payload_len = d->len - nh_off;

		auto& mh = msgvec[i].msg_hdr;
		size_t cap = mh.msg_iov[0].iov_len;
		size_t n = std::min(payload_len, cap);
		memcpy(mh.msg_iov[0].iov_base, payload, n);
		msgvec[i].msg_len = n;

		if (mh.msg_name && mh.msg_namelen >= sizeof(sockaddr_in)) {
  	  auto* sin = (struct sockaddr_in*)mh.msg_name;
  	  sin->sin_family = AF_INET;
  	  sin->sin_addr.s_addr = iph->saddr;   // already network order
  	  sin->sin_port = udp->source;         // already network order
  	  mh.msg_namelen = sizeof(sockaddr_in);
  	}
  	mh.msg_controllen = 0;   // no GRO/cmsg for the first cut
  	mh.msg_flags = 0;
	}

	xsk_ring_cons__release(&xdp_->rx, rcvd);
	unsigned nfree = xsk_umem_free_frames(xdp_.get());
	unsigned room = xsk_prod_nb_free(&xdp_->umem->fq, nfree);
	unsigned stock = std::min(room, nfree);
	if (stock > 0) {
		xsk_ring_prod__reserve(&xdp_->umem->fq, stock, &idx_fq);
		for (unsigned j = 0; j < stock; j++)
      *xsk_ring_prod__fill_addr(&xdp_->umem->fq, idx_fq + j) = xsk_alloc_umem_frame(xdp_.get());
    xsk_ring_prod__submit(&xdp_->umem->fq, stock);
	}
	if (xsk_ring_prod__needs_wakeup(&xdp_->umem->fq))
    recvfrom(xsk_socket__fd(xdp_->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
	
	return rcvd;
}

void XdpSocket::resumeRead(folly::AsyncUDPSocket::ReadCallback* cob) {
	// Base installs readCallback_ and registers the handler on the kernel fd_
	folly::AsyncUDPSocket::resumeRead(cob);

	if (!ownsXsk_) return;

	unregisterHandler();
	changeHandlerFD(folly::NetworkSocket(xsk_socket__fd(xdp_->xsk)));
	bool is_registered = registerHandler(folly::EventHandler::READ | folly::EventHandler::PERSIST);
	if (!is_registered) {
		XLOG(WARNING) << "Can't register the new handler";
	}
}

}