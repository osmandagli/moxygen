#include "moxygen/xdp/XdpSocket.h"
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetOps.h>
#include <folly/container/F14Map.h>

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

// UMEM is split in two pools so RX can never starve TX (and vice versa).
// RX: frames [0, NUM_RX_FRAMES) circulate only between fill ring, NIC and rx ring.
//     ice pre-posts a whole HW ring (2047) and the fill ring holds 2048 more.
// TX: frames [NUM_RX_FRAMES, NUM_FRAMES) circulate only between tx ring and cq.
#define NUM_RX_FRAMES 4096
#define NUM_TX_FRAMES 4096
#define NUM_FRAMES  (NUM_RX_FRAMES + NUM_TX_FRAMES)
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
	
  std::vector<uint64_t> rx_free; // RX frames owned by userspace, to go back to fq
  std::vector<uint64_t> tx_free; // TX frames available for writev

  uint64_t tx_fallback_pkts = 0; // segments sent via kernel because XSK TX was full

  int queueId = -1;
	int ifindex = -1;
	bpf_object* obj = nullptr;

	// L2 identity cache for TX (populated on RX)
	uint8_t local_mac[6] = {0}; // eth->h_dest on RX eth src on TX
	uint32_t local_ip = 0; 			// iph->daddr (net order) on RX ip src on TX
	uint16_t local_port = 0;		// udp->dest (net order) on RX udp src on TX
	bool l2_ready = false;

	// per-peer next-hop MAC, keyed by peer IPv4 (net order). 
	folly::F14FastMap<uint32_t, std::array<uint8_t, 6>> peer_macs;

	struct Stats {
		uint64_t tx_calls = 0, tx_segs_asked = 0, tx_segs_sent = 0, tx_completed = 0;
		uint64_t tx_fallback = 0, tx_floor_break = 0, tx_alloc_fail = 0;
		uint64_t tx_too_big = 0, tx_ring_full = 0, tx_short = 0, tx_eagain = 0;
		uint64_t tx_kick_err = 0, tx_bad_desc = 0;
		uint64_t rx_pkts = 0, rx_short = 0, rx_trunc = 0;
		uint64_t fq_reserve_fail = 0, dup_free = 0;
    } st;
    uint64_t ticks = 0;
    std::vector<uint8_t> in_pool = std::vector<uint8_t>(NUM_FRAMES, 0); // 1 = chunk sits in umem_frame_addr
    folly::F14FastMap<uint16_t, uint32_t> tx_trace;

	~xsk_socket_info() {
		if (ifindex > 0) bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
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

// RX descriptors carry frame base + headroom offset; strip it back to the frame base
inline uint64_t frame_base(uint64_t addr) { return addr & ~((uint64_t)FRAME_SIZE - 1); }

void     xsk_free_frame(std::vector<uint64_t>& pool, uint64_t addr) { pool.push_back(frame_base(addr)); }

uint64_t xsk_alloc_frame(std::vector<uint64_t>& pool)
{
	uint64_t frame;
	if (pool.empty())
		return INVALID_UMEM_FRAME;

	frame = pool.back();
	pool.pop_back();
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
	xsk_cfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;

	xsk_info->queueId = queueId;

	ret = xsk_socket__create(&xsk_info->xsk, ifname, 
													xsk_info->queueId, xsk_info->umem->umem, &xsk_info->rx, 
													&xsk_info->tx, &xsk_cfg);
	if (ret != 0) {
		goto errno_exit;
	}

	for(i=0; i < NUM_RX_FRAMES; i++) {
		xsk_info->rx_free.push_back((uint64_t)i * FRAME_SIZE);
	}
	for(i=NUM_RX_FRAMES; i < NUM_FRAMES; i++) {
		xsk_info->tx_free.push_back((uint64_t)i * FRAME_SIZE);
	}

	// Reserve space for fill ring
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		goto errno_exit;
	}

	// Populate the fill ring with addrs
	for(i=0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = xsk_alloc_frame(xsk_info->rx_free);
	}

	// Submit the filled slots to the kernel to process them
	xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
  
	return 0;

errno_exit:
	errno = -ret;
	return 1;
}

void complete_tx(xsk_socket_info* x) {
	uint32_t idx_cq = 0;
	unsigned completed = xsk_ring_cons__peek(&x->umem->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

	if (!completed) return;

	for (unsigned i = 0; i < completed; i++) {
		xsk_free_frame(x->tx_free, *xsk_ring_cons__comp_addr(&x->umem->cq, idx_cq + i));
	}
	xsk_ring_cons__release(&x->umem->cq, completed);
}

void complete_func(xsk_socket_info* x) {
	uint32_t idx_fq = 0;

	complete_tx(x);

	unsigned nfree = x->rx_free.size();
	unsigned room = xsk_prod_nb_free(&x->umem->fq, nfree);
	unsigned stock = std::min(room, nfree);
	if (stock > 0) {
		xsk_ring_prod__reserve(&x->umem->fq, stock, &idx_fq);
		for (unsigned j = 0; j < stock; j++)
      		*xsk_ring_prod__fill_addr(&x->umem->fq, idx_fq + j) = xsk_alloc_frame(x->rx_free);
    xsk_ring_prod__submit(&x->umem->fq, stock);
	}

	if (xsk_ring_prod__needs_wakeup(&x->umem->fq))
		//TODO add poll()
    	recvfrom(xsk_socket__fd(x->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

uint16_t ipv4_checksum(const void* data, size_t len) {
	const uint16_t* p = (const uint16_t*) data;
	uint32_t sum = 0;
	while (len > 1) { sum += *p++; len -= 2; } // add each 16-bit word into 32 bit sum
	if (len == 1) sum += *(const uint8_t*)p; // trailing odd byte
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16); // fold carries
	return (uint16_t)~sum; // one's complement; already in net order
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

	int ifindex = if_nametoindex("eno12409np1");
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

	ret = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_DRV_MODE, NULL);
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

	ret = xsk_configure_socket(xdp_.get(), "eno12409np1", 2);
	if (ret) {
		fprintf(stderr, "ERROR: Can't create socket \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't create socket");
	}

	ret = xsk_socket__update_xskmap(xdp_->xsk, map_fd);
	if (ret) {
		fprintf(stderr, "ERROR: Can't update xskmap \"%s\"\n",
			strerror(errno));
		throw std::runtime_error("ERROR: Can't update xskmap");
	}

  complete_func(getXsk());

}

int XdpSocket::recvmmsg(struct mmsghdr* msgvec, unsigned int vlen, unsigned int flags, struct timespec* timeout) {
	
	if (!ownsXsk_)
		return folly::AsyncUDPSocket::recvmmsg(msgvec, vlen, flags, timeout);

	unsigned rcvd;
	uint32_t idx_rx = 0;
	size_t nh_off;
	__u16 h_proto;

	rcvd = xsk_ring_cons__peek(&xdp_->rx, vlen, &idx_rx);
	if (!rcvd) {
	  complete_func(getXsk());
	  errno = EAGAIN; // mvfst treats as "try later"
	  return -1;
	}
	
	for (unsigned i = 0; i < rcvd; i++) {
		const struct xdp_desc* d = xsk_ring_cons__rx_desc(&xdp_->rx, idx_rx + i);
		uint8_t* pkt = (uint8_t*)xsk_umem__get_data(xdp_->umem->buffer, d->addr);

		// recycle the frame; safe because it only goes back to the fill ring in
		// complete_func() below, after the payload has been copied out
		xsk_free_frame(xdp_->rx_free, d->addr);
		
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

		std::array<uint8_t, 6> src;
		memcpy(src.data(), eth->h_source, 6);
		xdp_->peer_macs[iph->saddr] = src;

		if (!xdp_->l2_ready) {
			memcpy(xdp_->local_mac, eth->h_dest, 6);
			xdp_->local_ip = iph->daddr;
			xdp_->local_port = udp->dest;
			xdp_->l2_ready = true;
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
	complete_func(getXsk());

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

	rxKick_ = folly::AsyncTimeout::make(*getEventBase(), [this]() noexcept {
	  complete_func(xdp_.get());
	  rxKick_->scheduleTimeout(1);   // ms; re-arm
	});
	rxKick_->scheduleTimeout(1);

	recvfrom(xsk_socket__fd(xdp_->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

ssize_t XdpSocket::writev(const folly::SocketAddress& address, const struct iovec* vec, size_t iovec_len, folly::AsyncUDPSocket::WriteOptions options) {
	xsk_socket_info* x = getXsk();
	folly::IPAddress ip = address.getIPAddress();
	if (ip.isIPv4Mapped()) {
		ip = folly::IPAddress::createIPv4(ip);
	}
	// If something is not true fallback to old method
	if (!x || !x->l2_ready || !ip.isV4() || iovec_len != 1) {
		return folly::AsyncUDPSocket::writev(address, vec, iovec_len, options);
	}

	uint32_t peer_ip = ip.asV4().toLong();
	auto it = x->peer_macs.find(peer_ip);
	if (it == x->peer_macs.end()) { // never heard from this peer
		return folly::AsyncUDPSocket::writev(address, vec, iovec_len, options);
	}
	const std::array<uint8_t, 6>& dst_mac = it->second;
	uint16_t dst_port = htons(address.getPort());

	size_t payload_len = 0;
	for (size_t i = 0; i < iovec_len; i++) payload_len += vec[i].iov_len;
	if (payload_len == 0) return 0;

	size_t seg_size = options.gso > 0 ? (size_t)options.gso : payload_len;
	size_t sent = 0;
	size_t off = 0;

	for (; off < payload_len; off += seg_size) {
		// This is to make sure that the last one sized correctly
		size_t seg_len = std::min(seg_size, payload_len - off);

		ssize_t hdr_len = 42; // 14 (eth) + 20 (ip) + 8 (udp)
		// datagram must fit into FRAME SIZE (4096)
		if (hdr_len + seg_len > FRAME_SIZE) break;

		// need both a free TX frame and a TX ring slot
		if (x->tx_free.empty() || xsk_prod_nb_free(&x->tx, 1) < 1) {
			complete_tx(x); // reclaim finished TX frames, retry once
			if (x->tx_free.empty() || xsk_prod_nb_free(&x->tx, 1) < 1) break; // still full
		}

		uint64_t frame = xsk_alloc_frame(x->tx_free);
		uint8_t* pkt = (uint8_t*)xsk_umem__get_data(x->umem->buffer, frame);
    	//   4. build eth/ip/udp headers into pkt   (dstMac, x->local_mac, peerIp, dstPort ...)

		struct ethhdr* eth = (struct ethhdr*) pkt;
		memcpy(eth->h_dest, dst_mac.data(), 6); // peer, next hop
		memcpy(eth->h_source, x->local_mac, 6); // us
		eth->h_proto = htons(ETH_P_IP);

		struct iphdr* iph = (struct iphdr*) (pkt + sizeof(*eth));
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(sizeof(*iph) + sizeof(struct udphdr) + seg_len);
		iph->id = 0;
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = IPPROTO_UDP;
		iph->check = 0;
		iph->saddr = x->local_ip;
		iph->daddr = peer_ip;

		struct udphdr* udp = (struct udphdr*) (pkt + sizeof(*eth) + sizeof(*iph));
		udp->source = x->local_port;
		udp->dest = dst_port;
		udp->len = htons(sizeof(*udp) + seg_len);
		udp->check = 0;

		// copy the payload slice
		memcpy(pkt + hdr_len, (const uint8_t*)vec[0].iov_base + off, seg_len);

		iph->check = ipv4_checksum(iph, sizeof(*iph));
    //   7. reserve TX desc: addr, len = 42 + segLen; submit
		uint32_t tx_idx = 0;
		if (xsk_ring_prod__reserve(&x->tx, 1, &tx_idx) != 1) {
			xsk_free_frame(x->tx_free, frame); // couldn't queue stop
			break;
		}
		struct xdp_desc* txd = xsk_ring_prod__tx_desc(&x->tx, tx_idx);
		txd->addr = frame;
		txd->len = hdr_len + seg_len;
		xsk_ring_prod__submit(&x->tx, 1);
		sent += seg_len;
	}
	// Stage 8 wakeup + Stage 9 completion drain, then:
	//if (xsk_ring_prod__needs_wakeup(&x->tx)) 
	if (sent > 0)
		sendto(xsk_socket__fd(x->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	complete_tx(x);

	// Never drop the rest of a batch: whatever didn't fit in XSK TX goes out
	// through the kernel socket (same fd, same 4-tuple), keeping GSO.
	if (off < payload_len) {
		x->tx_fallback_pkts += (payload_len - off + seg_size - 1) / seg_size;
		XLOG_EVERY_MS(WARNING, 1000) << "XSK TX full, kernel fallback segments so far="
		                             << x->tx_fallback_pkts
		                             << " tx_free=" << x->tx_free.size();
		struct iovec rest = {(uint8_t*)vec[0].iov_base + off, payload_len - off};
		ssize_t r = folly::AsyncUDPSocket::writev(address, &rest, 1, options);
		if (r < 0) return sent > 0 ? (ssize_t)sent : r;
		sent += r;
	}
	return sent;
}

}