/*
 *	pfpacket.c
 *
 *	Copyright (C) 2001 Jiann-Ching Liu
 *
 *	Linux PF_PACKET interface for packet engine
 */

#ifdef linux

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <errno.h>
#include <netpacket/packet.h>
#include "pkteng.h"
#include "pktbuf.h"

#ifndef MSG_TRUNC
/*
 * This is being compiled on a system that lacks MSG_TRUNC; define it
 * with the value it has in the 2.2 and later kernels, so that, on
 * those kernels, when we pass it in the flags argument to "recvfrom()"
 * we're passing the right value and thus get the MSG_TRUNC behavior
 * we want.  (We don't get that behavior on 2.0[.x] kernels, because
 * they didn't support MSG_TRUNC.)
 */
// #define MSG_TRUNC       0x20
#endif

#define MAX_PACKET_LEN	2000

static int		sockfd = -1;
static PKTENG 		func_pointer;
static int		pflag = 0;		// promiscuous flag
static int		pkteng_id = -1;
static char		*ebuf = NULL;
static char		*device = NULL;
static int		device_id = -1;
static u_int64_t	pkts_received   = 0;
static u_int64_t	pkts_dropped    = 0;
static u_int64_t	octets_received = 0;
static u_int64_t	octets_dropped  = 0;
static struct packet_buffer_t	full_packet;


static struct packet_buffer_t *getbuffer (void) { return &full_packet; }
static struct packet_buffer	local_pktbuf;
static struct packet_buffer	*pkbeng = &local_pktbuf;



static int
iface_get_id(int fd, const char *device) {
	struct ifreq    ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl (fd, SIOCGIFINDEX, &ifr) == -1) {
		ebuf = strerror (errno);
		return -1;
	}

	return ifr.ifr_ifindex;
}

static int
iface_bind (int fd, int ifindex) {
	struct sockaddr_ll	sll;

	memset (&sll, 0, sizeof (sll));

	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	// sll.sll_protocol	= htons (ETH_P_ALL);
	sll.sll_protocol	= htons (ETH_P_IP);

	if (bind (fd, (struct sockaddr *) &sll, sizeof (sll)) < 0) {
		ebuf = strerror (errno);
		return -1;
	}

	return 0;
}

static int set_packet_buffer_engine (struct packet_buffer *pe) {
	pkbeng = pe;
	return 1;
}

static u_int64_t pkt_received   (void) { return pkts_received;   }
static u_int64_t pkt_dropped    (void) { return pkts_dropped;    }
static u_int64_t octet_received (void) { return octets_received; }
static u_int64_t octet_dropped  (void) { return octets_dropped;  }
static u_int32_t drv_received	(void) { return 0; }
static u_int32_t drv_dropped	(void) { return 0; }

static int go_promiscuous (const int flag) {
	if (device) {
#ifdef SOL_PACKET		
		/*
		 * Hmm, how can we set promiscuous mode on all interfaces?
		 * I am not sure if that is possible at all.
		 */

		struct packet_mreq	mr;

		memset (&mr, 0, sizeof(mr));
		mr.mr_ifindex = device_id;
		mr.mr_type    = flag ?  PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;

		if (setsockopt (sockfd, SOL_PACKET,
				PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
			ebuf = strerror (errno);
			return -1;
		}
#else
		struct ifreq if_data;

		if (device == NULL) return -1;

		strcpy(if_data.ifr_name, device);

		if (ioctl (sockfd, SIOCGIFFLAGS, &if_data) < 0) return -1;

		if (flag) {
			if_data.ifr_flags |= IFF_PROMISC;
		} else {
			if_data.ifr_flags &= ~IFF_PROMISC;
		}

		if (ioctl(sockfd, SIOCSIFFLAGS, &if_data) < 0) return -1;

		return 0;
#endif
	}
	return -1;
}

static int promiscuous (const int flag) {
	pflag = (flag != 0) ? 1 : 0;
	return 1;
}

static int open_packet_engine (void) {
	int	sock_type;

	sock_type = (device == NULL) ? SOCK_DGRAM : SOCK_RAW;

	do {
		if ((sockfd = socket (PF_PACKET, sock_type,
						htons (ETH_P_IP))) < 0) {
						// htons (ETH_P_ALL))) < 0) {
			ebuf = strerror (errno);
			break;
		}


		if (device != NULL) {
			if ((device_id = iface_get_id (sockfd, device)) < 0)
				break;
			if (iface_bind (sockfd, device_id) < 0) break;
		} else {
		}
	} while (sockfd < 0);

	if (sockfd < 0) return 0;

	// -------

	go_promiscuous (pflag);

	if (device != NULL) {
		fprintf (stderr, "listen on %s (pf_packet)\n", device);
	} else {
		fprintf (stderr, "listen on all interfaces (pf_packet)\n");
	}

	return 1;
}

static int bind_interface (char *interface) {
	device = interface;
	return 1;
}

static int listen_loop (volatile int *term,
				void (*callback)(const u_char *, const int)) {
	int			from_len, len;
	struct sockaddr		from;
	struct packet_buffer_t	*pbf;
	int			rcvflag = 0;

	rcvflag = MSG_TRUNC;

	while (! *term) {
		from_len = sizeof from;

		if ((pbf = pkbeng->request ()) != NULL) {
			pbf->len = recvfrom (sockfd, pbf->pktbuff,
				MIN_PACKET_LEN, rcvflag, &from, &from_len);
				// MAX_PACKET_LEN, rcvflag, &from, &from_len);
			// pbf->buffer_ready = 1;
			pkbeng->ready (pbf);
			pkts_received++; octets_received += pbf->len;
			// callback to wake up waiting thread
			callback (pbf->pktbuff, pbf->len);
		} else {
			len = recvfrom (sockfd, full_packet.pktbuff,
				MIN_PACKET_LEN, rcvflag, &from, &from_len);
			pkts_received ++; octets_received += len;
			pkts_dropped  ++; octets_dropped  += len;

			callback (NULL, 0);
		}
	}
	return 1;
}

static char *error (void) { return ebuf; }

static char *driver_version (void) {
	static char	*dv = "linux pf_packet";
	return dv;
}

static int release (void) {
	if (sockfd >= 0) {
		go_promiscuous (0);
		close (sockfd);
		sockfd = -1;
	}

	return 1;
}

static int clear_counter (void) {
	pkts_received = pkts_dropped = 0;
	octets_received = octets_dropped = 0;

	return 1;
}

int init_pkteng_linux_pf_packet (void) {
	local_pktbuf.request = &getbuffer;

	PKTENG_regist_functions (func_pointer);

	pkteng_id = PKTENG_regist_implementation ("pf_packet", &func_pointer);

	return 1;
}

#endif
