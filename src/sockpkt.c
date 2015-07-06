/*
 *	sockpkt.c
 *
 *	Copyright (C) 2001 Jiann-Ching Liu
 *
 *	Linux socket packet interface for packet engine
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
#include "pkteng.h"
#include "pktbuf.h"

#define MAX_PACKET_LEN	2000

static int		sockfd = -1;
static PKTENG 		func_pointer;
static int		pflag = 0;		// promiscuous flag
static int		pkteng_id = -1;
static char		*ebuf = NULL;
static char		*device = NULL;
static u_int64_t	pkts_received   = 0;
static u_int64_t	pkts_dropped    = 0;
static u_int64_t	octets_received = 0;
static u_int64_t	octets_dropped  = 0;
static struct packet_buffer_t	full_packet;


static struct packet_buffer_t *getbuffer (void) { return &full_packet; }
static struct packet_buffer	local_pktbuf;
static struct packet_buffer	*pkbeng = &local_pktbuf;

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

static int go_promiscuous (const int flag)
{
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
}

static int promiscuous (const int flag) {
	pflag = (flag != 0) ? 1 : 0;
	return 1;
}

static int open_packet_engine (void) {
	if ((sockfd = socket (AF_INET, SOCK_PACKET, htons (ETH_P_ALL))) < 0) {
		ebuf = strerror (errno);
		return 0;
	}

	if (device != NULL) {
		struct sockaddr		sa;

		memset (&sa, 0, sizeof(sa));
		sa.sa_family = AF_INET;
								                		strncpy (sa.sa_data, device, sizeof (sa.sa_data));

		if (bind (sockfd, &sa, sizeof (sa))) {
			close (sockfd);
			sockfd = -1;
			ebuf = strerror (errno);
			return 0;
		}

		fprintf (stderr, "listen on %s (sock packet) [obsolete]\n",
				device);
	} else {
		fprintf (stderr,
			"listen on all interfaces (sock packet) [obsolete]\n");
	}

	go_promiscuous (pflag);

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

	while (! *term) {
		from_len = sizeof from;

		if ((pbf = pkbeng->request ()) != NULL) {
			pbf->len = recvfrom (sockfd, pbf->buffer,
					MAX_PACKET_LEN, 0, &from, &from_len);
			// pbf->buffer_ready = 1;
			pkbeng->ready (pbf);
			pkts_received++; octets_received += pbf->len;
			callback (pbf->buffer, pbf->len);
		} else {
			len = recvfrom (sockfd, full_packet.buffer,
				MAX_PACKET_LEN, 0, &from, &from_len);
			pkts_received ++; octets_received += len;
			pkts_dropped  ++; octets_dropped  += len;
		}
	}
	return 1;
}

static char *error (void) { return ebuf; }

static char *driver_version (void) {
	static char	*dv = "linux socket packet";
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

int init_pkteng_linux_socket_packet (void) {
	local_pktbuf.request = &getbuffer;

	PKTENG_regist_functions (func_pointer);

	pkteng_id = PKTENG_regist_implementation ("sockpkt", &func_pointer);

	return 1;
}

#endif
