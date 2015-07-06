/*
 *	bpf.c
 *
 *	Copyright (C) 2001 Jiann-Ching Liu
 *
 *	BSD packet filter interface for packet engine
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if (HAVE_BPF == 1) || defined (__FreeBSD__)

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <errno.h>
#include "global_var.h"
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
static int		bufsize = 0;
static char		*buffer = NULL;


static struct packet_buffer_t	*getbuffer (void) { return &full_packet; }
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

static u_int32_t drv_received (void) {
        struct bpf_stat s;

        if (ioctl (sockfd, BIOCGSTATS, (caddr_t) &s) < 0) return 0;

	return s.bs_recv;
}

static u_int32_t drv_dropped (void) {
        struct bpf_stat s;

        if (ioctl (sockfd, BIOCGSTATS, (caddr_t) &s) < 0) return 0;

	return s.bs_drop;
}

static int go_promiscuous (const int flag) {
	if (flag) {
		ioctl (sockfd, BIOCPROMISC, NULL);
	}
	return -1;
}

static int promiscuous (const int flag) {
	pflag = (flag != 0) ? 1 : 0;
	return 1;
}

static int open_packet_engine (void) {
	int			n = 0;
	int			to_ms = 0;	// timeout
	u_int			v;	
	char			bpfdevice[sizeof "/dev/bpf0000000000"];
	struct ifreq		ifr;	
	struct bpf_version	bv;

	do {
		snprintf (bpfdevice, sizeof(bpfdevice), "/dev/bpf%d", n++);
		sockfd = open (bpfdevice, O_RDONLY);
	} while ((sockfd < 0) && (errno == EBUSY));

	if (sockfd < 0) {
		ebuf = "no devices found";
		return 0;
	}

	if (ioctl (sockfd, BIOCVERSION, (caddr_t) &bv) < 0) {
		ebuf = strerror (errno);
		close (sockfd);
		return 0;
	}

	if (device == NULL) {
		device = generic_lookupdev (&ebuf);
	}

	if ((bv.bv_major != BPF_MAJOR_VERSION) ||
	    (bv.bv_minor <  BPF_MINOR_VERSION)) {
		ebuf = "kernel bpf filter out of date";
		close (sockfd);
		return 0;
	}

	/*
	 * Try finding a good size for the buffer; 32768 may be too
	 * big, so keep cutting it in half until we find a size
	 * that works, or run out of sizes to try.
	 *
	 * XXX - there should be a user-accessible hook to set the
	 * initial buffer size.
	 */

	// fprintf (stderr, "DEVICE=%s\n", device);

	for (v = 32768; v != 0; v >>= 1) {
		/* Ignore the return value - this is because the call fails
		 * on BPF systems that don't have kernel malloc.  And if
		 * the call fails, it's no big deal, we just continue to
		 * use the standard buffer size.
		 */
		ioctl (sockfd, BIOCSBLEN, (caddr_t)&v);

		strncpy (ifr.ifr_name, device, sizeof (ifr.ifr_name));

		if (ioctl (sockfd, BIOCSETIF, (caddr_t) &ifr) >= 0)
			break;	/* that size worked; we're done */

		if (errno != ENOBUFS) {
			fprintf (stderr, "Some Error: ");
			ebuf = strerror (errno);
			close (sockfd);
			return 0;
		}
	}

	if (v == 0) {
		ebuf = strerror (errno);
		close (sockfd);
		return 0;
	}

	if ((buffer = malloc (bufsize = v)) == NULL) {
		ebuf = strerror (errno);
		close (sockfd);
		return 0;
	}

	/* Get the data link layer type. */
	if (ioctl (sockfd, BIOCGDLT, (caddr_t) &v) < 0) {
		fprintf (stderr, "Get the datalink layer type :");
		ebuf = strerror (errno);
		close (sockfd);
		return 0;
	}

	/* set timeout */
	if (to_ms != 0) {
		struct timeval to;

		to.tv_sec = to_ms / 1000;
		to.tv_usec = (to_ms * 1000) % 1000000;
		if (ioctl (sockfd, BIOCSRTIMEOUT, (caddr_t)&to) < 0) {
			ebuf = strerror (errno);
			close (sockfd);
			return 0;
		}
	}

	go_promiscuous (pflag);

	if (ioctl (sockfd, BIOCGBLEN, (caddr_t)&v) < 0) {
		fprintf (stderr, "Get BIOCGBLEN");
		ebuf = strerror (errno);
		close (sockfd);
		return 0;
	}

	fprintf (logfp, "listen on %s (%s) [ kernel %d.%d, driver %d.%d ]\n",
			device, bpfdevice,
			bv.bv_major, bv.bv_minor,
			BPF_MAJOR_VERSION, BPF_MINOR_VERSION);

	// -------


	return 1;
}

static int bind_interface (char *interface) {
	device = interface;
	return 1;
}

static int listen_loop (volatile int *term,
				void (*callback)(const u_char *, const int)) {
	struct packet_buffer_t	*pbf;
	int			len;
	int			caplen, hdrlen;
	u_char			*bp = NULL, *ep;
	int			cc;

	while (! *term) {
		if ((cc = read (sockfd, buffer, bufsize)) < 0) {
			if (errno == EINTR) continue;
			fprintf (stderr, "bpf: %s\n", strerror (errno));
			*term = 1;
			break;
		}

		bp = buffer;
		ep = bp + cc;

		while (bp < ep) {
			caplen = ((struct bpf_hdr *)bp)->bh_caplen;
			hdrlen = ((struct bpf_hdr *)bp)->bh_hdrlen;
			len    = ((struct bpf_hdr *)bp)->bh_datalen;

			if ((pbf = pkbeng->request ()) != NULL) {
				pkts_received++;
				octets_received += len;
				pbf->len = len;
				// memcpy (pbf->buffer, bp + hdrlen, caplen);
				memcpy (pbf->pktbuff,
					bp + hdrlen, sizeof pbf->pktbuff);
				// pbf->buffer_ready = 1;
				pkbeng->ready (pbf);
				callback (pbf->pktbuff, pbf->len);
			} else {
				pkts_received++;
				octets_received += len;
				pkts_dropped++;
				octets_dropped  += len;
			}

			bp += BPF_WORDALIGN(caplen + hdrlen);
		}
	}
	return 1;
}

static char *error (void) { return ebuf; }

static char *driver_version (void) {
	static char	*dv = "BSD Packet Filter";
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

int init_pkteng_bpf (void) {
	local_pktbuf.request = &getbuffer;

	PKTENG_regist_functions (func_pointer);

	pkteng_id = PKTENG_regist_implementation ("bpf", &func_pointer);

	return 1;
}

#endif
