/*
 *	pcap.c
 *
 *	Copyright (c) 2002, Jiann-Ching Liu
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if (HAVE_LIBPCAP == 1) && (HAVE_PCAP_H == 1)

#include <pcap.h>
#include <string.h>
#include "pkteng.h"
#include "pktbuf.h"

static PKTENG 	func_pointer;
static int	pflag = 0;		// promiscuous flag
// static int	snaplen = 1518;		// Ethernet MTU
static int	snaplen = MIN_PACKET_LEN;
static pcap_t	*pd = NULL;
static int	pkteng_id = -1;
static char 	*device = NULL;
static char	ebuf [PCAP_ERRBUF_SIZE] = "";
static u_char	*pcap_userdata = NULL;
static void	netflow_dummy_analyzer (const u_char *p, int l) {}
static void 	(*netflow_analyzer)(const u_char *, int)
					= netflow_dummy_analyzer;

static u_int64_t		pkts_received   = 0;
static u_int64_t		pkts_dropped    = 0;
static u_int64_t		octets_received = 0;
static u_int64_t		octets_dropped  = 0;
static struct packet_buffer	*pkbeng = NULL;
struct packet_buffer_t		*pbf;


static u_int64_t pkt_received   (void) { return pkts_received;   }
static u_int64_t pkt_dropped    (void) { return pkts_dropped;    }
static u_int64_t octet_received (void) { return octets_received; }
static u_int64_t octet_dropped  (void) { return octets_dropped;  }

static u_int32_t drv_received	(void) {
	struct pcap_stat stat;

	if (pcap_stats (pd, &stat) < 0) return 0;
	return stat.ps_recv;
}

static u_int32_t drv_dropped	(void) {
	struct pcap_stat stat;

	if (pcap_stats (pd, &stat) < 0) return 0;
	return stat.ps_drop;
}

static int set_packet_buffer_engine (struct packet_buffer *pe) {
	pkbeng = pe;
        return 1;
}

static void
packet_capture (u_char* user, const struct pcap_pkthdr* h, const u_char* p) {
	// netflow_analyzer (p, h->len);
	if ((pbf = pkbeng->request ()) != NULL) {
		pbf->len = h->len;
		memcpy (pbf->pktbuff, p, h->caplen);
		// pbf->buffer_ready = 1;
		pkbeng->ready (pbf);
		pkts_received++;
		octets_received += h->len;

		netflow_analyzer (pbf->pktbuff, pbf->len);
	} else {
		pkts_received++;
		octets_received += h->len;

		pkts_dropped++;
		octets_dropped += h->len;
	}
}


static int promiscuous (const int flag) {
	// pd = pcap_open_live(device, snaplen, !pflag, 1000, ebuf);
	pflag = (flag != 0) ? 1 : 0;
	return 1;
}

static int bind_interface (char *interface) {
	device = interface;
	return 1;
}

static char *error (void) { return ebuf; }

static char *driver_version (void) {
	static char	*dv = "pcap";
	return dv;
}

static int release (void) {
	if (pd != NULL) {
		/*
		struct pcap_stat	stat;

		if (pcap_stats(pd, &stat) < 0) {
			fprintf (stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		} else {
			fprintf (stderr, "%d packets received by filter\n",
						stat.ps_recv);
			fprintf (stderr, "%d packets dropped by kernel\n",
						stat.ps_drop);
		}
		*/
		pcap_close (pd);
		pd = NULL;
	}
	return 1;
}

static int listen_loop (volatile int *term,
				void (*callback)(const u_char *, int)) {
	netflow_analyzer = callback;

	while (! *term) {
		if (pcap_loop (pd, 1, packet_capture, pcap_userdata) < 0) {
			fprintf (stderr, "pcap_loop: %s\n", pcap_geterr (pd));
			return 0;
		}
	}

	return 1;
}

static int open_packet_engine (void) {
	int			i;
	struct bpf_program	fcode;
	char			*cmdbuf = NULL;
	bpf_u_int32		localnet, netmask;
	const int		Oflag = 1;	// run filter code optimizer

	if (device == NULL) {
		if ((device = pcap_lookupdev (ebuf)) == NULL) {
			return 0;
		}
	}


	pd = pcap_open_live (device, snaplen, pflag, 1000, ebuf);

	if (pd == NULL) { return 0; }

	fprintf (stderr, "listening on %s (pcap)\n", device);
		//	pcap_major_version (pd),
		//	pcap_minor_version (pd));

	if ((i = pcap_snapshot (pd)) > snaplen) {
		fprintf(stderr, "snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}

	if (pcap_lookupnet (device, &localnet, &netmask, ebuf) < 0) {
		localnet = netmask = 0;
		// fprintf (stderr, "%s", ebuf);
		return 0;
	}

	if (pcap_compile (pd, &fcode, cmdbuf, Oflag, netmask) < 0) {
		fprintf (stderr, "%s", pcap_geterr (pd));
		return 0;
	}

	// printer = lookup_printer (pcap_datalink (pd));
	

	return 1;
}


static int clear_counter (void) {
	pkts_received = pkts_dropped = 0;
	octets_received = octets_dropped = 0;
	return 0;
}

///////////////////////////////////////////////////////////////////////////

int init_pkteng_pcap (void) {
	PKTENG_regist_functions (func_pointer);

	pkteng_id = PKTENG_regist_implementation ("pcap", &func_pointer);

	return 1;
}

#endif
