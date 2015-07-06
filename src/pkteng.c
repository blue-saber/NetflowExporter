#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkteng.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

#define MAX_PACKET_ENGINE_NUM	10

static struct _pkteng_list {
	char		*signature;
	PKTENG		*implementation;
	int		refcnt;
} pkteng_list[MAX_PACKET_ENGINE_NUM];

static int	pkteng_idx = 0;
char		*PKTENG_err = NULL;

int PKTENG_regist_implementation (const char *sign, PKTENG *imp) {
	int	i;

	for (i = 0; i < pkteng_idx; i++) {
		if (strcmp (pkteng_list[i].signature, sign) == 0) {
			PKTENG_err = "signature already exists";
			return -1;
		}
	}

	if (i >= MAX_PACKET_ENGINE_NUM - 1) {
		PKTENG_err = "no space for new implementation";
		return -1;
	}

	pkteng_list[i].signature      = strdup (sign);
	pkteng_list[i].implementation = imp;
	pkteng_list[i].refcnt         = 0;
	pkteng_idx++;

	return i;
}

PKTENG* PKTENG_request_implementation (const char *sign) {
	PKTENG	*png = NULL;
	int	i;
	int	found = 0;

	if (sign == NULL) {
		for (i = 0; i < pkteng_idx; i++) {
			if (pkteng_list[i].refcnt == 0) {
				found = 1;
				break;
			}
		}
	} else {
		for (i = 0; i < pkteng_idx; i++) {
			if (strcmp (pkteng_list[i].signature, sign) == 0) {
				found = 1;
				break;
			}
		}
	}

	if (found) {
		png = pkteng_list[i].implementation;
		pkteng_list[i].refcnt++;
	}

	return png;
}

void PKTENG_init_packet_engine (void) {
#ifdef linux
	init_pkteng_linux_pf_packet ();
	// init_pkteng_linux_socket_packet ();
#endif
#if HAVE_BPF == 1
	init_pkteng_bpf ();
#endif
#if (HAVE_LIBPCAP == 1) && (HAVE_PCAP_H == 1)
	init_pkteng_pcap ();
#endif
}
