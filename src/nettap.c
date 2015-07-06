/*
 *	nettap.c
 *
 *	Copyright (C) 2001 Jiann-Ching Liu
 */

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "ipnetflow.h"
#include "global_var.h"
#include "ipflowlist.h"
#include "pkteng.h"
#include "hasheng.h"
#include "utils.h"
#include "cmdlintf.h"
#include "cmdfcn.h"

PKTENG		*pkteng = NULL;
static char	*interface = NULL;

static void signal_handler (int signo) {
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		// fprintf (stderr, "set alarm to 30 secord(s)\n");
		alarm (30);
		break;
	case SIGQUIT:
		pthread_kill (all_threads[0], SIGTERM);
		break;
	case SIGALRM:
		pthread_kill (all_threads[0], SIGTERM);
		pthread_exit (NULL);
		break;
	default:
		fprintf (stderr, "receive signal %d\n", signo);
		break;
	}
}

/*
static void wakeup (const u_char *buffer, int len) {
	netflow_wakeup ();
}
*/

int show_packet_engine (struct cmdlintf_t *cli, char *cmd) {
	cli->print ("Packet Engine: %s (%s)\n"
			"\t%llu packets received, %llu packets dropped\n",
			pkteng->driver_version (),
			((interface == NULL) ? "" : interface),
			pkteng->pkt_received (),
			pkteng->pkt_dropped ());
	return 1;
}

void nettap_main (char *args[]) {
	interface = args[1];

	if (interface == NULL) {
		char	*ebuf = NULL;

		if ((interface = generic_lookupdev (&ebuf)) == NULL) {
			fprintf (stderr, "nettap: %s\n", ebuf);
		}
	}

	PKTENG_init_packet_engine ();

	setsignal (SIGINT , signal_handler);
	setsignal (SIGQUIT, signal_handler);
	setsignal (SIGTERM, signal_handler);
	setsignal (SIGALRM, signal_handler);

	if ((pkteng = PKTENG_request_implementation (args[0])) != NULL) {
		// fprintf (stderr, "using [%s]\n", args[0]);
	} else if ((pkteng = PKTENG_request_implementation (NULL)) != NULL) {
	} else {
		fprintf (stderr, "no available packet engine\n");
		pthread_kill (all_threads[0], SIGTERM);
		pthread_exit (NULL);
	}

	fprintf (logfp, "Packet Engine: %s (%s) [%d]\n",
			pkteng->driver_version (),
			(interface == NULL) ? "" : interface,
			getpid ());
	fflush (logfp);

	pkteng->bind_interface (interface);
	pkteng->promiscuous (1);
	pkteng->set_packet_buffer_engine (pktbf);

	// clip->add ("show packet engine", 1, show_packet_engine, "", 0);

	if (pkteng->open_packet_engine () == 0) {
		fprintf (stderr, "%s\n", pkteng->error());
		pthread_kill (all_threads[0], SIGTERM);
		pthread_exit (NULL);
	} else {
		int	received;
		pkteng->listen_loop (&nettap_terminate, netflow_wakeup);

		fprintf (logfp,
			"Packet Engine: %llu packet(s) received, "
			"%llu packet(s) dropped\n",
			pkteng->pkt_received (), pkteng->pkt_dropped ());

		if ((received = pkteng->drv_received ()) != 0) {
			fprintf (logfp,
				"Kernel: %u (%u) packet(s) received, "
				"%u packet(s) dropped\n",
				pkteng->drv_received (),
				received,
				pkteng->drv_dropped ());
		}

		pkteng->release ();
	}

	fprintf (logfp, "nettap: terminated\n");
	fflush (logfp);

	pthread_exit (NULL);
}
