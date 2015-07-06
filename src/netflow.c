/*
 *	netflow.c
 *
 *	Copyright (C) 2001-2004 Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#include <sys/types.h>
#include <sys/time.h>
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
#include "pktbuf.h"
#include "hasheng.h"
#include "utils.h"
#include "netflow_cache.h"

#ifdef DEBUG
#include <arpa/inet.h>
#endif
// #include <arpa/inet.h>

#define ICMP_TRICK

#ifdef ICMP_TRICK
// #include <netinet/ip_icmp.h>
#endif

// static u_int16_t		ethtype;
static u_int16_t		ethertype_ip;
// static struct ether_header	*ethhdr;
static volatile int		in_sleep = 0;
static volatile int		cache_in_sleep = 0;
static pthread_t		local_thread;
static pthread_t		local_cache_thread;
static const int		header_len = sizeof (struct ip)
					+ sizeof (struct ether_header);
static pthread_mutex_t		wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t		wait_condi = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t		wait_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t		wait_cache_condi = PTHREAD_COND_INITIALIZER;
// static u_int32_t		packet_len[MAX_NETFLOW_THREAD];
// static u_int8_t  		tcp_flags[MAX_NETFLOW_THREAD];

struct ip_hdr {
	u_int8_t	ip_vhl;         /* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct in_addr	ip_src,ip_dst;  /* source and dest address */
};

struct tcp_header {
	u_int16_t	source;
	u_int16_t	dest;
	u_int32_t	seq;
	u_int32_t	ack_seq;
	u_int8_t	offset;
	u_int8_t	flags;
	u_int16_t	window;
	u_int16_t	check;
	u_int16_t	urg_ptr;
}  __attribute__ ((__packed__));

struct icmp_header {
	u_int8_t	icmp_type;
	u_int8_t	icmp_code;
}  __attribute__ ((__packed__));

static void signal_handler (int signo) {
	switch (signo) {
	case SIGTERM:
	case SIGINT:
		netflow_wakeup (NULL, 0);
		netflow_cache_wakeup ();
		// fprintf (stderr, "Alarm for 10 seconds\n");
		alarm (10);
		break;
	case SIGQUIT:
		netflow_wakeup (NULL, 0);
		netflow_cache_wakeup ();
		// fprintf (stderr, "Receive SIGQUIT (netflow)\n");
		pthread_kill (all_threads[0], SIGTERM);
		break;
	case SIGUSR1:
		// pthread_kill (all_threads[0], SIGTERM);
		// pthread_exit (NULL);
		break;
	case SIGALRM:
		netflow_wakeup (NULL, 0);
		netflow_cache_wakeup ();
		// fprintf (stderr, "signal Alarm\n");
		pthread_kill (local_thread, SIGUSR1);
		pthread_kill (local_cache_thread, SIGUSR1);
		pthread_kill (all_threads[0], SIGTERM);
		break;
	default:
		// fprintf (stderr, "receive signal %d\n", signo);
		break;
	}
}


static void netflow_callback (const int first,
			struct netflow_data *ptr, const int packet_len) {
	if (first) gettimeofday (&ptr->first, (struct timezone *) 0);

	// fprintf (stderr, "packet length = %u\n", packet_len);
	ptr->pkts ++;
	ptr->octets += packet_len;
	// [FIXME] I don't know how to handle this ....
	// ptr->flags  |= tcp_flags[my_id];
	gettimeofday (&ptr->last, (struct timezone *) 0);
}

static inline void analyze_ip_header (struct ip * ip, const int len) {
//	u_int16_t		src_port, dst_port;
	struct netflow_key	key;
	struct netflow_key	*kptr = &key;
	struct tcp_header	*tcp = 
			(struct tcp_header *)((u_char *) ip + ip->ip_hl * 4);
#if ENABLE_FLOW_CACHE_BUFFER == 1
	struct netflow_cache_data_t	*ptr;
#endif
	//unsigned int		hlen, off;
#ifdef ICMP_TRICK
	struct icmp_header	*icmp = (void *) tcp;
#endif
//	struct tcphdr		*tcp =
//			(struct tcphdr *)(((u_char *) ip) + ip->ip_hl * 4);
	/*
	 * If this is fragment zero, hand it to the next higher
	 * level protocol.
	 */
	// off = ntohs (ip->ip_off);
	// hlen = IP_HL(ip) * 4;

	/*
	if ((off & 0x1fff) == 0) {
	} else {
	}
	*/

#if ENABLE_FLOW_CACHE_BUFFER == 1
	while ((ptr = nfcb->request ()) == NULL) {
		// fprintf (stderr, "sorry !!\n");
		netflow_cache_wakeup ();
		usleep (1);
		if (terminate) return;
	}

	kptr = &ptr->key;
	ptr->len = len;
#endif

	kptr->src_ip   = ip->ip_src.s_addr;
	kptr->dst_ip   = ip->ip_dst.s_addr;
	kptr->prot     = ip->ip_p;

	// packet_len   = ip->ip_len;
	// packet_len = len - header_len;
	//packet_len[my_id] = len;
	// tcp_flags  = 0;
	// packet_len   = 1;


	if (ip->ip_p == IPPROTO_TCP) {
		// src_port = ntohs (tcp->source);
		// dst_port = ntohs (tcp->dest);
		//	src_port = ntohs (tcp->th_sport);
		//	dst_port = ntohs (tcp->th_dport);
		kptr->src_port = tcp->source;
		kptr->dst_port = tcp->dest;
		// tcp_flags    = tcp->flags;
	} else if (ip->ip_p == IPPROTO_UDP) {
		// src_port = ntohs (tcp->source);
		// dst_port = ntohs (tcp->dest);
		kptr->src_port = tcp->source;
		kptr->dst_port = tcp->dest;
#ifdef ICMP_TRICK
	} else if (ip->ip_p == IPPROTO_ICMP) {
		kptr->src_port = htons (icmp->icmp_type);
		kptr->dst_port = htons (icmp->icmp_code);
#endif
	} else {
		kptr->src_port = kptr->dst_port = 0;
		// src_port = 0;
		// dst_port = 0;
		// return;
	}

	//	key.src_port = src_port;
	//	key.dst_port = dst_port;

//	if (nflp->setentry (&key, &netflow_callback) < 0) {
//		// fprintf (stderr, "no free space on netflow buffer\n");
//		return;
//	}

#ifdef DEBUG
	if (debug_level > 0) {
		struct in_addr	srcip, dstip; 

		srcip.s_addr = key.src_ip;
		dstip.s_addr = key.dst_ip;

		fprintf (stderr,
			"[%02d]%s:%d -> ",
			key.prot,
			inet_ntoa (srcip),
			key.src_port);

		fprintf (stderr, "%s:%d\n",
			inet_ntoa (dstip),
			key.dst_port);
	}
#endif

#if ENABLE_FLOW_CACHE_BUFFER == 1
	// nfcb->push (&key, packet_len[my_id]);
	nfcb->ready (ptr);
	netflow_cache_wakeup ();
	// fprintf (stderr, "netflow_cache_wakeup\n");
#else
	nflp->setentry (kptr, &netflow_callback, len);
#endif

	/*
	if ((result = nflp->gethash (&key, &nfed)) == -1) {
		// fprintf (stderr, "no free space on netflow buffer\n");
		return;
	} else if (result == 0) {
		nfed->first = time (NULL);
	}

	nfed->pkts ++;
	nfed->octets += len;
	nfed->last   =  time (NULL);
	*/
}


static inline void analyze_protocol (const u_char *buffer, int len) {
	struct ether_header	*ethhdr;

	ethhdr  = (struct ether_header *) buffer;
	// ethtype = ntohs (ethhdr->ether_type);


	// if (ethtype == ETHERTYPE_IP) {
	if (ethertype_ip == ethhdr->ether_type) {
		analyze_ip_header (
			(struct ip *) (buffer + sizeof (struct ether_header)),
			len - 14);
		// 6 + 6 + 2
	}
}


void netflow_wakeup (const u_char *pkt, const int len) {
	// if (in_sleep) pthread_kill (local_thread, SIGUSR1);
	if (in_sleep > 0) {
		// fprintf (stderr, "wake up %d\n", in_sleep);
		pthread_mutex_lock   (&wait_mutex);
		pthread_cond_signal  (&wait_condi);
		pthread_mutex_unlock (&wait_mutex);
	}
}

void netflow_cache_wakeup (void) {
	// if (in_sleep) pthread_kill (local_thread, SIGUSR1);
	if (cache_in_sleep > 0) {
		pthread_mutex_lock   (&wait_cache_mutex);
		pthread_cond_signal  (&wait_cache_condi);
		pthread_mutex_unlock (&wait_cache_mutex);
	}
}

void * netflow_main (void *args) {
	struct packet_buffer_t	*ptr;
	sigset_t		sigs;
	int			my_id = *((int *) args);
	// int				signo;

	// pthread_mutex_init (&wait_mutex, NULL);
	// pthread_cond_init  (&wait_condi, NULL);

	fprintf (logfp, "Netflow Thread #%d started [%d]\n", my_id, getpid ());
	fflush (logfp);

	///////////////////////////////////////////////////////////
	//

	ethertype_ip = htons (ETHERTYPE_IP);

	setsignal (SIGINT,  signal_handler);
	setsignal (SIGQUIT, signal_handler);
	setsignal (SIGTERM, signal_handler);
	setsignal (SIGALRM, signal_handler);

	sigemptyset (&sigs);
//	sigaddset   (&sigs, SIGINT);
	sigaddset   (&sigs, SIGUSR1);
//	sigaddset   (&sigs, SIGQUIT);
	sigaddset   (&sigs, SIGALRM);
	sigaddset   (&sigs, SIGTERM);
	local_thread = pthread_self ();


	// pthread_exit (NULL);

	while (! terminate) {
		while ((ptr = pktbf->retrieve ()) != NULL) {
#ifdef DEBUG
			if (debug_level > 0) {
				fprintf (stderr, "Packet retrieved\n");
			}
#endif
			analyze_protocol (ptr->pktbuff, ptr->len);
			pktbf->dequeue (ptr);
		}
#ifdef DEBUG
		if (debug_level > 0) fprintf (stderr, "No data to retrieve\n");
		// fprintf (stderr, "No data to retrieve\n");
#endif
		// sigwait (&sigs, &signo);
		pthread_mutex_lock   (&wait_mutex);
		in_sleep++;
		pthread_cond_wait    (&wait_condi, &wait_mutex);
		in_sleep--;
		// pthread_cond_signal  (&wait_condi);
		pthread_mutex_unlock (&wait_mutex);
	}

	while ((ptr = pktbf->retrieve ()) != NULL) {
		// analyze_protocol (ptr->buffer, ptr->len, my_id);
		pktbf->dequeue (ptr);
	}

	// netflow_wakeup (NULL, 0);

	fprintf (logfp, "Netflow Thread #%d ended\n", my_id);
	fflush (logfp);

	pthread_exit (NULL);
}

void * netflow_cache_main (void *args) {
	struct netflow_cache_data_t	*ptr;
	sigset_t			sigs;
	// int				my_id = *((int *) args);
	// int				signo;

	// pthread_mutex_init (&wait_mutex, NULL);
	// pthread_cond_init  (&wait_condi, NULL);

	fprintf (logfp, "Netflow Cache Thread started [%d]\n", getpid ());
	fflush (logfp);

	///////////////////////////////////////////////////////////
	//

	setsignal (SIGINT,  signal_handler);
	setsignal (SIGQUIT, signal_handler);
	setsignal (SIGTERM, signal_handler);
	setsignal (SIGALRM, signal_handler);

	sigemptyset (&sigs);
//	sigaddset   (&sigs, SIGINT);
	sigaddset   (&sigs, SIGUSR1);
//	sigaddset   (&sigs, SIGQUIT);
	sigaddset   (&sigs, SIGALRM);
	sigaddset   (&sigs, SIGTERM);
	local_cache_thread = pthread_self ();


	// pthread_exit (NULL);

#if ENABLE_MONITOR_NETFLOW_CACHE == 1
	netflow_cache_state = 1;
#endif

	while (! terminate) {
		while ((ptr = nfcb->retrieve ()) != NULL) {
#ifdef DEBUG
			if (debug_level > 0) {
				fprintf (stderr, "Packet retrieved\n");
			}
#endif

#if ENABLE_MONITOR_NETFLOW_CACHE == 1
			netflow_cache_state = 2;
#endif
			nflp->setentry (&ptr->key,
					&netflow_callback, ptr->len);
			// analyze_protocol (ptr->buffer, ptr->len, my_id);
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
			netflow_cache_state = 3;
#endif
			nfcb->dequeue (ptr);
		}
#ifdef DEBUG
		if (debug_level > 0) fprintf (stderr, "No data to retrieve\n");
		// fprintf (stderr, "No data to retrieve\n");
#endif
		// sigwait (&sigs, &signo);
		pthread_mutex_lock   (&wait_cache_mutex);
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
		netflow_cache_state = 4;
#endif
		cache_in_sleep++;
		pthread_cond_wait    (&wait_cache_condi, &wait_cache_mutex);
		cache_in_sleep--;
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
		netflow_cache_state = 5;
#endif
		pthread_mutex_unlock (&wait_cache_mutex);
	}

#if ENABLE_MONITOR_NETFLOW_CACHE == 1
	netflow_cache_state = 6;
#endif

	while ((ptr = nfcb->retrieve ()) != NULL) {
		// analyze_protocol (ptr->buffer, ptr->len, my_id);
		nfcb->dequeue (ptr);
	}

	// netflow_cache_wakeup ();
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
	netflow_cache_state = 7;
#endif

	fprintf (logfp, "Netflow Cache Thread ended\n");
	fflush (logfp);

	pthread_exit (NULL);
}
