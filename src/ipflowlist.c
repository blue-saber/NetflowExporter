/*
 * 	ipflowlist.c
 *
 * 	Copyright (C) 2001, Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>
#include "ipnetflow.h"
#include "global_var.h"
#include "ipflowlist.h"
#include "netflow_v1.h"
#include "netflow_v5.h"
#include "cmdlintf.h"
#include "pkteng.h"
#include "hasheng.h"
#include "pktbuf.h"
#include "netflow_cache.h"
#include "utils.h"
// #include "setproctitle.h"

#if HAVE_CONFIG_H
#include "config.h"
#endif

// unknow function

#define NETFLOW_V5_ENGINE_TYPE		99
#define NETFLOW_V5_ENGINE_ID		99

#define MSecSUB(x,y) ((x.tv_sec - y.tv_sec) * 1000 + \
					(x.tv_usec - y.tv_usec) / 1000)

struct netflow_entry {
	struct netflow_key	key;
	struct netflow_data	data;
	int			next_free;
	int			expire_prev;	// for inactive connection
	int			expire_next;	// for inactive connection
	int			active_prev;	// for active connection
	int			active_next;	// for active connection
	short			inuse;
	short			valid;
	pthread_mutex_t		mutex;
};


static struct netflow_entry	*netflow_list       =  NULL;
static int			netflow_list_len    =  0;
static int			netflow_free_list   = -1;
static int			netflow_free_count  =  0;
static int			netflow_free_min    =  0;
static pthread_mutex_t		expire_list_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t		freelist_mutex      = PTHREAD_MUTEX_INITIALIZER;

static HASHENG			*iphash = NULL;
static struct netflow_list_t	nflist;
static DBDT			flowkey;
static DBDT			flowdata;
static DBDT			flowdkey;
static int			nf_index;
static unsigned long		concurrent_drop = 0;
static int			sockfd = -1;
static struct sockaddr_in	export_addr;
static netflow_v1_pdu		netflow_v1;
static int			netflow_v1_len;
static int			netflow_v1_hdrlen;
static netflow_v5_pdu		netflow_v5;
static int			netflow_v5_len;
static int			netflow_v5_hdrlen;
static int			netflow_v5_flow_sequence;
static struct timeval		startup_time;
static time_t			startup_timet;
static u_int64_t		active_exports = 0;
static u_int64_t		inactive_exports = 0;
static u_int64_t		exported_datagram = 0;
static unsigned long		failed_datagram = 0;
static unsigned long		bufferfull_cnt = 0;
static int			waitfor_export[NETFLOW_V1_MAXFLOWS];
static int			waitfor_export_idx = 0;


static void signal_handler (int signo) {
	// fprintf (stderr, "Get signal %d\n", signo);
	pthread_kill (all_threads[0], SIGTERM);
}

static int nfl_free_count (void) { return netflow_free_count; }

static int nfl_number_of_netflow (void) {
	return netflow_list_len - netflow_free_count - 1;
}

static inline int request_entry (void) {
	int	retval = 0;


	pthread_mutex_lock (&freelist_mutex);

	if ((retval = netflow_free_list) > 0) {
		netflow_free_list = netflow_list[retval].next_free;
		netflow_free_count--;

		if (netflow_free_min > netflow_free_count) {
			netflow_free_min = netflow_free_count;
		}
		//netflow_free_min = netflow_free_min < netflow_free_count ?
		//			netflow_free_min : netflow_free_count;
	}

	pthread_mutex_unlock (&freelist_mutex);

	if (retval > 0) {
		bzero (&netflow_list[retval], sizeof (struct netflow_entry));
		netflow_list[retval].inuse = 1;
		pthread_mutex_init (&netflow_list[retval].mutex, NULL);
#ifdef DEBUG
	// } else { // if (debug_level > 0) {
	//	fprintf (stderr, "No entry !!\n");
#endif
	}

	return retval;
}

static int get_lock_callback (const int idx) {
	int	retval = 1;

	pthread_mutex_lock   (&netflow_list[idx].mutex);

	if (! netflow_list[idx].inuse) {
		retval = 0;
		pthread_mutex_unlock (&netflow_list[idx].mutex);
	}

	return retval;
	
}

static int del_lock_callback (const int idx) {
	pthread_mutex_lock   (&netflow_list[idx].mutex);
	netflow_list[idx].inuse = 0;

	// pthread_mutex_unlock (&netflow_list[idx].mutex);

	return 1;
}

static int nfl_setentry (struct netflow_key *key,
			void (*callback)(const int, struct netflow_data *fd,
					const int),
			const int packet_len) {
	int			p, n, retval;
	int			pos;
	struct netflow_data	*ptr;
	int			gtst;

	flowkey.data = key;

//	if (iphash->get (iphash, &flowkey, &flowdata, &pos)) {
	if ((gtst = iphash->get (iphash, &flowkey,
					&flowdata, &pos,
					get_lock_callback)) > 0) {
		// 找到原先有 ...
		//
		// fprintf (stderr, "(%d)\r", nf_index);
#if ! HAVE_LIBREADLINE
		// fprintf (stderr, "o\r");
#endif
		ptr = &netflow_list[nf_index].data;
		retval = 0;

		// [FIXME] why not lock? 因為 get_lock_callback 中 lock
		// pthread_mutex_lock   (&netflow_list[nf_index].mutex);
	} else if (gtst == -1) {
		// expire ...
		concurrent_drop++;
		// pthread_mutex_unlock   (&netflow_list[nf_index].mutex);

		return 0;
	} else if ((nf_index = request_entry ()) > 0) {
#if ! HAVE_LIBREADLINE
		// fprintf (stderr, ".");
#endif
		iphash->put (iphash, &flowkey, &flowdata, pos);
		memcpy (&netflow_list[nf_index].key,
				key, sizeof (struct netflow_key));

		ptr = &netflow_list[nf_index].data;
		retval = 1;

		pthread_mutex_lock   (&netflow_list[nf_index].mutex);
	} else {
		// buffer full
#if 0
		if (netflow_free_count == 0) {
			bufferfull_cnt++;
			// fprintf (stderr, "* * * buffer full * * *\n");
		} else {
			fprintf (stderr, "* * * Abnormal buffer full * * *\n");
			// pthread_kill (all_threads[0], SIGTERM);
		}
#endif
		bufferfull_cnt++;

		return -1;
	}

	/////////////////////////////////////////////

	//	pthread_mutex_lock   (&netflow_list[nf_index].mutex);


	if (netflow_list[nf_index].inuse) {
		if (retval == 0) {	// old list
			pthread_mutex_lock   (&expire_list_mutex);

			p = netflow_list[nf_index].expire_prev;
			n = netflow_list[nf_index].expire_next;
			netflow_list[n].expire_prev = p;
			netflow_list[p].expire_next = n;

			pthread_mutex_unlock (&expire_list_mutex);
		}

		callback (retval, ptr, packet_len);
#ifdef DEBUG
		// if (debug_level > 0) fprintf (stderr, "setentry\n");
#endif
		pthread_mutex_lock   (&expire_list_mutex);

		if (retval == 1) {
			netflow_list[nf_index].active_prev = p
					= netflow_list[0].active_prev;
			netflow_list[nf_index].active_next = 0;
			netflow_list[0].active_prev = nf_index;
			netflow_list[p].active_next = nf_index;
		}

		netflow_list[nf_index].expire_prev = p
						= netflow_list[0].expire_prev;
		netflow_list[nf_index].expire_next = 0;
		netflow_list[0].expire_prev = nf_index;
		netflow_list[p].expire_next = nf_index;

		pthread_mutex_unlock (&expire_list_mutex);
	} else {
		// fprintf (stderr, "(drop)\n");
		concurrent_drop++;
	}

	pthread_mutex_unlock (&netflow_list[nf_index].mutex);

	return retval;
}

#if DEBUG_LEVEL > 2
static void print_flow (const int i) {
	struct in_addr		srcip, dstip;

	srcip.s_addr = netflow_list[i].key.src_ip;
	dstip.s_addr = netflow_list[i].key.dst_ip;

	fprintf (stderr, "P=%2d, %s:%d -> ",
			netflow_list[i].key.prot,
			inet_ntoa (srcip),
			ntohs (netflow_list[i].key.src_port));
	fprintf (stderr, "%s:%d - %llu pkts, %llu octs\n",
			inet_ntoa (dstip),
			ntohs (netflow_list[i].key.dst_port),
			netflow_list[i].data.pkts,
			netflow_list[i].data.octets);
}
#endif

static void export_expired_flow (void) {
	int			i, idx, nextfree;
	int			version;
	struct netflow_key	*k;
	struct netflow_data	*d;
	struct timeval		now;


	if (waitfor_export_idx == 0) return;

#ifdef DEBUG
	/*
	if (debug_level > 0) {
		fprintf (stderr,
			"export_expired_flow, waitfor_export_idx = %d\n",
			waitfor_export_idx);
	}
	*/
#endif

	version = netflow_pdu_version;

	gettimeofday (&now, (struct timezone *) 0);

	for (i = nextfree = 0; i < waitfor_export_idx; i++) {
		idx = waitfor_export[i];

		netflow_list[idx].next_free = nextfree;
		nextfree = idx;

		k = &netflow_list[idx].key;
		d = &netflow_list[idx].data;

		if (version == 1) {
			netflow_v1.records[i].srcaddr = k->src_ip;
			netflow_v1.records[i].dstaddr = k->dst_ip;
			netflow_v1.records[i].srcport = k->src_port;
			netflow_v1.records[i].dstport = k->dst_port;
			netflow_v1.records[i].prot    = k->prot;
			netflow_v1.records[i].flags   = d->flags;
			// netflow_v1.records[i].tos     = 0;
			netflow_v1.records[i].dPkts   =
				htonl ((u_int32_t) d->pkts);
			netflow_v1.records[i].dOctets =
				htonl ((u_int32_t) d->octets);
			netflow_v1.records[i].First   =
				htonl (MSecSUB(d->first, startup_time));
			netflow_v1.records[i].Last    =
				htonl (MSecSUB(d->last, startup_time));
		} else {
			netflow_v5.records[i].srcaddr = k->src_ip;
			netflow_v5.records[i].dstaddr = k->dst_ip;
			netflow_v5.records[i].srcport = k->src_port;
			netflow_v5.records[i].dstport = k->dst_port;
			netflow_v5.records[i].prot    = k->prot;
			netflow_v5.records[i].tcp_flags   = d->flags;
			// netflow_v5.records[i].tos     = 0;
			netflow_v5.records[i].dPkts   =
				htonl ((u_int32_t) d->pkts);
			netflow_v5.records[i].dOctets =
				htonl ((u_int32_t) d->octets);
			netflow_v5.records[i].First   =
				htonl (MSecSUB(d->first, startup_time));
			netflow_v5.records[i].Last    =
				htonl (MSecSUB(d->last, startup_time));
		}

		octet_exports += d->octets;
	}

	if (version == 1) {
		netflow_v1.count   = htons (waitfor_export_idx);
		netflow_v1_len     = netflow_v1_hdrlen +
			(waitfor_export_idx * sizeof (netflow_v1_record));
		netflow_v1.unix_secs = htonl (now.tv_sec);
		netflow_v1.SysUptime = htonl (MSecSUB(now, startup_time));
	} else {
		netflow_v5.count   = htons (waitfor_export_idx);
		netflow_v5_len     = netflow_v5_hdrlen +
			(waitfor_export_idx * sizeof (netflow_v5_record));
		netflow_v5.unix_secs = htonl (now.tv_sec);
		netflow_v5.SysUptime = htonl (MSecSUB(now, startup_time));
	}

	idx = waitfor_export[0];

	pthread_mutex_lock   (&freelist_mutex);
	netflow_list[idx].next_free = netflow_free_list;
	netflow_free_list = nextfree;
	netflow_free_count += waitfor_export_idx;
	pthread_mutex_unlock (&freelist_mutex);

	if (enable_flow_export) {
		exported_datagram++;
		flow_exports += waitfor_export_idx;

		// fprintf (stderr, "Export flow %d\n", waitfor_export_idx);

		if (version == 1) {
			if (sendto (sockfd, &netflow_v1,
					netflow_v1_len, 0,
					(struct sockaddr *) &export_addr,
					sizeof (export_addr)) < 0) {
				failed_datagram++;
			}
		} else {
			netflow_v5.flow_sequence = netflow_v5_flow_sequence;

			if (sendto (sockfd, &netflow_v5,
					netflow_v5_len, 0,
					(struct sockaddr *) &export_addr,
					sizeof (export_addr)) < 0) {
				failed_datagram++;
			}
		}
	}

	waitfor_export_idx = 0;
}

static void schedule_to_expire (int idx) {
	int			p, n;

	while (waitfor_export_idx >= NETFLOW_V5_MAXFLOWS) {
		export_expired_flow ();
	}

	waitfor_export [waitfor_export_idx++] = idx;

	// write back
	flowdkey.data = &netflow_list[idx].key;

	iphash->del (iphash, &flowdkey, del_lock_callback);

	// pthread_mutex_lock   (&netflow_list[idx].mutex);
	// netflow_list[idx].inuse = 0;

	pthread_mutex_lock   (&expire_list_mutex);

	p = netflow_list[idx].expire_prev;
	n = netflow_list[idx].expire_next;
	netflow_list[p].expire_next = n;
	netflow_list[n].expire_prev = p;

	p = netflow_list[idx].active_prev;
	n = netflow_list[idx].active_next;
	netflow_list[p].active_next = n;
	netflow_list[n].active_prev = p;

	pthread_mutex_unlock (&expire_list_mutex);

	pthread_mutex_unlock (&netflow_list[idx].mutex);
}

static void nfl_listall (void) {
	int			i, j, k, m, isloop;
	struct netflow_key	keybuffer;

	for (i = 1, m = 0; i < netflow_list_len; i++) {
		if (netflow_list[i].inuse) m++;
	}

	clip->print ("\nIn memory flow: %d\n", m);

	i = j = k = isloop = 0;
	while ((i = netflow_list[i].expire_next) != 0) {
		if (netflow_list[i].inuse == 1) {
			netflow_list[i].inuse = 2;
			k++;
		} else {
			j = 1;
			break;
		}
	}

	for (i = 1; i < netflow_list_len; i++)
		if (netflow_list[i].inuse == 2) netflow_list[i].inuse = 1;

	clip->print ("Expire Next: %d (loop=%d)\n", k, j);

	isloop += j;
	if (k != m) isloop++;

	i = j = k = 0;
	while ((i = netflow_list[i].expire_prev) != 0) {
		if (netflow_list[i].inuse == 1) {
			netflow_list[i].inuse = 2;
			k++;
		} else {
			j = 1;
			break;
		}
	}

	for (i = 1; i < netflow_list_len; i++)
		if (netflow_list[i].inuse == 2) netflow_list[i].inuse = 1;

	clip->print ("Expire Prev: %d (loop=%d)\n", k, j);

	isloop += j;
	if (k != m) isloop++;

	if (! isloop) {
		for (i = k = 0; (i = netflow_list[i].active_prev) != 0; k++) ;
		clip->print ("Active Prev: %d\n", k);

		for (i = k = 0; (i = netflow_list[i].active_next) != 0; k++) ;
		clip->print ("Active Next: %d\n", k);
	}

	for (k = 0, i = netflow_free_list; i > 0; k++)
		i = netflow_list[i].next_free;
	clip->print ("Netflow free entry: %d (%d)\n", netflow_free_count, k);


	flowkey.data = &keybuffer;
	k = iphash->firstkey (iphash, &flowkey, &flowdata);
	j = 0;

	while (k) {
		// fprintf (stderr, "rest %d\n", nf_index);
		j++;
		k = iphash->nextkey (iphash, &flowkey, &flowdata);
	};

	clip->print ("Hashing Table entry: %d\n", j);

	clip->print ("%llu flow(s) exported in %llu udp datagram(s)\n"
		"%lu udp datagram(s) dropped on failed, "
		"%lu packet(s) dropped on expire\n",
			flow_exports, exported_datagram,
			failed_datagram, concurrent_drop);

	clip->print ("%llu active exported, %llu inactive exported\n",
			active_exports, inactive_exports);
}

static void nfl_close (void) {
	int	i;

	for (i = 1; i < netflow_list_len; i++) {
		if (netflow_list[i].inuse) schedule_to_expire (i);
	}
	export_expired_flow ();


	netflow_list_len = 0;
	free (netflow_list);

	if (sockfd > 0) close (sockfd);

	sockfd = -1;

	iphash->release (iphash);
}

static void netflow_list_initialization (void) {
	bzero (&flowdkey, sizeof (DBDT));
	flowdkey.size  = sizeof (struct netflow_key);

	bzero (&flowkey,  sizeof (DBDT));
	bzero (&flowdata, sizeof (DBDT));

	// flowkey.size   = flowkey.ulen = sizeof (struct netflow_key);
	flowkey.size   = sizeof (struct netflow_key);
	// flowkey.flags  = DB_DBT_USERMEM;

	flowdata.data  = &nf_index;
	// flowdata.size  = flowdata.ulen = sizeof (int);
	flowdata.size  = sizeof (int);
	// flowdata.flags = DB_DBT_USERMEM;

	// flowdkey.size  = flowdkey.ulen = sizeof (struct netflow_key);
	// flowdkey.flags = DB_DBT_USERMEM;

	flow_exports = 0;
	octet_exports = 0;
}

static int netflow_export_udp_datagram_initialize (void) {
	struct hostent		*hp;
	struct in_addr		*ip;
	struct sockaddr_in	cli_addr;

	enable_flow_export = 0;
	if (sockfd >= 0) close (sockfd);

	sockfd = -1;

	if (flow_export_host == NULL) return 0;

	if ((hp = gethostbyname (flow_export_host)) != NULL) {
		ip = (struct in_addr *) hp->h_addr;
	} else {
		perror (flow_export_host);
		return 0;
	}

	bzero ((char *) &export_addr, sizeof (export_addr));
	export_addr.sin_family	    = AF_INET;
	export_addr.sin_addr.s_addr = inet_addr (inet_ntoa (*ip));
	export_addr.sin_port        = htons (flow_export_port);

	if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror ("socket");
		return 0;
	}

	bzero ((char *) &cli_addr, sizeof (cli_addr));

	cli_addr.sin_family		= AF_INET;
	cli_addr.sin_addr.s_addr	= htonl (INADDR_ANY);
	cli_addr.sin_port		= htons (0);

	if (bind (sockfd, (struct sockaddr *) &cli_addr,
				sizeof (cli_addr)) < 0) {
		perror ("bind");
		close (sockfd);
		sockfd = -1;
		return 0;
	}

	return 1;
}

static int prepare_for_netflow_export (void) {
	int	i;

	// version 1

	bzero ((char *) &netflow_v1, sizeof (netflow_v1_pdu));
	netflow_v1.version = htons (1);
	netflow_v1_hdrlen  = sizeof (netflow_v1_pdu)
			- (NETFLOW_V1_MAXFLOWS * sizeof (netflow_v1_record));
	netflow_v1.unix_nsecs = 0;

	for (i = 0; i < NETFLOW_V1_MAXFLOWS; i++) {
		netflow_v1.records[i].tos = 0;
	}

	// version 5

	bzero ((char *) &netflow_v5, sizeof (netflow_v5_pdu));
	netflow_v5.version = htons (5);
	netflow_v5_hdrlen  = sizeof (netflow_v5_pdu)
			- (NETFLOW_V5_MAXFLOWS * sizeof (netflow_v5_record));
	netflow_v5.unix_nsecs = 0;
	netflow_v5.engine_type = NETFLOW_V5_ENGINE_TYPE;
	netflow_v5.engine_id   = NETFLOW_V5_ENGINE_ID;
	netflow_v5_flow_sequence = 0;

	for (i = 0; i < NETFLOW_V1_MAXFLOWS; i++) {
		netflow_v5.records[i].tos = 0;
		netflow_v5.records[i].src_as = 0;
		netflow_v5.records[i].dst_as = 0;
		netflow_v5.records[i].src_mask = 16;
		netflow_v5.records[i].dst_mask = 16;
	}

	// ------------

	gettimeofday (&startup_time, (struct timezone *) 0);
	startup_timet = time (NULL);

	return 1;
}

int clear_counter (struct cmdlintf_t *cli, char *cmd) {
	flow_exports = 0;
	exported_datagram = 0;
	active_exports = inactive_exports = 0;
	failed_datagram =  concurrent_drop = 0;
	bufferfull_cnt = 0;

	*iphash->max_bits = 0;

	pkteng->clear_counter ();

	// cli->print ("%% Counter cleared\n");

	return 1;
}

int show_ip_cache_flow (struct cmdlintf_t *cli, char *cmd) {
	struct netflow_entry	*ptr;
	static int		pos = 0;
	int			i, j;
	struct in_addr		srcip, dstip;
	char			sip[16], dip[16];


	cli->print ("         Pr SrcIPaddress      SrcP "
		"DstIPaddress      DstP    Pkts      Octets\n");

	if (pos < 1 || pos >= netflow_list_len) pos = 1;

	for (i = pos, j = 0; i < netflow_list_len; i++) {
		ptr = &netflow_list[i];
		if (! ptr->inuse) continue;

		srcip.s_addr = ptr->key.src_ip;
		dstip.s_addr = ptr->key.dst_ip;
		strcpy (sip, inet_ntoa (srcip));
		strcpy (dip, inet_ntoa (dstip));

		clip->print ("%8d %02x %-15s %6d %-15s %6d %7d %12d\n",
			i,
			ptr->key.prot,
			sip, ntohs (ptr->key.src_port),
			dip, ntohs (ptr->key.dst_port),
			ptr->data.pkts
		);
		if (++j > 80) break;
	}

	pos = i;

	return 1;
}

int show_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	time_t		now;
	long		difft;
       	int		d, m, h, s;
	u_int64_t	pktrcv, pktdrp;
	double		percent = 0.0;
	// int		mbits, usedbits;

	pktrcv = pkteng->pkt_received ();
	pktdrp = pkteng->pkt_dropped ();

	if (pktrcv != 0) {
		percent = (double) pktdrp * 100.0 / (double) pktrcv;
	}

	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
		return 1;
	}

	// mbits = iphash->max_bits;
	// for (usedbits = 0; mbits != 0; usedbits++) mbits >>= 1;

	now = time (NULL);
	difft = (long) difftime (now, startup_timet);

	cli->print (
		"Exporting flows to %s (%d)\n"
		"Version %d flow records\n"
		"Flow exporting: %s\n"
		"%llu flows exported in %llu udp datagrams\n"
		"%llu byte flow data exported\n"
		"%llu active exported, %llu inactive exported\n"
		"%lu udp datagrams dropped on failed, "
		"%lu packets dropped on expire\n"
		"%lu flows dropped on flow-cache entries full\n"
		"ip flow-cache entries %d, %u in-use, %u maximum use\n"
		"ip flow-cache timeout active %d minute(s), "
		"inactive %d second(s)\n"
		"%llu packets received, %llu packets dropped\n"
		"%llu octets received, %llu octets dropped\n"
		"%4.2f%% packet dropped, maximum %d buckets used in hashing\n"
		"%d raw packet buffer, %d free."
#if ENABLE_FLOW_CACHE_BUFFER == 1
		" %d cache buffer, %d free."
#endif
		"\n"
		"System boot on: %s"
		"System up time:",
		(flow_export_host == NULL ? "(not set)" : flow_export_host),
		flow_export_port,
		netflow_pdu_version,
		(enable_flow_export ? "enable" : "disable"),
		flow_exports, exported_datagram,
		octet_exports,
		active_exports, inactive_exports,
		failed_datagram, concurrent_drop,
		bufferfull_cnt,
		netflow_list_len, 
		(netflow_list_len - netflow_free_count - 1),
		(netflow_list_len - netflow_free_min - 1),
		active_timeout_min, inactive_timeout,
		pktrcv, pktdrp,
		pkteng->octet_received (), pkteng->octet_dropped (),
		percent,
		*iphash->max_bits + 1,
		pktbf->num_of_buffers (), pktbf->num_of_freebuf (),
#if ENABLE_FLOW_CACHE_BUFFER == 1
		nfcb->num_of_buffers (), nfcb->num_of_freebuf (),
#endif
		ctime (&startup_timet));

	d = difft / 86400; difft %= 86400;
	h = difft /  3600; difft %=  3600;
	m = difft /    60;
	s = difft %    60;

	if (d > 0) cli->print (" %d day(s)", d);

	cli->print (" %02d:%02d:%02d\n", h, m, s);

	return 1;
}

int enable_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ( "%% Invalid input detected: \"%s\"\n", cmd);
	} else if (sockfd >= 0) {
		enable_flow_export = 1;
	} else {
		cli->print ("%% Unable to export flow to %s (%d)\n",
				(flow_export_host == NULL ? "(not set)"
				 			: flow_export_host),
				flow_export_port);
	}

	return 1;
}

int disable_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
	} else {
		// cli->print ("disable ip flow export\n");
		enable_flow_export = 0;
	}

	return 1;
}

int ip_flow_export_destination (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	i, len, port = 0;
		char	*host = NULL;

		len = strlen (cmd);

		for (i = 0; i < len; i++) {
			if ((cmd[i] == ' ') || (cmd[i] == '\t')) {
				if (i > 0) {
					host = utils_malloc (i + 1);
					strncpy (host, cmd, i);
					host[i] = '\0';
					break;
				}
			}
		}

		for (; i < len; i++) {
			if ((cmd[i] == ' ') || (cmd[i] == '\t')) {
			} else {
				break;
			}
		}

		if (is_numeric_string (&cmd[i])) port = atoi (&cmd[i]);

		if (port <= 0 || port >= 65536) {
			if (host != NULL) {
				free (host);
				host = NULL;
			}
		}

		if (host == NULL) {
			cli->print ("%% Invalid input detected: \"%s\"\n",
					cmd);
		} else {
			i = enable_flow_export;

			disable_ip_flow_export (cli, NULL);

			if (flow_export_host != NULL) free (flow_export_host);
			flow_export_host = host;
			flow_export_port = port;

			netflow_export_udp_datagram_initialize ();

			if (i) enable_ip_flow_export (cli, NULL);
		}
	}

	return 1;
}

struct netflow_list_t * init_netflow_list (
			const int ver, const int  numx, 
			const int actt, const int inactt,
			const char *host, const int port) {
	int	i;
	int	num = numx;

	if ((actt   >=  MIN_ACTIVE_TIMEOUT_MIN) &&
	    (actt   <=  MAX_ACTIVE_TIMEOUT_MIN))
		active_timeout_min = actt;

	if ((inactt >= MIN_INACTIVE_TIMEOUT) &&
	    (inactt <= MAX_INACTIVE_TIMEOUT))
		inactive_timeout   = inactt;

	netflow_list_initialization ();

	HASHENG_init_hashing_engine ();

	if ((iphash = HASHENG_request_implementation ("memhash")) == 0) {
//	} else if ((iphash = HASHENG_request_implementation ("bdb")) == 0) {
		fprintf (stderr, "engine not found\n");
		return NULL;
	}

	if (flow_cache_entries != 0) num = flow_cache_entries;

	if (hash_entries < (num * 2)) hash_entries = num * 10;

	iphash = iphash->init ("", hash_entries);


	if ((netflow_list = utils_calloc (num,
				sizeof (struct netflow_entry))) == NULL) {
		fprintf (logfp, "Allocate %d netflow buffer ... failed", num);
		return NULL;
	} else {
		netflow_free_count = 0;
		netflow_free_list  = -1;
		flow_cache_entries = netflow_list_len   = num;

		netflow_list[0].inuse       = 0;
		netflow_list[0].expire_prev = 0;
		netflow_list[0].expire_next = 0;
		netflow_list[0].active_prev = 0;
		netflow_list[0].active_next = 0;

		for (i = netflow_list_len-1; i > 0; i--) {
			netflow_list[i].inuse = 0;
			netflow_list[i].next_free = netflow_free_list;
			netflow_free_list         = i;
			netflow_free_count++;
		}

		netflow_free_min = netflow_free_count;
	}

	nflist.setentry		= &nfl_setentry;
	nflist.free_count	= &nfl_free_count;
	nflist.listall		= &nfl_listall;
	//nflist.expire		= &nfl_expire;
	nflist.close		= &nfl_close;
	nflist.number_of_flow	= &nfl_number_of_netflow;
	nflist.show_config	= &show_configuration;

	active_timeout = active_timeout_min * 60;
	active_exports = inactive_exports = 0;

	if (host != NULL) {
		flow_export_host = strdup (host);
	}

	if (port != 0) flow_export_port = port;

	if ((ver == 1) || (ver == 5)) netflow_pdu_version = ver;

	fprintf (logfp,
		"ip flow-export version %d\n"
		"ip flow-export destination %s %d\n"
		"ip flow-cache entries %d\n"
		"ip flow-cache timeout active %d minute(s)\n"
		"ip flow-cache timeout inactive %d second(s)\n",
		netflow_pdu_version,
		(flow_export_host == NULL ? "(not set)" : flow_export_host),
		flow_export_port,
		netflow_list_len, active_timeout_min, inactive_timeout);

	sockfd = -1;

	prepare_for_netflow_export ();
	netflow_export_udp_datagram_initialize ();

	enable_ip_flow_export (clip, NULL);

	return &nflist;
}


void expire_flow_main (void) {
	struct timeval	now;
	int		i;
	int		timetosleep = 0;

	fprintf (logfp, "expire_flow: started [%d]\n", getpid ());
	fflush (logfp);

	// setproctitle ("< expire flow >");

	setsignal (SIGINT,  signal_handler);
	setsignal (SIGQUIT, signal_handler);
	setsignal (SIGTERM, signal_handler);
	setsignal (SIGALRM, signal_handler);
/*
	signal (SIGINT , signal_handler);
	signal (SIGQUIT, signal_handler);
	signal (SIGTERM, signal_handler);
*/

	while (! terminate) {
		timetosleep = 1000000;
		if ((i = netflow_list[0].expire_next) > 0) {
			gettimeofday (&now, (struct timezone *) 0);

			timetosleep = 100000;

			if (netflow_list[i].data.last.tv_sec
					+ inactive_timeout < now.tv_sec) {
				// nfl_expire (i);
				schedule_to_expire (i);
				inactive_exports++;
				timetosleep = 0;
			}

			if ((i = netflow_list[0].active_next) > 0) {
				if (netflow_list[i].data.first.tv_sec
						+ active_timeout < now.tv_sec) {
					// nfl_expire (i);
					schedule_to_expire (i);
					active_exports++;
					timetosleep = 0;
				}
			}
		}

		if (timetosleep != 0) {
			export_expired_flow ();
			usleep (timetosleep);
		}
		// find a expire flow to write back
	}

	// fprintf (stderr, "Expire flow\n");

/*
	for (i = 1; i < netflow_list_len; i++) {
		if (netflow_list[i].inuse) nfl_expire (i);
	}
*/

	fprintf (logfp, "expire_flow: terminated\n");
	fflush (logfp);

	pthread_exit (NULL);
}
