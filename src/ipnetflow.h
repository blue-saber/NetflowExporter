#ifndef __IPNETFLOW_H_
#define __IPNETFLOW_H_

#include <sys/time.h>
#include <pthread.h>
#include "hasheng.h"

// #define DEBUG

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER BIG_ENDIAN
#endif

#ifndef DEFAULT_NETFLOW_ENTRY
#define DEFAULT_NETFLOW_ENTRY	524288
#endif

#define DEFAULT_PACKET_BUFFER    10000

#define MAX_NETFLOW_THREAD	16


#define MAX_ACTIVE_TIMEOUT_MIN  60
#define MIN_ACTIVE_TIMEOUT_MIN  1
#define MAX_INACTIVE_TIMEOUT    600
#define MIN_INACTIVE_TIMEOUT    10


struct netflow_list_t;
struct cmdlintf_t;


#ifdef DEBUG
extern int				debug_level;
#endif
extern char				*program_name;
extern char				*listen_interface;
extern volatile int			terminate;
extern pthread_t			all_threads[];
extern struct netflow_list_t		*nflp;
extern struct packet_buffer		*pktbf;
extern struct cmdlintf_t		*clip;
extern char				*conf_file;
extern short				reloading;

void *	netflow_main		(void *arg);
void *	netflow_cache_main	(void *arg);
void	nettap_main		(char *args[]);
void	snmp_main		(void);
void	expire_flow_main	(void);
void	netflow_wakeup		(const u_char *pkt, const int len);
void	netflow_cache_wakeup	(void);

int	setsignal (int signum, void (*sighandler)(int));

struct netflow_key {
	u_int8_t	prot;		// protocol
	u_int32_t	src_ip;
	u_int32_t	dst_ip;
	u_int16_t	src_port;
	u_int16_t	dst_port;
};

struct netflow_data {
	//u_int64_t	pkts;
	//u_int64_t	octets;
	u_int32_t	pkts;
	u_int32_t	octets;
	u_int8_t	flags;
	struct timeval	first;
	struct timeval	last;
};

#endif
