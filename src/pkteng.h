#ifndef __PACKET_ENGINE_H_
#define __PACKET_ENGINE_H_

#include <sys/types.h>

struct packet_buffer;

typedef	void (*PKTENG_callback)(const u_char *, int);

typedef struct {
	int	(*open_packet_engine)(void);
	int	(*bind_interface)(char *interface);
	int	(*listen_loop)(volatile int *term, 
				void (*callback)(const u_char *, const int));
	int	(*release)(void);
	int	(*promiscuous)(const int  flag);
	char*	(*driver_version)(void);
	char*	(*error)(void);
	int	(*set_packet_buffer_engine)(struct packet_buffer *pktbuf);
	u_int64_t	(*pkt_received)(void);
	u_int64_t	(*pkt_dropped)(void);
	u_int64_t	(*octet_received)(void);
	u_int64_t	(*octet_dropped)(void);
	u_int32_t	(*drv_received)(void);
	u_int32_t	(*drv_dropped)(void);
	int		(*clear_counter)(void);
} PKTENG;

int		PKTENG_regist_implementation (const char *sign, PKTENG *imp);
PKTENG*		PKTENG_request_implementation (const char *sign);
void		PKTENG_init_packet_engine (void);
char*		generic_lookupdev (char **errbuf);

extern PKTENG	*pkteng;

#define PKTENG_regist_functions(x)	{				\
			x.open_packet_engine = open_packet_engine;	\
		        x.bind_interface     = bind_interface;		\
			x.listen_loop        = listen_loop;		\
			x.release            = release;			\
			x.promiscuous        = promiscuous;		\
			x.driver_version     = driver_version;		\
			x.set_packet_buffer_engine  = set_packet_buffer_engine;\
			x.pkt_received       = pkt_received;		\
			x.pkt_dropped        = pkt_dropped;		\
			x.octet_received     = octet_received;		\
			x.octet_dropped      = octet_dropped;		\
			x.drv_received       = drv_received;		\
			x.drv_dropped        = drv_dropped;		\
			x.clear_counter      = clear_counter;		\
			x.error              = error; }

int init_pkteng_linux_pf_packet (void);
int init_pkteng_linux_socket_packet (void);
int init_pkteng_pcap (void);
int init_pkteng_bpf (void);

#endif
