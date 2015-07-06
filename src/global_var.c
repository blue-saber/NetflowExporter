/*
 *	global_var.c
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */


#include <sys/types.h>
#include <stdio.h>
#include "ipnetflow.h"
#include "global_var.h"

struct netflow_cache_t	*nfcb = NULL;
FILE			*logfp = NULL;
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
volatile int		netflow_cache_state = 0;
#endif
volatile int		nettap_terminate = 0;
int			num_of_netflow_engine = 1;
int			packet_buffer_engine_version = 1;
int			ip_flow_sampling_rate = 1;
int			flow_cache_entries = 0;
int			hash_entries = 0;
int			netflow_cache_size = DEFAULT_NETFLOW_CACHE;
int			packet_buf_size = DEFAULT_PACKET_BUFFER;
u_int64_t		flow_exports = 0;
u_int64_t		octet_exports = 0;
int			enable_flow_export = 0;
int			netflow_pdu_version = 5;
char			*flow_export_host = NULL;
int			flow_export_port  = 9991;
int			active_timeout_min = 10;
int			inactive_timeout = 30;
int			active_timeout = 0;
int			idle_timeout = 5;
