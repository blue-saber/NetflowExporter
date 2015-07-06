/*
 *	global_var.h
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#ifndef __NF_GLOBAL_VAR_H__
#define __NF_GLOBAL_VAR_H__

#ifndef	ENABLE_FLOW_CACHE_BUFFER
#define	ENABLE_FLOW_CACHE_BUFFER	1
#endif

#ifndef ENABLE_PACKET_BUFFER_ENGINE_VERSION
#define ENABLE_PACKET_BUFFER_ENGINE_VERSION	0
#endif

#ifndef ENABLE_NETFLOW_ENGINE_INSTANCE
#define ENABLE_NETFLOW_ENGINE_INSTANCE		0
#endif

#ifndef DEFAULT_NETFLOW_CACHE
#define	DEFAULT_NETFLOW_CACHE		10000
#endif

#define ENABLE_MONITOR_NETFLOW_CACHE		0

struct netflow_cache_t;

extern struct netflow_cache_t	*nfcb;
extern FILE			*logfp;
#if ENABLE_MONITOR_NETFLOW_CACHE == 1
extern volatile int		netflow_cache_state;
#endif
extern volatile int		nettap_terminate;
extern int			nf5_engine_type;
extern int			nf5_engine_id;
extern int			ip_flow_sampling_rate;
extern int			num_of_netflow_engine;
extern int			packet_buffer_engine_version;
extern int			flow_cache_entries;
extern int			hash_entries;
extern int			netflow_cache_size;
extern int			packet_buf_size;
extern u_int64_t		flow_exports;
extern u_int64_t		octet_exports;
extern int			enable_flow_export;
extern int			netflow_pdu_version;
extern char			*flow_export_host;
extern int			flow_export_port;
extern int			active_timeout_min;
extern int			inactive_timeout;
extern int			active_timeout;
extern int			idle_timeout;

#endif
