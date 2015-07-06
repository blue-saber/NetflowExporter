/*
 * 	ipflowlist.h
 *
 * 	Copyright (C) 2001, Jiann-Ching Liu
 */

#ifndef __IP_FLOW_LIST_H_
#define __IP_FLOW_LIST_H_

#include "ipnetflow.h"
#include "cmdfcn.h"

struct netflow_key;
struct netflow_data;

struct netflow_list_t {
	int	(*setentry)(struct netflow_key *key,
			void (*callback)(const int, struct netflow_data *fd,
				const int),
			const int);
	//void	(*expire)(const int idx);
	int	(*free_count)(void);
	int	(*number_of_flow)(void);
	int	(*show_config)(FILE *fp);
	void	(*listall)(void);
	void	(*close)(void);
};

struct netflow_list_t * init_netflow_list (
				const int ver, const int  num,
				const int actt, const int inacct,
				const char *host, const int port);

//init_pkteng_linux_socket_packet
//init_pkteng_pcap

#endif
