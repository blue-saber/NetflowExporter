/*
 *	ipnetflow_ds.h
 *
 *	Copyright (C) 2001 Jiann-Ching Liu
 *
 *
 *	Data Structure for ipnetflow
 */

#ifndef __IPNETFLOW_DS_H_
#define __IPNETFLOW_DS_H_



//////////////////////////////////////////////////////////////////


short tcp_port_to_record[] = {
	0, 20, 21, 22, 23, 25, 70, 79, 80, 109, 110, 111, 113, 119,
	123, 137, 138, 139, 143, 220, 443, 512, 513, 514, 515, 995,
	3128
};

int tcp_port_index_list [65536];

#define TCP_PORT_RECORD_LEN	(sizeof (tcp_port_to_record) / sizeof (short))

//////////////////////////////////////////////////////////////////

short udp_port_to_record[] = {
	0, 53, 137, 138, 139, 161, 162, 179
};

int udp_port_index_list [65536];

#define UDP_PORT_RECORD_LEN	(sizeof (udp_port_to_record) / sizeof (short))

//////////////////////////////////////////////////////////////////

typedef struct _ippktcnt {
	u_int64_t	sendpkt;
	u_int64_t	recvpkt;
	u_int64_t	sendbytes;
	u_int64_t	recvbytes;
	u_int64_t	sendproto[IP_PROTO_RECORD_LEN];
	u_int64_t	recvproto[IP_PROTO_RECORD_LEN];
	u_int64_t	tcpportin[TCP_PORT_RECORD_LEN];
	u_int64_t	tcpportou[TCP_PORT_RECORD_LEN];
	u_int64_t	udpportin[UDP_PORT_RECORD_LEN];
	u_int64_t	udpportou[UDP_PORT_RECORD_LEN];
	u_int32_t	tcpflow_cnt;
	u_int32_t	tcpflow_current;
} ippktcnt;

#endif
