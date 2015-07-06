#ifndef __NETFLOW_V1_H_
#define __NETFLOW_V1_H_

#include <sys/types.h>
#include "typedef.h"


#define NETFLOW_V1_MAXFLOWS	30

/*
 *  Netflow Export Datagram Format
 */

typedef struct _netflow_v1_record {
	u_int32_t srcaddr;	// Source IP address
	u_int32_t dstaddr;	// Destination IP address
	u_int32_t nexthop;	// IP address of next hop router
	u_int16_t input;	// SNMP index of input interface
	u_int16_t output;	// SNMP index of output interface
	u_int32_t dPkts;	// Packets in the flow
	u_int32_t dOctets;	// Total number of Layer 3 bytes
				//	in the packets of the flow
	u_int32_t First;	// SysUptime at atart of flow
	u_int32_t Last;		// SysUptime at the time the last packet
				//	of the flow was received.
	u_int16_t srcport;	// TCP/UDP source port number or equivalent
	u_int16_t dstport;	// TCP/UDP destination port number or equivalent
	u_int16_t pad1;		// Unused (zero) bytes
	u_int8_t  prot;		// IP protocol type (e.g. TCP=6; UDP=17)
	u_int8_t  tos;		// IP type of service (ToS)
	u_int8_t  flags;	// Cumulative OR of TCP flags
	u_int8_t  tcp_retx_cnt;	// * Number of mis-seq with delay > 1sec
	u_int8_t  tcp_retx_secs;// * Cumulative secs between mis-sequenced pkts
	u_int8_t  tcp_misseq_cnt; // * Number of mis-sequenced tcp pkts seen 
	u_int32_t reserved;	// Unused (zero) bytes
} netflow_v1_record;

typedef struct _netflow_v1_pdu {
	u_int16_t	version;	// Netflow export format version number
	u_int16_t	count;		// Number of flows exported in this
					// 	packet (1-24)
	u_int32_t	SysUptime;	// Current time in milliseconds
					// 	since the export device booted
	u_int32_t	unix_secs;	// Current count of seconds since 0000
					// 	UTC 1970
	u_int32_t	unix_nsecs;	// Residual nanoseconds since 0000
					// 	UTC 1970
	netflow_v1_record	records[NETFLOW_V1_MAXFLOWS];
} netflow_v1_pdu;

#endif
