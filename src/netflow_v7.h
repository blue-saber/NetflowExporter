#ifndef __NETFLOW_V7_H_
#define __NETFLOW_V7_H_

#include <sys/types.h>
#include "typedef.h"


#define NETFLOW_V7_MAXFLOWS	24

/*
 *  Netflow Export Datagram Format
 */

typedef struct _netflow_v7_record {
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
	u_int8_t  ffflags;	// Flags indicating, among other thins,
				//	what flow fields are invalid.
	u_int8_t  tcp_flags;	// TCP flags; always set to zero
	u_int8_t  prot;		// IP protocol type (e.g. TCP=6; UDP=17)
	u_int8_t  tos;		// IP type of service (ToS)
	u_int16_t src_as;	// AS number of the source,
				//	either origin or peer
	u_int16_t dst_as;	// AS number of the destination,
				//	either origin or peer
	u_int8_t  src_mask;	// Source address prefix mask bits
	u_int8_t  dst_mask;	// Destination address prefix mask bits
	u_int16_t fflags;	// Flags indicating, among other thins,
				//	what flow are invalid.
	u_int32_t router_sc;	// IP address of the router that is bypasswd
				//	by the Catalyst 5000 series switch.
				//	This is the same address the router
				//	uses when it sends NetFlow export
				//	packets. This IP address is propagated
				//	to all switches bypassing the router
				//	through the FCP protocol.
} netflow_v7_record;

typedef struct _netflow_v7_pdu {
	u_int16_t	version;	// Netflow export format version number
	u_int16_t	count;		// Number of flows exported in this
					// 	packet (1-24)
	u_int32_t	SysUptime;	// Current time in milliseconds
					// 	since the export device booted
	u_int32_t	unix_secs;	// Current count of seconds since 0000
					// 	UTC 1970
	u_int32_t	unix_nsecs;	// Residual nanoseconds since 0000
					// 	UTC 1970
	u_int32_t	flow_sequence;	// Sequence counter of total flows seen
	u_int32_t	reserved;	// Unused (zero) bytes
	netflow_v7_record	records[NETFLOW_V7_MAXFLOWS];
} netflow_v7_pdu;

#endif
