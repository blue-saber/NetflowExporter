#ifndef __IP_PACKET_H_
#define __IP_PACKET_H_

#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ip_packet_ethernet_encp {
	struct ether_header	eth;
	struct iphdr		ip;
	struct tcphdr		tcp;
};

#endif
