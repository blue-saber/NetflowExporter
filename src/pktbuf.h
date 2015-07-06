/*
 *	pktbuf.h
 *
 *	Copyright (c) 2001 Jiann-Ching Liu
 */

#ifndef __PACKET_BUFFER_H_
#define __PACKET_BUFFER_H_

#include <sys/types.h>

#define MAX_NETWORK_MTU	(1518)
// #define MIN_PACKET_LEN	(42)
#define MIN_PACKET_LEN	(78)

// 6 + 6 + 2 + 20 (IP) + 4
// 6 + 6 + 2 + 60 + 4 = 

struct packet_buffer_t {
	u_int8_t		buffer_ready;
	u_int16_t		len;
	// char			pktbuff[MAX_NETWORK_MTU];
	char			pktbuff[MIN_PACKET_LEN];
	struct packet_buffer_t	*next;
	struct packet_buffer_t	*prev;
};

struct packet_buffer {
	struct packet_buffer_t *	(*request)(void);	// for producer
	struct packet_buffer_t *	(*retrieve)(void);	// for consumer
	void				(*ready)(struct packet_buffer_t *);
	void				(*dequeue)(struct packet_buffer_t *);
	void				(*close)(void);
	int				(*count)(void);
	int				(*num_of_buffers)(void);
	int				(*num_of_freebuf)(void);
};

struct packet_buffer* init_packet_buffer_v1 (const int number_of_buffer);
struct packet_buffer* init_packet_buffer_v2 (const int number_of_buffer);

#endif
