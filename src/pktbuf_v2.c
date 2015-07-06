/*
 *	pktbuf.c
 *
 *	Copyright (C) 2002-2004, Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "pktbuf.h"
#include "utils.h"

static struct packet_buffer	pktbuf;
// static struct packet_buffer_t	*full_packet = NULL;
static struct packet_buffer_t	*pktlink;
static struct packet_buffer_t	*pkt_freelist;
static struct packet_buffer_t	*pkt_use_front;
static struct packet_buffer_t	*pkt_use_rear;
static int			packet_buffer_count = 0;
static int			bufuse = 0;
static pthread_mutex_t		mutex_used = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t		mutex_free = PTHREAD_MUTEX_INITIALIZER;


static int pktbuf_num_of_buffers (void) { return packet_buffer_count; }
static int pktbuf_num_of_freebuf (void) { return packet_buffer_count - bufuse; }

static struct packet_buffer_t *request (void) {
	struct packet_buffer_t	*ptr;

	// if (bufuse == packet_buffer_count) return NULL; // buffer full

	// fprintf (stderr, "request\n");
	pthread_mutex_lock (&mutex_free);
	if ((ptr = pkt_freelist) != NULL) {
		pkt_freelist = ptr->next;
		// fprintf (stderr, "request ok\n");
		bufuse++;
	}
	pthread_mutex_unlock (&mutex_free);

	return ptr;
}

static void bufready (struct packet_buffer_t *pkt) {
	pthread_mutex_lock   (&mutex_used);

	pkt->next = NULL;

	if (pkt_use_front == NULL) {
		pkt->prev     = NULL;
		pkt_use_front = pkt;
	} else {
		pkt->prev          = pkt_use_rear;
		pkt_use_rear->next = pkt;
	}

	pkt_use_rear  = pkt;

	pthread_mutex_unlock (&mutex_used);
}

static struct packet_buffer_t *retrieve (void) {
	struct packet_buffer_t	*ptr;

	pthread_mutex_lock (&mutex_used);

	if ((ptr = pkt_use_front) != NULL) {
		pkt_use_front = ptr->next;

		/*
		if ((pkt_use_front = ptr->next) == NULL) {
			pkt_use_rear = NULL;
		}
		*/
	}

	pthread_mutex_unlock (&mutex_used);

	return ptr;
}

static void dequeue (struct packet_buffer_t *pkt) {
	pthread_mutex_lock (&mutex_free);
	pkt->next = pkt_freelist;
	pkt_freelist = pkt;
	bufuse--;
	pthread_mutex_unlock (&mutex_free);
}

static void pktbuf_close (void) {
	int	len;

	len = packet_buffer_count;
	packet_buffer_count = 0;
	bufuse = 0;

	free (pktlink);
}

static int pktbuf_count (void) { return bufuse; }

struct packet_buffer *init_packet_buffer_v2 (const int number_of_buffer) {
	int			i;
	struct packet_buffer_t	*ptr;

	fprintf (stderr, "Allocate %d packet buffer ... ",
			number_of_buffer);

	if ((pktlink = utils_calloc (number_of_buffer,
				sizeof (struct packet_buffer_t))) == NULL) {
		fprintf (stderr, "error\n");
		return NULL;
	} else {
		packet_buffer_count = number_of_buffer;
	}

	for (i = 0, ptr = NULL; i < packet_buffer_count; i++) {
		// full_packet[i].buffer_ready = 0;
		// pktlink[i].buffer_ready = 0;
		pktlink[i].prev = NULL;
		pktlink[i].next = ptr;
		ptr = &pktlink[i];
	}

	pkt_freelist = ptr;
	pkt_use_front = NULL;
	pkt_use_rear  = NULL;


	fprintf (stderr, "ok\n");

	bufuse = 0;

	pktbuf.request  = &request;
	pktbuf.retrieve = &retrieve;
	pktbuf.dequeue  = &dequeue;
	pktbuf.ready	= &bufready;
	pktbuf.close    = &pktbuf_close;
	pktbuf.count	= &pktbuf_count;
	pktbuf.num_of_buffers = &pktbuf_num_of_buffers;
	pktbuf.num_of_freebuf = &pktbuf_num_of_freebuf;

	return &pktbuf;
}
