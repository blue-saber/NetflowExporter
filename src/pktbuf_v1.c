/*
 *	pktbuf.c
 *
 *	Copyright (C) 2002-2004, Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#define HAVE_CONCURRENT_ACCESS

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_CONCURRENT_ACCESS
#include <pthread.h>
#endif
#include "pktbuf.h"
#include "utils.h"


static struct packet_buffer	pktbuf;
static struct packet_buffer_t	*full_packet = NULL;
static int			packet_buffer_count = 0;
static int			front = 0, rear = 0;
static int			bufuse = 0;
#ifdef HAVE_CONCURRENT_ACCESS
static pthread_mutex_t		mutex = PTHREAD_MUTEX_INITIALIZER;
#endif


static int pktbuf_num_of_buffers (void) { return packet_buffer_count; }
static int pktbuf_num_of_freebuf (void) { return packet_buffer_count - bufuse; }

static struct packet_buffer_t *request (void) {
	int			i;

	if (bufuse == packet_buffer_count) return NULL; // buffer full

	// full_packet[front].buffer_ready = 0;
	i = front;
	front = (front + 1) % packet_buffer_count;

#ifdef HAVE_CONCURRENT_ACCESS
	pthread_mutex_lock (&mutex);
#endif
	bufuse++;
#ifdef HAVE_CONCURRENT_ACCESS
	pthread_mutex_unlock (&mutex);
#endif

	return &full_packet[i];
}

static struct packet_buffer_t *retrieve (void) {
	if (bufuse == 0) return NULL;

	if (full_packet[rear].buffer_ready == 0) return NULL;


	return &full_packet[rear];
}

static void bufready (struct packet_buffer_t *ptr) {
	ptr->buffer_ready = 1;
}

static void dequeue (struct packet_buffer_t *pkt) {
	int	i;

	if (bufuse > 0) {
		i = rear;
		full_packet[i].buffer_ready = 0;
		rear = (rear + 1) % packet_buffer_count;
#ifdef HAVE_CONCURRENT_ACCESS
		pthread_mutex_lock (&mutex);
#endif
		bufuse--;
#ifdef HAVE_CONCURRENT_ACCESS
		pthread_mutex_unlock (&mutex);
#endif
	}
}

static void pktbuf_close (void) {
	int	len;

	len = packet_buffer_count;
	packet_buffer_count = 0;
	front = rear = bufuse = 0;

	free (full_packet);
}

static int pktbuf_count (void) { return bufuse; }

struct packet_buffer *init_packet_buffer_v1 (const int number_of_buffer) {
	int		i;

	fprintf (stderr, "Allocate %d packet buffer ... ",
			number_of_buffer);

	if ((full_packet = utils_calloc (number_of_buffer,
				sizeof (struct packet_buffer_t))) == NULL) {
		fprintf (stderr, "error\n");
		return NULL;
	}

	for (i = 0; i < packet_buffer_count; i++) {
		full_packet[i].buffer_ready = 0;
	}

	packet_buffer_count = number_of_buffer;

	fprintf (stderr, "ok\n");

	front = rear = bufuse = 0;

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
