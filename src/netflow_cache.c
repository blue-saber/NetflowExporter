/*
 *	netflow_cache.c
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#define HAVE_CONCURRENT_ACCESS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_CONCURRENT_ACCESS
#include <pthread.h>
#endif
#include "ipnetflow.h"
#include "global_var.h"
#include "netflow_cache.h"
#include "utils.h"
#include "hasheng.h"

static struct netflow_cache_t		nfc_instance;
static struct netflow_cache_t		*nfcptr = NULL;
static int				nfc_cache_size = 0;
static struct netflow_cache_data_t	*netf_key = NULL;
static int				front = 0, rear = 0;
static int				bufuse = 0;
#ifdef HAVE_CONCURRENT_ACCESS
static pthread_mutex_t			mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int pktbuf_num_of_buffers (void) { return nfc_cache_size; }
static int pktbuf_num_of_freebuf (void) { return nfc_cache_size - bufuse; }
static int pktbuf_count (void) { return bufuse; }

static struct netflow_cache_data_t * request (void) {
	int				i;

	if (bufuse == nfc_cache_size) return NULL; // buffer full

	i = front;
	front = (front + 1) % nfc_cache_size;

#ifdef HAVE_CONCURRENT_ACCESS
	pthread_mutex_lock (&mutex);
#endif
	bufuse++;
#ifdef HAVE_CONCURRENT_ACCESS
	pthread_mutex_unlock (&mutex);
#endif

        return &netf_key[i];
}

static struct netflow_cache_data_t * retrieve (void) {
        if (bufuse == 0) return NULL;

        if (netf_key[rear].buffer_ready == 0) return NULL;

        return &netf_key[rear];
}

static void bufready (struct netflow_cache_data_t *ptr) {
        ptr->buffer_ready = 1;
}

static void dequeue (struct netflow_cache_data_t *pkt) {
	int	i;

	if (bufuse > 0) {
		i = rear;
		netf_key[i].buffer_ready = 0;
		rear = (rear + 1) % nfc_cache_size;
#ifdef HAVE_CONCURRENT_ACCESS
		pthread_mutex_lock (&mutex);
#endif
		bufuse--;
#ifdef HAVE_CONCURRENT_ACCESS
		pthread_mutex_unlock (&mutex);
#endif
	}
}

static void pfb_close (void) {
        int     len;

        len = nfc_cache_size;
        nfc_cache_size = 0;
        front = rear = bufuse = 0;

        free (netf_key);
}

struct netflow_cache_t	*init_netflow_cache (const int cache_size) {
	int		i;

	if (nfcptr == NULL) {
		if ((netf_key = utils_calloc (cache_size,
			sizeof (struct netflow_cache_data_t))) == NULL) {
			return NULL;
		}

		nfc_cache_size = cache_size;
		front = rear = bufuse = 0;
		nfcptr = &nfc_instance;

		for (i = 0; i < nfc_cache_size; i++) {
			memset (&netf_key[i], 0,
				sizeof (struct netflow_cache_data_t));

			netf_key[i].flowkey.data = &netf_key[i].key;
			netf_key[i].flowkey.size =
					sizeof (struct netflow_key);
			netf_key[i].buffer_ready = 0;
		}

		

		nfcptr->request		= request;
		nfcptr->ready		= bufready;
		nfcptr->retrieve	= retrieve;
		nfcptr->dequeue		= dequeue;
		nfcptr->close		= pfb_close;
		nfcptr->num_of_buffers	= pktbuf_num_of_buffers;
		nfcptr->num_of_freebuf	= pktbuf_num_of_freebuf;
		nfcptr->count		= pktbuf_count;

		fprintf (logfp, "init_netflow_cache ok\n");
	}

	return nfcptr;
}
