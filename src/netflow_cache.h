/*
 *	netflow_cache.h
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#ifndef __NETFLOW_CACHE_H__
#define __NETFLOW_CACHE_H__

#include "ipnetflow.h"
#include "hasheng.h"

struct netflow_cache_data_t {
	struct netflow_key	key;
	DBDT			flowkey;
	int			len;
	short			buffer_ready;
};

struct netflow_cache_t {
	struct netflow_cache_data_t *	(*request)(void);       // for producer
	struct netflow_cache_data_t *	(*retrieve)(void);      // for consumer
	void				(*ready)(struct netflow_cache_data_t *);
	void				(*dequeue)
						(struct netflow_cache_data_t*);
	void				(*close)(void);
	int				(*count)(void);
	int				(*num_of_buffers)(void);
	int				(*num_of_freebuf)(void);
};

struct netflow_cache_t	*init_netflow_cache (const int cache_size);

#endif
