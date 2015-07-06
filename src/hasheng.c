#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hasheng.h"

#define MAX_HASHING_ENGINE_NUM	10

static struct _hasheng_list {
	char		*signature;
	HASHENG		*implementation;
	int		refcnt;
} hasheng_list[MAX_HASHING_ENGINE_NUM];

static int	hasheng_idx = 0;
char		*HASHENG_err = NULL;


int HASHENG_regist_implementation (const char *sign, HASHENG *imp) {
	int	i;

	for (i = 0; i < hasheng_idx; i++) {
		if (strcmp (hasheng_list[i].signature, sign) == 0) {
			HASHENG_err = "signature already exists";
			return -1;
		}
	}

	if (i >= MAX_HASHING_ENGINE_NUM - 1) {
		HASHENG_err = "no space for new implementation";
		return -1;
	}

	hasheng_list[i].signature      = strdup (sign);
	hasheng_list[i].implementation = imp;
	hasheng_list[i].refcnt         = 0;
	hasheng_idx++;

	return i;
}

HASHENG* HASHENG_request_implementation (const char *sign) {
	HASHENG	*png = NULL;
	int	i;
	int	found = 0;

	if (sign == NULL) {
		for (i = 0; i < hasheng_idx; i++) {
			if (hasheng_list[i].refcnt == 0) {
				found = 1;
				break;
			}
		}
	} else {
		for (i = 0; i < hasheng_idx; i++) {
			if (strcmp (hasheng_list[i].signature, sign) == 0) {
				found = 1;
				break;
			}
		}
	}

	if (found) {
		png = hasheng_list[i].implementation;
		hasheng_list[i].refcnt++;
	}

	return png;
}

void HASHENG_init_hashing_engine (void) {
#ifdef linux
#endif
	init_hashing_engine_memory_hash ();
	// init_hashing_engine_berkeley_db ();
}
