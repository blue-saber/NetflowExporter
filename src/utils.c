/*
 *	utils.c
 *
 *	Copyright (C) 2001-2004 Jiann-Ching Liu
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "utils.h"

#define NUM_OF_BUCKET	10

static u_char		anybuffer[NUM_OF_BUCKET][32];
static int		idx = 0;
static unsigned int	memuse = 0;

int utils_memuse (void) { return memuse; }

void* utils_calloc (size_t nmemb, size_t size) {
	void	*ptr;

	if ((ptr = calloc (nmemb, size)) != NULL) memuse += nmemb * size;

	return ptr;
}

void   * utils_malloc (size_t size) {
	void	*ptr;

	if ((ptr = malloc (size)) != NULL) memuse += size;

	return ptr;
}


int check_byte_ending (void) {
	char		buffer[4] = { 1, 2, 3, 4 };
	void		*vptr = buffer;
	u_int32_t	*iptr = (u_int32_t *) buffer;
	int		i, bsum, lsum;

	vptr += 3;

	if (*((char *) vptr) != buffer[3]) return 0;

	for (i = bsum = lsum = 0;  i < 4; i++) {
		bsum = (bsum * 256) + buffer[i];
		lsum = (lsum * 256) + buffer[3-i];
	}

	if (bsum == *iptr) {
		// fprintf (stderr, "big endian");
		return 1;
	} else if (lsum == *iptr) {
		// fprintf (stderr, "little endian");
		return -1;
	} else {
		return 0;
	}
}

u_char * print_ip (const u_char *ipstr) {
	idx = (idx + 1) % NUM_OF_BUCKET;

	sprintf (anybuffer[idx], "%u.%u.%u.%u",
			ipstr[0], ipstr[1], ipstr[2], ipstr[3]);

	return anybuffer[idx];
}

u_char * print_ether (const u_char *mac) {
	idx = (idx + 1) % NUM_OF_BUCKET;

	sprintf (anybuffer[idx], "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);

	return anybuffer[idx];
}

u_char * print_mac (const u_char *mac) {
	idx = (idx + 1) % NUM_OF_BUCKET;

	sprintf (anybuffer[idx], "%02x%02x%02x%02x%02x%02x",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);

	return anybuffer[idx];
}

u_char * timet_2_mysql_datetime (const time_t *ptr) {
	struct tm	*tptr = localtime (ptr);

	idx = (idx + 1) % NUM_OF_BUCKET;

	sprintf (anybuffer[idx], "%04d-%02d-%02d %02d:%02d:%02d",
			tptr->tm_year + 1900,
			tptr->tm_mon + 1,
			tptr->tm_mday,
			tptr->tm_hour,
			tptr->tm_min,
			tptr->tm_sec);

	return anybuffer[idx];
}

u_char * text2macaddr (const char *str, u_char *macaddr) {
	u_char		*ptr = macaddr;
	int		j, k, dot, len;
       
	len = strlen (str);

	for (j = dot = 0; j < len; j++) if (str[j] == ':') dot++;

	if ((dot != 0) && (dot != 5))  return NULL;
	if ((dot == 0) && (len != 12)) return NULL;


	if (ptr == NULL) {
		idx = (idx + 1) % NUM_OF_BUCKET;
		ptr = anybuffer[idx];
	}

	if (dot == 0) {
		for (k = 0; k < 6; k++) {
			for (j = k * 2, dot = 0; j < k * 2 + 2; j++) {
				dot *= 16;

				if ((str[j] >= '0') && (str[j] <= '9')) {
					dot += (str[j] - '0');
				} else if ((str[j] >= 'A') && (str[j] <= 'F')) {
					dot += ((str[j] - 'A') + 10);
				} else if ((str[j] >= 'a') && (str[j] <= 'f')) {
					dot += ((str[j] - 'a') + 10);
				} else {
					return NULL;
				}
			}

			ptr[k++] = dot;
		}
	} else {
		for (j = k = dot = 0; (j < len) && (k < 6); j++) {
			if ((str[j] >= '0') && (str[j] <= '9')) {
				dot *= 16;
				dot += (str[j] - '0');
			} else if ((str[j] >= 'A') && (str[j] <= 'F')) {
				dot *= 16;
				dot += ((str[j] - 'A') + 10);
			} else if ((str[j] >= 'a') && (str[j] <= 'f')) {
				dot *= 16;
				dot += ((str[j] - 'a') + 10);
			} else if (str[j] == ':') {
				ptr[k++] = dot;
				dot = 0;
			} else {
				printf ("%c character\n", str[j]);
				return NULL;
			}
		}
		if (k != 5) return NULL;
		ptr[k] = dot;
	}
	// printf ("ok: ether= %s\n", print_ether (ptr));

	return ptr;
}

int is_numeric_string (const char *str) {
	int	i, len;

	if (str == NULL) return 0;
	if ((len = strlen (str)) == 0) return 0;

	for (i = 0; i < len; i++) {
		if ((str[i] < '0') || (str[i] > '9')) return 0;
	}

	return 1;
}
