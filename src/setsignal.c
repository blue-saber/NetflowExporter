/*
 *	setsignal.h
 *
 *	Copyright (c) 2001-2004, Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>

#define MAX_NUMBER_OF_THREAD	(20)
#define MAX_SIGNAL_NUM		(32)

typedef void (*signalhandler)(int);

struct signal_mask {
	pthread_t	thread_id;
	signalhandler	handler[MAX_SIGNAL_NUM];
};

static pthread_mutex_t		mutex = PTHREAD_MUTEX_INITIALIZER;
static struct signal_mask	smask[MAX_NUMBER_OF_THREAD];
static int			smask_idx = 0;

static void void_signal_handler (int signo) {};

static void signal_handler (int signo) {
	pthread_t	thrid;
	int		i;

	thrid = pthread_self ();

/*
	if ((signo == SIGQUIT) || (signo == SIGINT)) {
		fprintf (stderr, "Thread id = %lu, signal = %d\n",
				(unsigned long) thrid, signo);
	}
*/

	for (i = 0; i < smask_idx; i++) {
		if (pthread_equal (smask[i].thread_id, thrid)) {
			if ((signo >= 0) && (signo < MAX_SIGNAL_NUM)) {
				smask[i].handler[signo] (signo);
			}
			return;
		}
	}
	return;
}

int setsignal (int signum, void (*sighandler)(int)) {
	int		i, j, found;
	pthread_t	thrid;

	if ((signum < 0) || (signum >= MAX_SIGNAL_NUM)) return 0;

	pthread_mutex_lock   (&mutex);

	thrid = pthread_self ();

	for (i = found = 0; i < smask_idx; i++) {
		if (pthread_equal (smask[i].thread_id, thrid)) {
			found = 1;
			break;
		}
	}

	if (! found) {
		if (smask_idx >= MAX_NUMBER_OF_THREAD - 1) {
			fprintf (stderr, "no space for new thread");
		} else {
			smask_idx++;

			smask[i].thread_id = thrid;

			for (j = 0; j < MAX_SIGNAL_NUM; j++) {
				smask[i].handler[j] = void_signal_handler;
			}
			found = 1;
		}
	}

	if (found) {
		smask[i].handler[signum] = sighandler;
		signal (signum, signal_handler);
	}

	pthread_mutex_unlock (&mutex);

	// fprintf (stderr, "setsignal (%d) %d\n", signum, found);

	return 1;
}
