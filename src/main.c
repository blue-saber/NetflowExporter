/*
 *	main.c
 *
 *	Copyright (C) 2001-2004 Jiann-Ching Liu
 */

#ifdef _REENTRANT
#define _REENTRANT
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <grp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <grp.h>
#include <sched.h>
#include <pthread.h>

#if HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "ipnetflow.h"
#include "global_var.h"
#include "cmdfcn.h"
#include "ipflowlist.h"
#include "pkteng.h"
#include "pktbuf.h"
#include "hasheng.h"
#include "utils.h"
#include "cmdlintf.h"
#include "netflow_cache.h"
#ifdef linux
#include "setproctitle.h"
#endif

#define MAX_NUM_OF_THREAD	25
// #define MAX_NETFLOW_THREAD	16

// #define DEFAULT_NETFLOW_ENTRY	5
#define USE_UNIX_DOMAIN_SOCKET	1

#ifdef DEBUG
int				debug_level	= 0;
#endif
char				*program_name	= NULL;
short				reloading	= 0;
int				verbose_flag	= 0;
volatile int			terminate	= 0;
struct netflow_list_t		*nflp		= NULL;
struct packet_buffer		*pktbf		= NULL;
struct cmdlintf_t		*clip		= NULL;
char				*listen_interface	= NULL;


pthread_t		all_threads[MAX_NUM_OF_THREAD];
static pthread_t	*netflow_thread;
static pthread_t	*netflow_cache_thread;
static pthread_t	*expire_thread;
static pthread_t	*packet_engine_thread;
static int		all_thr_idx = 0;
static char		*nettap_args[2] = { NULL, NULL };
static int		flow_entries = DEFAULT_NETFLOW_ENTRY;
static int		export_port = 0;
static char*		export_host = NULL;
static int		daemon_flag = 0;
static int		client_flag = 0;

static char		*pid_file  = "/var/run/netflow.pid";
static char		*sock_file = "/var/run/netflow.sock";
char			*conf_file = "/etc/netflow.conf";
static char		*log_file  = "/var/log/netflow.log";

static void signal_interrupt (int signo) {
	terminate = 1;
	if (clip != NULL) clip->terminate ();
	// fprintf (stderr, "Terminate !!\n");
}

static struct packet_buffer* (*init_packet_buffer)(const int number_of_buffer);

static void init_signal_handler (void) {
	signal    (SIGHUP,  SIG_IGN);
	// signal    (SIGCHLD, SIG_IGN);
	setsignal (SIGALRM, signal_interrupt);
	setsignal (SIGUSR1, signal_interrupt);
	setsignal (SIGUSR2, signal_interrupt);
	setsignal (SIGTERM, signal_interrupt);
	setsignal (SIGQUIT, signal_interrupt);
	setsignal (SIGINT , signal_interrupt);
}

static int initialize (int argc, char *argv[]) {
	char	*cp;

	program_name = ((cp = strrchr (argv[0], '/')) != NULL) ? cp+1 : argv[0];

	// fprintf (stderr, "Check machine\'s byte order: ");

	if (check_byte_ending () < 0) {
#if BYTE_ORDER == LITTLE_ENDIAN
		// fprintf (stderr, " ... good\r\n");
#else
		// fprintf (stderr, " ... error\r\n");
		exit (0);
#endif
	} else {
#if BYTE_ORDER == BIG_ENDIAN
		// fprintf (stderr, " ... good\r\n");
#else
		// fprintf (stderr, " ... error\r\n");
		exit (0);
#endif
	}

	init_signal_handler ();

	return 1;
}

static int init_cmdline_options (int argc, char *argv[]) {
	int		c, errflag = 0;

#if HAVE_GETOPT_LONG
	int		option_index = 0;
	struct option	long_options[] = {
		{ "verbose"			, 0, 0, 'v' },
		{ "daemon"			, 0, 0, 'D' },
		{ "client"			, 0, 0, 'c' },
		{ "engine"			, 1, 0, 'e' },
		{ "interface"			, 1, 0, 'i' },
		{ "active-timeout"		, 1, 0, 'T' },
		{ "inactive-timeout"		, 1, 0, 't' },
		{ "port"			, 1, 0, 'p' },
		{ "host"			, 1, 0, 'h' },
		{ "flow-entries"		, 1, 0, 'f' },
		{ "flow-version"		, 1, 0, 'V' },
		{ 0				, 0, 0, 0   }
	};
#endif

#if HAVE_GETOPT_LONG
	while (( c = getopt_long (argc, argv, "cDe:f:h:i:p:t:T:vV:",
					long_options, &option_index)) != EOF) 
#else
	while ((c = getopt (argc, argv, "cDe:f:h:i:p:t:T:vV:")) != EOF)
#endif
	{
		switch (c) {
		case 'D':
			daemon_flag = 1;
			break;
		case 'c':
			client_flag = 1;
			break;
		case 'p':
			export_port = atoi (optarg);
			break;
		case 'h':
			export_host = optarg;
			break;
		case 'V':
			netflow_pdu_version = atoi (optarg);
			break;
		case 't':
			inactive_timeout   = atoi (optarg);
			break;
		case 'T':
			active_timeout_min = atoi (optarg);
			break;
		case 'e':
			nettap_args[0] = optarg;
			break;
		case 'i':
			nettap_args[1] = optarg;
			break;
		case 'v':
			verbose_flag++;
			break;
		case 'f':
			flow_entries = atoi (optarg);

			if (flow_entries < DEFAULT_NETFLOW_ENTRY) {
				flow_entries = DEFAULT_NETFLOW_ENTRY;
			}

			break;
		case 0:
			exit (0);
			break;
		case '?':
		default:
			errflag++;
			break;
		}
	}

	if (errflag) {
		fprintf (stderr, "NetflowExporter version %s\n\n"
				"usage: netflow [-options]\n", VERSION);
#if HAVE_GETOPT_LONG
		fprintf (stderr,"\t--host=127.0.0.1\n"
				"\t--port=9991\n"
				"\t--flow-version=5\n"
				"\t--verbose\n"
				"\t--daemon\n"
				"\t--client\n"
				"\t--engine=pcap\n"
				"\t--interface=eth0\n"
				"\t--flow-entries=%d\n"
				"\t--active-timeout=10\n"
				"\t--inactive-timeout=30\n\n",
				DEFAULT_NETFLOW_ENTRY);
#else
		fprintf (stderr,"\t-h=127.0.0.1\n"
				"\t-p=9991\n"
				"\t-V=5\n"
				"\t-v\n"
				"\t-D\n"
				"\t-c\n"
				"\t-e=pcap\n"
				"\t-i=eth0\n"
				"\t-f=%d\n"
				"\t-T=10\n"
				"\t-t=30\n\n",
				DEFAULT_NETFLOW_ENTRY);
#endif
		return 0;
	}

	if (optind < argc) {
		if (strcmp ("start", argv[optind]) == 0) {
			daemon_flag = 1;
			client_flag = 0;
		} else if (strcmp ("stop", argv[optind]) == 0) {
			FILE	*fp;
			char	buffer[128];
			int	pid;

			if ((fp = fopen (pid_file, "r")) != NULL) {
				fgets (buffer, sizeof buffer - 1, fp);
				fclose (fp);

				buffer[sizeof buffer - 1] = '\0';
				pid = atoi (buffer);

				if (pid > 1) {
					/*
					fprintf (stderr, "Send signal to %d\n",
							pid);
					*/
					kill (pid, SIGTERM);
				}
			}

			exit (0);
		}
	}

	return 1;
}

static int chomp (char *buffer) {
	int	i, len;

	len = strlen (buffer);

	for (i = len - 1; i >= 0; i--) {
		if (buffer[i] == '\r' || buffer[i] == '\n') {
			buffer[len = i] = '\0';
		} else {
			break;
		}
	}
	return len;
}

static int load_command (const char *file) {
	FILE	*fp;
	char	buffer[256];

	if ((fp = fopen (conf_file, "r")) != NULL) {
		while (fgets (buffer, sizeof buffer -1, fp) != NULL) {
			chomp (buffer);
			if (buffer[0] == ';' || buffer[0] == '\0') continue;

			// fprintf (stderr, "[%s]\n", buffer);
			clip->execute (buffer, 1);
		}

		fclose (fp);

		return 1;
	}

	return 0;
}

void show_login (struct cmdlintf_t *cli) {
	cli->print ("NetflowExporter version " VERSION "\n");
}

/*
static void client_signal_handler (const int signo) {
	// fprintf (stderr, "client_signal_handler\n");
	fprintf (stderr, "Timeout");
	clip->execute ("quit", 1);
}
*/

static void client_terminate (const int signo) {
	fprintf (stderr, "\n\n********** Timeout ***********\n");
	execlp ("stty", "stty", "echo", NULL);
	exit (0);
}

static void run_as_client (int argc, char *argv[], char *env[]) {
	// signal (SIGALRM, client_signal_handler);
#ifdef linux
	initsetproctitle (argc, argv, env);
	setproctitle ("client");
#endif
	signal (SIGALRM, client_terminate);
	signal (SIGHUP,  SIG_DFL);
	signal (SIGINT,  SIG_DFL);
	signal (SIGTERM, SIG_DFL);
	signal (SIGQUIT, SIG_DFL);

	clip->start (0);

	while (clip->cli () != 0);

	exit (0);
}

int main (int argc, char *argv[], char *env[]) {
	sigset_t        sigs_todo;
	int		i;
	int		nmargs[MAX_NETFLOW_THREAD];
	struct group	*grp;
	int		my_umask = 022;
	int		euid;

	euid = geteuid ();

#ifdef linux
	// initsetproctitle (argc, argv, env);
#endif
	initialize (argc, argv);

	if (! init_cmdline_options (argc, argv)) exit (1);

	if (access (sock_file, F_OK) == 0) {
		client_flag = 1;
		if (daemon_flag) {
			fprintf (stderr, "%s: exists !!\n", sock_file);
			exit (1);
		}
	} else {
		if (client_flag) {
			fprintf (stderr, "%s: not exists !!\n", sock_file);
			exit (1);
		}
	}
	
	if ((clip = init_cmdline_interface (81920)) == NULL) exit (1);


	regist_commands ();

	clip->socket_name (sock_file);
	clip->set_login_callback (show_login);

	{
		char	hname[64];
		char	prompt[128];

		if (gethostname (hname, sizeof hname - 1) < 0) {
			clip->set_prompt ("netflow> ");
		} else {
			char	*ptr;

			if ((ptr = strchr (hname, '.')) != NULL) *ptr = '\0';

			sprintf (prompt, "%s::netflow> ", hname);
			clip->set_prompt (prompt);
		}
	}

	// show_version (clip, NULL);

	if ((grp = getgrnam ("netflow")) != NULL) {

		my_umask = 002;
		setregid (grp->gr_gid, grp->gr_gid);
	}

	if (client_flag) {
		if (euid != 0) {
			gid_t	list[32];
			int	i, num;
			int	found = 0;

			if (grp != NULL) {
				if ((num = getgroups (32, list)) > 0) {
					for (i = 0; i < num; i++) {
						if (grp->gr_gid == list[i]) {
							found = 1;
							break;
						}
					}
				}
			}

			if (! found) {
				fprintf (stderr, "Permission deny\n");
				exit (1);
			}
		}

		run_as_client (argc, argv, env);
	}

	if (euid != 0) {
		fprintf (stderr, "root privilege required !\n");
		exit (1);
	}

	switch (fork ()) {
	case 0: // child
		break;
	case -1: // failed
		perror ("fork");
		exit (1);
		break;
	default:
		if (! daemon_flag) {
			int	i, ok;

			for (i = ok = 0; i < 10; i++) {
				if (access (sock_file, F_OK) == 0) {
					ok = 1;
					break;
				}
				sleep (1);
			}

			if (ok) run_as_client (argc, argv, env);
		}
		exit (0);
	}


	switch (packet_buffer_engine_version) {
	case 2:
		init_packet_buffer = init_packet_buffer_v2;
		break;
	case 1:
	default:
		init_packet_buffer = init_packet_buffer_v1;
		break;
	}

	// if (client_flag) return unix_domain_socket_client ();

	load_command (conf_file);


	if (nettap_args[1] == NULL) nettap_args[1] = listen_interface;

	setsid ();
	chdir ("/");
	umask (my_umask);
	close (0);
	close (1);

	{
		FILE	*fp;

		if ((fp = fopen (pid_file, "w")) != NULL) {
			fprintf (fp, "%d\n", getpid ());
			fclose (fp);
		}
	}

	if ((logfp = fopen (log_file, "a")) == NULL) {
		logfp = stderr;
	} else {
		time_t		now;

		close (2);

		now = time (NULL);
		fprintf (logfp,
			"=================================================="
			"================\n"
			"NetflowExporter Version %s, %s"
			"--------------------------------------------------"
			"----------------\n",
			VERSION, ctime (&now)
		);
	}

	if ((nflp = init_netflow_list (
				netflow_pdu_version,
				flow_entries,
				active_timeout_min, inactive_timeout,
				export_host, export_port)) == NULL) {
		fprintf (logfp, "%s:%d Init netflow list failed !!\n",
				__FILE__, __LINE__);
		exit (1);
	}

	if ((pktbf = init_packet_buffer (packet_buf_size)) == NULL) {
		fprintf (logfp, "%s:%d Init packet buffer failed!!\n",
				__FILE__, __LINE__);
		exit (1);
	}

	// netflow_cache_size = packet_buf_size;

#if ENABLE_FLOW_CACHE_BUFFER == 1
	if ((nfcb = init_netflow_cache (netflow_cache_size)) == NULL) {
		fprintf (logfp, "%s:%d Init netflow cache failed!!\n",
				__FILE__, __LINE__);
		exit (1);
	}
#endif

	sigemptyset (&sigs_todo);
	sigaddset   (&sigs_todo, SIGUSR1);
	sigaddset   (&sigs_todo, SIGTERM);
	sigaddset   (&sigs_todo, SIGINT);
	sigaddset   (&sigs_todo, SIGQUIT);

	all_threads[all_thr_idx++] = pthread_self ();

	{
		pthread_attr_t		tattr;
		struct sched_param	schedp;
		int			sched_min, sched_max;

		sched_max = sched_get_priority_max (SCHED_FIFO);
		sched_min = sched_get_priority_min (SCHED_FIFO);
		// SCHED_FIFO, SCHED_RR, and SCHED_OTHER

		pthread_attr_init (&tattr);

		schedp.sched_priority = sched_max;

#if PKTBUF_ENABLE_MULTIPLE_CONSUMMER == 0
		num_of_netflow_engine = 1;
#endif
		for (i = 0; i < num_of_netflow_engine; i++) {
			if (i >= MAX_NETFLOW_THREAD) break;

			netflow_thread = &all_threads[all_thr_idx];

			nmargs[i] = i;
			pthread_create (&all_threads[all_thr_idx++],
				NULL, netflow_main, &nmargs[i]);
		}

#if ENABLE_FLOW_CACHE_BUFFER == 1
		netflow_cache_thread = &all_threads[all_thr_idx];
		pthread_create (&all_threads[all_thr_idx++],
				NULL, netflow_cache_main, NULL);
#endif
		pthread_attr_setschedpolicy (&tattr, SCHED_FIFO);
		pthread_attr_setschedparam  (&tattr, &schedp);

		// pthread_create (&all_threads[all_thr_idx++],
		//		&tattr, (void *) nettap_main , nettap_args);

		packet_engine_thread = &all_threads[all_thr_idx];
		pthread_create (&all_threads[all_thr_idx++],
				NULL, (void *) nettap_main , nettap_args);

		fprintf (logfp, "nettap_main: ok(%d)\n", all_thr_idx);
		fflush (logfp);

		expire_thread = &all_threads[all_thr_idx];
		pthread_create (&all_threads[all_thr_idx++],
				NULL, (void *) expire_flow_main, NULL);

		fprintf (logfp, "expire_flow_main: ok\n");
		fflush (logfp);

		// pthread_setconcurrency (all_thr_idx);
	}

	// setproctitle ("running");

	if (clip->start (1) == 1) {
		fprintf (logfp, "Netflow: CLI Terminate\n");
	}

	terminate = 1;

	pthread_kill (*expire_thread,        SIGTERM); usleep (1);
	pthread_kill (*netflow_thread,       SIGTERM); usleep (1);
	pthread_kill (*netflow_cache_thread, SIGTERM); usleep (1);

	nettap_terminate = 1;

	for (i = 1; i < all_thr_idx; i++) pthread_kill (all_threads[i],SIGTERM);

	for (i = 0; i < num_of_netflow_engine; i++) {
		netflow_wakeup (NULL, 0);
		usleep (1);
	}

	// pthread_kill_other_threads_np ();

	// fprintf (logfp, "Netflow: Terminate\n");

	// fprintf (stderr, "Thread:");
	for (i = 1; i < all_thr_idx; i++) {
		// fprintf (stderr," %lu", all_threads[i]);
		pthread_join (all_threads[i], NULL);
	}
	// fprintf (stderr, "\n");

	pktbf->close ();
	nflp->close ();

	fprintf (logfp, "Netflow: Terminated\n"
			"-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
			"-=-=-=-=-=-=-=-=\n"
	);

	fclose (logfp);
	unlink (pid_file);

	if (reloading) execlp (argv[0], argv[0], "start", NULL);

	return 0;
}
