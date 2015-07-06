/*
 *	cmdfcn.c
 *
 *	Copyright (C) 2001-2004 Jiann-Ching Liu
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "ipnetflow.h"
#include "global_var.h"
#include "ipflowlist.h"
#include "cmdlintf.h"
#include "cmdfcn.h"
#include "utils.h"
#include "pktbuf.h"

static int show_packet_buffer (struct cmdlintf_t *cli, char *cmd) {
	cli->print ("Packet Buffer %d, %d free\n",
			pktbf->num_of_buffers (),
			pktbf->num_of_freebuf ());
	return 1;
}

static int show_config (struct cmdlintf_t *cli, char *cmd) {
	if ((nflp != NULL) && (nflp->show_config != NULL)) {
		nflp->show_config (NULL);
	}
	return 1;
}

static int listen_on_interface (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		if (listen_interface != NULL) free (listen_interface);

		listen_interface = strdup (cmd);
	}

	return 1;
}

static int cmd_write (struct cmdlintf_t *cli, char *cmd) {
	FILE	*fp;

	// umask (022);

	if ((fp = fopen (conf_file, "w")) != NULL) {
		if ((nflp != NULL) && (nflp->show_config != NULL)) {
			nflp->show_config (fp);
		}
		fclose (fp);

		clip->print ("Write %s [OK]\n", conf_file);
	} else {
		clip->print ("Write %s [%s]\n", conf_file, strerror (errno));
	}

	return 1;
}

static int show_memory (struct cmdlintf_t *cli, char *cmd) {
	int	bytes;
	float	mbytes;

	bytes = utils_memuse ();
	mbytes = (float) bytes / 1024.0 / 1024.0;

	clip->print ("Memory usage: %d bytes (%.2f Mbytes)\n",
			bytes, mbytes);

	return 1;
}

static int show_version (struct cmdlintf_t *cli, char *cmd) {
	int	(*printer)(const char *fmt, ...) = printf;

	if (clip != NULL) {
		printer = clip->print;
	}

	printer ("\n"
		"NetflowExporter Version %s   "
		"Copyright (c) 2001-2004 Jiann-Ching Liu\n"
//		"\n"
//		"NetflowExporter is written by "
//		"Jiann-Ching Liu "
//		"at Computer Center of NCU.\n"
		"\n",
		VERSION);

	return 1;
}

static int cmd_logout (struct cmdlintf_t *cli, char *cmd) {
	cli->print ("Exit\n");
	return 0;
}

static int cmd_reload (struct cmdlintf_t *cli, char *cmd) {
	cli->terminate ();
	cli->print ("Reload\n");
	reloading = 1;
	return 0;
}

static int cmd_echo (struct cmdlintf_t *cli, char *cmd) {
	cli->print ("%s\n", cmd != NULL ? cmd : "");
	return 1;
}

static int cmd_date (struct cmdlintf_t *cli, char *cmd) {
	time_t	now;

	now = time (NULL);
	cli->print ("%s", ctime (&now));
	return 1;
}

static int set_packet_buffer_engine_version (
					struct cmdlintf_t *cli, char *cmd) {
	// packet_buffer_engine_version;

	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 0 || i > 2) {
			cli->print ("%% out of range (1 ~ 2)\n");
		} else {
#if ENABLE_PACKET_BUFFER_ENGINE_VERSION == 1
			packet_buffer_engine_version = i;
#else
			cli->print ("%% Not support\n");
#endif
		}
	}

	return 1;
}

static int ip_flow_sampling (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 0 || i > 10000) {
			cli->print ("%% out of range (1 ~ 10000)\n");
		} else {
			ip_flow_sampling_rate = i;
		}
	}

	return 1;
}

static int set_netflow_engine_instance (struct cmdlintf_t *cli, char *cmd) {
	//num_of_netflow_engine
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 0 || i > MAX_NETFLOW_THREAD) {
			cli->print ("%% out of range (1 ~ %d)\n",
					MAX_NETFLOW_THREAD);
		} else {
#if ENABLE_NETFLOW_ENGINE_INSTANCE == 1
			num_of_netflow_engine = i;
#else
			cli->print ("%% Not support\n");
#endif
		}
	}

	return 1;
}

static int set_idle_timeout (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int     i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 0 || i > 60) {
			cli->print ("%% out of range (0 ~ 60)\n");
		} else {
			idle_timeout = i;
			cli->set_timeout (idle_timeout * 60);
		}
	}

	return 1;
}

static int set_cache_buffer_entries (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int     i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 1000) i = 1000;

		netflow_cache_size = i;
	}

	return 1;
}

static int set_packet_buffer_entries (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int     i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (i < 1000 || i > DEFAULT_PACKET_BUFFER * 1000) {
			cli->print ("%% out of range (%d ~ %d)\n",
					1000,
					DEFAULT_PACKET_BUFFER * 1000);
		} else {
			packet_buf_size = i;
		}
	}

	return 1;
}

static int set_hash_buffer_entries (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int     i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
				cmd);
			return 1;
		}

		i = atoi (cmd);

		if (flow_cache_entries == 0) {
			hash_entries = i < 100 ? 100 : i;
		} else if (i < flow_cache_entries ||
					i > flow_cache_entries * 1000) {
			cli->print ("%% out of range (%d ~ %d)\n",
					flow_cache_entries,
					flow_cache_entries * 1000);
		} else {
			hash_entries = i;
		}
	}

	return 1;
}

#ifdef DEBUG
static int set_debug_on (struct cmdlintf_t *cli, char *cmd) {
	debug_level = 1;
	cli->print ("Debug on\n");
	return 1;
}

static int set_debug_off (struct cmdlintf_t *cli, char *cmd) {
	debug_level = 0;
	cli->print ("Debug off\n");
	return 1;
}
#endif


int show_configuration (FILE *fp) {
	time_t	now;

	now = time (NULL);

	if (fp != NULL) {
		fprintf (fp,
			"; NetflowExporter Version %s\n"
			"; Copyright (c) 2001-2004 Jiann-Ching Liu,"
			" all rights reserved.\n"
			";\n"
			"; NetflowExporter Configuration, %s"
			";\n",
			VERSION, ctime (&now));

		if (listen_interface != NULL) {
			fprintf (fp,
				"listen on %s\n"
				";\n", listen_interface);
		}

		fprintf (fp,
			"set idle timeout %d\n"
#if ENABLE_PACKET_BUFFER_ENGINE_VERSION == 1
			"set packet buffer engine version %d\n"
#endif
			"set packet buffer entries %d\n"
			"set hash buffer entries %d\n"
			"set netflow cache entries %d\n"
#if ENABLE_NETFLOW_ENGINE_INSTANCE == 1
			"set netflow engine instance %d\n"
#endif
			";\n",
			idle_timeout,
#if ENABLE_PACKET_BUFFER_ENGINE_VERSION == 1
			packet_buffer_engine_version,
#endif
			packet_buf_size, hash_entries,
			netflow_cache_size
#if ENABLE_NETFLOW_ENGINE_INSTANCE == 1
			, num_of_netflow_engine
#endif
		);

		fprintf (fp,
			"ip flow-export version %d\n", netflow_pdu_version);

		if (flow_export_host != NULL) {
			fprintf (fp, "ip flow-export destination %s %d\n",
				flow_export_host,
				flow_export_port);
		}

		fprintf (fp,
			";\n"
			"ip flow-cache entries %d\n"
			";\n"
			"ip flow-cache timeout active %d\n"
			"ip flow-cache timeout inactive %d\n"
			";\n"
			"%s ip flow-export\n",
			flow_cache_entries,
			active_timeout_min,
			inactive_timeout,
			(enable_flow_export ? "enable" : "disable")
		);
	} else {
		clip->print (
			";\n"
			"; Current configuration for NetflowExporter\n"
			";\n");
		if (listen_interface != NULL) {
			clip->print (
				"listen on %s\n"
				";\n", listen_interface);
		}

		clip->print (
			"set idle timeout %d\n"
#if ENABLE_PACKET_BUFFER_ENGINE_VERSION == 1
			"set packet buffer engine version %d\n"
#endif
			"set packet buffer entries %d\n"
			"set hash buffer entries %d\n"
			"set netflow cache entries %d\n"
#if ENABLE_NETFLOW_ENGINE_INSTANCE == 1
			"set netflow engine instance %d\n"
#endif
			";\n",
			idle_timeout,
#if ENABLE_PACKET_BUFFER_ENGINE_VERSION == 1
			packet_buffer_engine_version,
#endif
			packet_buf_size, hash_entries,
			netflow_cache_size
#if ENABLE_NETFLOW_ENGINE_INSTANCE == 1
			, num_of_netflow_engine
#endif
		);

		clip->print (
			"ip flow-export version %d\n", netflow_pdu_version);

		if (flow_export_host != NULL) {
			clip->print ("ip flow-export destination %s %d\n",
				flow_export_host,
				flow_export_port);
		}

		clip->print (
			";\n"
			"ip flow-cache entries %d\n"
			";\n"
			"ip flow-cache timeout active %d\n"
			"ip flow-cache timeout inactive %d\n"
			";\n"
			"%s ip flow-export\n",
			flow_cache_entries,
			active_timeout_min,
			inactive_timeout,
			(enable_flow_export ? "enable" : "disable")
		);
	}

	return 1;
}

/*
int show_flow (struct cmdlintf_t *cli, char *cmd) {
	// nflist.listall ();
	return 1;
}
*/

#if 0
int show_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	time_t		now;
	long		difft;
       	int		d, m, h, s;
	// int		mbits, usedbits;

	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
		return 1;
	}

	// mbits = iphash->max_bits;
	// for (usedbits = 0; mbits != 0; usedbits++) mbits >>= 1;

	now = time (NULL);
	difft = (long) difftime (now, startup_timet);

	cli->print (
		"Exporting flows to %s (%d)\n"
		"Version %d flow records\n"
		"Flow exporting: %s\n"
		"%llu flows exported in %llu udp datagrams\n"
		"%llu byte flow data exported\n"
		"%llu active exported, %llu inactive exported\n"
		"%lu udp datagrams dropped on failed, "
		"%lu packets dropped on expire\n"
		"%lu flows dropped on buffer full\n"
		"ip flow-cache entries %d, %u in-use, %u maximum use\n"
		"ip flow-cache timeout active %d minute(s), "
		"inactive %d second(s)\n"
		"%llu packets received, %llu packets dropped\n"
		"%llu octets received, %llu octets dropped\n"
		"maximum %d buckets used in hashing\n"
		"System boot on: %s"
		"System up time:",
		(flow_export_host == NULL ? "(not set)" : flow_export_host),
		flow_export_port,
		netflow_pdu_version,
		(enable_flow_export ? "enable" : "disable"),
		flow_exports, exported_datagram,
		octet_exports,
		active_exports, inactive_exports,
		failed_datagram, concurrent_drop,
		bufferfull_cnt,
		netflow_list_len, 
		(netflow_list_len - netflow_free_count - 1),
		(netflow_list_len - netflow_free_min - 1),
		active_timeout_min, inactive_timeout,
		pkteng->pkt_received (),
		pkteng->pkt_dropped (),
		pkteng->octet_received (),
		pkteng->octet_dropped (),
		*iphash->max_bits + 1,
		ctime (&startup_timet));

	d = difft / 86400; difft %= 86400;
	h = difft /  3600; difft %=  3600;
	m = difft /    60;
	s = difft %    60;

	if (d > 0) cli->print (" %d day(s)", d);

	cli->print (" %02d:%02d:%02d\n", h, m, s);

	return 1;
}
#endif

int ip_flow_export_version (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
		return 1;
	} else {
		int	i;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
					cmd);
			return 1;
		}

		switch (i = atoi (cmd)) {
		case 1:
			netflow_pdu_version = 1;
			break;
		case 5:
			netflow_pdu_version = 5;
			break;
		case 7:
			cli->print ("%% Version %d no implement\n", i);
			break;
		default:
			cli->print ("%% Invalid version support: %d\n", i);
			break;
		}
	}

	return 1;
}

int ip_flow_cache_timeout_active (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
		return 1;
	} else {
		int	num;

		if (! is_numeric_string (cmd)) {
			cli->print ("%% Invalid input detected: \"%s\"\n",
					cmd);
			return 1;
		}

		num = atoi (cmd);

		if ((num >= MIN_ACTIVE_TIMEOUT_MIN) &&
				(num <= MAX_ACTIVE_TIMEOUT_MIN)) {
			active_timeout_min = num;
			active_timeout = num * 60;
		} else {
			cli->print ("%% out of range (%d ~ %d)\n",
					MIN_ACTIVE_TIMEOUT_MIN,
					MAX_ACTIVE_TIMEOUT_MIN);
		}
	}
	return 1;
}

int ip_flow_cache_timeout_inactive (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
		return 1;
	} else {
		int	num;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
					cmd);
			return 1;
		}

		num = atoi (cmd);

		if ((num >= MIN_INACTIVE_TIMEOUT) &&
				(num <= MAX_INACTIVE_TIMEOUT)) {
			inactive_timeout = num;
		} else {
			cli->print ("%% out of range (%d ~ %d)\n",
					MIN_INACTIVE_TIMEOUT,
					MAX_INACTIVE_TIMEOUT);
		}
	}
	return 1;
}

#if 0
int enable_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ( "%% Invalid input detected: \"%s\"\n", cmd);
	} else if (sockfd >= 0) {
		enable_flow_export = 1;
	} else {
		cli->print ("%% Unable to export flow to %s (%d)\n",
				(flow_export_host == NULL ? "(not set)"
				 			: flow_export_host),
				flow_export_port);
	}

	return 1;
}

int disable_ip_flow_export (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
	} else {
		// cli->print ("disable ip flow export\n");
		enable_flow_export = 0;
	}

	return 1;
}
#endif

int ip_flow_cache_entries (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	num;

		if (! is_numeric_string (cmd)) {
			cli->print ( "%% Invalid input detected: \"%s\"\n",
					cmd);
			return 1;
		}

		num = atoi (cmd);

		if ((num >= DEFAULT_NETFLOW_ENTRY) &&
				(num <= DEFAULT_NETFLOW_ENTRY * 1000)) {
			flow_cache_entries = num;
		} else {
			cli->print ("%% out of range (%d ~ %d)\n",
					DEFAULT_NETFLOW_ENTRY,
					DEFAULT_NETFLOW_ENTRY * 1000);
		}
	}

	// netflow_list_len;
	// flow_cache_entries 
	return 1;
}

#if 0
int ip_flow_export_destination (struct cmdlintf_t *cli, char *cmd) {
	if (cmd == NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		int	i, len, port = 0;
		char	*host = NULL;

		len = strlen (cmd);

		for (i = 0; i < len; i++) {
			if ((cmd[i] == ' ') || (cmd[i] == '\t')) {
				if (i > 0) {
					host = utils_malloc (i + 1);
					strncpy (host, cmd, i);
					host[i] = '\0';
					break;
				}
			}
		}

		for (; i < len; i++) {
			if ((cmd[i] == ' ') || (cmd[i] == '\t')) {
			} else {
				break;
			}
		}

		if (is_numeric_string (&cmd[i])) port = atoi (&cmd[i]);

		if (port <= 0 || port >= 65536) {
			if (host != NULL) {
				free (host);
				host = NULL;
			}
		}

		if (host == NULL) {
			cli->print ("%% Invalid input detected: \"%s\"\n",
					cmd);
		} else {
			i = enable_flow_export;

			disable_ip_flow_export (cli, NULL);

			if (flow_export_host != NULL) free (flow_export_host);
			flow_export_host = host;
			flow_export_port = port;

			netflow_export_udp_datagram_initialize ();

			if (i) enable_ip_flow_export (cli, NULL);
		}
	}

	return 1;
}
#endif

int show_state (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Incomplete command\n");
	} else {
		char	*state = "<option not activated>";

#if ENABLE_MONITOR_NETFLOW_CACHE == 1
		switch (netflow_cache_state) {
		case 0:
			state = "init";
			break;
		case 1:
			state = "running";
			break;
		case 2:
			state = "set entry";
			break;
		case 3:
			state = "dequeue";
			break;
		case 4:
			state = "wait";
			break;
		case 5:
			state = "wakeup";
			break;
		case 6:
			state = "exit";
			break;
		case 7:
			state = "terminate";
			break;
		}
#endif
		cli->print ("System State\n"
			"Netflow cache thread state: %s\n",
			state
		);
	}

	return 1;
}


void regist_commands (void) {
	clip->regcmd ();

	clip->add ("write", 1, cmd_write, "Write configuire", 0, 1);
	clip->add ("reload", 1, cmd_reload, "Reload", 0, 2);
#ifdef DEBUG
	clip->add ("set debug on", 1, set_debug_on, "", 0, 0);
	clip->add ("set debug off", 1, set_debug_off, "", 0, 0);
#endif
	clip->add ("show state", 1, show_state, "Show state", 0, 0);

	clip->add ("clear counter", 1, clear_counter, "Cleater Counter", 0, 0);

	clip->add ("set packet buffer engine version", 1,
				set_packet_buffer_engine_version,
				"Set packet buffer engine version", 1, 1);
	clip->add ("set packet buffer entries", 1,
				set_packet_buffer_entries,
				"Packet Buffer Entries", 1, 1);
	clip->add ("set hash buffer entries", 1,
				set_hash_buffer_entries,
				"Hash buffer entries", 1, 1);
	clip->add ("set idle timeout ", 1,
				set_idle_timeout,
				"Set Idle timeout", 1, 1);
	clip->add ("set netflow cache entries", 1,
				set_cache_buffer_entries,
				"Cache buffer Entries", 1, 1);
	clip->add ("set netflow engine instance", 1,
				set_netflow_engine_instance,
				"Set Netflow Engine Instance", 1, 1);
	clip->add ("show packet buffer", 1,
				show_packet_buffer,
				"Show packet buffer information", 0, 0);
	clip->add ("show copyright", 1, show_copyright, "Show Copyright", 0, 0);
	clip->add ("show version", 1, show_version, "Show Version", 0, 1);
	clip->add ("show memory" , 1, show_memory , "Show Memory", 0, 1);
	clip->add ("show configuration", 1, show_config,
				"Show Configuration", 0, 1);

	// clip->add ("show flow", 1, show_flow, "Show flow", 0, 0);

	clip->add ("show ip cache flow", 1, show_ip_cache_flow,
			"flow cache entries", 0, 1);

	clip->add ("show ip flow export", 1, show_ip_flow_export,
			"Display IP flow export information", 0, 1);

	clip->add ("ip flow-sampling-mode packet-interval", 1, ip_flow_sampling,
			"IP flow sampling", 1, 1);

	clip->add ("ip flow-export version", 1, ip_flow_export_version,
			"1,5 : Set flow-export version", 1, 1);

	clip->add ("ip flow-cache timeout active", 1,
			ip_flow_cache_timeout_active,
			"n : Set active timeout (in minutes)", 1, 1);

	clip->add ("ip flow-cache timeout inactive", 1,
			ip_flow_cache_timeout_inactive,
			"n : Set inactive timeout (in seconds)", 1, 1);

	clip->add ("ip flow-cache entries", 1,
			ip_flow_cache_entries,
			"n : Number of cache entries", 1, 1);

	clip->add ("ip flow-export destination", 1,
			ip_flow_export_destination,
			"[ip] [port] : Set export destination", 2, 1);

	clip->add ("enable ip flow-export", 1,
			enable_ip_flow_export,
			"Enable IP-flow Export", 0, 1);

	clip->add ("disable ip flow-export", 1,
			disable_ip_flow_export,
			"Disable IP-flow Export", 0, 1);

	clip->add ("listen on", 1, listen_on_interface,
			"Setting interface to listen", 0, 1);


	clip->add ("show packet engine", 1, show_packet_engine, "", 0, 1);

	clip->add ("exit", 1, cmd_logout, "", 0, 1);
	clip->add ("echo", 0, cmd_echo, "", 0, 1);
	clip->add ("date", 1, cmd_date, "", 0, 1);

}
