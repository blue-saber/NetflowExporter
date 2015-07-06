#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/ucd-snmp-agent-includes.h>
#include <ucd-snmp/agent_trap.h>
#include <ucd-snmp/snmp_alarm.h>
#include <ucd-snmp/read_config.h>
#include <ucd-snmp/version.h>

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "ipnetflow.h"
/*
#include "netflow.h"
#include "netflow_db.h"
#include "parser.h"
#include "utils.h"
#include "todo.h"
*/

#define DEBUG			0

#define SNMP_DEFAULT_PORT	161
#define TIMETICK		500000L
#define ONE_SEC			1000000L

#define NETFLOW_SNMP_OID	SNMP_OID_ENTERPRISES, 90125, 1
#define NETFLOW_NAME_LENGTH	(9)

#define NETFLOW_SNMP_VERSION	 1
#define NETFLOW_SNMP_CONTACT	 2
#define NETFLOW_SNMP_SYSNAME	 3

#define NETFLOW_SNMP_DB_RELOAD  5

#define NETFLOW_SNMP_TEST	 9


int	snmp_thread_data_write_and_clear = 0;
int	snmp_reconfig = 0;
oid	netflow_variables_oid[] = { NETFLOW_SNMP_OID };

extern int	init_system_mib   (void);
extern int	init_vacm_vars    (void);

#define NETFLOW_SYSNAME_LEN	256

static char	netflow_version[NETFLOW_SYSNAME_LEN];
static char	netflow_contact[NETFLOW_SYSNAME_LEN];
static char	netflow_sysname[NETFLOW_SYSNAME_LEN];
static char	netflow_reserved_buffer[NETFLOW_SYSNAME_LEN];

u_char	ipaddr[4] = { 140, 115, 1, 254 };

WriteMethod writeSNMP;
WriteMethod writeSNMP_integer;
u_char  *var_netflow (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method);
u_char  *var_testing (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method);
u_char  *var_sysinfo (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method);
u_char  *var_confsys (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method);

/*
    u_char          magic;          // passed to function as a hint
    u_char          type;           // type of variable
    u_short         acl;            // access control list for variable
    FindVarMethod  *findVar;        // function that finds variable
    u_char          namelen;        // length of name below
    oid             name[2];        // object identifier of variable
 */

struct variable2 netflow_variables[] = {
//	{ SNMP_GET_MAC_IP   , ASN_IPADDRESS, RWRITE, var_netflow, 1, {1}}
    { NETFLOW_SNMP_VERSION  , ASN_OCTET_STR, RONLY , var_sysinfo , 1, { 1}},
    { NETFLOW_SNMP_CONTACT  , ASN_OCTET_STR, RONLY , var_sysinfo , 1, { 2}},
    { NETFLOW_SNMP_SYSNAME  , ASN_OCTET_STR, RWRITE, var_sysinfo , 1, { 3}},
    { NETFLOW_SNMP_DB_RELOAD, ASN_INTEGER  , RWRITE, var_confsys , 1, { 5}},
    { NETFLOW_SNMP_TEST     , ASN_IPADDRESS, RONLY , var_netflow, 1, { 9}},
//	{ SYSCONTACT        , ASN_OCTET_STR, RWRITE, var_system  , 1, {4}}
};

static void init_netflow_mib (void) {
	sprintf (netflow_version, "NetflowExporter version %s", VERSION);
	sprintf (netflow_contact, "center5@cc.ncu.edu.tw");
	sprintf (netflow_sysname, "NetflowExporter");

	REGISTER_MIB ("", netflow_variables,
					variable2,
					netflow_variables_oid);
}

#if DEBUG
static void print_oid ( oid *name, size_t length) {
	int	i = 0;

	for (i = 0; i < length; i++) {
		printf (".%lu", name[i]);
	}

	printf ("\n");
}
#endif

/*
  header_system(...
  Arguments:
  vp      IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method


  .1.3.6.1.4.1.90125.1.1

*/

int
header_netflow (
		struct variable	*vp,
		oid		*name,
		size_t		*length,
		int		exact,
		size_t		*var_len,
		WriteMethod	**write_method ) {

	oid	newname[MAX_OID_LEN];
	int	result;


	memcpy ((char *) newname, (char *) vp->name,
						vp->namelen * sizeof (oid));

	newname[NETFLOW_NAME_LENGTH] = 0;
	result = snmp_oid_compare (name, *length,
					newname, vp->namelen + 1);



	if ((exact && (result != 0)) || (!exact && (result >= 0)))
		return MATCH_FAILED;


#if DEBUG
	if (exact) {		// for snmpget
		printf ("exact %d\n", vp->namelen);
	} else {		// for snmpwalk
		printf ("not exact %d\n", vp->namelen);
	}
#endif

	memcpy ((char *) name, (char *) newname,
					(vp->namelen + 1) * sizeof(oid));

	*length = vp->namelen + 1;
	*write_method = 0;
	*var_len = sizeof (long);	/* default to 'long' results */

	return MATCH_SUCCEEDED;
}

u_char *var_netflow (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method) {
	
	if (header_netflow (vp, name, length, exact,
				var_len, write_method) == MATCH_FAILED) {
		return NULL;
	}

	switch (vp->magic) {
	//case NETFLOW_SNMP_MAC_IP:
		// *write_method = writeSNMP;
	//	return ipaddr;
	//case NETFLOW_SNMP_IP_MAC:
	case NETFLOW_SNMP_TEST:
		return ipaddr;
	default:
		break;
	}

#if DEBUG
	fprintf (logfp, "%d\n", vp->magic);
#endif
	return NULL;
}

int
header_sysinfo (
		struct variable	*vp,
		oid		*name,
		size_t		*length,
		int		exact,
		size_t		*var_len,
		WriteMethod	**write_method ) {

	oid	newname[MAX_OID_LEN];
	int	result;

	memcpy ((char *)newname, (char *)vp->name, vp->namelen * sizeof(oid));

	newname[vp->namelen] = 0;
	result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);

	if ((exact && (result != 0)) || (!exact && (result >= 0)))
		return MATCH_FAILED;

	memcpy((char *) name,(char *) newname, (vp->namelen + 1) * sizeof(oid));
	*length = vp->namelen + 1;
	*write_method = 0;
	*var_len = sizeof(long);    /* default to 'long' results */
	return MATCH_SUCCEEDED;
}

u_char *
var_sysinfo (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method) {

	// sprintf (strbuffer, "Magic = %d, %lu", vp->magic, name[vp->namelen]);
	
	if (header_sysinfo (vp, name, length, exact,
				var_len, write_method) == MATCH_FAILED) {
		return NULL;
	}

	switch (vp->magic) {
	case NETFLOW_SNMP_VERSION:
		*var_len = strlen (netflow_version);
		return (u_char *) netflow_version;
	case NETFLOW_SNMP_CONTACT:
		*var_len = strlen (netflow_contact);
		return (u_char *) netflow_contact;
	case NETFLOW_SNMP_SYSNAME:
		*var_len = strlen (netflow_sysname);
		*write_method = writeSNMP;
		return (u_char *) netflow_sysname;
	default:
		return NULL;
	}
}

u_char *
var_confsys (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method) {
	static long		long_return;

	if (header_sysinfo (vp, name, length, exact,
				var_len, write_method) == MATCH_FAILED) {
		return NULL;
	}

	// todo_enqueue (ARP_TODO_UPDATE_DB);
	
	switch (vp->magic) {
	case NETFLOW_SNMP_DB_RELOAD:
		// long_return = in_update_mysql_db;
		*write_method = writeSNMP_integer;
		return (u_char *) &long_return;
	default:
		long_return = 0L;
		break;
	}

	return NULL;
}

int
header_testing (
		struct variable	*vp,
		oid		*name,
		size_t		*length,
		int		exact,
		size_t		*var_len,
		WriteMethod	**write_method ) {

	// oid	newname[MAX_OID_LEN];
	// int	result;

	if (exact) {
		if (*length != vp->namelen + 4) {
			return MATCH_FAILED;
		}
	} else {
#if DEBUG
		printf ("*length = %d\n", *length);
#endif
		return MATCH_SUCCEEDED;
	}

	// *length = vp->namelen;
	*write_method = 0;
	*var_len = sizeof (long);	/* default to 'long' results */

	return MATCH_SUCCEEDED;
}

u_char *var_testing (struct variable *vp, oid *name,
		size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method) {
	
	if (header_testing (vp, name, length, exact,
				var_len, write_method) == MATCH_FAILED) {
		return NULL;
	}

	if (! exact && (*length != vp->namelen + 4)) {
		return NULL;
	}
	switch (vp->magic) {
	// case NETFLOW_SNMP_MAC_IP:
		// *write_method = writeSNMP;
	//	return ipaddr;
	// case NETFLOW_SNMP_IP_MAC:
	//	return ipaddr;
	default:
		break;
	}

#if DEBUG
	fprintf (logfp, "%d\n", vp->magic);
#endif
	return NULL;
}

#if DEBUG
static int snmp_check_packet (struct snmp_session *session, snmp_ipaddr from) {
	struct sockaddr_in *fromIp = (struct sockaddr_in *) &from;

	snmp_log (LOG_INFO, "Received SNMP packet(s) from %s\n",
					inet_ntoa(fromIp->sin_addr));
	return ( 1 );
}
#endif

int
writeSNMP_integer ( int action,
		u_char *var_val,
		u_char var_val_type,
		size_t var_val_len,
		u_char *statP,
		oid *name,
		size_t name_len) {

	long	intval = *((long *) var_val);

	// fprintf (logfp, "writeSNMP_integer : %lu\n", name[9]);

	switch (action) {
	case RESERVE1:	// check values for acceptability
		if (var_val_type != ASN_INTEGER) {
			snmp_log (LOG_ERR, "not integer\n");
			return SNMP_ERR_WRONGTYPE;
		}

		/*
		if ((intval == 0) || (intval > ARP_TODO_MAX)) {
			snmp_log(LOG_ERR, "bad value\n");
			return SNMP_ERR_WRONGVALUE;
		}
		*/
		break;
	case RESERVE2:
		break;
	case ACTION:
		break;
	case UNDO:
		break;
	case COMMIT:
		// todo_enqueue (intval);
		// pthread_kill (main_thread, SIGUSR1);
		break;
	case FREE:
		break;
	}

	return SNMP_ERR_NOERROR;
	// return SNMP_ERR_GENERR;
}

int
writeSNMP ( int action,
		u_char *var_val,
		u_char var_val_type,
		size_t var_val_len,
		u_char *statP,
		oid *name,
		size_t name_len) {

	// u_char		*cp;
	char		*buf = NULL, *oldbuf = NULL;
	// int		count;

#if DEBUG
	fprintf (logfp, "writeSNMP : %lu\n", name[9]);
#endif

	buf = netflow_sysname;
	oldbuf = netflow_reserved_buffer;

	switch (action) {
	case RESERVE1:	// check values for acceptability
#if DEBUG
		fprintf (logfp, "reserve1\n");
#endif
		if (var_val_type != ASN_OCTET_STR) {
			snmp_log(LOG_ERR, "not string\n");
			return SNMP_ERR_WRONGTYPE;
		}
		if (var_val_len > sizeof (netflow_sysname) - 1){
			snmp_log(LOG_ERR, "bad length\n");
			return SNMP_ERR_WRONGLENGTH;
		}
		break;
	case RESERVE2:  // Allocate memory and similar resources
			// Using static strings, so nothing needs to be done
#if DEBUG
		printf ("reserve2\n");
#endif
		break;
	case ACTION:	// Save the old value, in case of UNDO
#if DEBUG
		printf ("action\n");
#endif
		strcpy( oldbuf, buf);
		memcpy( buf, var_val, var_val_len);
		buf[var_val_len] = 0;
		break;
	case UNDO:
#if DEBUG
		printf ("undo\n");
#endif
		strcpy (buf, oldbuf);
		oldbuf[0] = 0;
		break;
	case COMMIT:
		oldbuf[0] = 0;
#if DEBUG
		printf ("commit\n");
#endif
		break;
	case FREE:
		oldbuf[0] = 0;
#if DEBUG
		printf ("free\n");
#endif
		break;
	}

	return SNMP_ERR_NOERROR;
	// return SNMP_ERR_GENERR;
}


void snmp_main (void) {
	int		agentx_subagent = 0;
	int		numfds;
	fd_set		fdset;
	struct timeval	timeout, *tvp = &timeout;
	struct timeval	sched,   *svp = &sched,
			now,     *nvp = &now;
	int		count, block;
	int		port = SNMP_DEFAULT_PORT;
	char		*snmp_prog;
	const char	*snmp_prog_extension = "-snmp";



	/*
	if (sysconf_int ("enable-snmp") <= 0) {
		// fprintf (logfp, "UCD-SNMP %s (disable)\n", VersionInfo);
		pthread_exit (NULL);
	} else if (sysconf_int ("snmp-port") > 0) {
		port = sysconf_int ("snmp-port");
	}
	*/

	if ((snmp_prog = malloc (strlen (program_name) +
			strlen (snmp_prog_extension) + 1)) == NULL) {
		/*
		fprintf (logfp, "UCD-SNMP %s (memory allocation error)\n",
				VersionInfo);
		*/
		pthread_exit (NULL);
	}

	sprintf (snmp_prog, "%s%s", program_name, snmp_prog_extension);

	snmp_enable_stderrlog ();

#if 0
	if (logfile != NULL) {
		snmp_enable_filelog (logfile, 1);
		snmp_disable_stderrlog ();
	} else if (use_snmp_syslog) {
		snmp_enable_syslog ();
		snmp_disable_stderrlog ();
	}
#endif

	snmp_log (LOG_INFO,
		"UCD-SNMP %s, listen on UDP port %d (Thread: %ld)\n",
		VersionInfo, port, pthread_self ());

	if (agentx_subagent) {
		ds_set_boolean (DS_APPLICATION_ID, DS_AGENT_ROLE, 1);
	}

	init_agent (snmp_prog);

	// init_my_mib_code ();
	// init_mib_modules ();
	init_system_mib   ();
	init_vacm_vars    ();
	init_netflow_mib ();

	init_snmp (snmp_prog);

#if DEBUG
	read_config_print_usage ("    ");
#endif

	if (! agentx_subagent) {
#if DEBUG
		if (init_master_agent (port, snmp_check_packet, NULL) != 0) {
#else
		if (init_master_agent (port, NULL, NULL) != 0) {
#endif
			terminate = 1;
			pthread_exit (NULL);
		} else {
			// snmp_disable_stderrlog ();
			// snmp_enable_syslog ();
		}
	} 

	// send coldstart trap via snmptrap(1) if possible

	send_easy_trap (0, 0);

	// snmp_disable_stderrlog ();
	/*
	 *     
	 *     Set the 'sched'uled timeout to the current time + one TIMETICK.
	 *           */

	gettimeofday (nvp, (struct timezone *) NULL);
	svp->tv_usec = nvp->tv_usec + TIMETICK;
	svp->tv_sec  = nvp->tv_sec;

	while (svp->tv_usec >= ONE_SEC){
		svp->tv_usec -= ONE_SEC;
		svp->tv_sec++;
	}

	//  snmp_timeout ();
	//
	    /*
	     *     Loop-forever: execute message handlers for sockets with data,
	     *     reset the 'sched'uler.
	     *                */
	while (! terminate) {
		if (snmp_thread_data_write_and_clear) {
			snmp_thread_data_write_and_clear = 0;
		}

		if (snmp_reconfig) {
			snmp_reconfig = 0;
			snmp_log (LOG_INFO, "Reconfiguring daemon\n");
			update_config ();
		}

		tvp =  &timeout;
		tvp->tv_sec = 0;
		tvp->tv_usec = TIMETICK;

		numfds = 0;
		FD_ZERO(&fdset);
		block = 0;

		snmp_select_info (&numfds, &fdset, tvp, &block);

		if (block == 1) tvp = NULL; /* block without timeout */

		if ((count = select (numfds, &fdset, 0, 0, tvp)) > 0){
			snmp_read (&fdset);
		} else {
			switch (count){
			case 0:
				snmp_timeout ();
				break;
			case -1:
				if (errno == EINTR){
					continue;
				} else {
					snmp_log_perror ("select");
				}
				terminate = 1;
				break;
			default:
				snmp_log (LOG_ERR,
					"select returned %d\n", count);
				terminate = 1;
				break;
			}
		}  /* endif -- count>0 */

		/*
		 * If the time 'now' is greater than the 'sched'uled time, then:
		 *
		 *    Check alarm and event timers.
		 *    Reset the 'sched'uled time to current time + one TIMETICK.
		 *    Age the cache network addresses (from whom messges have
		 *        been received).
		*/

		gettimeofday(nvp, (struct timezone *) NULL);

		if (nvp->tv_sec > svp->tv_sec
				|| (nvp->tv_sec == svp->tv_sec &&
					nvp->tv_usec > svp->tv_usec)){
			svp->tv_usec = nvp->tv_usec + TIMETICK;
			svp->tv_sec = nvp->tv_sec;

			while (svp->tv_usec >= ONE_SEC){
				svp->tv_usec -= ONE_SEC;
				svp->tv_sec++;
			}
		}  /* endif -- now>sched */

		/* run requested alarms */
		run_alarms ();
	}
	
	snmp_log (LOG_INFO,
			"Received TERM or STOP signal...  shutting down...\n");
	snmp_shutdown (snmp_prog);
	pthread_exit (NULL);
}
