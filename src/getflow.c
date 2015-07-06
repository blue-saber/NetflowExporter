#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef linux
#include <getopt.h>
#endif
#include <signal.h>
#include "netflow_v1.h"
#include "netflow_v5.h"
#include "netflow_v7.h"

#define MAX_BUFFER_LEN	4096

volatile int	terminate = 0;

void interrupt (int signo) {
	if (signo == SIGALRM) {
		exit (0);
	} else if (! terminate) {
		fprintf (stderr, "\n** wait a minute **\n");
		terminate = 1;
		alarm (10);
	} else {
		fprintf (stderr, "** QUIT **\n");
		exit (0);
	}
}


int main (int argc, char *argv[]) {
	int			sockfd;
	struct sockaddr_in	serv_addr;
	struct sockaddr_in	cli_addr;
	int			port = 9991;
	char			buffer[MAX_BUFFER_LEN];
	netflow_v1_pdu		*nf1 = (netflow_v1_pdu *) buffer;
	netflow_v5_pdu		*nf5 = (netflow_v5_pdu *) buffer;
	netflow_v7_pdu		*nf7 = (netflow_v7_pdu *) buffer;

	signal (SIGHUP , SIG_IGN);
	signal (SIGCHLD, SIG_IGN);
	signal (SIGINT , interrupt);
	signal (SIGQUIT, interrupt);
	signal (SIGTERM, interrupt);
	signal (SIGALRM, interrupt);

	if ((sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror ("socket");
		exit (0);
	}

	bzero ((char *) &serv_addr, sizeof (serv_addr));
	serv_addr.sin_family	  = AF_INET;
	serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
	serv_addr.sin_port	  = htons (port);

	if (bind (sockfd, (struct sockaddr *) &serv_addr,
				sizeof (serv_addr)) < 0) {
		perror ("bind");
	}

	while (! terminate) {
		int		len, clilen;
		int		i, count;
		u_int32_t	unix_secs, SysUptime;
		u_int32_t	dPkts, dOctets;
		u_int32_t	First, Last;
		u_int16_t	srcport, dstport;
		u_int16_t	in_intf, ou_intf;
		struct in_addr	*srcaddr, *dstaddr;
		u_int8_t	prot, tos;

		clilen = sizeof (cli_addr);

		len = recvfrom (sockfd, buffer, MAX_BUFFER_LEN,
				0, (struct sockaddr *) &cli_addr, &clilen);

		if (len < 0) {
			perror ("recvfrom");
			continue;
		}

		unix_secs = ntohl (nf1->unix_secs);
		SysUptime = ntohl (nf1->SysUptime);

		fprintf (stderr, "\nConnect from: %s - %s",
				inet_ntoa (cli_addr.sin_addr),
				ctime ((time_t *) &unix_secs));

		fprintf (stderr, "netflow version: %d (count = %d, len = %d)\n",
				htons (nf1->version),
				(count = ntohs (nf1->count)),
				len);

		for (i = 0; i < count; i++) {
			switch (htons (nf1->version)) {
			default:
			case 1:
				dPkts   = ntohl (nf1->records[i].dPkts);
				dOctets = ntohl (nf1->records[i].dOctets);
				First   = unix_secs - (SysUptime -
					 ntohl (nf1->records[i].First)) / 1000;
				Last    = unix_secs - (SysUptime -
					 ntohl (nf1->records[i].Last)) / 1000;
				srcport = ntohs (nf1->records[i].srcport);
				dstport = ntohs (nf1->records[i].dstport);
				in_intf = ntohs (nf1->records[i].input);
				ou_intf = ntohs (nf1->records[i].output);
				srcaddr = (struct in_addr *)
						&nf1->records[i].srcaddr;
				dstaddr = (struct in_addr *)
						&nf1->records[i].dstaddr;
				prot    = nf1->records[i].prot;
				tos     = nf1->records[i].tos;
				break;
			case 5:
				dPkts   = ntohl (nf5->records[i].dPkts);
				dOctets = ntohl (nf5->records[i].dOctets);
				First   = unix_secs - (SysUptime -
					 ntohl (nf5->records[i].First)) / 1000;
				Last    = unix_secs - (SysUptime -
					 ntohl (nf5->records[i].Last)) / 1000;
				srcport = ntohs (nf5->records[i].srcport);
				dstport = ntohs (nf5->records[i].dstport);
				in_intf = ntohs (nf5->records[i].input);
				ou_intf = ntohs (nf5->records[i].output);
				srcaddr = (struct in_addr *)
						&nf5->records[i].srcaddr;
				dstaddr = (struct in_addr *)
						&nf5->records[i].dstaddr;
				prot   = nf5->records[i].prot;
				tos     = nf5->records[i].tos;

				break;
			case 7:
				dPkts   = ntohl (nf7->records[i].dPkts);
				dOctets = ntohl (nf7->records[i].dOctets);
				First   = unix_secs - (SysUptime -
					 ntohl (nf7->records[i].First)) / 1000;
				Last    = unix_secs - (SysUptime -
					 ntohl (nf7->records[i].Last)) / 1000;
				srcport = ntohs (nf7->records[i].srcport);
				dstport = ntohs (nf7->records[i].dstport);
				in_intf = ntohs (nf7->records[i].input);
				ou_intf = ntohs (nf7->records[i].output);
				srcaddr = (struct in_addr *)
						&nf7->records[i].srcaddr;
				dstaddr = (struct in_addr *)
						&nf7->records[i].dstaddr;
				prot    = nf7->records[i].prot;
				tos     = nf7->records[i].tos;
				break;
			}
			printf ("SRC=%s:%d, ", inet_ntoa (*srcaddr),
						srcport);
			printf ("DST=%s:%d, ", inet_ntoa (*dstaddr),
						dstport);
			printf ("PROTO=%d, TOS=%d (Intf: %d -> %d)\n",
					prot, tos, in_intf, ou_intf);
			printf ("packets = %u, octets = %u\n",
					dPkts, dOctets);
			printf ("start of flow : %s",
					ctime ((time_t *) &First));
			printf ("last  of flow : %s",
					ctime ((time_t *) &Last));
		}
	}

	close (sockfd);
	exit (0);
}
