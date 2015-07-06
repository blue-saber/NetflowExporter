#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "utils.h"

#ifndef HAVE_STRLCPY
#define strlcpy(x, y, z) \
	(strncpy((x), (y), (z)), \
		((z) <= 0 ? 0 : ((x)[(z) - 1] = '\0')), \
		strlen((y)))
#endif


#ifdef IFF_LOOPBACK
#define ISLOOPBACK(p) ((p)->ifr_flags & IFF_LOOPBACK)
#define ISLOOPBACK_IFA(p) ((p)->ifa_flags & IFF_LOOPBACK)
#else
#define ISLOOPBACK(p) ((p)->ifr_name[0] == 'l' && (p)->ifr_name[1] == 'o' && \
		(isdigit((p)->ifr_name[2]) || (p)->ifr_name[2] == '\0'))
#define ISLOOPBACK_IFA(p) ((p)->ifa_name[0] == 'l' && (p)->ifa_name[1] == 'o' \
		&& (isdigit((p)->ifa_name[2]) || (p)->ifa_name[2] == '\0'))
#endif

char* generic_lookupdev (char **errbuf) {
#ifdef HAVE_IFADDRS_H
	struct ifaddrs *ifap, *ifa, *mp;
	int n, minunit;
	char *cp;
	static char device[IF_NAMESIZE + 1];

	if (getifaddrs (&ifap) != 0) {
		*errbuf = strerror (errno);
		return NULL;
	}

	mp = NULL;
	minunit = 666;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		const char *endcp;

		if ((ifa->ifa_flags & IFF_UP) == 0 || ISLOOPBACK_IFA(ifa))
			continue;

		endcp = ifa->ifa_name + strlen(ifa->ifa_name);
		for (cp = ifa->ifa_name; cp < endcp && !isdigit(*cp); ++cp)
			continue;

		if (isdigit (*cp)) {
			n = atoi(cp);
		} else {
			n = 0;
		}
		if (n < minunit) {
			minunit = n;
			mp = ifa;
		}
	}
	if (mp == NULL) {
		*errbuf = strerror (errno);
#ifdef HAVE_FREEIFADDRS
		freeifaddrs(ifap);
#else
		free(ifap);
#endif
		return (NULL);
	}

	strlcpy(device, mp->ifa_name, sizeof(device));
#ifdef HAVE_FREEIFADDRS
	freeifaddrs(ifap);
#else
	free(ifap);
#endif
	return (device);
#else
	register int fd, minunit, n;
	register char *cp;
	register struct ifreq *ifrp, *ifend, *ifnext, *mp;
	struct ifconf ifc;
	char *buf;
	struct ifreq ifr;
	static char device[sizeof(ifrp->ifr_name) + 1];
	unsigned buf_size;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		*errbuf = strerror (errno);
		return NULL;
	}

	buf_size = 8192;

	for (;;) {
		buf = utils_malloc (buf_size);
		if (buf == NULL) {
			close (fd);
			*errbuf = "out of memory";
			return NULL;
		}

		ifc.ifc_len = buf_size;
		ifc.ifc_buf = buf;
		memset (buf, 0, buf_size);
		if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0
		    && errno != EINVAL) {
			free (buf);
			*errbuf = strerror (errno);
			close (fd);
			return NULL;
		}
		if (ifc.ifc_len < buf_size)
			break;
		free (buf);
		buf_size *= 2;
	}

	ifrp = (struct ifreq *)buf;
	ifend = (struct ifreq *)(buf + ifc.ifc_len);

	mp = NULL;
	minunit = 666;
	for (; ifrp < ifend; ifrp = ifnext) {
		const char *endcp;

#ifdef HAVE_SOCKADDR_SA_LEN
		n = ifrp->ifr_addr.sa_len + sizeof(ifrp->ifr_name);
		if (n < sizeof(*ifrp))
			ifnext = ifrp + 1;
		else
			ifnext = (struct ifreq *)((char *)ifrp + n);
		if (ifrp->ifr_addr.sa_family != AF_INET)
			continue;
#else
		ifnext = ifrp + 1;
#endif
		/*
		 * Need a template to preserve address info that is
		 * used below to locate the next entry.  (Otherwise,
		 * SIOCGIFFLAGS stomps over it because the requests
		 * are returned in a union.)
		 */
		strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
			if (errno == ENXIO) continue;
			*errbuf = strerror (errno);
			close(fd);
			free (buf);
			return NULL;
		}

		/* Must be up and not the loopback */
		if ((ifr.ifr_flags & IFF_UP) == 0 || ISLOOPBACK(&ifr))
			continue;

		endcp = ifrp->ifr_name + strlen(ifrp->ifr_name);
		for (cp = ifrp->ifr_name; cp < endcp && !isdigit(*cp); ++cp)
			continue;
		
		if (isdigit (*cp)) {
			n = atoi(cp);
		} else {
			n = 0;
		}
		if (n < minunit) {
			minunit = n;
			mp = ifrp;
		}
	}
	(void)close(fd);
	if (mp == NULL) {
		*errbuf = strerror (errno);
		free (buf);
		return NULL;
	}

	strlcpy (device, mp->ifr_name, sizeof(device));
	free(buf);
	return (device);
#endif
}
