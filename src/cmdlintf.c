/*
 *	cmdlintf.c	(Command Line Interface)
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#include <sys/types.h>
#include <sys/socket.h>
// #include <netinet/in.h>
#include <sys/un.h>
// #include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "cmdlintf.h"

#define MAX_CMD_WORD_LEN        (64)
#define MAX_TRANSFER_BUFFER	10240


typedef struct _cmdstru {
	char		*name;
	int		is_rmt;
	int		(*func)(struct cmdlintf_t *, char *);
	int		cmd_type;
	char		*doc;
	int		nargs;
	struct _cmdstru	*subcmd;
	struct _cmdstru	*next;
} command_t;

struct cmdlintf_pd_t {
	char		*sockname;
	volatile short	terminate;
	int		num_of_connection;
	command_t	cmdptr;
	char		*prompt;
	short		have_precommand;
	int		svc_fd;
	int		pending_cmd;
	// int     	(*print)(const char *fmt, ...);
	void		(*callback)(struct cmdlintf_t *);
};

static struct cmdlintf_t	cli_intfinstance;
static struct cmdlintf_t	*cliptr = NULL;
static struct cmdlintf_pd_t	cli_public_data;
static struct cmdlintf_pd_t	*pdptr = &cli_public_data;

static char	*bp_buffer = NULL;
static int	bp_size = 0;
static int	bp_index = 0;

static int	idle_time = 0;


static char * dupstr (const char *s) {
	char	*r;

	// r = xmalloc (strlen (s) + 1);
	r = malloc (strlen (s) + 1);
	strcpy (r, s);
	return r;
}

static char *nthwordptr (char *cmd, const int n) {
	int		len;
	int		i, j, m;

	len = strlen (cmd);

	for (j = 1, i = m = 0; i < len; i++) {
		if (whitespace (cmd[i])) {
			if (m > 0) {
				m = 0;
				if (j++ == n) break;
			}
		} else {
			m++;
			if (j == n) return &cmd[i];
		}
	}
	return NULL;
}

static char *nthword (const char *cmd, const int n) {
	static char	word[5][MAX_CMD_WORD_LEN];
	static int	idx = 0;
	int		i, j, k, m, len;

	len = strlen (cmd);
	idx = (idx + 1) % 5;

	for (j = 1, i = k = m = 0; i < len; i++) {
		if (whitespace (cmd[i])) {
			if (m > 0) {
				m = 0;
				if (j++ == n) break;
			}
		} else {
			m++;
			if (j == n) {
				if (k < MAX_CMD_WORD_LEN-1) {
					word[idx][k++] = cmd[i];
				}
			}
		}
	}

	if (k == 0) return NULL;

	word[idx][k] = '\0';

	return word[idx];
}

static char * stripwhite (char *string) {
	char	*s, *t;

	for (s = string; whitespace (*s); s++) ;
	if (*s == 0) return s;
	t = s + strlen (s) - 1;
	while (t > s && whitespace (*t)) t--;
	*++t = '\0';
	return s;
}

static int nofwords (const char *cmd) {
	int	i, j, m, len;

	len = strlen (cmd);

	for (i = j = m = 0; i < len; i++) {
		if (whitespace (cmd[i])) {
			if (m > 0) {
				m = 0;
				j++;
			}
		} else {
			m++;
		}
	}

	if (m > 0) j++;
	return j;
} 


static int cmd_history (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
	} else {
		HIST_ENTRY	**the_list;
		int		i;

		if ((the_list = history_list ())!= NULL) {
			for (i = 0; the_list[i] != NULL; i++) {
				cli->print ("%5d %s\n",
					i + history_base,
					the_list[i]->line);
			}
		}

		return 2;
	}

	return 1;
}

static int cmd_clear_history (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
	} else {
		clear_history ();
		return 2;
	}
	return 1;
}

static void external_terminate (void) { pdptr->terminate = 1; }

static int cmd_terminate (struct cmdlintf_t *cli, char *cmd) {
	if (cmd != NULL) {
		cli->print ("%% Invalid input detected: \"%s\"\n", cmd);
	} else {
		cli->pd->terminate = 1;
	}

	return 0;
}
/*
 */



static void bpinit (void) { bp_index = 0; }
static int bplen (void) { return bp_index; }
static char *bpbptr (void) { return bp_buffer; }

static int bprint (const char *fmt, ...) {
	va_list	ap;
	int	len;

	if (bp_size < bp_index + 80) return 0;

	va_start (ap, fmt);
	len = vsprintf (&bp_buffer[bp_index], fmt, ap);
	va_end (ap);

	bp_index += len;

	return len;
}


// ----------------------------------------------------------

static command_t * find_match_command (const char *text, const int mcnt) {
	command_t	*ptr = &pdptr->cmdptr;
	int		i, found;
	char		*word;

	for (i = 1, found = 0; (i <= mcnt) && (ptr != NULL); i++) {
		if ((word = nthword (text, i)) == NULL) break;
		if ((ptr = ptr->subcmd) == NULL) break;
		for (found = 0; ptr != NULL; ptr = ptr->next) {
			if (strcmp (ptr->name, word) == 0) {
				found = 1;
				break;
			}
		}
	}

	return found ? ptr : NULL;
}

static char * entry_completion (const char *text, int state) {
	static int		iwds, wds;
	static command_t	*cptr = NULL;
	static int		len = 0;
	char			*matches;

	matches = NULL;

	if (! state) {
		len  = strlen (text);
		wds  = nofwords (rl_line_buffer);
		iwds = nofwords (text);

		wds -= iwds;

		// fprintf (stderr, "[%s](%d)\n", rl_line_buffer, wds);

		cptr = find_match_command (rl_line_buffer, wds);

		if (cptr != NULL) {
			if (cptr->subcmd != NULL) {
				cptr = cptr->subcmd;
			} else if (iwds == 0) {
				if (cptr->nargs == 0) {
					cliptr->print ("\n   <cr>\t\t%s\n",
						(cptr->doc == NULL ? ""
						: cptr->doc));
				} else {
					cliptr->print (
						"\n   [%d args]\t\t%s\n",
						cptr->nargs,
						(cptr->doc == NULL ? ""
						: cptr->doc));
				}
				rl_forced_update_display ();
				return NULL;
			} else {
				// rl_forced_update_display ();
				return NULL;
			}
		}
	}

	if (cptr != NULL) {
		while (cptr->name != NULL) {
			if (strncmp (cptr->name, text, len) == 0) {
				matches = strdup (cptr->name);
				cptr = cptr->next;
				break;
			} else {
				cptr = cptr->next;
				if (cptr == NULL) break;
			}
		}
	}

	return matches;
}

static char * command_generator (const char *text, int state) {
	static int		list_index, len;
	static command_t	*ptr = NULL;
	char			*name;

	if (! state) {
		list_index = 0;
		len = strlen (text);
		ptr = pdptr->cmdptr.subcmd;
	}

	while (ptr != NULL) {
		if ((name = ptr->name) != NULL) {
			ptr = ptr->next;
			if (strncmp (name, text, len) == 0)
				// return strdup (name);
				return strdup (name);
			} else {
				ptr = ptr->next;
			}
	}

	return NULL;
}

static char * cli_socket_name (const char *filename) {
	if (filename != NULL) {
		if (pdptr->sockname != NULL) {
			free (pdptr->sockname);
			pdptr->sockname = NULL;
		}

		if (filename[0] != '\0') {
			pdptr->sockname = strdup (filename);
		}
	}

	return pdptr->sockname;
}

static int cli_addcmd (const char *cmd, const int rmt,
			int (*cmdfunc)(struct cmdlintf_t *, char *),
			const char *doc, const int args, const int cmdtype) {
	command_t		*ptr = &pdptr->cmdptr, *q;
	char			*word;
	int			level;
	int			wds;
	int			found;

	wds = nofwords (cmd);

	for (level = 1; level <= wds; level++) {
		if ((word = nthword (cmd, level)) == NULL) break;

		found = 0;

		for (q = ptr->subcmd; q != NULL; q = q->next) {
			if (strcmp (word, q->name) == 0) {
				found = 1;
				break;
			}
		}

		if (! found) {
			q = calloc (1, sizeof (command_t));
			q->next = ptr->subcmd;
			ptr->subcmd = q;
			q->subcmd = NULL;
			q->name  = dupstr (word);
			q->func  = NULL;
			q->doc   = NULL;
			q->nargs = 0;
			q->is_rmt= rmt;
			q->cmd_type = cmdtype;
		}

		if (level == wds) {
			if (found) {
				fprintf (stderr, "Duplicate Command\n");
				return 0;
			} else {
				if (doc != NULL) q->doc = dupstr (doc);
				q->func  = cmdfunc;
				q->nargs = args;
				return 1;
			}
		} else {
			ptr = q;
		}
	}

	return 0;
}

static void show_subcmd (command_t *command) {
	command_t	*ptr;

	if (command == NULL) return;

	for (ptr = command->subcmd; ptr != NULL; ptr = ptr->next) {
		cliptr->print ("\t%s\n", ptr->name);
	}
}

static command_t * find_match_as_possible (const char *text, int *mcnt) {
	command_t		*ptr = &pdptr->cmdptr;
	command_t		*fptr = NULL;
	int			i;
	char			*word;

	for (i = 1; ptr != NULL; i++) {
		if ((word = nthword (text, i)) == NULL) break;
		if ((ptr = ptr->subcmd) == NULL) break;
		for (; ptr != NULL; ptr = ptr->next) {
			if (strcmp (ptr->name, word) == 0) {
				fptr = ptr;
				*mcnt = i;
				break;
			}
		}
	}

	return fptr;
}

static void find_match_commands (char *cmd) {
	command_t	*command;
	command_t	*ptr = &pdptr->cmdptr;
	int		i = 0;

	command = find_match_as_possible (cmd, &i);

	if (cmd[0] == '\0' && i == 0) {
		show_subcmd (ptr);
	} else if (command == NULL) {
		cliptr->print ("%% Unrecognized command\n");
	} else if (command->func == NULL) {
		if (i == nofwords (cmd)) {
			show_subcmd (command);
		} else {
			cliptr->print ("%% Unrecognized command\n");
		}
	} else {
		// cliptr->print ("%% Unrecognized command\n");
	}
}

static int execute_line (char *cmd) {
	int		i, retval;
	command_t	*command;
	int		len, rlen, xlen;
	char		buffer[1024];

	command = find_match_as_possible (cmd, &i);

	if (command == NULL) {
		cliptr->print ("%% %s: no such command\n", nthword (cmd, 1));
	} else if (command->func == NULL) {
		cliptr->print ("%% %s: Incomplete command.\n", cmd);
	} else if (! command->is_rmt) {
		return ((*(command->func)) (cliptr, nthwordptr (cmd, i+1)));
	} else {
		if (pdptr->svc_fd >= 0) {
			retval = 1;

			write (pdptr->svc_fd, cmd, strlen (cmd));

			read (pdptr->svc_fd, &retval, sizeof retval);
			read (pdptr->svc_fd, &len, sizeof len);

			while (len > 0) {
				if (len > sizeof buffer - 1) {
					xlen = sizeof buffer - 1;
				} else {
					xlen = len;
				}

				rlen = read (pdptr->svc_fd, buffer, xlen);

				if (rlen <= 0) break;

				fwrite (buffer, 1, rlen, stderr);
				len -= rlen;
			}

			return retval;
		} else {
			return ((*(command->func)) (cliptr,
						nthwordptr (cmd, i+1)));
		}
	}
	return 1;
}

static int external_execute (char *cmd, const int cmdtype) {
	int		i;
	command_t	*command;

	command = find_match_as_possible (cmd, &i);

	if (command == NULL) {
		cliptr->print ("%% %s: no such command\n", nthword (cmd, 1));
	} else if (command->func == NULL) {
		cliptr->print ("%% %s: Incomplete command.\n", cmd);
	} else {
		if (cmdtype == command->cmd_type) {
			return ((*(command->func)) (cliptr,
						nthwordptr (cmd, i+1)));
		}
	}
	return 1;
}

static void rl_stuff_str (const char *str) {
	int	i;

	if (str == NULL) return;

	for (i = 0; str[i] != '\0'; i++) rl_stuff_char (str[i]);
}

static int cmdline_interface (void) {
	static char		*line, *linenbs;
	static int		retval, result;
	static char		*expansion;

	if (pdptr->prompt == NULL) pdptr->prompt = strdup ("cli>");

	do {
		pdptr->pending_cmd = 0;

		if (! (line = readline (pdptr->prompt))) return 1;
		if (! pdptr->pending_cmd) break;

		find_match_commands (line);

		rl_stuff_str (line);
		// rl_on_new_line ();
		free (line);
	} while (pdptr->pending_cmd);

	retval = 1;

	linenbs = stripwhite (line);

	if (*linenbs) {
		result = history_expand (linenbs, &expansion);

		if (result) cliptr->print ("%s\n", expansion);

		if ((result < 0) || (result == 2)) {
			free (expansion);
		} else {
			if (expansion[0] != ';') {
				retval = execute_line (expansion);
			}
			if (retval != 2) add_history (expansion);
			free (expansion);
			cliptr->print ("\r\n");
		}
	}

	return retval;
}

static char ** command_completion (const char *text, int start, int end) {
	char	**matches = NULL;

	if (start == 0) {
		matches = rl_completion_matches (text, command_generator);
	}

	return matches;
}

static int help_function (int x, int y) {
	// rl_on_new_line_with_prompt ();
	cliptr->print ("?\n");
	rl_done = 1;
	pdptr->pending_cmd = 1;
	// rl_on_new_line ();
	// cliptr->print ("%% Unrecognized command");

	return 0;
}

static int cli_init (void) {
	rl_catch_signals = 1;
	rl_readline_name = "CLI";
	rl_attempted_completion_function	= command_completion;
	rl_completion_entry_function		= entry_completion;
	//

	return 1;
}

static void cli_set_prompt (const char *prompt) {
	if (pdptr->prompt != NULL) free (pdptr->prompt);

	pdptr->prompt = strdup (prompt);
}

static void accept_client (const int fd, const int cli_pid) {
	int			len, retval;
	char			buffer[4096];
	fd_set			fds;
	struct timeval		timeout;
	int			rc;
	int			cnt = 0;

	// fprintf (stderr, "client:%d\n", cli_pid);

	while (! pdptr->terminate) {
		FD_ZERO (&fds);
		FD_SET (fd, &fds);
		timeout.tv_sec  = 1;
		timeout.tv_usec = 0;

		if ((rc = select (fd + 1, &fds, NULL, NULL, &timeout)) < 0) {
			if (errno != EINTR) perror ("select");
			fprintf (stderr, "%d: %s\n", errno,
					strerror (errno));
			continue;
		} else if (rc == 0) {
			if (idle_time > 0) {
				if (++cnt > idle_time) {
					fprintf (stderr,
						"*** time out (%d) ***\n",
						cli_pid);
					kill (cli_pid, SIGALRM);
					break;
				}
			}
			continue;
		}

		if (FD_ISSET (fd, &fds)) {
			cnt = 0;
			if ((len = read (fd, buffer, sizeof buffer - 1)) > 0) {
				buffer[len] = '\0';
				retval = execute_line (buffer);

				write (fd, &retval, sizeof retval);
				len = bplen ();

				write (fd, &len, sizeof len);

				if (len > 0) write (fd, bpbptr (), len);
				bpinit ();
				if (retval == 0) break;
			} else {
				// end of file ?
				break;
			}
		}
	}
}

static int cli_start (const int is_server) {
	int			sockfd;
	struct sockaddr_un	serv_addr;
	int			servlen;
	int			len;


	if (pdptr->sockname != NULL) {
		if ((sockfd = socket (PF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror ("socket");
			return 0;
		}

		memset (&serv_addr, 0, sizeof serv_addr);
		serv_addr.sun_family = AF_UNIX;
		strcpy (serv_addr.sun_path, pdptr->sockname);
		servlen = strlen (serv_addr.sun_path) +
				sizeof (serv_addr.sun_family) + 1;

		if (is_server) {
			fd_set			fds;
			struct timeval		timeout;
			int			fd, rc, clilen;
			struct sockaddr_un	cli_addr;
			int			cli_pid;

			if (bind (sockfd, (struct sockaddr *) &serv_addr,
							servlen) < 0) {
				perror ("bind");
				close (sockfd);
				return 0;
			}

			listen (sockfd, 5);

			bpinit ();
			cliptr->print = bprint;

			while (! pdptr->terminate) {
				FD_ZERO (&fds);
				FD_SET (sockfd, &fds);
				timeout.tv_sec  = 2;
				timeout.tv_usec = 500000;

				if ((rc = select (sockfd + 1, &fds,
						NULL, NULL, &timeout)) < 0) {
					if (errno != EINTR) perror ("select");
					continue;
				} else if (rc == 0) {
					continue;
				}

				if (FD_ISSET (sockfd, &fds)) {
					clilen = sizeof cli_addr;

					if ((fd = accept (sockfd,
						(struct sockaddr *) &cli_addr,
						&clilen)) < 0) continue;

					read (fd, &cli_pid, sizeof cli_pid);
					// show_version ();
					
					if (pdptr->callback != NULL) {
						pdptr->callback (cliptr);
					}

					len = bplen ();
					write (fd, &len, sizeof len);
					if (len > 0) write (fd, bpbptr (), len);
					bpinit ();

					accept_client (fd, cli_pid);
					close (fd);
				}
			}

			close (sockfd);
			unlink (pdptr->sockname);

			return 1;
		} else {
			int	rc, len;

			if (connect (sockfd, (struct sockaddr *) &serv_addr,
						servlen) < 0) {
				perror (pdptr->sockname);
				close (sockfd);
				return 0;
			}

			len = getpid ();
			write (sockfd, &len, sizeof len);

			cli_init ();
			rl_bind_key ('?', help_function);
			pdptr->svc_fd = sockfd;

			if ((rc = read (sockfd, &len, sizeof len))
							== sizeof len) {
				if (len > 0) {
					char	*ptr;
					int	rlen;

					ptr = malloc (len);

					while (len > 0) {
						rlen = read (sockfd, ptr, len);
						if (rlen <= 0) break;

						fwrite (ptr, 1, rlen, stderr);
						len -= rlen;
					}

					free (ptr);
				}
			} else {
				fprintf (stderr, "rc=%d\n", rc);
			}
		}
	} else {
		cli_init ();
		rl_bind_key ('?', help_function);
	}

	return 1;
}

static int lprint (const char *fmt, ...) {
	va_list		ap;
	int		len;
	FILE		*fp = rl_outstream;

	if (fp == NULL) fp = stderr;

	va_start (ap, fmt);
	len = vfprintf (fp, fmt, ap);
	va_end (ap);

	return len;
}

// ----------------------------------------------------------

static void regist_default_command (void) {
	if (! pdptr->have_precommand) {
		pdptr->have_precommand = 1;

		cliptr->add ("history", 0, cmd_history, NULL, 0, 0);
		cliptr->add ("clear history", 0, cmd_clear_history, NULL, 0, 0);
		cliptr->add ("terminate", 1, cmd_terminate, NULL, 0, 0);
	}
}

// ----------------------------------------------------------

static int cli_set_timeout (const int sec) {
	idle_time = sec;
	// return rl_set_keyboard_input_timeout (sec);
	return sec;
}

static void cli_set_login_callback (void (*cbk)(struct cmdlintf_t *)) {
	pdptr->callback = cbk;
}

struct cmdlintf_t * init_cmdline_interface (const int bsize) {
	if (cliptr == NULL) {
		cliptr = & cli_intfinstance;

		if (bp_buffer == NULL) {
			if ((bp_buffer = malloc (bsize)) != NULL) {
				bp_size = bsize;
			}
		}

		cliptr->pd		= pdptr;
		cliptr->add		= cli_addcmd;
		cliptr->socket_name	= cli_socket_name;
		cliptr->start		= cli_start;
		cliptr->set_prompt	= cli_set_prompt;
		cliptr->cli		= cmdline_interface;
		cliptr->print		= lprint;
		cliptr->regcmd		= regist_default_command;
		cliptr->set_timeout	= cli_set_timeout;
		cliptr->set_login_callback	= cli_set_login_callback;
		cliptr->execute		= external_execute;
		cliptr->terminate	= external_terminate;

		pdptr->sockname			= NULL;
		pdptr->terminate		= 0;
		pdptr->num_of_connection	= 0;
		pdptr->have_precommand		= 0;
		pdptr->prompt			= NULL;
		pdptr->svc_fd			= -1;
		pdptr->callback			= NULL;

		memset (&pdptr->cmdptr, 0, sizeof (pdptr->cmdptr));
		pdptr->cmdptr.subcmd		= NULL;
		pdptr->cmdptr.next		= NULL;
	}

	return cliptr;
}
