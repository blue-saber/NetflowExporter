/*
 *	cmdlintf.h	(Command Line Interface)
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#ifndef __CMDLINE_INTF_H__
#define __CMDLINE_INTF_H__

struct cmdlintf_pd_t;

struct cmdlintf_t {
	struct cmdlintf_pd_t	*pd;
	int	(*add)(const char *cmd, const int rmt,
				int (*cmdfunc)(struct cmdlintf_t *, char *),
				const char *doc, const int args,
				const int cmdtype);
	char *	(*socket_name)(const char *filename);

	void	(*set_prompt)(const char *str);
	int	(*set_timeout)(const int sec);
	int	(*start)(const int is_server);
	int	(*cli)(void);
	int	(*print)(const char *fmt, ...);
	void	(*regcmd)(void);

	void	(*set_login_callback)(void (*cbk)(struct cmdlintf_t *));
	int	(*execute)(char *cmd, const int cmdtype);
	void	(*terminate)(void);
};

extern struct cmdlintf_t * init_cmdline_interface (const int bufsize);

#endif
