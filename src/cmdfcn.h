/*
 *	cmdfcn.h
 *
 *	Copyright (c) 2004, Jiann-Ching Liu
 */

#ifndef __CMD_FUNCTIONS_H__
#define __CMD_FUNCTIONS_H__

struct cmdlintf_t;

extern int clear_counter (struct cmdlintf_t *cli, char *cmd);
extern int ip_flow_cache_entries (struct cmdlintf_t *cli, char *cmd);
extern int show_ip_flow_export (struct cmdlintf_t *cli, char *cmd);
extern int show_ip_cache_flow (struct cmdlintf_t *cli, char *cmd);
extern int show_flow (struct cmdlintf_t *cli, char *cmd);
extern int ip_flow_export_version (struct cmdlintf_t *self, char *cmd);
extern int ip_flow_cache_timeout_active (struct cmdlintf_t *cli, char *cmd);
extern int ip_flow_cache_timeout_inactive (struct cmdlintf_t *cli, char *cmd);
extern int ip_flow_export_destination (struct cmdlintf_t *cli, char *cmd);
extern int enable_ip_flow_export (struct cmdlintf_t *cli, char *cmd);
extern int disable_ip_flow_export (struct cmdlintf_t *cli, char *cmd);
extern int show_packet_engine (struct cmdlintf_t *cli, char *cmd);
extern int show_copyright (struct cmdlintf_t *cli, char *cmd);

extern int show_configuration (FILE *fp);
extern void regist_commands (void);

#endif
