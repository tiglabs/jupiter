/* Copyright (c) 2017. TIG developer. */

#ifndef __UNIXCTL_COMMAND_H__
#define __UNIXCTL_COMMAND_H__

typedef void unixctl_command_cb_func(int, char **, int);
int unixctl_command_reply(int fd, const char *format, ...);
int unixctl_command_reply_error(int fd, const char *format, ...);
int unixctl_command_register(const char *name, const char *usage,
                             const char *summary, int min_argc, int max_argc,
                             unixctl_command_cb_func *cb);

int unixctl_server_create(const char *path);
void unixctl_server_destory(int fd, const char *path);
void unixctl_server_run_once(int unixctl_server_fd);

int unixctl_client_create(const char *path);
void unixctl_client_destory(int fd, const char *path);
int unixctl_client_request(int fd, const char *cmdline);

#endif

