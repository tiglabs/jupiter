/* Copyright (c) 2018. TIG developer. */

#ifndef __UNIXCTL_COMMAND_H__
#define __UNIXCTL_COMMAND_H__

#include <stdint.h>

#include <sys/queue.h>

typedef void unixctl_command_cb_func(int, char **, int);

struct unixctl_cmd_entry {
    TAILQ_ENTRY(unixctl_cmd_entry) next;
    const char *name;
    const char *usage;
    const char *summary;
    uint16_t min_argc, max_argc;
    unixctl_command_cb_func *cb;
};

TAILQ_HEAD(unixctl_cmd_head, unixctl_cmd_entry);

extern struct unixctl_cmd_head unixctl_cmd_entries;

#define UNIXCTL_CMD_REGISTER(n, u, s, min, max, f)                             \
    struct unixctl_cmd_entry cmd_##f = {                                       \
        .name = n,                                                             \
        .usage = u,                                                            \
        .summary = s,                                                          \
        .min_argc = min,                                                       \
        .max_argc = max,                                                       \
        .cb = f,                                                               \
    };                                                                         \
    __attribute__((constructor)) static void unixctl_cmd_register_##f(void) {  \
        TAILQ_INSERT_TAIL(&unixctl_cmd_entries, &cmd_##f, next);               \
    }

int unixctl_command_reply(int fd, const char *format, ...);
int unixctl_command_reply_error(int fd, const char *format, ...);
int unixctl_command_reply_string(int fd, const char *string);

int unixctl_server_create(const char *path);
void unixctl_server_destory(int fd, const char *path);
void unixctl_server_run_once(int unixctl_server_fd);

int unixctl_client_create(const char *path);
void unixctl_client_destory(int fd, const char *path);
int unixctl_client_request(int fd, const char *cmdline);

#endif
