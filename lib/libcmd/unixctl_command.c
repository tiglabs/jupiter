/* Copyright (c) 2017. TIG developer. */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "unixctl_command.h"

#define FALSE 0
#define TRUE 1

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef offsetof
/** Return the offset of a field in a structure. */
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

#define CMDMSG_HDR_SIZE offsetof(struct unixctl_cmd_message, data)
#define CMDMSG_DATA_SIZE 512

#define CMDMSG_T_REQUEST 0x0
#define CMDMSG_T_REPLY 0x1

#define CMDMSG_S_SUCCESS 0x0
#define CMDMSG_S_FAIL 0x1

struct unixctl_cmd_message {
    /* msg header */
    uint8_t type;
    uint8_t status;
    uint16_t data_size;
    /* msg body */
    char data[CMDMSG_DATA_SIZE];
} __attribute((packed));

#define CMD_MAX_OPTIONS 32

struct unixctl_cmd_entry {
    TAILQ_ENTRY(unixctl_cmd_entry) next;
    const char *name;
    const char *usage;
    const char *summary;
    uint16_t min_argc, max_argc;
    unixctl_command_cb_func *cb;
};

TAILQ_HEAD(, unixctl_cmd_entry)
unixctl_cmd_entries = TAILQ_HEAD_INITIALIZER(unixctl_cmd_entries);

static int
read_cmd_message(int fd, struct unixctl_cmd_message *cmdmsg) {
    struct iovec iov;
    struct msghdr msgh = {0};
    int ret;

    memset(cmdmsg, 0, sizeof(*cmdmsg));
    iov.iov_base = cmdmsg;
    iov.iov_len = CMDMSG_HDR_SIZE;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    ret = recvmsg(fd, &msgh, 0);
    if (ret <= 0)
        return ret;
    if (msgh.msg_flags & MSG_TRUNC)
        return -1;
    if (cmdmsg->data_size > 0) {
        ret = read(fd, cmdmsg->data, cmdmsg->data_size);
        if (ret != (int)cmdmsg->data_size)
            return -1;
    }
    return ret;
}

static int
write_cmd_message(int fd, struct unixctl_cmd_message *cmdmsg) {
    struct iovec iov = {0};
    struct msghdr msgh = {0};
    int ret;

    iov.iov_base = cmdmsg;
    iov.iov_len = CMDMSG_HDR_SIZE + cmdmsg->data_size;
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    do {
        ret = sendmsg(fd, &msgh, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    return ret;
}

static int
__unixctl_command_reply(int fd, int err, const char *buf, size_t buf_len) {
    struct unixctl_cmd_message cmdmsg;
    size_t wlen, offset = 0;

    while ((wlen = MIN(buf_len, CMDMSG_DATA_SIZE)) > 0) {
        memset(&cmdmsg, 0, sizeof(cmdmsg));
        cmdmsg.type = CMDMSG_T_REPLY;
        cmdmsg.status = err ? CMDMSG_S_FAIL : CMDMSG_S_SUCCESS;
        cmdmsg.data_size = wlen;
        strncpy(cmdmsg.data, buf + offset, wlen);
        if (write_cmd_message(fd, &cmdmsg) < 0)
            return -1;
        buf_len -= wlen;
        offset += wlen;
    }
    return 0;
}

int
unixctl_command_reply(int fd, const char *format, ...) {
    char buf[CMDMSG_DATA_SIZE];
    va_list ap;
    int buf_len;

    va_start(ap, format);
    buf_len = vsnprintf(buf, CMDMSG_DATA_SIZE, format, ap);
    va_end(ap);
    if (buf_len < 0)
        return -1;
    return __unixctl_command_reply(fd, FALSE, buf, buf_len);
}

int
unixctl_command_reply_error(int fd, const char *format, ...) {
    char buf[CMDMSG_DATA_SIZE];
    va_list ap;
    int buf_len;

    va_start(ap, format);
    buf_len = vsnprintf(buf, CMDMSG_DATA_SIZE, format, ap);
    va_end(ap);
    if (buf_len < 0)
        return -1;
    return __unixctl_command_reply(fd, TRUE, buf, buf_len);
}

static struct unixctl_cmd_entry *
unixctl_cmd_lookup_by_name(const char *name) {
    struct unixctl_cmd_entry *entry;

    TAILQ_FOREACH(entry, &unixctl_cmd_entries, next) {
        if (strcmp(entry->name, name) == 0)
            return entry;
    }
    return NULL;
}

int
unixctl_command_register(const char *name, const char *usage,
                         const char *summary, int min_argc, int max_argc,
                         unixctl_command_cb_func *cb) {
    struct unixctl_cmd_entry *entry;

    if (unixctl_cmd_lookup_by_name(name))
        return -1;
    if (min_argc > max_argc)
        return -1;
    entry = malloc(sizeof(struct unixctl_cmd_entry));
    if (!entry)
        return -1;
    entry->name = name;
    entry->usage = usage;
    entry->summary = summary;
    entry->min_argc = min_argc;
    entry->max_argc = max_argc;
    entry->cb = cb;
    TAILQ_INSERT_TAIL(&unixctl_cmd_entries, entry, next);
    return 0;
}

#define PARSE_DELIMITER " \f\n\r\t\v"
static int
parse_tokenize_string(char *string, char *tokens[], uint32_t *n_tokens) {
    uint32_t i;

    if ((string == NULL) || (tokens == NULL) || (*n_tokens < 1))
        return -EINVAL;

    for (i = 0; i < *n_tokens; i++) {
        tokens[i] = strtok_r(string, PARSE_DELIMITER, &string);
        if (tokens[i] == NULL)
            break;
    }

    if ((i == *n_tokens) &&
        (NULL != strtok_r(string, PARSE_DELIMITER, &string)))
        return -E2BIG;

    *n_tokens = i;
    return 0;
}

static void
unixctl_list_command_cb(int fd, __attribute__((unused)) char *argv[],
                        __attribute__((unused)) int argc) {
    struct unixctl_cmd_entry *entry;

    unixctl_command_reply(fd, "COMMAND LIST:\n");
    TAILQ_FOREACH(entry, &unixctl_cmd_entries, next) {
        unixctl_command_reply(fd, "  %-40s  %s\n"
                                  "  %-40c  %s\n\n",
                              entry->name, entry->usage, ' ', entry->summary);
    }
}

void
unixctl_server_run_once(int unixctl_server_fd) {
    struct unixctl_cmd_message cmdmsg;
    int cfd;
    char *tokens[CMD_MAX_OPTIONS];
    uint32_t n_tokens = CMD_MAX_OPTIONS;
    struct unixctl_cmd_entry *entry;

    cfd = accept(unixctl_server_fd, NULL, NULL);
    if (cfd < 0)
        return;
    if (read_cmd_message(cfd, &cmdmsg) <= 0)
        goto end;
    if (parse_tokenize_string(cmdmsg.data, tokens, &n_tokens) < 0) {
        unixctl_command_reply_error(cfd, "Too many parameters.\n");
        goto end;
    }
    if (n_tokens == 0) {
        unixctl_list_command_cb(cfd, NULL, 0);
        goto end;
    }
    entry = unixctl_cmd_lookup_by_name(tokens[0]);
    if (!entry) {
        unixctl_command_reply_error(cfd, "Unknow command: %s.\n", tokens[0]);
        goto end;
    }
    if (entry->min_argc > n_tokens - 1) {
        unixctl_command_reply_error(cfd, "Too few parameters.\n");
        goto end;
    }
    if (entry->max_argc < n_tokens - 1) {
        unixctl_command_reply_error(cfd, "Too many parameters.\n");
        goto end;
    }
    if (entry->cb)
        entry->cb(cfd, tokens + 1, n_tokens - 1);
end:
    close(cfd);
}

int
unixctl_server_create(const char *path) {
    struct sockaddr_un un;
    int fd;

    if (!path)
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
        return -1;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0)
        return -1;
    if (listen(fd, 10) < 0)
        return -1;
    unixctl_command_register("list-command", "", "List all the commands.", 0, 0,
                             unixctl_list_command_cb);
    return fd;
}

void
unixctl_server_destory(int fd, const char *path) {
    close(fd);
    unlink(path);
}

int
unixctl_client_create(const char *path) {
    struct sockaddr_un un;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, path);
    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void
unixctl_client_destory(int fd, __attribute__((unused)) const char *path) {
    close(fd);
}

int
unixctl_client_request(int fd, const char *cmdline) {
    struct unixctl_cmd_message cmdmsg = {0};

    cmdmsg.data_size = strlen(cmdline);
    strncpy(cmdmsg.data, cmdline, cmdmsg.data_size);
    if (write_cmd_message(fd, &cmdmsg) < 0) {
        return -1;
    }

    while (read_cmd_message(fd, &cmdmsg) > 0) {
        if (cmdmsg.status == CMDMSG_S_FAIL) {
            fprintf(stderr, "%s", cmdmsg.data);
            return 1;
        }
        fprintf(stdout, "%s", cmdmsg.data);
        fflush(stdout);
    }
    return 0;
}

