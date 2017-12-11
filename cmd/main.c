/* Copyright (c) 2017. TIG developer. */

#include <stdio.h>
#include <string.h>

#include "unixctl_command.h"

static const char *default_unix_sock_path = "/var/run/jupiter.sock";

static void
usage(const char *progname) {
    printf("Usage: %s COMMAND [ARG...] [--unixsock=%s]\n", progname,
           default_unix_sock_path);
}

static const char *
parse_progname(const char *arg) {
    char *p;
    if ((p = strrchr(arg, '/')) != NULL)
        return strdup(p + 1);
    return strdup(arg);
}

int
main(int argc, char **argv) {
    const char *unix_sock_path = NULL;
    char cmdline[1024] = {0};
    int client, ret;
    int i;

    for (i = 1; i < argc; i++) {
        if (strncmp("--unixsock=", argv[i], strlen("--unixsock=")) == 0) {
            unix_sock_path = strdup(argv[i] + strlen("--unixsock="));
        } else {
            strcat(cmdline, argv[i]);
            strcat(cmdline, " ");
        }
    }
    if (!unix_sock_path)
        unix_sock_path = default_unix_sock_path;
    if (strlen(cmdline) == 0) {
        const char *progname;
        progname = parse_progname(argv[0]);
        usage(progname);
        strcat(cmdline, "list-command");
    }
    client = unixctl_client_create(unix_sock_path);
    if (client < 0) {
        fprintf(stderr, "Create unix socket client failed.\n");
        return -1;
    }
    ret = unixctl_client_request(client, cmdline);
    if (ret < 0) {
        fprintf(stderr, "Unable to request unix socket server.\n");
        return -1;
    }
    return ret != 0 ? -1 : 0;
}

