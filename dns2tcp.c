#define _GNU_SOURCE
#include "logutils.h"
#include "netutils.h"
#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#undef _GNU_SOURCE

static bool g_verbose = false;

static void print_command_help(void) {
    printf("usage: dns2tcp <-L LISTEN_ADDR> <-R REMOTE_ADDR> [-vVh]\n"
           " -L <ip#port>           udp listen address, it is required\n"
           " -R <ip#port>           tcp server address, it is required\n"
           " -v                     print verbose log, default: <disabled>\n"
           " -V                     print version number of dns2tcp and exit\n"
           " -h                     print help information of dns2tcp and exit\n"
           "bug report: https://github.com/zfl9/dns2tcp. email: zfl9.com@gmail.com\n"
    );
}

static void parse_command_args(int argc, char *argv[]) {
    opterr = 0;
    int shortopt = -1;
    char *bindaddr_optarg = NULL;
    char *servaddr_optarg = NULL;
    const char *optstr = ":L:R:vVh";
    while ((shortopt = getopt(argc, argv, optstr)) != -1) {
        switch (shortopt) {
            case 'L':
                bindaddr_optarg = optarg;
                break;
            case 'R':
                servaddr_optarg = optarg;
            case 'v':
                g_verbose = true;
        }
    }
    return;
PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main() {
    print_command_help();
    return 0;
}
