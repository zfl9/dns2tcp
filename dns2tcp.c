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

#define DNS2TCP_VERSION "dns2tcp v1.0"

static bool       g_verbose                 = false;
static uv_loop_t *g_evloop                  = NULL;
static char       g_listen_ipstr[IP6STRLEN] = {0};
static portno_t   g_listen_portno           = 0;
static skaddr6_t  g_listen_skaddr           = {0};
static char       g_remote_ipstr[IP6STRLEN] = {0};
static portno_t   g_remote_portno           = 0;
static skaddr6_t  g_remote_skaddr           = {0};

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

static void parse_address_opt(char *ip_port_str, bool is_listen_addr) {
    const char *opt_name = is_listen_addr ? "listen" : "remote";

    char *portstr = strchr(ip_port_str, '#');
    if (!portstr) {
        printf("[parse_address_opt] %s port is not specified\n", opt_name);
        goto PRINT_HELP_AND_EXIT;
    }
    if (portstr == ip_port_str) {
        printf("[parse_address_opt] %s addr is not specified\n", opt_name);
        goto PRINT_HELP_AND_EXIT;
    }

    *portstr = 0; ++portstr;
    if (strlen(portstr) + 1 > PORTSTRLEN) {
        printf("[parse_address_opt] %s port is invalid: %s\n", opt_name, portstr);
        goto PRINT_HELP_AND_EXIT;
    }
    portno_t portno = strtol(portstr, NULL, 10);
    if (portno == 0) {
        printf("[parse_address_opt] %s port is invalid: %s\n", opt_name, portstr);
        goto PRINT_HELP_AND_EXIT;
    }

    char *ipstr = ip_port_str;
    if (strlen(ipstr) + 1 > IP6STRLEN) {
        printf("[parse_address_opt] %s addr is invalid: %s\n", opt_name, ipstr);
        goto PRINT_HELP_AND_EXIT;
    }
    int ipfamily = get_ipstr_family(ipstr);
    if (ipfamily == -1) {
        printf("[parse_address_opt] %s addr is invalid: %s\n", opt_name, ipstr);
        goto PRINT_HELP_AND_EXIT;
    }

    void *skaddr_ptr = is_listen_addr ? &g_listen_skaddr : &g_remote_skaddr;
    if (ipfamily == AF_INET) {
        build_ipv4_addr(skaddr_ptr, ipstr, portno);
    } else {
        build_ipv6_addr(skaddr_ptr, ipstr, portno);
    }

    if (is_listen_addr) {
        strcpy(g_listen_ipstr, ipstr);
        g_listen_portno = portno;
    } else {
        strcpy(g_remote_ipstr, ipstr);
        g_remote_portno = portno;
    }
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

static void parse_command_args(int argc, char *argv[]) {
    char *opt_listen_addr = NULL;
    char *opt_remote_addr = NULL;

    opterr = 0;
    int shortopt = -1;
    const char *optstr = "L:R:vVh";
    while ((shortopt = getopt(argc, argv, optstr)) != -1) {
        switch (shortopt) {
            case 'L':
                opt_listen_addr = optarg;
                break;
            case 'R':
                opt_remote_addr = optarg;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(DNS2TCP_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case '?':
                if (!strchr(optstr, optopt)) {
                    printf("[parse_command_args] unknown option '-%c'\n", optopt);
                } else {
                    printf("[parse_command_args] missing optval '-%c'\n", optopt);
                }
                goto PRINT_HELP_AND_EXIT;
        }
    }

    if (!opt_listen_addr) {
        printf("[parse_command_args] missing option: '-L'\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!opt_remote_addr) {
        printf("[parse_command_args] missing option: '-R'\n");
        goto PRINT_HELP_AND_EXIT;
    }

    parse_address_opt(opt_listen_addr, true);
    parse_address_opt(opt_remote_addr, false);
    return;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_command_args(argc, argv);

    // TODO

    return 0;
}
