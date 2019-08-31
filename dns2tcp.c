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

#define IF_VERBOSE if (g_verbose)
#define DNS2TCP_VERSION "dns2tcp v1.0"

static bool       g_verbose                 = false;
static uv_loop_t *g_evloop                  = NULL;
static uv_udp_t  *g_udp_server              = NULL;
static char       g_listen_ipstr[IP6STRLEN] = {0};
static portno_t   g_listen_portno           = 0;
static skaddr6_t  g_listen_skaddr           = {0};
static char       g_remote_ipstr[IP6STRLEN] = {0};
static portno_t   g_remote_portno           = 0;
static skaddr6_t  g_remote_skaddr           = {0};

static void udp_alloc_cb(uv_handle_t *udp_server, size_t sugsize, uv_buf_t *uvbuf);
static void udp_recv_cb(uv_udp_t *udp_server, ssize_t nread, const uv_buf_t *uvbuf, const skaddr_t *skaddr, unsigned flags);

static void tcp_connect_cb(uv_connect_t *connreq, int status);
static void tcp_write_cb(uv_write_t *writereq, int status);
static void tcp_alloc_cb(uv_handle_t *tcp_client, size_t sugsize, uv_buf_t *uvbuf);
static void tcp_read_cb(uv_stream_t *tcp_client, ssize_t nread, const uv_buf_t *uvbuf);
static void tcp_close_cb(uv_handle_t *tcp_client);

static void print_command_help(void) {
    printf("usage: dns2tcp <-L LISTEN_ADDR> <-R REMOTE_ADDR> [-vVh]\n"
           " -L <ip#port>           udp listen address, it is required\n"
           " -R <ip#port>           tcp remote address, it is required\n"
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

    LOGINF("[main] udp listen addr: %s#%hu", g_listen_ipstr, g_listen_portno);
    LOGINF("[main] tcp remote addr: %s#%hu", g_remote_ipstr, g_remote_portno);
    IF_VERBOSE LOGINF("[main] verbose mode, affect performance");

    g_evloop = uv_default_loop();
    g_udp_server = &(uv_udp_t){0};
    uv_udp_init(g_evloop, g_udp_server);

    int retval = uv_udp_bind(g_udp_server, (void *)&g_listen_skaddr, 0);
    if (retval < 0) {
        LOGERR("[main] bind failed: (%d) %s", -retval, uv_strerror(retval));
        return -retval;
    }
    uv_udp_recv_start(g_udp_server, udp_alloc_cb, udp_recv_cb);

    uv_run(g_evloop, UV_RUN_DEFAULT);
    return 0;
}

static void udp_alloc_cb(uv_handle_t *udp_server __attribute__((unused)), size_t sugsize __attribute__((unused)), uv_buf_t *uvbuf) {
    uvbuf->base = malloc(DNS_PACKET_MAXSIZE + 2) + 2;
    uvbuf->len = DNS_PACKET_MAXSIZE;
}

static void udp_recv_cb(uv_udp_t *udp_server __attribute__((unused)), ssize_t nread, const uv_buf_t *uvbuf, const skaddr_t *skaddr, unsigned flags) {
    if (nread == 0) goto FREE_UVBUF;

    if (nread < 0) {
        LOGERR("[udp_recv_cb] recv failed: (%zd) %s", -nread, uv_strerror(nread));
        goto FREE_UVBUF;
    }

    if (flags & UV_UDP_PARTIAL) {
        LOGERR("[udp_recv_cb] received a partial packet, discard it");
        goto FREE_UVBUF;
    }

    IF_VERBOSE {
        char ipstr[IP6STRLEN]; portno_t portno;
        if (skaddr->sa_family == AF_INET) {
            parse_ipv4_addr((void *)skaddr, ipstr, &portno);
        } else {
            parse_ipv6_addr((void *)skaddr, ipstr, &portno);
        }
        LOGINF("[udp_recv_cb] recv %zdB data from %s#%hu", nread, ipstr, portno);
    }

    uv_tcp_t *tcp_client = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(g_evloop, tcp_client);
    uv_tcp_nodelay(tcp_client, 1);

    uint16_t *msglen_ptr = (void *)uvbuf->base - 2;
    *msglen_ptr = htons(nread);
    tcp_client->data = uvbuf->base - 2;

    uv_connect_t *connreq = malloc(sizeof(uv_connect_t));
    int retval = uv_tcp_connect(connreq, tcp_client, (void *)&g_remote_skaddr, tcp_connect_cb);
    if (retval < 0) {
        LOGERR("[udp_recv_cb] connect failed: (%d) %s", -retval, uv_strerror(retval));
        uv_close((void *)tcp_client, tcp_close_cb);
        free(connreq);
        return;
    }
    IF_VERBOSE LOGINF("[udp_recv_cb] connecting to %s#%hu", g_remote_ipstr, g_remote_portno);
    return;

FREE_UVBUF:
    free(uvbuf->base - 2);
}

static void tcp_connect_cb(uv_connect_t *connreq, int status) {
    uv_stream_t *tcp_client = connreq->handle;
    free(connreq);

    if (status < 0) {
        LOGERR("[tcp_connect_cb] connect failed: (%d) %s", -status, uv_strerror(status));
        goto CLOSE_TCPCLIENT;
    }
    IF_VERBOSE LOGINF("[tcp_connect_cb] connected to %s#%hu", g_remote_ipstr, g_remote_portno);

    uv_write_t *writereq = malloc(sizeof(uv_write_t));
    uv_buf_t uvbufs[] = {{.base = tcp_client->data, .len = ntohs(*(uint16_t *)tcp_client->data) + 2}};
    status = uv_write(writereq, tcp_client, uvbufs, 1, tcp_write_cb);
    if (status < 0) {
        LOGERR("[tcp_connect_cb] write failed: (%d) %s", -status, uv_strerror(status));
        free(writereq);
        goto CLOSE_TCPCLIENT;
    }
    IF_VERBOSE LOGINF("[tcp_connect_cb] writing %huB data to %s#%hu", ntohs(*(uint16_t *)tcp_client->data), g_remote_ipstr, g_remote_portno);
    return;

CLOSE_TCPCLIENT:
    uv_close((void *)tcp_client, tcp_close_cb);
}

static void tcp_write_cb(uv_write_t *writereq, int status) {
    uv_stream_t *tcp_client = writereq->handle;
    free(writereq);

    if (status < 0) {
        LOGERR("[tcp_write_cb] write failed: (%d) %s", -status, uv_strerror(status));
        uv_close((void *)tcp_client, tcp_close_cb);
        return;
    }
    IF_VERBOSE LOGINF("[tcp_write_cb] data has been written to %s#%hu", g_remote_ipstr, g_remote_portno);

    uv_read_start(tcp_client, tcp_alloc_cb, tcp_read_cb);
}

static void tcp_alloc_cb(uv_handle_t *tcp_client, size_t sugsize, uv_buf_t *uvbuf) {
    // TODO
}

static void tcp_read_cb(uv_stream_t *tcp_client, ssize_t nread, const uv_buf_t *uvbuf) {
    // TODO
}

static void tcp_close_cb(uv_handle_t *tcp_client) {
    // TODO
}
