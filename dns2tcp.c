#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "libev/ev.h"

#define DNS2TCP_VER "dns2tcp v1.1.1"

#ifndef IPV6_V6ONLY
  #define IPV6_V6ONLY 26
#endif

#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

#ifndef TCP_SYNCNT
  #define TCP_SYNCNT 7
#endif

#define IP4STRLEN INET_ADDRSTRLEN /* include \0 */
#define IP6STRLEN INET6_ADDRSTRLEN /* include \0 */
#define PORTSTRLEN 6 /* "65535" (include \0) */

#define DNS_MSGSZ 1472 /* mtu:1500 - iphdr:20 - udphdr:8 */

/* ======================== helper ======================== */

#define __unused __attribute__((unused))

#define alignto(alignment) __attribute__((aligned(alignment)))

// get the struct pointer by the field(member) pointer
#define container_of(p_field, struct_type, field_name) ( \
    (struct_type *) ((void *)(p_field) - offsetof(struct_type, field_name)) \
)

/* ======================== log-func ======================== */

#define log_write(color, level, fmt, args...) ({ \
    time_t t_ = time(NULL); \
    const struct tm *tm_ = localtime(&t_); \
    printf("\e[" color ";1m%d-%02d-%02d %02d:%02d:%02d " level "\e[0m " \
        "\e[1m[%s]\e[0m " fmt "\n", \
        tm_->tm_year + 1900, tm_->tm_mon + 1, tm_->tm_mday, \
        tm_->tm_hour,        tm_->tm_min,     tm_->tm_sec, \
        __func__, ##args); \
})

#define log_verbose(fmt, args...) ({ \
    if (verbose()) log_info(fmt, ##args); \
})

#define log_info(fmt, args...) \
    log_write("32", "I", fmt, ##args)

#define log_warning(fmt, args...) \
    log_write("33", "W", fmt, ##args)

#define log_error(fmt, args...) \
    log_write("35", "E", fmt, ##args)

/* ======================== socket-addr ======================== */

union skaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

#define skaddr_family(addr) ((addr)->sa.sa_family)
#define skaddr_is_sin(addr) (skaddr_family(addr) == AF_INET)
#define skaddr_is_sin6(addr) (skaddr_family(addr) == AF_INET6)
#define skaddr_len(addr) (skaddr_is_sin(addr) ? sizeof((addr)->sin) : sizeof((addr)->sin6))

static void skaddr_from_text(union skaddr *addr, int family, const char *ipstr, uint16_t port) {
    if (family == AF_INET) {
        addr->sin.sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &addr->sin.sin_addr);
        addr->sin.sin_port = htons(port);
    } else {
        addr->sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &addr->sin6.sin6_addr);
        addr->sin6.sin6_port = htons(port);
    }
}

static void skaddr_to_text(const union skaddr *addr, char *ipstr, uint16_t *port) {
    if (skaddr_is_sin(addr)) {
        inet_ntop(AF_INET, &addr->sin.sin_addr, ipstr, IP4STRLEN);
        *port = ntohs(addr->sin.sin_port);
    } else {
        inet_ntop(AF_INET6, &addr->sin6.sin6_addr, ipstr, IP6STRLEN);
        *port = ntohs(addr->sin6.sin6_port);
    }
}

/* AF_INET, AF_INET6, -1(invalid) */
static int get_ipstr_family(const char *ipstr) {
    char tmp[16];
    if (!ipstr)
        return -1;
    if (inet_pton(AF_INET, ipstr, &tmp) == 1)
        return AF_INET;
    if (inet_pton(AF_INET6, ipstr, &tmp) == 1)
        return AF_INET6;
    return -1;
}

/* ======================== context ======================== */

typedef struct {
    evio_t       watcher; /* tcp watcher */
    char         buffer[2 + DNS_MSGSZ] alignto(__alignof__(uint16_t)); /* msglen(be16) + msg */
    uint16_t     nbytes; /* nrecv or nsend */
    union skaddr srcaddr;
} ctx_t;

/* ======================== global-vars ======================== */

enum {
    OPT_IPV6_V6ONLY = 1 << 0,
    OPT_REUSE_PORT  = 1 << 1,
    OPT_VERBOSE     = 1 << 2,
};

#define has_opt(opt) (g_options & (opt))
#define enable_opt(opt) (g_options |= (opt))

#define verbose() has_opt(OPT_VERBOSE)

static uint8_t g_options    = 0;
static uint8_t g_syn_maxcnt = 0;

static int          g_udp_sockfd              = -1;
static char         g_listen_ipstr[IP6STRLEN] = {0};
static uint16_t     g_listen_port             = 0;
static union skaddr g_listen_skaddr           = {0};

static char         g_remote_ipstr[IP6STRLEN] = {0};
static uint16_t     g_remote_port             = 0;
static union skaddr g_remote_skaddr           = {0};

static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events);

static void print_help(void) {
    printf("usage: dns2tcp <-L listen> <-R remote> [-s syncnt] [-6rvVh]\n"
           " -L <ip[#port]>          udp listen address, this is required\n"
           " -R <ip[#port]>          tcp remote address, this is required\n"
           " -s <syncnt>             set TCP_SYNCNT(max) for remote socket\n"
           " -6                      enable IPV6_V6ONLY for listen socket\n"
           " -r                      enable SO_REUSEPORT for listen socket\n"
           " -v                      print verbose log, default: <disabled>\n"
           " -V                      print version number of dns2tcp and exit\n"
           " -h                      print help information of dns2tcp and exit\n"
           "bug report: https://github.com/zfl9/dns2tcp. email: zfl9.com@gmail.com\n"
    );
}

static void parse_addr(const char *addr, bool is_listen_addr) {
    const char *end = addr + strlen(addr);
    const char *sep = strchr(addr, '#') ?: end;

    const char *ipstart = addr;
    int iplen = sep - ipstart;

    const char *portstart = sep + 1;
    int portlen = (sep < end) ? end - portstart : -1;

    char ipstr[IP6STRLEN];
    if (iplen >= IP6STRLEN) goto err;

    memcpy(ipstr, ipstart, iplen);
    ipstr[iplen] = 0;

    int family = get_ipstr_family(ipstr);
    if (family == -1) goto err;

    uint16_t port = 53;
    if (portlen >= 0 && (port = strtoul(portstart, NULL, 10)) == 0) goto err;

    if (is_listen_addr) {
        strcpy(g_listen_ipstr, ipstr);
        g_listen_port = port;
        skaddr_from_text(&g_listen_skaddr, family, ipstr, port);
    } else {
        strcpy(g_remote_ipstr, ipstr);
        g_remote_port = port;
        skaddr_from_text(&g_remote_skaddr, family, ipstr, port);
    }
    return;

err:;
    const char *type = is_listen_addr ? "listen" : "remote";
    printf("invalid %s address: '%s'\n", type, addr);
    print_help();
    exit(1);
}

static void parse_opt(int argc, char *argv[]) {
    char opt_listen_addr[IP6STRLEN + PORTSTRLEN] = {0};
    char opt_remote_addr[IP6STRLEN + PORTSTRLEN] = {0};

    opterr = 0;
    int shortopt;
    const char *optstr = "L:R:s:6rafvVh";
    while ((shortopt = getopt(argc, argv, optstr)) != -1) {
        switch (shortopt) {
            case 'L':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid listen addr: %s\n", optarg);
                    goto err;
                }
                strcpy(opt_listen_addr, optarg);
                break;
            case 'R':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid remote addr: %s\n", optarg);
                    goto err;
                }
                strcpy(opt_remote_addr, optarg);
                break;
            case 's':
                g_syn_maxcnt = strtoul(optarg, NULL, 10);
                if (g_syn_maxcnt == 0) {
                    printf("invalid tcp syn cnt: %s\n", optarg);
                    goto err;
                }
                break;
            case '6':
                enable_opt(OPT_IPV6_V6ONLY);
                break;
            case 'r':
                enable_opt(OPT_REUSE_PORT);
                break;
            case 'a':
                /* nop */
                break;
            case 'f':
                /* nop */
                break;
            case 'v':
                enable_opt(OPT_VERBOSE);
                break;
            case 'V':
                printf(DNS2TCP_VER"\n");
                exit(0);
            case 'h':
                print_help();
                exit(0);
            case '?':
                if (!strchr(optstr, optopt)) {
                    printf("unknown option '-%c'\n", optopt);
                } else {
                    printf("missing optval '-%c'\n", optopt);
                }
                goto err;
        }
    }

    if (strlen(opt_listen_addr) == 0) {
        printf("missing option: '-L'\n");
        goto err;
    }
    if (strlen(opt_remote_addr) == 0) {
        printf("missing option: '-R'\n");
        goto err;
    }

    parse_addr(opt_listen_addr, true);
    parse_addr(opt_remote_addr, false);
    return;

err:
    print_help();
    exit(1);
}

/* udp listen or tcp connect */
static int create_socket(int family, int type) {
    const char *err_op = NULL;

    int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err_op = "create_socket";
        goto out;
    }

    const int opt = 1;
    if (type == SOCK_DGRAM) {
        // udp listen socket
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            err_op = "set_reuseaddr";
            goto out;
        }
        if (has_opt(OPT_REUSE_PORT) && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            err_op = "set_reuseport";
            goto out;
        }
        if (family == AF_INET6 && has_opt(OPT_IPV6_V6ONLY) && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            err_op = "set_ipv6only";
            goto out;
        }
    } else {
        // tcp connect socket
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
            err_op = "set_tcp_nodelay";
            goto out;
        }
        const int syn_maxcnt = g_syn_maxcnt;
        if (syn_maxcnt && setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_maxcnt, sizeof(syn_maxcnt)) < 0) {
            err_op = "set_tcp_syncnt";
            goto out;
        }
    }

out:
    if (err_op)
        log_error("%s(fd:%d, family:%d, type:%d) failed: %m", err_op, fd, family, type);
    return fd;
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_opt(argc, argv);

    log_info("udp listen addr: %s#%hu", g_listen_ipstr, g_listen_port);
    log_info("tcp remote addr: %s#%hu", g_remote_ipstr, g_remote_port);
    if (g_syn_maxcnt) log_info("enable TCP_SYNCNT:%hhu sockopt", g_syn_maxcnt);
    if (has_opt(OPT_IPV6_V6ONLY)) log_info("enable IPV6_V6ONLY sockopt");
    if (has_opt(OPT_REUSE_PORT)) log_info("enable SO_REUSEPORT sockopt");
    log_verbose("verbose mode, affect performance");

    g_udp_sockfd = create_socket(skaddr_family(&g_listen_skaddr), SOCK_DGRAM);
    if (g_udp_sockfd < 0)
        return 1;

    if (bind(g_udp_sockfd, &g_listen_skaddr.sa, skaddr_len(&g_listen_skaddr)) < 0) {
        log_error("bind udp address: %m");
        return 1;
    }

    evloop_t *evloop = ev_default_loop(0);

    evio_t watcher;
    ev_io_init(&watcher, udp_recvmsg_cb, g_udp_sockfd, EV_READ);
    ev_io_start(evloop, &watcher);

    return ev_run(evloop, 0);
}

static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher __unused, int events __unused) {
    ctx_t *ctx = malloc(sizeof(*ctx));

    ssize_t nrecv = recvfrom(g_udp_sockfd, (void *)ctx->buffer + 2, DNS_MSGSZ, 0, &ctx->srcaddr.sa, &(socklen_t){sizeof(ctx->srcaddr)});
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_warning("recv from udp socket: %m");
        goto free_ctx;
    }

    if (verbose()) {
        char ip[IP6STRLEN];
        uint16_t port;
        skaddr_to_text(&ctx->srcaddr, ip, &port);
        log_info("recv from %s#%hu, nrecv:%zd", ip, port, nrecv);
    }

    uint16_t *p_msglen = (void *)ctx->buffer;
    *p_msglen = htons(nrecv); /* msg length */

    int sockfd = create_socket(skaddr_family(&g_remote_skaddr), SOCK_STREAM);
    if (sockfd < 0)
        goto free_ctx;

    if (connect(sockfd, &g_remote_skaddr.sa, skaddr_len(&g_remote_skaddr)) < 0 && errno != EINPROGRESS) {
        log_warning("connect to %s#%hu: %m", g_remote_ipstr, g_remote_port);
        goto close_sockfd;
    }
    log_verbose("try to connect to %s#%hu", g_remote_ipstr, g_remote_port);

    ev_io_init(&ctx->watcher, tcp_connect_cb, sockfd, EV_WRITE);
    ev_io_start(evloop, &ctx->watcher);

    return;

close_sockfd:
    close(sockfd);
free_ctx:
    free(ctx);
}

static void free_ctx(ctx_t *ctx, evloop_t *evloop) {
    ev_io_stop(evloop, &ctx->watcher);
    close(ctx->watcher.fd);
    free(ctx);
}

static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    ctx_t *ctx = container_of(watcher, ctx_t, watcher);

    if (getsockopt(watcher->fd, SOL_SOCKET, SO_ERROR, &errno, &(socklen_t){sizeof(errno)}) < 0 || errno) {
        log_warning("connect to %s#%hu: %m", g_remote_ipstr, g_remote_port);
        free_ctx(ctx, evloop);
        return;
    }
    log_verbose("connect to %s#%hu succeed", g_remote_ipstr, g_remote_port);

    ctx->nbytes = 0;
    ev_set_cb(watcher, tcp_sendmsg_cb);
    ev_invoke(evloop, watcher, EV_WRITE);
}

static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    ctx_t *ctx = container_of(watcher, ctx_t, watcher);

    uint16_t *p_msglen = (void *)ctx->buffer;
    uint16_t datalen = 2 + ntohs(*p_msglen);

    ssize_t nsend = send(watcher->fd, (void *)ctx->buffer + ctx->nbytes, datalen - ctx->nbytes, 0);
    if (nsend < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        log_warning("send to %s#%hu: %m", g_remote_ipstr, g_remote_port);
        free_ctx(ctx, evloop);
        return;
    }
    log_verbose("send to %s#%hu, nsend:%zd", g_remote_ipstr, g_remote_port, nsend);

    ctx->nbytes += nsend;
    if (ctx->nbytes >= datalen) {
        ctx->nbytes = 0;
        ev_io_stop(evloop, watcher);
        ev_io_init(watcher, tcp_recvmsg_cb, watcher->fd, EV_READ);
        ev_io_start(evloop, watcher);
    }
}

static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    ctx_t *ctx = container_of(watcher, ctx_t, watcher);

    void *buffer = ctx->buffer;

    ssize_t nrecv = recv(watcher->fd, buffer + ctx->nbytes, 2 + DNS_MSGSZ - ctx->nbytes, 0);
    if (nrecv < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        log_warning("recv from %s#%hu: %m", g_remote_ipstr, g_remote_port);
        goto free_ctx;
    }
    if (nrecv == 0) {
        log_warning("recv from %s#%hu: connection is closed", g_remote_ipstr, g_remote_port);
        goto free_ctx;
    }
    log_verbose("recv from %s#%hu, nrecv:%zd", g_remote_ipstr, g_remote_port, nrecv);

    ctx->nbytes += nrecv;

    uint16_t msglen;
    if (ctx->nbytes < 2 || ctx->nbytes < 2 + (msglen = ntohs(*(uint16_t *)buffer))) return;

    ssize_t nsend = sendto(g_udp_sockfd, buffer + 2, msglen, 0, &ctx->srcaddr.sa, skaddr_len(&ctx->srcaddr));
    if (nsend < 0 || verbose()) {
        char ip[IP6STRLEN];
        uint16_t port;
        skaddr_to_text(&ctx->srcaddr, ip, &port);
        if (nsend < 0)
            log_warning("send to %s#%hu: %m", ip, port);
        else
            log_info("send to %s#%hu, nsend:%zd", ip, port, nsend);
    }

free_ctx:
    free_ctx(ctx, evloop);
}
