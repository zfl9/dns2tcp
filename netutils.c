#define _GNU_SOURCE
#include "netutils.h"
#include <arpa/inet.h>
#undef _GNU_SOURCE

/* build ipv4 socket address from ipstr and portno */
void build_ipv4_addr(skaddr4_t *addr, const char *ipstr, portno_t portno) {
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ipstr, &addr->sin_addr);
    addr->sin_port = htons(portno);
}

/* build ipv6 socket address from ipstr and portno */
void build_ipv6_addr(skaddr6_t *addr, const char *ipstr, portno_t portno) {
    addr->sin6_family = AF_INET6;
    inet_pton(AF_INET6, ipstr, &addr->sin6_addr);
    addr->sin6_port = htons(portno);
}

/* parse ipstr and portno from ipv4 socket address */
void parse_ipv4_addr(const skaddr4_t *addr, char *ipstr, portno_t *portno) {
    inet_ntop(AF_INET, &addr->sin_addr, ipstr, IP4STRLEN);
    *portno = ntohs(addr->sin_port);
}

/* parse ipstr and portno from ipv6 socket address */
void parse_ipv6_addr(const skaddr6_t *addr, char *ipstr, portno_t *portno) {
    inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, IP6STRLEN);
    *portno = ntohs(addr->sin6_port);
}

/* AF_INET or AF_INET6 or -1(invalid ip string) */
int get_ipstr_family(const char *ipstr) {
    if (!ipstr) return -1;
    uint8_t ipaddr[16]; /* save ipv4/ipv6 addr */
    if (inet_pton(AF_INET, ipstr, &ipaddr) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, ipstr, &ipaddr) == 1) {
        return AF_INET6;
    } else {
        return -1;
    }
}
