#ifndef DNS2TCP_NETUTILS_H
#define DNS2TCP_NETUTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <netinet/in.h>
#undef _GNU_SOURCE

/* mtu(1500) - iphdr(20) - udphdr(8) */
#define DNS_PACKET_MAXSIZE 1472 /* bytes */

/* ipaddr string len */
#define IP4STRLEN INET_ADDRSTRLEN
#define IP6STRLEN INET6_ADDRSTRLEN

/* portno string len */
#define PORTSTRLEN 6

/* port number typedef */
typedef uint16_t portno_t;

/* sockaddr type alias */
typedef struct sockaddr     skaddr_t;
typedef struct sockaddr_in  skaddr4_t;
typedef struct sockaddr_in6 skaddr6_t;

/* build ipv4 socket address from ipstr and portno */
void build_ipv4_addr(skaddr4_t *addr, const char *ipstr, portno_t portno);

/* build ipv6 socket address from ipstr and portno */
void build_ipv6_addr(skaddr6_t *addr, const char *ipstr, portno_t portno);

/* parse ipstr and portno from ipv4 socket address */
void parse_ipv4_addr(const skaddr4_t *addr, char *ipstr, portno_t *portno);

/* parse ipstr and portno from ipv6 socket address */
void parse_ipv6_addr(const skaddr6_t *addr, char *ipstr, portno_t *portno);

/* AF_INET or AF_INET6 or -1(invalid ip string) */
int get_ipstr_family(const char *ipstr);

#endif
