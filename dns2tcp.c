#define _GNU_SOURCE
#include "logutils.h"
#include <uv.h>
#undef _GNU_SOURCE

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

int main() {
    print_command_help();
    return 0;
}
