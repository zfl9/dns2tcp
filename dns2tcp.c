#define _GNU_SOURCE
#include "logutils.h"
#include <uv.h>
#undef _GNU_SOURCE

int main(void) {
    LOGINF("[main] hello, world!");
    return 0;
}
