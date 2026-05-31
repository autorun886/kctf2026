#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "include/kctf.h"

/* g_render_mode 定义在此，spn_round.c 通过 extern 引用 */
volatile uint32_t g_render_mode = 0x00u;

static int parse_tracer_pid(const char *buf) {
    const char *p = strstr(buf, get_string(1));  /* "TracerPid:" */
    if (!p) return 0;
    p += 10;
    while (*p == ' ' || *p == '\t') p++;
    int val = 0;
    while (*p >= '0' && *p <= '9') {
        val = val * 10 + (*p - '0');
        p++;
    }
    return val;
}

__attribute__((constructor(101)))
static void early_init(void) {
    char buf[512];
    int fd = open(get_string(0), O_RDONLY);  /* "/proc/self/status" */
    if (fd < 0) return;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    if (parse_tracer_pid(buf) != 0)
        g_render_mode = 0x01u;
}
