#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "include/kctf.h"

/* ── 蜜罐 C 全局变量（伪装为日志级别）──────────────── */
static volatile uint8_t g_log_verbosity  = 0x02;  /* 正常值 = 2 */
static          int     g_logging_checked = 0;

/* ── /proc/self/maps 扫描（检测点 C）────────────────── */
static void adjust_logging(void) {
    typedef FILE *(*fn_fopen)(const char *, const char *);
    typedef char *(*fn_fgets)(char *, int, FILE *);
    typedef int   (*fn_fclose)(FILE *);
    fn_fopen  p_fopen  = (fn_fopen) get_func_by_id(1);
    fn_fgets  p_fgets  = (fn_fgets) get_func_by_id(2);
    fn_fclose p_fclose = (fn_fclose)get_func_by_id(3);

    FILE *f = p_fopen ? p_fopen(get_string(2), "r") : NULL;
    if (!f) return;
    char line[512];
    int suspicious = 0;
    while (p_fgets ? p_fgets(line, sizeof(line), f) : NULL) {
        /* 原有检测：frida/xposed/substrate/gadget 关键字 */
        if (strstr(line, get_string(3)) ||
            strstr(line, get_string(4)) ||
            strstr(line, get_string(5)) ||
            strstr(line, get_string(6)))
            suspicious++;

        /* 新增：大匿名可执行内存段检测
         * Frida 注入后申请 >2MB 的匿名 rwx/r-x 内存块
         * 格式：7a1000-9a1000 r-xp 00000000 00:00 0
         * 特征：权限含 x，无文件路径（行尾无 '/'），大小 > 0x200000 */
        if (strstr(line, "x") && !strstr(line, "/")) {
            /* 解析地址范围 */
            unsigned long lo = 0, hi = 0;
            int i = 0;
            while (line[i] && line[i] != '-') {
                char c = line[i];
                lo = lo * 16 + (c >= 'a' ? c-'a'+10 : c >= 'A' ? c-'A'+10 : c-'0');
                i++;
            }
            if (line[i] == '-') {
                i++;
                while (line[i] && line[i] != ' ') {
                    char c = line[i];
                    hi = hi * 16 + (c >= 'a' ? c-'a'+10 : c >= 'A' ? c-'A'+10 : c-'0');
                    i++;
                }
            }
            if ((hi - lo) > 0x200000)
                suspicious++;
        }
    }
    if (p_fclose) p_fclose(f);
    g_log_verbosity = suspicious ? 0x00u : 0x02u;
}

/*
 * generate_sbox — 伪装名：aes_sbox_init
 * Fisher-Yates shuffle 由 xorshift32 驱动，生成 256 字节双射置换表。
 * 蜜罐 C（显式分支）：Frida 注入 → limit=128 → 后半恒等 → 非双射。
 */
void generate_sbox(uint32_t seed, uint8_t sbox[256]) {
    __asm__ volatile(
        "cmp xzr, xzr\n\t"
        "b.eq 1f\n\t"
        ".word 0xCAFEBABE\n\t"
        "1:\n\t"
        ::: "cc"
    );
    if (!g_logging_checked) {
        adjust_logging();
        g_logging_checked = 1;
    }

    for (int i = 0; i < 256; i++) sbox[i] = (uint8_t)i;

    /* 正常 verbosity=2 → limit=255（完整 shuffle）
     * 异常 verbosity=0 → limit=128（后半恒等，非双射）  */
    int limit = (g_log_verbosity == 0x02u) ? 255 : 128;

    uint32_t xs = seed;
    for (int i = limit; i > 0; i--) {
        xs ^= xs << 13;
        xs ^= xs >> 17;
        xs ^= xs << 5;
        uint8_t j = (uint8_t)(xs % (uint32_t)(i + 1));
        uint8_t tmp = sbox[i]; sbox[i] = sbox[j]; sbox[j] = tmp;
    }
}
