#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include "include/kctf.h"

/*
 * resolver.c — Phase 5.1 动态符号解析
 *
 * 函数名加密方案（独立于 strings.c）：
 *   key_byte(id, pos) = ((id * 0x5B + 0x3C) ^ (pos * 0x1F)) & 0xFF
 *
 * 函数 ID 表：
 *   0  clock_gettime
 *   1  fopen
 *   2  fgets
 *   3  fclose
 *   4  open
 *   5  read
 *   6  close
 *   7  mprotect
 *   8  mmap
 *   9  munmap
 */

/* ── 加密函数名（precomputed）──────────────────────────── */
static const uint8_t RN_0[] = {
    0x5F,0x4F,0x6D,0x02,0x2B,0xF8,0xE1,0x80,0xB0,0x5F,0x63,0x04,0x2D
};  /* clock_gettime */

static const uint8_t RN_1[] = {
    0xF1,0xE7,0xD9,0xAF,0x85
};  /* fopen */

static const uint8_t RN_2[] = {
    0x94,0x8A,0xA9,0xDB,0xFD
};  /* fgets */

static const uint8_t RN_3[] = {
    0x2B,0x31,0x1F,0x7F,0x42,0xB3
};  /* fclose */

static const uint8_t RN_4[] = {
    0xC7,0xC7,0xF3,0x9B
};  /* open */

static const uint8_t RN_5[] = {
    0x71,0x79,0x5C,0x3A
};  /* read */

static const uint8_t RN_6[] = {
    0x3D,0x2D,0x0F,0x70,0x47
};  /* close */

static const uint8_t RN_7[] = {
    0xD4,0xD6,0xF5,0x8B,0xB1,0x47,0x60,0x14
};  /* mprotect */

static const uint8_t RN_8[] = {
    0x79,0x66,0x4B,0x39
};  /* mmap */

static const uint8_t RN_9[] = {
    0x02,0x05,0x3F,0x5F,0x72,0x84
};  /* munmap */

static const struct {
    const uint8_t *enc;
    uint8_t        len;
} RN_TABLE[10] = {
    { RN_0, 13 }, { RN_1,  5 }, { RN_2,  5 }, { RN_3,  6 },
    { RN_4,  4 }, { RN_5,  4 }, { RN_6,  5 }, { RN_7,  8 },
    { RN_8,  4 }, { RN_9,  6 },
};

/* ── 解析缓存 ─────────────────────────────────────────── */
static void *g_cache[10];
static int   g_resolved[10];

/* ── 解密函数名到临时缓冲区 ──────────────────────────── */
static void decrypt_name(int id, char out[32]) {
    const uint8_t *enc = RN_TABLE[id].enc;
    uint8_t        len = RN_TABLE[id].len;
    uint8_t base = (uint8_t)((id * 0x5B + 0x3C) & 0xFF);
    for (int pos = 0; pos < len; pos++) {
        uint8_t k = base ^ (uint8_t)((pos * 0x1F) & 0xFF);
        out[pos] = (char)(enc[pos] ^ k);
    }
    out[len] = '\0';
}

/*
 * get_func — 按 ID 解析并缓存函数指针。
 * 使用 RTLD_DEFAULT（当前进程已加载的所有库）。
 */
void *get_func(const char *name) {
    /* name 参数保留兼容性，实际通过 ID 查表 */
    (void)name;
    return NULL;
}

/* get_func_by_id — 内部使用，按 ID 解析 */
void *get_func_by_id(int id) {
    if (id < 0 || id >= 10) return NULL;
    if (g_resolved[id]) return g_cache[id];

    char fname[32];
    decrypt_name(id, fname);
    g_cache[id]    = dlsym(RTLD_DEFAULT, fname);
    g_resolved[id] = 1;
    return g_cache[id];
}
