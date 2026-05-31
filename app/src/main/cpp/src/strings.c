#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/*
 * strings.c — Phase 5.2 加密字符串表
 *
 * 密钥方案：key_byte(id, pos) = ((id * 0x37 + 0xA5) ^ (pos * 0x13)) & 0xFF
 * 解密：plain[pos] = enc[pos] ^ key_byte(id, pos)
 *
 * 字符串 ID 表：
 *   0  "/proc/self/status"
 *   1  "TracerPid:"
 *   2  "/proc/self/maps"
 *   3  "frida"
 *   4  "xposed"
 *   5  "substrate"
 *   6  "gadget"
 */

/* ── 加密数据（precomputed）────────────────────────────── */
static const uint8_t ENC_0[] = {
    0x8A,0xC6,0xF1,0xF3,0x8A,0xD5,0xA4,0x45,
    0x51,0x68,0x34,0x07,0x35,0x33,0xDB,0xCD,0xE6
};  /* /proc/self/status */

static const uint8_t ENC_1[] = {
    0x88,0xBD,0x9B,0x86,0xF5,0xF1,0xFE,0x30,0x20,0x4D
};  /* TracerPid: */

static const uint8_t ENC_2[] = {
    0x3C,0x70,0x47,0x45,0x3C,0x63,0x12,0xF3,
    0xE7,0xDE,0x82,0xAF,0x96,0x94,0x6A
};  /* /proc/self/maps */

static const uint8_t ENC_3[] = {
    0x2C,0x2B,0x05,0x17,0x67
};  /* frida */

static const uint8_t ENC_4[] = {
    0xF9,0xE2,0xC8,0xCB,0xA8,0xBA
};  /* xposed */

static const uint8_t ENC_5[] = {
    0xCB,0xDE,0xFC,0xF2,0x80,0x95,0xAB,0x49,0x45
};  /* substrate */

static const uint8_t ENC_6[] = {
    0x88,0x9D,0xAD,0xB1,0xC6,0xC4
};  /* gadget */

/* ── 字符串描述表 ─────────────────────────────────────── */
static const struct {
    const uint8_t *enc;
    uint8_t        len;
} STR_TABLE[7] = {
    { ENC_0, 17 },
    { ENC_1, 10 },
    { ENC_2, 15 },
    { ENC_3,  5 },
    { ENC_4,  6 },
    { ENC_5,  9 },
    { ENC_6,  6 },
};

/* ── 解密缓冲区（最长 18 字节 + null）────────────────── */
static char g_str_buf[32];

/*
 * get_string — 解密并返回字符串指针。
 * 非线程安全（单线程初始化路径，可接受）。
 */
const char *get_string(int id) {
    if (id < 0 || id >= 7) return "";
    const uint8_t *enc = STR_TABLE[id].enc;
    uint8_t        len = STR_TABLE[id].len;
    uint8_t base = (uint8_t)((id * 0x37 + 0xA5) & 0xFF);
    for (int pos = 0; pos < len; pos++) {
        uint8_t k = base ^ (uint8_t)((pos * 0x13) & 0xFF);
        g_str_buf[pos] = (char)(enc[pos] ^ k);
    }
    g_str_buf[len] = '\0';
    return g_str_buf;
}
