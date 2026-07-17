#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "include/kctf.h"

extern const uint8_t kctf_guard_start[];
extern const uint8_t kctf_guard_end[];

void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

__attribute__((noinline))
uint32_t kctf_guard_anchor(void) {
    uintptr_t start = (uintptr_t)kctf_guard_start;
    uintptr_t end = (uintptr_t)kctf_guard_end;
    return (uint32_t)((end - start) ^ (start >> 4));
}

uint32_t kctf_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static uint64_t parse_hex_u64(const char **pp) {
    const char *p = *pp;
    uint64_t v = 0;
    while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
           (*p >= 'A' && *p <= 'F')) {
        uint8_t d = (uint8_t)((*p <= '9') ? (*p - '0') :
                   ((*p <= 'F') ? (*p - 'A' + 10) : (*p - 'a' + 10)));
        v = (v << 4) | d;
        p++;
    }
    *pp = p;
    return v;
}

uint32_t kctf_runtime_text_crc(uint32_t text_off, uint32_t text_size) {
    (void)text_off;
    uintptr_t start = (uintptr_t)kctf_guard_start;
    uintptr_t end = (uintptr_t)kctf_guard_end;
    if (end <= start) return 0;

    size_t guard_size = (size_t)(end - start);
    if (text_size == 0 || text_size > (4u << 20)) return 0;
    if (guard_size != (size_t)text_size) return 0;

    return kctf_crc32((const uint8_t *)start, guard_size);
}
