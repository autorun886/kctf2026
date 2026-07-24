#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/* ── 方案 A 目标状态（precompute_a.py 计算，Release build）── */
static volatile const uint8_t ENC_EXPECTED_STATE_A[STATE_LEN] = {
    0x63, 0x87, 0x36, 0xAE, 0x57, 0x1C, 0x00, 0xC0,
    0x8A, 0x2B, 0x8F, 0xB5, 0x61, 0x1E, 0x01, 0xAA
};

static const uint8_t IV_A[STATE_LEN] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

/* ── JNI 回调获取 soKey（与方案 B 相同逻辑）────────────── */
static void fetch_sokey_a(JNIEnv *env, jobject obj, uint8_t out[SOKEY_LEN]) {
    jclass    clazz = (*env)->GetObjectClass(env, obj);
    jmethodID mid   = (*env)->GetMethodID(env, clazz, "deriveNativeKey", "()[B");
    jbyteArray jarr = (jbyteArray)(*env)->CallObjectMethod(env, obj, mid);
    (*env)->GetByteArrayRegion(env, jarr, 0, SOKEY_LEN, (jbyte *)out);
    (*env)->DeleteLocalRef(env, jarr);
    (*env)->DeleteLocalRef(env, clazz);
}

/* ── 方案 A JNI 入口（与方案 B 共用同一 Java 方法名）────
 * 实际部署时两方案编译为不同 .so，此处先共存于同一库，
 * 通过函数名区分；Phase 8 打包时拆分。                   */
JNIEXPORT jint JNICALL
Java_com_autorun_kctf_MainActivity_nativeProcessInputA(
        JNIEnv *env, jobject obj, jbyteArray jflag) {

    uint8_t flag[FLAG_LEN];
    (*env)->GetByteArrayRegion(env, jflag, 0, FLAG_LEN, (jbyte *)flag);

    uint8_t soKey[SOKEY_LEN];
    fetch_sokey_a(env, obj, soKey);

    /* 修复链：顺序执行，每步输出作为下一步输入 */
    repair_cfg(flag, soKey);

    /* dispatch_table[0] & 0xFF → S-Box 修复起始偏移 */
    extern uint32_t dispatch_table[4];
    uint8_t cfg_dep = (uint8_t)(dispatch_table[0] & 0xFFu);
    repair_sbox(flag, cfg_dep);

    /* sbox_shipped[0] → 常量修复 LCG 混入值 */
    extern uint8_t sbox_shipped[256];
    uint8_t sbox_first = sbox_shipped[0];
    repair_constants(flag, sbox_first);

    /* round_constants[0] >> 28 → 语义修复有效位数参数 */
    extern uint32_t round_constants[32];
    uint8_t rc_high4 = (uint8_t)(round_constants[0] >> 28);
    repair_semantics(flag, rc_high4);

    /* 执行 BB0~BB7 计算 */
    uint32_t state32[4] = {0, 0, 0, 0};
    core_compute(state32);
    uint8_t final_state[STATE_LEN];
    for (int i = 0; i < 4; i++) {
        final_state[i*4+0] = (uint8_t)(state32[i]      );
        final_state[i*4+1] = (uint8_t)(state32[i] >>  8);
        final_state[i*4+2] = (uint8_t)(state32[i] >> 16);
        final_state[i*4+3] = (uint8_t)(state32[i] >> 24);
    }

    /* 解密目标状态 */
    uint8_t expected[STATE_LEN];
    for (int i = 0; i < STATE_LEN; i++)
        expected[i] = ENC_EXPECTED_STATE_A[i] ^ soKey[i];

    /* 常量时间比较 */
    volatile uint8_t diff = 0;
    for (int i = 0; i < STATE_LEN; i++)
        diff |= final_state[i] ^ expected[i];

    return (diff == 0) ? 1 : 0;
}
