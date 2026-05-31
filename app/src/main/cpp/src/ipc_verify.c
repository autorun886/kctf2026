#include <stdint.h>
#include <string.h>
#include "include/kctf.h"

/* IPC 校验（可选层）— Phase 3.6 实现
 * 当前返回全零 fallback，不影响主流程编译。 */
void get_ipc_material(uint8_t out[16]) {
    memset(out, 0, 16);
}
