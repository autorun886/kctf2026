cmake_minimum_required(VERSION 3.22.1)
project("kctf" LANGUAGES C ASM)

# ── 编译隔离：禁止 LTO，防止编译器合并相似函数/常量
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-lto -fno-merge-all-constants -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-lto -fno-merge-all-constants -fvisibility=hidden")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -fno-lto -fvisibility=hidden")

# ── 共享源文件（两方案均使用）
set(SHARED_SRCS
    src/init.c
    src/ipc_verify.c
    src/utils.c
    src/kctf_guard.S
    src/resolver.c
    src/strings.c
    src/tea_impl.c
    src/aes_impl.c
)

# ── 方案 B 源文件
set(SCHEME_B_SRCS
    src/gf_math.c
    src/key_expand.c
    src/sbox_gen.c
    src/spn_round.c
    src/jni_entry.c
    src/seeds_oracle.c
    src/const_xor.c
    src/seeds_oracle.S
)

# ── 方案 A 源文件
set(SCHEME_A_SRCS
    src/core_compute.c
    src/repair_cfg.c
    src/repair_sbox.c
    src/repair_constants.c
    src/repair_semantics.c
)

add_library(${CMAKE_PROJECT_NAME} SHARED
    ${SHARED_SRCS}
    ${SCHEME_B_SRCS}
    ${SCHEME_A_SRCS}
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE src/include)

target_link_libraries(${CMAKE_PROJECT_NAME}
    android
    log
    dl
)
