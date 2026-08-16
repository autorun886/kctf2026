# KCTF2026 编译文档

本文记录如何从当前源码生成与 `KCTF2026_release_current/KCTF2026.apk` 一致的 release APK。

## 环境

本机验证环境：

- JDK: `/home/user/.local/jdk-debroot/usr/lib/jvm/java-17-openjdk-amd64`
- Android SDK: `/home/user/Android/Sdk`
- Android platform: `android-36`
- NDK: `/home/user/Android/Sdk/ndk/27.0.12077973`
- CMake: `/home/user/Android/Sdk/cmake/3.22.1`
- Gradle wrapper: `gradle-8.13`
- Android Gradle Plugin: `8.13.0`

建议先设置环境变量：

```bash
export JAVA_HOME=/home/user/.local/jdk-debroot/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/home/user/Android/Sdk
export ANDROID_SDK_ROOT=/home/user/Android/Sdk
export PATH="$JAVA_HOME/bin:$PATH"
```

## 普通构建

普通 release 构建命令：

```bash
./gradlew assembleRelease
```

输出文件：

```text
app/build/outputs/apk/release/app-release.apk
```

注意：普通 Gradle 构建可以成功，但不会与发布包字节级一致。原因是本题 native 层包含构建后收敛常量和 oracle shellcode 后处理，发布 APK 不是单次 `assembleRelease` 的直接输出。

## 收敛构建

执行项目自带收敛脚本：

```bash
python3 converge.py --release --max-iter 10
```

该脚本会执行以下步骤：

1. `clean + assembleRelease`
2. 从 `libkctf.so` 的 `.kctfguard` 派生 `guard_crc32` 和 `soKey`
3. 提取 native basic block 偏移
4. 计算并写回 native 校验常量
5. 重新构建直到 CRC 稳定
6. patch oracle 数据并 XOR 加密 oracle shellcode
7. strip patched `.so`
8. 替换 APK 内的 `lib/arm64-v8a/libkctf.so`
9. 清理 AGP VCS metadata、AGP app metadata 和 `DebugProbesKt.bin`
10. 重新 zipalign
11. 使用 `kctf2026.jks` 重新签名 APK
12. 运行 Python 侧方案 A/B 验证

本次收敛结果：

```text
guard_crc32 = 3e0695ce
soKey       = 870573e5f5c63d52862dbd05ab3d9494
flagA       = a77a78ffc894367d1bf5bb3faab6e2f4db0070533de8b73443
flagA_dec   = 0200000001832dbd05c70573e5b979379edec0adde07421337
flagB       = 7ae31b94d256f80c41b7298e63a5df104bc8723d960fe458ad
flag        = a77a7ae3781bff94c8d2945636f87d0c1b41f5b7bb293f8eaa63b6a5e2dff410db4b00c87072533d3d96e80fb7e4345843ad
```

## 与发布包字节一致

收敛后的 `.so` 逻辑内容已经一致，但 LLVM linker 生成的 `.note.gnu.build-id` 可能不同。发布包的 build-id 为：

```text
d8b94a5f528806996fee71c4785bf20c86f53deb
```

如果要得到与 `KCTF2026_release_current/KCTF2026.apk` 字节完全一致的 APK，需要把 APK 内 `libkctf.so` 的 build-id 归一化为该值，清理发布 metadata，重新 zipalign，然后重新签名：

```bash
python3 -c 'import zipfile, os; apk="app/build/outputs/apk/release/app-release.apk"; out=apk+".tmp"; name="lib/arm64-v8a/libkctf.so"; skip={"META-INF/version-control-info.textproto","META-INF/com/android/build/gradle/app-metadata.properties","DebugProbesKt.bin"}; release=bytes.fromhex("d8b94a5f528806996fee71c4785bf20c86f53deb"); off=0x2e0; zin=zipfile.ZipFile(apk,"r"); zout=zipfile.ZipFile(out,"w");
for item in zin.infolist():
    if item.filename in skip: continue
    data=zin.read(item.filename)
    if item.filename==name:
        data=bytearray(data); data[off:off+20]=release; data=bytes(data)
    zout.writestr(item,data)
zin.close(); zout.close(); os.replace(out,apk)'

/home/user/Android/Sdk/build-tools/36.0.0/zipalign -p -f 4 \
  app/build/outputs/apk/release/app-release.apk \
  app/build/outputs/apk/release/app-release.aligned.apk
mv app/build/outputs/apk/release/app-release.aligned.apk \
  app/build/outputs/apk/release/app-release.apk

/home/user/Android/Sdk/build-tools/36.0.0/apksigner sign \
  --v1-signing-enabled false \
  --v2-signing-enabled false \
  --v3-signing-enabled true \
  --ks kctf2026.jks \
  --ks-pass pass:kctf2026 \
  --ks-key-alias kctf \
  --key-pass pass:kctf2026 \
  app/build/outputs/apk/release/app-release.apk
```

这里的 `0x2e0` 是当前 ELF 布局中 `.note.gnu.build-id` 的 20 字节 payload 偏移。若编译器、NDK 或链接参数变化，应先用 `readelf -n` 和 `readelf -S` 重新确认。

## 验证

比较 APK 哈希：

```bash
sha256sum app/build/outputs/apk/release/app-release.apk ../KCTF2026_release_current/KCTF2026.apk
```

期望输出：

```text
e891d19b725b470dc5cf55531d6f3b3b977f5937b37f600d322365cdb155c05a  app/build/outputs/apk/release/app-release.apk
e891d19b725b470dc5cf55531d6f3b3b977f5937b37f600d322365cdb155c05a  ../KCTF2026_release_current/KCTF2026.apk
```

验证 flag 派生：

```bash
python3 flag_generate.py app/build/outputs/apk/release/app-release.apk
```

解包逐文件比较：

```bash
mkdir -p /tmp/kctf-built /tmp/kctf-release
unzip -q -o app/build/outputs/apk/release/app-release.apk -d /tmp/kctf-built
unzip -q -o ../KCTF2026_release_current/KCTF2026.apk -d /tmp/kctf-release
diff -qr /tmp/kctf-built /tmp/kctf-release
```

期望 `diff -qr` 无输出。
