# Add project specific ProGuard rules here.

# 保留 JNI 入口（native 方法不能被混淆/删除）
-keep class com.autorun.kctf.MainActivity {
    public native int nativeProcessInput(byte[]);
    public byte[] a();
}

# 保留 Activity 生命周期
-keep class com.autorun.kctf.MainActivity extends android.app.Activity { *; }
