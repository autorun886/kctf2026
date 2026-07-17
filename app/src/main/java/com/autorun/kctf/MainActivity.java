package com.autorun.kctf;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.InputStream;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("kctf");
    }

    public native int nativeProcessInput(byte[] flag);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        EditText etFlag = findViewById(R.id.et_flag);
        Button btnVerify = findViewById(R.id.btn_verify);

        btnVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String input = etFlag.getText().toString().trim();
                // 直接输入 hex 字符串，100 字符 = 50 字节
                byte[] flagBytes = hexDecode(input);
                if (flagBytes == null || flagBytes.length != 50) {
                    Toast.makeText(MainActivity.this, "Wrong, try again.", Toast.LENGTH_SHORT).show();
                    return;
                }
                int result = nativeProcessInput(flagBytes);
                if (result == 1) {
                    Toast.makeText(MainActivity.this, "Correct! Flag accepted.", Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(MainActivity.this, "Wrong, try again.", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    /**
     * Called by native layer via JNI to derive soKey.
     * Reads the stable guard section of libkctf.so from the APK file directly,
     * computes CRC32, then expands to 16 bytes via LCG.
     * The returned blob is maskedKeyShare[16] || crc32[4] || textOff[4] || textSize[4].
     * Reading from APK avoids Android 12+ memory mapping issues where
     * section headers are not present in /proc/self/mem.
     */
    public byte[] deriveNativeKey() {
        try {
            // Get APK path directly from ApplicationInfo (reliable on all Android versions)
            String apkPath = getApplicationInfo().sourceDir;

            // Determine ABI — try arm64-v8a first, then armeabi-v7a
            String[] abis = {"arm64-v8a", "armeabi-v7a", "x86_64", "x86"};
            byte[] soBytes = null;
            try (ZipFile zip = new ZipFile(apkPath)) {
                for (String abi : abis) {
                    ZipEntry entry = zip.getEntry("lib/" + abi + "/libkctf.so");
                    if (entry != null) {
                        soBytes = new byte[(int) entry.getSize()];
                        try (InputStream is = zip.getInputStream(entry)) {
                            int off = 0, n;
                            while (off < soBytes.length && (n = is.read(soBytes, off, soBytes.length - off)) > 0)
                                off += n;
                        }
                        break;
                    }
                }
            }
            if (soBytes == null) {
                return new byte[28];
            }

            // Parse ELF to find the executable guard section
            long e_shoff     = readLE64(soBytes, 40);
            int  e_shentsize = readLE16(soBytes, 58);
            int  e_shnum     = readLE16(soBytes, 60);
            int  e_shstrndx  = readLE16(soBytes, 62);

            // Read section header string table
            int shstrOff  = (int) readLE64(soBytes, (int)(e_shoff + (long)e_shstrndx * e_shentsize + 24));
            int shstrSize = (int) readLE64(soBytes, (int)(e_shoff + (long)e_shstrndx * e_shentsize + 32));

            // Find .kctfguard section. Some Android linker scripts merge the
            // input section into output .text, so also scan .text for the
            // stable guard byte pattern.
            long textOff = 0, textSize = 0;
            long fallbackTextOff = 0, fallbackTextSize = 0;
            for (int i = 0; i < e_shnum; i++) {
                int shBase = (int)(e_shoff + (long)i * e_shentsize);
                int nameIdx = (int) readLE32(soBytes, shBase);
                String name = readCString(soBytes, shstrOff + nameIdx);
                if (".kctfguard".equals(name)) {
                    textOff  = readLE64(soBytes, shBase + 24);
                    textSize = readLE64(soBytes, shBase + 32);
                    break;
                } else if (".text".equals(name)) {
                    fallbackTextOff  = readLE64(soBytes, shBase + 24);
                    fallbackTextSize = readLE64(soBytes, shBase + 32);
                }
            }
            if (textSize == 0) {
                long[] guard = findGuardInText(soBytes, fallbackTextOff, fallbackTextSize);
                if (guard != null) {
                    textOff = guard[0];
                    textSize = guard[1];
                } else {
                    textOff = fallbackTextOff;
                    textSize = fallbackTextSize;
                }
            }
            if (textSize == 0) {
                return new byte[28];
            }

            // CRC32 of the selected executable section
            CRC32 crc = new CRC32();
            crc.update(soBytes, (int) textOff, (int) textSize);
            long crcVal = crc.getValue();

            // LCG expand to 16 bytes
            long[] EXPAND = {
                0xA3F1B28C7D4E5F60L, 0x9C8B7A6D5E4F3021L,
                0x1F2E3D4C5B6A7980L, 0xD0E1F2038495A6B7L
            };
            long MUL = 0x5851F42D4C957F2DL;
            long ADD = 0x14057B7EF767814FL;

            byte[] key = new byte[28];
            for (int i = 0; i < 4; i++) {
                long m = (crcVal ^ EXPAND[i]) * MUL + ADD;
                key[i*4]   = (byte)(m >>> 24);
                key[i*4+1] = (byte)(m >>> 16);
                key[i*4+2] = (byte)(m >>>  8);
                key[i*4+3] = (byte)(m       );
            }
            for (int i = 0; i < 16; i++)
                key[i] ^= nativeShareMask(i);
            writeLE32(key, 16, (int) crcVal);
            writeLE32(key, 20, (int) textOff);
            writeLE32(key, 24, (int) textSize);
            return key;
        } catch (Exception e) {
            return new byte[28];
        }
    }

    private static byte[] hexDecode(String hex) {
        if (hex.length() % 2 != 0) return null;
        try {
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++)
                out[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
            return out;
        } catch (NumberFormatException e) { return null; }
    }

    private static long readLE64(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }
    private static long readLE32(byte[] b, int off) {
        return (b[off]&0xFFL) | ((b[off+1]&0xFFL)<<8) | ((b[off+2]&0xFFL)<<16) | ((b[off+3]&0xFFL)<<24);
    }
    private static int readLE16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off+1] & 0xFF) << 8);
    }
    private static void writeLE32(byte[] b, int off, int v) {
        b[off]   = (byte)(v);
        b[off+1] = (byte)(v >>> 8);
        b[off+2] = (byte)(v >>> 16);
        b[off+3] = (byte)(v >>> 24);
    }
    private static byte nativeShareMask(int i) {
        return (byte)(((0x6D + i * 0x3B) ^ (i * 0x1D)) & 0xFF);
    }

    private static long[] findGuardInText(byte[] data, long textOff, long textSize) {
        if (textSize <= 0 || textSize > Integer.MAX_VALUE || textOff < 0 || textOff + textSize > data.length)
            return null;
        byte[] guard = new byte[] {
            (byte)0xE0,(byte)0xCC,(byte)0x9C,(byte)0xD2,(byte)0x20,(byte)0x41,(byte)0xAD,(byte)0xF2,
            (byte)0xA0,(byte)0xD0,(byte)0xD5,(byte)0xF2,(byte)0xE0,(byte)0x6C,(byte)0xF7,(byte)0xF2,
            (byte)0x41,(byte)0x6E,(byte)0x9E,(byte)0xD2,(byte)0xC1,(byte)0x8D,(byte)0xA7,(byte)0xF2,
            (byte)0x41,(byte)0xA7,(byte)0xDE,(byte)0xF2,(byte)0xE1,(byte)0xA9,(byte)0xF4,(byte)0xF2,
            (byte)0x02,(byte)0x00,(byte)0x01,(byte)0xCA,(byte)0x42,(byte)0x34,(byte)0xC2,(byte)0x93,
            (byte)0x42,(byte)0x94,(byte)0x16,(byte)0x91,(byte)0x43,(byte)0x74,(byte)0xC0,(byte)0xCA,
            (byte)0x63,(byte)0x00,(byte)0x01,(byte)0x8B,(byte)0x63,(byte)0x44,(byte)0xC3,(byte)0x93,
            (byte)0x60,(byte)0x00,(byte)0x02,(byte)0xCA,(byte)0xC0,(byte)0x03,(byte)0x5F,(byte)0xD6,
            (byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,(byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,
            (byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,(byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,
            (byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,(byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,
            (byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5,(byte)0x1F,(byte)0x20,(byte)0x03,(byte)0xD5
        };
        int start = (int)textOff;
        int end = (int)(textOff + textSize - guard.length);
        for (int i = start; i <= end; i++) {
            int j = 0;
            while (j < guard.length && data[i + j] == guard[j]) j++;
            if (j == guard.length) return new long[] { i, guard.length };
        }
        return null;
    }
    private static String readCString(byte[] buf, int off) {
        int end = off;
        while (end < buf.length && buf[end] != 0) end++;
        return new String(buf, off, end - off);
    }
}
