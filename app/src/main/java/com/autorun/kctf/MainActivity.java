package com.autorun.kctf;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("kctf");
    }

    private static volatile int m = 0x5EED4A71;

    private Toast currentToast;

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
                cancelCurrentToast();
                String input = etFlag.getText().toString();
                String normalized = input.trim().toLowerCase(Locale.ROOT);
                if (!input.equals(normalized)) {
                    showResultToast("Wrong, try again.", Toast.LENGTH_SHORT);
                    return;
                }
                // 直接输入 hex 字符串，100 字符 = 50 字节
                byte[] flagBytes = hexDecode(normalized);
                if (flagBytes == null || flagBytes.length != 50) {
                    showResultToast("Wrong, try again.", Toast.LENGTH_SHORT);
                    return;
                }
                int result = nativeProcessInput(flagBytes);
                if (result == 1) {
                    showResultToast("Correct! Flag accepted.", Toast.LENGTH_LONG);
                } else {
                    showResultToast("Wrong, try again.", Toast.LENGTH_SHORT);
                }
            }
        });
    }

    private void showResultToast(String message, int duration) {
        cancelCurrentToast();
        currentToast = Toast.makeText(this, message, duration);
        currentToast.show();
    }

    private void cancelCurrentToast() {
        if (currentToast != null) {
            currentToast.cancel();
            currentToast = null;
        }
    }

    private static final int[][] A = {
        {0x37, 0x29, 0xF3, 0x32},
        {0x77, 0xEE, 0x81, 0x30, 0x09, 0xD9, 0xF5, 0xEA, 0x1F, 0x9E, 0x0D},
        {0x9F, 0xCF, 0x67, 0x82, 0x59, 0xBA, 0x00, 0x50, 0xCA},
        {0x8C, 0x2B, 0x9E, 0xB3, 0xD1, 0xE7, 0x8C, 0xEE, 0xDE, 0xBE, 0xAB},
        {0x66, 0xF4, 0xE8, 0x23, 0xE3, 0x65},
        {0xF3, 0x03, 0x48},
        {0x89, 0x85, 0x3B, 0xF4, 0x90, 0x97, 0x24, 0xB0, 0x81, 0xD2},
        {0x32, 0x92, 0x20, 0x4C, 0x12},
        {0xB0, 0xB1, 0xE4, 0x76, 0x07, 0xBA, 0xD0, 0x05, 0x57, 0x8E, 0x8C},
        {0x3D, 0x5D, 0xD2, 0xC1, 0x83, 0x3B, 0xD7, 0x00, 0x32},
        {0x77, 0xAD, 0xE8, 0xFF, 0x35, 0x9E, 0x73, 0x38, 0xE4, 0x38, 0x70, 0x02, 0x8E, 0x9A}
    };

    public byte[] a() {
        ZipFile zip = null;
        try {
            String apkPath = null;
            String[] abis = null;
            byte[] soBytes = null;
            long e_shoff = 0;
            int e_shentsize = 0;
            int e_shnum = 0;
            int e_shstrndx = 0;
            int shstrOff = 0;
            long textOff = 0;
            long textSize = 0;
            long fallbackTextOff = 0;
            long fallbackTextSize = 0;
            long crcVal = 0;
            byte[] key = null;
            int abiIndex = 0;
            int sectionIndex = 0;
            int salt = 0;
            int state = 0x31;
            String p0 = null;
            String p1 = null;
            String sGuard = null;
            String sText = null;

            while (true) {
                switch (state) {
                    case 0x31:
                        apkPath = getApplicationInfo().sourceDir;
                        salt = apkPath.length() ^ (getPackageName().length() << 5)
                                ^ (android.os.Build.SUPPORTED_ABIS.length << 11);
                        p0 = a(0, salt);
                        p1 = a(1, salt);
                        abis = new String[] {a(2, salt), a(3, salt), a(4, salt), a(5, salt)};
                        sGuard = a(6, salt);
                        sText = a(7, salt);
                        zip = new ZipFile(apkPath);
                        state = 0x63;
                        break;

                    case 0x63:
                        if (abiIndex >= abis.length) {
                            state = 0x3F;
                            break;
                        }
                        ZipEntry entry = zip.getEntry(p0 + abis[abiIndex] + p1);
                        if (entry == null) {
                            abiIndex++;
                            state = ((salt ^ abiIndex) & 1) == 0 ? 0x5A : 0x63;
                            break;
                        }
                        soBytes = new byte[(int) entry.getSize()];
                        try (InputStream is = zip.getInputStream(entry)) {
                            int off = 0;
                            int n;
                            while (off < soBytes.length
                                    && (n = is.read(soBytes, off, soBytes.length - off)) > 0) {
                                off += n;
                            }
                        }
                        state = 0x22;
                        break;

                    case 0x5A:
                        salt ^= (abiIndex * 0x45D9F3B) ^ a(8 + (abiIndex & 1), salt).length();
                        state = 0x63;
                        break;

                    case 0x22:
                        if (soBytes == null) {
                            state = 0x3F;
                            break;
                        }
                        e_shoff = readLE64(soBytes, 40);
                        e_shentsize = readLE16(soBytes, 58);
                        e_shnum = readLE16(soBytes, 60);
                        e_shstrndx = readLE16(soBytes, 62);
                        state = 0x74;
                        break;

                    case 0x74:
                        shstrOff = (int) readLE64(soBytes, (int)(e_shoff + (long)e_shstrndx * e_shentsize + 24));
                        state = 0x16;
                        break;

                    case 0x16:
                        if (sectionIndex >= e_shnum) {
                            state = 0x48;
                            break;
                        }
                        int shBase = (int)(e_shoff + (long)sectionIndex * e_shentsize);
                        int nameIdx = (int) readLE32(soBytes, shBase);
                        String name = readCString(soBytes, shstrOff + nameIdx);
                        if (sGuard.equals(name)) {
                            textOff = readLE64(soBytes, shBase + 24);
                            textSize = readLE64(soBytes, shBase + 32);
                            state = 0x48;
                        } else {
                            if (sText.equals(name)) {
                                fallbackTextOff = readLE64(soBytes, shBase + 24);
                                fallbackTextSize = readLE64(soBytes, shBase + 32);
                            }
                            sectionIndex++;
                            state = ((sectionIndex ^ salt) & 3) == 0 ? 0x27 : 0x16;
                        }
                        break;

                    case 0x27:
                        salt ^= Integer.rotateLeft(sectionIndex + e_shnum + a(10, salt).length(), 3);
                        state = 0x16;
                        break;

                    case 0x48:
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
                        state = (textSize == 0) ? 0x3F : 0x52;
                        break;

                    case 0x52:
                        CRC32 crc = new CRC32();
                        crc.update(soBytes, (int) textOff, (int) textSize);
                        crcVal = crc.getValue();
                        state = 0x6D;
                        break;

                    case 0x6D:
                        long[] expand = {
                            0xA3F1B28C7D4E5F60L, 0x9C8B7A6D5E4F3021L,
                            0x1F2E3D4C5B6A7980L, 0xD0E1F2038495A6B7L
                        };
                        long mul = 0x5851F42D4C957F2DL;
                        long add = 0x14057B7EF767814FL;

                        key = new byte[32];
                        for (int i = 0; i < 4; i++) {
                            long m = (crcVal ^ expand[i]) * mul + add;
                            key[i*4]   = (byte)(m >>> 24);
                            key[i*4+1] = (byte)(m >>> 16);
                            key[i*4+2] = (byte)(m >>>  8);
                            key[i*4+3] = (byte)(m       );
                        }
                        state = 0x7E;
                        break;

                    case 0x7E:
                        for (int i = 0; i < 16; i++)
                            key[i] ^= nativeShareMask(i);
                        writeLE32(key, 16, (int) crcVal);
                        writeLE32(key, 20, (int) textOff);
                        writeLE32(key, 24, (int) textSize);
                        writeLE32(key, 28, d(key, (int) crcVal, (int) textOff, (int) textSize));
                        return key;

                    case 0x3F:
                        return new byte[32];

                    default:
                        state = 0x3F;
                        break;
                }
            }
        } catch (Exception e) {
            return new byte[32];
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static String a(int id, int salt) {
        int[] enc = null;
        byte[] out = null;
        int idx = 0;
        int key = 0;
        int junk = salt ^ (id * 0x7F4A7C15);
        int pc = 0x09;
        while (true) {
            switch (pc) {
                case 0x09:
                    enc = A[Math.floorMod(id, A.length)];
                    out = new byte[enc.length];
                    key = b(id);
                    idx = 0;
                    pc = 0x2C;
                    break;
                case 0x2C:
                    if (idx >= enc.length) {
                        pc = 0x71;
                        break;
                    }
                    int b = enc[idx] ^ (key & 0xFF);
                    out[idx] = (byte)b;
                    key = c(key, b, id, idx);
                    idx++;
                    pc = ((junk + idx) & 3) == 1 ? 0x45 : 0x2C;
                    break;
                case 0x45:
                    junk ^= Integer.rotateLeft(idx + salt + id, idx & 7);
                    pc = 0x2C;
                    break;
                case 0x71:
                    return new String(out, StandardCharsets.US_ASCII);
                default:
                    pc = 0x09;
                    break;
            }
        }
    }

    private static int b(int id) {
        int x = 0x6D2B79F5 ^ (id * 0x045D9F3B);
        x ^= x >>> 16;
        x *= 0x7FEB352D;
        x ^= x >>> 15;
        return x;
    }

    private static int c(int key, int plain, int id, int idx) {
        int x = key + 0x9E3779B9 + plain * 0x01000193 + (id << 8) + idx;
        x ^= Integer.rotateLeft(x, 7);
        return Integer.rotateLeft(x, 11) ^ 0xA5A5A5A5;
    }

    private static int d(byte[] meta, int crc, int off, int size) {
        int x = m ^ 0x6B02C3A5;
        int acc = crc ^ Integer.rotateLeft(off + 0x27D4EB2F, 7)
                ^ Integer.rotateRight(size ^ 0xA0761D64, 3);
        int idx = 0;
        int pc = 0x12;
        while (true) {
            switch (pc) {
                case 0x12:
                    x ^= acc;
                    pc = 0x34;
                    break;
                case 0x34:
                    if (idx >= 16) {
                        pc = 0x5D;
                        break;
                    }
                    int b = meta[idx] & 0xFF;
                    x ^= b << ((idx & 3) * 8);
                    x = Integer.rotateLeft(x + 0x9E3779B9 + idx * 0x045D9F3B,
                            (b & 7) + 3);
                    idx++;
                    pc = ((x ^ idx) & 3) == 0 ? 0x49 : 0x34;
                    break;
                case 0x49:
                    x ^= Integer.rotateLeft(m + idx + 0x165667B1, idx & 15);
                    pc = 0x34;
                    break;
                case 0x5D:
                    x ^= x >>> 16;
                    x *= 0x7FEB352D;
                    x ^= x >>> 15;
                    x *= 0x846CA68B;
                    x ^= x >>> 16;
                    return x;
                default:
                    pc = 0x5D;
                    break;
            }
        }
    }

    private static byte[] hexDecode(String hex) {
        if (hex.length() != 100) return null;
        byte[] out = new byte[50];
        for (int i = 0; i < out.length; i++) {
            int hi = hexValue(hex.charAt(i * 2));
            int lo = hexValue(hex.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }

    private static int hexValue(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
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
