package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 学习用的小工具方法集 —— 只有字节/字/大端的互相转换、拼接、异或、十六进制打印，
 * 加一个"注册 BC provider"和一个"拿 JCE 摘要当裁判"。
 *
 * <p>这里没有对象、没有继承、没有可变的全局状态，每个方法都是"参数进、新数组出"，
 * 所以任何算法都可以直接调用它们，不需要先构造什么。
 *
 * <p>约定：32-bit 字统一放在 long 里并用 {@link #u32(long)} 掩码，避免 Java 有符号 int 的干扰。
 */
final class Calc
{
    static final long M32 = 0xFFFFFFFFL;

    private Calc()
    {
    }

    // ---------------------------------------------------------------- 注册 BC provider

    /** 幂等的 provider 注册：只有要拿 JCE/BC 当裁判时才调一次。 */
    static void useBc()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---------------------------------------------------------------- 32-bit 字运算

    /** 截断为无符号 32-bit。 */
    static long u32(long x)
    {
        return x & M32;
    }

    /** 32-bit 循环左移 —— SM3/SM4 的"本质"只有这一个原语。 */
    static long rotl(long x, int n)
    {
        int k = n & 31;
        long v = u32(x);
        return k == 0 ? v : (((v << k) & M32) | (v >>> (32 - k)));
    }

    // ---------------------------------------------------------------- 数组与字节

    /** 按 size 切块（最后一块可能不足 size）。 */
    static List<byte[]> chunks(byte[] data, int size)
    {
        List<byte[]> out = new ArrayList<byte[]>();
        for (int i = 0; i < data.length; i += size)
        {
            out.add(Arrays.copyOfRange(data, i, Math.min(i + size, data.length)));
        }
        return out;
    }

    // ---------------------------------------------------------------- 字节 <-> 字 / 大数

    /** 大端字节数组 -> 无符号 32-bit 字数组（长度必须是 4 的倍数）。 */
    static long[] words32(byte[] b)
    {
        long[] w = new long[b.length / 4];
        for (int i = 0; i < w.length; i++)
        {
            w[i] = ((b[4 * i] & 0xffL) << 24) | ((b[4 * i + 1] & 0xffL) << 16)
                | ((b[4 * i + 2] & 0xffL) << 8) | (b[4 * i + 3] & 0xffL);
        }
        return w;
    }

    /** 无符号 32-bit 字数组 -> 大端字节数组。 */
    static byte[] bytes32(long[] w)
    {
        byte[] b = new byte[w.length * 4];
        for (int i = 0; i < w.length; i++)
        {
            long v = u32(w[i]);
            b[4 * i] = (byte)(v >>> 24);
            b[4 * i + 1] = (byte)(v >>> 16);
            b[4 * i + 2] = (byte)(v >>> 8);
            b[4 * i + 3] = (byte)v;
        }
        return b;
    }

    static byte[] concat(byte[]... parts)
    {
        int n = 0;
        for (byte[] p : parts)
        {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts)
        {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    /** 等长异或 —— 分组密码所有模式都只用这一个操作。 */
    static byte[] xor(byte[] a, byte[] b)
    {
        byte[] out = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(a[i] ^ b[i]);
        }
        return out;
    }

    static BigInteger toBigInt(byte[] b)
    {
        return new BigInteger(1, b);
    }

    /** 大数 -> 固定长度大端字节，用于 SM2/RSA 的序列化。 */
    static byte[] toBytes(BigInteger v, int length)
    {
        byte[] raw = v.toByteArray();
        if (raw.length == length)
        {
            return raw;
        }
        byte[] out = new byte[length];
        if (raw.length > length)
        {
            System.arraycopy(raw, raw.length - length, out, 0, length);
        }
        else
        {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }

    // ---------------------------------------------------------------- 十六进制 / 打印

    static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b)
        {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    static String hex(long[] words)
    {
        StringBuilder sb = new StringBuilder();
        for (long w : words)
        {
            sb.append(String.format("%08x", u32(w)));
        }
        return sb.toString();
    }

    static byte[] unhex(String s)
    {
        if ((s.length() & 1) != 0)
        {
            throw new IllegalArgumentException("十六进制字符串长度必须是偶数: " + s);
        }
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++)
        {
            out[i] = (byte)Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    // ---------------------------------------------------------------- 裁判与杂项

    /** 标准摘要：给"我们手写的实现"和"JCE 实现"做对照的第三方裁判。 */
    static byte[] digest(String algorithm, byte[] data)
        throws Exception
    {
        return MessageDigest.getInstance(algorithm).digest(data);
    }

    static int ceilDiv(int a, int b)
    {
        return (a + b - 1) / b;
    }

    /** 重复字符串，Java 8 兼容。 */
    static String repeat(String s, int n)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++)
        {
            sb.append(s);
        }
        return sb.toString();
    }

    static byte[] repeatedByte(int value, int n)
    {
        byte[] out = new byte[n];
        Arrays.fill(out, (byte)value);
        return out;
    }
}
