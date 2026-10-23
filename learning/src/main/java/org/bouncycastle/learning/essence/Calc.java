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
 *
 * <p><b>符号表 —— 本文件（以及 SM3/SM4 等所有位运算算法）共用的记号</b>
 * <pre>
 *   字 (word)        32 个比特组成的最小操作单位；Java 没有无符号 int，所以一律借 long 的高位来表示"无符号"
 *   x₀ x₁ x₂ x₃      一个 32-bit 字的 4 个字节，下标 0 是<b>最高位字节</b>（大端约定，见 {@link #words32}）
 *   mod 2³²          "只保留低 32 位"：加法/移位溢出的一律丢掉，等价于 &amp; M32
 *   M32              截断掩码 = 0xFFFFFFFF = 2³²−1；x &amp; M32 就是 x mod 2³²
 *   u32(x)           x mod 2³² 的函数写法，返回 [0, 2³²) 里的值
 *   rotl(x, n)       循环左移 (rotate left)：左移 n 位后把溢出的高 n 位补回低 n 位；n 只需取低 5 位 (n &amp; 31)
 *   >>>              无符号右移：左侧补 0；有符号的 >> 会补符号位，位运算里几乎总是错的
 *   大端 (big-endian) 高位字节放在低地址（网络字节序）；SM3 的 W 扩展、SM2 的坐标序列化都用它
 *   ‖                字节串拼接 (concatenate)，见 {@link #concat}，<b>不是</b>异或
 *   ⊕                逐比特异或 (XOR)，见 {@link #xor}
 * </pre>
 */
public final class Calc
{
    /**
     * M32 = 2³²−1 = 0xFFFFFFFF，32-bit 截断掩码：任何 x &amp; M32 即 x mod 2³²，
     * 也就是"只留最低 32 位"。算法书里写在 mod 2³² 下的每一步，这里都靠它落地。
     */
    public static final long M32 = 0xFFFFFFFFL;

    private Calc()
    {
    }

    // ---------------------------------------------------------------- 注册 BC provider

    /** 幂等的 provider 注册：只有要拿 JCE/BC 当裁判时才调一次。 */
    public static void useBc()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---------------------------------------------------------------- 32-bit 字运算

    /**
     * 截断为无符号 32-bit。
     *
     * <p>u32(x) = x &amp; M32 = x mod 2³²：入参 x 可以是加法溢出后的 long（形如 2³²·q + r），
     * 返回唯一的 r ∈ [0, 2³²)。算法里"每一步都 mod 2³²"就是靠在每个中间结果上套一次 u32 实现的。
     */
    public static long u32(long x)
    {
        return x & M32;
    }

    /**
     * 32-bit 循环左移 —— SM3/SM4 的"本质"只有这一个原语。
     *
     * <p>rotl(x, n)：把 x 的比特整体向左推 n 格，转出 32 位窗口的最高 n 位从最低端补回来，
     * 数学上就是 x·2ⁿ 在"循环比特环"上的位置置换（不丢信息，可逆，逆运算是 rotr = rotl(x, 32−n)）。
     * <pre>
     *   k  = n &amp; 31      移位量取低 5 位：rotl(x, n) 与 rotl(x, n mod 32) 完全相同（n=32 等于不移）
     *   (v &lt;&lt; k) &amp; M32  左移 k 位并截断，得到高 k 位即将溢出的部分
     *   v &gt;&gt;&gt; (32 − k)  同一批高 k 位改从低位进来 —— 这就是"循环"
     * </pre>
     */
    public static long rotl(long x, int n)
    {
        int k = n & 31;
        long v = u32(x);
        return k == 0 ? v : (((v << k) & M32) | (v >>> (32 - k)));
    }

    // ---------------------------------------------------------------- 数组与字节

    /**
     * 按 size 切块（最后一块可能不足 size）。
     *
     * <p>size = 分组长度（SM3 用 64 字节，即 512 bit），返回的每一项就是一个"消息分组 (message block)"；
     * 切块之前必须先做 MD 填充，否则最后一块会不足 size —— 填充正是为了保证"每一块都正好 size 字节"。
     */
    public static List<byte[]> chunks(byte[] data, int size)
    {
        List<byte[]> out = new ArrayList<byte[]>();
        for (int i = 0; i < data.length; i += size)
        {
            out.add(Arrays.copyOfRange(data, i, Math.min(i + size, data.length)));
        }
        return out;
    }

    // ---------------------------------------------------------------- 字节 <-> 字 / 大数

    /**
     * 大端字节数组 -> 无符号 32-bit 字数组（长度必须是 4 的倍数）。
     *
     * <p>这就是"大端序列化 (big-endian)"的反向操作：字节下标越小，位权越高。
     * <pre>
     *   w[i] = b[4i]·2²⁴ + b[4i+1]·2¹⁶ + b[4i+2]·2⁸ + b[4i+3]
     *   b[4i] 是字 w[i] 的最高位字节 (MSB)，b[4i+3] 是最低位字节 (LSB)
     *   &amp; 0xffL 先把有符号 byte 还原成 0..255 的无符号值（否则 0x80 会变成 -128 并污染高位）
     *   一个 64 字节的 SM3 分组 => 16 个 32-bit 字，即消息扩展里的 W₀..W₁₅
     * </pre>
     */
    public static long[] words32(byte[] b)
    {
        long[] w = new long[b.length / 4];
        for (int i = 0; i < w.length; i++)
        {
            w[i] = ((b[4 * i] & 0xffL) << 24) | ((b[4 * i + 1] & 0xffL) << 16)
                | ((b[4 * i + 2] & 0xffL) << 8) | (b[4 * i + 3] & 0xffL);
        }
        return w;
    }

    /**
     * 无符号 32-bit 字数组 -> 大端字节数组（{@link #words32(byte[])} 的逆运算）。
     *
     * <pre>
     *   b[4i]   = (v &gt;&gt;&gt; 24)  字 v 的第 31..24 位（最高字节）放在低地址
     *   b[4i+3] = v             字 v 的第 7..0 位（最低字节）放在高地址
     * </pre>
     * 强转 (byte) 只取最低 8 位，正好把一个 32-bit 字切成 4 个字节；SM3 最后"大端序列化"这一步
     * 就是它：8 个 32-bit 链接字 -> 32 字节 = 256 bit 摘要。
     */
    public static byte[] bytes32(long[] w)
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

    /**
     * 字节串拼接，对应公式里的 ‖（concatenate）：parts[0] ‖ parts[1] ‖ … 依次首尾相接。
     * 注意 ‖ 与 ⊕（{@link #xor}）是两回事 —— 拼接变长、异或等长，学习时最容易看混。
     */
    public static byte[] concat(byte[]... parts)
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

    /**
     * 等长异或 —— 分组密码所有模式都只用这一个操作。
     *
     * <p>out[i] = a[i] ⊕ b[i]，逐比特置反：相同得 0、不同得 1。它自带两条关键性质：
     * 自反 a ⊕ b ⊕ b = a（所以解密就是再异或一次同一个流），以及 a ⊕ 0 = a。
     * SM2 的 C2 = M ⊕ KDF(...)、SM3 的 W′[j] = W[j] ⊕ W[j+4] 用的都是它。
     */
    public static byte[] xor(byte[] a, byte[] b)
    {
        byte[] out = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = (byte)(a[i] ^ b[i]);
        }
        return out;
    }

    /**
     * 大端字节数组 -> 大整数（无符号解读）。
     *
     * <p>{@code new BigInteger(1, b)} 的两个参数：符号位 1（强制当正数）+ 字节数组 b，
     * 按大端读成 v = Σ b[i]·256^(len−1−i)。因为 Java 的 byte 有符号，直接给单参构造函数会把
     * 0x80 以上误判成负数，所以这里必须显式指定符号位 1。SM2 里 e = SM3(ZA‖M) 转大整数就靠它。
     */
    public static BigInteger toBigInt(byte[] b)
    {
        return new BigInteger(1, b);
    }

    /**
     * 大数 -> 固定长度大端字节，用于 SM2/RSA 的序列化。
     *
     * <p>大端且<b>定长</b>：长度 length 通常是 32（256 bit 曲线的坐标/标量都写成 32 字节）。
     * BigInteger.toByteArray() 会带上符号字节 0x00 或省掉前导零，长度不固定，所以这里两种情况都要修正：
     * <pre>
     *   raw.length &gt; length   多出来的是符号字节/前导零 —— 只取最后 length 个字节
     *   raw.length &lt; length   数值太小、前导零被省了 —— 在<b>头部</b>补零对齐（大端：高位在前）
     * </pre>
     * 定长很重要：ZA、KDF、C1 的输入都是"拼接"出来的，少一个前导零就会让整条消息错位。
     */
    public static byte[] toBytes(BigInteger v, int length)
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

    /**
     * 字节数组 -> 十六进制字符串（每字节 2 个字符，高位字符在前 = 大端可读形式），只用于打印/比对。
     * (x >> 4) &amp; 0xf 取这个字节的高 4 位 (high nibble)，x &amp; 0xf 取低 4 位。
     */
    public static String hex(byte[] b)
    {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b)
        {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    /** 32-bit 字数组 -> 十六进制，每字固定 8 个字符（%08x），正好对上 SM3 的 8 个链接字 A..H。 */
    public static String hex(long[] words)
    {
        StringBuilder sb = new StringBuilder();
        for (long w : words)
        {
            sb.append(String.format("%08x", u32(w)));
        }
        return sb.toString();
    }

    /**
     * 十六进制字符串 -> 字节数组（{@link #hex(byte[])} 的逆）；长度必须为偶数，否则半个字节无法成对。
     * 每 2 个字符按 16 进制解析成 1 字节，字符顺序即大端字节顺序。
     */
    public static byte[] unhex(String s)
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

    /**
     * 标准摘要：给"我们手写的实现"和"JCE 实现"做对照的第三方裁判。
     *
     * <p>algorithm 是 JCA 标准名（"SM3"、"SHA-256"…），data 是原始字节；先 {@link #useBc()}
     * 注册 provider 才取得到国密算法名。
     */
    public static byte[] digest(String algorithm, byte[] data)
        throws Exception
    {
        return MessageDigest.getInstance(algorithm).digest(data);
    }

    /** 向上取整的除法 ceil(a/b)：整数除法会截掉小数，加 b−1 再除等价于"多出的零头也要占一块"。KDF 里算 ceil(klen/32) 块。 */
    public static int ceilDiv(int a, int b)
    {
        return (a + b - 1) / b;
    }

    /** 重复字符串，Java 8 兼容。 */
    public static String repeat(String s, int n)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++)
        {
            sb.append(s);
        }
        return sb.toString();
    }

    /** 生成 n 个同值字节，例如 MD 填充的 0^(k) 段、HMAC 的 ipad(0x36)/opad(0x5c) 常量串。 */
    public static byte[] repeatedByte(int value, int n)
    {
        byte[] out = new byte[n];
        Arrays.fill(out, (byte)value);
        return out;
    }
}
