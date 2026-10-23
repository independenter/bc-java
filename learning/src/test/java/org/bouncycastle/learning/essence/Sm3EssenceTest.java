package org.bouncycastle.learning.essence;

import java.util.Arrays;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;

import static org.bouncycastle.learning.essence.Calc.M32;
import static org.bouncycastle.learning.essence.Calc.rotl;
import static org.bouncycastle.learning.essence.Calc.u32;

/**
 * SM3（GB/T 32905-2016）的本质计算 —— 面向过程版。
 *
 * <p>没有 Digest 对象、没有继承体系，SM3 只是几个普通静态方法串起来的直线代码：
 * <pre>
 *   sm3(msg) = 大端序列化( 逐块压缩( MD填充(msg) ) )
 *   逐块压缩：用一个 for 循环把链接值 V 一块一块往前推：V = cf(V, block)   // Merkle–Damgård 迭代
 * </pre>
 * "状态"就是循环里的局部变量（一个 long[8]），每轮就地改写它 —— 不克隆、不套函数、不传参绕圈。
 * 这正是面向过程写法的核心：一条命令一条命令地执行，而不是把函数当值来回传递。
 */
@Slf4j
public class Sm3EssenceTest
{
    /** HMAC / KDF 里 SM3 的分组长度（字节）。 */
    private static final int BLOCK_SIZE = 64;

    /**
     * 轮常数 T_j：前 16 轮取 0x79cc4519，后 48 轮取 0x7a879d8a —— SM3 里唯一的"魔术数"，就两个常量。
     * 写成普通静态方法：传进轮号 j，返回一个 32-bit 字。
     */
    static long tConstant(int j)
    {
        return j < 16 ? 0x79cc4519L : 0x7a879d8aL;
    }

    /**
     * FF_j：布尔函数写成带三个参数 (a/b/c) 加轮号 j 的普通静态方法 —— 这就是它的本质。
     * 前 16 轮只用异或（线性），后 48 轮才引入与/或（多数函数，非线性）—— 这是 SM3 抗碰撞的关键设计。
     */
    static long ff(long j, long a, long b, long c)
    {
        return u32(j < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c)));
    }

    /** GG_j：同理，前 16 轮纯异或（线性），后 48 轮是选择函数（非线性）。 */
    static long gg(long j, long a, long b, long c)
    {
        return u32(j < 16 ? (a ^ b ^ c) : ((a & b) | ((~a & M32) & c)));
    }

    /**
     * P0 是"扩散函数"：一个字的每一位靠它摊到 32 位上，本质只有 异或 + 循环左移。
     * 普通静态方法，一个入参 x。
     */
    static long p0(long x)
    {
        return u32(x ^ rotl(x, 9) ^ rotl(x, 17));
    }

    /**
     * P1 也是扩散函数。注意它的第二段移位是 23 位，不是 22 位 —— 网上大量资料把这一处抄错。
     */
    static long p1(long x)
    {
        return u32(x ^ rotl(x, 15) ^ rotl(x, 23));
    }

    /** 初始值 IV —— 标准的 8 个 32-bit 字。 */
    private static long[] iv()
    {
        return new long[]{
            0x7380166fL, 0x4914b2b9L, 0x172442d7L, 0xda8a0600L,
            0xa96f30bcL, 0x163138aaL, 0xe38dee4dL, 0xb0fb0e4eL
        };
    }

    /**
     * SM3 全流程：MD 填充 -> 逐块压缩（for 循环往前推链接值）-> 大端序列化。
     * 包级静态方法，供其他算法（SM2）直接调用。
     */
    static byte[] sm3(byte[] msg)
    {
        List<byte[]> blocks = mdPad(msg);
        long[] v = iv();
        for (int i = 0; i < blocks.size(); i++)
        {
            v = cf(v, blocks.get(i));
        }
        return Calc.bytes32(v);
    }

    /** MD 填充：m ‖ 0x80 ‖ 0^k ‖ len₆₄(m)。返回 64 字节块的列表 —— 一个普通过程，就地算完返回。 */
    static List<byte[]> mdPad(byte[] msg)
    {
        int zeros = (56 - (msg.length + 1) % 64 + 64) % 64;
        byte[] bits = new byte[8];
        long bitLen = 8L * msg.length;
        for (int i = 0; i < 8; i++)
        {
            bits[i] = (byte)(bitLen >>> (56 - 8 * i));
        }
        byte[] padded = Calc.concat(msg, new byte[]{ (byte)0x80 }, Calc.repeatedByte(0, zeros), bits);
        return Calc.chunks(padded, 64);
    }

    /**
     * 消息扩展：W[0..67]。递推式即标准公式，用一个 for 循环从 j=16 直接就地写进数组 w[j]。
     * 只有 W[j-3] 和 W[j-13] 带循环移位，W[j-6] 是原值 —— 背错这一项是最常见的实现 bug。
     */
    static long[] wExpand(byte[] block)
    {
        long[] w = new long[68];
        long[] seeded = Calc.words32(block);
        System.arraycopy(seeded, 0, w, 0, 16);
        for (int j = 16; j < 68; j++)
        {
            w[j] = u32(p1(u32(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)))
                ^ rotl(w[j - 13], 7) ^ w[j - 6]);
        }
        return w;
    }

    /**
     * 压缩函数 CF：一个 for 循环跑满 64 步，最后与上一个链接值逐字异或。
     * 状态是 8 个局部变量 a..h（对应 A..H），每轮用临时变量算出新值再整体赋值 —— 就地推进，不克隆数组。
     */
    static long[] cf(long[] v, byte[] block)
    {
        long[] w = wExpand(block);
        long[] wp = new long[64];
        for (int i = 0; i < 64; i++)
        {
            wp[i] = u32(w[i] ^ w[i + 4]);
        }

        long a = v[0], b = v[1], c = v[2], d = v[3];
        long e = v[4], f = v[5], g = v[6], h = v[7];
        for (int j = 0; j < 64; j++)
        {
            long ss1 = rotl(u32(rotl(a, 12) + e + rotl(tConstant(j), j)), 7);
            long ss2 = u32(ss1 ^ rotl(a, 12));
            long tt1 = u32(ff(j, a, b, c) + d + ss2 + wp[j]);
            long tt2 = u32(gg(j, e, f, g) + h + ss1 + w[j]);
            // 先算出下一轮的 8 个字，再整体写回局部变量（不新建数组）
            long na = tt1;
            long nb = a;
            long nc = rotl(b, 9);
            long nd = c;
            long ne = p0(tt2);
            long nf = e;
            long ng = rotl(f, 19);
            long nh = g;
            a = na;
            b = nb;
            c = nc;
            d = nd;
            e = ne;
            f = nf;
            g = ng;
            h = nh;
        }
        return new long[]{
            u32(a ^ v[0]), u32(b ^ v[1]), u32(c ^ v[2]), u32(d ^ v[3]),
            u32(e ^ v[4]), u32(f ^ v[5]), u32(g ^ v[6]), u32(h ^ v[7])
        };
    }

    // ------------------------------------------------------------------ 测试

    /** 标准测试向量：SM3("abc") 与 SM3("abcd"*16)。自己的面向过程实现必须一字不差。 */
    @Test
    public void sm3EssenceMatchesGbt32905Vectors()
        throws Exception
    {
        String abc = Calc.hex(sm3("abc".getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abc\")            = {}", abc);
        Assert.assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", abc);

        String abcd16 = Calc.hex(sm3(Calc.repeat("abcd", 16).getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abcd\"*16)        = {}", abcd16);
        Assert.assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", abcd16);

        // 与 JCE 第三方实现互相印证（不同长度覆盖所有填充分支）
        Calc.useBc();
        for (int len : new int[]{ 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128 })
        {
            byte[] data = new byte[len];
            Arrays.fill(data, (byte)'a');
            Assert.assertArrayEquals("长度 " + len + " 的填充/折叠不一致",
                Calc.digest("SM3", data), sm3(data));
        }
        log.info("[SM3-本质] 与 JCE SM3 在 11 种长度（含填充边界 55/56/63/64/119/120）上完全一致");
    }

    /** Merkle–Damgård 的本质：hash(m1‖m2) = CF(CF(IV, pad 前若干块) …) —— 逐块 for 循环可拼接。 */
    @Test
    public void merkleDamgardIsJustALoopOverBlocks()
        throws Exception
    {
        byte[] head = Calc.repeat("head-", 5).getBytes("UTF-8");
        byte[] tail = Calc.repeat("-tail", 7).getBytes("UTF-8");

        // 分块逐块推进后与整体推进必须相同（除了最后一块要带长度）：验证"推进顺序无关性"
        long[] whole = iv();
        List<byte[]> wholeBlocks = mdPad(Calc.concat(head, tail));
        for (int i = 0; i < wholeBlocks.size(); i++)
        {
            whole = cf(whole, wholeBlocks.get(i));
        }
        log.info("[SM3-本质] 整体折叠        = {}", Calc.hex(whole));
        Assert.assertArrayEquals(Calc.bytes32(whole), sm3(Calc.concat(head, tail)));

        // 逐字节喂入（流式）与一次性喂入等价 —— 这就是 MessageDigest.update() 的数学本质
        SM3Digest ref = new SM3Digest();
        ref.update(head, 0, head.length);
        ref.update(tail, 0, tail.length);
        byte[] streamed = new byte[32];
        ref.doFinal(streamed, 0);
        Assert.assertArrayEquals("流式 update 与一次性 digest 必须等价（Merkle–Damgård 可拼接性）",
            sm3(Calc.concat(head, tail)), streamed);
        log.info("[SM3-本质] 流式 update == 一次性 digest：{}", Calc.hex(streamed));
    }

    /** HMAC-SM3：只用"哈希函数"这一个抽象就能构造消息认证码（NIST 的意义所在）。 */
    @Test
    public void hmacSm3IsHashCompositionNotAClass()
        throws Exception
    {
        byte[] key = "key-for-sm3-hmac".getBytes("UTF-8");
        byte[] msg = "Hello functional HMAC".getBytes("UTF-8");
        byte[] ours = hmacSm3(key, msg);
        log.info("[SM3-HMAC] 普通过程 HMAC-SM3   = {}", Calc.hex(ours));

        Calc.useBc();
        HMac bc = new HMac(new SM3Digest());
        bc.init(new KeyParameter(key));
        bc.update(msg, 0, msg.length);
        byte[] expected = new byte[bc.getMacSize()];
        bc.doFinal(expected, 0);
        Assert.assertArrayEquals("HMAC-SM3 与 BC HMac 不一致", expected, ours);
        Assert.assertNotEquals("HMAC 必须依赖密钥", Calc.hex(ours), Calc.hex(hmacSm3("other-key".getBytes("UTF-8"), msg)));
    }

    /** 密钥规约：过长先哈希、过短右侧补零 —— HMAC 唯一的"密钥预处理"，一个普通静态方法。 */
    private static byte[] fitKey(byte[] key)
    {
        if (key.length > BLOCK_SIZE)
        {
            return Arrays.copyOf(Calc.concat(sm3(key), new byte[BLOCK_SIZE - 32]), BLOCK_SIZE);
        }
        return Arrays.copyOf(Calc.concat(key, new byte[BLOCK_SIZE - key.length]), BLOCK_SIZE);
    }

    /** HMAC(k, m) = H(k⊕opad ‖ H(k⊕ipad ‖ m)) —— 几步顺序调用 SM3，没有任何对象与函数值。 */
    private static byte[] hmacSm3(byte[] key, byte[] msg)
    {
        byte[] k = fitKey(key);
        byte[] ipad = Calc.repeatedByte(0x36, BLOCK_SIZE);
        byte[] opad = Calc.repeatedByte(0x5c, BLOCK_SIZE);
        byte[] inner = sm3(Calc.concat(Calc.xor(k, ipad), msg));
        return sm3(Calc.concat(Calc.xor(k, opad), inner));
    }

    /** KDF（SM2 加密里那个"计数器模式派生函数"）：本质 = hash(z ‖ 计数器) 的无限流取前 klen 字节。 */
    @Test
    public void kdfIsAnInfiniteHashStreamTruncated()
        throws Exception
    {
        byte[] z = Calc.unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e0f");
        for (int klen : new int[]{ 1, 16, 32, 33, 64, 100 })
        {
            byte[] ours = kdf(z, klen);

            KDF2BytesGenerator bcKdf = new KDF2BytesGenerator(new SM3Digest());
            bcKdf.init(new KDFParameters(z, null));
            byte[] expected = new byte[klen];
            bcKdf.generateBytes(expected, 0, klen);

            Assert.assertArrayEquals("KDF 长度 " + klen + " 不一致", expected, ours);
            log.info("[SM3-KDF] klen={} -> {}", klen, Calc.hex(ours));
        }
        log.info("[SM3-KDF] 结论：KDF 就是一个 for 循环，把 ct 从 1 递增、不断把 hash(z‖ct) 拼到尾部再截断");
    }

    /** KDF 派生：for 循环把计数器 1..ceil(klen/32) 逐个 hash(z‖ct) 拼流，最后截断到 klen 字节。 */
    private static byte[] kdf(byte[] z, int klen)
    {
        int blocks = Calc.ceilDiv(klen, 32);
        byte[] stream = new byte[0];
        for (int ct = 1; ct <= blocks; ct++)
        {
            byte[] counterBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                counterBytes[i] = (byte)(ct >>> (24 - 8 * i));
            }
            stream = Calc.concat(stream, sm3(Calc.concat(z, counterBytes)));
        }
        return Arrays.copyOf(stream, klen);
    }

    /** 填充模式的"哈希侧视角"：0x80 + 0 填充 vs 只追加长度 —— 说明为什么 SM3 不需要加密式填充。 */
    @Test
    public void hashPaddingIsLengthAwareNotBlockAware()
        throws Exception
    {
        byte[] aligned = Calc.repeat("0123456789abcdef", 4).getBytes("UTF-8");   // 64 字节
        byte[] short0 = new byte[0];

        log.info("[SM3-填充] 64 字节对齐消息的真实 SM3 = {}", Calc.hex(sm3(aligned)));
        log.info("[SM3-填充] 去掉长度字段的\"伪 SM3\"    = {}", Calc.hex(naiveNoLength(aligned)));
        Assert.assertNotEquals("真实 SM3 绝不能等于无长度字段的逐块推进",
            Calc.hex(sm3(aligned)), Calc.hex(naiveNoLength(aligned)));
        Assert.assertEquals("空消息也必须产生一个完整块（0x80 + 长度）", 1, mdPad(short0).size());
        Assert.assertEquals("56 字节消息要两个块（长度字段放不下）", 2,
            mdPad(new byte[56]).size());
        Assert.assertEquals("55 字节消息只要一个块", 1, mdPad(new byte[55]).size());
    }

    /**
     * 反面教材：丢掉长度字段，直接按 64 字节切块逐块推进（这里只演示 64 字节对齐的输入不受影响）。
     * 少了 ENTL/长度字段，就等于给长度扩展攻击开了门。
     */
    private static byte[] naiveNoLength(byte[] msg)
    {
        List<byte[]> blocks = Calc.chunks(msg, 64);
        long[] v = iv();
        for (int i = 0; i < blocks.size(); i++)
        {
            v = cf(v, blocks.get(i));
        }
        return Calc.bytes32(v);
    }

    /** 布尔函数与置换函数的本质：只由 与/或/非/异或/循环移位 构成，可被完全展开成表达式。 */
    @Test
    public void booleanFunctionsDecomposeToXorAndRotate()
    {
        long a = 0xdeadbeefL, b = 0x12345678L, c = 0xcafebabeL;
        // 前 16 轮 FF/GG 都是纯异或（线性）
        Assert.assertEquals(u32(a ^ b ^ c), ff(0L, a, b, c));
        Assert.assertEquals(u32(a ^ b ^ c), gg(15L, a, b, c));
        // 16 轮之后 FF 变成多数函数、GG 变成选择函数（引入非线性）
        Assert.assertEquals(u32((a & b) | (a & c) | (b & c)), ff(16L, a, b, c));
        Assert.assertEquals(u32((a & b) | ((~a & M32) & c)), gg(63L, a, b, c));
        // P0/P1 的"扩散"性质：单比特翻转，输出比特数远大于 1
        int flipped = Long.bitCount(p0(1L)) + Long.bitCount(p1(1L));
        log.info("[SM3-布尔函数] bitCount(P0(1)) + bitCount(P1(1)) = {}", flipped);
        Assert.assertTrue("P0/P1 必须把 1 个输入比特扩散到多个输出比特", flipped >= 6);
        Assert.assertNotEquals("P0 不是恒等映射", Long.valueOf(1L), Long.valueOf(p0(1L)));
    }
}
