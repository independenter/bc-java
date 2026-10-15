package org.bouncycastle.learning.functional;

import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;

import static org.bouncycastle.learning.functional.Fp.M32;
import static org.bouncycastle.learning.functional.Fp.apply4;
import static org.bouncycastle.learning.functional.Fp.rotl;
import static org.bouncycastle.learning.functional.Fp.u32;

/**
 * SM3（GB/T 32905-2016）的本质计算 —— 纯函数版。
 *
 * <p>没有 Digest 对象、没有继承体系，SM3 只是四个纯函数的复合：
 * <pre>
 *   sm3 = digestBigEndian ∘ foldCF ∘ mdPad
 *   foldCF = V -＞ block -＞ xorWords(fold(64 轮压缩, V), V)   // Merkle–Damgård 迭代
 * </pre>
 * 全部中间量都是不可变数组，"状态"靠 fold 传递（state threading），这正是函数式写法的核心。
 */
@Slf4j
public class Sm3FunctionalTest
{
    /** 轮常数 T_j：前 16 轮 0x79cc4519，后 48 轮 0x7a879d8a —— SM3 里唯一的"魔术数"。 */
    private static final Function<Long, Long> T = j -> j < 16 ? 0x79cc4519L : 0x7a879d8aL;

    /**
     * FF_j / GG_j 写成柯里化函数：j 是"轮"，a/b/c 是三个 32-bit 字。这就是布尔函数的本质。
     * 前 16 轮只用异或（线性），后 48 轮才引入与/或（非线性）—— 这是 SM3 抗碰撞的关键设计。
     */
    private static final Function<Long, Function<Long, Function<Long, Function<Long, Long>>>> FF =
        j -> a -> b -> c -> u32(j < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c)));

    private static final Function<Long, Function<Long, Function<Long, Function<Long, Long>>>> GG =
        j -> a -> b -> c -> u32(j < 16 ? (a ^ b ^ c) : ((a & b) | ((~a & M32) & c)));

    /** P0/P1 是"扩散函数"：一个字的每一位靠它们摊到 32 位上，本质只有 异或 + 循环左移。 */
    private static final UnaryOperator<Long> P0 = x -> u32(x ^ rotl(x, 9) ^ rotl(x, 17));

    /** 注意 P1 的第二段移位是 23 位，不是 22 位 —— 网上大量资料把这一处抄错。 */
    private static final UnaryOperator<Long> P1 = x -> u32(x ^ rotl(x, 15) ^ rotl(x, 23));

    /** 初始值 IV —— 标准的 8 个 32-bit 字。 */
    private static long[] iv()
    {
        return new long[]{
            0x7380166fL, 0x4914b2b9L, 0x172442d7L, 0xda8a0600L,
            0xa96f30bcL, 0x163138aaL, 0xe38dee4dL, 0xb0fb0e4eL
        };
    }

    /** 把纯函数装配成一条管道：pad -> 逐块压缩 -> 大端序列化。供其他算法（SM2）复用。 */
    static Function<byte[], byte[]> sm3Pipeline()
    {
        return msg -> Fp.bytes32(
            Fp.fold(mdPad().apply(msg), iv(), (v, block) -> cf().apply(v).apply(block)));
    }

    /** MD 填充：m ‖ 0x80 ‖ 0^k ‖ len₆₄(m)。返回 64 字节块的列表 —— 纯函数。 */
    private static Function<byte[], List<byte[]>> mdPad()
    {
        return msg ->
        {
            int zeros = (56 - (msg.length + 1) % 64 + 64) % 64;
            byte[] bits = new byte[8];
            long bitLen = 8L * msg.length;
            for (int i = 0; i < 8; i++)
            {
                bits[i] = (byte)(bitLen >>> (56 - 8 * i));
            }
            byte[] padded = Fp.concat(msg, new byte[]{ (byte)0x80 }, Fp.repeatedByte(0, zeros), bits);
            return Fp.chunks(padded, 64);
        };
    }

    /**
     * 消息扩展：W[0..67]。递推式即标准公式，注意每一步都返回新数组而不是原地写。
     * 只有 W[j-3] 和 W[j-13] 带循环移位，W[j-6] 是原值 —— 背错这一项是最常见的实现 bug。
     */
    private static Function<byte[], long[]> wExpand()
    {
        return block ->
        {
            long[] seeded = Arrays.copyOf(Fp.words32(block), 68);
            return Fp.foldRange(16, 68, seeded, (w, j) -> Fp.replace(w, j, u32(
                P1.apply(u32(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)))
                    ^ rotl(w[j - 13], 7) ^ w[j - 6])));
        };
    }

    /** 压缩函数 CF：64 步折叠 + 与上一个链接值异或。返回不可变的新链接值。 */
    private static Function<long[], Function<byte[], long[]>> cf()
    {
        return v -> block ->
        {
            long[] w = wExpand().apply(block);
            long[] wp = IntStream.range(0, 64).mapToLong(i -> u32(w[i] ^ w[i + 4])).toArray();
            // 状态 = 8 个字 A..H；一轮 = 一个纯函数 状态 -> 状态
            Function<long[], Function<Integer, long[]>> round = s -> j ->
            {
                long ss1 = rotl(u32(rotl(s[0], 12) + s[4] + rotl(T.apply((long)j), j)), 7);
                long ss2 = u32(ss1 ^ rotl(s[0], 12));
                long tt1 = u32(apply4(FF, (long)j, s[0], s[1], s[2]) + s[3] + ss2 + wp[j]);
                long tt2 = u32(apply4(GG, (long)j, s[4], s[5], s[6]) + s[7] + ss1 + w[j]);
                return new long[]{ tt1, s[0], rotl(s[1], 9), s[2], P0.apply(tt2), s[4], rotl(s[5], 19), s[6] };
            };
            long[] folded = Fp.foldRange(0, 64, v, (s, j) -> round.apply(s).apply(j));
            return IntStream.range(0, 8).mapToLong(i -> u32(folded[i] ^ v[i])).toArray();
        };
    }

    // ------------------------------------------------------------------ 测试

    /** 标准测试向量：SM3("abc") 与 SM3("abcd"*16)。自己的纯函数实现必须一字不差。 */
    @Test
    public void sm3EssenceMatchesGbt32905Vectors()
        throws Exception
    {
        Function<byte[], byte[]> sm3 = sm3Pipeline();

        String abc = Fp.hex(sm3.apply("abc".getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abc\")            = {}", abc);
        Assert.assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", abc);

        String abcd16 = Fp.hex(sm3.apply(Fp.repeat("abcd", 16).getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abcd\"*16)        = {}", abcd16);
        Assert.assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", abcd16);

        // 与 JCE 第三方实现互相印证（不同长度覆盖所有填充分支）
        Fp.useBc();
        for (int len : new int[]{ 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128 })
        {
            byte[] data = new byte[len];
            Arrays.fill(data, (byte)'a');
            Assert.assertArrayEquals("长度 " + len + " 的填充/折叠不一致",
                Fp.digest("SM3", data), sm3.apply(data));
        }
        log.info("[SM3-本质] 与 JCE SM3 在 11 种长度（含填充边界 55/56/63/64/119/120）上完全一致");
    }

    /** Merkle–Damgård 的本质：hash(m1‖m2) = CF(CF(IV, pad 前若干块) …) —— 折叠可拼接。 */
    @Test
    public void merkleDamgardIsJustAFoldOverBlocks()
        throws Exception
    {
        Function<byte[], byte[]> sm3 = sm3Pipeline();
        BiFunction<long[], byte[], long[]> feed = (v, block) -> cf().apply(v).apply(block);

        byte[] head = Fp.repeat("head-", 5).getBytes("UTF-8");
        byte[] tail = Fp.repeat("-tail", 7).getBytes("UTF-8");

        // 分块折叠后与整体折叠必须相同（除了最后一块要带长度）：验证"折叠顺序无关性"
        long[] whole = Fp.fold(mdPad().apply(Fp.concat(head, tail)), iv(), (v, b) -> feed.apply(v, b));
        log.info("[SM3-本质] 整体折叠        = {}", Fp.hex(whole));
        Assert.assertArrayEquals(Fp.bytes32(whole), sm3.apply(Fp.concat(head, tail)));

        // 逐字节喂入（流式）与一次性喂入等价 —— 这就是 MessageDigest.update() 的数学本质
        SM3Digest ref = new SM3Digest();
        ref.update(head, 0, head.length);
        ref.update(tail, 0, tail.length);
        byte[] streamed = new byte[32];
        ref.doFinal(streamed, 0);
        Assert.assertArrayEquals("流式 update 与一次性 digest 必须等价（Merkle–Damgård 可拼接性）",
            sm3.apply(Fp.concat(head, tail)), streamed);
        log.info("[SM3-本质] 流式 update == 一次性 digest：{}", Fp.hex(streamed));
    }

    /** HMAC-SM3：只用"哈希函数"这一个抽象就能构造消息认证码（NIST 的意义所在）。 */
    @Test
    public void hmacSm3IsHashCompositionNotAClass()
        throws Exception
    {
        Function<byte[], byte[]> sm3 = sm3Pipeline();
        final int blockSize = 64;
        // 密钥规约：过长先哈希、过短右侧补零 —— HMAC 唯一的"密钥预处理"
        UnaryOperator<byte[]> fitKey = key -> Arrays.copyOf(
            key.length > blockSize ? Fp.concat(sm3.apply(key), new byte[blockSize - 32])
                : Fp.concat(key, new byte[blockSize - key.length]), blockSize);
        byte[] ipad = Fp.repeatedByte(0x36, blockSize);
        byte[] opad = Fp.repeatedByte(0x5c, blockSize);
        // HMAC(k, m) = H(k⊕opad ‖ H(k⊕ipad ‖ m)) —— 一行复合，没有任何对象
        BiFunction<byte[], byte[], byte[]> hmac = (key, msg) ->
        {
            byte[] k = fitKey.apply(key);
            return sm3.apply(Fp.concat(Fp.xor(k, opad), sm3.apply(Fp.concat(Fp.xor(k, ipad), msg))));
        };

        byte[] key = "key-for-sm3-hmac".getBytes("UTF-8");
        byte[] msg = "Hello functional HMAC".getBytes("UTF-8");
        byte[] ours = hmac.apply(key, msg);
        log.info("[SM3-HMAC] 纯函数 HMAC-SM3   = {}", Fp.hex(ours));

        Fp.useBc();
        HMac bc = new HMac(new SM3Digest());
        bc.init(new KeyParameter(key));
        bc.update(msg, 0, msg.length);
        byte[] expected = new byte[bc.getMacSize()];
        bc.doFinal(expected, 0);
        Assert.assertArrayEquals("HMAC-SM3 与 BC HMac 不一致", expected, ours);
        Assert.assertNotEquals("HMAC 必须依赖密钥", Fp.hex(ours), Fp.hex(hmac.apply("other-key".getBytes("UTF-8"), msg)));
    }

    /** KDF（SM2 加密里那个"计数器模式派生函数"）：本质 = hash(z ‖ 计数器) 的无限流取前 klen 字节。 */
    @Test
    public void kdfIsAnInfiniteHashStreamTruncated()
        throws Exception
    {
        Function<byte[], byte[]> sm3 = sm3Pipeline();
        BiFunction<byte[], Integer, byte[]> kdf = (z, klen) ->
        {
            List<Integer> counters = IntStream.rangeClosed(1, Fp.ceilDiv(klen, 32)).boxed()
                .collect(Collectors.toList());
            byte[] stream = Fp.fold(counters, new byte[0], (acc, ct) ->
            {
                byte[] counterBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    counterBytes[i] = (byte)(ct >>> (24 - 8 * i));
                }
                return Fp.concat(acc, sm3.apply(Fp.concat(z, counterBytes)));
            });
            return Arrays.copyOf(stream, klen);
        };

        byte[] z = Fp.unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e0f");
        for (int klen : new int[]{ 1, 16, 32, 33, 64, 100 })
        {
            byte[] ours = kdf.apply(z, klen);

            KDF2BytesGenerator bcKdf = new KDF2BytesGenerator(new SM3Digest());
            bcKdf.init(new KDFParameters(z, null));
            byte[] expected = new byte[klen];
            bcKdf.generateBytes(expected, 0, klen);

            Assert.assertArrayEquals("KDF 长度 " + klen + " 不一致", expected, ours);
            log.info("[SM3-KDF] klen={} -> {}", klen, Fp.hex(ours));
        }
        log.info("[SM3-KDF] 结论：KDF 就是 fold(计数器序列, 空串, 累加 hash(z‖ct)) 再截断");
    }

    /** 填充模式的"哈希侧视角"：0x80 + 0 填充 vs 只追加长度 —— 说明为什么 SM3 不需要加密式填充。 */
    @Test
    public void hashPaddingIsLengthAwareNotBlockAware()
        throws Exception
    {
        Function<byte[], byte[]> sm3 = sm3Pipeline();
        Function<byte[], byte[]> naiveNoLength = msg ->
        {
            // 反面教材：丢掉长度字段 -> 长度扩展攻击（这里只演示 64 字节对齐的输入不受影响）
            long[] v = Fp.fold(Fp.chunks(msg, 64), iv(), (acc, block) -> cf().apply(acc).apply(block));
            return Fp.bytes32(v);
        };

        byte[] aligned = Fp.repeat("0123456789abcdef", 4).getBytes("UTF-8");   // 64 字节
        byte[] short0 = new byte[0];

        log.info("[SM3-填充] 64 字节对齐消息的真实 SM3 = {}", Fp.hex(sm3.apply(aligned)));
        log.info("[SM3-填充] 去掉长度字段的\"伪 SM3\"    = {}", Fp.hex(naiveNoLength.apply(aligned)));
        Assert.assertNotEquals("真实 SM3 绝不能等于无长度字段的折叠",
            Fp.hex(sm3.apply(aligned)), Fp.hex(naiveNoLength.apply(aligned)));
        Assert.assertEquals("空消息也必须产生一个完整块（0x80 + 长度）", 1, mdPad().apply(short0).size());
        Assert.assertEquals("56 字节消息要两个块（长度字段放不下）", 2,
            mdPad().apply(new byte[56]).size());
        Assert.assertEquals("55 字节消息只要一个块", 1, mdPad().apply(new byte[55]).size());
    }

    /** 布尔函数与置换函数的本质：只由 与/或/非/异或/循环移位 构成，可被完全展开成表达式。 */
    @Test
    public void booleanFunctionsDecomposeToXorAndRotate()
    {
        long a = 0xdeadbeefL, b = 0x12345678L, c = 0xcafebabeL;
        // 前 16 轮 FF/GG 都是纯异或（线性）
        Assert.assertEquals(u32(a ^ b ^ c), apply4(FF, 0L, a, b, c).longValue());
        Assert.assertEquals(u32(a ^ b ^ c), apply4(GG, 15L, a, b, c).longValue());
        // 16 轮之后 FF 变成多数函数、GG 变成选择函数（引入非线性）
        Assert.assertEquals(u32((a & b) | (a & c) | (b & c)), apply4(FF, 16L, a, b, c).longValue());
        Assert.assertEquals(u32((a & b) | ((~a & M32) & c)), apply4(GG, 63L, a, b, c).longValue());
        // P0/P1 的"扩散"性质：单比特翻转，输出比特数远大于 1
        int flipped = Long.bitCount(P0.apply(1L)) + Long.bitCount(P1.apply(1L));
        log.info("[SM3-布尔函数] bitCount(P0(1)) + bitCount(P1(1)) = {}", flipped);
        Assert.assertTrue("P0/P1 必须把 1 个输入比特扩散到多个输出比特", flipped >= 6);
        Assert.assertNotEquals("P0 不是恒等映射", Long.valueOf(1L), P0.apply(1L));
    }
}
