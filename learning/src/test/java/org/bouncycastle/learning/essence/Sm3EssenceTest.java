package org.bouncycastle.learning.essence;

import java.util.Arrays;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import static org.bouncycastle.learning.essence.Calc.M32;
import static org.bouncycastle.learning.essence.Calc.rotl;
import static org.bouncycastle.learning.essence.Calc.u32;

/**
 * SM3（GB/T 32905-2016）的本质测试。
 *
 * <p>实现本体在 {@link Sm3}（src/main）：那类纯静态方法没有状态，抽到 main 之后 SM9 引擎和
 * JCE Provider 才能复用；这里逐块核对它的输出 —— 标准测试向量、Merkle–Damgård 可拼接性、
 * 填充边界、布尔函数的线性/非线性分界，全部与 BC 的 SM3Digest 互相印证。
 *
 * <p>"状态"就是 {@link Sm3#cf} 循环里的局部变量（一个 long[8]），每轮就地改写它 ——
 * 不克隆、不套函数、不传参绕圈，这就是面向过程写法的核心。
 *
 * <p><b>符号表 —— 本文件里出现的字母/记号</b>（算法本身的 W[j]、W′[j]、T_j、FF_j、GG_j、P0/P1、
 * 链接值 V = A..H、轮号 j 等符号全部定义在 {@link Sm3} 的类注释里，这里只补测试自己的记号）
 * <pre>
 *   msg / m      被摘要（或被认证）的消息字节串；H 表示 SM3 这个哈希函数本身
 *   BLOCK_SIZE   分组长度 B = 64 字节 = 512 bit；HMAC 的密钥规约阈值、ipad/opad 的长度都是它
 *   key / k      HMAC 的密钥（注意：HMAC 里的 k 是密钥，和 SM2 签名里那个随机数 k 毫无关系）
 *   K            HMAC 密钥经规约后得到的 B 字节定长值（见 {@link #fitKey}）
 *   ipad, opad   两个常量填充串：ipad = 0x36 重复 B 次，opad = 0x5c 重复 B 次（0x36 ⊕ 0x5c = 0x6a，
 *                两者逐比特差异够大，保证内层/外层哈希看到的密钥"看起来"是两个独立值）
 *   ⊕            逐字节异或 (XOR)；‖ 是字节串拼接（concatenate），两者别混
 *   z            KDF 的输入密钥材料 (IKM, input keying material)，SM2 加密里就是共享点坐标 x₂‖y₂
 *   klen         要派生的输出字节数；32 是 SM2 里取 128-bit 密钥流两次的量级来源
 *   ct           KDF 的固定计数器 (counter)，从 1 开始每次加 1，编码成 4 字节大端
 *   v            链接值 V（8 个 32-bit 字的 long 数组）；IV = 初始链接值，cf() = 压缩函数
 *   len          测试里遍历的消息字节长度；55/56/63/64 是填充的分界点，理由见 {@link #hashPaddingIsLengthAwareNotBlockAware}
 *   counts[i]    频率直方图第 i 个桶的样本数；H = −Σ pᵢ·log₂pᵢ 是香农熵（单位：比特）
 * </pre>
 */
@Slf4j
public class Sm3EssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /** HMAC / KDF 里 SM3 的分组长度（字节）。 */
    private static final int BLOCK_SIZE = Sm3.BLOCK_SIZE;

    // ------------------------------------------------------------------ 测试

    /**
     * 标准测试向量：SM3("abc") 与 SM3("abcd"*16)。自己的面向过程实现必须一字不差。
     *
     * <p>两个向量分别覆盖 3 字节（1 个块，填充后 0x80 + 53 个 0 + 8 字节长度）与
     * 64 字节（恰好对齐，填充必须<b>再开一整块</b>）两种填充分支；
     * 期望值是 GB/T 32905 附录里的原文，逐位（256 bit = 64 个十六进制字符）比对。
     */
    @TraceExecution(value = "SM3 标准向量与逐块压缩", algorithm = "SM3", flow = "SM3-HASH")
    @Test
    public void sm3EssenceMatchesGbt32905Vectors()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"vectors", "abc / abcd*16"}, null, "start");

        String abc = Calc.hex(Sm3.sm3("abc".getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abc\")            = {}", abc);
        Assert.assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", abc);

        // 追踪用（不改被测调用）：用 Sm3.mdPad / iv / wExpand / cf 复刻一次 "abc" 的块级与轮级过程
        byte[] abcMsg = "abc".getBytes("UTF-8");
        List<byte[]> abcBlocks = Sm3.mdPad(abcMsg);
        byte[] abcBlock = abcBlocks.get(0);
        Tracer.trace("pad", new Object[]{"msgLen", abcMsg.length, "blockSize", BLOCK_SIZE},
            abcBlocks.size() + " block", "pad");
        Tracer.trace("split", new Object[]{"msgLen", abcMsg.length, "blockLen", abcBlock.length},
            Calc.hex(abcBlock), "split");
        long[] v0 = Sm3.iv();
        Tracer.trace("initV", null, Calc.hex(v0), "initV");
        long[] v1 = Sm3.cf(v0, abcBlock);
        Tracer.traceLoop("cfLoop", new Object[]{"block", 1, "blockLen", abcBlock.length},
            Calc.hex(v1), "cfLoop", 1, abcBlocks.size(), "cfLoop");
        long[] w = Sm3.wExpand(abcBlock);
        Tracer.trace("expand", new Object[]{"W[0]", w[0], "W[15]", w[15]}, Calc.hex(w), "expand");
        traceCompressRounds(v0, abcBlock);
        Tracer.trace("finalize", new Object[]{"Vn", Calc.hex(v1)}, abc, "finalize");

        String abcd16 = Calc.hex(Sm3.sm3(Calc.repeat("abcd", 16).getBytes("UTF-8")));
        log.info("[SM3-本质] SM3(\"abcd\"*16)        = {}", abcd16);
        Assert.assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", abcd16);
        Tracer.trace("finalize", new Object[]{"vector", "abcd*16", "msgLen", 64}, abcd16, "finalize");

        // 与 JCE 第三方实现互相印证（不同长度覆盖所有填充分支）
        Calc.useBc();
        // 55/56：0x80 之后还能不能塞下 8 字节长度字段；63/64：是否需要多切一整块；0：空消息也要出一个块
        for (int len : new int[]{ 0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128 })
        {
            byte[] data = new byte[len];
            Arrays.fill(data, (byte)'a');
            Assert.assertArrayEquals("长度 " + len + " 的填充/折叠不一致",
                Calc.digest("SM3", data), Sm3.sm3(data));
        }
        Tracer.trace("finalize", new Object[]{"lengths", 11, "reference", "JCE SM3"},
            "11 种长度全部一致", "finalize");
        log.info("[SM3-本质] 与 JCE SM3 在 11 种长度（含填充边界 55/56/63/64/119/120）上完全一致");
        Tracer.trace("end", new Object[]{"vectors", 2, "crossChecks", 11}, null, "end");
    }

    /**
     * Merkle–Damgård 的本质：hash(m1‖m2) = CF(CF(IV, pad 前若干块) …) —— 逐块 for 循环可拼接。
     *
     * <p>符号：m1 = head（前半段消息）、m2 = tail（后半段）、‖ = 拼接、IV = 初始链接值、
     * CF = 压缩函数、块序列 B₀..Bₙ₋₁ 来自 mdPad(head‖tail)。
     * 折叠式 Vᵢ = CF(Vᵢ₋₁, Bᵢ₋₁) 只要求"上一块的输出当下一块的输入"，所以循环怎么切都不改变结果 ——
     * 这就是可拼接性（streamability）的数学内容，也是 MessageDigest.update() 能分批喂的原因。
     */
    @TraceExecution(value = "Merkle–Damgård 逐块折叠", algorithm = "SM3", flow = "SM3-HASH")
    @Test
    public void merkleDamgardIsJustALoopOverBlocks()
        throws Exception
    {
        byte[] head = Calc.repeat("head-", 5).getBytes("UTF-8");
        byte[] tail = Calc.repeat("-tail", 7).getBytes("UTF-8");

        Tracer.trace("start", new Object[]{"headLen", head.length, "tailLen", tail.length}, null, "start");

        // 分块逐块推进后与整体推进必须相同（除了最后一块要带长度）：验证"推进顺序无关性"
        // whole 就是链接值 V：初值 V₀ = IV，循环里每步做 V = CF(V, B)
        long[] whole = Sm3.iv();
        byte[] wholeMsg = Calc.concat(head, tail);
        List<byte[]> wholeBlocks = Sm3.mdPad(wholeMsg);
        Tracer.trace("pad", new Object[]{"msgLen", wholeMsg.length, "blockSize", BLOCK_SIZE},
            wholeBlocks.size() + " blocks", "pad");
        Tracer.trace("split", new Object[]{"blocks", wholeBlocks.size()},
            wholeBlocks.get(0).length + " B/block", "split");
        Tracer.trace("initV", null, Calc.hex(whole), "initV");
        for (int i = 0; i < wholeBlocks.size(); i++)
        {
            whole = Sm3.cf(whole, wholeBlocks.get(i));
            if (i == 0)
            {
                Tracer.traceLoop("cfLoop", new Object[]{"block", i + 1, "blockLen", wholeBlocks.get(i).length},
                    Calc.hex(whole), "cfLoop", i + 1, wholeBlocks.size(), "cfLoop");
                long[] w = Sm3.wExpand(wholeBlocks.get(i));
                Tracer.trace("expand", new Object[]{"block", i + 1, "W[0]", w[0], "W[67]", w[67]},
                    Calc.hex(w), "expand");
                traceCompressRounds(Sm3.iv(), wholeBlocks.get(i));
            }
            else
            {
                Tracer.traceLoop("cfLoop", new Object[]{"block", i + 1, "blocksLeft", wholeBlocks.size() - i - 1},
                    Calc.hex(whole), "cfLoop", i + 1, wholeBlocks.size(), "cfLoop");
            }
        }
        log.info("[SM3-本质] 整体折叠        = {}", Calc.hex(whole));
        Assert.assertArrayEquals(Calc.bytes32(whole), Sm3.sm3(Calc.concat(head, tail)));
        Tracer.trace("finalize", new Object[]{"blocks", wholeBlocks.size()}, Calc.hex(whole), "finalize");

        // 逐字节喂入（流式）与一次性喂入等价 —— 这就是 MessageDigest.update() 的数学本质
        SM3Digest ref = new SM3Digest();
        ref.update(head, 0, head.length);
        ref.update(tail, 0, tail.length);
        byte[] streamed = new byte[32];
        ref.doFinal(streamed, 0);
        Assert.assertArrayEquals("流式 update 与一次性 digest 必须等价（Merkle–Damgård 可拼接性）",
            Sm3.sm3(Calc.concat(head, tail)), streamed);
        log.info("[SM3-本质] 流式 update == 一次性 digest：{}", Calc.hex(streamed));
        Tracer.trace("finalize", new Object[]{"streamed", true, "digest", Calc.hex(streamed)},
            Calc.hex(streamed), "finalize");
        Tracer.trace("end", new Object[]{"blocks", wholeBlocks.size()}, null, "end");
    }

    /**
     * HMAC-SM3：只用"哈希函数"这一个抽象就能构造消息认证码（NIST 的意义所在）。
     *
     * <p>MAC (Message Authentication Code) = 带密钥的摘要：只有持有同一把密钥的人能算出同一个值，
     * 它同时给出<b>完整性</b>和<b>来源认证</b> —— 而普通哈希两者都不给（任何人都能重算 H(m)）。
     */
    @TraceExecution(value = "HMAC 是哈希函数的组合", algorithm = "SM3", flow = "SM3-HMAC")
    @Test
    public void hmacSm3IsHashCompositionNotAClass()
        throws Exception
    {
        byte[] key = "key-for-sm3-hmac".getBytes("UTF-8");
        byte[] msg = "Hello functional HMAC".getBytes("UTF-8");
        Tracer.trace("start", new Object[]{"keyLen", key.length, "msgLen", msg.length}, null, "start");
        byte[] ours = hmacSm3(key, msg);
        log.info("[SM3-HMAC] 普通过程 HMAC-SM3   = {}", Calc.hex(ours));

        // 追踪用：按 HMAC 定义重算中间值（不改变上面的被测调用），把 k / ipad / opad / inner / outer 记下来
        byte[] k = fitKey(key);
        byte[] ipad = Calc.repeatedByte(0x36, BLOCK_SIZE);
        byte[] opad = Calc.repeatedByte(0x5c, BLOCK_SIZE);
        byte[] kIpad = Calc.xor(k, ipad);
        byte[] kOpad = Calc.xor(k, opad);
        byte[] inner = Sm3.sm3(Calc.concat(kIpad, msg));
        byte[] outer = Sm3.sm3(Calc.concat(kOpad, inner));
        Tracer.trace("fitKey", new Object[]{"keyLen", key.length, "key", Calc.hex(key)}, Calc.hex(k), "fitKey");
        Tracer.trace("ipad", new Object[]{"ipad", Calc.hex(ipad), "K", Calc.hex(k)}, Calc.hex(kIpad), "ipad");
        Tracer.trace("inner", new Object[]{"K^ipad", Calc.hex(kIpad), "msg", new String(msg, "UTF-8")},
            Calc.hex(inner), "inner");
        Tracer.trace("opad", new Object[]{"opad", Calc.hex(opad), "K", Calc.hex(k)}, Calc.hex(kOpad), "opad");
        Tracer.trace("outer", new Object[]{"K^opad", Calc.hex(kOpad), "inner", Calc.hex(inner)},
            Calc.hex(outer), "outer");

        Calc.useBc();
        HMac bc = new HMac(new SM3Digest());
        bc.init(new KeyParameter(key));
        bc.update(msg, 0, msg.length);
        byte[] expected = new byte[bc.getMacSize()];
        bc.doFinal(expected, 0);
        Assert.assertArrayEquals("HMAC-SM3 与 BC HMac 不一致", expected, ours);
        Assert.assertNotEquals("HMAC 必须依赖密钥", Calc.hex(ours), Calc.hex(hmacSm3("other-key".getBytes("UTF-8"), msg)));
        Tracer.traceDecision("compare", new Object[]{"ours", Calc.hex(ours), "bc", Calc.hex(expected),
            "outer", Calc.hex(outer)}, true, "compare", "ours == BC HMac 且换密钥后不同");
        Tracer.trace("end", new Object[]{"macLen", ours.length}, null, "end");
    }

    /**
     * 密钥规约：过长先哈希、过短右侧补零 —— HMAC 唯一的"密钥预处理"，一个普通静态方法。
     *
     * <p>目标只有一个：把任意长度的密钥 key 变成<b>正好 B = BLOCK_SIZE = 64 字节</b>的 K，
     * 因为 HMAC 的定义要求 K 能和 ipad/opad 逐字节异或（异或是等长运算，见 {@link Calc#xor}）。
     * <pre>
     *   key.length &gt; 64   用 K = SM3(key) ‖ 0³²：过长不能直接截断（截断会让"多出来的那一段密钥"完全不起作用，
     *                     等于削弱熵），所以先用哈希把它压成 32 字节摘要，再在<b>右侧</b>补零凑满 64 字节
     *   key.length ≤ 64   用 K = key ‖ 0^(64−len)：右侧补零到 B 字节，原密钥每一位都保留
     * </pre>
     */
    private static byte[] fitKey(byte[] key)
    {
        if (key.length > BLOCK_SIZE)
        {
            return Arrays.copyOf(Calc.concat(Sm3.sm3(key), new byte[BLOCK_SIZE - 32]), BLOCK_SIZE);
        }
        return Arrays.copyOf(Calc.concat(key, new byte[BLOCK_SIZE - key.length]), BLOCK_SIZE);
    }

    /**
     * HMAC(k, m) = H(k⊕opad ‖ H(k⊕ipad ‖ m)) —— 几步顺序调用 SM3，没有任何对象与函数值。
     *
     * <p>逐个符号：
     * <pre>
     *   k      规约后的 64 字节密钥 K（见 {@link #fitKey}）；m 是消息；H 就是 SM3
     *   ipad   0x36 重复 64 字节；opad 0x5c 重复 64 字节；两者相差 0x36⊕0x5c = 0x6a，逐比特差异足够大，
     *          于是 K⊕ipad 与 K⊕opad 是两个"看起来互不相关"的 64 字节值
     *   ‖      拼接；⊕ 逐字节异或
     *   inner  = H((K⊕ipad) ‖ m)  内层摘要，32 字节
     *   结果   = H((K⊕opad) ‖ inner)  外层摘要 —— 就是本方法的返回值
     * </pre>
     * 为什么要"套两层"：MD 构造本身扛不住长度扩展 —— 已知 H(m) 就能从中间态 V 继续折叠出 H(m‖pad‖m′)。
     * 外层再哈希一次，攻击者拿不到"以密钥打头的那个块"的链接值，就无法继续往后推；
     * 密钥同时出现在内层块的首块和外层块的首块，两个掩码值不同，也无法把内层的中间态复用。
     * 结论：HMAC 把一个"只有哈希函数"的黑盒升级成消息认证码，安全性只需 H 是抗碰撞的 MD。
     */
    private static byte[] hmacSm3(byte[] key, byte[] msg)
    {
        byte[] k = fitKey(key);
        byte[] ipad = Calc.repeatedByte(0x36, BLOCK_SIZE);
        byte[] opad = Calc.repeatedByte(0x5c, BLOCK_SIZE);
        byte[] inner = Sm3.sm3(Calc.concat(Calc.xor(k, ipad), msg));
        return Sm3.sm3(Calc.concat(Calc.xor(k, opad), inner));
    }

    /**
     * KDF（SM2 加密里那个"计数器模式派生函数"）：本质 = hash(z ‖ 计数器) 的无限流取前 klen 字节。
     *
     * <p>为什么需要 KDF：共享点坐标 x₂‖y₂ 只有 64 字节，而且它是"两个比特串"而不是均匀密钥；
     * KDF 的作用是把任意长度的密钥材料 z 展开成任意长度的输出，并且每一段输出都只依赖 z 一次哈希。
     * 这里 klen 覆盖 1/16/32/33/64/100，专门测"不足一块""正好两块多"的截断分支。
     */
    @TraceExecution(value = "KDF 是截断的哈希流", algorithm = "SM3", flow = "SM3-KDF")
    @Test
    public void kdfIsAnInfiniteHashStreamTruncated()
        throws Exception
    {
        byte[] z = Calc.unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e0f");
        Tracer.trace("start", new Object[]{"z", Calc.hex(z), "zLen", z.length}, null, "start");

        // 追踪用：只把 klen=33 的两段逐段展开，其余 klen 在 compare 里汇总（不改被测的 kdf 调用）
        int detailKlen = 33;
        int detailBlocks = Calc.ceilDiv(detailKlen, 32);
        Tracer.trace("init", new Object[]{"klen", detailKlen, "hashLen", 32},
            detailBlocks + " segments", "init");
        byte[] detailStream = new byte[0];
        for (int ct = 1; ct <= detailBlocks; ct++)
        {
            byte[] counterBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                counterBytes[i] = (byte)(ct >>> (24 - 8 * i));
            }
            byte[] segment = Sm3.sm3(Calc.concat(z, counterBytes));
            Tracer.traceLoop("ctLoop.segment", new Object[]{"ct", ct, "blocks", detailBlocks},
                Calc.hex(segment), "ctLoop", ct, detailBlocks, "ctLoop");
            Tracer.trace("hash", new Object[]{"ct", ct, "ct4", Calc.hex(counterBytes)},
                Calc.hex(segment), "hash");
            detailStream = Calc.concat(detailStream, segment);
            Tracer.trace("concat", new Object[]{"ct", ct, "prevLen", detailStream.length - segment.length},
                detailStream.length + " B", "concat");
        }
        byte[] detailOut = Arrays.copyOf(detailStream, detailKlen);
        Tracer.trace("truncate", new Object[]{"streamLen", detailStream.length, "klen", detailKlen},
            Calc.hex(detailOut), "truncate");

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
        Tracer.traceDecision("compare", new Object[]{"klens", 6, "reference", "BC KDF2(SM3)"}, true,
            "compare", "klen 1/16/32/33/64/100 全部一致");
        Tracer.trace("end", new Object[]{"maxKlen", 100}, null, "end");
    }

    /**
     * KDF 派生：for 循环把计数器 1..ceil(klen/32) 逐个 hash(z‖ct) 拼流，最后截断到 klen 字节。
     *
     * <p>符号与公式（这就是 GM/T 0003.4 / ISO 18033-3 的 KDF 计数器模式，counter mode）：
     * <pre>
     *   z        输入密钥材料 (IKM)：SM2 加密里是共享点的坐标 x₂ ‖ y₂（各 32 字节大端）
     *   klen     需要的输出字节数；blocks = ceil(klen / 32) 是"要哈希几次才够"
     *   ct       固定计数器 (counter)，从 <b>1</b> 开始（不是 0！）逐个加 1，编码成 4 字节<b>大端</b>
     *   ct₄      ct 的 4 字节大端表示：counterBytes[i] = ct &gt;&gt;&gt; (24 − 8i)，即 i=0 放最高字节
     *   第 ct 段 = SM3(z ‖ ct₄)  —— 每段 32 字节（256 bit = SM3 的完整输出）
     *   输出     = 第 1 段 ‖ 第 2 段 ‖ … ‖ 第 blocks 段，再截断到前 klen 字节
     * </pre>
     * 计数器存在的意义：保证各段输出互不重复（段与段的输入不同），这样"截断拼接"才等价于
     * 从一个确定性无限密钥流里取前 klen 字节；少了 ct，KDF(x‖y) 只会给出同样 32 字节的重复。
     */
    private static byte[] kdf(byte[] z, int klen)
    {
        int blocks = Calc.ceilDiv(klen, 32);
        byte[] stream = new byte[0];
        for (int ct = 1; ct <= blocks; ct++)
        {
            // 把 32-bit 计数器 ct 摊成 4 个字节，高位在前（大端）：i = 0 取第 31..24 位
            byte[] counterBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                counterBytes[i] = (byte)(ct >>> (24 - 8 * i));
            }
            stream = Calc.concat(stream, Sm3.sm3(Calc.concat(z, counterBytes)));
        }
        return Arrays.copyOf(stream, klen);
    }

    /**
     * 填充模式的"哈希侧视角"：0x80 + 0 填充 vs 只追加长度 —— 说明为什么 SM3 不需要加密式填充。
     *
     * <p>MD 填充式：m ‖ 0x80 ‖ 0^k ‖ len₆₄(m)，要求总长 ≡ 0 (mod 64)。
     * 三条断言的分界点解释（len 是消息<b>字节</b>数，8 字节给长度字段，块长 64 字节）：
     * <pre>
     *   len = 0   空消息也要一个块：0x80 + 55 个 0 + 8 字节长度 = 64，绝不允许"输入为空就不压缩"
     *   len = 55  55 + 1(0x80) = 56，正好停在长度字段前面 —— k = 0，一个块搞定
     *   len = 56  56 + 1 = 57 已经越过 56 这个"必须给长度留 8 字节"的位置 —— k = 63，只能两个块
     * </pre>
     * 所以边界不是 64 而是 56 = 64 − 8：这是 MD 填充最容易写错的一处。
     */
    @TraceExecution(value = "填充只认长度不认块对齐", algorithm = "SM3", flow = "SM3-HASH")
    @Test
    public void hashPaddingIsLengthAwareNotBlockAware()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"lengths", "0/55/56/64", "blockSize", BLOCK_SIZE}, null, "start");

        byte[] aligned = Calc.repeat("0123456789abcdef", 4).getBytes("UTF-8");   // 64 字节
        byte[] short0 = new byte[0];

        Tracer.trace("pad", new Object[]{"msgLen", short0.length}, Sm3.mdPad(short0).size() + " block", "pad");
        Tracer.trace("pad", new Object[]{"msgLen", 55}, Sm3.mdPad(new byte[55]).size() + " block", "pad");
        Tracer.trace("pad", new Object[]{"msgLen", 56}, Sm3.mdPad(new byte[56]).size() + " blocks", "pad");
        Tracer.trace("pad", new Object[]{"msgLen", aligned.length}, Sm3.mdPad(aligned).size() + " blocks", "pad");
        Tracer.trace("split", new Object[]{"lengths", "0/55/56/64"},
            "MD 块数 1/1/2/2；naive 64 字节 = 1 块", "split");
        long[] v0 = Sm3.iv();
        Tracer.trace("initV", null, Calc.hex(v0), "initV");
        List<byte[]> naiveBlocks = Calc.chunks(aligned, BLOCK_SIZE);
        long[] v = v0;
        for (int i = 0; i < naiveBlocks.size(); i++)
        {
            v = Sm3.cf(v, naiveBlocks.get(i));
            Tracer.traceLoop("cfLoop", new Object[]{"block", i + 1, "blockLen", naiveBlocks.get(i).length},
                Calc.hex(v), "cfLoop", i + 1, naiveBlocks.size(), "cfLoop");
        }

        log.info("[SM3-填充] 64 字节对齐消息的真实 SM3 = {}", Calc.hex(Sm3.sm3(aligned)));
        log.info("[SM3-填充] 去掉长度字段的\"伪 SM3\"    = {}", Calc.hex(naiveNoLength(aligned)));
        Assert.assertNotEquals("真实 SM3 绝不能等于无长度字段的逐块推进",
            Calc.hex(Sm3.sm3(aligned)), Calc.hex(naiveNoLength(aligned)));
        // 下面三条正是 0 / 55 / 56 三个填充分支的"块数"验证（块数 = 折叠次数，见 Sm3.mdPad）
        Assert.assertEquals("空消息也必须产生一个完整块（0x80 + 长度）", 1, Sm3.mdPad(short0).size());
        Assert.assertEquals("56 字节消息要两个块（长度字段放不下）", 2,
            Sm3.mdPad(new byte[56]).size());
        Assert.assertEquals("55 字节消息只要一个块", 1, Sm3.mdPad(new byte[55]).size());
        Tracer.trace("finalize", new Object[]{"mode", "SM3 (m‖0x80‖0^k‖len)", "blocks", Sm3.mdPad(aligned).size()},
            Calc.hex(Sm3.sm3(aligned)), "finalize");
        Tracer.trace("finalize", new Object[]{"mode", "naive (无长度字段)", "blocks", naiveBlocks.size()},
            Calc.hex(naiveNoLength(aligned)), "finalize");
        Tracer.trace("end", new Object[]{"paddingBoundary", 56}, null, "end");
    }

    /**
     * 反面教材：丢掉长度字段，直接按 64 字节切块逐块推进（这里只演示 64 字节对齐的输入不受影响）。
     * 少了 ENTL/长度字段，就等于给长度扩展攻击开了门。
     *
     * <p>符号：Calc.chunks(msg, 64) = 不做 MD 填充、只按块长 B = 64 切分（要求 len 已是 64 的倍数）；
     * v = 链接值 V，V₀ = IV，循环体 V = CF(V, Bᵢ)；Calc.bytes32(v) = 大端序列化，
     * 把 8 个 32-bit 字摊成 32 字节 = 256 bit。与真实 SM3 的<b>唯一</b>区别就是没有 ‖ 0x80 ‖ 0^k ‖ len₆₄。
     * 危害：摘要值本身就是最后的链接值，攻击者可以直接拿它当新起点继续折叠 m′ 的块，
     * 于是无需密钥/无需知道 m 就能算出 H(m ‖ pad(m) ‖ m′) —— 这就是长度扩展 (length extension)；
     * len₆₄ 字段让"续接"后的长度与哈希里写死的长度对不上，再加上 HMAC 才是正解。
     */
    private static byte[] naiveNoLength(byte[] msg)
    {
        List<byte[]> blocks = Calc.chunks(msg, 64);
        long[] v = Sm3.iv();
        for (int i = 0; i < blocks.size(); i++)
        {
            v = Sm3.cf(v, blocks.get(i));
        }
        return Calc.bytes32(v);
    }

    /**
     * 追踪专用：按 {@link Sm3#cf} 的 64 轮方程重跑一遍压缩，产生 compress 循环的逐轮事件。
     * 这段是测试侧的展示用复刻，不参与任何断言，也不改变被测调用。
     */
    private static void traceCompressRounds(long[] v, byte[] block)
    {
        long[] w = Sm3.wExpand(block);
        long[] wp = new long[64];
        for (int i = 0; i < 64; i++)
        {
            wp[i] = u32(w[i] ^ w[i + 4]);
        }
        long a = v[0], b = v[1], c = v[2], d = v[3];
        long e = v[4], f = v[5], g = v[6], h = v[7];
        for (int j = 0; j < 64; j++)
        {
            long ss1 = rotl(u32(rotl(a, 12) + e + rotl(Sm3.tConstant(j), j)), 7);
            long ss2 = u32(ss1 ^ rotl(a, 12));
            long tt1 = u32(Sm3.ff(j, a, b, c) + d + ss2 + wp[j]);
            long tt2 = u32(Sm3.gg(j, e, f, g) + h + ss1 + w[j]);
            long na = tt1;
            long nb = a;
            long nc = rotl(b, 9);
            long nd = c;
            long ne = Sm3.p0(tt2);
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
            Tracer.traceLoop("compress.round", new Object[]{
                "j", j, "W[j]", w[j], "W'[j]", wp[j]
            }, Calc.hex(new long[]{ a, b, c, d, e, f, g, h }), "compress", j + 1, 64, "compress");
        }
    }

    /**
     * 布尔函数与置换函数的本质：只由 与/或/非/异或/循环移位 构成，可被完全展开成表达式。
     *
     * <p>这里的符号（与 {@link Sm3} 的符号表同名同义）：
     * <pre>
     *   a, b, c    FF_j / GG_j 的三个 32-bit 输入字（测试里取 0xdeadbeef、0x12345678、0xcafebabe 当样本，
     *              实际压缩时它们是本轮的 (A,B,C) 或 (E,F,G)）
     *   j          轮号：0 和 15 落在"前 16 轮线性区"，16 和 63 落在"后 48 轮非线性区"—— 边界就是 j = 16
     *   ⊕ ∧ ¬ ∨    逐位异或 / 与 / 非 / 或；~a 是 long 取反，必须 &amp; M32 截回 32 位，否则高 32 位全是 1
     *   多数函数   (a∧b)∨(a∧c)∨(b∧c)：逐位取三数的"多数比特"，输入差 1 比特时输出可能差很多 —— 非线性来源
     *   选择函数   (a∧b)∨(¬a∧c)：逐位以 a 为开关选 b 或 c；SHA-256 的 Ch 与它同型
     *   线性 vs    异或是 GF(2) 上的加法（线性映射，差分一算就中），掺进与/或以后才有真正的非线性
     *   非线性     —— 这正是"前 16 轮线性、后 48 轮非线性"这个设计的含义
     *   x          P0/P1 的入参字；rotl(x, n) 是 32-bit 循环左移，n 只取低 5 位（n &amp; 31）
     *   bitCount   统计一个 32-bit 字里有几个 1，用来量化"1 个输入比特被扩散成了几个输出比特"
     * </pre>
     */
    @TraceExecution(value = "布尔函数分解为异或与循环移位", algorithm = "SM3", flow = "SM3-BOOL")
    @Test
    public void booleanFunctionsDecomposeToXorAndRotate()
    {
        long a = 0xdeadbeefL, b = 0x12345678L, c = 0xcafebabeL;
        Tracer.trace("start", new Object[]{"a", Calc.hex(new long[]{a}), "b", Calc.hex(new long[]{b}),
            "c", Calc.hex(new long[]{c})}, null, "start");
        // 前 16 轮 FF/GG 都是纯异或（线性）
        Assert.assertEquals(u32(a ^ b ^ c), Sm3.ff(0L, a, b, c));
        Assert.assertEquals(u32(a ^ b ^ c), Sm3.gg(15L, a, b, c));
        // 16 轮之后 FF 变成多数函数、GG 变成选择函数（引入非线性）
        Assert.assertEquals(u32((a & b) | (a & c) | (b & c)), Sm3.ff(16L, a, b, c));
        Assert.assertEquals(u32((a & b) | ((~a & M32) & c)), Sm3.gg(63L, a, b, c));
        Tracer.trace("ff", new Object[]{"j0", 0, "j16", 16, "a", Calc.hex(new long[]{a}),
            "b", Calc.hex(new long[]{b}), "c", Calc.hex(new long[]{c})},
            "FF(0)=" + Calc.hex(new long[]{Sm3.ff(0L, a, b, c)}) + " (期望 "
                + Calc.hex(new long[]{u32(a ^ b ^ c)}) + "); FF(16)="
                + Calc.hex(new long[]{Sm3.ff(16L, a, b, c)}) + " (期望 "
                + Calc.hex(new long[]{u32((a & b) | (a & c) | (b & c))}) + ")", "ff");
        Tracer.trace("gg", new Object[]{"j15", 15, "j63", 63, "a", Calc.hex(new long[]{a}),
            "b", Calc.hex(new long[]{b}), "c", Calc.hex(new long[]{c})},
            "GG(15)=" + Calc.hex(new long[]{Sm3.gg(15L, a, b, c)}) + " (期望 "
                + Calc.hex(new long[]{u32(a ^ b ^ c)}) + "); GG(63)="
                + Calc.hex(new long[]{Sm3.gg(63L, a, b, c)}) + " (期望 "
                + Calc.hex(new long[]{u32((a & b) | ((~a & M32) & c))}) + ")", "gg");
        // P0/P1 的"扩散"性质：单比特翻转，输出比特数远大于 1
        int flipped = Long.bitCount(Sm3.p0(1L)) + Long.bitCount(Sm3.p1(1L));
        Tracer.trace("p0p1", new Object[]{"x", 1, "P0", Calc.hex(new long[]{Sm3.p0(1L)}),
            "P1", Calc.hex(new long[]{Sm3.p1(1L)})},
            "P0 期望 " + Calc.hex(new long[]{u32(rotl(1L, 9) ^ rotl(1L, 17) ^ 1L)}) + "；P1 期望 "
                + Calc.hex(new long[]{u32(1L ^ rotl(1L, 15) ^ rotl(1L, 23))}) + "；扩散比特 " + flipped, "p0p1");
        log.info("[SM3-布尔函数] bitCount(P0(1)) + bitCount(P1(1)) = {}", flipped);
        Assert.assertTrue("P0/P1 必须把 1 个输入比特扩散到多个输出比特", flipped >= 6);
        Assert.assertNotEquals("P0 不是恒等映射", Long.valueOf(1L), Long.valueOf(Sm3.p0(1L)));
        // 轮常数只有两个值：j<16 用 0x79cc4519，j>=16 全部用 0x7a879d8a（64 步共用第二个）
        Assert.assertEquals(0x79cc4519L, Sm3.tConstant(0));
        Assert.assertEquals(0x7a879d8aL, Sm3.tConstant(16));
        Assert.assertEquals(Sm3.tConstant(16), Sm3.tConstant(63));
        Tracer.trace("tconst", new Object[]{"T(0)", Sm3.tConstant(0), "T(16)", Sm3.tConstant(16),
            "T(63)", Sm3.tConstant(63)},
            "j<16 → 0x79cc4519；j>=16 → 0x7a879d8a；rotl(T(16),32)=T(16)", "tconst");
        // 循环移位取 j 的低 5 位（n & 31）：所以 SS1 里 rotl(T_j, j) 在 j=32 时等于不旋转
        Assert.assertEquals(Sm3.tConstant(16), rotl(Sm3.tConstant(16), 32));
        // 最后一行是"P0 就是那三项异或"的逐项展开核对：rotl(1,9)、rotl(1,17) 与 1 本身异或，
        // 说明 P0 完全由移位+异或构成，没有任何查表或隐藏状态；1L 代表只有最低位为 1 的那个字
        Assert.assertEquals(u32(rotl(1L, 9) ^ rotl(1L, 17) ^ 1L), Sm3.p0(1L));
        Tracer.traceDecision("assert", new Object[]{"checks", 4, "failed", 0}, true, "assert",
            "FF/GG/P0/P1/T_j 的分解式与期望值全部一致");
        Tracer.trace("end", new Object[]{"passed", true}, null, "end");
    }
}
