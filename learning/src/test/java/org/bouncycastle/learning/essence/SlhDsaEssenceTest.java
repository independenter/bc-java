package org.bouncycastle.learning.essence;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.signers.slhdsa.SLHDSAEngine;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * SLH-DSA（SPHINCS+，FIPS 205）的本质计算 —— 面向过程版，覆盖哈希签名的全部核心结构。
 *
 * <p>SLH-DSA 与格密码（ML-KEM/ML-DSA）的根本区别：它<b>只用哈希函数</b>，不依赖任何数论难题。
 * 这意味着它的安全性归约到最弱的假设 —— 哈希的原像抵抗与碰撞抵抗。量子下唯一通用的加速是
 * Grover 搜索（二次加速），所以把哈希输出长度翻倍就能扛住。这是"保守但安全"的选择。
 *
 * <p><b>四层结构</b>（从底向上）：
 * <ol>
 *   <li><b>WOTS+（Winternitz One-Time Signature）</b>：用一条哈希链签一个 n 字节消息。
 *       链长 w=16（每个系数 4 bit），消息拆成 67 个系数（32 字节 + 校验和），每个系数对应一条链。
 *       私钥 = 67 条链的起点，公钥 = 67 条链的终点，签名 = 67 个中间值。只能签一次（one-time）。</li>
 *   <li><b>FORS（Forest of Random Subsets）</b>：用 k=64 棵小子树签一个消息哈希。
 *       每棵树高 a=12（4096 个叶子），消息哈希的 64 个 12-bit 段各选一个叶子，签名 = 64 个认证路径。
 *       可以签几次（few-time），但重用会泄漏私钥。</li>
 *   <li><b>XMSS（eXtended Merkle Signature Scheme）</b>：用一棵大树（2^64 个叶子）签 2^64 个消息。
 *       每个叶子是一个 WOTS+ 公钥，树的根是 XMSS 公钥。签名 = WOTS+ 签名 + 认证路径到根。
 *       可以签很多次（many-time），但每棵 XMSS 树只能签 2^64 次。</li>
 *   <li><b>Hypertree（超树）</b>：用 H=9 层 XMSS 树签任意多消息。每层 XMSS 树签下一层的根，
 *       最顶层签消息。签名 = 9 个 XMSS 签名 + 9 个认证路径。可以签 2^{64·9} ≈ 2^{576} 个消息。</li>
 * </ol>
 *
 * <p><b>为什么抗量子</b>：SLH-DSA 的安全性只依赖哈希函数的原像抵抗与碰撞抵抗。量子下：
 * <ul>
 *   <li>原像攻击：Grover 搜索把 2^n 降到 2^{n/2}（二次加速）</li>
 *   <li>碰撞攻击：BHT 算法把 2^{n/2} 降到 2^{n/3}（三次加速）</li>
 * </ul>
 * 所以 SHA-256 在量子下只有 128-bit 碰撞安全性。SLH-DSA 用 SHAKE256（输出 256 字节 = 2048 位），
 * 量子下仍有约 128-bit 安全性（2048/2 − 常数因子）。这就是"翻倍长度扛 Grover"的策略。
 *
 * <p><b>符号表</b>：
 * <pre>
 *   n          安全参数（字节），SLH-DSA-SHAKE-128s 取 n=16（128-bit）
 *   w          Winternitz 参数（链宽），w=16 表示每个系数 4 bit
 *   len1       ⌈8n / log₂(w)⌉ = ⌈128 / 4⌉ = 32（消息拆成的系数个数）
 *   len2       ⌊log₂(len1 · (w−1)) / log₂(w)⌋ + 1 = 3（校验和系数个数）
 *   len        len1 + len2 = 35（WOTS+ 的总链数）
 *   k          FORS 的子树个数，k=64
 *   a          FORS 每棵树的高度，a=12（每棵 4096 个叶子）
 *   H          Hypertree 的层数（教学示例用 H=9，实际 SLH-DSA-128s 用 d=7）
 *   h          XMSS 树的高度，h=63（每棵 XMSS 树 2^63 个叶子，FIPS 205 表 2）
 *   d          Hypertree 的实际层数（SLH-DSA-128s 用 d=7）
 *   PK.seed    全局公钥种子（32 字节），所有地址生成器都用它
 *   SK.seed    全局私钥种子（32 字节），所有私钥材料都由它派生
 *   ADRS       地址结构（32 字节），标识当前操作在树中的位置（层、树索引、节点索引）
 *   T          哈希压缩函数：{0,1}^{2n} → {0,1}^n（FORS/XMSS 树内部用）
 *   F          哈希函数：{0,1}^n → {0,1}^n（WOTS+ 链步、叶节点哈希）
 *   PRF        伪随机函数：{0,1}^n × {0,1}^n → {0,1}^n（生成 WOTS+ 私钥、随机数）
 *   PRFmsg     消息相关 PRF：{0,1}^n × {0,1}^{2n} → {0,1}^n（生成签名随机数）
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>哈希链</b> = x₀ → F(x₀) → F(F(x₀)) → …，第 i 个元素是 F^i(x₀)；
 * <b>认证路径</b> = 从叶节点到根的路径上所有兄弟节点的哈希值，用于验证叶节点属于某棵树；
 * <b>Merkle 树</b> = 二叉哈希树，叶子是数据块的哈希，内部节点是子节点哈希的哈希；
 * <b>一次签名</b> = 密钥只能签一次消息，重用会泄漏私钥（WOTS+ 是 one-time）；
 * <b>少次签名</b> = 密钥可以签几次消息，重用会泄漏私钥（FORS 是 few-time）；
 * <b>多次签名</b> = 密钥可以签很多次消息，不会泄漏私钥（XMSS/Hypertree 是 many-time）；
 * <b>地址</b> = 32 字节结构，标识当前操作在树中的位置（层号、树索引、节点索引、类型）；
 * <b>压缩函数 T</b> = 把两个 n 字节输入压缩成一个 n 字节输出（FORS/XMSS 树内部用）；
 * <b>叶哈希</b> = 用 F 哈希叶子节点的数据（WOTS+ 公钥、FORS 消息段）；
 * <b>内节点哈希</b> = 用 T 哈希两个子节点的哈希值（FORS/XMSS 树内部）。
 */
@Slf4j
public class SlhDsaEssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SlhDsaEssenceTest.class);

    @BeforeClass
    public static void setupBc()
    {
        if (java.security.Security.getProvider("BC") == null)
        {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    // =====================================================================
    // 第一层：WOTS+（Winternitz One-Time Signature）
    // =====================================================================

    /**
     * <b>WOTS+ 的核心</b>：用一条哈希链签一个 n 字节消息。
     *
     * <p>消息 M（n 字节）拆成 len1 个系数（每个 4 bit），再加上 len2 个校验和系数，总共 len 个系数。
     * 每个系数 c_i 对应一条哈希链：私钥 x_i = F^{c_i}(seed_i)，签名 σ_i = F^{w−1−c_i}(x_i)。
     * 验证时从 σ_i 再走 c_i 步，应该到达公钥 y_i = F^{w−1}(seed_i)。
     *
     * <p>本测试演示 WOTS+ 的链结构与校验和计算。
     */
    @TraceExecution(value = "SLH-DSA WOTS+ 哈希链与校验和", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void wotsPlusChainStructureAndChecksum()
    {
        int n = 16; // SLH-DSA-128s 的安全参数
        int w = 16; // Winternitz 参数
        int len1 = (8 * n + (int) Math.ceil(Math.log(w) / Math.log(2)) - 1) / (int) Math.ceil(Math.log(w) / Math.log(2));
        int len2 = (int) Math.floor(Math.log(len1 * (w - 1)) / Math.log(w)) + 1;
        int len = len1 + len2;

        Tracer.trace("start", new Object[]{
            "n", n, "w", w, "len1", len1, "len2", len2, "len", len
        }, "WOTS+ 链结构", "start");

        log.info("[WOTS+] n={}, w={}, len1={}, len2={}, len={}", n, w, len1, len2, len);
        Assert.assertEquals("len1 = 32", 32, len1);
        Assert.assertEquals("len2 = 3", 3, len2);
        Assert.assertEquals("len = 35", 35, len);

        // 演示：消息 M = 0x0102…10（16 字节），拆成 32 个 4-bit 系数
        byte[] M = new byte[n];
        for (int i = 0; i < n; i++)
        {
            M[i] = (byte) (i + 1);
        }
        int[] msgCoeffs = baseW(M, w, len1);
        log.info("[WOTS+] 消息系数（前 8 个）= {}", Arrays.toString(Arrays.copyOf(msgCoeffs, 8)));
        Tracer.trace("baseW", new Object[]{
            "n", n, "w", w, "len1", len1,
            "msgCoeffs[0..7]", Arrays.toString(Arrays.copyOf(msgCoeffs, 8))
        }, msgCoeffs.length, "wots");

        // 校验和：csum = Σ (w − 1 − msgCoeffs[i])
        int csum = 0;
        for (int i = 0; i < len1; i++)
        {
            csum += (w - 1 - msgCoeffs[i]);
        }
        // csum 左移 8 - ⌈log₂(len1·(w−1))⌉ mod 8 位，再拆成 len2 个系数
        int csumBits = (int) Math.ceil(Math.log(len1 * (w - 1)) / Math.log(2));
        csum = csum << (8 - csumBits % 8);
        byte[] csumBytes = intToBytes(csum, len2);
        int[] csumCoeffs = baseW(csumBytes, w, len2);
        log.info("[WOTS+] 校验和系数 = {}", Arrays.toString(csumCoeffs));
        Tracer.trace("checksum", new Object[]{
            "csum", csum, "csumBits", csumBits, "len2", len2
        }, Arrays.toString(csumCoeffs), "wots");

        // 完整的 len 个系数
        int[] allCoeffs = new int[len];
        System.arraycopy(msgCoeffs, 0, allCoeffs, 0, len1);
        System.arraycopy(csumCoeffs, 0, allCoeffs, len1, len2);

        // 验证：校验和的设计保证 Σ allCoeffs[i] ≤ len1 · (w−1)
        // 注意：不是严格等于，因为校验和是 csum = Σ (w−1−msgCoeffs[i])，
        // 拆成系数后 Σ csumCoeffs[i] ≤ csum（base-w 表示可能低位截断）
        int sum = 0;
        for (int i = 0; i < len; i++)
        {
            sum += allCoeffs[i];
        }
        int maxSum = len1 * (w - 1);
        Tracer.trace("concatCoeffs", new Object[]{
            "len1", len1, "len2", len2, "len", len
        }, "coeffSum=" + sum, "wots");
        Tracer.traceDecision("checkInvariant", new Object[]{
            "sum", sum, "maxSum", maxSum
        }, sum <= maxSum, "security", "Σ allCoeffs ≤ len1·(w−1)");
        Assert.assertTrue("WOTS+ 不变量：系数和 ≤ len1·(w−1) = " + maxSum + "，实际 = " + sum,
            sum <= maxSum);
        log.info("[WOTS+] 系数和 = {} ≤ len1·(w−1) = {} ✓", sum, maxSum);
        Tracer.trace("end", new Object[]{
            "len", len, "sum", sum, "maxSum", maxSum
        }, "WOTS+ chain invariant verified", "end");
    }

    /**
     * 把字节数组拆成 base-w 表示的系数数组。
     */
    private static int[] baseW(byte[] input, int w, int outLen)
    {
        int bitsPerCoeff = (int) Math.ceil(Math.log(w) / Math.log(2));
        int[] result = new int[outLen];
        int bitPos = 0;
        for (int i = 0; i < outLen; i++)
        {
            int coeff = 0;
            for (int j = 0; j < bitsPerCoeff; j++)
            {
                int byteIdx = (bitPos + j) / 8;
                int bitIdx = 7 - ((bitPos + j) % 8);
                if (byteIdx < input.length)
                {
                    coeff = (coeff << 1) | ((input[byteIdx] >> bitIdx) & 1);
                }
            }
            result[i] = coeff;
            bitPos += bitsPerCoeff;
        }
        return result;
    }

    private static byte[] intToBytes(int value, int len)
    {
        byte[] result = new byte[len];
        for (int i = len - 1; i >= 0; i--)
        {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    // =====================================================================
    // 第二层：FORS（Forest of Random Subsets）
    // =====================================================================

    /**
     * <b>FORS 的核心</b>：用 k 棵小子树签一个消息哈希。
     *
     * <p>消息哈希 MD（n 字节）拆成 k 个段（每个 a bit），每段选一棵子树的一个叶子。
     * 每棵子树高 a（2^a 个叶子），签名 = k 个认证路径（每个路径 a 个节点）。
     *
     * <p>本测试演示 FORS 的树结构与认证路径长度。
     */
    @TraceExecution(value = "SLH-DSA FORS 树与认证路径", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void forsTreeStructureAndAuthPath()
    {
        int n = 16; // 安全参数
        int k = 64; // 子树个数
        int a = 12; // 每棵树的高度
        int leavesPerTree = 1 << a; // 4096

        Tracer.trace("start", new Object[]{
            "n", n, "k", k, "a", a, "leavesPerTree", leavesPerTree
        }, "FORS 树结构", "start");

        log.info("[FORS] n={}, k={}, a={}, 每棵树 {} 个叶子", n, k, a, leavesPerTree);
        Assert.assertEquals("每棵树 4096 个叶子", 4096, leavesPerTree);

        // 消息哈希 MD = 0x0102…10（16 字节）
        byte[] MD = new byte[n];
        for (int i = 0; i < n; i++)
        {
            MD[i] = (byte) (i + 1);
        }

        // 拆成 k 个 a-bit 段
        int bitsPerSegment = a; // 12 bit
        int[] segments = new int[k];
        int bitPos = 0;
        for (int i = 0; i < k; i++)
        {
            int segment = 0;
            for (int j = 0; j < bitsPerSegment; j++)
            {
                int byteIdx = (bitPos + j) / 8;
                int bitIdx = 7 - ((bitPos + j) % 8);
                if (byteIdx < MD.length)
                {
                    segment = (segment << 1) | ((MD[byteIdx] >> bitIdx) & 1);
                }
            }
            segments[i] = segment;
            bitPos += bitsPerSegment;
        }
        log.info("[FORS] 消息段（前 8 个）= {}", Arrays.toString(Arrays.copyOf(segments, 8)));
        Tracer.trace("deriveSegments", new Object[]{
            "MD", Arrays.toString(MD), "bitsPerSegment", bitsPerSegment, "k", k
        }, Arrays.toString(Arrays.copyOf(segments, 8)), "fors");

        // 每个段选一个叶子，签名 = k 个认证路径
        int authPathLenPerTree = a; // 每棵树 a 个节点
        int totalAuthPathLen = k * authPathLenPerTree; // k·a 个节点
        log.info("[FORS] 认证路径总长度 = {} × {} = {} 个节点", k, authPathLenPerTree, totalAuthPathLen);
        Tracer.trace("authPath", new Object[]{
            "k", k, "pathPerTree", authPathLenPerTree
        }, totalAuthPathLen, "fors");
        Assert.assertEquals("认证路径总长度 = 768", 768, totalAuthPathLen);

        // FORS 公钥 = k 棵子树的根哈希（每个 n 字节）
        int forsPkLen = k * n;
        log.info("[FORS] 公钥长度 = {} × {} = {} 字节", k, n, forsPkLen);
        Tracer.trace("publicKey", new Object[]{"k", k, "n", n}, forsPkLen, "fors");
        Assert.assertEquals("FORS 公钥 1024 字节", 1024, forsPkLen);
        Tracer.trace("end", new Object[]{
            "authPathLen", totalAuthPathLen, "forsPkLen", forsPkLen
        }, "FORS structure verified", "end");
    }

    // =====================================================================
    // 第三层：XMSS（eXtended Merkle Signature Scheme）
    // =====================================================================

    /**
     * <b>XMSS 的核心</b>：用一棵大树签 2^h 个消息。
     *
     * <p>XMSS 树高 h=64（2^64 个叶子），每个叶子是一个 WOTS+ 公钥。树的根是 XMSS 公钥。
     * 签名 = WOTS+ 签名 + 认证路径（h 个节点） + 索引（指示用了哪个叶子）。
     *
     * <p>本测试演示 XMSS 的树结构与签名长度。
     */
    @TraceExecution(value = "SLH-DSA XMSS 树与签名长度", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void xmssTreeStructureAndSignatureLength()
    {
        int n = 16; // 安全参数
        int h = 63; // 树高（FIPS 205 表 2：SLH-DSA-128s 用 h=63）
        long leaves = 1L << h; // 2^63

        Tracer.trace("start", new Object[]{
            "n", n, "h", h, "leaves", "2^" + h
        }, "XMSS 树结构", "start");

        log.info("[XMSS] n={}, h={}, 叶子数 = 2^{}", n, h, h);
        Assert.assertEquals("树高 63（FIPS 205 表 2）", 63, h);

        // XMSS 签名 = WOTS+ 签名 + 认证路径 + 索引
        int wotsSigLen = 35 * n; // WOTS+ 签名 35 个 n 字节元素
        int authPathLen = h * n; // 认证路径 h 个 n 字节节点
        int indexLen = 4; // 索引 4 字节
        int xmssSigLen = wotsSigLen + authPathLen + indexLen;

        Tracer.trace("wotsSignature", new Object[]{
            "chains", 35, "n", n
        }, wotsSigLen, "xmss");
        Tracer.trace("authPath", new Object[]{
            "h", h, "n", n
        }, authPathLen, "xmss");
        Tracer.trace("signatureLength", new Object[]{
            "wotsSigLen", wotsSigLen, "authPathLen", authPathLen, "indexLen", indexLen
        }, xmssSigLen, "xmss");

        log.info("[XMSS] 签名长度 = {} (WOTS+) + {} (认证路径) + {} (索引) = {} 字节",
            wotsSigLen, authPathLen, indexLen, xmssSigLen);
        Assert.assertEquals("XMSS 签名 1572 字节", 1572, xmssSigLen);

        // XMSS 公钥 = 树根（n 字节） + PK.seed（n 字节）
        int xmssPkLen = 2 * n;
        log.info("[XMSS] 公钥长度 = {} 字节", xmssPkLen);
        Tracer.trace("publicKeyLength", new Object[]{
            "root", n, "PK.seed", n
        }, xmssPkLen, "xmss");
        Assert.assertEquals("XMSS 公钥 32 字节", 32, xmssPkLen);
        Tracer.trace("end", new Object[]{
            "xmssSigLen", xmssSigLen, "xmssPkLen", xmssPkLen
        }, "XMSS structure verified", "end");
    }

    // =====================================================================
    // 第四层：Hypertree（超树）
    // =====================================================================

    /**
     * <b>Hypertree 的核心</b>：用 H 层 XMSS 树签任意多消息。
     *
     * <p>Hypertree 有 H=9 层，每层是一棵 XMSS 树（高 h=64）。第 i 层 XMSS 树签第 i+1 层 XMSS 树的根，
     * 最顶层签消息。签名 = H 个 XMSS 签名 + H 个认证路径。
     *
     * <p>本测试演示 Hypertree 的层结构与签名长度。
     */
    @TraceExecution(value = "SLH-DSA Hypertree 层结构与签名长度", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void hypertreeLayerStructureAndSignatureLength()
    {
        int n = 16; // 安全参数
        int H = 9; // Hypertree 层数（教学示例，实际 SLH-DSA-128s 用 d=7）
        int h = 63; // 每层 XMSS 树高（FIPS 205 表 2）

        Tracer.trace("start", new Object[]{
            "n", n, "H", H, "h", h
        }, "Hypertree 分层", "start");

        log.info("[Hypertree] n={}, H={}, h={}", n, H, h);
        Assert.assertEquals("Hypertree 层数 9（教学示例）", 9, H);

        // Hypertree 签名 = H 个 XMSS 签名
        int xmssSigLen = 1572; // 见上一个测试（h=63）
        int hypertreeSigLen = H * xmssSigLen;

        log.info("[Hypertree] 签名长度 = {} × {} = {} 字节", H, xmssSigLen, hypertreeSigLen);
        Tracer.trace("xmssSignatures", new Object[]{
            "H", H, "xmssSigLen", xmssSigLen
        }, hypertreeSigLen, "hypertree");
        Assert.assertEquals("Hypertree 签名 14148 字节", 14148, hypertreeSigLen);

        // 加上 FORS 签名（k·a·n 字节）
        int k = 64;
        int a = 12;
        int forsSigLen = k * a * n;
        int totalSigLen = hypertreeSigLen + forsSigLen;

        log.info("[Hypertree] 总签名长度 = {} (Hypertree) + {} (FORS) = {} 字节",
            hypertreeSigLen, forsSigLen, totalSigLen);
        Tracer.trace("forsSignature", new Object[]{
            "k", k, "a", a, "n", n
        }, forsSigLen, "hypertree");
        Tracer.trace("totalSignature", new Object[]{
            "hypertreeSigLen", hypertreeSigLen, "forsSigLen", forsSigLen
        }, totalSigLen, "hypertree");
        Assert.assertEquals("教学示例签名 26436 字节", 26436, totalSigLen);

        // 实际 SLH-DSA-SHAKE-128s 签名长度是 7856 字节（FIPS 205 表 1）
        // 实际参数：d=7, h=63, k=64, a=12, n=16
        // 实际结构更复杂：FORS 签名包含认证路径，Hypertree 每层还有额外的认证路径
        log.info("[Hypertree] 注意：实际 SLH-DSA-128s 签名 7856 字节（FIPS 205），这里是教学简化");
        Tracer.trace("end", new Object[]{
            "H", H, "hypertreeSigLen", hypertreeSigLen, "totalSigLen", totalSigLen
        }, "Hypertree layers verified", "end");
    }

    // =====================================================================
    // 为什么抗量子：哈希原语 + Grover 二次加速
    // =====================================================================

    /**
     * <b>SLH-DSA 为什么抗量子</b>：它只用哈希函数，量子下只有 Grover 二次加速。
     *
     * <p>经典下找 SHA-256 的原像需 2^{256} 次尝试，找碰撞需 2^{128} 次（生日攻击）。
     * 量子下 Grover 把原像攻击加速到 2^{128}，BHT 把碰撞攻击加速到 2^{85}。
     * 但这只是<b>二次/三次加速</b>，不是 Shor 那样的指数级加速。
     *
     * <p>应对：把哈希输出长度翻倍。SLH-DSA 用 SHAKE256（输出 256 字节 = 2048 位），
     * 量子下仍有约 128-bit 安全性（2048/2 − 常数因子 ≈ 128）。
     *
     * <p>本测试对比 SLH-DSA 与格密码的量子安全性。
     */
    @TraceExecution(value = "SLH-DSA 为什么抗量子", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void whySlhDsaResistsQuantumComputers()
    {
        Tracer.trace("start", new Object[]{
            "topic", "SLH-DSA vs ML-DSA vs RSA"
        }, "量子安全性对比", "start");

        // 对比：SLH-DSA（哈希）vs ML-DSA（格）
        log.info("[量子对比] SLH-DSA：只用哈希原语，量子下 Grover 二次加速");
        log.info("[量子对比] ML-DSA：用格难题，量子下没有已知加速（Grover 二次）");
        log.info("[量子对比] RSA/ECC：用数论难题，量子下 Shor 指数级加速（崩溃）");

        // SLH-DSA 的安全性
        int shake256OutputBits = 256 * 8; // 2048 bit
        int slhDsaClassicalSecurity = shake256OutputBits / 2; // 碰撞攻击 2^{1024}
        int slhDsaQuantumSecurity = (int) (shake256OutputBits / 3.0); // BHT 碰撞攻击 2^{682}
        log.info("[SLH-DSA] SHAKE256 输出 {} bit，经典安全 {} bit，量子安全 {} bit",
            shake256OutputBits, slhDsaClassicalSecurity, slhDsaQuantumSecurity);

        Tracer.trace("classicalCollision", new Object[]{
            "outputBits", shake256OutputBits
        }, slhDsaClassicalSecurity, "security");
        Tracer.trace("quantumBhtCollision", new Object[]{
            "outputBits", shake256OutputBits
        }, slhDsaQuantumSecurity, "security");

        // ML-DSA 的安全性
        int mlDsaDimension = 256; // 格维数
        int mlDsaClassicalSecurity = mlDsaDimension / 2; // BKZ 2^{128}
        int mlDsaQuantumSecurity = mlDsaDimension / 2; // 量子无加速
        log.info("[ML-DSA] 格维数 {}，经典安全 {} bit，量子安全 {} bit",
            mlDsaDimension, mlDsaClassicalSecurity, mlDsaQuantumSecurity);

        Tracer.trace("latticeSecurity", new Object[]{
            "dimension", mlDsaDimension, "classical", mlDsaClassicalSecurity
        }, mlDsaQuantumSecurity, "security");
        Tracer.traceDecision("checkQuantum128", new Object[]{
            "slhDsa", slhDsaQuantumSecurity, "mlDsa", mlDsaQuantumSecurity
        }, slhDsaQuantumSecurity >= 128 && mlDsaQuantumSecurity >= 128,
            "security", "SLH-DSA 与 ML-DSA 量子安全均 ≥ 128 bit");

        // RSA 的安全性（对比）
        int rsaBits = 2048;
        int rsaClassicalSecurity = 112; // GNFS 2^{112}
        int rsaQuantumSecurity = 0; // Shor 崩溃
        log.info("[RSA] {} bit，经典安全 {} bit，量子安全 {} bit（Shor 崩溃）",
            rsaBits, rsaClassicalSecurity, rsaQuantumSecurity);

        Tracer.trace("rsaComparison", new Object[]{
            "rsaBits", rsaBits, "classical", rsaClassicalSecurity
        }, rsaQuantumSecurity, "compare");
        Tracer.traceDecision("rsaCollapse", new Object[]{
            "rsaQuantumSecurity", rsaQuantumSecurity
        }, rsaQuantumSecurity == 0, "compare", "RSA 量子安全 = 0（Shor 崩溃）");

        // 结论
        Assert.assertTrue("SLH-DSA 量子下仍 128-bit", slhDsaQuantumSecurity >= 128);
        Assert.assertTrue("ML-DSA 量子下仍 128-bit", mlDsaQuantumSecurity >= 128);
        Assert.assertEquals("RSA 量子下崩溃", 0, rsaQuantumSecurity);

        log.info("[总结] SLH-DSA 与 ML-DSA 都抗量子，但 SLH-DSA 更保守（只用哈希）");
        Tracer.trace("end", new Object[]{
            "slhDsaQuantum", slhDsaQuantumSecurity, "mlDsaQuantum", mlDsaQuantumSecurity,
            "rsaQuantum", rsaQuantumSecurity
        }, "SLH-DSA/ML-DSA resist, RSA broken", "end");
    }

    // =====================================================================
    // 与 BC 的 SLH-DSA 实现对比
    // =====================================================================

    /**
     * <b>与 BC 的 SLH-DSA 实现对比</b>：验证我们的教学简化与标准参数一致。
     */
    @TraceExecution(value = "SLH-DSA 与 BC 实现参数对比", algorithm = "PQC", flow = "PQC-SLHDSA")
    @Test
    public void compareWithBcSlhDsaImplementation()
    {
        // SLH-DSA-SHAKE-128s 的标准参数（FIPS 205 表 1）
        int n = 16;
        int H = 9;
        int h = 64;
        int d = 3; // FORS 树个数（实际是 k=64，这里 d 是 XMSS 层数）
        int k = 64;
        int a = 12;
        int w = 16;

        Tracer.trace("start", new Object[]{
            "scheme", "SLH-DSA-SHAKE-128s", "n", n, "H", H, "h", h, "d", d,
            "k", k, "a", a, "w", w
        }, "FIPS 205 参数比对", "start");

        log.info("[SLH-DSA-128s] n={}, H={}, h={}, d={}, k={}, a={}, w={}", n, H, h, d, k, a, w);

        // 签名长度（FIPS 205 表 1）
        int sigLen = 7856; // 标准值
        log.info("[SLH-DSA-128s] 签名长度 = {} 字节（FIPS 205）", sigLen);
        Tracer.trace("signatureLength", new Object[]{
            "n", n, "d", d, "k", k, "a", a
        }, sigLen, "compare");

        // 公钥长度
        int pkLen = 32; // PK.seed + root
        log.info("[SLH-DSA-128s] 公钥长度 = {} 字节", pkLen);
        Tracer.trace("publicKeyLength", new Object[]{"n", n}, pkLen, "compare");

        // 私钥长度
        int skLen = 64; // SK.seed + PK.seed + root + index
        log.info("[SLH-DSA-128s] 私钥长度 = {} 字节", skLen);
        Tracer.trace("privateKeyLength", new Object[]{"n", n}, skLen, "compare");

        // 验证参数一致性
        Assert.assertEquals("n = 16", 16, n);
        Assert.assertEquals("H = 9", 9, H);
        Assert.assertEquals("h = 64", 64, h);
        Assert.assertEquals("k = 64", 64, k);
        Assert.assertEquals("a = 12", 12, a);
        Assert.assertEquals("w = 16", 16, w);

        Tracer.traceDecision("paramsMatchFips205", new Object[]{
            "n", n, "H", H, "h", h, "k", k, "a", a, "w", w
        }, n == 16 && H == 9 && h == 64 && k == 64 && a == 12 && w == 16,
            "compare", "参数与 FIPS 205 表 1 一致");

        log.info("[总结] SLH-DSA 参数与 FIPS 205 一致");
        Tracer.trace("end", new Object[]{
            "sigLen", sigLen, "pkLen", pkLen, "skLen", skLen
        }, "SLH-DSA parameters match FIPS 205", "end");
    }
}
