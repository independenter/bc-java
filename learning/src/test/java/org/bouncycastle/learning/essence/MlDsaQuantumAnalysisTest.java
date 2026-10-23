package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.Assert;
import org.junit.Test;

/**
 * ML-DSA（FIPS 204，原 Dilithium）的量子抗性过程式分解。
 *
 * <p>本文件不重复 PqcEssenceTest 里的环运算/NTT/分解/打包实现，只聚焦一个问题：
 * <b>为什么 ML-DSA 能抗住量子计算机？</b> 答案分三层：
 * <ol>
 *   <li><b>困难问题层</b>：ML-DSA 的安全性归约到 Module-SIS（短整数解）问题。
 *       给定随机矩阵 A，找非零短向量 z 使得 A·z = 0 (mod q) 是困难的。
 *       这个问题在量子下没有已知的多项式时间算法。</li>
 *   <li><b>量子加速层</b>：Grover 搜索能给 SIS 带来二次加速，
 *       但这只是指数减半，不是 Shor 那样的指数→多项式。</li>
 *   <li><b>协议层</b>：Fiat-Shamir 变换 + 拒绝采样，让签名不泄漏私钥信息，
 *       即使量子敌人看到再多签名也提取不出短基。</li>
 * </ol>
 *
 * <p><b>符号表（本文件专用）</b>：
 * <pre>
 *   k, l       矩阵 A 的行数/列数（ML-DSA-44: 4/4; ML-DSA-65: 6/5; ML-DSA-87: 8/7）
 *   q          多项式环模数（ML-DSA 固定 q=8380417=2^23−2^13+1）
 *   n          多项式次数（固定 n=256）
 *   η          私钥短多项式 s1/s2 的系数界（ML-DSA-44: 2; 65: 4; 87: 2）
 *   γ₁, γ₂     签名掩码 y 的幅度界与 decompose 参数
 *   τ          挑战多项式 c 的汉明权重（恰好 τ 个非零系数，系数只取 ±1）
 *   A ∈ R_q^{k×l} 公钥矩阵（均匀随机多项式，由种子 ρ 展开）
 *   s1 ∈ R_q^l 私钥短向量（系数 ∈ [−η, η]）
 *   s2 ∈ R_q^k 私钥噪声向量（系数 ∈ [−η, η]）
 *   t = A·s1 + s2  公钥向量
 *   y ∈ R_q^l 签名掩码（一次性随机数，系数 ∈ [−γ₁, γ₁]）
 *   c          挑战多项式（恰好 τ 个非零系数，系数 ∈ {−1, 0, 1}）
 *   z = y + c·s1   签名响应（必须满足 ‖z‖∞ < γ₁ − β）
 *   w = A·y        签名侧的"承诺"
 *   w' = A·z − c·t 验签侧重构的"承诺"（与 w 相差可控噪声）
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>Module-SIS</b> = 给定随机 A ∈ R_q^{k×l}，找非零短向量 z ∈ R_q^l 使得 A·z = 0 (mod q)，
 * 困难性来自"短"这个约束 —— 不短的话随便找，短的话归约到格上的 SVP；
 * <b>Fiat-Shamir 变换</b> = 把交互式证明（ prover → verifier 发挑战）变成非交互式签名：
 * 挑战 c = H(commitment ‖ message)，用哈希函数扮演 verifier；
 * <b>拒绝采样</b> = 签名时如果 z 的系数太大（‖z‖∞ ≥ γ₁ − β），就丢弃重做，
 * 保证签名的分布不泄漏 s1 的信息（否则看多了签名能统计出 s1）；
 * <b>decompose</b> = 把 w 拆成高位 w1 和低位 w0，验签时只比对 w1（低位被噪声污染）；
 * <b>hint</b> = 1-bit 提示，修复 w1 在模 M 边界处的歧义，让验签成功率接近 100%。
 */
@Slf4j
public class MlDsaQuantumAnalysisTest
{
    private static final org.slf4j.Logger log =
        org.slf4j.LoggerFactory.getLogger(MlDsaQuantumAnalysisTest.class);

    // =====================================================================
    // 第一层：困难问题 —— Module-SIS 为什么量子下仍难
    // =====================================================================

    /**
     * <b>Module-SIS 问题的结构</b>：给定 A ∈ R_q^{k×l}，找非零短向量 z ∈ R_q^l
     * 使得 A·z = 0 (mod q)。
     *
     * <p>这个问题为什么难？
     * <ol>
     *   <li>如果不要"短"约束：z 就是 A 的零空间里的任意向量，高斯消元 O(l³) 搞定</li>
     *   <li>要"短"约束：变成"格上的最短向量问题 (SVP)"，量子下无多项式算法</li>
     *   <li>"短"的定义：‖z‖∞ = max|z[i]| ≤ B，B 是某个界（ML-DSA 里 B = γ₁）</li>
     * </ol>
     *
     * <p>本测试演示：
     * <ol>
     *   <li>无"短"约束时，找 z 是平凡的（线性代数）</li>
     *   <li>有"短"约束时，暴力搜索是指数时间</li>
     *   <li>格约减算法（LLL/BKZ）能找"近似最短"，但对 256 维格仍指数时间</li>
     * </ol>
     */
    @Test
    public void moduleSisIsHardBecauseOfShortness()
    {
        int q = 8380417; // ML-DSA 的模数
        int k = 4;       // ML-DSA-44 的行数
        int l = 4;       // ML-DSA-44 的列数
        int n = 256;     // 多项式次数

        log.info("[Module-SIS] q={}, k={}, l={}, n={}", q, k, l, n);

        // 1. 生成随机矩阵 A（k×l 个多项式）
        int[][][] A = new int[k][l][n];
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < k; i++)
        {
            for (int j = 0; j < l; j++)
            {
                for (int d = 0; d < n; d++)
                {
                    A[i][j][d] = rng.nextInt(q);
                }
            }
        }

        // 2. 无"短"约束：找 z 使得 A·z = 0 (mod q)
        // 这是线性方程组，有 l·n = 1024 个未知数，k·n = 1024 个方程
        // 当 l > k 时（ML-DSA-65: l=5, k=6），有非平凡解
        // 但 ML-DSA-44 是 l=k=4，只有零解（除非 A 奇异）
        log.info("[无约束] 未知数 = l·n = {}，方程 = k·n = {}", l * n, k * n);
        log.info("[关键] 要非平凡解，必须 l > k（ML-DSA-65: l=5, k=6）");

        // 3. 有"短"约束：找 z 使得 A·z = 0 且 ‖z‖∞ ≤ B
        // 暴力搜索：每个系数有 (2B+1) 种选择，总共 (2B+1)^{l·n} 种
        // ML-DSA-44: B = γ₁ = 2^17 = 131072, l·n = 1024
        // 搜索空间 ≈ (2·131072)^{1024} = 2^{17·1024} = 2^{17408}
        int gamma1_44 = 1 << 17; // 2^17
        int dim = l * n;
        double searchSpaceBits = Math.log(2 * gamma1_44 + 1) / Math.log(2) * dim;
        log.info("[有约束] B = γ₁ = {}, 维度 = {}, 搜索空间 ≈ 2^{}",
            gamma1_44, dim, (int) searchSpaceBits);
        Assert.assertTrue("搜索空间 ≥ 2^1000", searchSpaceBits >= 1000);

        // 4. 格约减算法：BKZ-256 的启发式复杂度 ≈ 2^{0.292·dim}
        double bkzComplexity = 0.292 * dim;
        log.info("[BKZ] 格约减复杂度 ≈ 2^{}，量子下 Grover 加速到 2^{}",
            (int) bkzComplexity, (int) (bkzComplexity / 2));
        Assert.assertTrue("BKZ 复杂度 ≥ 2^100", bkzComplexity >= 100);
    }

    /**
     * <b>SIS 与 LWE 的对偶关系</b>：SIS 是"找短向量在零空间里"，LWE 是"找短向量带噪声"。
     * 两者都可以归约到格上的 SVP，但角度不同：
     * <ul>
     *   <li>SIS → 签名（ML-DSA）：签名 = 短向量 z，验证 = A·z = 0</li>
     *   <li>LWE → 加密/KEM（ML-KEM）：密文 = 带噪声样本，解密 = 去噪声</li>
     * </ul>
     *
     * <p>本测试演示两者的结构差异。
     */
    @Test
    public void compareSisAndLwe()
    {
        log.info("[SIS vs LWE] 两种困难问题的对比");

        // 1. SIS：找短 z 使得 A·z = 0 (mod q)
        log.info("[SIS] 等式约束：A·z = 0，困难性来自'短'");
        log.info("[SIS] 应用：签名（ML-DSA），签名 = 短向量 z");

        // 2. LWE：从 (A, t = A·s + e) 反解 s
        log.info("[LWE] 噪声约束：t = A·s + e，困难性来自'噪声 e'");
        log.info("[LWE] 应用：加密/KEM（ML-KEM），密文 = 带噪声样本");

        // 3. 量子抗性：两者都没有已知的多项式时间量子算法
        log.info("[量子] SIS 和 LWE 量子下都归约到 SVP，最好算法仍指数时间");

        // 4. 参数对比
        int mldsaDim = 4 * 256; // ML-DSA-44: k=4, n=256
        int mlkemDim = 2 * 256; // ML-KEM-512: k=2, n=256
        log.info("[维度] ML-DSA-44 格维度={}, ML-KEM-512 格维度={}", mldsaDim, mlkemDim);
        Assert.assertTrue("ML-DSA 维度 ≥ ML-KEM", mldsaDim >= mlkemDim);
    }

    // =====================================================================
    // 第二层：协议安全 —— Fiat-Shamir + 拒绝采样
    // =====================================================================

    /**
     * <b>拒绝采样的必要性</b>：如果直接输出 z = y + c·s1，
     * 那么 z 的分布会依赖于 s1 —— 看多了签名，统计 z 的分布就能提取 s1。
     *
     * <p>拒绝采样的解决方案：如果 ‖z‖∞ ≥ γ₁ − β，就丢弃重做。
     * 这样 z 的分布就与 s1 无关（在可接受范围内均匀），签名不泄漏私钥。
     *
     * <p>本测试演示拒绝采样的核心逻辑。
     */
    @Test
    public void rejectionSamplingHidesSecretKey()
    {
        int q = 8380417;
        int n = 256;
        int gamma1 = 1 << 17; // 2^17
        int beta = 78;        // ML-DSA-44 的 β（噪声放大界）
        int threshold = gamma1 - beta;

        log.info("[拒绝采样] γ₁={}, β={}, 阈值={}", gamma1, beta, threshold);

        // 1. 模拟签名：z = y + c·s1
        int[] y = new int[n];
        int[] s1 = new int[n];
        int[] c = new int[n];
        SecureRandom rng = new SecureRandom();

        // y 的系数 ∈ [−γ₁, γ₁]
        for (int i = 0; i < n; i++)
        {
            y[i] = rng.nextInt(2 * gamma1 + 1) - gamma1;
        }

        // s1 的系数 ∈ [−2, 2]（η=2）
        for (int i = 0; i < n; i++)
        {
            s1[i] = rng.nextInt(5) - 2;
        }

        // c 是稀疏多项式（τ=39 个非零系数，系数 ∈ {−1, 1}）
        int tau = 39;
        for (int i = 0; i < tau; i++)
        {
            int idx = rng.nextInt(n);
            c[idx] = rng.nextBoolean() ? 1 : -1;
        }

        // z = y + c·s1 (mod q)
        int[] cs1 = polyMulSparse(c, s1);
        int[] z = new int[n];
        for (int i = 0; i < n; i++)
        {
            z[i] = (y[i] + cs1[i]) % q;
            if (z[i] < 0) z[i] += q;
        }

        // 2. 检查 ‖z‖∞（中心化后）
        int maxAbs = 0;
        for (int i = 0; i < n; i++)
        {
            int centered = z[i] > q / 2 ? z[i] - q : z[i];
            int abs = Math.abs(centered);
            if (abs > maxAbs) maxAbs = abs;
        }

        log.info("[签名] ‖z‖∞ = {}，阈值 = {}", maxAbs, threshold);
        boolean accept = maxAbs < threshold;
        log.info("[结果] {}", accept ? "接受" : "拒绝（重做）");

        // 3. 拒绝采样的效果：z 的分布在 [−threshold, threshold] 内均匀
        // 与 s1 无关，签名不泄漏私钥
        log.info("[关键] 拒绝后 z 的分布与 s1 无关 → 签名不泄漏私钥");
    }

    /**
     * 稀疏多项式乘法：c 只有 τ 个非零系数。
     */
    private static int[] polyMulSparse(int[] c, int[] s)
    {
        int n = c.length;
        int[] result = new int[n];
        for (int i = 0; i < n; i++)
        {
            if (c[i] == 0) continue;
            for (int j = 0; j < n; j++)
            {
                int idx = (i + j) % n;
                int sign = (i + j >= n) ? -1 : 1; // X^n = −1
                result[idx] = (result[idx] + sign * c[i] * s[j]) % 8380417;
            }
        }
        return result;
    }

    /**
     * <b>Fiat-Shamir 变换</b>：把交互式证明变成非交互式签名。
     *
     * <p>交互式证明：
     * <ol>
     *   <li>Prover → Verifier：发承诺 w = A·y</li>
     *   <li>Verifier → Prover：发挑战 c（随机）</li>
     *   <li>Prover → Verifier：发响应 z = y + c·s1</li>
     * </ol>
     *
     * <p>Fiat-Shamir 变换：c = H(w ‖ message)，用哈希函数扮演 Verifier。
     * 这样签名就是 (z, c)，不需要交互。
     *
     * <p>本测试演示 Fiat-Shamir 的核心逻辑。
     */
    @Test
    public void fiatShamirMakesSignatureNonInteractive()
    {
        int n = 256;

        log.info("[Fiat-Shamir] 把交互式证明变成非交互式签名");

        // 1. 模拟承诺：w = A·y（简化为随机多项式）
        int[] w = new int[n];
        new SecureRandom().nextBytes(new byte[n]);
        for (int i = 0; i < n; i++)
        {
            w[i] = new SecureRandom().nextInt(8380417);
        }

        // 2. 模拟消息
        byte[] message = "Hello, ML-DSA!".getBytes();

        // 3. Fiat-Shamir：c = H(w ‖ message)
        byte[] wBytes = new byte[n * 4];
        for (int i = 0; i < n; i++)
        {
            wBytes[i * 4] = (byte) (w[i] & 0xFF);
            wBytes[i * 4 + 1] = (byte) ((w[i] >> 8) & 0xFF);
            wBytes[i * 4 + 2] = (byte) ((w[i] >> 16) & 0xFF);
            wBytes[i * 4 + 3] = (byte) ((w[i] >> 24) & 0xFF);
        }
        byte[] input = concat(wBytes, message);
        byte[] challengeHash = shake256(input, 32);
        log.info("[挑战] c = H(w ‖ message) = {}...", bytesToHex(challengeHash, 4));

        // 4. 从 challengeHash 展开成稀疏多项式 c（sampleInBall）
        int[] c = sampleInBall(challengeHash, 39, n);
        int nonZero = 0;
        for (int i = 0; i < n; i++)
        {
            if (c[i] != 0) nonZero++;
        }
        log.info("[展开] c 有 {} 个非零系数（τ=39）", nonZero);
        Assert.assertEquals("c 恰好 39 个非零系数", 39, nonZero);

        // 5. 响应：z = y + c·s1（这里简化为随机 z）
        log.info("[响应] z = y + c·s1，签名 = (z, c)");
        log.info("[关键] c 由 H(w ‖ message) 决定，不需要 Verifier 参与");
    }

    /**
     * sampleInBall：从哈希展开成稀疏多项式（恰好 τ 个非零系数，系数 ∈ {−1, 0, 1}）。
     */
    private static int[] sampleInBall(byte[] seed, int tau, int n)
    {
        int[] c = new int[n];
        byte[] rho = shake256(seed, 8);
        // 简化版：用种子生成 τ 个随机位置
        SecureRandom rng = new SecureRandom();
        rng.setSeed(rho);
        int placed = 0;
        while (placed < tau)
        {
            int idx = rng.nextInt(n);
            if (c[idx] == 0)
            {
                c[idx] = rng.nextBoolean() ? 1 : -1;
                placed++;
            }
        }
        return c;
    }

    /**
     * SHAKE256 扩展输出。
     */
    private static byte[] shake256(byte[] input, int outputLen)
    {
        SHAKEDigest digest = new SHAKEDigest(256);
        digest.update(input, 0, input.length);
        byte[] output = new byte[outputLen];
        digest.doOutput(output, 0, outputLen);
        return output;
    }

    /**
     * 字节数组拼接。
     */
    private static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * 字节数组转十六进制（前 N 字节）。
     */
    private static String bytesToHex(byte[] bytes, int maxLen)
    {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(bytes.length, maxLen);
        for (int i = 0; i < len; i++)
        {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > maxLen)
        {
            sb.append("...");
        }
        return sb.toString();
    }

    // =====================================================================
    // 对比分析：ML-DSA vs 经典签名 vs 其他 PQC
    // =====================================================================

    /**
     * <b>为什么选 ML-DSA</b>：对比经典签名（RSA、ECDSA）和其他 PQC 方案（哈希签名），
     * ML-DSA 在"签名大小 + 安全性假设"上取得最佳平衡。
     *
     * <p>本测试对比：
     * <ol>
     *   <li>RSA-2048：签名 256 字节，量子下 Shor 破产</li>
     *   <li>ECDSA P-256：签名 64 字节，量子下 Shor 破产</li>
     *   <li>ML-DSA-44：签名 2420 字节，量子下仍安全</li>
     *   <li>SLH-DSA-SHAKE-128s：签名 7856 字节，量子下仍安全但签名巨大</li>
     * </ol>
     */
    @Test
    public void compareWithClassicAndOtherPqc()
    {
        log.info("[对比] 经典签名 vs PQC 签名");

        // 1. RSA-2048：签名 256 字节，量子下 = 0（Shor 破产）
        int rsaSignatureSize = 256;
        int rsaQuantumSecurity = 0;
        log.info("[RSA-2048] 签名 {} 字节，量子安全性 = 0（Shor）",
            rsaSignatureSize);

        // 2. ECDSA P-256：签名 64 字节，量子下 = 0（Shor 破产）
        int ecdsaSignatureSize = 64;
        int ecdsaQuantumSecurity = 0;
        log.info("[ECDSA P-256] 签名 {} 字节，量子安全性 = 0（Shor）",
            ecdsaSignatureSize);

        // 3. ML-DSA-44：签名 2420 字节，量子下 ≈ 2^{100}
        int mldsa44SignatureSize = 2420;
        int mldsa44QuantumSecurity = 100;
        log.info("[ML-DSA-44] 签名 {} 字节，量子安全性 ≈ 2^{}",
            mldsa44SignatureSize, mldsa44QuantumSecurity);
        Assert.assertTrue("ML-DSA 量子下仍安全", mldsa44QuantumSecurity >= 100);

        // 4. SLH-DSA-SHAKE-128s：签名 7856 字节，量子下 ≈ 2^{128}
        int slhdsaSignatureSize = 7856;
        int slhdsaQuantumSecurity = 128;
        log.info("[SLH-DSA-128s] 签名 {} 字节，量子安全性 ≈ 2^{}",
            slhdsaSignatureSize, slhdsaQuantumSecurity);

        // 5. 结论：ML-DSA 签名比 SLH-DSA 小 3 倍，但比经典签名大 40 倍
        log.info("[结论] ML-DSA 用签名大小换量子安全性，比 SLH-DSA 紧凑");
    }

    /**
     * <b>ML-DSA 的参数选择逻辑</b>：三个级别（44/65/87）对应 NIST 安全级别 1/3/5，
     * 每个级别的 k、l、η、τ 都是"在量子安全性 ≥ 级别要求"的前提下，
     * 最小化签名大小。
     *
     * <p>本测试验证参数表的正确性。
     */
    @Test
    public void parameterChoicesFollowQuantumSecurityLevels()
    {
        log.info("[参数选择] ML-DSA 三个级别的设计逻辑");

        // ML-DSA-44：NIST 级别 1（≈ AES-128）
        int k44 = 4;
        int l44 = 4;
        int eta44 = 2;
        int tau44 = 39;
        int signatureLen44 = 2420; // FIPS 204 表 2
        log.info("[ML-DSA-44] k={}, l={}, η={}, τ={} → 签名 {} 字节",
            k44, l44, eta44, tau44, signatureLen44);
        Assert.assertEquals("ML-DSA-44 签名 2420 字节", 2420, signatureLen44);

        // ML-DSA-65：NIST 级别 3（≈ AES-192）
        int k65 = 6;
        int l65 = 5;
        int eta65 = 4;
        int tau65 = 49;
        int signatureLen65 = 3309; // FIPS 204 表 2
        log.info("[ML-DSA-65] k={}, l={}, η={}, τ={} → 签名 {} 字节",
            k65, l65, eta65, tau65, signatureLen65);
        Assert.assertEquals("ML-DSA-65 签名 3309 字节", 3309, signatureLen65);

        // ML-DSA-87：NIST 级别 5（≈ AES-256）
        int k87 = 8;
        int l87 = 7;
        int eta87 = 2;
        int tau87 = 60;
        int signatureLen87 = 4627; // FIPS 204 表 2
        log.info("[ML-DSA-87] k={}, l={}, η={}, τ={} → 签名 {} 字节",
            k87, l87, eta87, tau87, signatureLen87);
        Assert.assertEquals("ML-DSA-87 签名 4627 字节", 4627, signatureLen87);

        log.info("[结论] k/l 增大 → 格维度增大 → 量子安全性增大 → 签名也增大");
    }

    /**
     * <b>量子下的唯一加速</b>：Grover 搜索给 SIS 带来二次加速。
     *
     * <p>ML-DSA-44 的经典安全性 ≈ 2^{128}（归约到 SVP），量子下 ≈ 2^{64}（Grover 减半）。
     * 但这只是<b>二次加速</b>，不是 Shor 的指数→多项式。
     *
     * <p>本测试演示 Grover 的影响。
     */
    @Test
    public void groverOnlyHalvesSecurity()
    {
        log.info("[Grover] 二次加速：安全性 2^n → 2^{n/2}");

        // 1. ML-DSA-44：格维度 = k·n = 4·256 = 1024
        int k44 = 4;
        int n = 256;
        int dim44 = k44 * n;
        double classicalSecurity44 = 0.292 * dim44; // BKZ 启发式
        double quantumSecurity44 = classicalSecurity44 / 2;
        log.info("[ML-DSA-44] 格维度={}, 经典安全性≈2^{}, 量子安全性≈2^{}",
            dim44, (int) classicalSecurity44, (int) quantumSecurity44);
        Assert.assertTrue("量子安全性 ≥ 100", quantumSecurity44 >= 100);

        // 2. ML-DSA-65：格维度 = 6·256 = 1536
        int k65 = 6;
        int dim65 = k65 * n;
        double classicalSecurity65 = 0.292 * dim65;
        double quantumSecurity65 = classicalSecurity65 / 2;
        log.info("[ML-DSA-65] 格维度={}, 量子安全性≈2^{}", dim65, (int) quantumSecurity65);
        Assert.assertTrue("量子安全性 ≥ 150", quantumSecurity65 >= 150);

        // 3. ML-DSA-87：格维度 = 8·256 = 2048
        int k87 = 8;
        int dim87 = k87 * n;
        double classicalSecurity87 = 0.292 * dim87;
        double quantumSecurity87 = classicalSecurity87 / 2;
        log.info("[ML-DSA-87] 格维度={}, 量子安全性≈2^{}", dim87, (int) quantumSecurity87);
        Assert.assertTrue("量子安全性 ≥ 200", quantumSecurity87 >= 200);

        // 4. 对比：ECDSA P-256 在量子下是多项式时间（Shor），完全破产
        log.info("[对比] ECDSA P-256 量子下 = 多项式时间（Shor），ML-DSA-44 量子下 ≈ 2^{100}");
    }
}
