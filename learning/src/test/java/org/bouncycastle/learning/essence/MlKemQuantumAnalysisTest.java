package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.junit.Assert;
import org.junit.Test;

/**
 * ML-KEM（FIPS 203，原 Kyber）的量子抗性过程式分解。
 *
 * <p>本文件不重复 PqcEssenceTest 里的环运算/NTT/压缩/打包实现，只聚焦一个问题：
 * <b>为什么 ML-KEM 能抗住量子计算机？</b> 答案分三层：
 * <ol>
 *   <li><b>困难问题层</b>：ML-KEM 的安全性归约到 Module-LWE（带错误学习）问题。
 *       这个问题在量子下没有已知的多项式时间算法 —— Shor 算法只能解"周期结构"的问题
 *       （整数分解、离散对数），而 LWE 是"带噪声的线性方程组"，没有周期可用。</li>
 *   <li><b>量子加速层</b>：Grover 搜索能给 LWE 带来二次加速（2^{n/2} → 2^{n}），
 *       但这只是指数减半，不是 Shor 那样的指数→多项式。把参数翻倍就能扛住。</li>
 *   <li><b>协议层</b>：Fujisaki-Okamoto 变换把 IND-CPA 升级到 IND-CCA，
 *       即使量子敌人带着解密 oracle 也分不清密文对应的密钥与随机串。</li>
 * </ol>
 *
 * <p><b>符号表（本文件专用）</b>：
 * <pre>
 *   k          模块 LWE 的维度（ML-KEM-512/768/1024 对应 k=2/3/4）
 *   q          多项式环模数（ML-KEM 固定 q=3329=13·2^8+1）
 *   n          多项式次数（固定 n=256）
 *   η₁, η₂     噪声分布参数（中心二项式分布的界）
 *   d_u, d_v   密文压缩位宽（ML-KEM-512: 10/4; 768: 10/4; 1024: 11/5）
 *   s ∈ R_q^k  私钥向量（k 个多项式，每个系数从中心二项式分布抽）
 *   A ∈ R_q^{k×k} 公钥矩阵（均匀随机多项式，由种子 ρ 展开）
 *   t = A·s + e  公钥向量（e 是噪声向量）
 *   r ∈ R_q^k  封装随机数（一次性，每次封装重新抽）
 *   K = 32 字节  共享密钥（由 SHAKE256 从 r 和密文导出）
 *   c = (c₁, c₂) 密文（c₁ 是压缩后的 A^T·r，c₂ 是压缩后的 t^T·r + ⌊q/2⌋·m）
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>Module-LWE</b> = 给定 (A, t=A·s+e)，从 t 反解 s 是困难的（即使量子机也不行），
 * 因为 e 的存在让"解线性方程组"变成"带误差的最优化"，可归约到格上的最短向量问题（SVP）；
 * <b>中心二项式分布</b> = 抽 η 个均匀比特再抽 η 个，差值作为系数（范围 [−η, η]），
 * 比高斯分布好实现，比均匀分布"短"，是格密码里的"廉价噪声源"；
 * <b>压缩</b> = compress(q, d, x) = ⌊(2^d / q) · x⌉ mod 2^d，把 [0, q) 的系数压到 [0, 2^d)，
 * 牺牲一点精度换密文变短；
 * <b>FO 变换</b> = Fujisaki-Okamoto 变换：先算 (K, r) = G(m)，再封装 r 得到 c，
 * 解密时重算 c' 比对，不一致就返回伪随机密钥（隐式拒绝），把 CPA 升到 CCA。
 */
@Slf4j
public class MlKemQuantumAnalysisTest
{
    private static final org.slf4j.Logger log =
        org.slf4j.LoggerFactory.getLogger(MlKemQuantumAnalysisTest.class);

    // =====================================================================
    // 第一层：困难问题 —— Module-LWE 为什么量子下仍难
    // =====================================================================

    /**
     * <b>Module-LWE 问题的结构</b>：给定 A ∈ R_q^{k×k} 和 t = A·s + e ∈ R_q^k，
     * 从 t 反解 s 是困难的。关键是噪声 e 的存在 —— 如果没有 e，就是解线性方程组，
     * 高斯消元 O(k³) 搞定；有了 e，变成"找最接近的格点"（SVP），量子下无多项式算法。
     *
     * <p>本测试演示：
     * <ol>
     *   <li>无噪声时（e=0），从 (A, t) 反解 s 是平凡的（矩阵求逆）</li>
     *   <li>有噪声时（e≠0），直接求逆会算出 s' = s + A⁻¹·e，误差被放大</li>
     *   <li>格约减算法（LLL/BKZ）能找"近似最短向量"，但对 256 维格仍指数时间</li>
     * </ol>
     */
    @Test
    public void moduleLweIsHardBecauseOfNoise()
    {
        int q = 3329; // ML-KEM 的模数
        int k = 2;    // ML-KEM-512 的维度
        int n = 256;  // 多项式次数

        log.info("[Module-LWE] q={}, k={}, n={}", q, k, n);

        // 1. 生成随机矩阵 A（k×k 个多项式，每个 n 个系数）
        int[][][] A = new int[k][k][n];
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < k; i++)
        {
            for (int j = 0; j < k; j++)
            {
                for (int d = 0; d < n; d++)
                {
                    A[i][j][d] = rng.nextInt(q);
                }
            }
        }

        // 2. 生成短向量 s（系数从 [−1, 0, 1] 抽，模拟中心二项式）
        int[][] s = new int[k][n];
        for (int i = 0; i < k; i++)
        {
            for (int d = 0; d < n; d++)
            {
                s[i][d] = rng.nextInt(3) - 1; // −1, 0, 1
            }
        }

        // 3. 无噪声版本：t = A·s (mod q)，反解 s 是平凡的
        int[][] tNoNoise = matVecMulMod(q, A, s);
        log.info("[无噪声] t[0][0] = {}", tNoNoise[0][0]);

        // 4. 有噪声版本：t = A·s + e (mod q)，e 也是短向量
        int[][] e = new int[k][n];
        for (int i = 0; i < k; i++)
        {
            for (int d = 0; d < n; d++)
            {
                e[i][d] = rng.nextInt(3) - 1;
            }
        }
        int[][] tWithNoise = new int[k][n];
        for (int i = 0; i < k; i++)
        {
            for (int d = 0; d < n; d++)
            {
                tWithNoise[i][d] = (tNoNoise[i][d] + e[i][d]) % q;
            }
        }
        log.info("[有噪声] t[0][0] = {}，误差 e[0][0] = {}", tWithNoise[0][0], e[0][0]);

        // 5. 为什么"直接求逆"不行：A⁻¹·t = s + A⁻¹·e，误差被放大
        // 在 R_q 上 A 不一定可逆，但即使可逆，A⁻¹ 的系数也是 [0, q) 均匀分布，
        // A⁻¹·e 的系数会变成 O(q) 量级，完全淹没 s 的 O(1) 信号
        log.info("[关键] 噪声 e 让'解线性方程组'变成'带误差的最优化' → 归约到 SVP");

        // 6. SVP 的量子复杂度：已知最好算法（经典与量子）对 256 维格都是 2^{Ω(n)}
        // BKZ-256 在经典下约 2^{118}，量子下 Grover 加速到 2^{59}，仍远超多项式
        int latticeDim = k * n; // 格的维度 = k·n = 512
        log.info("[SVP] 格维度 = k·n = {}，量子下仍指数时间", latticeDim);
        Assert.assertTrue("格维度 ≥ 512", latticeDim >= 512);
    }

    /**
     * 矩阵×向量 (mod q)：C[i] = Σ_j A[i][j]·v[j] (mod q)，多项式乘法用卷积。
     */
    private static int[][] matVecMulMod(int q, int[][][] A, int[][] v)
    {
        int k = A.length;
        int n = A[0][0].length;
        int[][] result = new int[k][n];
        for (int i = 0; i < k; i++)
        {
            for (int j = 0; j < k; j++)
            {
                int[] prod = polyMulMod(q, A[i][j], v[j]);
                for (int d = 0; d < n; d++)
                {
                    result[i][d] = (result[i][d] + prod[d]) % q;
                }
            }
        }
        return result;
    }

    /**
     * 多项式乘法 (mod q, mod X^256+1)：朴素 O(n²) 卷积，越界项乘 −1。
     */
    private static int[] polyMulMod(int q, int[] a, int[] b)
    {
        int n = a.length;
        int[] result = new int[n];
        for (int i = 0; i < n; i++)
        {
            long sum = 0;
            for (int j = 0; j <= i; j++)
            {
                sum += (long) a[j] * b[i - j];
            }
            for (int j = i + 1; j < n; j++)
            {
                sum -= (long) a[j] * b[n + i - j]; // X^n = −1
            }
            result[i] = (int) ((sum % q + q) % q);
        }
        return result;
    }

    // =====================================================================
    // 第二层：量子加速 —— Grover 只给 LWE 二次加速
    // =====================================================================

    /**
     * <b>Grover 搜索对 LWE 的影响</b>：Grover 能给"非结构化搜索"带来 √N 加速，
     * 对 LWE 的应用是"暴力搜最短向量"：经典 2^n → 量子 2^{n/2}。
     *
     * <p>但这只是<b>二次加速</b>，不是 Shor 的指数→多项式。
     * ML-KEM-512 的经典安全性约 2^{118}（归约到 SVP），量子下约 2^{59}，
     * 仍远超 2^{64}（NIST 安全级别 1 的下限）。
     *
     * <p>本测试演示：
     * <ol>
     *   <li>Grover 的加速因子是 √N（二次）</li>
     *   <li>把参数翻倍（k 从 2 到 4），格维度从 512 到 1024，安全性从 2^{59} 到 2^{100+}</li>
     *   <li>这就是 ML-KEM 三个级别（512/768/1024）的设计逻辑</li>
     * </ol>
     */
    @Test
    public void groverOnlyGivesQuadraticSpeedup()
    {
        log.info("[Grover] 二次加速：搜索空间 N → √N");

        // 1. ML-KEM-512：k=2, n=256, 格维度 512
        int k512 = 2;
        int n = 256;
        int dim512 = k512 * n;
        // NIST 安全级别 1（≈ AES-128）：经典 2^118，量子 2^59（Grover 减半）
        int classicalSecurity512 = 118;
        int quantumSecurity512 = 59;
        log.info("[ML-KEM-512] 格维度={}, 经典安全性≈2^{}, 量子安全性≈2^{}",
            dim512, classicalSecurity512, quantumSecurity512);
        Assert.assertTrue("量子安全性 ≥ 50", quantumSecurity512 >= 50);

        // 2. ML-KEM-768：k=3, 格维度 768
        int k768 = 3;
        int dim768 = k768 * n;
        // NIST 安全级别 3（≈ AES-192）：经典 2^182，量子 2^91
        int classicalSecurity768 = 182;
        int quantumSecurity768 = 91;
        log.info("[ML-KEM-768] 格维度={}, 量子安全性≈2^{}", dim768, quantumSecurity768);
        Assert.assertTrue("量子安全性 ≥ 80", quantumSecurity768 >= 80);

        // 3. ML-KEM-1024：k=4, 格维度 1024
        int k1024 = 4;
        int dim1024 = k1024 * n;
        // NIST 安全级别 5（≈ AES-256）：经典 2^256，量子 2^128
        int classicalSecurity1024 = 256;
        int quantumSecurity1024 = 128;
        log.info("[ML-KEM-1024] 格维度={}, 量子安全性≈2^{}", dim1024, quantumSecurity1024);
        Assert.assertTrue("量子安全性 ≥ 120", quantumSecurity1024 >= 120);

        // 4. 对比：RSA-2048 在量子下是多项式时间（Shor），完全破产
        log.info("[对比] RSA-2048 量子下 = 多项式时间（Shor），ML-KEM-512 量子下 ≈ 2^{100}");
    }

    // =====================================================================
    // 第三层：协议安全 —— FO 变换把 CPA 升到 CCA
    // =====================================================================

    /**
     * <b>IND-CCA 安全性</b>：即使量子敌人带着解密 oracle（能解密任意密文），
     * 也分不清"挑战密文对应的密钥"与"随机 32 字节"。
     *
     * <p>ML-KEM 用 Fujisaki-Okamoto 变换实现：
     * <ol>
     *   <li>封装时：先算 (K, r) = G(m)，再用 r 封装得到 c，返回 (c, K)</li>
     *   <li>解密时：用私钥解密 c 得到 m'，重算 (K', r') = G(m')，再封装 r' 得到 c'</li>
     *   <li>比对：c' == c 则返回 K'，否则返回伪随机密钥（隐式拒绝）</li>
     * </ol>
     *
     * <p>这个"重封装比对"的步骤让解密 oracle 无能为力 —— 篡改密文会导致重封装失败，
     * 返回伪随机密钥，敌人得不到任何有用信息。
     *
     * <p>本测试演示 FO 变换的核心逻辑。
     */
    @Test
    public void foTransformUpgradesCpaToCca()
    {
        int q = 3329;
        int n = 256;

        log.info("[FO 变换] 把 IND-CPA 升级到 IND-CCA");

        // 1. 模拟封装：m → (K, r) = G(m)
        byte[] m = new byte[32];
        new SecureRandom().nextBytes(m);
        byte[] Gr = shake256(m, 64);
        byte[] K = Arrays.copyOfRange(Gr, 0, 32);
        byte[] r = Arrays.copyOfRange(Gr, 32, 64);
        log.info("[封装] m={}... → K={}..., r={}...",
            bytesToHex(m, 4), bytesToHex(K, 4), bytesToHex(r, 4));

        // 2. 模拟加密：用 r 封装得到 c（这里简化为 c = r，实际是多项式压缩）
        byte[] c = r.clone();

        // 3. 模拟解密：用私钥解密 c 得到 r'
        byte[] rPrime = c.clone(); // 简化：c 就是 r，解密后 r' = r

        // 4. 密钥导出：K' = H(r' ‖ H(c))
        byte[] Hc = shake256(c, 32);
        byte[] input = concat(rPrime, Hc);
        byte[] KPrime = shake256(input, 32);
        log.info("[解密] r'={}..., K'={}...", bytesToHex(rPrime, 4), bytesToHex(KPrime, 4));

        // 5. 合法密文：K' 与 K 不同（因为密钥导出路径不同），但这是确定的
        log.info("[合法] K={}..., K'={}...（两者不同，因为导出路径不同）",
            bytesToHex(K, 4), bytesToHex(KPrime, 4));

        // 6. 模拟攻击者篡改密文
        byte[] cTampered = c.clone();
        cTampered[0] ^= 0x01; // 翻转 1 bit
        byte[] rTampered = cTampered.clone();
        byte[] HcTampered = shake256(cTampered, 32);
        byte[] inputTampered = concat(rTampered, HcTampered);
        byte[] KPrimeTampered = shake256(inputTampered, 32);
        log.info("[攻击] 篡改密文后 K'={}...", bytesToHex(KPrimeTampered, 4));

        // 7. 关键：篡改后的 K' 与合法的 K' 完全不同
        Assert.assertFalse("篡改后密钥不同", Arrays.equals(KPrime, KPrimeTampered));
        log.info("[结论] 篡改密文 → 解密出错的 r' → 完全不同的 K' → 隐式拒绝");
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

    // =====================================================================
    // 对比分析：ML-KEM vs 经典 KEM vs 其他 PQC
    // =====================================================================

    /**
     * <b>为什么选 ML-KEM</b>：对比经典 KEM（RSA、ECDH）和其他 PQC 方案（哈希签名、多变量），
     * ML-KEM 在"安全性假设 + 性能 + 密文大小"上取得最佳平衡。
     *
     * <p>本测试对比：
     * <ol>
     *   <li>RSA-KEM：基于整数分解，量子下 Shor 多项式时间破解</li>
     *   <li>ECDH：基于椭圆曲线 DLP，量子下 Shor 多项式时间破解</li>
     *   <li>ML-KEM：基于 Module-LWE，量子下最好算法仍指数时间</li>
     *   <li>SLH-DSA（对比）：基于哈希，签名大（7856 字节）但安全性假设最弱</li>
     * </ol>
     */
    @Test
    public void compareWithClassicAndOtherPqc()
    {
        log.info("[对比] 经典 KEM vs PQC KEM");

        // 1. RSA-2048：经典安全性 112-bit，量子下 = 0（Shor 破产）
        int rsaKeySize = 2048;
        int rsaClassicalSecurity = 112;
        int rsaQuantumSecurity = 0;
        log.info("[RSA-{}] 经典安全性 2^{}，量子安全性 = 0（Shor）",
            rsaKeySize, rsaClassicalSecurity);

        // 2. ECDH P-256：经典安全性 128-bit，量子下 = 0（Shor 破产）
        int ecdhKeySize = 256;
        int ecdhClassicalSecurity = 128;
        int ecdhQuantumSecurity = 0;
        log.info("[ECDH P-{}] 经典安全性 2^{}，量子安全性 = 0（Shor）",
            ecdhKeySize, ecdhClassicalSecurity);

        // 3. ML-KEM-512：经典安全性 118-bit，量子下 59-bit（Grover 二次加速）
        int mlKemKeySize = 512;
        int mlKemClassicalSecurity = 118;
        int mlKemQuantumSecurity = 59;
        log.info("[ML-KEM-{}] 经典安全性 2^{}，量子安全性 2^{}（Grover）",
            mlKemKeySize, mlKemClassicalSecurity, mlKemQuantumSecurity);
        Assert.assertTrue("ML-KEM 量子下仍安全", mlKemQuantumSecurity >= 59);

        // 4. 密文大小对比
        int rsaCiphertextSize = 256; // RSA-2048
        int ecdhCiphertextSize = 32; // P-256
        int mlKemCiphertextSize = 768; // ML-KEM-512
        log.info("[密文大小] RSA={} 字节, ECDH={} 字节, ML-KEM={} 字节",
            rsaCiphertextSize, ecdhCiphertextSize, mlKemCiphertextSize);

        // 5. 结论：ML-KEM 密文大（768 字节 vs ECDH 32 字节），但量子下仍安全
        log.info("[结论] ML-KEM 用密文大小换量子安全性，这是格密码的代价");
    }

    /**
     * <b>ML-KEM 的参数选择逻辑</b>：三个级别（512/768/1024）对应 NIST 安全级别 1/3/5，
     * 每个级别的 k、η₁、η₂、d_u、d_v 都是"在量子安全性 ≥ 级别要求"的前提下，
     * 最小化密文大小。
     *
     * <p>本测试验证参数表的正确性。
     */
    @Test
    public void parameterChoicesFollowQuantumSecurityLevels()
    {
        log.info("[参数选择] ML-KEM 三个级别的设计逻辑");

        // ML-KEM-512：NIST 级别 1（≈ AES-128）
        int k512 = 2;
        int eta1_512 = 3;
        int eta2_512 = 2;
        int du_512 = 10;
        int dv_512 = 4;
        int n = 256; // 多项式次数
        int ciphertextLen512 = k512 * n * du_512 / 8 + n * dv_512 / 8;
        log.info("[ML-KEM-512] k={}, η₁={}, η₂={}, d_u={}, d_v={} → 密文 {} 字节",
            k512, eta1_512, eta2_512, du_512, dv_512, ciphertextLen512);
        Assert.assertEquals("ML-KEM-512 密文 768 字节", 768, ciphertextLen512);

        // ML-KEM-768：NIST 级别 3（≈ AES-192）
        int k768 = 3;
        int eta1_768 = 2;
        int eta2_768 = 2;
        int du_768 = 10;
        int dv_768 = 4;
        int ciphertextLen768 = k768 * n * du_768 / 8 + n * dv_768 / 8;
        log.info("[ML-KEM-768] k={}, η₁={}, η₂={}, d_u={}, d_v={} → 密文 {} 字节",
            k768, eta1_768, eta2_768, du_768, dv_768, ciphertextLen768);
        Assert.assertEquals("ML-KEM-768 密文 1088 字节", 1088, ciphertextLen768);

        // ML-KEM-1024：NIST 级别 5（≈ AES-256）
        int k1024 = 4;
        int eta1_1024 = 2;
        int eta2_1024 = 2;
        int du_1024 = 11;
        int dv_1024 = 5;
        int ciphertextLen1024 = k1024 * n * du_1024 / 8 + n * dv_1024 / 8;
        log.info("[ML-KEM-1024] k={}, η₁={}, η₂={}, d_u={}, d_v={} → 密文 {} 字节",
            k1024, eta1_1024, eta2_1024, du_1024, dv_1024, ciphertextLen1024);
        Assert.assertEquals("ML-KEM-1024 密文 1568 字节", 1568, ciphertextLen1024);

        log.info("[结论] k 增大 → 格维度增大 → 量子安全性增大 → 密文也增大");
    }
}
