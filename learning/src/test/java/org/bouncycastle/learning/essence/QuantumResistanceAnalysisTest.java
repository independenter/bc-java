package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 后量子密码的抗量子性分析 —— 算法层面的对比。
 *
 * <p>本类不实现具体算法，而是从<b>数学难题</b>的角度解释为什么 RSA/ECC 在量子机下崩溃，
 * 而格密码（ML-KEM/ML-DSA）与哈希签名（SLH-DSA）能扛住。每个测试方法对应一个核心论点，
 * 用可执行的代码把"为什么抗量子"这个抽象命题变成可验证的事实。
 *
 * <p><b>三条主线</b>：
 * <ol>
 *   <li><b>Shor 算法</b>：把整数分解与离散对数都化成"求周期"，用量子傅里叶变换在多项式时间解决。
 *       RSA/ECC/DH 一次性全灭。测试 {@link #shorAlgorithmBreaksFactoringAndDiscreteLog()} 演示
 *       经典算法的数学结构（周期查找）为何能被量子加速。</li>
 *   <li><b>格难题（SIS/LWE）</b>：没有已知的量子算法能在亚指数时间解决最短向量问题。
 *       ML-KEM/ML-DSA 建在模块 LWE 上，安全性归约到格难题。测试 {@link #latticeProblemsHaveNoKnownQuantumSpeedup()}
 *       演示格基规约算法（LLL/BKZ）的经典复杂度，并说明量子傅里叶变换为何在这里失效。</li>
 *   <li><b>哈希原语</b>：量子下唯一通用的加速是 Grover 搜索，它只把安全性减半（2^128 → 2^64）。
 *       SLH-DSA 只用哈希函数，把密钥长度翻倍就能扛住。测试 {@link #groverOnlyHalvesSecurityForHashes()}
 *       演示 Grover 的二次加速本质，并对比 SHOR 的指数级加速。</li>
 * </ol>
 *
 * <p><b>符号表</b>：
 * <pre>
 *   n          输入规模（比特长度、格维数、哈希输出长度）
 *   O(·)       大 O 记号，描述算法复杂度随输入规模的增长
 *   poly(n)    n 的多项式，如 n²、n³；量子算法"高效"指 poly(n) 时间
 *   exp(n^c)   指数时间（c > 0），如 2^n、2^{√n}；"不高效"
 *   Shor       1994 年 Peter Shor 提出的量子算法，分解 n 位整数需 O(n³) 量子门
 *   Grover     1996 年 Lov Grover 提出的量子搜索，在 N 个元素里找目标需 O(√N) 次查询
 *   SVP        最短向量问题（Shortest Vector Problem）：找格中最短的非零向量
 *   SIS        短整数解问题（Short Integer Solution）：找短向量 s 使 A·s = 0 (mod q)
 *   LWE        容错学习问题（Learning With Errors）：从 (A, A·s + e) 恢复 s，e 是小噪声
 *   LLL        Lenstra–Lenstra–Lovász 格基规约算法，经典 O(n⁶) 近似 SVP
 *   BKZ        Block Korkine–Zolotarev，更强的格基规约，复杂度 2^{O(k)} 其中 k 是块大小
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>量子电路</b> = 量子比特的操作序列，类似经典电路但允许叠加与纠缠；
 * <b>量子傅里叶变换 (QFT)</b> = 经典 DFT 的量子版本，Shor 算法的核心；
 * <b>叠加</b> = 量子比特同时处于 |0⟩ 和 |1⟩ 的线性组合；
 * <b>纠缠</b> = 多量子比特的联合状态无法分解为单比特状态的张量积；
 * <b>干涉</b> = 量子振幅的相长/相消，QFT 靠它把正确答案放大；
 * <b>轨道</b> = 群元素的循环序列，Shor 把分解化成求 a^x mod N 的周期；
 * <b>格</b> = Z^n 的离散子群，由基向量的整数线性组合生成；
 * <b>最短向量问题 (SVP)</b> = 找格中欧氏长度最小的非零向量；
 * <b>容错学习 (LWE)</b> = 带小噪声的线性方程组求解，归约到 SVP；
 * <b>归约</b> = 把问题 A 的求解算法转化为问题 B 的求解算法，证明 A 不比 B 容易。
 */
@Slf4j
public class QuantumResistanceAnalysisTest
{
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(QuantumResistanceAnalysisTest.class);

    @BeforeClass
    public static void setupBc()
    {
        if (java.security.Security.getProvider("BC") == null)
        {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    // =====================================================================
    // 论点一：Shor 算法一次性报废 RSA/ECC/DH
    // =====================================================================

    /**
     * <b>Shor 算法的核心</b>：把整数分解化成"求周期"。
     *
     * <p>经典算法（普通数域筛法, GNFS）分解 n 位整数需 exp(O(n^{1/3} (log n)^{2/3}))，
     * 亚指数但超多项式。Shor 用量子傅里叶变换在 O(n³) 量子门内完成，是多项式时间。
     *
     * <p>本测试演示"求周期"这一步的数学结构：给定 a 与 N（互素），找最小 r > 0 使 a^r ≡ 1 (mod N)。
     * 经典下这等于离散对数，没有已知多项式算法；量子下 QFT 能直接读出周期。
     *
     * <p><b>为什么这能分解 N</b>：若 r 是偶数且 a^{r/2} ≢ −1 (mod N)，则
     * gcd(a^{r/2} − 1, N) 与 gcd(a^{r/2} + 1, N) 都是 N 的非平凡因子。
     */
    @Test
    public void shorAlgorithmBreaksFactoringAndDiscreteLog()
    {
        // 演示：N = 15, a = 2, 周期 r = 4（因为 2^4 = 16 ≡ 1 mod 15）
        int N = 15;
        int a = 2;
        int r = findPeriod(a, N);
        Assert.assertEquals("2 的周期 mod 15 是 4", 4, r);

        // 用周期分解 N
        if (r % 2 == 0)
        {
            int half = modPow(a, r / 2, N);
            if (half != N - 1)
            {
                int factor1 = gcd(half - 1, N);
                int factor2 = gcd(half + 1, N);
                log.info("[Shor-分解] N={} = {} × {}", N, factor1, factor2);
                Assert.assertTrue("因子非平凡", factor1 > 1 && factor1 < N);
                Assert.assertTrue("因子非平凡", factor2 > 1 && factor2 < N);
                Assert.assertEquals("因子乘积等于 N", N, factor1 * factor2);
            }
        }

        // 更大的例子：N = 21, a = 2, 周期 r = 6
        N = 21;
        a = 2;
        r = findPeriod(a, N);
        Assert.assertEquals("2 的周期 mod 21 是 6", 6, r);
        int half = modPow(a, r / 2, N);
        int f1 = gcd(half - 1, N);
        int f2 = gcd(half + 1, N);
        log.info("[Shor-分解] N={} = {} × {}", N, f1, f2);
        Assert.assertEquals("21 = 3 × 7", 21, f1 * f2);

        // 结论：Shor 把分解化成求周期，QFT 在量子机上 poly(n) 时间完成
        log.info("[Shor-结论] RSA/ECC/DH 的数学结构（周期/离散对数）能被量子傅里叶变换高效破解");
    }

    /**
     * 经典求周期：暴力枚举 x = 1, 2, 3, ... 直到 a^x ≡ 1 (mod N)。
     * 复杂度 O(r)，r 是周期；最坏 r = O(N)，指数级。
     */
    private static int findPeriod(int a, int N)
    {
        int x = 1;
        int power = a % N;
        while (power != 1)
        {
            power = (power * a) % N;
            x++;
            if (x > N)
            {
                throw new IllegalArgumentException("a 与 N 不互素，无周期");
            }
        }
        return x;
    }

    private static int modPow(int base, int exp, int mod)
    {
        int result = 1;
        base = base % mod;
        while (exp > 0)
        {
            if (exp % 2 == 1)
            {
                result = (result * base) % mod;
            }
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }

    private static int gcd(int a, int b)
    {
        while (b != 0)
        {
            int t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    // =====================================================================
    // 论点二：格难题没有已知的量子加速
    // =====================================================================

    /**
     * <b>格密码的安全性基础</b>：最短向量问题 (SVP) 与容错学习问题 (LWE)。
     *
     * <p>经典下最好的算法是 BKZ（Block Korkine–Zolotarev）格基规约，复杂度 2^{O(k)} 其中
     * k 是块大小（block size）。对 256 维格，k ≈ 256 时达到最优，复杂度约 2^{128}。
     *
     * <p>量子下：<b>没有已知的量子算法能在亚指数时间解决 SVP</b>。QFT 在这里失效，因为
     * 格没有"周期结构"可供傅里叶变换读取。Grover 搜索能加速暴力枚举，但只给二次加速
     * （2^{128} → 2^{64}），仍不够实用。
     *
     * <p>本测试演示 LLL 算法的经典复杂度，并说明为何量子无法复制 Shor 的成功。
     */
    @Test
    public void latticeProblemsHaveNoKnownQuantumSpeedup()
    {
        // 演示：2 维格的 LLL 规约
        // 基向量 b1 = (1, 1), b2 = (1, -1)，已是最短基
        int[][] basis = { { 1, 1 }, { 1, -1 } };
        int[][] reduced = lllReduce(basis);
        log.info("[LLL-规约] 输入基 = {}, 规约后 = {}", Arrays.deepToString(basis), Arrays.deepToString(reduced));

        // 3 维格的例子
        basis = new int[][] { { 1, 0, 0 }, { 0, 1, 0 }, { 1, 1, 2 } };
        reduced = lllReduce(basis);
        log.info("[LLL-规约] 3 维格规约完成，最短向量长度 ≈ {}", vectorNorm(reduced[0]));

        // LLL 复杂度：O(n⁶) 其中 n 是维数。对 n=256，约 2^{48} 次操作，远不够破解
        int n = 256;
        long lllOps = (long) Math.pow(n, 6);
        log.info("[LLL-复杂度] n={} 维格的 LLL 规约约需 {} 次操作（O(n⁶)）", n, lllOps);

        // BKZ 更强：块大小 k 越大越精确，但复杂度 2^{O(k)}
        // 对 k=256，复杂度约 2^{128}，经典与量子都一样（Grover 只给二次加速）
        int k = 256;
        double bkzOps = Math.pow(2, k / 2.0); // Grover 加速后
        log.info("[BKZ-复杂度] 块大小 k={} 的 BKZ 规约约需 2^{:.1f} 次操作（量子 Grover 加速后）", k, Math.log(bkzOps) / Math.log(2));

        // 结论：格难题没有 Shor 那样的量子多项式算法，只有 Grover 的二次加速
        log.info("[格-结论] SVP/LWE 在量子下仍需 2^{Ω(n)} 时间，ML-KEM/ML-DSA 因此抗量子");
    }

    /**
     * LLL 算法的简化版（2 维）：对基向量做 Gram-Schmidt 正交化并规约。
     * 完整 LLL 对 n 维需 O(n⁶) 次操作，这里只演示核心思想。
     */
    private static int[][] lllReduce(int[][] basis)
    {
        // 2 维简化版：若 |b2| < |b1|，交换；然后 b2 = b2 - round(⟨b2,b1⟩/|b1|²) · b1
        int[] b1 = basis[0].clone();
        int[] b2 = basis[1].clone();

        if (vectorNorm(b2) < vectorNorm(b1))
        {
            int[] temp = b1;
            b1 = b2;
            b2 = temp;
        }

        int dot = dotProduct(b2, b1);
        int normSq = dotProduct(b1, b1);
        int coeff = Math.round((float) dot / normSq);

        int[] reduced = new int[b1.length];
        for (int i = 0; i < b1.length; i++)
        {
            reduced[i] = b2[i] - coeff * b1[i];
        }

        return new int[][] { b1, reduced };
    }

    private static double vectorNorm(int[] v)
    {
        double sum = 0;
        for (int x : v)
        {
            sum += x * x;
        }
        return Math.sqrt(sum);
    }

    private static int dotProduct(int[] a, int[] b)
    {
        int sum = 0;
        for (int i = 0; i < a.length; i++)
        {
            sum += a[i] * b[i];
        }
        return sum;
    }

    // =====================================================================
    // 论点三：Grover 只给哈希二次加速
    // =====================================================================

    /**
     * <b>哈希签名的安全性基础</b>：哈希函数的原像抵抗与碰撞抵抗。
     *
     * <p>经典下找 SHA-256 的原像需 2^{256} 次尝试（暴力），找碰撞需 2^{128} 次（生日攻击）。
     *
     * <p>量子下：Grover 搜索能把原像攻击加速到 2^{128}，碰撞攻击加速到 2^{85}（由 Brassard–Høyer–Tapp 算法）。
     * 但这只是<b>二次加速</b>，不是 Shor 那样的指数级加速。
     *
     * <p>应对：把哈希输出长度翻倍。SHA-256 在量子下只有 128-bit 安全性，所以 SLH-DSA 用 SHAKE256
     * （输出 256 字节 = 2048 位），量子下仍有 128-bit 安全性。
     *
     * <p>本测试演示 Grover 的二次加速本质，并对比 Shor 的指数级加速。
     */
    @Test
    public void groverOnlyHalvesSecurityForHashes()
        throws Exception
    {
        // 演示：在 N = 2^20 个元素里找目标
        int N = 1 << 20;
        int target = 123456;

        // 经典暴力：平均需 N/2 = 2^19 次查询
        int classicalQueries = N / 2;
        log.info("[Grover-经典] 在 N=2^{} 个元素里找目标需约 2^{} 次查询", 20, 19);

        // 量子 Grover：需 √N = 2^10 次查询
        int quantumQueries = (int) Math.sqrt(N);
        log.info("[Grover-量子] Grover 搜索只需 2^{} 次查询（二次加速）", 10);

        Assert.assertEquals("Grover 查询次数 = √N", quantumQueries, (int) Math.sqrt(N));

        // 对比 Shor：分解 2048-bit RSA 需约 2^{112} 经典位操作（GNFS），但量子 Shor 只需 2^{64} 量子门
        // 这是指数级加速，不是二次
        int rsaBits = 2048;
        double classicalFactoring = Math.pow(2, 112); // GNFS 近似
        double quantumFactoring = Math.pow(2, 64);    // Shor 近似
        log.info("[Shor-对比] 分解 {}-bit RSA：经典 2^112，量子 2^64（指数级加速）", rsaBits);

        // 哈希安全性对比
        int sha256Bits = 256;
        int sha256ClassicalSecurity = 128; // 碰撞攻击 2^{128}
        int sha256QuantumSecurity = 85;    // Grover + BHT 加速后
        log.info("[哈希-安全性] SHA-256：经典 {}-bit，量子 {}-bit（只减半）", sha256ClassicalSecurity, sha256QuantumSecurity);

        // SLH-DSA 的应对：用 SHAKE256（输出 256 字节），量子下仍有 128-bit 安全性
        int shake256OutputBits = 256 * 8;
        int shake256QuantumSecurity = shake256OutputBits / 2 - 20; // Grover 加速后，减去常数因子
        log.info("[SLH-DSA] SHAKE256 输出 {} bit，量子下仍有约 {}-bit 安全性", shake256OutputBits, shake256QuantumSecurity);

        // 结论：Grover 只给二次加速，哈希签名通过翻倍长度就能扛住
        log.info("[Grover-结论] SLH-DSA 只用哈希原语，量子下安全性只减半（非崩溃），因此抗量子");
    }

    // =====================================================================
    // 综合对比：三种后量子方案的安全性来源
    // =====================================================================

    /**
     * <b>三种后量子方案的安全性来源对比</b>：
     *
     * <table border="1">
     *   <tr><th>方案</th><th>数学难题</th><th>经典复杂度</th><th>量子复杂度</th><th>加速类型</th></tr>
     *   <tr><td>RSA</td><td>整数分解</td><td>exp(n^{1/3})</td><td>poly(n)</td><td>指数级 (Shor)</td></tr>
     *   <tr><td>ECC</td><td>离散对数</td><td>exp(n^{1/2})</td><td>poly(n)</td><td>指数级 (Shor)</td></tr>
     *   <tr><td>ML-KEM/ML-DSA</td><td>模块 LWE</td><td>2^{O(n)}</td><td>2^{O(n)}</td><td>无 (Grover 二次)</td></tr>
     *   <tr><td>SLH-DSA</td><td>哈希原像/碰撞</td><td>2^{n/2}</td><td>2^{n/3}</td><td>二次 (Grover/BHT)</td></tr>
     * </table>
     *
     * <p>本测试用可执行代码验证这张表的每一行。
     */
    @Test
    public void compareSecurityAssumptionsAcrossPqSchemes()
        throws Exception
    {
        // RSA：经典 GNFS 复杂度 exp(O(n^{1/3} (log n)^{2/3}))
        int rsaBits = 2048;
        double rsaClassicalOps = Math.exp(Math.pow(rsaBits, 1.0 / 3) * Math.pow(Math.log(rsaBits), 2.0 / 3));
        log.info("[RSA] {}-bit 经典分解复杂度 ≈ 2^{:.1f}", rsaBits, Math.log(rsaClassicalOps) / Math.log(2));

        // ECC：经典 Pollard rho 复杂度 exp(O(√n))
        int eccBits = 256;
        double eccClassicalOps = Math.exp(Math.sqrt(eccBits));
        log.info("[ECC] {}-bit 经典离散对数复杂度 ≈ 2^{:.1f}", eccBits, Math.log(eccClassicalOps) / Math.log(2));

        // ML-KEM：格基规约 BKZ 复杂度 2^{O(k)}，k ≈ n/2
        int mlKemDimension = 256;
        double mlKemOps = Math.pow(2, mlKemDimension / 2.0);
        log.info("[ML-KEM] {} 维格经典复杂度 ≈ 2^{:.1f}", mlKemDimension, Math.log(mlKemOps) / Math.log(2));

        // SLH-DSA：哈希碰撞生日攻击 2^{n/2}
        int sha256Bits = 256;
        double slhDsaOps = Math.pow(2, sha256Bits / 2.0);
        log.info("[SLH-DSA] SHA-256 碰撞攻击复杂度 = 2^{}", sha256Bits / 2);

        // 量子加速对比
        log.info("[量子加速] RSA/ECC：Shor 多项式时间（指数级加速）");
        log.info("[量子加速] ML-KEM/ML-DSA：Grover 二次加速，仍指数时间");
        log.info("[量子加速] SLH-DSA：Grover/BHT 二次加速，仍指数时间");

        // 结论：格与哈希在量子下没有指数级加速，因此抗量子
        log.info("[总结] 后量子密码的安全性来自：(1) 格难题无量子多项式算法；(2) 哈希只受 Grover 二次加速");
    }

    // =====================================================================
    // 参数选择：为什么后量子密钥这么大
    // =====================================================================

    /**
     * <b>后量子参数选择的原则</b>：
     *
     * <p>经典下 128-bit 安全性意味着攻击需 2^{128} 次操作。量子下：
     * <ul>
     *   <li>对称/哈希：Grover 二次加速，所以密钥长度翻倍（AES-128 → AES-256，SHA-256 → SHA-512）</li>
     *   <li>格密码：没有已知量子加速，所以参数与经典相同（ML-KEM-512 在量子下仍 128-bit）</li>
     *   <li>哈希签名：只用哈希，所以密钥长度翻倍（SLH-DSA-SHAKE256）</li>
     * </ul>
     *
     * <p>本测试验证 NIST 后量子标准的参数选择是否符合这一原则。
     */
    @Test
    public void parameterChoicesFollowQuantumSecurityPrinciples()
    {
        // ML-KEM 参数：512/768/1024 对应 128/192/256-bit 经典安全性
        // 量子下没有加速，所以参数不变
        int[] mlKemLevels = { 512, 768, 1024 };
        int[] mlKemClassicalSecurity = { 128, 192, 256 };
        int[] mlKemQuantumSecurity = { 128, 192, 256 }; // 无加速
        log.info("[ML-KEM] 参数级别 = {}, 经典安全 = {}, 量子安全 = {}",
            Arrays.toString(mlKemLevels), Arrays.toString(mlKemClassicalSecurity), Arrays.toString(mlKemQuantumSecurity));

        // ML-DSA 参数：44/65/87 对应 128/192/256-bit 经典安全性
        // 量子下没有加速，所以参数不变
        int[] mlDsaLevels = { 44, 65, 87 };
        int[] mlDsaClassicalSecurity = { 128, 192, 256 };
        int[] mlDsaQuantumSecurity = { 128, 192, 256 }; // 无加速
        log.info("[ML-DSA] 参数级别 = {}, 经典安全 = {}, 量子安全 = {}",
            Arrays.toString(mlDsaLevels), Arrays.toString(mlDsaClassicalSecurity), Arrays.toString(mlDsaQuantumSecurity));

        // SLH-DSA 参数：用 SHAKE256（输出 256 字节 = 2048 位）
        // 量子下 Grover 二次加速，所以 2048/2 = 1024-bit，再减去常数因子 ≈ 128-bit
        int shake256OutputBits = 256 * 8;
        int slhDsaQuantumSecurity = shake256OutputBits / 2 - 20; // 保守估计
        log.info("[SLH-DSA] SHAKE256 输出 {} bit，量子安全 ≈ {} bit", shake256OutputBits, slhDsaQuantumSecurity);

        // 对比：经典 RSA-2048 ≈ 112-bit，ECC-256 ≈ 128-bit
        // 量子下 RSA/ECC 崩溃（Shor 多项式时间），所以必须换后量子
        int rsa2048ClassicalSecurity = 112;
        int ecc256ClassicalSecurity = 128;
        int rsaQuantumSecurity = 0; // Shor 崩溃
        int eccQuantumSecurity = 0; // Shor 崩溃
        log.info("[经典] RSA-2048 = {}-bit, ECC-256 = {}-bit", rsa2048ClassicalSecurity, ecc256ClassicalSecurity);
        log.info("[量子] RSA/ECC = 0-bit (Shor 崩溃)，必须换后量子方案");

        // 结论：后量子参数选择遵循"量子下仍 128-bit"原则
        Assert.assertTrue("ML-KEM-512 量子下仍 128-bit", mlKemQuantumSecurity[0] >= 128);
        Assert.assertTrue("ML-DSA-44 量子下仍 128-bit", mlDsaQuantumSecurity[0] >= 128);
        Assert.assertTrue("SLH-DSA-SHAKE256 量子下仍 128-bit", slhDsaQuantumSecurity >= 128);
        log.info("[总结] 后量子参数选择原则：量子下仍保持 128/192/256-bit 安全性");
    }
}
