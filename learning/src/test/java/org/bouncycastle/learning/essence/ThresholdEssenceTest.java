package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * 门限密码（Threshold Cryptography）的本质计算 —— 面向过程版，覆盖 Shamir 秘密共享与门限 ECDSA 签名。
 *
 * <p>门限密码要解决的核心问题：<b>把一把密钥切成 n 份，任意 t 份合在一起能恢复，少于 t 份什么也得不到</b>。
 * 这就是 (t, n)-门限方案。它有两个直接应用：
 * <ol>
 *   <li><b>门限密钥托管</b>：公司私钥切成 5 份交给 5 个高管，任意 3 人到场才能签名（3-of-5 门限）</li>
 *   <li><b>门限签名</b>：n 个参与方各持一片密钥，t 方协同产出一张合法签名，任何一方单独签不了</li>
 * </ol>
 *
 * <p>本类分三层：
 * <ol>
 *   <li><b>Shamir 秘密共享 (SSS)</b>： Adi Shamir 1979 年的方案。秘密 s 放在一个 t−1 次多项式 f(x) 的常数项
 *       f(0) = s，n 个份额是 f(1), f(2), …, f(n)。恢复时用拉格朗日插值算 f(0) —— t 个点唯一确定一个 t−1 次
 *       多项式，所以 t 份够恢复；t−1 份则有无穷多个多项式穿过那些点，秘密完全不确定。</li>
 *   <li><b>门限 ECDSA 签名</b>：私钥 d 用 SSS 切成 n 份 d₁…dₙ。签名时 t 个参与方各出局部签名 sᵢ，
 *       用拉格朗日系数 λᵢ 加权合成 s = Σ λᵢ·sᵢ，得到的 (r, s) 与用完整私钥 d 直接签的完全相同。</li>
 *   <li><b>安全性分析</b>：为什么少于 t 份拿不到秘密（信息论安全），为什么门限签名不比完整签名弱（归约到 ECDSA）。</li>
 * </ol>
 *
 * <p><b>符号表 —— 全类公式共享的字母/记号</b>
 * <pre>
 *   t          门限值（threshold）：恢复秘密/产生签名至少需要 t 份
 *   n          总份额数（total shares）：密钥被切成 n 份
 *   s          待共享的秘密（secret），SSS 里是 f(0)；门限签名里是 ECDSA 私钥 d
 *   f(x)       t−1 次随机多项式：f(x) = s + a₁x + a₂x² + … + a_{t-1}x^{t-1} (mod p)
 *              常数项 f(0) = s 是秘密，其余系数 a₁…a_{t-1} 随机选取
 *   a_i        多项式的随机系数（i = 1…t−1），每个都在 Z/pZ 里均匀选取
 *   x_i        第 i 个份额的公开横坐标（通常取 1, 2, …, n），公开量，不是秘密
 *   y_i = f(x_i) 第 i 个份额的值（秘密份额），必须保密分发给第 i 个参与方
 *   λ_i        拉格朗日系数 (Lagrange coefficient)：λ_i = Π_{j≠i} x_j / (x_j − x_i) (mod p)
 *              恢复秘密时 s = Σ λ_i · y_i (mod p)
 *   p (大写 P)  有限域的模数：SSS 里所有多项式运算都在 Z/pZ 上进行；
 *              门限签名里 p 是 SM2 曲线的域模数，n 是基点阶（注意区分：SSS 的 p 可以任意大，
 *              但门限签名里 p 和 n 由曲线固定）
 *   d          ECDSA/SM2 私钥标量，门限签名里 d 就是 SSS 的秘密 s
 *   d_i        第 i 个参与方持有的私钥份额：d_i = f(i) (mod n)
 *   k          签名一次性随机数（nonce），门限签名里 k 也需要门限化（本类用"指定方生成"简化）
 *   R = k·G    签名的承诺点（curve point），r = R.x mod n
 *   e          消息哈希整数：e = Hash(Z_A ‖ M)
 *   sig = (r, s) ECDSA/SM2 签名对
 *   λ_i (签名) 门限签名里的拉格朗日系数：λ_i = Π_{j≠i} j / (j − i) (mod n)
 *              注意这里 x_i = i（份额编号从 1 开始），所以 λ_i 的分母分子都是小整数
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>秘密共享 (secret sharing)</b> = 把秘密拆成多份分发给不同参与方，少于门限数合不起来；
 * <b>Shamir 秘密共享 (SSS)</b> = 用多项式插值实现的秘密共享，t−1 次多项式需要 t 个点确定；
 * <b>拉格朗日插值 (Lagrange interpolation)</b> = 给定 t 个点 (x_i, y_i)，唯一确定一个 t−1 次多项式，
 * 公式 f(x) = Σ y_i · λ_i(x)，其中 λ_i(x) = Π_{j≠i} (x − x_j)/(x_i − x_j)；
 * <b>信息论安全 (information-theoretic security)</b> = 即使攻击者有无限算力，少于 t 份也得不到任何关于秘密的信息
 * （不是"算不出来"，而是"所有可能的秘密等概率"）；
 * <b>门限签名 (threshold signature)</b> = t-of-n 参与方协同产出一张签名，任何一方单独签不了；
 * <b>局部签名 (partial signature)</b> = 每个参与方用自己的份额算出的签名片段，合成后才是完整签名；
 * <b>(t, n)-门限</b> = n 份里任意 t 份可恢复/签名，t−1 份不行；读作"t of n"。
 */
@Slf4j
public class ThresholdEssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    // =====================================================================
    // 曲线常数（SM2 的 sm2p256v1）
    // =====================================================================

    private static final X9ECParameters CURVE_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN =
        new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN());
    private static final BigInteger P = CURVE_PARAMS.getCurve().getField().getCharacteristic();
    private static final BigInteger N = CURVE_PARAMS.getN();
    private static final BigInteger GX = CURVE_PARAMS.getG().getAffineXCoord().toBigInteger();
    private static final BigInteger GY = CURVE_PARAMS.getG().getAffineYCoord().toBigInteger();

    // =====================================================================
    // 第一层：Shamir 秘密共享 (SSS) —— 多项式切割 + 拉格朗日恢复
    // =====================================================================

    /**
     * <b>SSS 的切割</b>：秘密 s 放在 f(0)，随机选 t−1 个系数，在 x = 1, 2, …, n 处求值，得到 n 个份额。
     *
     * <p>公式：f(x) = s + a₁x + a₂x² + … + a_{t−1}x^{t−1} (mod p)
     * <br>份额：y_i = f(i) (mod p)，i = 1, 2, …, n
     *
     * <p>本测试用 (3, 5)-门限演示：5 份里任意 3 份可恢复秘密。
     */
    @TraceExecution(value = "Shamir 秘密共享：多项式切割与份额分发", algorithm = "THRESHOLD",
        flow = "THRESHOLD-SHAMIR")
    @Test
    public void shamirSecretSharingSplit()
    {
        int t = 3; // 门限值
        int n = 5; // 总份额数
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "Shamir split", "start");

        // 秘密 s：一个 256-bit 随机数
        BigInteger secret = new BigInteger(256, new SecureRandom()).mod(P);
        log.info("[SSS 切割] 秘密 s = {}...", secret.toString(16).substring(0, 16));

        // 1. 构造 t−1 次多项式：f(x) = s + a₁x + a₂x² (mod p)
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = secret; // 常数项 = 秘密
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, new SecureRandom()).mod(P);
        }
        log.info("[SSS 切割] 多项式次数 = {}（需要 {} 份恢复）", t - 1, t);
        Tracer.trace("split", new Object[]{"t", t, "coeffs", coeffs, "modulus", P}, coeffs, "split");

        // 2. 在 x = 1, 2, …, n 处求值，得到 n 个份额
        BigInteger[] shares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            BigInteger x = BigInteger.valueOf(i + 1);
            shares[i] = polyEval(coeffs, x, P);
        }
        log.info("[SSS 切割] 份额 y₁={}..., y₂={}..., …, y₅={}...",
            shares[0].toString(16).substring(0, 8),
            shares[1].toString(16).substring(0, 8),
            shares[4].toString(16).substring(0, 8));
        Tracer.trace("distribute", new Object[]{"n", n, "shares", shares}, shares, "distribute");

        // 3. 验证：f(0) = s（常数项就是秘密）
        BigInteger f0 = polyEval(coeffs, BigInteger.ZERO, P);
        Assert.assertEquals("f(0) = 秘密", secret, f0);
        log.info("[SSS 切割] f(0) = {}... ✓", f0.toString(16).substring(0, 16));
        Tracer.traceDecision("verify", new Object[]{"secret", secret, "f(0)", f0},
            secret.equals(f0), "verify", "f(0) == s");
        Tracer.trace("end", new Object[]{"secret", secret, "f(0)", f0}, null, "end");
    }

    /**
     * <b>SSS 的恢复</b>：用 t 个份额 (x_i, y_i) 做拉格朗日插值，算出 f(0) = 秘密。
     *
     * <p>拉格朗日插值公式：f(0) = Σ_{i=1}^{t} y_i · λ_i (mod p)
     * <br>其中 λ_i = Π_{j≠i} (0 − x_j) / (x_i − x_j) = Π_{j≠i} x_j / (x_j − x_i) (mod p)
     *
     * <p>本测试演示：从 5 份里任选 3 份恢复，结果与原始秘密逐字节相同。
     */
    @TraceExecution(value = "Shamir 秘密共享：拉格朗日插值恢复", algorithm = "THRESHOLD",
        flow = "THRESHOLD-SHAMIR")
    @Test
    public void shamirSecretSharingRecover()
    {
        int t = 3;
        int n = 5;
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "Shamir recover", "start");

        // 1. 先切割
        BigInteger secret = new BigInteger(256, new SecureRandom()).mod(P);
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = secret;
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, new SecureRandom()).mod(P);
        }
        Tracer.trace("split", new Object[]{"t", t, "coeffs", coeffs, "modulus", P}, coeffs, "split");
        BigInteger[] shares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            shares[i] = polyEval(coeffs, BigInteger.valueOf(i + 1), P);
        }
        Tracer.trace("distribute", new Object[]{"n", n, "shares", shares}, shares, "distribute");

        // 2. 用前 t 份恢复（x = 1, 2, 3）
        int[] indices = {0, 1, 2}; // 选第 1、2、3 份
        BigInteger[] selectedShares = new BigInteger[t];
        BigInteger[] selectedX = new BigInteger[t];
        for (int i = 0; i < t; i++)
        {
            selectedShares[i] = shares[indices[i]];
            selectedX[i] = BigInteger.valueOf(indices[i] + 1);
        }
        BigInteger recovered = lagrangeInterpolateAtZero(selectedX, selectedShares, P);
        log.info("[SSS 恢复] 用份额 {} 恢复: {}...", Arrays.toString(indices),
            recovered.toString(16).substring(0, 16));
        Assert.assertEquals("恢复的秘密 = 原始秘密", secret, recovered);
        Tracer.trace("recover", new Object[]{"indices", Arrays.toString(indices), "shares", selectedShares},
            recovered, "recover");
        Tracer.traceDecision("verify", new Object[]{"secret", secret, "recovered", recovered},
            secret.equals(recovered), "verify", "t 份恢复 == 原始秘密");

        // 3. 用另外 t 份恢复（x = 2, 4, 5）
        int[] indices2 = {1, 3, 4};
        BigInteger[] selectedShares2 = new BigInteger[t];
        BigInteger[] selectedX2 = new BigInteger[t];
        for (int i = 0; i < t; i++)
        {
            selectedShares2[i] = shares[indices2[i]];
            selectedX2[i] = BigInteger.valueOf(indices2[i] + 1);
        }
        BigInteger recovered2 = lagrangeInterpolateAtZero(selectedX2, selectedShares2, P);
        log.info("[SSS 恢复] 用份额 {} 恢复: {}...", Arrays.toString(indices2),
            recovered2.toString(16).substring(0, 16));
        Assert.assertEquals("任意 t 份都能恢复", secret, recovered2);
        Tracer.trace("recover", new Object[]{"indices", Arrays.toString(indices2), "shares", selectedShares2},
            recovered2, "recover");
        Tracer.traceDecision("verify", new Object[]{"secret", secret, "recovered", recovered2},
            secret.equals(recovered2), "verify", "任意 t 份恢复 == 原始秘密");

        // 4. 用 t−1 份恢复：结果不等于秘密（信息论安全）
        int[] indices3 = {0, 1}; // 只有 2 份 < t = 3
        BigInteger[] selectedShares3 = new BigInteger[2];
        BigInteger[] selectedX3 = new BigInteger[2];
        for (int i = 0; i < 2; i++)
        {
            selectedShares3[i] = shares[indices3[i]];
            selectedX3[i] = BigInteger.valueOf(indices3[i] + 1);
        }
        BigInteger wrongRecovered = lagrangeInterpolateAtZero(selectedX3, selectedShares3, P);
        log.info("[SSS 恢复] 用 {} 份（< t）恢复: {}... ≠ 秘密",
            2, wrongRecovered.toString(16).substring(0, 16));
        Assert.assertFalse("少于 t 份恢复不出秘密", secret.equals(wrongRecovered));
        Tracer.trace("recover", new Object[]{"indices", Arrays.toString(indices3), "shares", selectedShares3},
            wrongRecovered, "recover");
        Tracer.traceDecision("verify", new Object[]{"secret", secret, "recovered", wrongRecovered},
            secret.equals(wrongRecovered), "verify", "t−1 份恢复 != 原始秘密");
        Tracer.trace("security", new Object[]{"threshold", t, "parts", 2}, "insufficient shares", "security");
        Tracer.trace("end", new Object[]{"secret", secret, "wrongRecovered", wrongRecovered}, null, "end");
    }

    /**
     * <b>SSS 的信息论安全</b>：t−1 份对秘密没有任何信息优势 —— 所有可能的秘密等概率。
     *
     * <p>证明思路：给定 t−1 个点 (x₁,y₁)…(x_{t-1},y_{t-1})，穿过这些点的 t−1 次多项式有无穷多个
     * （差一个自由参数 a_{t-1}），每个多项式给出不同的 f(0)，所以秘密可以是任何值。
     *
     * <p>本测试用统计方法验证：固定 t−1 份，枚举所有可能的第 t 份，恢复出的秘密均匀分布。
     */
    @TraceExecution(value = "Shamir 秘密共享：t−1 份信息论安全", algorithm = "THRESHOLD",
        flow = "THRESHOLD-SHAMIR")
    @Test
    public void shamirIsInformationTheoreticallySecure()
    {
        int t = 2; // 简化：2-of-n 门限
        int n = 3;
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "information-theoretic security", "start");

        // 固定秘密和多项式
        BigInteger secret = BigInteger.valueOf(42);
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = secret;
        coeffs[1] = BigInteger.valueOf(7); // f(x) = 42 + 7x (mod p)
        Tracer.trace("split", new Object[]{"t", t, "coeffs", coeffs, "modulus", P}, coeffs, "split");

        // 计算份额
        BigInteger[] shares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            shares[i] = polyEval(coeffs, BigInteger.valueOf(i + 1), P);
        }
        Tracer.trace("distribute", new Object[]{"n", n, "shares", shares}, shares, "distribute");

        // 只拿第 1 份（x=1, y=f(1)=49），尝试用不同的"第 2 份"恢复
        BigInteger x1 = BigInteger.ONE;
        BigInteger y1 = shares[0]; // f(1) = 49
        log.info("[信息论安全] 已知份额 (1, {})", y1);

        // 枚举第 2 份的 x 坐标（x=2），看恢复出的秘密
        // 对于 2 次多项式，给定 1 个点，第 2 个点可以是任何值 ⇒ 秘密可以是任何值
        BigInteger[] recoveredSecrets = new BigInteger[5];
        for (int trial = 0; trial < 5; trial++)
        {
            BigInteger a1Trial = BigInteger.valueOf(trial * 1000 + 1);
            BigInteger f2 = secret.add(a1Trial.multiply(BigInteger.valueOf(2))).mod(P);
            BigInteger[] xs = {x1, BigInteger.valueOf(2)};
            BigInteger[] ys = {y1, f2};
            recoveredSecrets[trial] = lagrangeInterpolateAtZero(xs, ys, P);
        }
        log.info("[信息论安全] 用不同'第 2 份'恢复的秘密: {}, {}, {}, {}, {}",
            recoveredSecrets[0], recoveredSecrets[1], recoveredSecrets[2],
            recoveredSecrets[3], recoveredSecrets[4]);
        Tracer.trace("recover", new Object[]{"knownShare", shares[0], "trials", recoveredSecrets.length},
            recoveredSecrets, "recover");

        // 验证：恢复出的秘密各不相同（说明 1 份对秘密没有约束力）
        boolean allDifferent = true;
        for (int i = 1; i < recoveredSecrets.length; i++)
        {
            if (recoveredSecrets[i].equals(recoveredSecrets[0]))
            {
                allDifferent = false;
                break;
            }
        }
        Assert.assertTrue("1 份（< t=2）恢复出的秘密各不相同", allDifferent);
        log.info("[信息论安全] 结论：少于 t 份 ⇒ 秘密完全不确定 ⇒ 信息论安全 ✓");
        Tracer.traceDecision("verify", new Object[]{"knownShares", 1, "threshold", t},
            allDifferent, "verify", "t−1 份恢复出的秘密各不相同");
        Tracer.trace("security", new Object[]{"threshold", t, "knownShares", 1},
            allDifferent, "security");
        Tracer.trace("end", new Object[]{"threshold", t, "recoveredSecrets", recoveredSecrets}, null, "end");
    }

    // =====================================================================
    // 第二层：门限 ECDSA 签名 —— 局部签名 + 拉格朗日合成
    // =====================================================================

    /**
     * <b>门限 ECDSA 签名的完整流程</b>：
     * <ol>
     *   <li>密钥生成：随机选私钥 d，用 SSS 切成 n 份 d₁…dₙ</li>
     *   <li>签名：t 个参与方各用 d_i 算局部签名，用拉格朗日系数合成完整签名 (r, s)</li>
     *   <li>验证：用公钥 P = d·G 验签，结果与用完整私钥直接签的相同</li>
     * </ol>
     *
     * <p>本测试演示 (2, 3)-门限 ECDSA：3 方里任意 2 方协同可签名。
     */
    @TraceExecution(value = "门限 ECDSA 签名：局部签名与拉格朗日合成", algorithm = "THRESHOLD",
        flow = "THRESHOLD-ECDSA")
    @Test
    public void thresholdEcdsaSignature()
    {
        int t = 2; // 门限值
        int n = 3; // 总参与方数
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "threshold ECDSA", "start");

        // 1. 密钥生成：随机私钥 d，公钥 P = d·G
        BigInteger d = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] pubPoint = ecMul(d, GX, GY, P);
        log.info("[门限签名] 私钥 d = {}...", d.toString(16).substring(0, 16));
        log.info("[门限签名] 公钥 P = ({}..., {}...)",
            pubPoint[0].toString(16).substring(0, 8),
            pubPoint[1].toString(16).substring(0, 8));
        Tracer.trace("setup", new Object[]{"d", d, "P", pubPoint}, pubPoint, "setup");

        // 2. 用 SSS 把 d 切成 n 份（mod n，不是 mod p！因为签名运算在 Z/nZ 里）
        BigInteger[] dShares = new BigInteger[n];
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = d;
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, new SecureRandom()).mod(N);
        }
        for (int i = 0; i < n; i++)
        {
            dShares[i] = polyEval(coeffs, BigInteger.valueOf(i + 1), N);
        }
        log.info("[门限签名] 份额 d₁={}..., d₂={}..., d₃={}...",
            dShares[0].toString(16).substring(0, 8),
            dShares[1].toString(16).substring(0, 8),
            dShares[2].toString(16).substring(0, 8));
        Tracer.trace("keyDist", new Object[]{"dShares", dShares}, dShares, "keyDist");

        // 3. 签名：选 t=2 个参与方（第 1 方和第 3 方）
        int[] signers = {0, 2}; // 参与方索引
        BigInteger message = BigInteger.valueOf(12345); // 待签消息（简化为整数）

        // 3a. 第 1 方生成随机数 k（简化：由一方生成，实际也需要门限化）
        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] kPoint = ecMul(k, GX, GY, P);
        BigInteger r = kPoint[0].mod(N);
        log.info("[门限签名] k = {}..., r = {}...",
            k.toString(16).substring(0, 8), r.toString(16).substring(0, 8));

        // 3b. 每个参与方算局部签名 s_i
        // ECDSA 签名公式：s = k⁻¹ · (e + r·d) mod n
        // 门限版本：s_i = k⁻¹ · (e/t + r·d_i) mod n（简化版，实际协议更复杂）
        // 这里用拉格朗日系数加权：s = Σ λ_i · s_i
        BigInteger kInv = k.modInverse(N);
        BigInteger[] partialSigs = new BigInteger[signers.length];
        BigInteger[] lagrangeCoeffs = computeLagrangeCoefficients(signers, N);

        for (int idx = 0; idx < signers.length; idx++)
        {
            int i = signers[idx];
            // 局部签名：s_i = λ_i · k⁻¹ · (e + r · d_i) mod n
            BigInteger e_plus_rd = message.add(r.multiply(dShares[i])).mod(N);
            partialSigs[idx] = lagrangeCoeffs[idx].multiply(kInv).multiply(e_plus_rd).mod(N);
            log.info("[门限签名] 参与方 {} 的局部签名 s_{} = {}...",
                i + 1, i + 1, partialSigs[idx].toString(16).substring(0, 8));
            Tracer.traceLoop("partialSign", new Object[]{"participant", i + 1,
                "share", dShares[i], "lambda", lagrangeCoeffs[idx]},
                partialSigs[idx], "partialSign", idx + 1, signers.length, "partialSign");
        }
        Tracer.trace("partialSign", new Object[]{"partialSigs", partialSigs}, partialSigs, "partialSign");

        // 3c. 合成完整签名：s = Σ s_i mod n
        BigInteger s = BigInteger.ZERO;
        for (BigInteger ps : partialSigs)
        {
            s = s.add(ps).mod(N);
        }
        log.info("[门限签名] 合成签名 s = {}...", s.toString(16).substring(0, 8));
        Tracer.trace("combine", new Object[]{"s", s}, s, "combine");

        // 4. 验证：用公钥 P 验签 (r, s)
        boolean valid = ecdsaVerify(pubPoint, message, r, s);
        log.info("[门限签名] 验签结果: {}", valid ? "通过" : "失败");
        Assert.assertTrue("门限签名验签通过", valid);
        Tracer.traceDecision("verify", new Object[]{"r", r, "s", s}, valid, "verify", "门限签名验签通过");

        // 5. 对比：用完整私钥 d 直接签名，结果应该相同
        BigInteger sDirect = kInv.multiply(message.add(r.multiply(d))).mod(N);
        log.info("[对比] 直接签名 s = {}...", sDirect.toString(16).substring(0, 8));
        Assert.assertEquals("门限签名 = 直接签名", sDirect, s);
        Tracer.trace("end", new Object[]{"s", s, "sDirect", sDirect}, "threshold ECDSA", "end");
    }

    /**
     * <b>门限签名的安全性</b>：为什么 t 方协同签出的签名与用完整私钥签的相同？
     *
     * <p>关键等式：Σ λ_i · d_i = d (mod n)
     * <br>这是拉格朗日插值的性质：t 个点 (i, d_i) 唯一确定 t−1 次多项式 f(x)，
     * 而 f(0) = d，所以 Σ λ_i · f(i) = f(0) = d。
     *
     * <p>本测试验证这个关键等式。
     */
    @TraceExecution(value = "门限签名安全归约：Σ λᵢ·dᵢ = d", algorithm = "THRESHOLD",
        flow = "THRESHOLD-ECDSA")
    @Test
    public void thresholdSignatureSecurityReduction()
    {
        int t = 3;
        int n = 5;
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "threshold security reduction", "start");

        // 1. 生成私钥和份额
        BigInteger d = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = d;
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, new SecureRandom()).mod(N);
        }
        BigInteger[] dShares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            dShares[i] = polyEval(coeffs, BigInteger.valueOf(i + 1), N);
        }
        Tracer.trace("setup", new Object[]{"d", d, "coeffs", coeffs}, d, "setup");
        Tracer.trace("keyDist", new Object[]{"n", n, "dShares", dShares}, dShares, "keyDist");

        // 2. 选 t 个参与方，计算拉格朗日系数
        int[] signers = {0, 2, 4}; // 第 1、3、5 方
        BigInteger[] lambdas = computeLagrangeCoefficients(signers, N);

        // 3. 验证关键等式：Σ λ_i · d_i = d (mod n)
        BigInteger reconstructed = BigInteger.ZERO;
        for (int idx = 0; idx < signers.length; idx++)
        {
            int i = signers[idx];
            reconstructed = reconstructed.add(lambdas[idx].multiply(dShares[i])).mod(N);
            Tracer.traceLoop("lagrangeTerm", new Object[]{"participant", i + 1,
                "share", dShares[i], "lambda", lambdas[idx]},
                lambdas[idx].multiply(dShares[i]).mod(N), "partialSign",
                idx + 1, signers.length, "partialSign");
        }
        log.info("[安全归约] Σ λ_i · d_i = {}...", reconstructed.toString(16).substring(0, 16));
        log.info("[安全归约] d = {}...", d.toString(16).substring(0, 16));
        Assert.assertEquals("拉格朗日合成恢复私钥", d, reconstructed);
        Tracer.trace("combine", new Object[]{"d", d, "reconstructed", reconstructed},
            reconstructed, "combine");

        // 4. 结论：门限签名的安全性归约到 ECDSA —— 如果 ECDSA 安全，门限 ECDSA 也安全
        log.info("[安全归约] 结论：门限签名 ≡ 完整签名 ⇒ 安全性归约到 ECDSA ✓");
        Tracer.trace("end", new Object[]{"d", d, "reconstructed", reconstructed}, null, "end");
    }

    /**
     * <b>门限签名的协同性</b>：少于 t 方签不出合法签名。
     *
     * <p>本测试演示：2 方（< t=3）尝试签名，验签失败。
     */
    @TraceExecution(value = "门限签名协同性：少于 t 方签不出合法签名", algorithm = "THRESHOLD",
        flow = "THRESHOLD-ECDSA")
    @Test
    public void thresholdSignatureRequiresTParties()
    {
        int t = 3;
        int n = 5;
        Tracer.trace("start", new Object[]{"t", t, "n", n}, "threshold requires t parties", "start");

        // 1. 生成私钥和份额
        BigInteger d = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] pubPoint = ecMul(d, GX, GY, P);
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = d;
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, new SecureRandom()).mod(N);
        }
        BigInteger[] dShares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            dShares[i] = polyEval(coeffs, BigInteger.valueOf(i + 1), N);
        }
        Tracer.trace("setup", new Object[]{"d", d, "P", pubPoint}, pubPoint, "setup");
        Tracer.trace("keyDist", new Object[]{"n", n, "dShares", dShares}, dShares, "keyDist");

        // 2. 只有 2 方尝试签名（< t=3）
        int[] insufficientSigners = {0, 1};
        BigInteger message = BigInteger.valueOf(99999);
        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] kPoint = ecMul(k, GX, GY, P);
        BigInteger r = kPoint[0].mod(N);
        BigInteger kInv = k.modInverse(N);

        BigInteger[] lambdas = computeLagrangeCoefficients(insufficientSigners, N);
        BigInteger sPartial = BigInteger.ZERO;
        for (int idx = 0; idx < insufficientSigners.length; idx++)
        {
            int i = insufficientSigners[idx];
            BigInteger e_plus_rd = message.add(r.multiply(dShares[i])).mod(N);
            BigInteger partialSig = lambdas[idx].multiply(kInv).multiply(e_plus_rd).mod(N);
            sPartial = sPartial.add(partialSig).mod(N);
            Tracer.traceLoop("partialSign", new Object[]{"participant", i + 1,
                "share", dShares[i], "lambda", lambdas[idx]},
                partialSig, "partialSign", idx + 1, t, "partialSign");
        }
        Tracer.trace("combine", new Object[]{"signers", insufficientSigners.length, "s", sPartial},
            sPartial, "combine");

        // 3. 验签：应该失败
        boolean valid = ecdsaVerify(pubPoint, message, r, sPartial);
        log.info("[协同性] {} 方（< t={}）签名验签: {}",
            insufficientSigners.length, t, valid ? "通过（错误！）" : "失败 ✓");
        Assert.assertFalse("少于 t 方签不出合法签名", valid);
        Tracer.traceDecision("verify", new Object[]{"signers", insufficientSigners.length,
            "threshold", t, "s", sPartial}, valid, "verify", "少于 t 方验签必须失败");

        // 4. 对比：3 方（= t）签名，验签通过
        int[] sufficientSigners = {0, 1, 2};
        BigInteger[] lambdasFull = computeLagrangeCoefficients(sufficientSigners, N);
        BigInteger sFull = BigInteger.ZERO;
        for (int idx = 0; idx < sufficientSigners.length; idx++)
        {
            int i = sufficientSigners[idx];
            BigInteger e_plus_rd = message.add(r.multiply(dShares[i])).mod(N);
            BigInteger partialSig = lambdasFull[idx].multiply(kInv).multiply(e_plus_rd).mod(N);
            sFull = sFull.add(partialSig).mod(N);
            Tracer.traceLoop("partialSign", new Object[]{"participant", i + 1,
                "share", dShares[i], "lambda", lambdasFull[idx]},
                partialSig, "partialSign", idx + 1, sufficientSigners.length, "partialSign");
        }
        Tracer.trace("combine", new Object[]{"signers", sufficientSigners.length, "s", sFull},
            sFull, "combine");
        boolean validFull = ecdsaVerify(pubPoint, message, r, sFull);
        log.info("[协同性] {} 方（= t）签名验签: {}",
            sufficientSigners.length, validFull ? "通过 ✓" : "失败（错误！）");
        Assert.assertTrue("t 方协同可签出合法签名", validFull);
        Tracer.traceDecision("verify", new Object[]{"signers", sufficientSigners.length,
            "threshold", t, "s", sFull}, validFull, "verify", "t 方协同验签必须通过");
        Tracer.trace("end", new Object[]{"sPartial", sPartial, "sFull", sFull}, null, "end");
    }

    // =====================================================================
    // 辅助方法：多项式运算、拉格朗日插值、椭圆曲线运算
    // =====================================================================

    /**
     * 多项式求值：f(x) = coeffs[0] + coeffs[1]·x + coeffs[2]·x² + … (mod modulus)
     */
    private static BigInteger polyEval(BigInteger[] coeffs, BigInteger x, BigInteger modulus)
    {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE; // x^0 = 1
        for (int i = 0; i < coeffs.length; i++)
        {
            result = result.add(coeffs[i].multiply(xPow)).mod(modulus);
            xPow = xPow.multiply(x).mod(modulus);
        }
        return result;
    }

    /**
     * 拉格朗日插值在 x=0 处的值：f(0) = Σ y_i · λ_i (mod modulus)
     * <br>其中 λ_i = Π_{j≠i} x_j / (x_j − x_i) (mod modulus)
     */
    private static BigInteger lagrangeInterpolateAtZero(BigInteger[] xs, BigInteger[] ys,
        BigInteger modulus)
    {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < xs.length; i++)
        {
            BigInteger lambda = BigInteger.ONE;
            for (int j = 0; j < xs.length; j++)
            {
                if (i != j)
                {
                    // λ_i *= x_j / (x_j − x_i)
                    BigInteger num = xs[j];
                    BigInteger den = xs[j].subtract(xs[i]).mod(modulus);
                    lambda = lambda.multiply(num).multiply(den.modInverse(modulus)).mod(modulus);
                }
            }
            result = result.add(ys[i].multiply(lambda)).mod(modulus);
        }
        return result;
    }

    /**
     * 计算拉格朗日系数：给定的参与方索引列表，返回每个参与方的 λ_i (mod modulus)
     * <br>x_i = signers[i] + 1（份额编号从 1 开始）
     */
    private static BigInteger[] computeLagrangeCoefficients(int[] signers, BigInteger modulus)
    {
        BigInteger[] lambdas = new BigInteger[signers.length];
        for (int idx = 0; idx < signers.length; idx++)
        {
            BigInteger xi = BigInteger.valueOf(signers[idx] + 1);
            BigInteger lambda = BigInteger.ONE;
            for (int jdx = 0; jdx < signers.length; jdx++)
            {
                if (idx != jdx)
                {
                    BigInteger xj = BigInteger.valueOf(signers[jdx] + 1);
                    // λ_i *= x_j / (x_j − x_i)
                    BigInteger num = xj;
                    BigInteger den = xj.subtract(xi).mod(modulus);
                    lambda = lambda.multiply(num).multiply(den.modInverse(modulus)).mod(modulus);
                }
            }
            lambdas[idx] = lambda;
        }
        return lambdas;
    }

    /**
     * 椭圆曲线点加：P + Q (mod p)
     */
    private static BigInteger[] ecAdd(BigInteger[] pt1, BigInteger[] pt2)
    {
        if (pt1.length == 0) return pt2;
        if (pt2.length == 0) return pt1;

        BigInteger x1 = pt1[0], y1 = pt1[1];
        BigInteger x2 = pt2[0], y2 = pt2[1];

        if (x1.equals(x2) && y1.equals(y2))
        {
            return ecDouble(pt1);
        }
        if (x1.equals(x2))
        {
            return new BigInteger[0]; // 无穷远点
        }

        // λ = (y2 − y1) / (x2 − x1) mod p
        BigInteger lam = y2.subtract(y1).mod(P).multiply(x2.subtract(x1).modInverse(P)).mod(P);
        // x3 = λ² − x1 − x2 mod p
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(P);
        // y3 = λ(x1 − x3) − y1 mod p
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BigInteger[]{x3, y3};
    }

    /**
     * 椭圆曲线倍点：2P (mod p)
     */
    private static BigInteger[] ecDouble(BigInteger[] pt)
    {
        if (pt.length == 0) return pt;
        BigInteger x = pt[0], y = pt[1];
        if (y.signum() == 0) return new BigInteger[0];

        // λ = (3x² + a) / (2y) mod p，SM2 的 a = p − 3
        BigInteger a = P.subtract(BigInteger.valueOf(3));
        BigInteger num = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a).mod(P);
        BigInteger den = y.multiply(BigInteger.valueOf(2)).mod(P);
        BigInteger lam = num.multiply(den.modInverse(P)).mod(P);
        // x3 = λ² − 2x mod p
        BigInteger x3 = lam.multiply(lam).subtract(x.multiply(BigInteger.valueOf(2))).mod(P);
        // y3 = λ(x − x3) − y mod p
        BigInteger y3 = lam.multiply(x.subtract(x3)).subtract(y).mod(P);
        return new BigInteger[]{x3, y3};
    }

    /**
     * 椭圆曲线标量乘：k·P (mod p)，double-and-add 算法
     */
    private static BigInteger[] ecMul(BigInteger k, BigInteger gx, BigInteger gy, BigInteger mod)
    {
        BigInteger[] result = new BigInteger[0]; // 无穷远点
        BigInteger[] base = {gx, gy};
        BigInteger exp = k;
        while (exp.signum() > 0)
        {
            if (exp.testBit(0))
            {
                result = ecAdd(result, base);
            }
            base = ecDouble(base);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    /**
     * ECDSA 验签：检查 (r, s) 是否是消息 e 对公钥 P 的合法签名
     */
    private static boolean ecdsaVerify(BigInteger[] pubPoint, BigInteger e, BigInteger r,
        BigInteger s)
    {
        if (r.signum() <= 0 || r.compareTo(N) >= 0) return false;
        if (s.signum() <= 0 || s.compareTo(N) >= 0) return false;

        BigInteger sInv = s.modInverse(N);
        BigInteger u1 = e.multiply(sInv).mod(N);
        BigInteger u2 = r.multiply(sInv).mod(N);

        // R = u1·G + u2·P
        BigInteger[] r1 = ecMul(u1, GX, GY, P);
        BigInteger[] r2 = ecMul(u2, pubPoint[0], pubPoint[1], P);
        BigInteger[] R = ecAdd(r1, r2);
        if (R.length == 0) return false;

        // 检查 R.x mod n == r
        return R[0].mod(N).equals(r);
    }
}
