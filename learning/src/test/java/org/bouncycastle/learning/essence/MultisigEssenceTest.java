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
 * 多重签名（Multisignature）的本质计算 —— 面向过程版，覆盖 n-of-n 多重签名方案。
 *
 * <p>多重签名与门限签名的区别：
 * <ul>
 *   <li><b>门限签名 (t, n)</b>：n 方里任意 t 方协同可签名，产出一张标准签名</li>
 *   <li><b>多重签名 (n, n)</b>：所有 n 方都必须签名，签名是 n 个独立签名的组合</li>
 * </ul>
 *
 * <p>本类实现最简单的多重签名方案：<b>n-of-n MuSig 风格</b>
 * <ol>
 *   <li>每个参与方有自己的密钥对 (d_i, P_i)</li>
 *   <li>聚合公钥：P_agg = P_1 + P_2 + … + P_n（椭圆曲线点加）</li>
 *   <li>签名：每个参与方用 d_i 签同一个随机数 R，得到 s_i</li>
 *   <li>聚合签名：s_agg = s_1 + s_2 + … + s_n (mod n)</li>
 *   <li>验证：用 P_agg 验签 (R, s_agg)，等价于验证所有 n 方都签了</li>
 * </ol>
 *
 * <p><b>符号表 —— 全类公式共享的字母/记号</b>
 * <pre>
 *   n          参与方总数（本类固定 n=3 演示）
 *   d_i        第 i 个参与方的私钥（BigInteger）
 *   P_i        第 i 个参与方的公钥（椭圆曲线点，P_i = d_i · G）
 *   P_agg      聚合公钥：P_agg = P_1 + P_2 + … + P_n
 *   m          待签消息（byte[]）
 *   e          消息哈希：e = Hash(m)（BigInteger）
 *   k          一次性随机数（所有参与方共用同一个 k，这是简化版，实际协议更复杂）
 *   R          承诺点：R = k · G
 *   r          R 的 x 坐标 mod n：r = R.x mod n
 *   s_i        第 i 个参与方的局部签名：s_i = k⁻¹ · (e + r · d_i) mod n
 *   s_agg      聚合签名：s_agg = Σ s_i mod n
 *   sig        多重签名：(r, s_agg)
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>多重签名 (multisignature)</b> = 多个参与方协同签名，所有方都必须参与（n-of-n）；
 * <b>聚合公钥 (aggregate public key)</b> = 所有参与方公钥的和，验证时用聚合公钥验一次即可；
 * <b>聚合签名 (aggregate signature)</b> = 所有参与方局部签名的和，签名长度与单方签名相同；
 * <b>MuSig</b> = 一种高效的多重签名方案（Schnorr 风格），本类实现的是简化版 ECDSA 风格。
 */
@Slf4j
public class MultisigEssenceTest
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
    // 第一层：密钥生成与聚合
    // =====================================================================

    /**
     * <b>多重签名的密钥生成</b>：每个参与方生成自己的密钥对，然后聚合公钥。
     *
     * <p>流程：
     * <ol>
     *   <li>参与方 i 生成私钥 d_i，计算公钥 P_i = d_i · G</li>
     *   <li>聚合公钥 P_agg = P_1 + P_2 + … + P_n（椭圆曲线点加）</li>
     *   <li>P_agg 是公开的，任何人都可以用它验签</li>
     * </ol>
     */
    @TraceExecution(value = "多重签名：n 方密钥对与聚合公钥", algorithm = "MULTISIG",
        flow = "MULTISIG-CORE")
    @Test
    public void multisigKeyGeneration()
    {
        int n = 3; // 3 个参与方
        Tracer.trace("start", new Object[]{"n", n}, "multisig key generation", "start");

        // 1. 每个参与方生成密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
            log.info("[参与方 {}] 私钥 d_{} = {}...", i + 1, i + 1,
                d[i].toString(16).substring(0, 16));
            log.info("[参与方 {}] 公钥 P_{} = ({}..., {}...)", i + 1, i + 1,
                pubPoints[i][0].toString(16).substring(0, 8),
                pubPoints[i][1].toString(16).substring(0, 8));
        }

        // 2. 聚合公钥：P_agg = P_1 + P_2 + P_3
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }
        log.info("[聚合] P_agg = ({}..., {}...)",
            pAgg[0].toString(16).substring(0, 8),
            pAgg[1].toString(16).substring(0, 8));
        Tracer.trace("keyAgg", new Object[]{"n", n, "P_i", pubPoints}, pAgg, "keyAgg");

        // 3. 验证：P_agg = (d_1 + d_2 + d_3) · G
        BigInteger dSum = BigInteger.ZERO;
        for (int i = 0; i < n; i++)
        {
            dSum = dSum.add(d[i]).mod(N);
        }
        BigInteger[] pAggCheck = ecMul(dSum, GX, GY, P);
        Assert.assertArrayEquals("P_agg = Σ d_i · G", pAgg, pAggCheck);
        log.info("[验证] P_agg = (Σ d_i) · G ✓");
        Tracer.trace("keyAgg.check", new Object[]{"P_agg", pAgg, "sumD_G", pAggCheck},
            "P_agg == (Σ d_i)·G", "keyAgg");
        Tracer.trace("end", new Object[]{"P_agg", pAgg}, null, "end");
    }

    // =====================================================================
    // 第二层：多重签名流程
    // =====================================================================

    /**
     * <b>多重签名的完整流程</b>：3 方协同签名，产出一个聚合签名 (r, s_agg)。
     *
     * <p>流程：
     * <ol>
     *   <li>所有参与方协商同一个随机数 k（简化版，实际协议用 commitments 防作弊）</li>
     *   <li>计算承诺点 R = k · G，r = R.x mod n</li>
     *   <li>每个参与方计算局部签名 s_i = k⁻¹ · (e + r · d_i) mod n</li>
     *   <li>聚合签名 s_agg = Σ s_i mod n</li>
     *   <li>验证：用 P_agg 验签 (r, s_agg)</li>
     * </ol>
     */
    @TraceExecution(value = "多重签名：nonce 生成、部分签名与聚合", algorithm = "MULTISIG",
        flow = "MULTISIG-CORE")
    @Test
    public void multisigSigningProcess()
    {
        int n = 3;
        Tracer.trace("start", new Object[]{"n", n}, "multisig", "start");

        // 1. 生成密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
        }

        // 2. 聚合公钥
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }
        Tracer.trace("keyAgg", new Object[]{"P_agg", pAgg}, pAgg, "keyAgg");

        // 3. 待签消息
        byte[] message = "Multisig message".getBytes();
        BigInteger e = new BigInteger(1, message); // 简化：直接用消息当哈希

        // 4. 协商随机数 k（简化：由第一方生成，实际协议需要 commitments）
        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] rPoint = ecMul(k, GX, GY, P);
        BigInteger r = rPoint[0].mod(N);
        log.info("[签名] 随机数 k = {}...", k.toString(16).substring(0, 16));
        log.info("[签名] 承诺 R = ({}..., {}...)",
            rPoint[0].toString(16).substring(0, 8),
            rPoint[1].toString(16).substring(0, 8));
        log.info("[签名] r = {}...", r.toString(16).substring(0, 8));
        Tracer.traceLoop("nonceGen", new Object[]{"k", k, "R", rPoint}, rPoint,
            "nonceGen", 1, 1, "nonceGen");
        Tracer.trace("nonceAgg", new Object[]{"r", r}, r, "nonceAgg");

        // 5. 每个参与方计算局部签名
        // 关键：e 要被 n 方分摊，否则聚合后 e 会被加 n 次
        BigInteger kInv = k.modInverse(N);
        BigInteger eSplit = e.multiply(BigInteger.valueOf(n).modInverse(N)).mod(N);
        BigInteger[] sPartial = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            // s_i = k⁻¹ · (e/n + r · d_i) mod n，聚合后 = k⁻¹ · (e + r · Σ d_i)
            sPartial[i] = kInv.multiply(eSplit.add(r.multiply(d[i]))).mod(N);
            log.info("[参与方 {}] 局部签名 s_{} = {}...", i + 1, i + 1,
                sPartial[i].toString(16).substring(0, 8));
            Tracer.traceLoop("partialSig", new Object[]{"participant", i + 1,
                "d_i", d[i], "eSplit", eSplit}, sPartial[i], "partialSig",
                i + 1, n, "partialSig");
        }
        Tracer.trace("partialSig", new Object[]{"sPartial", sPartial}, sPartial, "partialSig");

        // 6. 聚合签名：s_agg = Σ s_i mod n
        BigInteger sAgg = BigInteger.ZERO;
        for (int i = 0; i < n; i++)
        {
            sAgg = sAgg.add(sPartial[i]).mod(N);
        }
        log.info("[聚合] s_agg = {}...", sAgg.toString(16).substring(0, 8));
        Tracer.trace("sigAgg", new Object[]{"sAgg", sAgg}, sAgg, "sigAgg");

        // 7. 验证：用 P_agg 验签 (r, s_agg)
        boolean valid = ecdsaVerify(pAgg, e, r, sAgg);
        log.info("[验证] 多重签名验签: {}", valid ? "通过 ✓" : "失败");
        Assert.assertTrue("多重签名验签通过", valid);
        Tracer.traceDecision("verify", new Object[]{"r", r, "sAgg", sAgg}, valid, "verify",
            "聚合签名对 P_agg 验签通过");

        // 8. 对比：聚合签名等价于用 Σ d_i 直接签名
        BigInteger dSum = BigInteger.ZERO;
        for (int i = 0; i < n; i++)
        {
            dSum = dSum.add(d[i]).mod(N);
        }
        // 直接签名：s = k⁻¹ · (e + r · Σ d_i) mod n
        BigInteger sDirect = kInv.multiply(e.add(r.multiply(dSum))).mod(N);
        Assert.assertEquals("聚合签名 = 直接签名", sDirect, sAgg);
        log.info("[对比] 聚合签名 ≡ 用 Σ d_i 直接签名 ✓");
        Tracer.trace("end", new Object[]{"sAgg", sAgg, "sDirect", sDirect}, "multisig", "end");
    }

    /**
     * <b>多重签名的安全性</b>：必须所有 n 方都参与，少一方验签失败。
     */
    @TraceExecution(value = "多重签名协同性：缺少一方验签失败", algorithm = "MULTISIG",
        flow = "MULTISIG-CORE")
    @Test
    public void multisigRequiresAllParties()
    {
        int n = 3;
        Tracer.trace("start", new Object[]{"n", n}, "multisig requires all parties", "start");

        // 1. 生成密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
        }

        // 2. 聚合公钥
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }
        Tracer.trace("keyAgg", new Object[]{"n", n, "P_i", pubPoints}, pAgg, "keyAgg");

        // 3. 待签消息
        byte[] message = "Test".getBytes();
        BigInteger e = new BigInteger(1, message);

        // 4. 随机数 k
        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] rPoint = ecMul(k, GX, GY, P);
        BigInteger r = rPoint[0].mod(N);
        BigInteger kInv = k.modInverse(N);
        Tracer.traceLoop("nonceGen", new Object[]{"k", k, "R", rPoint}, rPoint,
            "nonceGen", 1, 1, "nonceGen");
        Tracer.trace("nonceAgg", new Object[]{"r", r}, r, "nonceAgg");

        // 5. 只有 2 方签名（< n=3）
        BigInteger sPartial = BigInteger.ZERO;
        for (int i = 0; i < 2; i++) // 只签前 2 方
        {
            BigInteger si = kInv.multiply(e.add(r.multiply(d[i]))).mod(N);
            sPartial = sPartial.add(si).mod(N);
            Tracer.traceLoop("partialSig", new Object[]{"participant", i + 1, "d_i", d[i]},
                si, "partialSig", i + 1, n, "partialSig");
        }
        Tracer.trace("sigAgg", new Object[]{"participants", 2, "s", sPartial}, sPartial, "sigAgg");

        // 6. 验签：应该失败
        boolean valid = ecdsaVerify(pAgg, e, r, sPartial);
        log.info("[协同性] 2 方（< n=3）签名验签: {}", valid ? "通过（错误！）" : "失败 ✓");
        Assert.assertFalse("少于 n 方签不出合法多重签名", valid);
        Tracer.traceDecision("verify", new Object[]{"participants", 2, "n", n,
            "s", sPartial}, valid, "verify", "少于 n 方验签必须失败");
        Tracer.trace("end", new Object[]{"participants", 2, "n", n, "s", sPartial}, null, "end");
    }

    /**
     * <b>多重签名 vs 门限签名</b>：对比两者的区别。
     */
    @TraceExecution(value = "多重签名 vs 门限签名：参与门槛与签名长度", algorithm = "MULTISIG",
        flow = "MULTISIG-CORE")
    @Test
    public void compareMultisigAndThreshold()
    {
        Tracer.trace("start", new Object[]{"schemeA", "multisig", "schemeB", "threshold"}, null, "start");
        log.info("[对比] 多重签名 vs 门限签名");
        log.info("[多重签名] n-of-n：所有 n 方都必须参与，少一方不行");
        log.info("[多重签名] 聚合公钥 P_agg = Σ P_i，聚合签名 s_agg = Σ s_i");
        log.info("[多重签名] 签名长度 = 单方签名长度（聚合后）");
        log.info("");
        log.info("[门限签名] t-of-n：任意 t 方参与即可，更灵活");
        log.info("[门限签名] 需要秘密共享，密钥切成 n 份");
        log.info("[门限签名] 签名长度 = 单方签名长度（与门限值 t 无关）");
        log.info("");
        log.info("[结论] 多重签名简单但要求所有方在线；门限签名灵活但需要秘密共享");
        Tracer.trace("keyAgg", new Object[]{"multisig", "P_agg = Σ P_i", "threshold", "公钥由密钥份额导出"},
            "P_agg", "keyAgg");
        Tracer.trace("partialSig", new Object[]{"multisig", "n 方全部参与", "threshold", "任意 t 方参与"},
            "partial signature", "partialSig");
        Tracer.trace("sigAgg", new Object[]{"multisig", "s_agg = Σ s_i", "threshold", "σ = Σ λᵢ·σᵢ"},
            "single-size signature", "sigAgg");
        Tracer.traceDecision("verify", new Object[]{"multisig", "P_agg", "threshold", "完整公钥"},
            true, "verify", "两者都可用一把公钥验证单方长度的签名");
        Tracer.trace("end", new Object[]{"schemes", 2}, null, "end");
    }

    // =====================================================================
    // 辅助方法：椭圆曲线运算
    // =====================================================================

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
            return new BigInteger[0];
        }

        BigInteger lam = y2.subtract(y1).mod(P).multiply(x2.subtract(x1).modInverse(P)).mod(P);
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] ecDouble(BigInteger[] pt)
    {
        if (pt.length == 0) return pt;
        BigInteger x = pt[0], y = pt[1];
        if (y.signum() == 0) return new BigInteger[0];

        BigInteger a = P.subtract(BigInteger.valueOf(3));
        BigInteger num = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a).mod(P);
        BigInteger den = y.multiply(BigInteger.valueOf(2)).mod(P);
        BigInteger lam = num.multiply(den.modInverse(P)).mod(P);
        BigInteger x3 = lam.multiply(lam).subtract(x.multiply(BigInteger.valueOf(2))).mod(P);
        BigInteger y3 = lam.multiply(x.subtract(x3)).subtract(y).mod(P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] ecMul(BigInteger k, BigInteger gx, BigInteger gy, BigInteger mod)
    {
        BigInteger[] result = new BigInteger[0];
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

    private static boolean ecdsaVerify(BigInteger[] pubPoint, BigInteger e, BigInteger r,
        BigInteger s)
    {
        if (r.signum() <= 0 || r.compareTo(N) >= 0) return false;
        if (s.signum() <= 0 || s.compareTo(N) >= 0) return false;

        BigInteger sInv = s.modInverse(N);
        BigInteger u1 = e.multiply(sInv).mod(N);
        BigInteger u2 = r.multiply(sInv).mod(N);

        BigInteger[] r1 = ecMul(u1, GX, GY, P);
        BigInteger[] r2 = ecMul(u2, pubPoint[0], pubPoint[1], P);
        BigInteger[] R = ecAdd(r1, r2);
        if (R.length == 0) return false;

        return R[0].mod(N).equals(r);
    }
}
