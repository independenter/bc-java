package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.junit.Assert;
import org.junit.Test;

/**
 * 交互式协同签名（Interactive Collaborative Signature）的本质计算 —— 面向过程版。
 *
 * <p>三种"多方签名"方案的本质区别：
 * <ul>
 *   <li><b>门限签名 (t, n)</b>：用 Shamir 秘密共享把私钥切成 n 份，任意 t 份可恢复私钥并签名；
 *       签名过程中私钥会被重构（虽然只在内存里短暂存在）。</li>
 *   <li><b>多重签名 (n, n)</b>：每个参与方有自己的密钥对，聚合公钥 P_agg = Σ P_i，
 *       签名时所有方共用同一个随机数 k，各自计算局部签名后聚合；需要秘密分发 e/n。</li>
 *   <li><b>交互式协同签名</b>：每个参与方有自己的密钥对，<b>私钥从不离开本地</b>；
 *       通过多轮交互（承诺 → 响应）协同产出一张标准签名；验证时用聚合公钥验一次即可。</li>
 * </ul>
 *
 * <p>本类实现<b>基于 Schnorr 签名的 2 方交互式协同签名协议</b>（可推广到 n 方）：
 * <ol>
 *   <li><b>密钥生成</b>：参与方 i 生成 (d_i, P_i = d_i · G)，公开 P_i</li>
 *   <li><b>聚合公钥</b>：P_agg = P_1 + P_2 + … + P_n（椭圆曲线点加）</li>
 *   <li><b>签名第 1 轮（承诺）</b>：参与方 i 生成随机数 k_i，计算 R_i = k_i · G，广播 R_i</li>
 *   <li><b>签名第 2 轮（响应）</b>：
 *       <ul>
 *         <li>所有方计算 R = R_1 + R_2 + … + R_n</li>
 *         <li>所有方计算挑战 e = SM3(R ‖ P_agg ‖ m)（Fiat-Shamir 哈希）</li>
 *         <li>参与方 i 计算 s_i = k_i + e · d_i mod n（私钥 d_i 永远不离开本地！）</li>
 *         <li>广播 s_i</li>
 *       </ul>
 *   </li>
 *   <li><b>聚合签名</b>：s = s_1 + s_2 + … + s_n mod n，签名 = (R, s)</li>
 *   <li><b>验证</b>：检查 s · G == R + e · P_agg（标准 Schnorr 验签）</li>
 * </ol>
 *
 * <p><b>安全性关键</b>：
 * <ul>
 *   <li>私钥 d_i 永远不离开本地（不像门限签名需要重构私钥）</li>
 *   <li>随机数 k_i 每个参与方独立生成（不像多重签名共用 k）</li>
 *   <li>承诺 R_i 必须先广播，再计算挑战 e（防止 k_i 被操控）</li>
 *   <li>挑战 e 绑定 R、P_agg、m 三者（Fiat-Shamir 变换，防伪造）</li>
 * </ul>
 *
 * <p><b>符号表 —— 全类公式共享的字母/记号</b>
 * <pre>
 *   n          参与方总数（本类固定 n=2 演示，协议可推广）
 *   d_i        第 i 个参与方的私钥（BigInteger，永远不离开本地）
 *   P_i        第 i 个参与方的公钥（椭圆曲线点，P_i = d_i · G）
 *   P_agg      聚合公钥：P_agg = P_1 + P_2 + … + P_n
 *   k_i        第 i 个参与方的一次性随机数（本地生成，不广播）
 *   R_i        第 i 个参与方的承诺点：R_i = k_i · G（第 1 轮广播）
 *   R          聚合承诺：R = R_1 + R_2 + … + R_n
 *   m          待签消息（byte[]）
 *   e          挑战值：e = SM3(R ‖ P_agg ‖ m)（Fiat-Shamir 哈希）
 *   s_i        第 i 个参与方的响应：s_i = k_i + e · d_i mod n（第 2 轮广播）
 *   s          聚合签名值：s = s_1 + s_2 + … + s_n mod n
 *   sig        协同签名：(R, s)
 * </pre>
 *
 * <p><b>术语一行定义</b>：
 * <b>交互式协同签名 (interactive collaborative signature)</b> = 多方通过多轮交互协同产出签名，
 * 私钥从不离开本地；<b>承诺 (commitment)</b> = 第 1 轮广播的 R_i，绑定 k_i 但不泄露；
 * <b>响应 (response)</b> = 第 2 轮广播的 s_i，结合挑战和私钥；<b>Fiat-Shamir 变换</b> =
 * 用哈希函数把交互式证明变成非交互式（挑战 e = Hash(承诺 ‖ 公钥 ‖ 消息)）；
 * <b>Schnorr 签名</b> = 基于离散对数的签名方案，签名 = (R, s)，验证 s·G == R + e·P。
 */
@Slf4j
public class InteractiveCollaborativeSignatureEssenceTest
{
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
     * <b>协同签名的密钥生成</b>：每个参与方独立生成密钥对，然后聚合公钥。
     *
     * <p>流程：
     * <ol>
     *   <li>参与方 i 生成私钥 d_i（本地保存，不广播），计算公钥 P_i = d_i · G</li>
     *   <li>广播 P_i，所有方计算聚合公钥 P_agg = P_1 + P_2 + … + P_n</li>
     *   <li>P_agg 是公开的，任何人都可以用它验签</li>
     * </ol>
     *
     * <p>关键点：私钥 d_i 永远不离开本地（不像门限签名需要切割和重构）。
     */
    @Test
    public void collaborativeKeyGeneration()
    {
        int n = 2; // 2 个参与方

        // 1. 每个参与方生成密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
            log.info("[参与方 {}] 私钥 d_{} = {}... (本地保存，不广播)", i + 1, i + 1,
                d[i].toString(16).substring(0, 16));
            log.info("[参与方 {}] 公钥 P_{} = ({}..., {}...) (广播)", i + 1, i + 1,
                pubPoints[i][0].toString(16).substring(0, 8),
                pubPoints[i][1].toString(16).substring(0, 8));
        }

        // 2. 聚合公钥：P_agg = P_1 + P_2
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }
        log.info("[聚合] P_agg = ({}..., {}...)",
            pAgg[0].toString(16).substring(0, 8),
            pAgg[1].toString(16).substring(0, 8));

        // 3. 验证：P_agg = (d_1 + d_2) · G
        BigInteger dSum = d[0].add(d[1]).mod(N);
        BigInteger[] pAggCheck = ecMul(dSum, GX, GY, P);
        Assert.assertArrayEquals("P_agg = (d_1 + d_2) · G", pAgg, pAggCheck);
        log.info("[验证] P_agg = (Σ d_i) · G ✓");
        log.info("[安全] 私钥 d_i 永远不离开本地，只有公钥 P_i 被广播");
    }

    // =====================================================================
    // 第二层：交互式协同签名流程（2 轮）
    // =====================================================================

    /**
     * <b>2 方交互式协同签名的完整流程</b>：2 轮交互，产出标准 Schnorr 签名 (R, s)。
     *
     * <p>流程：
     * <ol>
     *   <li><b>第 1 轮（承诺）</b>：参与方 i 生成随机数 k_i，计算 R_i = k_i · G，广播 R_i</li>
     *   <li><b>第 2 轮（响应）</b>：
     *       <ul>
     *         <li>所有方计算 R = R_1 + R_2</li>
     *         <li>所有方计算挑战 e = SM3(R ‖ P_agg ‖ m)</li>
     *         <li>参与方 i 计算 s_i = k_i + e · d_i mod n（私钥 d_i 本地使用，不广播）</li>
     *         <li>广播 s_i</li>
     *       </ul>
     *   </li>
     *   <li><b>聚合</b>：s = s_1 + s_2 mod n，签名 = (R, s)</li>
     *   <li><b>验证</b>：s · G == R + e · P_agg（标准 Schnorr 验签）</li>
     * </ol>
     *
     * <p>关键点：
     * <ul>
     *   <li>私钥 d_i 永远不离开本地（第 2 轮在本地计算 s_i）</li>
     *   <li>随机数 k_i 每个参与方独立生成（不共用，不像多重签名）</li>
     *   <li>承诺 R_i 必须先广播，再计算挑战 e（防止 k_i 被操控）</li>
     * </ul>
     */
    @Test
    public void interactiveCollaborativeSigning()
    {
        int n = 2;

        // 0. 准备密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
        }
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }

        // 待签消息
        byte[] message = "Collaborative signature".getBytes();
        log.info("[消息] m = \"{}\"", new String(message));

        // =================================================================
        // 第 1 轮：承诺（Commitment）
        // =================================================================
        log.info("");
        log.info("=== 第 1 轮：承诺 ===");

        // 每个参与方生成随机数 k_i（本地保存，不广播）
        BigInteger[] k = new BigInteger[n];
        BigInteger[][] rPoints = new BigInteger[n][];
        for (int i = 0; i < n; i++)
        {
            k[i] = new BigInteger(256, new SecureRandom()).mod(N);
            rPoints[i] = ecMul(k[i], GX, GY, P);
            log.info("[参与方 {}] 随机数 k_{} = {}... (本地保存)", i + 1, i + 1,
                k[i].toString(16).substring(0, 16));
            log.info("[参与方 {}] 承诺 R_{} = ({}..., {}...) (广播)", i + 1, i + 1,
                rPoints[i][0].toString(16).substring(0, 8),
                rPoints[i][1].toString(16).substring(0, 8));
        }

        // 聚合承诺：R = R_1 + R_2
        BigInteger[] R = rPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            R = ecAdd(R, rPoints[i]);
        }
        log.info("[聚合] R = ({}..., {}...)",
            R[0].toString(16).substring(0, 8),
            R[1].toString(16).substring(0, 8));

        // =================================================================
        // 第 2 轮：响应（Response）
        // =================================================================
        log.info("");
        log.info("=== 第 2 轮：响应 ===");

        // 所有方计算挑战 e = SM3(R ‖ P_agg ‖ m)
        BigInteger e = computeChallenge(R, pAgg, message);
        log.info("[挑战] e = SM3(R ‖ P_agg ‖ m) = {}...", e.toString(16).substring(0, 16));

        // 每个参与方计算响应 s_i = k_i + e · d_i mod n（私钥 d_i 本地使用）
        BigInteger[] sPartial = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            sPartial[i] = k[i].add(e.multiply(d[i])).mod(N);
            log.info("[参与方 {}] 响应 s_{} = k_{} + e · d_{} = {}... (广播)", i + 1, i + 1,
                i + 1, i + 1, sPartial[i].toString(16).substring(0, 8));
            log.info("[参与方 {}] 私钥 d_{} 始终在本地，未广播 ✓", i + 1, i + 1);
        }

        // 聚合签名值：s = s_1 + s_2 mod n
        BigInteger s = BigInteger.ZERO;
        for (int i = 0; i < n; i++)
        {
            s = s.add(sPartial[i]).mod(N);
        }
        log.info("[聚合] s = s_1 + s_2 = {}...", s.toString(16).substring(0, 8));

        // =================================================================
        // 验证：s · G == R + e · P_agg
        // =================================================================
        log.info("");
        log.info("=== 验证 ===");

        boolean valid = schnorrVerify(pAgg, message, R, s);
        log.info("[验证] s · G == R + e · P_agg: {}", valid ? "通过 ✓" : "失败");
        Assert.assertTrue("协同签名验签通过", valid);

        // 签名 = (R, s)，与单方 Schnorr 签名格式完全一致
        log.info("[签名] 协同签名 = (R, s)，长度与单方签名相同");
        log.info("[安全] 整个过程中私钥 d_i 永远不离开本地");
    }

    // =====================================================================
    // 第三层：安全性验证
    // =====================================================================

    /**
     * <b>协同签名的安全性</b>：缺少任意一方的承诺或响应，验签失败。
     */
    @Test
    public void collaborativeSignatureRequiresAllParties()
    {
        int n = 2;

        // 0. 准备密钥对
        BigInteger[] d = new BigInteger[n];
        BigInteger[][] pubPoints = new BigInteger[n][2];
        for (int i = 0; i < n; i++)
        {
            d[i] = new BigInteger(256, new SecureRandom()).mod(N);
            pubPoints[i] = ecMul(d[i], GX, GY, P);
        }
        BigInteger[] pAgg = pubPoints[0].clone();
        for (int i = 1; i < n; i++)
        {
            pAgg = ecAdd(pAgg, pubPoints[i]);
        }

        byte[] message = "Test".getBytes();

        // 1. 只有第 1 方生成承诺（缺少第 2 方）
        BigInteger k1 = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] R1 = ecMul(k1, GX, GY, P);

        // 2. 用 R1 代替 R（没有聚合第 2 方的承诺）
        BigInteger e = computeChallenge(R1, pAgg, message);

        // 3. 只有第 1 方计算响应
        BigInteger s1 = k1.add(e.multiply(d[0])).mod(N);

        // 4. 验签：应该失败（因为 R ≠ R1 + R2）
        boolean valid = schnorrVerify(pAgg, message, R1, s1);
        log.info("[协同性] 只有 1 方（< n=2）参与，验签: {}", valid ? "通过（错误！）" : "失败 ✓");
        Assert.assertFalse("少于 n 方签不出合法协同签名", valid);
    }

    /**
     * <b>三种"多方签名"方案对比</b>：门限签名 vs 多重签名 vs 交互式协同签名。
     */
    @Test
    public void compareThreeSchemes()
    {
        log.info("[对比] 门限签名 vs 多重签名 vs 交互式协同签名");
        log.info("");
        log.info("[门限签名 (t, n)]");
        log.info("  - 任意 t 方参与即可，更灵活");
        log.info("  - 需要 Shamir 秘密共享，私钥被切成 n 份");
        log.info("  - 签名时需要重构私钥（虽然短暂，但存在风险）");
        log.info("  - 签名长度 = 单方签名长度");
        log.info("");
        log.info("[多重签名 (n, n)]");
        log.info("  - 所有 n 方都必须参与，少一方不行");
        log.info("  - 聚合公钥 P_agg = Σ P_i，聚合签名 s_agg = Σ s_i");
        log.info("  - 所有方共用同一个随机数 k（需要 commitments 防作弊）");
        log.info("  - 签名长度 = 单方签名长度");
        log.info("");
        log.info("[交互式协同签名]");
        log.info("  - 所有 n 方都必须参与（2 轮交互）");
        log.info("  - 私钥永远不离开本地（最安全）");
        log.info("  - 每个参与方独立生成随机数 k_i（不共用）");
        log.info("  - 签名长度 = 单方签名长度（标准 Schnorr 格式）");
        log.info("");
        log.info("[结论]");
        log.info("  - 灵活性：门限签名 > 多重签名 = 交互式协同签名");
        log.info("  - 安全性：交互式协同签名 > 门限签名 > 多重签名");
        log.info("  - 通信轮数：门限签名(1轮) < 多重签名(1轮) < 交互式协同签名(2轮)");
    }

    // =====================================================================
    // 辅助方法
    // =====================================================================

    /**
     * 计算挑战 e = SM3(R ‖ P_agg ‖ m)。
     */
    private static BigInteger computeChallenge(BigInteger[] R, BigInteger[] pAgg, byte[] message)
    {
        SM3Digest digest = new SM3Digest();

        // R 的 x, y 坐标（32 字节大端）
        byte[] rx = toBytes32(R[0]);
        byte[] ry = toBytes32(R[1]);
        digest.update(rx, 0, rx.length);
        digest.update(ry, 0, ry.length);

        // P_agg 的 x, y 坐标
        byte[] px = toBytes32(pAgg[0]);
        byte[] py = toBytes32(pAgg[1]);
        digest.update(px, 0, px.length);
        digest.update(py, 0, py.length);

        // 消息
        digest.update(message, 0, message.length);

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return new BigInteger(1, hash).mod(N);
    }

    /**
     * Schnorr 验签：检查 s · G == R + e · P_agg。
     */
    private static boolean schnorrVerify(BigInteger[] pAgg, byte[] message,
        BigInteger[] R, BigInteger s)
    {
        // 计算挑战 e
        BigInteger e = computeChallenge(R, pAgg, message);

        // 左边：s · G
        BigInteger[] left = ecMul(s, GX, GY, P);

        // 右边：R + e · P_agg
        BigInteger[] ePagg = ecMul(e, pAgg[0], pAgg[1], P);
        BigInteger[] right = ecAdd(R, ePagg);

        // 检查 left == right
        if (left.length == 0 && right.length == 0) return true;
        if (left.length == 0 || right.length == 0) return false;
        return left[0].equals(right[0]) && left[1].equals(right[1]);
    }

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

    /**
     * 把 BigInteger 转成 32 字节大端（SM2 曲线坐标固定 32 字节）。
     */
    private static byte[] toBytes32(BigInteger val)
    {
        byte[] bytes = val.toByteArray();
        if (bytes.length == 32)
        {
            return bytes;
        }
        else if (bytes.length > 32)
        {
            // 去掉前导 0
            byte[] result = new byte[32];
            System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
            return result;
        }
        else
        {
            // 补前导 0
            byte[] result = new byte[32];
            System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
            return result;
        }
    }
}
