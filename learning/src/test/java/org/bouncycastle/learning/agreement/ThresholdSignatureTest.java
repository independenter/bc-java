package org.bouncycastle.learning.agreement;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 门限签名（Threshold Signature）的协议测试 —— 面向过程版，覆盖密钥切割、协同签名、密钥恢复。
 *
 * <p>本文件演示 (t, n)-门限签名的完整协议流程：
 * <ol>
 *   <li><b>密钥生成</b>：生成 SM2 密钥对，用 Shamir 秘密共享把私钥切成 n 份</li>
 *   <li><b>协同签名</b>：t 个参与方各用私钥份额算局部签名，合成完整签名</li>
 *   <li><b>验签</b>：用公钥验签，结果与用完整私钥直接签的相同</li>
 *   <li><b>密钥恢复</b>：t 个参与方用拉格朗日插值恢复私钥</li>
 * </ol>
 *
 * <p>与 {@code ThresholdEssenceTest} 的区别：
 * <ul>
 *   <li>Essence 测试：手写椭圆曲线运算，展示算法本质</li>
 *   <li>Agreement 测试：用 BC 的 JCE API（KeyPairGenerator、Signature）当裁判，验证协议正确性</li>
 * </ul>
 *
 * <p><b>符号表（本文件专用）</b>：
 * <pre>
 *   t          门限值：至少需要 t 个参与方协同签名
 *   n          总参与方数：私钥被切成 n 份
 *   d          SM2 私钥（BigInteger）
 *   d_i        第 i 个参与方的私钥份额（d_i = f(i) mod n，f 是 t−1 次多项式，f(0) = d）
 *   λ_i        拉格朗日系数：λ_i = Π_{j≠i} j / (j − i) mod n
 *   P          SM2 公钥（椭圆曲线点）
 *   sig        SM2 签名（byte[]）
 *   msg        待签消息（byte[]）
 * </pre>
 */
@Slf4j
public class ThresholdSignatureTest
{
    private static final X9ECParameters SM2_CURVE = GMNamedCurves.getByName("sm2p256v1");
    private static final BigInteger SM2_N = SM2_CURVE.getN(); // SM2 曲线的阶（素数）

    @BeforeClass
    public static void setupBc()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // =====================================================================
    // 场景一：(2, 3)-门限签名 —— 3 方里任意 2 方协同可签名
    // =====================================================================

    /**
     * <b>(2, 3)-门限签名的完整流程</b>：
     * <ol>
     *   <li>生成 SM2 密钥对（d, P）</li>
     *   <li>用 SSS 把 d 切成 3 份（d₁, d₂, d₃）</li>
     *   <li>选 2 方（第 1 方和第 3 方）协同签名</li>
     *   <li>用公钥 P 验签，应该通过</li>
     * </ol>
     */
    @Test
    public void thresholdSignature2of3()
        throws Exception
    {
        int t = 2;
        int n = 3;

        // 1. 生成 SM2 密钥对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        byte[] pubBytes = kp.getPublic().getEncoded();
        log.info("[2-of-3] 私钥 d = {}...", d.toString(16).substring(0, 16));

        // 2. 用 SSS 把 d 切成 3 份
        BigInteger[] dShares = splitSecret(d, t, n);
        log.info("[2-of-3] 份额 d₁={}..., d₂={}..., d₃={}...",
            dShares[0].toString(16).substring(0, 8),
            dShares[1].toString(16).substring(0, 8),
            dShares[2].toString(16).substring(0, 8));

        // 3. 选第 1 方和第 3 方协同签名
        int[] signers = {0, 2};
        byte[] message = "Hello, threshold signature!".getBytes();
        byte[] sig = thresholdSign(dShares, signers, message, d.bitLength());
        log.info("[2-of-3] 签名长度 = {} 字节", sig.length);

        // 4. 用公钥验签
        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        boolean valid = verifier.verify(sig);
        log.info("[2-of-3] 验签结果: {}", valid ? "通过 ✓" : "失败");
        Assert.assertTrue("门限签名验签通过", valid);

        // 5. 对比：用完整私钥直接签名，结果应该不同（因为 k 不同），但都合法
        Signature directSigner = Signature.getInstance("SM3withSM2", "BC");
        directSigner.initSign(kp.getPrivate());
        directSigner.update(message);
        byte[] sigDirect = directSigner.sign();
        log.info("[2-of-3] 直接签名长度 = {} 字节", sigDirect.length);

        // 两个签名都合法（但字节不同，因为随机数 k 不同）
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        Assert.assertTrue("直接签名也合法", verifier.verify(sigDirect));
    }

    /**
     * <b>密钥恢复</b>：用 t 个份额恢复私钥 d。
     */
    @Test
    public void thresholdSignatureKeyRecovery()
        throws Exception
    {
        int t = 2;
        int n = 3;

        // 1. 生成密钥并切割
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] dShares = splitSecret(d, t, n);

        // 2. 用第 1 方和第 3 方恢复私钥
        int[] recoverers = {0, 2};
        BigInteger[] selectedShares = new BigInteger[t];
        for (int i = 0; i < t; i++)
        {
            selectedShares[i] = dShares[recoverers[i]];
        }
        BigInteger recovered = recoverSecret(selectedShares, recoverers, d.bitLength());
        log.info("[密钥恢复] 原始 d = {}...", d.toString(16).substring(0, 16));
        log.info("[密钥恢复] 恢复 d = {}...", recovered.toString(16).substring(0, 16));
        Assert.assertEquals("恢复的私钥 = 原始私钥", d, recovered);

        // 3. 用恢复的私钥签名，应该合法
        // 注意：需要用原始公钥 kp.getPublic() 验签，因为恢复的私钥对应的是原始公钥
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
            ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getParameters();
        org.bouncycastle.jce.spec.ECPrivateKeySpec privSpec =
            new org.bouncycastle.jce.spec.ECPrivateKeySpec(recovered, ecSpec);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
        java.security.PrivateKey recoveredKey = kf.generatePrivate(privSpec);

        byte[] message = "Test message".getBytes();
        Signature signer = Signature.getInstance("SM3withSM2", "BC");
        signer.initSign(recoveredKey);
        signer.update(message);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic()); // 用原始公钥验签
        verifier.update(message);
        Assert.assertTrue("恢复的私钥可以签名", verifier.verify(sig));
    }

    /**
     * <b>少于 t 方签不出合法签名</b>：只有 1 方（< t=2）尝试签名，验签失败。
     */
    @Test
    public void thresholdSignatureRequiresTParties()
        throws Exception
    {
        int t = 2;
        int n = 3;

        // 1. 生成密钥并切割
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] dShares = splitSecret(d, t, n);

        // 2. 只有 1 方尝试签名（< t=2）
        int[] insufficientSigners = {0};
        byte[] message = "Test".getBytes();
        byte[] sigPartial = thresholdSign(dShares, insufficientSigners, message, d.bitLength());

        // 3. 验签：应该失败
        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        boolean valid = verifier.verify(sigPartial);
        log.info("[协同性] 1 方（< t=2）签名验签: {}", valid ? "通过（错误！）" : "失败 ✓");
        Assert.assertFalse("少于 t 方签不出合法签名", valid);
    }

    /**
     * <b>(3, 5)-门限签名</b>：5 方里任意 3 方协同可签名。
     */
    @Test
    public void thresholdSignature3of5()
        throws Exception
    {
        int t = 3;
        int n = 5;

        // 1. 生成密钥并切割
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] dShares = splitSecret(d, t, n);
        log.info("[3-of-5] 私钥切成 {} 份，门限 = {}", n, t);

        // 2. 选 3 方协同签名（第 1、3、5 方）
        int[] signers = {0, 2, 4};
        byte[] message = "Multi-party signature".getBytes();
        byte[] sig = thresholdSign(dShares, signers, message, d.bitLength());

        // 3. 验签
        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        boolean valid = verifier.verify(sig);
        log.info("[3-of-5] 验签结果: {}", valid ? "通过 ✓" : "失败");
        Assert.assertTrue("3-of-5 门限签名验签通过", valid);
    }

    // =====================================================================
    // 辅助方法：SSS 切割、恢复、门限签名
    // =====================================================================

    /**
     * Shamir 秘密共享：把秘密 s 切成 n 份，门限为 t。
     *
     * @param s         秘密（BigInteger）
     * @param t         门限值
     * @param n         总份额数
     * @return n 个份额（BigInteger 数组）
     */
    private static BigInteger[] splitSecret(BigInteger s, int t, int n)
    {
        // 使用 SM2 曲线的阶作为模数（保证是素数）
        BigInteger modulus = SM2_N;
        
        // 确保秘密小于模数
        s = s.mod(modulus);

        // 构造 t−1 次多项式：f(x) = s + a₁x + a₂x² + … (mod modulus)
        BigInteger[] coeffs = new BigInteger[t];
        coeffs[0] = s;
        SecureRandom rng = new SecureRandom();
        for (int i = 1; i < t; i++)
        {
            coeffs[i] = new BigInteger(256, rng).mod(modulus);
        }

        // 在 x = 1, 2, …, n 处求值
        BigInteger[] shares = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            BigInteger x = BigInteger.valueOf(i + 1);
            shares[i] = polyEval(coeffs, x, modulus);
        }
        return shares;
    }

    /**
     * 拉格朗日恢复：用 t 个份额恢复秘密。
     *
     * @param shares    t 个份额
     * @param indices   份额的索引（0-based）
     * @param keyBits   密钥位宽（用于确定模数）
     * @return 恢复的秘密
     */
    private static BigInteger recoverSecret(BigInteger[] shares, int[] indices, int keyBits)
    {
        // 使用 SM2 曲线的阶作为模数
        BigInteger modulus = SM2_N;
        
        BigInteger[] xs = new BigInteger[shares.length];
        for (int i = 0; i < shares.length; i++)
        {
            xs[i] = BigInteger.valueOf(indices[i] + 1);
        }
        return lagrangeInterpolateAtZero(xs, shares, modulus);
    }

    /**
     * 门限签名：用指定的参与方份额协同签名。
     *
     * <p>简化实现：用恢复的私钥直接签名（实际协议应该用局部签名合成）。
     * 这里只是为了演示协议流程，真正的门限签名协议（如 GG18/GG20）更复杂。
     *
     * @param dShares   所有份额
     * @param signers   参与签名的参与方索引
     * @param message   待签消息
     * @param keyBits   密钥位宽
     * @return 签名（byte[]）
     */
    private static byte[] thresholdSign(BigInteger[] dShares, int[] signers, byte[] message,
        int keyBits)
        throws Exception
    {
        // 简化：先恢复私钥，再用它签名
        BigInteger[] selectedShares = new BigInteger[signers.length];
        for (int i = 0; i < signers.length; i++)
        {
            selectedShares[i] = dShares[signers[i]];
        }
        BigInteger recovered = recoverSecret(selectedShares, signers, keyBits);

        // 用恢复的私钥签名
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
            ((org.bouncycastle.jce.interfaces.ECPrivateKey) kp.getPrivate()).getParameters();
        org.bouncycastle.jce.spec.ECPrivateKeySpec privSpec =
            new org.bouncycastle.jce.spec.ECPrivateKeySpec(recovered, ecSpec);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
        java.security.PrivateKey privKey = kf.generatePrivate(privSpec);

        Signature signer = Signature.getInstance("SM3withSM2", "BC");
        signer.initSign(privKey);
        signer.update(message);
        return signer.sign();
    }

    /**
     * 多项式求值：f(x) = coeffs[0] + coeffs[1]·x + coeffs[2]·x² + … (mod modulus)
     */
    private static BigInteger polyEval(BigInteger[] coeffs, BigInteger x, BigInteger modulus)
    {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE;
        for (int i = 0; i < coeffs.length; i++)
        {
            result = result.add(coeffs[i].multiply(xPow)).mod(modulus);
            xPow = xPow.multiply(x).mod(modulus);
        }
        return result;
    }

    /**
     * 拉格朗日插值在 x=0 处的值：f(0) = Σ y_i · λ_i (mod modulus)
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
                    BigInteger num = xs[j];
                    BigInteger den = xs[j].subtract(xs[i]).mod(modulus);
                    lambda = lambda.multiply(num).multiply(den.modInverse(modulus)).mod(modulus);
                }
            }
            result = result.add(ys[i].multiply(lambda)).mod(modulus);
        }
        return result;
    }
}
