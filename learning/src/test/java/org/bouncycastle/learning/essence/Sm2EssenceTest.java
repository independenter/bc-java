package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.junit.Assert;
import org.junit.Test;

/**
 * SM2（GM/T 0003）的本质计算 —— 面向过程版。
 *
 * <p>椭圆曲线在这里<b>不是对象</b>：一个点就是 {@code BigInteger[]{x, y}}，无穷远点就是空数组。
 * 于是整条曲线只是一组普通静态方法，参数都是实打实的数，循环用 {@code for}/{@code while}：
 * <pre>
 *   add(p, q)            弦的斜率 λ = (y₂-y₁)/(x₂-x₁)
 *   doublePoint(p)       切线的斜率 λ = (3x²+a)/(2y)（来自导数）
 *   mul(k, point)        按位 double-and-add：从最高位往下 for 循环，先 double、再按位 add
 *   sm2Sign(d, e, k)     r=(e+x₁) mod n, s=(1+d)⁻¹(k-rd) mod n
 *   sm2Verify(pub, e, rs) (x₁,y₁) = sG + tP, t=(r+s) mod n, 检查 (e+x₁) mod n == r
 * </pre>
 * 算法模式（C1C2C3 / C1C3C2）只是"三段字节的不同排列"，KDF 是 SM3 的计数器 while 循环。
 * 哈希复用 {@link Sm3EssenceTest} 里我们自己写的那个面向过程 SM3 —— 一个方法调另一个方法，仅此而已。
 *
 * <p>文件后半部分是<b>"随机数 k 为什么必须真随机"</b>的推导与攻击：签名式子对 d 只有一次方程
 * {@code d = (k - s)·(r + s)⁻¹ mod n}，所以 k 可预测、有规律、或值域偏窄，都会线性成本地算出私钥。
 * 详见 {@link #privateKeyFromKnownK} 与 {@link #privateKeyFromKnownDelta} 两处注释。
 */
@Slf4j
public class Sm2EssenceTest
{
    /** 曲线常数（GM/T 0003.5 的 sm2p256v1）；下面有一个测试专门拿 BC 的官方常数核对。 */
    private static final BigInteger P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    private static final BigInteger B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    private static final BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

    private static final byte[] DEFAULT_ID = "1234567812345678".getBytes();
    private static final int KEY_BYTES = 32;

    /** 无穷远点（单位元）= 空数组。点从此只是数据。 */
    private static final BigInteger[] INFINITY = new BigInteger[0];

    private static final BigInteger[] G = new BigInteger[]{ GX, GY };

    /** SM3 直接调用本模块自己写的那个过程版实现。 */
    private static byte[] sm3(byte[] msg)
    {
        return Sm3EssenceTest.sm3(msg);
    }

    /** 模 p 归一化，保证结果落在 [0, p)。 */
    private static BigInteger modP(BigInteger x)
    {
        return x.mod(P);
    }

    /** 求逆：椭圆曲线里唯一的"贵"运算，就是模逆（扩展欧几里得）。 */
    private static BigInteger inverse(BigInteger v)
    {
        return v.mod(P).modInverse(P);
    }

    /** 点在曲线上吗？ y² ≡ x³ + ax + b (mod p)。这是一个返回 boolean 的普通方法，不是对象方法。 */
    private static boolean onCurve(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return true;                                   // 无穷远点按约定在曲线上
        }
        BigInteger lhs = modP(pt[1].multiply(pt[1]));
        BigInteger rhs = modP(pt[0].multiply(pt[0]).multiply(pt[0]).add(A.multiply(pt[0])).add(B));
        return lhs.equals(rhs);
    }

    /** 取负点：y -> -y，返回新数组。 */
    private static BigInteger[] negate(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return pt;
        }
        return new BigInteger[]{ pt[0], modP(pt[1].negate()) };
    }

    /** 倍点：弦切线的斜率 λ = (3x²+a)/(2y) 来自导数 3x²+a。 */
    private static BigInteger[] doublePoint(BigInteger[] pt)
    {
        if (pt.length == 0 || modP(pt[1].shiftLeft(1)).signum() == 0)
        {
            return INFINITY;
        }
        BigInteger lam = modP(pt[0].multiply(pt[0]).multiply(BigInteger.valueOf(3)).add(A))
            .multiply(inverse(pt[1].shiftLeft(1))).mod(P);
        BigInteger x = modP(lam.multiply(lam).subtract(pt[0]).subtract(pt[0]));
        BigInteger y = modP(lam.multiply(pt[0].subtract(x)).subtract(pt[1]));
        return new BigInteger[]{ x, y };
    }

    /** 加法：普通静态方法，返回新数组；相消情况返回单位元。 */
    private static BigInteger[] add(BigInteger[] p, BigInteger[] q)
    {
        if (p.length == 0)
        {
            return q;
        }
        if (q.length == 0)
        {
            return p;
        }
        if (p[0].equals(q[0]))
        {
            return modP(p[1].add(q[1])).signum() == 0 ? INFINITY : doublePoint(p);
        }
        BigInteger lam = modP(q[1].subtract(p[1])).multiply(inverse(modP(q[0].subtract(p[0])))).mod(P);
        BigInteger x = modP(lam.multiply(lam).subtract(p[0]).subtract(q[0]));
        BigInteger y = modP(lam.multiply(p[0].subtract(x)).subtract(p[1]));
        return new BigInteger[]{ x, y };
    }

    /** 标量乘 = 逐位扫描的 for 循环（从最高位往下：先 double，再按位 add）。这就是"倍加算法"的本质。 */
    private static BigInteger[] mul(BigInteger k, BigInteger[] point)
    {
        BigInteger[] acc = INFINITY;                       // 局部变量当累加器，一目了然
        for (int j = 0; j < k.bitLength(); j++)
        {
            int bit = k.bitLength() - 1 - j;               // 从最高位开始
            BigInteger[] doubled = doublePoint(acc);
            if (k.testBit(bit))
            {
                acc = add(doubled, point);
            }
            else
            {
                acc = doubled;
            }
        }
        return acc;
    }

    /** ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)：SM2 把"身份"绑进哈希的那一步。 */
    private static byte[] za(byte[] userId, BigInteger[] pub)
    {
        byte[] entl = Calc.toBytes(BigInteger.valueOf(8L * userId.length), 2);
        return sm3(Calc.concat(entl, userId,
            Calc.toBytes(A, KEY_BYTES), Calc.toBytes(B, KEY_BYTES),
            Calc.toBytes(GX, KEY_BYTES), Calc.toBytes(GY, KEY_BYTES),
            Calc.toBytes(pub[0], KEY_BYTES), Calc.toBytes(pub[1], KEY_BYTES)));
    }

    /** e = SM3(ZA ‖ M) 转成大整数 —— SM2 的"消息摘要"其实只有这一行。 */
    private static BigInteger eValue(byte[] za, byte[] message)
    {
        return Calc.toBigInt(sm3(Calc.concat(za, message)));
    }

    /**
     * 签名：{@code sm2Sign(d, e, k)} 返回 {@code {r, s}}。
     * r = (e + x₁) mod n，s = (1+d)⁻¹ (k - r·d) mod n —— 三个实参一个返回数组，没有任何"函数套函数"。
     */
    private static BigInteger[] sm2Sign(BigInteger d, BigInteger e, BigInteger k)
    {
        BigInteger x1 = mul(k, G)[0];                       // (x₁,y₁) = kG，只需要 x₁
        BigInteger r = modN(e.add(x1));
        Assert.assertTrue("r 不能为 0（k 需重试）", r.signum() != 0);
        BigInteger s = modN(k.subtract(r.multiply(d)).multiply(BigInteger.ONE.add(d).modInverse(N)));
        Assert.assertTrue("r + k 不能等于 n（k 需重试）", modN(r.add(k)).signum() != 0);
        return new BigInteger[]{ r, s };
    }

    /**
     * 验签：{@code sm2Verify(pub, e, rs)} 返回 boolean。
     * t = (r+s) mod n，(x₁,y₁) = sG + tP，检查 (e+x₁) mod n == r。
     */
    private static boolean sm2Verify(BigInteger[] pub, BigInteger e, BigInteger[] rs)
    {
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(N) >= 0 || s.compareTo(N) >= 0)
        {
            return false;
        }
        BigInteger t = modN(r.add(s));
        if (t.signum() == 0)
        {
            return false;
        }
        BigInteger[] point = add(mul(s, G), mul(t, pub));
        if (point.length == 0)
        {
            return false;
        }
        return modN(e.add(point[0])).equals(r);
    }

    private static BigInteger modN(BigInteger x)
    {
        return x.mod(N);
    }

    /** KDF（SM3 计数器流）：加密里把共享点坐标变成密钥流的过程 —— 一个 while 循环逐块填充。 */
    private static byte[] kdfSm3(byte[] z, int klen)
    {
        byte[] out = new byte[klen];
        int off = 0;
        int counter = 1;                                    // 计数器从 1 开始，每轮出 32 字节
        while (off < klen)
        {
            byte[] stream = sm3(Calc.concat(z, Calc.toBytes(BigInteger.valueOf(counter), 4)));
            int take = Math.min(klen - off, stream.length);
            System.arraycopy(stream, 0, out, off, take);
            off += take;
            counter++;
        }
        return out;
    }

    /**
     * SM2 加密：{@code sm2Encrypt(pub, c1c3c2, k, plaintext)} 返回密文。
     * C1 = kG（04‖x‖y），共享点 kP=(x₂,y₂)，密钥流 = KDF(x₂‖y₂)，C2 = M ⊕ 流，C3 = SM3(x₂‖M‖y₂)。
     * mode = C1C2C3 / C1C3C2 只决定 C2、C3 的排列顺序 —— 这就是"算法模式"的全部差异。
     */
    private static byte[] sm2Encrypt(BigInteger[] pub, boolean c1c3c2, BigInteger k, byte[] plaintext)
    {
        BigInteger[] c1Point = mul(k, G);
        BigInteger[] shared = mul(k, pub);
        byte[] x2 = Calc.toBytes(shared[0], KEY_BYTES);
        byte[] y2 = Calc.toBytes(shared[1], KEY_BYTES);
        byte[] c1 = Calc.concat(new byte[]{ 0x04 }, Calc.toBytes(c1Point[0], KEY_BYTES), Calc.toBytes(c1Point[1], KEY_BYTES));
        byte[] c2 = Calc.xor(plaintext, kdfSm3(Calc.concat(x2, y2), plaintext.length));
        byte[] c3 = sm3(Calc.concat(x2, plaintext, y2));
        return c1c3c2 ? Calc.concat(c1, c3, c2) : Calc.concat(c1, c2, c3);
    }

    /** SM2 解密：{@code sm2Decrypt(d, c1c3c2, ciphertext)} 返回明文，并重新校验 C3（认证性来自这里）。 */
    private static byte[] sm2Decrypt(BigInteger d, boolean c1c3c2, byte[] ciphertext)
    {
        BigInteger[] c1Point = new BigInteger[]{
            Calc.toBigInt(Arrays.copyOfRange(ciphertext, 1, 1 + KEY_BYTES)),
            Calc.toBigInt(Arrays.copyOfRange(ciphertext, 1 + KEY_BYTES, 1 + 2 * KEY_BYTES)) };
        byte[] c3 = c1c3c2
            ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, 1 + 2 * KEY_BYTES + 32)
            : Arrays.copyOfRange(ciphertext, ciphertext.length - 32, ciphertext.length);
        byte[] c2 = c1c3c2
            ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES + 32, ciphertext.length)
            : Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, ciphertext.length - 32);

        BigInteger[] shared = mul(d, c1Point);
        byte[] x2 = Calc.toBytes(shared[0], KEY_BYTES);
        byte[] y2 = Calc.toBytes(shared[1], KEY_BYTES);
        byte[] plaintext = Calc.xor(c2, kdfSm3(Calc.concat(x2, y2), c2.length));
        Assert.assertArrayEquals("C3 校验失败：密文被篡改", c3, sm3(Calc.concat(x2, plaintext, y2)));
        return plaintext;
    }

    // ---------------------------------------------------------------- 测试

    /** 曲线常数必须等于国家标准的 sm2p256v1；顺便验证 G 在曲线上、n 是它的阶。 */
    @Test
    public void curveConstantsAreTheStandardCurve()
    {
        X9ECParameters std = GMNamedCurves.getByName("sm2p256v1");
        Assert.assertEquals("p 必须与标准一致", std.getCurve().getField().getCharacteristic(), P);
        Assert.assertEquals("a 必须与标准一致", modP(std.getCurve().getA().toBigInteger()), A);
        Assert.assertEquals("b 必须与标准一致", modP(std.getCurve().getB().toBigInteger()), B);
        Assert.assertEquals("n 必须与标准一致", std.getN(), N);
        Assert.assertEquals("Gx 必须与标准一致", std.getG().getAffineXCoord().toBigInteger(), GX);
        Assert.assertEquals("Gy 必须与标准一致", std.getG().getAffineYCoord().toBigInteger(), GY);
        Assert.assertTrue("生成元必须在曲线上", onCurve(G));
        Assert.assertEquals("n 必须是 G 的阶：nG = 无穷远点", 0, mul(N, G).length);
        Assert.assertArrayEquals("(n+1)G = G", G, mul(N.add(BigInteger.ONE), G));
        log.info("[SM2-曲线] p={} a={} n 阶检验通过", P.toString(16).substring(0, 8) + "…");
    }

    /** 群律：交换律、结合律、倍点=自加、标量乘的分配律 —— 全部由普通静态方法验证。 */
    @Test
    public void ecPointArithmeticFormsAnAbelianGroup()
    {
        BigInteger k1 = new BigInteger("1234567890123456789012345678901234567890");
        BigInteger k2 = new BigInteger("9876543210987654321098765432109876543210");

        Assert.assertArrayEquals("加法交换律", add(mul(k1, G), mul(k2, G)), add(mul(k2, G), mul(k1, G)));
        Assert.assertArrayEquals("倍点 == 自加", doublePoint(G), add(G, G));
        Assert.assertArrayEquals("(k1+k2)G == k1G + k2G", mul(k1.add(k2), G), add(mul(k1, G), mul(k2, G)));
        Assert.assertArrayEquals("(k1·k2)G == k1(k2G)", mul(k1.multiply(k2), G), mul(k1, mul(k2, G)));
        Assert.assertArrayEquals("P + (-P) = 单位元", INFINITY, add(mul(k1, G), negate(mul(k1, G))));
        Assert.assertArrayEquals("单位元是恒等", mul(k1, G), add(INFINITY, mul(k1, G)));
        Assert.assertTrue("任意标量乘的结果仍在曲线上", onCurve(mul(k2, G)));
        log.info("[SM2-群律] 6 条群公理全部由普通静态方法验证通过");
    }

    /** 用 BC 生成的私钥 d，我们手写的过程版标量乘必须算出同一个公钥点。 */
    @Test
    public void ourPureScalarMulRebuildsBcPublicKey()
        throws Exception
    {
        Calc.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        org.bouncycastle.math.ec.ECPoint q = ((ECPublicKey) kp.getPublic()).getQ();
        BigInteger[] ours = mul(d, G);

        Assert.assertEquals("我们的 x₁ == BC 的仿射 x", modP(q.getAffineXCoord().toBigInteger()), ours[0]);
        Assert.assertEquals("我们的 y₁ == BC 的仿射 y", modP(q.getAffineYCoord().toBigInteger()), ours[1]);
        log.info("[SM2-本质] dG 由 for 循环的倍加算法独立算出，与 BC 完全一致：x={}", Calc.hex(Calc.toBytes(ours[0], 32)));
    }

    /** 签名的本质：我们的 (r,s) 能被 BC 验签，BC 的签名也能被我们的静态方法验签。 */
    @Test
    public void sm2SignAndVerifyAreTwoLinesOfModularArithmetic()
        throws Exception
    {
        Calc.useBc();
        byte[] msg = "SM2 signature essence".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);
        BigInteger e = eValue(za, msg);

        // (1) 我们签，BC 验
        BigInteger k = randomK();
        byte[] der = der(sm2Sign(d, e, k));
        Signature v = Signature.getInstance("SM3withSM2", "BC");
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assert.assertTrue("我们生成的 SM2 签名必须被 BC 接受", v.verify(der));

        // (2) BC 签，我们验
        Signature s = Signature.getInstance("SM3withSM2", "BC");
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] bcSig = s.sign();
        ASN1Sequence seq = ASN1Sequence.getInstance(bcSig);
        BigInteger[] rs = new BigInteger[]{
            ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getValue() };
        Assert.assertEquals("我们的静态方法必须验过 BC 的签名", Boolean.TRUE,
            sm2Verify(pub, e, rs));

        // (3) 篡改检测：改 r、改消息，都必须失败
        Assert.assertEquals("r 被改动必须失败", Boolean.FALSE,
            sm2Verify(pub, e, new BigInteger[]{ rs[0].add(BigInteger.ONE), rs[1] }));
        BigInteger eOther = eValue(za, "other message".getBytes("UTF-8"));
        Assert.assertEquals("消息被改动（e 变了）必须失败", Boolean.FALSE,
            sm2Verify(pub, eOther, rs));

        log.info("[SM2-签名] e={}, r={}, s={}", e.toString(16).substring(0, 12) + "…",
            rs[0].toString(16).substring(0, 12) + "…", rs[1].toString(16).substring(0, 12) + "…");
    }

    /** ZA 把身份 ID 绑进签名：ID 不一致时，同一枚签名必须验不过。 */
    @Test
    public void zaBindsTheIdentityIntoTheHash()
        throws Exception
    {
        Calc.useBc();
        byte[] id = "alice@example.cn".getBytes("UTF-8");
        byte[] msg = "identity is part of the digest".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);

        byte[] zaAlice = za(id, pub);
        byte[] zaDefault = za(DEFAULT_ID, pub);
        Assert.assertFalse("不同 ID 必须产生不同的 ZA", Arrays.equals(zaAlice, zaDefault));

        BigInteger eAlice = eValue(zaAlice, msg);
        BigInteger k = randomK();
        BigInteger[] sig = sm2Sign(d, eAlice, k);

        Signature v = Signature.getInstance("SM3withSM2", "BC");
        v.setParameter(new SM2ParameterSpec(id));
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assert.assertTrue("BC 用同一个 ID 必须验过", v.verify(der(sig)));

        Signature vWrong = Signature.getInstance("SM3withSM2", "BC");   // 默认 ID
        vWrong.initVerify(kp.getPublic());
        vWrong.update(msg);
        Assert.assertFalse("BC 用默认 ID 必须验不过（这就是 ZA 的作用）", vWrong.verify(der(sig)));

        Assert.assertEquals("我们的静态方法用 Alice 的 e 能验过", Boolean.TRUE,
            sm2Verify(pub, eAlice, sig));
        log.info("[SM2-ZA] ZA(Alice)={} ZA(default)={}", Calc.hex(zaAlice), Calc.hex(zaDefault));
    }

    /** 加密的两种模式（C1C2C3 / C1C3C2）：与 BC 的 SM2Engine、JCE Cipher 双向互操作。 */
    @Test
    public void sm2CipherModesDifferOnlyInSegmentOrder()
        throws Exception
    {
        Calc.useBc();
        byte[] pt = "SM2 encryption is ECIES with SM3-based KDF".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        X9ECParameters std = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domain = new ECDomainParameters(std.getCurve(), std.getG(), std.getN());

        for (boolean c1c3c2 : new boolean[]{ false, true })
        {
            byte[] ours = sm2Encrypt(pub, c1c3c2, randomK(), pt);

            // 我们的密文 -> BC 解密
            SM2Engine engine = new SM2Engine(c1c3c2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
            engine.init(false, new ECPrivateKeyParameters(d, domain));
            Assert.assertArrayEquals("BC 必须能解我们的密文（模式 " + (c1c3c2 ? "C1C3C2" : "C1C2C3") + "）",
                pt, engine.processBlock(ours, 0, ours.length));

            // BC 的密文 -> 我们解密（BC 的 SM2Engine 加密侧强制要求 ParametersWithRandom）
            SM2Engine enc = new SM2Engine(c1c3c2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
            enc.init(true, new ParametersWithRandom(
                new ECPublicKeyParameters(std.getCurve().createPoint(pub[0], pub[1]), domain), new SecureRandom()));
            byte[] fromBc = enc.processBlock(pt, 0, pt.length);
            Assert.assertArrayEquals("我们必须能解 BC 的密文", pt, sm2Decrypt(d, c1c3c2, fromBc));
            log.info("[SM2-加密模式] {} 互操作通过，密文长度 {}", c1c3c2 ? "C1C3C2" : "C1C2C3", fromBc.length);
        }

        // 同一条明文、同一个 k，两种模式只差 C2/C3 的排列
        BigInteger fixedK = new BigInteger("24b690a5f5dd752a475c4b36f5ad43fc25fc37ba", 16);
        byte[] a = sm2Encrypt(pub, false, fixedK, pt);
        byte[] b = sm2Encrypt(pub, true, fixedK, pt);
        Assert.assertTrue("两种模式的 C1 段必须相同", Arrays.equals(Arrays.copyOf(a, 65), Arrays.copyOf(b, 65)));
        Assert.assertTrue("C1C3C2 = C1 ‖ (a 的 C3) ‖ (a 的 C2)",
            Arrays.equals(b, Calc.concat(Arrays.copyOf(a, 65),
                Arrays.copyOfRange(a, 65 + pt.length, a.length),
                Arrays.copyOfRange(a, 65, 65 + pt.length))));

        // JCE 端到端：Cipher "SM2" 默认就是 C1C2C3
        Cipher jce = Cipher.getInstance("SM2", "BC");
        jce.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        Assert.assertArrayEquals("JCE SM2 必须能解我们的 C1C2C3 密文", pt, jce.doFinal(a));

        // 认证性：改一个 bit，C3 校验必须失败
        byte[] tampered = a.clone();
        tampered[70] ^= 1;
        try
        {
            sm2Decrypt(d, false, tampered);
            Assert.fail("C3 应该拦住被篡改的密文");
        }
        catch (AssertionError expected)
        {
            log.info("[SM2-加密模式] 篡改密文 -> C3 校验失败（SM2 密文自带认证性）");
        }
    }

    /** 本质中最危险的一条：k 复用会直接泄露私钥。这里用静态方法把 d 反解出来。 */
    @Test
    public void reusingKLeaksThePrivateKey()
        throws Exception
    {
        Calc.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        BigInteger k = randomK();                                  // 故意复用同一个 k
        BigInteger e1 = eValue(za, "message one".getBytes("UTF-8"));
        BigInteger e2 = eValue(za, "message two".getBytes("UTF-8"));
        BigInteger[] sig1 = sm2Sign(d, e1, k);
        BigInteger[] sig2 = sm2Sign(d, e2, k);

        // s = (1+d)⁻¹(k - r d)  =>  s₁-s₂ = (1+d)⁻¹(-(e₁-e₂)d)  =>  d = -s₁-s₂ / (s₁-s₂+e₁-e₂)
        BigInteger ds = sig1[1].subtract(sig2[1]);
        BigInteger de = e1.subtract(e2);
        BigInteger recovered = ds.negate().multiply(ds.add(de).modInverse(N)).mod(N);

        Assert.assertEquals("两条 k 复用的签名足以反推出私钥 d", d, recovered);
        Assert.assertArrayEquals("反推出的 d 必须能重算出同一个公钥", pub, mul(recovered, G));
        log.info("[SM2-k 复用] 从两枚签名反解出 d = {}（与真实私钥一致）", recovered.toString(16).substring(0, 16) + "…");
    }

    // ====================================================================
    //  k 为什么必须"真随机" —— 三条攻击路线与它们的代数
    // ====================================================================
    /*
     * 全部问题都出在一行代数上。SM2 的签名式子（GB/T 32918.2）对私钥 d 来说是<b>一次方程</b>：
     * <pre>
     *   s = (1 + d)⁻¹ (k - r·d)          | 两边乘 (1+d)
     *   s(1 + d) = k - r·d
     *   s + s·d = k - r·d                  | 含 d 的项并到左边
     *   d·(s + r) = k - s
     *   <b>d = (k - s)·(s + r)⁻¹  (mod n)</b>     | 一次模逆，私钥落地
     * </pre>
     * 由此得到三条铁律，也是下面三个测试各自要打破的东西：
     * <ol>
     *   <li><b>k 一旦泄露，d 就泄露</b>，而且连公钥都不需要看 —— 所以"能不能预测 k"等价于"能不能预测私钥"。</li>
     *   <li>攻击者手上永远有<b>免费的核对 oracle</b>：验签要的 x₁ = (r - e) mod n 是公开量，
     *       于是猜一个 k 候选，只要检查 x([k]G) 是否等于它，就能判断猜对没有；
     *       核对用的另一条路是 [d_cand]G == P，两式等价。</li>
     *   <li>验签公式里的 t = (r + s) mod n 不是随便挑的系数 —— 它就是上面推导中 d 的系数，
     *       所以 sG + tP 恰好把 kG 复原出来。签名和验签是同一行代数的两面。</li>
     * </ol>
     * "真随机"要同时满足三件事，缺一件就有对应的攻击：<b>不可预测</b>（测试①）、<b>无规律</b>（测试②）、
     * <b>值域上的分布均匀且熵足够</b>（测试③）。前两条给出的是零搜索的直接解，第三条给出的是
     * 把搜索空间从 2²⁵⁵ 压到几千次加法的可枚举性。
     */

    /** 设备用"截断的毫秒数"当种子：种子空间只有 8 bit，这才是现实里最常见的坏随机数。 */
    private static final int SEED_SPACE = 256;

    /** 弱随机池：k 只从 [1, K_POOL] 里取 —— 等价于"只生成 2 字节随机数当 k"的实现。 */
    private static final int K_POOL = 1024;

    /**
     * 攻击公式①：已知 k 时直接反解私钥。<b>d = (k - s)·(r + s)⁻¹ mod n</b>，一次模逆。
     * 参数全是普通的大整数，返回也是一个普通的大整数 —— 没有任何"拿到签名的对象再调方法"。
     */
    private static BigInteger privateKeyFromKnownK(BigInteger k, BigInteger r, BigInteger s)
    {
        BigInteger coefficient = modN(r.add(s));
        Assert.assertTrue("r + s 不能为 0（否则验签本身就不合法）", coefficient.signum() != 0);
        return modN(k.subtract(s).multiply(coefficient.modInverse(N)));
    }

    /**
     * 攻击公式②：k 有规律（两枚签名的 k 相差已知公差 Δ）时，连 k 都不用知道。
     * <pre>
     *   s₁(1 + d) = k₁ - r₁·d
     *   s₂(1 + d) = k₂ - r₂·d = k₁ + Δ - r₂·d     | 两式相减，未知的 k₁ 消掉
     *   (s₂ - s₁)(1 + d) = Δ - (r₂ - r₁)·d
     *   Δs + Δs·d = Δ - Δr·d                        | 含 d 的项并到左边
     *   d·(Δs + Δr) = Δ - Δs
     *   <b>d = (Δ - Δs)·(Δs + Δr)⁻¹  (mod n)</b>,  Δs = s₂ - s₁, Δr = r₂ - r₁
     * </pre>
     * Δs、Δr 都来自<b>公开</b>的签名，Δ 由规律性给出。Δ = 0 就是 k 复用，退化成本类上面那条公式
     * （注意 r = e + x₁，同一个 k 给出同一个 x₁，所以 Δr = e₂ - e₁）。
     */
    private static BigInteger privateKeyFromKnownDelta(BigInteger delta, BigInteger r1, BigInteger s1,
        BigInteger r2, BigInteger s2)
    {
        BigInteger deltaS = modN(s2.subtract(s1));
        BigInteger deltaR = modN(r2.subtract(r1));
        BigInteger coefficient = modN(deltaS.add(deltaR));
        Assert.assertTrue("Δs + Δr 不能为 0", coefficient.signum() != 0);
        return modN(modN(delta.subtract(deltaS)).multiply(coefficient.modInverse(N)));
    }

    /** 从私钥反看 k：s(1+d) = k - r·d ⇒ <b>k = s(1 + d) + r·d mod n</b>。攻击者用它确认整条规律。 */
    private static BigInteger kFromPrivateKey(BigInteger d, BigInteger r, BigInteger s)
    {
        return modN(s.multiply(BigInteger.ONE.add(d)).add(r.multiply(d)));
    }

    /** 弱随机源①：和 {@link #randomK()} 长得一模一样的一行代码，错的只是把 SecureRandom 换成 Random。 */
    private static BigInteger lcgK(long seed)
    {
        return new BigInteger(N.bitLength(), new Random(seed)).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /** 弱随机源②：把递增计数器当随机数（现实中"用消息序号派生 k"的实现）。 */
    private static BigInteger counterK(long counter, long step)
    {
        return BigInteger.valueOf(1000003L).add(BigInteger.valueOf(counter).multiply(BigInteger.valueOf(step)));
    }

    /** 样本频率直方图 -> 香农熵（比特）。就是 for 循环累加 -p·log₂p，没有 map 也没有 stream。 */
    private static double shannonEntropyBits(int[] counts)
    {
        int total = 0;
        for (int i = 0; i < counts.length; i++)
        {
            total += counts[i];
        }
        double bits = 0.0;
        for (int i = 0; i < counts.length; i++)
        {
            if (counts[i] > 0)
            {
                double p = (double)counts[i] / (double)total;
                bits -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return bits;
    }

    /**
     * 裁判：攻击者拿到 d 之后能不能<b>冒充受害者</b>，用 BC 的验签器说了算。
     * 用 recovered 签一条全新消息 -> DER -> {@code SM3withSM2} 用真实公钥验，必须通过。
     */
    private static void assertRecoveredKeyCanForge(KeyPair kp, BigInteger recoveredD, byte[] zaFor)
        throws Exception
    {
        byte[] fresh = "signature produced by the attacker".getBytes("UTF-8");
        BigInteger[] forged = sm2Sign(recoveredD, eValue(zaFor, fresh), randomK());
        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(fresh);
        Assert.assertTrue("反推出的 d 必须能签出 BC 认可的签名（否则它不是真私钥）", verifier.verify(der(forged)));
    }

    /**
     * 测试①（不可预测性被破坏）：<b>可预测的 k = 可预测的私钥</b>。
     * 设备用 8 bit 的种子（截断的毫秒数、递增的启动计数）喂 {@code java.util.Random} 生成 k，
     * 攻击者<b>枚举种子</b>并重放同一个伪随机数生成器即可命中真实的 k，然后一次模逆拿到 d。
     */
    @Test
    public void predictablePrngSeedEnumerationLeaksThePrivateKey()
        throws Exception
    {
        Calc.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);
        byte[] msg = "k comes from a truncated millisecond clock".getBytes("UTF-8");
        BigInteger e = eValue(za, msg);

        long deviceSeed = 90L;                                    // 设备内部那个"保密"的种子
        BigInteger[] sig = sm2Sign(d, e, lcgK(deviceSeed));

        // 攻击者的免费线索：x₁ = (r - e) mod n，纯公开量（对比时统一取 mod n，因为 p 略大于 n）
        BigInteger x1Target = modN(sig[0].subtract(e));

        long hitSeed = -1L;
        BigInteger hitK = null;
        long probes = 0;
        for (long seed = 0; seed < SEED_SPACE; seed++)
        {
            BigInteger candidateK = lcgK(seed);
            probes++;
            if (modN(mul(candidateK, G)[0]).equals(x1Target))     // [k]G 的横坐标对上了
            {
                hitSeed = seed;
                hitK = candidateK;
                break;
            }
        }

        Assert.assertTrue("枚举 " + SEED_SPACE + " 个种子必须命中真实的 k", hitK != null);
        Assert.assertEquals("命中的种子就是设备那个", deviceSeed, hitSeed);

        BigInteger recovered = privateKeyFromKnownK(hitK, sig[0], sig[1]);
        Assert.assertEquals("重放 PRNG 得到 k 后，一次模逆就该还原私钥", d, recovered);
        Assert.assertArrayEquals("另一条核对路线 [d_cand]G == P 也必须成立", pub, mul(recovered, G));
        assertRecoveredKeyCanForge(kp, recovered, za);

        // 对照组：真随机 k 的空间是 2^255 量级，而枚举成本是线性的 —— 没有可预测性就没有落脚点
        log.info("[SM2-可预测k] 枚举 {} 个种子命中 k={}，一次模逆得到 d；真随机时 k 的空间有 2^{} 量级",
            probes, hitK.toString(16), N.bitLength());
    }

    /**
     * 测试②（独立性被破坏）：<b>k 有规律 = 零搜索直接解出私钥</b>。
     * 设备用计数器当随机数，两枚签名的 k 相差公开的公差 Δ。按 {@code privateKeyFromKnownDelta}
     * 的推导，只需要 4 个公开大整数加一次模逆 —— 连枚举都没有。
     */
    @Test
    public void sequentialKIsSolvedByLinearEquationsWithoutAnySearch()
        throws Exception
    {
        Calc.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        BigInteger delta = BigInteger.valueOf(1000003L);           // 公差：设备的计数器步长
        BigInteger k1 = counterK(7L, delta.longValue());
        BigInteger k2 = counterK(8L, delta.longValue());
        Assert.assertEquals("两枚签名的 k 之差必须正好是规律本身", delta, k2.subtract(k1));

        BigInteger e1 = eValue(za, "first message".getBytes("UTF-8"));
        BigInteger e2 = eValue(za, "second message".getBytes("UTF-8"));
        BigInteger[] sig1 = sm2Sign(d, e1, k1);
        BigInteger[] sig2 = sm2Sign(d, e2, k2);

        // 攻击者只知道"k 是等差的"，不知道 k 本身
        BigInteger recovered = privateKeyFromKnownDelta(delta, sig1[0], sig1[1], sig2[0], sig2[1]);
        Assert.assertEquals("公差 + 两枚公开签名即可解出 d", d, recovered);

        // 两条独立公式互相印证：先解出 d，再回推 k₁，必须与设备用的那个 k₁ 相同
        Assert.assertEquals("由 d 回推的 k₁ = s₁(1+d) + r₁d 必须与真实值一致", k1,
            kFromPrivateKey(recovered, sig1[0], sig1[1]));
        Assert.assertEquals("再由 k₁ 走攻击公式①也得到同一个 d", recovered,
            privateKeyFromKnownK(k1, sig1[0], sig1[1]));
        Assert.assertArrayEquals("公钥核对", pub, mul(recovered, G));
        assertRecoveredKeyCanForge(kp, recovered, za);

        // Δ = 0 是本公式的特例（k 复用）：与 reusingKLeaksThePrivateKey 同一条式子
        byte[] other = "another message".getBytes("UTF-8");
        BigInteger[] reuseA = sm2Sign(d, e1, k1);
        BigInteger[] reuseB = sm2Sign(d, eValue(za, other), k1);
        Assert.assertEquals("公差为 0（k 完全复用）也必须解出 d", d,
            privateKeyFromKnownDelta(BigInteger.ZERO, reuseA[0], reuseA[1], reuseB[0], reuseB[1]));

        // 对照：真随机（Δ 未知）时这条零搜索攻击立刻失效 —— 公差本身进不了方程
        BigInteger[] safeA = sm2Sign(d, e1, randomK());
        BigInteger[] safeB = sm2Sign(d, eValue(za, other), randomK());
        Assert.assertFalse("k 之间没有关系时，随便猜的公差不可能给出真实私钥",
            d.equals(privateKeyFromKnownDelta(BigInteger.ONE, safeA[0], safeA[1], safeB[0], safeB[1])));

        log.info("[SM2-规律k] 已知公差 {} 时，4 个公开量 + 1 次模逆得到 d = {}…", delta,
            recovered.toString(16).substring(0, 16));
    }

    /**
     * 测试③（均匀性/熵被破坏）：<b>频率分布偏差让搜索空间塌缩</b>。
     * 三件事一起做：先<b>测量</b>出弱随机源的分布缺陷（重复、直方图熵、有效位长），
     * 再用两条各自独立的路把它变成私钥泄露 ——
     * (a) 值域只有 2^10，枚举时利用"相邻候选只差一个 G"把标量乘降成一次点加；
     * (b) 池子里撞车（生日悖论）就等价于 k 复用，直接套测试②的 Δ = 0 公式。
     */
    @Test
    public void biasedKDistributionIsMeasuredAndThenExploited()
        throws Exception
    {
        Calc.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        // 128 枚签名，k 取自只有 K_POOL 个值的弱池（种子固定，测试可重复）
        int samples = 128;
        Random weakPool = new Random(20261022L);
        BigInteger[] ks = new BigInteger[samples];
        BigInteger[] es = new BigInteger[samples];
        BigInteger[][] sigs = new BigInteger[samples][];
        boolean[] seen = new boolean[K_POOL + 1];
        int duplicates = 0;
        int[] histogram = new int[K_POOL / 16];                    // 64 个桶，看分布是否摊开
        int maxBitLength = 0;
        for (int i = 0; i < samples; i++)
        {
            ks[i] = BigInteger.valueOf(weakPool.nextInt(K_POOL) + 1);
            es[i] = eValue(za, ("message number " + i).getBytes("UTF-8"));
            sigs[i] = sm2Sign(d, es[i], ks[i]);
            int value = ks[i].intValue();
            histogram[(value - 1) / 16]++;                         // value ∈ [1, 1024] -> 桶 0..63
            if (ks[i].bitLength() > maxBitLength)
            {
                maxBitLength = ks[i].bitLength();
            }
            if (seen[value])
            {
                duplicates++;                                      // 生日悖论：池子小就一定会撞车
            }
            seen[value] = true;
        }

        // ---- 测量：分布缺陷是<b>看得见</b>的。注意有限样本的熵估计只能证明"不够随机"，
        //      证明不了"够随机"，所以这里真正的判据是重复次数与有效位长（值域上界）。
        double entropyBits = shannonEntropyBits(histogram);
        Assert.assertTrue("弱池里必然出现重复 k：" + duplicates + " 次", duplicates > 0);
        Assert.assertTrue("有效位长只有 " + maxBitLength + " bit，远低于 255", maxBitLength <= 16);
        Assert.assertTrue("桶分布摊不开，观测熵只有 " + entropyBits + " bit，远小于 k 需要的 ~255 bit",
            entropyBits < 8.0);

        // ---- 攻击(a)：值域可枚举。逐格往前走一格 = 一次点加，比重新做标量乘便宜三个数量级
        BigInteger firstTarget = modN(sigs[0][0].subtract(es[0]));  // x₁ = (r - e) mod n，公开
        BigInteger[] walked = G;                                    // walked = [1]G，之后每轮 += G
        BigInteger enumeratedK = null;
        int adds = 0;
        for (int k = 1; k <= K_POOL; k++)
        {
            if (k > 1)
            {
                walked = add(walked, G);                           // [k]G = [(k-1)G] + G
                adds++;
            }
            if (modN(walked[0]).equals(firstTarget))
            {
                enumeratedK = BigInteger.valueOf(k);
                break;
            }
        }
        Assert.assertNotNull("枚举 2^10 个候选必须命中第一枚签名的 k", enumeratedK);
        Assert.assertEquals("命中值应与弱池实际用的 k 相同", ks[0], enumeratedK);
        Assert.assertEquals("枚举到 k 之后仍然是一次模逆还原私钥", d,
            privateKeyFromKnownK(enumeratedK, sigs[0][0], sigs[0][1]));
        log.info("[SM2-低熵k] 值域 {} 个候选、{} 次点加就枚举到 k；真随机时空间是 2^{} 且无规律可用",
            K_POOL, adds, N.bitLength());

        // ---- 攻击(b)：撞车 = k 复用。弱池的重复不是统计噪音，而是直接的私钥泄露
        int collisionA = -1;
        int collisionB = -1;
        for (int i = 0; i < samples && collisionB < 0; i++)
        {
            for (int j = i + 1; j < samples; j++)
            {
                if (ks[i].equals(ks[j]))
                {
                    collisionA = i;
                    collisionB = j;
                    break;
                }
            }
        }
        Assert.assertTrue("必须能找到一对复用同一个 k 的签名", collisionB > collisionA);
        BigInteger viaCollision = privateKeyFromKnownDelta(BigInteger.ZERO,
            sigs[collisionA][0], sigs[collisionA][1], sigs[collisionB][0], sigs[collisionB][1]);
        Assert.assertEquals("撞车的那两枚签名直接给出 d", d, viaCollision);
        Assert.assertArrayEquals("公钥核对", pub, mul(viaCollision, G));
        assertRecoveredKeyCanForge(kp, viaCollision, za);
        log.info("[SM2-频率分布] {} 枚签名里 {} 次重复，第 {} / {} 枚撞车 -> 套 Δ=0 公式得到 d",
            samples, duplicates, collisionA, collisionB);

        // ---- 对照：SecureRandom 的 128 个 k 两两不同、位长贴着 255，上面两条攻击都失去落脚点
        int secureDuplicates = 0;
        int secureMinBits = Integer.MAX_VALUE;
        BigInteger[] secureKs = new BigInteger[samples];
        for (int i = 0; i < samples; i++)
        {
            secureKs[i] = randomK();
            if (secureKs[i].bitLength() < secureMinBits)
            {
                secureMinBits = secureKs[i].bitLength();
            }
            for (int j = 0; j < i; j++)
            {
                if (secureKs[i].equals(secureKs[j]))
                {
                    secureDuplicates++;
                }
            }
        }
        Assert.assertEquals("真随机的 128 个 k 不应出现任何重复", 0, secureDuplicates);
        // 阈值取 200 bit 而不是贴着 255：单个真随机 k 落在 200 bit 以下的概率是 2^-56，
        // 但落在 250 以下的概率有 2^-6（约 1/64）—— 贴着上界断言本身就是错的统计判断。
        // 而弱池的 k 位长永远不超过 10 bit，两者的差距才是可以断言的东西。
        Assert.assertTrue("真随机的 k 位长全部应 ≥ 200 bit（实测最小 " + secureMinBits + " bit）",
            secureMinBits >= 200);
        log.info("[SM2-真随机对照] {} 枚签名的 k 两两不同，位长全部 ≥ {} bit；弱池只有 {} 个格子（约 2^{} bit），"
            + "所以值域枚举与撞车两条攻击都失效", samples, secureMinBits, K_POOL, 10);
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * BC 的 "SM2" KeyPairGenerator 若不显式 initialize，默认曲线并不是 sm2p256v1，
     * 而本类所有静态方法都只用 GB/T 32918 的曲线常量，所以必须显式指定命名曲线，
     * 否则"我们的 dG"和"BC 的公钥"根本不在同一条曲线上。
     */
    private static KeyPair sm2KeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        kpg.initialize(new org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec("sm2p256v1"));
        return kpg.generateKeyPair();
    }

    private static BigInteger[] publicKeyOf(KeyPair kp)
    {
        org.bouncycastle.math.ec.ECPoint q = ((ECPublicKey) kp.getPublic()).getQ();
        return new BigInteger[]{ modP(q.getAffineXCoord().toBigInteger()), modP(q.getAffineYCoord().toBigInteger()) };
    }

    private static BigInteger randomK()
    {
        BigInteger k;
        do
        {
            k = new BigInteger(N.bitLength(), new SecureRandom()).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        }
        while (k.signum() <= 0 || k.compareTo(N.subtract(BigInteger.ONE)) >= 0);
        return k;
    }

    /** DER(SEQUENCE{r,s}) —— 只是为了把我们算出的 (r,s) 喂给 BC 的验签器。 */
    private static byte[] der(BigInteger[] rs)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(rs[0]));
        v.add(new ASN1Integer(rs[1]));
        return new DERSequence(v).getEncoded();
    }
}
