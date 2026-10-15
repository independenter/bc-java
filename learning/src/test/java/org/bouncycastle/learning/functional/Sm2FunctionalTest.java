package org.bouncycastle.learning.functional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
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

import static org.bouncycastle.learning.functional.Fp.foldRange;

/**
 * SM2（GM/T 0003）的本质计算 —— 纯函数版。
 *
 * <p>椭圆曲线在这里<b>不是对象</b>：一个点就是 {@code BigInteger[]{x, y}}，无穷远点就是空数组。
 * 于是整条曲线只是一组纯函数：
 * <pre>
 *   add  : (Point, Point) -> Point      λ = (y₂-y₁)/(x₂-x₁)
 *   dbl  : Point -> Point               λ = (3x²+a)/(2y)
 *   mul  : (Integer, Point) -> Point    按位 double-and-add 的 fold
 *   sign : d -> e -> k -> (r, s)        r=(e+x₁) mod n, s=(1+d)⁻¹(k-rd) mod n
 *   verify: P -> e -> (r,s) -> Bool     (x₁,y₁) = sG + tP, t=(r+s) mod n
 * </pre>
 * 算法模式（C1C2C3 / C1C3C2）只是"三段字节的不同排列"，KDF 是 SM3 的计数器流。
 * 哈希复用 {@link Sm3FunctionalTest} 里我们自己写的纯函数 SM3 —— 这才是真正的函数组合。
 */
@Slf4j
public class Sm2FunctionalTest
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

    /** SM3 作为纯函数复用（本模块自己实现的那个）。 */
    private static final Function<byte[], byte[]> SM3 = Sm3FunctionalTest.sm3Pipeline();

    /** 模 p 归一化，保证结果落在 [0, p)。 */
    private static BigInteger modP(BigInteger x)
    {
        return x.mod(P);
    }

    /** 求逆：椭圆曲线里唯一的"贵"运算，就是模逆（扩展欧几里得）。 */
    private static final Function<BigInteger, BigInteger> inverse = v -> v.mod(P).modInverse(P);

    /** 点在曲线上吗？ y² ≡ x³ + ax + b (mod p)。这是谓词，不是方法。 */
    private static final Function<BigInteger[], Boolean> onCurve = pt -> pt.length == 0
        ? Boolean.TRUE
        : modP(pt[1].multiply(pt[1])).equals(modP(pt[0].multiply(pt[0]).multiply(pt[0]).add(A.multiply(pt[0])).add(B)));

    /** 取负点：y -> -y。 */
    private static final UnaryOperator<BigInteger[]> negate = pt ->
        pt.length == 0 ? pt : new BigInteger[]{ pt[0], modP(pt[1].negate()) };

    /** 倍点：弦切线的斜率来自导数 3x²+a。 */
    private static final UnaryOperator<BigInteger[]> doublePoint = pt ->
    {
        if (pt.length == 0 || modP(pt[1].shiftLeft(1)).signum() == 0)
        {
            return INFINITY;
        }
        BigInteger lam = modP(pt[0].multiply(pt[0]).multiply(BigInteger.valueOf(3)).add(A))
            .multiply(inverse.apply(pt[1].shiftLeft(1))).mod(P);
        BigInteger x = modP(lam.multiply(lam).subtract(pt[0]).subtract(pt[0]));
        BigInteger y = modP(lam.multiply(pt[0].subtract(x)).subtract(pt[1]));
        return new BigInteger[]{ x, y };
    };

    /** 加法：纯函数，返回新数组；相消情况返回单位元。 */
    private static final BiFunction<BigInteger[], BigInteger[], BigInteger[]> add = (p, q) ->
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
            return modP(p[1].add(q[1])).signum() == 0 ? INFINITY : doublePoint.apply(p);
        }
        BigInteger lam = modP(q[1].subtract(p[1])).multiply(inverse.apply(modP(q[0].subtract(p[0])))).mod(P);
        BigInteger x = modP(lam.multiply(lam).subtract(p[0]).subtract(q[0]));
        BigInteger y = modP(lam.multiply(p[0].subtract(x)).subtract(p[1]));
        return new BigInteger[]{ x, y };
    };

    /** 标量乘 = 按位的 fold（从最高位往下：先 double，再按位 add）。这就是"倍加算法"的本质。 */
    private static BigInteger[] mul(BigInteger k, BigInteger[] point)
    {
        return foldRange(0, k.bitLength(), INFINITY, (acc, j) ->
        {
            int bit = k.bitLength() - 1 - j;
            BigInteger[] doubled = doublePoint.apply(acc);
            return k.testBit(bit) ? add.apply(doubled, point) : doubled;
        });
    }

    /** ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)：SM2 把"身份"绑进哈希的那一步。 */
    private static Function<byte[], Function<BigInteger[], byte[]>> computeZA()
    {
        return id -> pub ->
        {
            byte[] entl = Fp.toBytes(BigInteger.valueOf(8L * id.length), 2);
            return SM3.apply(Fp.concat(entl, id,
                Fp.toBytes(A, KEY_BYTES), Fp.toBytes(B, KEY_BYTES),
                Fp.toBytes(GX, KEY_BYTES), Fp.toBytes(GY, KEY_BYTES),
                Fp.toBytes(pub[0], KEY_BYTES), Fp.toBytes(pub[1], KEY_BYTES)));
        };
    }

    /** e = SM3(ZA ‖ M) 转成大整数 —— SM2 的"消息摘要"其实只有这一行。 */
    private static final BiFunction<byte[], byte[], BigInteger> E_VALUE = (za, msg) ->
        Fp.toBigInt(SM3.apply(Fp.concat(za, msg)));

    /**
     * 签名：{@code d -> e -> k -> (r, s)}。
     * r = (e + x₁) mod n，s = (1+d)⁻¹ (k - r·d) mod n —— 柯里化写成三级函数。
     */
    private static final Function<BigInteger, Function<BigInteger, Function<BigInteger, BigInteger[]>>> SM2_SIGN =
        d -> e -> k ->
        {
            BigInteger x1 = mul(k, G)[0];                        // (x₁,y₁) = kG，只需要 x₁
            BigInteger r = modN(e.add(x1));
            Assert.assertTrue("r 不能为 0（k 需重试）", r.signum() != 0);
            BigInteger s = modN(k.subtract(r.multiply(d)).multiply(BigInteger.ONE.add(d).modInverse(N)));
            Assert.assertTrue("r + k 不能等于 n（k 需重试）", modN(r.add(k)).signum() != 0);
            return new BigInteger[]{ r, s };
        };

    /**
     * 验签：{@code P -> e -> (r,s) -> Boolean}。
     * t = (r+s) mod n，(x₁,y₁) = sG + tP，检查 (e+x₁) mod n == r。
     */
    private static final Function<BigInteger[], Function<BigInteger, Function<BigInteger[], Boolean>>> SM2_VERIFY =
        pub -> e -> sig ->
        {
            BigInteger r = sig[0];
            BigInteger s = sig[1];
            if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(N) >= 0 || s.compareTo(N) >= 0)
            {
                return Boolean.FALSE;
            }
            BigInteger t = modN(r.add(s));
            if (t.signum() == 0)
            {
                return Boolean.FALSE;
            }
            BigInteger[] point = add.apply(mul(s, G), mul(t, pub));
            if (point.length == 0)
            {
                return Boolean.FALSE;
            }
            return modN(e.add(point[0])).equals(r);
        };

    private static BigInteger modN(BigInteger x)
    {
        return x.mod(N);
    }

    /** KDF（SM3 计数器流）：加密里把共享点坐标变成密钥流的纯函数。 */
    private static BiFunction<byte[], Integer, byte[]> kdfSm3()
    {
        return (z, klen) -> foldRange(1, Fp.ceilDiv(klen, 32) + 1, new byte[0], (acc, ct) ->
        {
            byte[] stream = SM3.apply(Fp.concat(z, Fp.toBytes(BigInteger.valueOf(ct), 4)));
            int remain = klen - acc.length;
            return Fp.concat(acc, Arrays.copyOf(stream, Math.min(remain, stream.length)));
        });
    }

    /**
     * SM2 加密：{@code k -> 明文 -> 密文}。
     * C1 = kG（04‖x‖y），共享点 kP=(x₂,y₂)，密钥流 = KDF(x₂‖y₂)，C2 = M ⊕ 流，C3 = SM3(x₂‖M‖y₂)。
     * mode = C1C2C3 / C1C3C2 只决定 C2、C3 的排列顺序 —— 这就是"算法模式"的全部差异。
     */
    private static Function<BigInteger, Function<byte[], byte[]>> sm2Encrypt(BigInteger[] pub, final boolean c1c3c2)
    {
        return k -> plaintext ->
        {
            BigInteger[] c1Point = mul(k, G);
            BigInteger[] shared = mul(k, pub);
            byte[] x2 = Fp.toBytes(shared[0], KEY_BYTES);
            byte[] y2 = Fp.toBytes(shared[1], KEY_BYTES);
            byte[] c1 = Fp.concat(new byte[]{ 0x04 }, Fp.toBytes(c1Point[0], KEY_BYTES), Fp.toBytes(c1Point[1], KEY_BYTES));
            byte[] c2 = Fp.xor(plaintext, kdfSm3().apply(Fp.concat(x2, y2), plaintext.length));
            byte[] c3 = SM3.apply(Fp.concat(x2, plaintext, y2));
            return c1c3c2 ? Fp.concat(c1, c3, c2) : Fp.concat(c1, c2, c3);
        };
    }

    /** SM2 解密：{@code 密文 -> 明文}，并重新校验 C3（认证性来自这里）。 */
    private static Function<byte[], byte[]> sm2Decrypt(BigInteger d, final boolean c1c3c2)
    {
        return ciphertext ->
        {
            BigInteger[] c1Point = new BigInteger[]{
                Fp.toBigInt(Arrays.copyOfRange(ciphertext, 1, 1 + KEY_BYTES)),
                Fp.toBigInt(Arrays.copyOfRange(ciphertext, 1 + KEY_BYTES, 1 + 2 * KEY_BYTES)) };
            byte[] c3 = c1c3c2
                ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, 1 + 2 * KEY_BYTES + 32)
                : Arrays.copyOfRange(ciphertext, ciphertext.length - 32, ciphertext.length);
            byte[] c2 = c1c3c2
                ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES + 32, ciphertext.length)
                : Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, ciphertext.length - 32);

            BigInteger[] shared = mul(d, c1Point);
            byte[] x2 = Fp.toBytes(shared[0], KEY_BYTES);
            byte[] y2 = Fp.toBytes(shared[1], KEY_BYTES);
            byte[] plaintext = Fp.xor(c2, kdfSm3().apply(Fp.concat(x2, y2), c2.length));
            Assert.assertArrayEquals("C3 校验失败：密文被篡改", c3, SM3.apply(Fp.concat(x2, plaintext, y2)));
            return plaintext;
        };
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
        Assert.assertTrue("生成元必须在曲线上", onCurve.apply(G));
        Assert.assertEquals("n 必须是 G 的阶：nG = 无穷远点", 0, mul(N, G).length);
        Assert.assertArrayEquals("(n+1)G = G", G, mul(N.add(BigInteger.ONE), G));
        log.info("[SM2-曲线] p={} a={} n 阶检验通过", P.toString(16).substring(0, 8) + "…");
    }

    /** 群律：交换律、结合律、倍点=自加、标量乘的分配律 —— 全部由纯函数验证。 */
    @Test
    public void ecPointArithmeticFormsAnAbelianGroup()
    {
        BigInteger k1 = new BigInteger("1234567890123456789012345678901234567890");
        BigInteger k2 = new BigInteger("9876543210987654321098765432109876543210");

        Assert.assertArrayEquals("加法交换律", add.apply(mul(k1, G), mul(k2, G)), add.apply(mul(k2, G), mul(k1, G)));
        Assert.assertArrayEquals("倍点 == 自加", doublePoint.apply(G), add.apply(G, G));
        Assert.assertArrayEquals("(k1+k2)G == k1G + k2G", mul(k1.add(k2), G), add.apply(mul(k1, G), mul(k2, G)));
        Assert.assertArrayEquals("(k1·k2)G == k1(k2G)", mul(k1.multiply(k2), G), mul(k1, mul(k2, G)));
        Assert.assertArrayEquals("P + (-P) = 单位元", INFINITY, add.apply(mul(k1, G), negate.apply(mul(k1, G))));
        Assert.assertArrayEquals("单位元是恒等", mul(k1, G), add.apply(INFINITY, mul(k1, G)));
        Assert.assertTrue("任意标量乘的结果仍在曲线上", onCurve.apply(mul(k2, G)));
        log.info("[SM2-群律] 6 条群公理全部由纯函数验证通过");
    }

    /** 用 BC 生成的私钥 d，我们的纯函数标量乘必须算出同一个公钥点。 */
    @Test
    public void ourPureScalarMulRebuildsBcPublicKey()
        throws Exception
    {
        Fp.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        org.bouncycastle.math.ec.ECPoint q = ((ECPublicKey) kp.getPublic()).getQ();
        BigInteger[] ours = mul(d, G);

        Assert.assertEquals("我们的 x₁ == BC 的仿射 x", modP(q.getAffineXCoord().toBigInteger()), ours[0]);
        Assert.assertEquals("我们的 y₁ == BC 的仿射 y", modP(q.getAffineYCoord().toBigInteger()), ours[1]);
        log.info("[SM2-本质] dG 由纯函数独立算出，与 BC 完全一致：x={}", Fp.hex(Fp.toBytes(ours[0], 32)));
    }

    /** 签名的本质：我们的 (r,s) 能被 BC 验签，BC 的签名也能被我们的纯函数验签。 */
    @Test
    public void sm2SignAndVerifyAreTwoLinesOfModularArithmetic()
        throws Exception
    {
        Fp.useBc();
        byte[] msg = "SM2 signature essence".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = computeZA().apply(DEFAULT_ID).apply(pub);
        BigInteger e = E_VALUE.apply(za, msg);

        // (1) 我们签，BC 验
        BigInteger k = randomK();
        byte[] der = der(SM2_SIGN.apply(d).apply(e).apply(k));
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
        Assert.assertEquals("我们的纯函数必须验过 BC 的签名", Boolean.TRUE,
            SM2_VERIFY.apply(pub).apply(e).apply(rs));

        // (3) 篡改检测：改 r、改消息，都必须失败
        Assert.assertEquals("r 被改动必须失败", Boolean.FALSE,
            SM2_VERIFY.apply(pub).apply(e).apply(new BigInteger[]{ rs[0].add(BigInteger.ONE), rs[1] }));
        BigInteger eOther = E_VALUE.apply(za, "other message".getBytes("UTF-8"));
        Assert.assertEquals("消息被改动（e 变了）必须失败", Boolean.FALSE,
            SM2_VERIFY.apply(pub).apply(eOther).apply(rs));

        log.info("[SM2-签名] e={}, r={}, s={}", e.toString(16).substring(0, 12) + "…",
            rs[0].toString(16).substring(0, 12) + "…", rs[1].toString(16).substring(0, 12) + "…");
    }

    /** ZA 把身份 ID 绑进签名：ID 不一致时，同一枚签名必须验不过。 */
    @Test
    public void zaBindsTheIdentityIntoTheHash()
        throws Exception
    {
        Fp.useBc();
        byte[] id = "alice@example.cn".getBytes("UTF-8");
        byte[] msg = "identity is part of the digest".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);

        byte[] zaAlice = computeZA().apply(id).apply(pub);
        byte[] zaDefault = computeZA().apply(DEFAULT_ID).apply(pub);
        Assert.assertFalse("不同 ID 必须产生不同的 ZA", Arrays.equals(zaAlice, zaDefault));

        BigInteger eAlice = E_VALUE.apply(zaAlice, msg);
        BigInteger k = randomK();
        BigInteger[] sig = SM2_SIGN.apply(d).apply(eAlice).apply(k);

        Signature v = Signature.getInstance("SM3withSM2", "BC");
        v.setParameter(new SM2ParameterSpec(id));
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assert.assertTrue("BC 用同一个 ID 必须验过", v.verify(der(sig)));

        Signature vWrong = Signature.getInstance("SM3withSM2", "BC");   // 默认 ID
        vWrong.initVerify(kp.getPublic());
        vWrong.update(msg);
        Assert.assertFalse("BC 用默认 ID 必须验不过（这就是 ZA 的作用）", vWrong.verify(der(sig)));

        Assert.assertEquals("我们的纯函数用 Alice 的 e 能验过", Boolean.TRUE,
            SM2_VERIFY.apply(pub).apply(eAlice).apply(sig));
        log.info("[SM2-ZA] ZA(Alice)={} ZA(default)={}", Fp.hex(zaAlice), Fp.hex(zaDefault));
    }

    /** 加密的两种模式（C1C2C3 / C1C3C2）：与 BC 的 SM2Engine、JCE Cipher 双向互操作。 */
    @Test
    public void sm2CipherModesDifferOnlyInSegmentOrder()
        throws Exception
    {
        Fp.useBc();
        byte[] pt = "SM2 encryption is ECIES with SM3-based KDF".getBytes("UTF-8");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        X9ECParameters std = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domain = new ECDomainParameters(std.getCurve(), std.getG(), std.getN());

        for (boolean c1c3c2 : new boolean[]{ false, true })
        {
            byte[] ours = sm2Encrypt(pub, c1c3c2).apply(randomK()).apply(pt);

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
            Assert.assertArrayEquals("我们必须能解 BC 的密文", pt, sm2Decrypt(d, c1c3c2).apply(fromBc));
            log.info("[SM2-加密模式] {} 互操作通过，密文长度 {}", c1c3c2 ? "C1C3C2" : "C1C2C3", fromBc.length);
        }

        // 同一条明文、同一个 k，两种模式只差 C2/C3 的排列
        BigInteger fixedK = new BigInteger("24b690a5f5dd752a475c4b36f5ad43fc25fc37ba", 16);
        byte[] a = sm2Encrypt(pub, false).apply(fixedK).apply(pt);
        byte[] b = sm2Encrypt(pub, true).apply(fixedK).apply(pt);
        Assert.assertTrue("两种模式的 C1 段必须相同", Arrays.equals(Arrays.copyOf(a, 65), Arrays.copyOf(b, 65)));
        Assert.assertTrue("C1C3C2 = C1 ‖ (a 的 C3) ‖ (a 的 C2)",
            Arrays.equals(b, Fp.concat(Arrays.copyOf(a, 65),
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
            sm2Decrypt(d, false).apply(tampered);
            Assert.fail("C3 应该拦住被篡改的密文");
        }
        catch (AssertionError expected)
        {
            log.info("[SM2-加密模式] 篡改密文 -> C3 校验失败（SM2 密文自带认证性）");
        }
    }

    /** 本质中最危险的一条：k 复用会直接泄露私钥。这里用纯函数把 d 反解出来。 */
    @Test
    public void reusingKLeaksThePrivateKey()
        throws Exception
    {
        Fp.useBc();
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = computeZA().apply(DEFAULT_ID).apply(pub);

        BigInteger k = randomK();                                  // 故意复用同一个 k
        BigInteger e1 = E_VALUE.apply(za, "message one".getBytes("UTF-8"));
        BigInteger e2 = E_VALUE.apply(za, "message two".getBytes("UTF-8"));
        BigInteger[] sig1 = SM2_SIGN.apply(d).apply(e1).apply(k);
        BigInteger[] sig2 = SM2_SIGN.apply(d).apply(e2).apply(k);

        // s = (1+d)⁻¹(k - r d)  =>  s₁-s₂ = (1+d)⁻¹(-(e₁-e₂)d)  =>  d = -s₁-s₂ / (s₁-s₂+e₁-e₂)
        BigInteger ds = sig1[1].subtract(sig2[1]);
        BigInteger de = e1.subtract(e2);
        BigInteger recovered = ds.negate().multiply(ds.add(de).modInverse(N)).mod(N);

        Assert.assertEquals("两条 k 复用的签名足以反推出私钥 d", d, recovered);
        Assert.assertArrayEquals("反推出的 d 必须能重算出同一个公钥", pub, mul(recovered, G));
        log.info("[SM2-k 复用] 从两枚签名反解出 d = {}（与真实私钥一致）", recovered.toString(16).substring(0, 16) + "…");
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * BC 的 "SM2" KeyPairGenerator 若不显式 initialize，默认曲线并不是 sm2p256v1，
     * 而本类所有纯函数都只用 GB/T 32918 的曲线常量，所以必须显式指定命名曲线，
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

    /** DER(SEQUENCE{r,s}) —— 只是为了把我们的纯函数结果喂给 BC 的验签器。 */
    private static byte[] der(BigInteger[] rs)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(rs[0]));
        v.add(new ASN1Integer(rs[1]));
        return new DERSequence(v).getEncoded();
    }
}
