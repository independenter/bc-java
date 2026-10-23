package org.bouncycastle.learning.agreement;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;

/**
 * 面向过程版的国密密钥协商：ECC-SM4-SM3（合规、静态）与 ECDHE-SM4-SM3（要 PFS）各走一遍。
 *
 * <p>套件名的三段各管一件事，拆开名字就看懂了：
 * <ul>
 *   <li><b>前段（ECC / ECDHE）= 密钥怎么到手</b>：ECC-SM4-SM3 是客户端现抛一个 48 字节 pre_master，
 *       用<b>服务器长期 SM2 公钥加密</b>发过去（密钥传输）；ECDHE-SM4-SM3 走 GB/T 32918.3 的
 *       SM2 密钥交换协议，双方各出「长期密钥 + 本次临时密钥」两对，网络上谁也不发送秘密（密钥协商）。</li>
 *   <li><b>中段（SM4）= 记录层的分组算法</b>；<b>后段（SM3）= PRF 与 MAC 用的哈希</b>。</li>
 * </ul>
 * 前后两段的实质差别只有一条：<b>静态没有前向安全，临时有</b>。本文件把这条差别做成可执行的断言，而不是口号。
 *
 * <p>GB/T 32918.3 的核心计算在这里全部手写（普通静态方法 + for/while，零 lambda、零函数式接口）：
 * <ol>
 *   <li>Z = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py) —— 身份必须进哈希，否则对方的公钥可被中间人替换；</li>
 *   <li>x̄ = 2^w + (x AND (2^w − 1))，w = 域位宽/2 − 1 = 127 —— 只留一半，高位统一压成 2^w；</li>
 *   <li>t = (d_长期 + x̄(自己的临时点) · r_临时) mod n —— 长期与临时<b>混在同一个标量里</b>，这是协议的心跳；</li>
 *   <li>U = [h·t](P_对方长期 + x̄(对方临时点) · R_对方临时) —— 双方各自得到同一个 U；</li>
 *   <li>k = KDF_SM3(x_U ‖ y_U ‖ Z_A ‖ Z_B ‖ 4 字节大端计数器) —— 计数器从 1 开始，与 MGF1/P_hash 同族；</li>
 *   <li>S_A / S_B 密钥确认（BC 源码里叫 S1 / S2）—— 交换校验值，中间人换了 R 就在这一步暴露。</li>
 * </ol>
 * 每一段算完都拿 BC 的 {@code SM2KeyExchange} 当裁判：同一批输入必须给出<b>逐字节相同</b>的 k 与确认值。
 *
 * <p>与 {@code RsaKeyAgreementTest} 最重要的差别：那边"RSA 只认证、曲线只协商"，是两个密钥对各司其职；
 * 这边 SM2 的长期私钥<b>直接参与</b> t 的计算，所以协商本身自带身份认证（不需要额外的签名步骤），
 * 代价是双方都必须知道对方的 ID（Z 值的输入）。
 *
 * <p>风格说明：按用户要求写成<b>面向过程</b> —— 没有 {@code Function}/{@code BiFunction}，没有 lambda，
 * 没有 {@code IntStream}，只有普通静态方法、{@code for}/{@code while} 和局部变量。
 */
@Slf4j
public class Sm2KeyAgreementTest
{
    private static final Charset UTF8 = Charset.forName("UTF-8");

    /** GB/T 32918 里的用户标识 ID_A / ID_B；实际系统里通常是统一社会信用代码或设备序列号。 */
    private static final byte[] ID_A = "alice@example.cn".getBytes(UTF8);
    private static final byte[] ID_B = "bob@example.cn".getBytes(UTF8);

    private static final int SM3_BYTES = 32;
    private static final int SM4_KEY_BYTES = 16;
    private static final int SM4_IV_BYTES = 16;
    private static final int PRE_MASTER_BYTES = 48;   // TLS 结构：2 字节版本号 + 46 字节随机
    private static final int MASTER_SECRET_BYTES = 48;

    /** 双向 SM4 密钥 + 双向 IV + 双向 HMAC-SM3 密钥 = 记录层需要的全部字节。 */
    private static final int SESSION_KEY_BYTES = 2 * SM4_KEY_BYTES + 2 * SM4_IV_BYTES + 2 * SM3_BYTES;

    private static final ECDomainParameters SM2_DOMAIN = sm2Domain();

    static ECDomainParameters sm2Domain()
    {
        X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
        return new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    }

    static void useBc()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---------------------------------------------------------------- 基础过程

    static byte[] concat(byte[]... parts)
    {
        try
        {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int i = 0; i < parts.length; i++)
            {
                out.write(parts[i], 0, parts[i].length);
            }
            return out.toByteArray();
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e);
        }
    }

    static byte[] randomBytes(int count)
    {
        byte[] out = new byte[count];
        new SecureRandom().nextBytes(out);
        return out;
    }

    /** 抛一个 [1, n-1] 的标量 —— 长期密钥和临时密钥都这么来，差别只在"存不存"。 */
    static BigInteger randomScalar()
    {
        BigInteger n = SM2_DOMAIN.getN();
        SecureRandom random = new SecureRandom();
        BigInteger d;
        do
        {
            d = new BigInteger(n.bitLength(), random);
        }
        while (d.signum() == 0 || d.compareTo(n) >= 0);
        return d;
    }

    static ECPoint baseMultiply(BigInteger d)
    {
        return SM2_DOMAIN.getG().multiply(d).normalize();
    }

    static byte[] sm3(byte[] data)
    {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] out = new byte[SM3_BYTES];
        digest.doFinal(out, 0);
        return out;
    }

    static byte[] sm3(byte[] first, byte[] second)
    {
        SM3Digest digest = new SM3Digest();
        digest.update(first, 0, first.length);
        digest.update(second, 0, second.length);
        byte[] out = new byte[SM3_BYTES];
        digest.doFinal(out, 0);
        return out;
    }

    /** 域元素定宽编码：sm2p256v1 是 256-bit 域，所以永远是 32 字节（Z 值与 KDF 都要求定宽）。 */
    static byte[] fieldBytes(ECFieldElement element)
    {
        return element.getEncoded();
    }

    static byte[] bigEndian32(int value)
    {
        return new byte[]{ (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value };
    }

    // ---------------------------------------------------------------- 第 1 步：Z 值（把身份绑进哈希）

    /**
     * Z = SM3(ENTL ‖ ID ‖ a ‖ b ‖ xG ‖ yG ‖ Px ‖ Py)。
     * ENTL 是 ID 的<b>比特</b>长度（两字节大端），不是字节长度 —— 写错这里 Z 就全变了。
     */
    static byte[] zValue(byte[] userId, ECPoint publicKey)
    {
        int bitLen = userId.length * 8;

        SM3Digest digest = new SM3Digest();
        digest.update((byte) (bitLen >>> 8));
        digest.update((byte) bitLen);
        digest.update(userId, 0, userId.length);

        byte[] a = fieldBytes(SM2_DOMAIN.getCurve().getA());
        byte[] b = fieldBytes(SM2_DOMAIN.getCurve().getB());
        byte[] gx = fieldBytes(SM2_DOMAIN.getG().getAffineXCoord());
        byte[] gy = fieldBytes(SM2_DOMAIN.getG().getAffineYCoord());
        byte[] px = fieldBytes(publicKey.getAffineXCoord());
        byte[] py = fieldBytes(publicKey.getAffineYCoord());

        digest.update(a, 0, a.length);
        digest.update(b, 0, b.length);
        digest.update(gx, 0, gx.length);
        digest.update(gy, 0, gy.length);
        digest.update(px, 0, px.length);
        digest.update(py, 0, py.length);

        byte[] out = new byte[SM3_BYTES];
        digest.doFinal(out, 0);
        return out;
    }

    // ---------------------------------------------------------------- 第 2 步：x̄ 截半

    /** x̄ = 2^w + (x AND (2^w − 1))，w = 曲线域位宽 / 2 − 1；SM2 是 256/2 − 1 = 127。 */
    static int wValue()
    {
        return SM2_DOMAIN.getCurve().getFieldSize() / 2 - 1;
    }

    /**
     * 注意是"把高 129 位扔掉、高位强制置成 2^w"，不是取模 —— 这样 x̄ 一定落在 [2^127, 2^128)，
     * 分布与原始 x 坐标一样均匀，而 t 的求解难度不依赖"从半个 x 还原私钥"。
     */
    static BigInteger reduceX(BigInteger x)
    {
        int w = wValue();
        BigInteger mask = BigInteger.ONE.shiftLeft(w).subtract(BigInteger.ONE);
        return x.and(mask).setBit(w);
    }

    // ---------------------------------------------------------------- 第 3 步：t 与 U

    /** t = (d_长期 + x̄(自己的临时点) · r_临时) mod n。 */
    static BigInteger computeT(BigInteger staticPrivate, BigInteger ephemeralPrivate, ECPoint ownEphemeralPoint)
    {
        BigInteger xBar = reduceX(ownEphemeralPoint.getAffineXCoord().toBigInteger());
        return staticPrivate.add(xBar.multiply(ephemeralPrivate)).mod(SM2_DOMAIN.getN());
    }

    static BigInteger scalarK1(BigInteger t)
    {
        return SM2_DOMAIN.getH().multiply(t).mod(SM2_DOMAIN.getN());
    }

    /** 展开写法：U = [k1]P_对方长期 + [k2]R_对方临时，其中 k2 = k1 · x̄_对方临时。 */
    static ECPoint computeU(BigInteger t, ECPoint otherStatic, ECPoint otherEphemeral)
    {
        BigInteger k1 = scalarK1(t);
        BigInteger k2 = k1.multiply(reduceX(otherEphemeral.getAffineXCoord().toBigInteger()))
            .mod(SM2_DOMAIN.getN());
        return otherStatic.multiply(k1).add(otherEphemeral.multiply(k2)).normalize();
    }

    /** 先加后乘写法（协议原文的形状）：U = [k1](P + [x̄]R)。与 computeU 必须给出同一个点。 */
    static ECPoint computeUFactored(BigInteger t, ECPoint otherStatic, ECPoint otherEphemeral)
    {
        BigInteger k1 = scalarK1(t);
        ECPoint inner = otherStatic.add(otherEphemeral.multiply(
            reduceX(otherEphemeral.getAffineXCoord().toBigInteger()))).normalize();
        return inner.multiply(k1).normalize();
    }

    // ---------------------------------------------------------------- 第 4 步：KDF 与密钥确认

    /** KDF_SM3：计数器从 1 开始，每轮出 32 字节，直到凑够 keyLengthBits 位。 */
    static byte[] kdfSm3(ECPoint u, byte[] zFirst, byte[] zSecond, int keyLengthBits)
    {
        byte[] prefix = concat(fieldBytes(u.getAffineXCoord()), fieldBytes(u.getAffineYCoord()), zFirst, zSecond);

        byte[] out = new byte[(keyLengthBits + 7) / 8];
        int off = 0;
        int counter = 1;
        while (off < out.length)
        {
            byte[] hash = sm3(prefix, bigEndian32(counter));
            int take = Math.min(hash.length, out.length - off);
            System.arraycopy(hash, 0, out, off, take);
            off += take;
            counter++;
        }
        return out;
    }

    /** 确认值的内层哈希：x_U ‖ Z_A ‖ Z_B ‖ 发起方临时点 ‖ 响应方临时点（顺序固定为发起方在前）。 */
    static byte[] innerHash(ECPoint u, byte[] zA, byte[] zB, ECPoint initiatorEphemeral, ECPoint responderEphemeral)
    {
        return sm3(concat(fieldBytes(u.getAffineXCoord()), zA, zB,
            fieldBytes(initiatorEphemeral.getAffineXCoord()),
            fieldBytes(initiatorEphemeral.getAffineYCoord()),
            fieldBytes(responderEphemeral.getAffineXCoord()),
            fieldBytes(responderEphemeral.getAffineYCoord())));
    }

    /** S_A / S_B：BC 源码里叫 S1 / S2，唯一区别是 0x02 / 0x03 这个方向字节。 */
    static byte[] confirmationTag(byte directionMarker, ECPoint u, byte[] inner)
    {
        return sm3(concat(new byte[]{ directionMarker }, fieldBytes(u.getAffineYCoord()), inner));
    }

    /**
     * 完整一遍 SM2 密钥交换（手写的过程版本），返回 {k, S_A, S_B}。
     * initiator=true 时"自己"是 A（用自己的 d/r、对方的 P/R），false 时"自己"是 B。
     */
    static byte[][] ownKeyExchange(boolean initiator, BigInteger ownStatic, BigInteger ownEphemeral,
        ECPoint ownStaticPoint, ECPoint ownEphemeralPoint, byte[] ownId,
        ECPoint otherStaticPoint, ECPoint otherEphemeralPoint, byte[] otherId, int keyLengthBits)
    {
        // KDF 与内层哈希永远按「Z_A 在前、Z_B 在后」读，与"我是哪一方"无关 —— 这是双方能对齐的关键
        byte[] zA = initiator ? zValue(ownId, ownStaticPoint) : zValue(otherId, otherStaticPoint);
        byte[] zB = initiator ? zValue(otherId, otherStaticPoint) : zValue(ownId, ownStaticPoint);
        ECPoint rA = initiator ? ownEphemeralPoint : otherEphemeralPoint;
        ECPoint rB = initiator ? otherEphemeralPoint : ownEphemeralPoint;

        BigInteger t = computeT(ownStatic, ownEphemeral, ownEphemeralPoint);
        ECPoint u = computeU(t, otherStaticPoint, otherEphemeralPoint);

        byte[] k = kdfSm3(u, zA, zB, keyLengthBits);
        byte[] inner = innerHash(u, zA, zB, rA, rB);
        return new byte[][]{ k, confirmationTag((byte) 0x02, u, inner), confirmationTag((byte) 0x03, u, inner) };
    }

    // ---------------------------------------------------------------- SM3 版 PRF（GM TLS 与 TLS 1.2 同构，只换哈希）

    /** P_hash 的 SM3 版：A(i) = HMAC(secret, A(i-1))，输出块 = HMAC(secret, A(i) ‖ seed)。 */
    static byte[] pHashSm3(byte[] secret, byte[] seed, int length)
        throws Exception
    {
        Mac hmac = Mac.getInstance("HmacSM3", "BC");
        hmac.init(new SecretKeySpec(secret, "HmacSM3"));

        byte[] out = new byte[length];
        int off = 0;
        byte[] a = seed;                                  // A(0) == seed
        while (off < length)
        {
            a = hmac.doFinal(a);
            byte[] block = hmac.doFinal(concat(a, seed));
            int take = Math.min(block.length, length - off);
            System.arraycopy(block, 0, out, off, take);
            off += take;
        }
        return out;
    }

    /** label 把"用途"绑进密钥里：master secret 与 key expansion 必须派生出不同的材料。 */
    static byte[] gmPrf(byte[] secret, String label, byte[] seed, int length)
        throws Exception
    {
        return pHashSm3(secret, concat(label.getBytes(UTF8), seed), length);
    }

    /** 会话密钥材料切分：双向 SM4 密钥 + 双向 IV + 双向 HMAC-SM3 密钥。 */
    static byte[][] splitSessionKeys(byte[] material)
    {
        byte[] clientKey = Arrays.copyOfRange(material, 0, SM4_KEY_BYTES);
        byte[] serverKey = Arrays.copyOfRange(material, SM4_KEY_BYTES, 2 * SM4_KEY_BYTES);
        byte[] clientIv = Arrays.copyOfRange(material, 2 * SM4_KEY_BYTES, 2 * SM4_KEY_BYTES + SM4_IV_BYTES);
        byte[] serverIv = Arrays.copyOfRange(material, 2 * SM4_KEY_BYTES + SM4_IV_BYTES,
            2 * (SM4_KEY_BYTES + SM4_IV_BYTES));
        byte[] clientMac = Arrays.copyOfRange(material, 2 * (SM4_KEY_BYTES + SM4_IV_BYTES),
            2 * (SM4_KEY_BYTES + SM4_IV_BYTES) + SM3_BYTES);
        byte[] serverMac = Arrays.copyOfRange(material, 2 * (SM4_KEY_BYTES + SM4_IV_BYTES) + SM3_BYTES,
            SESSION_KEY_BYTES);
        return new byte[][]{ clientKey, serverKey, clientIv, serverIv, clientMac, serverMac };
    }

    // ---------------------------------------------------------------- 记录层：SM4-CBC + HMAC-SM3（先加密后认证，TLS 1.1 的形状）

    static byte[] sm4Cbc(boolean encrypting, byte[] key, byte[] iv, byte[] data)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "BC");
        cipher.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    static byte[] hmacSm3(byte[] key, byte[] data)
        throws Exception
    {
        Mac hmac = Mac.getInstance("HmacSM3", "BC");
        hmac.init(new SecretKeySpec(key, "HmacSM3"));
        return hmac.doFinal(data);
    }

    /** 记录形状（本文件的简化版）：IV ‖ HMAC-SM3(IV ‖ 密文 ‖ 序号) ‖ SM4-CBC 密文。 */
    static byte[] sealRecord(byte[] key, byte[] iv, byte[] macKey, int sequence, byte[] plain)
        throws Exception
    {
        byte[] body = sm4Cbc(true, key, iv, plain);
        byte[] tag = hmacSm3(macKey, concat(iv, body, bigEndian32(sequence)));
        return concat(iv, tag, body);
    }

    static byte[] openRecord(byte[] key, byte[] macKey, int sequence, byte[] record)
        throws Exception
    {
        byte[] recvIv = Arrays.copyOfRange(record, 0, SM4_IV_BYTES);
        byte[] recvTag = Arrays.copyOfRange(record, SM4_IV_BYTES, SM4_IV_BYTES + SM3_BYTES);
        byte[] body = Arrays.copyOfRange(record, SM4_IV_BYTES + SM3_BYTES, record.length);

        byte[] expect = hmacSm3(macKey, concat(recvIv, body, bigEndian32(sequence)));
        if (!java.security.MessageDigest.isEqual(expect, recvTag))
        {
            throw new IllegalStateException("记录 MAC 校验失败");
        }
        return sm4Cbc(false, key, recvIv, body);
    }

    // ---------------------------------------------------------------- BC 裁判

    /** BC 的私钥侧参数会自己从私钥推出公钥点，所以只需要交 d 与 r。 */
    static SM2KeyExchange bcExchange(boolean initiator, BigInteger staticPrivate, BigInteger ephemeralPrivate,
        byte[] ownId)
    {
        SM2KeyExchangePrivateParameters privateParameters = new SM2KeyExchangePrivateParameters(initiator,
            new ECPrivateKeyParameters(staticPrivate, SM2_DOMAIN),
            new ECPrivateKeyParameters(ephemeralPrivate, SM2_DOMAIN));
        SM2KeyExchange exchange = new SM2KeyExchange();
        exchange.init(new ParametersWithID(privateParameters, ownId));
        return exchange;
    }

    static byte[] bcKey(SM2KeyExchange exchange, ECPoint otherStatic, ECPoint otherEphemeral, byte[] otherId,
        int keyLengthBits)
    {
        SM2KeyExchangePublicParameters publicParameters = new SM2KeyExchangePublicParameters(
            new ECPublicKeyParameters(otherStatic, SM2_DOMAIN),
            new ECPublicKeyParameters(otherEphemeral, SM2_DOMAIN));
        return exchange.calculateKey(keyLengthBits, new ParametersWithID(publicParameters, otherId));
    }

    static byte[][] bcKeyWithConfirmation(SM2KeyExchange exchange, ECPoint otherStatic, ECPoint otherEphemeral,
        byte[] otherId, byte[] peerConfirmationTag, int keyLengthBits)
    {
        SM2KeyExchangePublicParameters publicParameters = new SM2KeyExchangePublicParameters(
            new ECPublicKeyParameters(otherStatic, SM2_DOMAIN),
            new ECPublicKeyParameters(otherEphemeral, SM2_DOMAIN));
        return exchange.calculateKeyWithConfirmation(keyLengthBits, peerConfirmationTag,
            new ParametersWithID(publicParameters, otherId));
    }

    // ---------------------------------------------------------------- 测试

    /**
     * ECDHE-SM4-SM3 的心脏：手写的 GB/T 32918.3 与 BC 的 {@code SM2KeyExchange} 逐字节相同，
     * 而且 A、B 从各自的视角算出同一个 k —— 网络上只走了两个临时点，没有任何秘密被发送。
     */
    @Test
    public void handWrittenSm2KeyExchangeMatchesBcOnBothSides()
        throws Exception
    {
        useBc();

        // 双方各有：长期密钥对（存下来）+ 本次临时密钥对（用完丢）
        BigInteger dA = randomScalar(), rA = randomScalar();
        BigInteger dB = randomScalar(), rB = randomScalar();
        ECPoint pA = baseMultiply(dA), ra = baseMultiply(rA);
        ECPoint pB = baseMultiply(dB), rb = baseMultiply(rB);
        int bits = SESSION_KEY_BYTES * 8;

        // 1) x̄ 的形状先钉死：高位被压成 2^127，所以位长恰好 128
        BigInteger xBar = reduceX(ra.getAffineXCoord().toBigInteger());
        Assert.assertEquals("w = 域位宽/2 - 1 = 127", 127, wValue());
        Assert.assertEquals("x̄ 必须落在 [2^127, 2^128)", 128, xBar.bitLength());
        Assert.assertEquals("x̄ 的低 127 位必须就是原 x 坐标的低 127 位",
            ra.getAffineXCoord().toBigInteger().and(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)),
            xBar.and(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)));

        // 2) U 的两种写法（分配律）必须给出同一个点
        BigInteger tA = computeT(dA, rA, ra);
        Assert.assertTrue("先加后乘与两次点乘必须等价",
            computeU(tA, pB, rb).equals(computeUFactored(tA, pB, rb)));

        // 3) A 与 B 从各自视角协商
        byte[][] fromA = ownKeyExchange(true, dA, rA, pA, ra, ID_A, pB, rb, ID_B, bits);
        byte[][] fromB = ownKeyExchange(false, dB, rB, pB, rb, ID_B, pA, ra, ID_A, bits);
        Assert.assertEquals("k 的长度 = 记录层需要的字节数", SESSION_KEY_BYTES, fromA[0].length);
        Assert.assertArrayEquals("A 与 B 必须算出同一个会话密钥（网络上只有两个临时点）", fromA[0], fromB[0]);

        // 4) 裁判：BC 的两个方向
        byte[] bcKeyA = bcKey(bcExchange(true, dA, rA, ID_A), pB, rb, ID_B, bits);
        byte[] bcKeyB = bcKey(bcExchange(false, dB, rB, ID_B), pA, ra, ID_A, bits);
        Assert.assertArrayEquals("手写的 k 必须与 BC 逐字节相同（发起方视角）", bcKeyA, fromA[0]);
        Assert.assertArrayEquals("手写的 k 必须与 BC 逐字节相同（响应方视角）", bcKeyB, fromB[0]);

        log.info("[ECDHE-SM4-SM3] 手写 t=(d+x̄r) mod n、U 两次点乘、KDF_SM3 计数器 -> k={} 字节，与 BC 一致",
            fromA[0].length);
    }

    /**
     * PFS 的可数定义 + 静态/临时对照：只换临时密钥，k 必须换；握着长期私钥和全部抓包也推不出旧会话的 k。
     * 而 ECC-SM4-SM3 那边 pre_master 是被长期公钥加密发送的，私钥一泄露，十年前的流量照样解。
     */
    @Test
    public void ephemeralSm2ExchangeHasForwardSecrecyWhileStaticTransportDoesNot()
        throws Exception
    {
        useBc();

        BigInteger dA = randomScalar(), dB = randomScalar();
        ECPoint pA = baseMultiply(dA), pB = baseMultiply(dB);
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);
        int bits = SESSION_KEY_BYTES * 8;

        // ---- 会话 1：临时密钥 rA1 / rB1
        BigInteger rA1 = randomScalar(), rB1 = randomScalar();
        ECPoint ra1 = baseMultiply(rA1), rb1 = baseMultiply(rB1);
        byte[] k1 = ownKeyExchange(true, dA, rA1, pA, ra1, ID_A, pB, rb1, ID_B, bits)[0];

        // ---- 会话 2：长期密钥一模一样，只换临时密钥
        BigInteger rA2 = randomScalar(), rB2 = randomScalar();
        byte[] k2 = ownKeyExchange(true, dA, rA2, pA, baseMultiply(rA2), ID_A, pB, baseMultiply(rB2), ID_B, bits)[0];
        Assert.assertFalse("临时密钥一换，会话密钥必然不同 —— 这就是前向安全", Arrays.equals(k1, k2));

        // 派生层跟着全变：k 变了，master_secret 与记录层密钥全都变
        byte[] master1 = gmPrf(k1, "master secret", concat(clientRandom, serverRandom), MASTER_SECRET_BYTES);
        byte[] master2 = gmPrf(k2, "master secret", concat(clientRandom, serverRandom), MASTER_SECRET_BYTES);
        Assert.assertFalse("master_secret 随 k 变化", Arrays.equals(master1, master2));
        Assert.assertFalse("同一秘密不同 label 必然得到不同材料（label 绑用途）",
            Arrays.equals(gmPrf(k1, "master secret", clientRandom, MASTER_SECRET_BYTES),
                gmPrf(k1, "key expansion", clientRandom, MASTER_SECRET_BYTES)));

        // ---- 攻击者视角：握有 dA、dB，抓到 R_A1/R_B1（临时私钥早丢了），只能瞎猜 r_A
        byte[] guessed = ownKeyExchange(true, dA, BigInteger.ONE, pA, baseMultiply(BigInteger.ONE),
            ID_A, pB, rb1, ID_B, bits)[0];
        Assert.assertFalse("只有长期私钥推不出当时的 r_A，历史会话密钥不可还原", Arrays.equals(k1, guessed));
        byte[] guessedMaster = gmPrf(guessed, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);
        Assert.assertFalse("猜出来的 k 得到另一个 master_secret", Arrays.equals(master1, guessedMaster));

        // ---- 对照：ECC-SM4-SM3 的静态密钥传输，没有任何临时成分
        byte[] preMaster = randomBytes(PRE_MASTER_BYTES);
        SM2Engine enc = new SM2Engine(SM2Engine.Mode.C1C3C2);
        enc.init(true, new ParametersWithRandom(new ECPublicKeyParameters(pB, SM2_DOMAIN), new SecureRandom()));
        byte[] transported = enc.processBlock(preMaster, 0, preMaster.length);

        // 当时：服务器用长期私钥正常解出 pre_master
        SM2Engine dec = new SM2Engine(SM2Engine.Mode.C1C3C2);
        dec.init(false, new ECPrivateKeyParameters(dB, SM2_DOMAIN));
        Assert.assertArrayEquals("服务器用长期私钥解开 pre_master", preMaster,
            dec.processBlock(transported, 0, transported.length));

        // 十年后私钥泄露（或法院要求交出）：把当年存下的密文重放，一切还原
        SM2Engine subpoena = new SM2Engine(SM2Engine.Mode.C1C3C2);
        subpoena.init(false, new ECPrivateKeyParameters(dB, SM2_DOMAIN));
        byte[] replayed = subpoena.processBlock(transported, 0, transported.length);
        Assert.assertArrayEquals("静态套件的 pre_master 能被长期私钥事后解密 —— 无前向安全", preMaster, replayed);
        byte[] replayedMaster = gmPrf(replayed, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);
        byte[] masterFromOriginalPre = gmPrf(preMaster, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);
        Assert.assertArrayEquals("重放得到的 master_secret 与当年完全相同：全部历史流量裸奔",
            masterFromOriginalPre, replayedMaster);

        // 而 ECDHE 那边根本不存在"被加密发送的秘密"，网络里只有两个公开点
        log.info("[ECC vs ECDHE-SM4-SM3] 静态=pre_master 上线可被事后解密；临时=长期私钥泄露也无用（guessed k 不同）");
    }

    /**
     * 密钥确认（S_A / S_B）与记录层：确认值能当场抓出"替换临时点"的中间人；
     * k 扩展出的双向 SM4 密钥 / IV / MAC 密钥双向可用，改一 bit 记录必须被拒。
     */
    @Test
    public void confirmationTagsCatchMitmAndKeysProtectRecordsBothWays()
        throws Exception
    {
        useBc();

        BigInteger dA = randomScalar(), rA = randomScalar();
        BigInteger dB = randomScalar(), rB = randomScalar();
        ECPoint pA = baseMultiply(dA), ra = baseMultiply(rA);
        ECPoint pB = baseMultiply(dB), rb = baseMultiply(rB);
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);
        int bits = SESSION_KEY_BYTES * 8;

        // 1) 双方都算得出 S_A / S_B，且互相一致
        byte[][] a = ownKeyExchange(true, dA, rA, pA, ra, ID_A, pB, rb, ID_B, bits);
        byte[][] b = ownKeyExchange(false, dB, rB, pB, rb, ID_B, pA, ra, ID_A, bits);
        Assert.assertArrayEquals("A 算的 S_A 必须等于 B 算的 S_A", a[1], b[1]);
        Assert.assertArrayEquals("A 算的 S_B 必须等于 B 算的 S_B", a[2], b[2]);
        Assert.assertFalse("S_A 与 S_B 必须不同（方向字节 0x02 / 0x03 的作用）", Arrays.equals(a[1], a[2]));

        // 2) 裁判：BC 的响应方分支返回 {k, S_A, S_B}
        byte[][] responderOut = bcKeyWithConfirmation(bcExchange(false, dB, rB, ID_B), pA, ra, ID_A, a[1], bits);
        Assert.assertArrayEquals("BC 响应方解出的 k 与我们的一致", b[0], responderOut[0]);
        Assert.assertArrayEquals("BC 响应方算出的 S_A（下标 1）与我们的一致", a[1], responderOut[1]);
        Assert.assertArrayEquals("BC 响应方算出的 S_B（下标 2）与我们的一致", a[2], responderOut[2]);

        // 3) 裁判：BC 的发起方分支只返回 {k, S_B}，并会校验收到的 S_A
        byte[][] initiatorOut = bcKeyWithConfirmation(bcExchange(true, dA, rA, ID_A), pB, rb, ID_B, b[1], bits);
        Assert.assertArrayEquals("BC 发起方解出的 k 与我们的一致", a[0], initiatorOut[0]);
        Assert.assertArrayEquals("BC 发起方算出的 S_B 与我们的一致（它不返回 S_A，那是它正在校验的那枚）",
            a[2], initiatorOut[1]);

        // 4) 中间人把 B 的临时点换成自己的：A 仍算得出某个 k，但 S_A 对不上
        BigInteger rEvil = randomScalar();
        ECPoint rEvilPoint = baseMultiply(rEvil);
        byte[][] evilView = ownKeyExchange(false, dB, rEvil, pB, rEvilPoint, ID_B, pA, ra, ID_A, bits);
        Assert.assertFalse("换掉临时点之后 k 必然不同", Arrays.equals(b[0], evilView[0]));
        Assert.assertFalse("换掉临时点之后 S_A 必然对不上", Arrays.equals(a[1], evilView[1]));

        boolean thrownByEvilTag = false;
        try
        {
            bcKeyWithConfirmation(bcExchange(true, dA, rA, ID_A), pB, rb, ID_B, evilView[1], bits);
        }
        catch (IllegalStateException expected)
        {
            thrownByEvilTag = true;
        }
        Assert.assertTrue("BC 的发起方分支必须用确认值把中间人当场抛出", thrownByEvilTag);

        // 5) 记录层：k 扩展出双向 SM4 密钥/IV/MAC 密钥，两个方向各走一遍
        //    key expansion 的 seed 顺序反过来（server 在前）—— 正序会让双向材料对称，成了反射攻击的温床
        byte[] material = gmPrf(a[0], "key expansion", concat(serverRandom, clientRandom), SESSION_KEY_BYTES);
        byte[][] keys = splitSessionKeys(material);
        Assert.assertEquals("会话密钥材料正好切出 6 段", SESSION_KEY_BYTES, material.length);

        byte[] note = "国密记录层双向可用".getBytes(UTF8);
        byte[] wire = sealRecord(keys[0], keys[2], keys[4], 1, note);
        Assert.assertArrayEquals("A 发 B 收", note, openRecord(keys[0], keys[4], 1, wire));
        byte[] back = sealRecord(keys[1], keys[3], keys[5], 1, "ack".getBytes(UTF8));
        Assert.assertArrayEquals("B 发 A 收", "ack".getBytes(UTF8), openRecord(keys[1], keys[5], 1, back));

        // 6) 篡改：改密文一 bit、改序号，MAC 都必须先失败（先认证后解密）
        byte[] tamperedBody = wire.clone();
        tamperedBody[tamperedBody.length - 1] ^= 1;
        Assert.assertTrue("改一 bit 密文必须被 MAC 拦住", recordRejected(keys[0], keys[4], 1, tamperedBody));
        Assert.assertTrue("重放成另一个序号必须被拦住", recordRejected(keys[0], keys[4], 2, wire));
        Assert.assertFalse("拿另一方向的写密钥来解，必然解不回原明文",
            recordDecryptsTo(keys[1], keys[4], 1, wire, note));

        Assert.assertFalse("client/server 的 SM4 密钥不能相同", Arrays.equals(keys[0], keys[1]));
        Assert.assertFalse("client/server 的 IV 不能相同", Arrays.equals(keys[2], keys[3]));
        log.info("[ECC-SM4-SM3 记录层] S_A/S_B 与 BC 对齐，k={} 字节扩展出 SM4 key/iv + HMAC-SM3 key", a[0].length);
    }

    /** MAC 不通过就必须抛异常 —— 返回值只是把"抛了"变成一个可断言的布尔。 */
    static boolean recordRejected(byte[] key, byte[] macKey, int sequence, byte[] record)
    {
        try
        {
            openRecord(key, macKey, sequence, record);
            return false;
        }
        catch (Exception expected)
        {
            return true;
        }
    }

    /** 能否解回期望的明文：MAC 失败或填充/内容不对都算"解不出"。 */
    static boolean recordDecryptsTo(byte[] key, byte[] macKey, int sequence, byte[] record, byte[] expected)
    {
        try
        {
            return Arrays.equals(expected, openRecord(key, macKey, sequence, record));
        }
        catch (Exception e)
        {
            return false;
        }
    }

    /**
     * Z 值的身份绑定：换 ID 就换 Z，Z 进 KDF 就换 k —— 这是"国密协商双方都必须带正确 ID"的真正原因，
     * 也是 SM2 协商自带认证的原因（不需要 TLS 那样额外签一段 ServerKeyExchange）。
     */
    @Test
    public void zValueBindsIdentityIntoTheSessionKey()
        throws Exception
    {
        useBc();

        BigInteger dA = randomScalar(), rA = randomScalar();
        BigInteger dB = randomScalar(), rB = randomScalar();
        ECPoint pA = baseMultiply(dA), ra = baseMultiply(rA);
        ECPoint pB = baseMultiply(dB), rb = baseMultiply(rB);
        int bits = SESSION_KEY_BYTES * 8;

        // 1) Z 的形状与敏感性
        byte[] zAlice = zValue(ID_A, pA);
        Assert.assertEquals("Z 值就是一枚 SM3 摘要：32 字节", SM3_BYTES, zAlice.length);
        Assert.assertFalse("换 ID 必须换 Z",
            Arrays.equals(zAlice, zValue("mallory@example.cn".getBytes(UTF8), pA)));
        Assert.assertFalse("换公钥必须换 Z", Arrays.equals(zAlice, zValue(ID_A, pB)));

        // ENTL 用比特而不是字节：16 字节的 ID_A 是 128 比特，少一个字符就少 8 比特
        byte[] idShort = "alice@example.c".getBytes(UTF8);
        Assert.assertEquals("ENTL 是比特长度", 128, ID_A.length * 8);
        Assert.assertEquals("少一个字符就是少 8 比特", 120, idShort.length * 8);
        Assert.assertFalse("ID 少一个字符必然换 Z", Arrays.equals(zAlice, zValue(idShort, pA)));

        // 2) Z 进 KDF，所以 ID 错配 -> 双方算出不同的 k（不是"报错"，而是安静地拿到两把不同的密钥）
        byte[][] correct = ownKeyExchange(true, dA, rA, pA, ra, ID_A, pB, rb, ID_B, bits);
        byte[] swappedIds = ownKeyExchange(true, dA, rA, pA, ra, ID_B, pB, rb, ID_A, bits)[0];
        Assert.assertFalse("身份 ID 换了会换会话密钥 —— 协商必须双方的 ID 都正确",
            Arrays.equals(correct[0], swappedIds));

        // 3) 裁判：BC 显式 ID 与我们的手写一致；BC 用空 ID 必然得到另一个 k
        byte[] bcWithIds = bcKey(bcExchange(true, dA, rA, ID_A), pB, rb, ID_B, bits);
        Assert.assertArrayEquals("我们的 k 与 BC（同样的显式 ID）逐字节一致", bcWithIds, correct[0]);

        SM2KeyExchange emptyId = new SM2KeyExchange();
        emptyId.init(new SM2KeyExchangePrivateParameters(true,
            new ECPrivateKeyParameters(dA, SM2_DOMAIN), new ECPrivateKeyParameters(rA, SM2_DOMAIN)));
        byte[] bcEmpty = bcKey(emptyId, pB, rb, new byte[0], bits);
        Assert.assertFalse("BC 用空 ID 得到另一个 k（默认 ID 是空串，不是任意字符串）",
            Arrays.equals(bcWithIds, bcEmpty));

        // 4) 与 RSA 体系的对照：SM2 的长期私钥进了 t，所以协商本身就认证了身份
        //    抓包者替换 R 会改变 x̄，从而改变 t/U/k 与两枚确认值 —— 上面第 4 步已把它做成断言
        log.info("[SM2-Z 值] Z=SM3(ENTLA‖ID‖a‖b‖xG‖yG‖xA‖yA)，ID 进哈希即身份进密钥；协商自带认证");
    }
}
