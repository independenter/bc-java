package org.bouncycastle.learning.sm9;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.essence.Calc;
import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 签名 —— 对标 {@code Signature.getInstance("SM3withSM2","BC")}，用法几乎一样，
 * 但"验签方需要什么"是这两套体系的分水岭。
 *
 * <pre>
 *   签名（GB/T 32915.2 A1~A4）
 *     g = e(P1, Ppubs);  w = g^r;  h = H2(M‖w);  l = (r − h) mod n;  S = l·ds
 *   验签（B1~B5）
 *     P' = H1(ID,0x01)·P2 + Ppubs;  u = e(S,P');  t = g^h;  w = u·t;  核对 H2(M‖w) == h
 * </pre>
 *
 * <p>三点与 SM2 不同的地方，都会在本类的分支里体现：
 * <ol>
 *   <li><b>名字里的 SM3 不是"先摘要再签"</b>。SM2 的 Z‖M 走一遍 SM3 得到 e；SM9 的 H2 是把
 *       {@code 0x02‖M‖w} 走<b>两遍</b> SM3 再截前 40 字节 —— 摘要与签名不可分离，所以本类
 *       不接 MessageDigest，直接把 update 进来的字节整段交给 H2。
 *       {@code initSign(key)} 之后再 {@code update(...)} 只是攒消息，{@code sign()} 才真正调用一次引擎。</li>
 *   <li><b>随机数 r 必须逐次不可预测</b>（与 SM2 的 k 同理）：两个签名若复用同一个 r，
 *       差值 (h₁−h₂) 就能把 ds 直接解出来 —— 见 {@code Sm9SignEssenceTest} 的推导与测试。
 *       标准 A3 还要求 l=0 时回到 A2 重采，本类在 JCE 层重采，引擎保持"一次算完"的纯函数。</li>
 *   <li><b>验签方必须知道 ID</b>。SM2 里 ID 只影响杂凑值，SM9 里 ID 进了 P'，
 *       换 ID 就换公钥 —— 所以 {@link #engineInitVerify(PublicKey)} 之后，如果公钥对象里
 *       没带 ID，就必须 {@code setParameter(new SM9ParameterSpec(id))}。</li>
 * </ol>
 *
 * <p>输出编码用国标的 {@code SEQUENCE { OCTET STRING h, BIT STRING S }}（97 字节裸值 h‖S 的包装），
 * 与 {@code Sm9SignEssenceTest} 里核对过的 DER 完全一致。
 */
public class SM9SignatureSpi
    extends SignatureSpi
{
    /** 裸签名长度：h(32) + S(65)。 */
    private static final int RAW_SIGNATURE_LEN = 97;

    private SM9PrivateKey signingKey;
    private SM9PublicKey verifyKey;
    private byte[] id;
    private SecureRandom random = new SecureRandom();
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();

    public SM9SignatureSpi()
    {
    }

    // ---------------------------------------------------------------- 初始化

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        engineInitSign(privateKey, new SecureRandom());
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof SM9PrivateKey))
        {
            throw new InvalidKeyException("SM9 签名只接受 SM9PrivateKey，收到 "
                + (privateKey == null ? "null" : privateKey.getClass().getName()));
        }
        SM9PrivateKey key = (SM9PrivateKey) privateKey;
        if (key.getHid() != Sm9Math.HID_SIGN)
        {
            throw new InvalidKeyException("这把是加密体系的私钥（hid=0x"
                + Integer.toHexString(key.getHid()) + "）：SM9 的签名/加密私钥由 hid 分开导出，不能混用");
        }
        signingKey = key;
        verifyKey = null;
        // 用户私钥自带 ID；主私钥没有 ID，等 setParameter 来给
        this.id = key.getId();
        this.random = random == null ? new SecureRandom() : random;
        message.reset();
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof SM9PublicKey))
        {
            throw new InvalidKeyException("SM9 验签只接受 SM9PublicKey，收到 "
                + (publicKey == null ? "null" : publicKey.getClass().getName()));
        }
        SM9PublicKey key = (SM9PublicKey) publicKey;
        if (key.getHid() != Sm9Math.HID_SIGN)
        {
            throw new InvalidKeyException("这是加密主公钥 Ppube（hid=0x"
                + Integer.toHexString(key.getHid()) + "），验签要的是签名主公钥 Ppubs");
        }
        verifyKey = key;
        signingKey = null;
        this.id = key.getId();
        message.reset();
    }

    /** {@code setParameter(new SM9ParameterSpec(id))} —— 与 SM2 传 {@code SM2ParameterSpec} 同一路子。 */
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SM9ParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9 只接受 SM9ParameterSpec");
        }
        SM9ParameterSpec spec = (SM9ParameterSpec) params;
        if (spec.getHid() != Sm9Math.HID_SIGN)
        {
            throw new InvalidAlgorithmParameterException("签名流程的 hid 必须是 0x01，传的是 0x"
                + Integer.toHexString(spec.getHid()));
        }
        if (spec.getId() == null)
        {
            throw new InvalidAlgorithmParameterException("SM9ParameterSpec 里必须带标识");
        }
        this.id = spec.getId();
    }

    protected AlgorithmParameterSpec engineGetParameterSpec(Class<?> paramSpec)
        throws InvalidAlgorithmParameterException
    {
        return new SM9ParameterSpec(id, Sm9Math.HID_SIGN);
    }

    /**
     * 老的"按字符串取名"的参数接口（JDK 8 起就是抽象方法，必须实现）。
     * SM9 的参数只有标识一个，所以这里只回应该名字，其余一律拒绝 ——
     * 新代码应当走 {@link #engineSetParameter(AlgorithmParameterSpec)}。
     */
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException
    {
        if (!"ID".equalsIgnoreCase(param))
        {
            throw new InvalidParameterException("SM9 签名只有一个参数 ID，请求的是 " + param);
        }
        if (!(value instanceof byte[]))
        {
            throw new InvalidParameterException("ID 必须是 byte[]");
        }
        this.id = ((byte[]) value).clone();
    }

    protected Object engineGetParameter(String param)
        throws InvalidParameterException
    {
        if (!"ID".equalsIgnoreCase(param))
        {
            throw new InvalidParameterException("SM9 签名只有一个参数 ID，请求的是 " + param);
        }
        return id;
    }

    // ---------------------------------------------------------------- 攒消息

    protected void engineUpdate(byte input)
    {
        message.write(input);
    }

    protected void engineUpdate(byte[] input, int offset, int len)
    {
        message.write(input, offset, len);
    }

    // ---------------------------------------------------------------- 签名 / 验签

    protected byte[] engineSign()
        throws SignatureException
    {
        if (signingKey == null)
        {
            throw new SignatureException("还没 initSign，不能签名");
        }
        if (id == null)
        {
            throw new SignatureException("SM9 主私钥没有标识：请 setParameter(new SM9ParameterSpec(id))，"
                + "或者直接用带 ID 的用户私钥");
        }
        byte[] m = message.toByteArray();
        // 主私钥在这里现算 ds，用户私钥直接返回自带的点 —— 两条路都收敛成同一个点
        byte[] ds = signingKey.extractUserPoint(id);
        byte[] ppubs = signingKey.getMasterPublicKey();
        byte[] raw;
        while (true)
        {
            BigInteger r = Sm9Math.randScalar(random);
            try
            {
                raw = Sm9Math.signWithUserKey(m, id, ds, ppubs, r);
                break;
            }
            catch (IllegalArgumentException e)
            {
                // l = (r − h) mod n == 0：标准 A3 要求回到 A2 重采 r（概率约 2^-256）。
                // 重采是 JCE 层的职责，引擎保持"一次算完"的纯函数形态。
                continue;
            }
        }
        return toDer(raw);
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        if (verifyKey == null)
        {
            throw new SignatureException("还没 initVerify，不能验签");
        }
        if (id == null)
        {
            throw new SignatureException("验签必须知道签名者的标识：SM9 的公钥是 (ID, Ppubs) 一对，"
                + "请 setParameter(new SM9ParameterSpec(id)) 或用带 ID 的 SM9PublicKey");
        }
        byte[] raw = fromDer(sigBytes);
        return Sm9Math.verify(message.toByteArray(), raw, id,
            Sm9Math.twistFromOctets(verifyKey.getPoint()));
    }

    // ---------------------------------------------------------------- DER 包装

    /**
     * 国标 SM9 签名值：{@code SEQUENCE { OCTET STRING h(32), BIT STRING S(65) }}。
     * h 用 OCTET STRING（它就是 32 字节整数，不需要按位解释），S 是曲线点所以用 BIT STRING。
     */
    private static byte[] toDer(byte[] raw)
        throws SignatureException
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DEROctetString(Arrays.copyOfRange(raw, 0, 32)));
        vector.add(new DERBitString(Arrays.copyOfRange(raw, 32, RAW_SIGNATURE_LEN)));
        try
        {
            return new DERSequence(vector).getEncoded();
        }
        catch (IOException e)
        {
            throw new SignatureException("SM9 签名 DER 编码失败", e);
        }
    }

    /** 解回 97 字节裸值；长度不对直接当"签名格式错误"拒绝，不进引擎。 */
    private static byte[] fromDer(byte[] der)
        throws SignatureException
    {
        try
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(der);
            byte[] h = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
            byte[] s = ASN1BitString.getInstance(seq.getObjectAt(1)).getOctets();
            if (h.length != 32 || s.length != 65 || s[0] != 0x04)
            {
                throw new SignatureException("SM9 签名值必须是 h(32) + S(0x04 打头 65)，实际 "
                    + h.length + " + " + s.length);
            }
            return Calc.concat(h, s);
        }
        catch (SignatureException e)
        {
            throw e;
        }
        catch (RuntimeException e)
        {
            throw new SignatureException("SM9 签名值不是合法的 DER： " + e.getMessage());
        }
    }
}
