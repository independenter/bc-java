package org.bouncycastle.learning.sm9;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.essence.Calc;
import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 私钥 —— 一个类装下两种形态，因为基于标识密码里"谁持有密钥"决定了密钥的形状：
 * <pre>
 *   KGC（密钥生成中心）持有 主私钥：ks / ke —— 一个 32 字节的<b>标量</b>
 *   用户（Alice）持有 用户私钥：ds ∈ G₁（65 字节）/ de ∈ G₂（129 字节）—— 一个<b>点</b>
 * </pre>
 * 两者的关系是标准里那条除法：
 * <pre>
 *   ds = ks · (ks + H1(ID, 0x01))⁻¹ · P1        de = ke · (ke + H1(ID, 0x03))⁻¹ · P2
 * </pre>
 * 标识进了分母，所以"用户私钥"天生绑定 ID，换 ID 就用不了 —— 这是 SM9 不需要证书的原因，
 * 也是它必须把主私钥保密的原因（拿到 ks 的人可以给<b>任何</b>标识导出私钥）。
 *
 * <p>{@link #isMasterKey()} 为 true 时本对象代表 KGC；此时 {@link #extractUserPoint(byte[])}
 * 会现算出某个标识的用户私钥点，JCE 层因此能同时支持两种用法：
 * <ul>
 *   <li>{@code initSign(主私钥) + setParameter(ID)} —— KGC 代签，等价于 GmSSL 那几个以 ks/ke 为入参的高层 API；</li>
 *   <li>{@code initSign(用户私钥)} —— 真实终端的形态，设备里根本没有主私钥。</li>
 * </ul>
 *
 * <p>编码格式是学习模块的统一封装 {@code SEQUENCE { INTEGER hid, OCTET STRING id, OCTET STRING secret, BIT STRING masterPub }}；
 * 国标的主私钥 {@code SEQUENCE{INTEGER k, BIT STRING Ppub}} 与用户私钥 {@code SEQUENCE{BIT STRING d, BIT STRING Ppub}}
 * 已在 {@code Sm9KeyEssenceTest} 里逐字段核对过，这里不再重复定义。
 */
public final class SM9PrivateKey
    implements PrivateKey
{
    private static final long serialVersionUID = 1L;

    private final byte[] id;
    private final byte[] secret;
    private final byte[] masterPub;
    private final int hid;

    /**
     * @param id        标识；null 表示这是 KGC 的主私钥
     * @param secret    主私钥：32 字节大端标量；用户私钥：ds(65) / de(129) 点字节
     * @param masterPub 对应体系的主公钥点（Ppubs 129 字节 / Ppube 65 字节）
     * @param hid       {@link SM9ParameterSpec#HID_SIGN} 或 {@link SM9ParameterSpec#HID_ENC}
     */
    public SM9PrivateKey(byte[] id, byte[] secret, byte[] masterPub, int hid)
    {
        if (secret == null || masterPub == null)
        {
            throw new IllegalArgumentException("SM9 私钥必须同时带 secret 与主公钥点");
        }
        int expectedPub = hid == Sm9Math.HID_SIGN ? 129 : 65;
        if (masterPub.length != expectedPub || masterPub[0] != 0x04)
        {
            throw new IllegalArgumentException("主公钥点长度必须是 " + expectedPub + " 字节，实际 " + masterPub.length);
        }
        if (id == null)
        {
            // 主私钥：只有一个标量，长度固定 32
            if (secret.length != 32)
            {
                throw new IllegalArgumentException("主私钥标量必须是 32 字节，实际 " + secret.length);
            }
        }
        else
        {
            // 用户私钥：是一个点，签名体系在 G₁(65)，加密体系在 G₂(129)
            int expectedPoint = hid == Sm9Math.HID_SIGN ? 65 : 129;
            if (secret.length != expectedPoint || secret[0] != 0x04)
            {
                throw new IllegalArgumentException("hid=0x" + Integer.toHexString(hid) + " 的用户私钥必须是 "
                    + expectedPoint + " 字节的点，实际 " + secret.length);
            }
        }
        this.id = id == null ? null : id.clone();
        this.secret = secret.clone();
        this.masterPub = masterPub.clone();
        this.hid = hid;
    }

    /** 从 {@link #getEncoded()} 的字节还原。 */
    public static SM9PrivateKey decode(byte[] der)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        int hid = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        byte[] id = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
        byte[] secret = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        byte[] masterPub = ASN1BitString.getInstance(seq.getObjectAt(3)).getOctets();
        return new SM9PrivateKey(id.length == 0 ? null : id, secret, masterPub, hid);
    }

    public String getAlgorithm()
    {
        return "SM9";
    }

    public String getFormat()
    {
        return "SM9";
    }

    public byte[] getEncoded()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(hid));
        vector.add(new DEROctetString(id == null ? new byte[0] : id));
        vector.add(new DEROctetString(secret));
        vector.add(new DERBitString(masterPub));
        try
        {
            return new DERSequence(vector).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("SM9 私钥编码失败", e);
        }
    }

    public byte[] getId()
    {
        return id == null ? null : id.clone();
    }

    public int getHid()
    {
        return hid;
    }

    /** 主私钥标量（ks/ke）；用户私钥返回 null —— 它本来就不该知道主私钥。 */
    public BigInteger getMasterScalar()
    {
        return isMasterKey() ? Calc.toBigInt(secret) : null;
    }

    /** 原始秘密字节：主私钥是 32 字节标量，用户私钥是点。 */
    public byte[] getSecret()
    {
        return secret.clone();
    }

    /** 所属体系的主公钥点。 */
    public byte[] getMasterPublicKey()
    {
        return masterPub.clone();
    }

    public boolean isMasterKey()
    {
        return id == null;
    }

    /**
     * 拿到"真正参与运算的那个点"：
     * <pre>
     *   主私钥  -> 现场提取 ds = ks/(ks+H1(ID,hid))·P1  或  de = ke/(ke+H1(ID,hid))·P2
     *   用户私钥 -> 直接返回自带的那个点
     * </pre>
     * 这一步把 KGC 视角和用户视角收敛成同一个入参，JCE 层只需要调它。
     */
    public byte[] extractUserPoint(byte[] idFor)
    {
        byte[] useId = isMasterKey() ? idFor : id;
        if (useId == null)
        {
            throw new IllegalStateException("SM9 没有标识就无法导出私钥：请 setParameter(new SM9ParameterSpec(id))");
        }
        if (!isMasterKey())
        {
            return secret.clone();
        }
        BigInteger k = Calc.toBigInt(secret);
        if (hid == Sm9Math.HID_SIGN)
        {
            return Sm9Math.pointToOctets(Sm9Math.signPrivateKeyExtract(k, useId));
        }
        // 加密体系用自带的 hid（0x03 加密 / 0x02 交换）：同一把 ke 会导出两把不同的 de
        return Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(k, useId, hid));
    }

    /** 与之配对的公钥（公钥 = 标识 + 主公钥点）。 */
    public SM9PublicKey toPublicKey()
    {
        return new SM9PublicKey(id, masterPub, hid);
    }

    public String toString()
    {
        return "SM9PrivateKey(" + (isMasterKey() ? "master" : "user") + ", hid=0x"
            + Integer.toHexString(hid) + ", id="
            + (id == null ? "<none>" : new String(id, java.nio.charset.StandardCharsets.UTF_8)) + ")";
    }
}
