package org.bouncycastle.learning.sm9;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 公钥 —— 与 SM2/EC 公钥最大的差别：<b>公钥 = 标识 + 主公钥点</b>，两个字段缺一不可。
 *
 * <p>拆开看标准里的公式就明白为什么：
 * <pre>
 *   验签   P' = H1(ID, 0x01)·P2 + Ppubs      —— 标识直接乘进 G₂ 再和主公钥相加
 *   加密   Q  = H1(ID, 0x03)·P1 + Ppube      —— 同上
 * </pre>
 * 也就是说"某人的公钥"从来不是一个孤立的点，而是 (ID, 主公钥) 这一对。BC 的 SM2 公钥是一个
 * ECPoint，标识只在 {@code SM2ParameterSpec} 里当杂凑输入；SM9 里 ID 缺失就根本无法运算，
 * 所以它必须进密钥对象。
 *
 * <p>点所在的群随用途不同：
 * <pre>
 *   HID_SIGN —— Ppubs = ks·P2 ∈ G₂，0x04 打头 129 字节（x₁‖x₀‖y₁‖y₀）
 *   HID_ENC  —— Ppube = ke·P1 ∈ G₁，0x04 打头 65 字节（x‖y）
 * </pre>
 * {@code id == null} 表示"只有主公钥"（KGC 广播的那一把），此时用它的地方必须另外给出标识，
 * JCE 层会拒绝并提示调用 {@code setParameter(new SM9ParameterSpec(id))}。
 *
 * <p>编码格式是本学习模块统一封装的 {@code SEQUENCE { INTEGER hid, OCTET STRING id, BIT STRING point }}；
 * 国标的主公钥/用户公钥结构（含 domainParameters）已在 {@code Sm9KeyEssenceTest} 里逐字段核对过。
 */
public final class SM9PublicKey
    implements PublicKey
{
    private static final long serialVersionUID = 1L;

    private final byte[] id;
    private final byte[] point;
    private final int hid;

    /**
     * @param id    标识；null 表示只有主公钥
     * @param point 主公钥点的字节（签名 129 字节 / 加密 65 字节，都带 0x04 前缀）
     * @param hid   {@link SM9ParameterSpec#HID_SIGN} 或 {@link SM9ParameterSpec#HID_ENC}
     */
    public SM9PublicKey(byte[] id, byte[] point, int hid)
    {
        int expected = hid == Sm9Math.HID_SIGN ? 129 : 65;
        if (point == null || point.length != expected || point[0] != 0x04)
        {
            throw new IllegalArgumentException("hid=0x" + Integer.toHexString(hid) + " 的公钥点必须是 0x04 打头的 "
                + expected + " 字节（签名在 G₂，加密在 G₁），实际 "
                + (point == null ? "null" : point.length + " 字节"));
        }
        this.id = id == null ? null : id.clone();
        this.point = point.clone();
        this.hid = hid;
    }

    /** 从 {@link #getEncoded()} 的字节还原。 */
    public static SM9PublicKey decode(byte[] der)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        int hid = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue().intValue();
        byte[] id = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
        byte[] point = ASN1BitString.getInstance(seq.getObjectAt(2)).getOctets();
        // 空 OCTET STRING 就是"只有主公钥"，与构造函数里的 null 对齐
        return new SM9PublicKey(id.length == 0 ? null : id, point, hid);
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
        vector.add(new DERBitString(point));
        try
        {
            return new DERSequence(vector).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("SM9 公钥编码失败", e);
        }
    }

    public byte[] getId()
    {
        return id == null ? null : id.clone();
    }

    /** 主公钥点：Ppubs（G₂，129 字节）或 Ppube（G₁，65 字节）。 */
    public byte[] getPoint()
    {
        return point.clone();
    }

    public int getHid()
    {
        return hid;
    }

    /** true 表示这是 KGC 广播的主公钥，还没有绑定任何标识。 */
    public boolean isMasterKey()
    {
        return id == null;
    }

    /** 换绑定标识：用于"同一把主公钥服务多个 ID"的常见场景（比如批量加密给不同收件人）。 */
    public SM9PublicKey withId(byte[] newId)
    {
        return new SM9PublicKey(newId, point, hid);
    }

    public String toString()
    {
        return "SM9PublicKey(hid=0x" + Integer.toHexString(hid) + ", id="
            + (id == null ? "<master>" : new String(id, java.nio.charset.StandardCharsets.UTF_8))
            + ", point=" + point.length + " bytes)";
    }
}
