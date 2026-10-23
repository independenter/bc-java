package org.bouncycastle.learning.sm9;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 的算法参数 —— 对标 BC 的 {@code SM2ParameterSpec}，但要多带两样东西。
 *
 * <p>SM2 里 ID 只是"杂凑的附加输入"，公钥本身是普通 EC 点；SM9 是<b>基于标识</b>的密码：
 * 主私钥经过 {@code k/(k + H1(ID,hid))} 这个标量分母才导出用户私钥，所以 ID 不是可选参数，
 * 它就是公钥的一部分。参数类因此只需要三个值：
 * <pre>
 *   id        —— 标识（用户密钥场景必填；主公钥场景为 null）
 *   hid       —— 用途：0x01 签名、0x02 密钥交换、0x03 加密
 *   masterKey —— 主私钥标量（32 字节）：只有"从主私钥提取用户私钥"时才用得上
 * </pre>
 * 四个构造器对应四种用途，JCE 层用 {@code id == null} / {@code masterKey != null} 两个判断
 * 就能区分开（见 {@link #isMasterKeyGeneration()} 与 {@link #isPrivateKeyExtraction()}）：
 * <pre>
 *   new SM9ParameterSpec(HID_SIGN)                        生成签名主公钥对
 *   new SM9ParameterSpec(aliceId, HID_SIGN)               验签/加密时告诉 JCE 层的身份
 *   new SM9ParameterSpec(aliceId, HID_SIGN, ks)           KGC 提取 Alice 的签名私钥
 * </pre>
 * hid 与密钥类型必须匹配：签名体系用 HID_SIGN，加密体系用 HID_ENC —— 同一把主密钥给两个用途
 * 导出的是<b>两把不同的私钥</b>，混用会验不过（这是 hid 存在的全部理由）。
 */
public final class SM9ParameterSpec
    implements AlgorithmParameterSpec, Serializable
{
    private static final long serialVersionUID = 1L;

    /** 签名用途（GB/T 32915.2 里的 HID = 0x01）。 */
    public static final int HID_SIGN = Sm9Math.HID_SIGN;

    /** 密钥交换用途（GB/T 32915.4 里的 HID = 0x02）。 */
    public static final int HID_EXCH = Sm9Math.HID_EXCH;

    /** 加密用途（GB/T 32915.3 里的 HID = 0x03）。 */
    public static final int HID_ENC = Sm9Math.HID_ENC;

    private final byte[] id;
    private final byte[] masterKey;
    private final int hid;

    /** 只给标识，用途默认是签名 —— 与 {@code new SM2ParameterSpec(id)} 的手感保持一致。 */
    public SM9ParameterSpec(byte[] id)
    {
        this(id, HID_SIGN, null);
    }

    /** 给标识 + 用途。 */
    public SM9ParameterSpec(byte[] id, int hid)
    {
        this(id, hid, null);
    }

    /** 生成主公钥对：没有标识（标识还不存在），只有用途。 */
    public SM9ParameterSpec(int hid)
    {
        this(null, hid, null);
    }

    /**
     * 完整形态：从主私钥 {@code masterKey} 为标识 {@code id} 提取用户私钥。
     *
     * @param masterKey 32 字节大端主私钥标量（ks 或 ke），为 null 表示不提取
     */
    public SM9ParameterSpec(byte[] id, int hid, byte[] masterKey)
    {
        checkHid(hid);
        if (masterKey != null && masterKey.length != 32)
        {
            throw new IllegalArgumentException("SM9 主私钥标量是 32 字节，实际 " + masterKey.length);
        }
        if (masterKey != null && id == null)
        {
            throw new IllegalArgumentException("提取用户私钥必须给出标识：ID 已经进了私钥的分母");
        }
        this.id = id == null ? null : id.clone();
        this.hid = hid;
        this.masterKey = masterKey == null ? null : masterKey.clone();
    }

    /** 用途与标识都必须成对出现：签名体系配 HID_SIGN，加密体系配 HID_ENC。 */
    private static void checkHid(int hid)
    {
        if (hid != HID_SIGN && hid != HID_EXCH && hid != HID_ENC)
        {
            throw new IllegalArgumentException("未知 hid = " + hid + "，只允许 0x01/0x02/0x03");
        }
    }

    /** 标识；返回 null 表示"还没有标识"，即主公钥生成场景。 */
    public byte[] getId()
    {
        return id == null ? null : id.clone();
    }

    public int getHid()
    {
        return hid;
    }

    /** 主私钥标量；null 表示本次不需要提取用户私钥。 */
    public byte[] getMasterKey()
    {
        return masterKey == null ? null : masterKey.clone();
    }

    /** 是否"生成主公钥对"：没有标识就是主公钥。 */
    public boolean isMasterKeyGeneration()
    {
        return id == null;
    }

    /** 是否"KGC 用主私钥提取用户私钥"。 */
    public boolean isPrivateKeyExtraction()
    {
        return masterKey != null;
    }

    public String toString()
    {
        return "SM9ParameterSpec(hid=0x" + Integer.toHexString(hid)
            + ", id=" + (id == null ? "<none>" : new String(id, java.nio.charset.StandardCharsets.UTF_8))
            + ", masterKey=" + (masterKey == null ? "<none>" : "<32 bytes>") + ")";
    }
}
