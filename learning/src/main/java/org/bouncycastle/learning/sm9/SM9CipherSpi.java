package org.bouncycastle.learning.sm9;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 加密 —— 对标 {@code Cipher.getInstance("SM2","BC")}，但内部<b>没有分组密码</b>。
 *
 * <p>SM9 的加密是"基于标识的加密 IBBE"，本质是一次 KEM 加一次异或：
 * <pre>
 *   Q  = H1(ID,0x03)·P1 + Ppube              收信人的"公钥点"，ID 直接加进去
 *   C1 = r·Q                                 一次性公钥（G₁ 点，65 字节）
 *   w  = e(Ppube, P2)^r = e(C1, de)          双线性让发/收双方算到同一个 384 字节串
 *   K  = KDF(C1_x‖C1_y‖w‖ID, len+32)         前 len 字节当掩码，后 32 字节当 HMAC 密钥
 *   C2 = M ⊕ K[0..len)
 *   C3 = HMAC-SM3(K[len..len+32), C2)
 * </pre>
 * 所以密文长度 = 明文长度 + 65 + 32，而且<b>必须整段 doFinal</b>：掩码 K 是从明文头部对齐异或下来的，
 * 分块推进没有意义 —— 这正是本类把所有 {@code engineUpdate} 都写成抛异常的原因。
 *
 * <p>与 SM2 加密的两点手感差异：
 * <ol>
 *   <li>发信人不需要向 KGC 申请任何东西：只有 ID 与公开的 Ppube 就能加密，主私钥 ke 全程不参与
 *       （见 {@link Sm9Math#encryptToIdentity}）；</li>
 *   <li>"解不开"统一抛 {@link BadPaddingException}：C1 不在曲线上、C3 对不上、ID 不匹配，对外都是
 *       同一个异常。区分原因等于给攻击者一个解密预言 —— GB/T 32915.3 的 B1 步（先验 C1 在 G₁ 上）
 *       就是为此存在，引擎里那句检查在 {@code kemDecryptWithUserKey} 里。</li>
 * </ol>
 *
 * <p>输出编码用国标的密文结构
 * {@code SEQUENCE { INTEGER 0, BIT STRING C1, OCTET STRING C3, OCTET STRING C2 }}；
 * 开头那个 INTEGER 0 表示"明文用异或而不是分组密码变换"，是标准里唯一的模式标记位。
 */
public class SM9CipherSpi
    extends CipherSpi
{
    /** 一次性公钥 C1：G₁ 点，0x04 打头 65 字节。 */
    private static final int C1_LEN = 65;

    /** 完整性标签 C3：HMAC-SM3 的输出，32 字节。 */
    private static final int C3_LEN = 32;

    /** getOutputSize 要的保守余量：固定开销 + DER 外层。 */
    private static final int OVERHEAD = C1_LEN + C3_LEN + 16;

    private int opmode = Cipher.ENCRYPT_MODE;
    private byte[] id;
    private byte[] ppube;
    private byte[] de;
    private SecureRandom random = new SecureRandom();

    public SM9CipherSpi()
    {
    }

    // ---------------------------------------------------------------- 变换名：SM9 既不分块也不填充

    /**
     * SM9 没有分组模式：掩码来自 KDF，不来自 CBC/CTR 这类分组链接。
     * 允许 {@code "SM9"}、{@code "ECB"}、{@code "NONE"} 这三种"其实什么都没做"的写法，
     * 是为了让 {@code Cipher.getInstance("SM9/ECB/NoPadding")} 这种习惯不至于直接失败。
     */
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        if (mode != null && !mode.equals("SM9") && !mode.equals("ECB") && !mode.equals("NONE"))
        {
            throw new NoSuchAlgorithmException(
                "SM9 没有分组模式（掩码由 KDF 按明文长度生成）：" + mode);
        }
    }

    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        if (padding != null && !padding.equalsIgnoreCase("NoPadding") && !padding.equalsIgnoreCase("NONE"))
        {
            throw new NoSuchPaddingException("SM9 不加分组填充（C2 与明文等长）：" + padding);
        }
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected int engineGetOutputSize(int inputLen)
    {
        if (opmode == Cipher.ENCRYPT_MODE)
        {
            return inputLen + OVERHEAD;
        }
        // 解密方向只要保证是上界即可：明文 = 密文 − 97，用 inputLen 当保守上界
        return Math.max(inputLen, 0);
    }

    protected java.security.spec.AlgorithmParameterSpec engineGetAlgorithmParameterSpec(Class<?> cls)
        throws java.security.InvalidAlgorithmParameterException
    {
        return id == null ? null : new SM9ParameterSpec(id, Sm9Math.HID_ENC);
    }

    protected byte[] engineGetIV()
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    /** SM9 的参数走 {@code init(opmode, key, SM9ParameterSpec)}，没有 AlgorithmParameters 的落点。 */
    protected void engineSetParameters(AlgorithmParameters params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("SM9 不支持 AlgorithmParameters，请用 SM9ParameterSpec");
        }
    }

    protected void engineSetParameters(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SM9ParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9 只接受 SM9ParameterSpec");
        }
        this.id = ((SM9ParameterSpec) params).getId();
    }

    protected int engineGetKeySize(Key key)
    {
        return 256;
    }

    // ---------------------------------------------------------------- 初始化

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException("SM9 初始化失败：" + e.getMessage());
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE)
        {
            throw new InvalidKeyException("SM9 只做加密/解密，不支持 WRAP/UNWRAP（密钥包装另有 GB/T 32915.4 的交换协议）");
        }
        if (params != null && !(params instanceof SM9ParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("SM9 只接受 SM9ParameterSpec，收到 " + params.getClass().getName());
        }
        byte[] explicitId = params == null ? null : ((SM9ParameterSpec) params).getId();
        this.opmode = opmode;
        this.random = random == null ? new SecureRandom() : random;
        ppube = null;
        de = null;
        if (opmode == Cipher.ENCRYPT_MODE)
        {
            initEncrypt(key, explicitId);
        }
        else
        {
            initDecrypt(key, explicitId);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("SM9 不支持 AlgorithmParameters，请用 SM9ParameterSpec");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    }

    /**
     * 加密方向：公钥必须是<b>加密体系</b>的 Ppube（G₁，65 字节），并且要先检查它真的在曲线上 ——
     * 把非法点当公钥用会让 C1 落到一个只有攻击者知道的 w 上。
     */
    private void initEncrypt(Key key, byte[] explicitId)
        throws InvalidKeyException
    {
        if (!(key instanceof SM9PublicKey))
        {
            throw new InvalidKeyException("SM9 加密需要 SM9PublicKey（Ppube + ID），收到 "
                + (key == null ? "null" : key.getClass().getName()));
        }
        SM9PublicKey pub = (SM9PublicKey) key;
        if (pub.getHid() != Sm9Math.HID_ENC)
        {
            throw new InvalidKeyException("这是签名主公钥 Ppubs（hid=0x01），加密要用加密主公钥 Ppube（hid=0x03）");
        }
        byte[] point = pub.getPoint();
        if (!Sm9Math.pointIsOnCurve(Sm9Math.pointFromOctets(point)))
        {
            throw new InvalidKeyException("Ppube 不在 G₁ 上：拒绝用非法点做加密");
        }
        this.id = explicitId != null ? explicitId : pub.getId();
        if (this.id == null)
        {
            throw new InvalidKeyException("SM9 加密必须知道收信人标识：ID 会进 H1 和 KDF，"
                + "请用带 ID 的公钥或 init(opmode, key, new SM9ParameterSpec(id))");
        }
        this.ppube = point;
    }

    /**
     * 解密方向：私钥可以是 KGC 的 ke（主私钥，现算 de），也可以是收信人自己的 de。
     * 两条路在 {@link SM9PrivateKey#extractUserPoint(byte[])} 里收敛成同一个 G₂ 点。
     */
    private void initDecrypt(Key key, byte[] explicitId)
        throws InvalidKeyException
    {
        if (!(key instanceof SM9PrivateKey))
        {
            throw new InvalidKeyException("SM9 解密需要 SM9PrivateKey（de 或 ke），收到 "
                + (key == null ? "null" : key.getClass().getName()));
        }
        SM9PrivateKey priv = (SM9PrivateKey) key;
        if (priv.getHid() != Sm9Math.HID_ENC)
        {
            throw new InvalidKeyException("这把是签名体系的私钥（hid=0x01）：SM9 的加密私钥 de 由 hid=0x03 单独导出");
        }
        byte[] useId = explicitId != null ? explicitId : priv.getId();
        if (useId == null)
        {
            throw new InvalidKeyException("SM9 主私钥没有标识：请 init(DECRYPT_MODE, ke, new SM9ParameterSpec(id, HID_ENC))");
        }
        this.id = useId;
        this.de = priv.extractUserPoint(useId);
    }

    // ---------------------------------------------------------------- SM9 不分块：update 一律拒绝

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
        throws IllegalStateException
    {
        throw new IllegalStateException("SM9 是一次性 doFinal：K = KDF(C1‖w‖ID) 的掩码从明文头部对齐，不能分块推进");
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws IllegalStateException
    {
        throw new IllegalStateException("SM9 是一次性 doFinal：K = KDF(C1‖w‖ID) 的掩码从明文头部对齐，不能分块推进");
    }

    // ---------------------------------------------------------------- doFinal

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] data = input == null || inputLen <= 0
            ? new byte[0]
            : Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        return opmode == Cipher.ENCRYPT_MODE ? encrypt(data) : decrypt(data);
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output == null || output.length - outputOffset < result.length)
        {
            throw new ShortBufferException("输出缓冲不够：需要 " + result.length
                + " 字节，可用 " + (output == null ? 0 : output.length - outputOffset));
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    /**
     * 加密：r 每次都必须不可预测（与 SM2 的 k、SM9 签名的 r 同理）——
     * r 一旦重复，同一个 (ID, 密文) 的掩码就重复，两条明文异或直接得到异或后的明文对。
     */
    private byte[] encrypt(byte[] plaintext)
        throws IllegalBlockSizeException
    {
        BigInteger r = Sm9Math.randScalar(random);
        byte[] raw = Sm9Math.encryptToIdentity(id, ppube, plaintext, r);
        byte[] c1 = Arrays.copyOfRange(raw, 0, C1_LEN);
        byte[] c3 = Arrays.copyOfRange(raw, C1_LEN, C1_LEN + C3_LEN);
        byte[] c2 = Arrays.copyOfRange(raw, C1_LEN + C3_LEN, raw.length);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(0));
        vector.add(new DERBitString(c1));
        vector.add(new DEROctetString(c3));
        vector.add(new DEROctetString(c2));
        try
        {
            return new DERSequence(vector).getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalBlockSizeException("SM9 密文 DER 编码失败：" + e.getMessage());
        }
    }

    /** 解密：结构、C1 合法性、C3 完整性任意一处失败都只报"解不开"，不区分原因。 */
    private byte[] decrypt(byte[] ciphertext)
        throws BadPaddingException
    {
        ASN1Sequence seq;
        try
        {
            seq = ASN1Sequence.getInstance(ciphertext);
        }
        catch (RuntimeException e)
        {
            throw new BadPaddingException("SM9 密文不是合法的 GB/T 32915.3 结构：" + e.getMessage());
        }
        BigInteger flag = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        byte[] c1 = ASN1BitString.getInstance(seq.getObjectAt(1)).getOctets();
        byte[] c3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
        byte[] c2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
        if (flag.signum() != 0)
        {
            throw new BadPaddingException("SM9 密文的变换标记是 " + flag + "，本实现只支持 0（异或）");
        }
        if (c1.length != C1_LEN || c3.length != C3_LEN)
        {
            throw new BadPaddingException("SM9 密文分量长度不对：C1=" + c1.length + ", C3=" + c3.length);
        }
        try
        {
            return Sm9Math.decryptWithUserKey(id, de, c1, c2, c3);
        }
        catch (RuntimeException e)
        {
            // C1 不在曲线上 / C3 校验失败 / 点解码非法，对调用方来说都只是"解不开"
            throw new BadPaddingException("SM9 解密失败：" + e.getMessage());
        }
    }
}
