package org.bouncycastle.learning.sm9;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.learning.essence.Calc;
import org.bouncycastle.learning.essence.Sm9Math;

/**
 * SM9 的"密钥对生成" —— 对标 {@code KeyPairGenerator.getInstance("SM2","BC")}，但语义完全不同。
 *
 * <p>基于标识密码里没有"随机的公私钥对"。能生成的只有一把<b>主密钥</b>，
 * 之后所有用户私钥都是从这个主密钥<b>推导</b>出来的，推导公式里带着持有人的标识：
 * <pre>
 *   主公钥（KGC 广播）  Ppubs = ks·P2 ∈ G₂      Ppube = ke·P1 ∈ G₁
 *   用户私钥（KGC 下发） ds = ks/(ks + H1(ID,0x01))·P1      de = ke/(ke + H1(ID,0x03))·P2
 * </pre>
 * 所以本 SPI 用 {@link SM9ParameterSpec} 的三个字段区分三种请求：
 * <table border="1">
 *   <tr><th>spec 形态</th><th>含义</th><th>产生的 KeyPair</th></tr>
 *   <tr><td>id=null, masterKey=null</td><td>生成主密钥（KGC 用）</td>
 *       <td>公钥=主公钥点，私钥=32 字节标量</td></tr>
 *   <tr><td>id=非空, masterKey=非空</td><td>提取用户私钥（KGC 给 Alice 发卡）</td>
 *       <td>公钥=(ID, 主公钥)，私钥=ds 或 de 点</td></tr>
 *   <tr><td>id=非空, masterKey=null</td><td>"我自己生成一对"</td>
 *       <td><b>报错</b> —— 这正是 SM9 的定义：没有主私钥就算不出私钥</td></tr>
 * </table>
 *
 * <p>签名体系与加密体系是<b>两把独立的主密钥</b>（hid 0x01 / 0x03），公钥点所在的群也不同：
 * 前者在 G₂（129 字节），后者在 G₁（65 字节）。这就是 {@link SM9ParameterSpec#getHid()}
 * 存在的原因，也是本类里唯一一处分支判断。
 */
public class SM9KeyPairGeneratorSpi
    extends KeyPairGeneratorSpi
{
    /** SM9 的标量是 256 位（曲线的阶 n 是 256 位素数）。 */
    private static final int KEY_SIZE = 256;

    private SM9ParameterSpec spec;
    private SecureRandom random;

    public SM9KeyPairGeneratorSpi()
    {
        // 默认就是"生成签名主密钥对"：调用方连 initialize 都不调也能出钥匙
        this.spec = new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN);
        this.random = new SecureRandom();
    }

    /**
     * 两个名字族都实现，是 {@code KeyPairGeneratorSpi} 的历史包袱：
     * JDK 8 里抽象方法叫 {@code initialize}/{@code generateKeyPair}，JDK 9 之后加了
     * {@code engineInitialize}/{@code engineGenKeyPair}，BC 的 SM2 用的是后一套（{@code --release}
     * 不同看到的形状就不同）。这里把真正的逻辑放在私有方法里，两组名字都只是转调，
     * 于是同一个类在任一组 API 上都能被 {@code KeyPairGenerator} 调到。
     */
    public void initialize(int keysize, SecureRandom random)
    {
        doInitialize(keysize, random);
    }

    protected void engineInitialize(int keysize, SecureRandom random)
    {
        doInitialize(keysize, random);
    }

    /** 不传参数时默认生成<b>签名</b>主密钥对，与 {@code KeyPairGenerator.getInstance("SM2")} 的默认手感一致。 */
    private void doInitialize(int keysize, SecureRandom random)
    {
        // 200 是 JCE 无参 initialize() 传下来的占位默认值，0 是"没设置"；SM9 只有 256 位标量
        if (keysize != KEY_SIZE && keysize != 200 && keysize != 0)
        {
            throw new IllegalArgumentException("SM9 的标量固定 256 位，请求的是 " + keysize);
        }
        this.spec = new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN);
        this.random = random == null ? new SecureRandom() : random;
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        doInitialize(params, random);
    }

    protected void engineInitialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        doInitialize(params, random);
    }

    private void doInitialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(params instanceof SM9ParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(
                "SM9 只接受 SM9ParameterSpec，收到的是 " + (params == null ? "null" : params.getClass().getName()));
        }
        SM9ParameterSpec sm9 = (SM9ParameterSpec) params;
        if (sm9.isMasterKeyGeneration() && sm9.isPrivateKeyExtraction())
        {
            throw new InvalidAlgorithmParameterException("生成主公钥不需要主私钥：请去掉 masterKey");
        }
        if (!sm9.isMasterKeyGeneration() && !sm9.isPrivateKeyExtraction())
        {
            throw new InvalidAlgorithmParameterException(
                "只给 ID 是不够的：基于标识密码里用户私钥必须由 KGC 用主私钥推导，"
                    + "请传 new SM9ParameterSpec(id, hid, ks)");
        }
        this.spec = sm9;
        this.random = random == null ? new SecureRandom() : random;
    }

    public KeyPair generateKeyPair()
    {
        return doGenerateKeyPair();
    }

    protected KeyPair engineGenKeyPair()
    {
        return doGenerateKeyPair();
    }

    private KeyPair doGenerateKeyPair()
    {
        if (spec.isMasterKeyGeneration())
        {
            // 主密钥：秘密部分就是一个随机标量 ks/ke
            return generateMasterKeyPair(Sm9Math.randScalar(random));
        }
        // 提取用户私钥：标量必须用调用方给的那把主私钥，绝不能再随机 —— 否则就对不上
        // Alice 已经拿到的那张卡了（ds 与 ks 是一对绑死的关系）
        return extractUserKeyPair(Calc.toBigInt(spec.getMasterKey()));
    }

    /**
     * KGC 的主密钥：私钥是一个随机标量 ks/ke，公钥是它乘上对应的生成元。
     * 注意 ks 本身<b>绝不</b>是"私钥对的秘密部分"那么温和 —— 拿到 ks 就能给任何标识导出私钥。
     */
    private KeyPair generateMasterKeyPair(BigInteger k)
    {
        int hid = spec.getHid();
        byte[] masterPub = masterPublicKeyBytes(k, hid);
        SM9PrivateKey privateKey = new SM9PrivateKey(null, Calc.toBytes(k, KEY_SIZE / 8), masterPub, hid);
        return new KeyPair(new SM9PublicKey(null, masterPub, hid), privateKey);
    }

    /**
     * KGC 给标识 {@code id} 发卡：公钥就是 (ID, 主公钥)，私钥是标准那条除法算出来的点。
     */
    private KeyPair extractUserKeyPair(BigInteger k)
    {
        int hid = spec.getHid();
        byte[] id = spec.getId();
        byte[] masterPub = masterPublicKeyBytes(k, hid);
        byte[] userPoint;
        if (hid == Sm9Math.HID_SIGN)
        {
            userPoint = Sm9Math.pointToOctets(Sm9Math.signPrivateKeyExtract(k, id));
        }
        else
        {
            userPoint = Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(k, id, hid));
        }
        return new KeyPair(new SM9PublicKey(id, masterPub, hid),
            new SM9PrivateKey(id, userPoint, masterPub, hid));
    }

    /** 主公钥点字节：签名体系在 G₂（129），加密/交换体系在 G₁（65）。 */
    private static byte[] masterPublicKeyBytes(BigInteger k, int hid)
    {
        if (hid == Sm9Math.HID_SIGN)
        {
            return Sm9Math.twistToOctets(Sm9Math.signMasterPublicKey(k));
        }
        return Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(k));
    }
}
