package org.bouncycastle.learning.sm9;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.CryptoHelper;
import org.bouncycastle.learning.essence.Calc;
import org.bouncycastle.learning.essence.Sm9Math;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * SM9Provider 的 JCE 外壳测试 —— 目的只有一个：证明 {@link Sm9Math} 那套面向过程的数学
 * 能严丝合缝地插进 Java 标准密码插座，并且<b>插上去之后算的还是同一道题</b>。
 *
 * <p>与 {@code essence} 包里那几个测试的分工：
 * <pre>
 *   essence.Sm9*EssenceTest   —— 数学对不对（对 GmSSL 的国标 KAT 逐字节核对）
 *   sm9.SM9ProviderTest       —— 插座对不对（JCE 三件套的用法、参数、异常形态与 SM2 一致）
 * </pre>
 * 两边在测试③/④里用<b>同一个随机数 r</b> 做逐字节对照，把"外壳"和"内核"锁死在一起：
 * JCE 层唯一的贡献是 ASN.1 包装与参数校验，公式一个都没改。
 *
 * <p>对标 SM2 的调用形状（这是学习目的的核心）：
 * <pre>
 *   Cipher.getInstance("SM2","BC")              ↔  Cipher.getInstance("SM9","SM9")
 *   Signature.getInstance("SM3withSM2","BC")    ↔  Signature.getInstance("SM3withSM9","SM9")
 *   sig.setParameter(new SM2ParameterSpec(id))  ↔  sig.setParameter(new SM9ParameterSpec(id))
 *   KeyPairGenerator.getInstance("SM2","BC")    ↔  KeyPairGenerator.getInstance("SM9","SM9")
 * </pre>
 */
@Slf4j
public class SM9ProviderTest
{
    private static final byte[] ID_ALICE = "alice@sm9.example".getBytes();
    private static final byte[] ID_BOB = "bob@sm9.example".getBytes();
    private static final byte[] MESSAGE = "SM9 的公钥是 (ID, 主公钥) 一对，不是孤立的点".getBytes();

    /** 固定的 r：用来让 JCE 层与引擎算出同一个签名/密文，逐字节对照。取 n−7 保证在 [1,n−1] 内。 */
    private static final BigInteger FIXED_R = Sm9Math.N.subtract(BigInteger.valueOf(7));

    /**
     * 每次都吐同一个标量的 SecureRandom。
     *
     * <p>为什么要这么费劲地注入随机数：真实系统里 r 必须<b>逐次不可预测</b>（复用 r 会直接漏出私钥点，
     * 见 {@code Sm9SignEssenceTest#reusedRandomLeaksThePrivateKeyPoint}）；但做对照实验时又必须
     * 让两次计算用同一个 r。JCE 把 SecureRandom 作为 init 的入参交出来，正是为了这两种场景 ——
     * 前者传系统的强随机，后者传这个可控的固定随机。
     */
    private static final class FixedRandom
        extends SecureRandom
    {
        private final byte[] fixed;

        private FixedRandom(BigInteger value)
        {
            this.fixed = Calc.toBytes(value, 32);
        }

        public void nextBytes(byte[] bytes)
        {
            System.arraycopy(fixed, 0, bytes, 0, Math.min(fixed.length, bytes.length));
        }
    }

    @BeforeClass
    public static void installProvider()
    {
        SM9Provider.install();
        Provider provider = Security.getProvider(SM9Provider.NAME);
        Assert.assertNotNull("Provider 必须已注册进 JCE", provider);
        log.info("[SM9-JCE] 已注册 {}，条目 {} 条", provider, provider.size());
    }

    // ---------------------------------------------------------------- ①主密钥生成

    /**
     * {@code KeyPairGenerator} 生成的是<b>主密钥</b>：私钥一个 32 字节标量，公钥它乘生成元。
     * 签名/加密两套体系的公钥点甚至不在同一个群里（G₂ 129 字节 vs G₁ 65 字节）。
     */
    @Test
    public void masterKeyPairGenerationFollowsTheStandardFormula()
        throws Exception
    {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("SM9", SM9Provider.NAME);

        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN));
        KeyPair signPair = kg.generateKeyPair();
        SM9PrivateKey ks = (SM9PrivateKey) signPair.getPrivate();
        SM9PublicKey ppubs = (SM9PublicKey) signPair.getPublic();
        Assert.assertTrue("主私钥没有标识", ks.isMasterKey());
        Assert.assertEquals("主私钥就是一个 256 位标量", 32, ks.getSecret().length);
        Assert.assertEquals("Ppubs = ks·P2 ∈ G₂，129 字节", 129, ppubs.getPoint().length);
        // 与引擎的公式逐字节对照：JCE 层没有偷偷换生成元或换群
        Assert.assertEquals(Calc.hex(Sm9Math.twistToOctets(Sm9Math.signMasterPublicKey(ks.getMasterScalar()))),
            Calc.hex(ppubs.getPoint()));

        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_ENC));
        KeyPair encPair = kg.generateKeyPair();
        SM9PrivateKey ke = (SM9PrivateKey) encPair.getPrivate();
        SM9PublicKey ppube = (SM9PublicKey) encPair.getPublic();
        Assert.assertEquals("Ppube = ke·P1 ∈ G₁，65 字节", 65, ppube.getPoint().length);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(ke.getMasterScalar()))),
            Calc.hex(ppube.getPoint()));

        // 密钥长度只有 256 一种：曲线的阶 n 是定死的
        try
        {
            kg.initialize(128, new SecureRandom());
            Assert.fail("SM9 没有 128 位的密钥");
        }
        catch (IllegalArgumentException e)
        {
            log.info("[SM9-JCE] 拒绝 128 位：{}", e.getMessage());
        }

        // 编码往返：公钥/私钥的 DER 必须逐字段复原（换绑定 ID 的 withId 也顺手验一次）
        SM9PublicKey reread = SM9PublicKey.decode(ppubs.getEncoded());
        Assert.assertArrayEquals(reread.getPoint(), ppubs.getPoint());
        Assert.assertEquals(reread.getHid(), ppubs.getHid());
        SM9PrivateKey rereadKs = SM9PrivateKey.decode(ks.getEncoded());
        Assert.assertArrayEquals(rereadKs.getSecret(), ks.getSecret());
        log.info("[SM9-JCE] 主公钥 {} 字节 / 主私钥 {} 字节 DER",
            ppubs.getEncoded().length, ks.getEncoded().length);
    }

    // ---------------------------------------------------------------- ②用户私钥提取

    /**
     * "密钥对生成"在 SM9 里的第二层含义：KGC 用<b>主私钥</b>为某个标识导出用户私钥。
     * 少了主私钥这件事就做不到 —— 这正是基于标识密码与 PKI 的定义性差别。
     */
    @Test
    public void userKeyExtractionNeedsTheMasterPrivateKey()
        throws Exception
    {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("SM9", SM9Provider.NAME);
        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN));
        SM9PrivateKey ks = (SM9PrivateKey) kg.generateKeyPair().getPrivate();

        kg.initialize(new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_SIGN, ks.getSecret()));
        KeyPair alice = kg.generateKeyPair();
        SM9PrivateKey ds = (SM9PrivateKey) alice.getPrivate();
        SM9PublicKey alicePub = (SM9PublicKey) alice.getPublic();
        Assert.assertFalse("用户私钥绑定标识", ds.isMasterKey());
        Assert.assertArrayEquals(ID_ALICE, ds.getId());
        Assert.assertEquals("ds ∈ G₁：签名私钥是 65 字节的点", 65, ds.getSecret().length);
        // 与引擎对照：ds = ks·(ks + H1(ID,0x01))⁻¹·P1
        Assert.assertEquals(
            Calc.hex(Sm9Math.pointToOctets(Sm9Math.signPrivateKeyExtract(ks.getMasterScalar(), ID_ALICE))),
            Calc.hex(ds.getSecret()));
        // 公钥 = (ID, 主公钥)，主公钥那一段与 KGC 广播的完全相同
        Assert.assertArrayEquals(ks.getMasterPublicKey(), alicePub.getPoint());
        // 私钥对象自带反推公钥的能力：用户私钥 -> (ID, 主公钥)
        Assert.assertArrayEquals(alicePub.getPoint(), ds.toPublicKey().getPoint());
        Assert.assertArrayEquals(ID_ALICE, ds.toPublicKey().getId());

        // 加密体系：de ∈ G₂（129 字节），而且与签名的 ds 是两把互不相干的点
        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_ENC));
        SM9PrivateKey ke = (SM9PrivateKey) kg.generateKeyPair().getPrivate();
        kg.initialize(new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_ENC, ke.getSecret()));
        SM9PrivateKey aliceDec = (SM9PrivateKey) kg.generateKeyPair().getPrivate();
        Assert.assertEquals(129, aliceDec.getSecret().length);
        Assert.assertNotEquals("hid 不同就导出不同的私钥：这就是 hid 存在的全部理由",
            Calc.hex(ds.getSecret()), Calc.hex(aliceDec.getSecret()));

        // 只给 ID 不给主私钥 = 想"自己生成一对"：SM9 里不可能，必须报错
        try
        {
            kg.initialize(new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_SIGN));
            Assert.fail("没有主私钥就不能导出用户私钥");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            log.info("[SM9-JCE] 拒绝自造密钥对：{}", e.getMessage());
        }
        // 未知 hid 也一样拒绝（0x09 不在 0x01/0x02/0x03 里）
        try
        {
            kg.initialize(new SM9ParameterSpec(0x09));
            Assert.fail("hid 只有三个合法值");
        }
        catch (IllegalArgumentException e)
        {
            log.info("[SM9-JCE] 拒绝未知 hid：{}", e.getMessage());
        }
    }

    // ---------------------------------------------------------------- ③签名 / 验签

    /**
     * JCE 签名与引擎签名在<b>同一个 r</b> 下必须逐字节相同 —— 唯一的差别是外面那层国标 DER。
     * 顺带覆盖：主公钥 + setParameter 的验签路径、四类失败场景、以及"加密私钥不能拿来签"。
     */
    @Test
    public void signatureThroughJceMatchesEngineByteForByte()
        throws Exception
    {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("SM9", SM9Provider.NAME);
        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN));
        KeyPair master = kg.generateKeyPair();
        SM9PrivateKey ks = (SM9PrivateKey) master.getPrivate();
        kg.initialize(new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_SIGN, ks.getSecret()));
        KeyPair alice = kg.generateKeyPair();

        BigInteger r = FIXED_R;
        Signature signer = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        signer.initSign(alice.getPrivate(), new FixedRandom(r));
        signer.update(MESSAGE, 0, MESSAGE.length / 2);
        signer.update(MESSAGE, MESSAGE.length / 2, MESSAGE.length - MESSAGE.length / 2);
        byte[] der = signer.sign();

        // 引擎路线：ks 视角（GmSSL 那几个高层 API 的形状）与用户视角同一条公式
        byte[] engineRaw = Sm9Math.sign(MESSAGE, ID_ALICE, ks.getMasterScalar(), r);
        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        byte[] h = ASN1OctetString.getInstance(parsed.getObjectAt(0)).getOctets();
        byte[] s = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        Assert.assertEquals("签名值 = h(32) ‖ S(65)，与引擎一字不差",
            Calc.hex(engineRaw), Calc.hex(Calc.concat(h, s)));

        // 验签有三条入口，都必须通过
        Signature v1 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v1.initVerify(alice.getPublic());
        v1.update(MESSAGE);
        Assert.assertTrue("用 Alice 的公钥（自带 ID）验签", v1.verify(der));

        Signature v2 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v2.initVerify(master.getPublic());                       // 主公钥，没有 ID
        v2.setParameter(new SM9ParameterSpec(ID_ALICE));         // 与 SM2 传 SM2ParameterSpec 同一路子
        v2.update(MESSAGE);
        Assert.assertTrue("主公钥 + setParameter(ID) 也能验", v2.verify(der));

        // 主公钥不带 ID 又不调 setParameter：SM9 里公钥是半个，必须报错而不是返回 false
        Signature v3 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v3.initVerify(master.getPublic());
        v3.update(MESSAGE);
        try
        {
            v3.verify(der);
            Assert.fail("缺标识就没法算 P'");
        }
        catch (SignatureException e)
        {
            log.info("[SM9-JCE] 缺 ID 时拒绝：{}", e.getMessage());
        }

        // 换 Bob 的 ID 去验：P' 变了，验不过 —— 标识密码里"读错公钥"就是这个代价
        Signature v4 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v4.initVerify(((SM9PublicKey) master.getPublic()).withId(ID_BOB));
        v4.update(MESSAGE);
        Assert.assertFalse(v4.verify(der));

        // 改一个字节的消息
        byte[] tampered = MESSAGE.clone();
        tampered[0] ^= 0x01;
        Signature v5 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v5.initVerify(alice.getPublic());
        v5.update(tampered);
        Assert.assertFalse(v5.verify(der));

        // 换个 r：签名不同但都合法（SM9 与 SM2 一样是随机化签名）
        Signature signer2 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        signer2.initSign(alice.getPrivate());
        signer2.update(MESSAGE);
        byte[] der2 = signer2.sign();
        Assert.assertFalse(Arrays.equals(der, der2));
        Signature v6 = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        v6.initVerify(alice.getPublic());
        v6.update(MESSAGE);
        Assert.assertTrue(v6.verify(der2));

        // 拿加密体系的私钥来签：hid 不对，直接在 init 阶段拒绝
        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_ENC));
        SM9PrivateKey ke = (SM9PrivateKey) kg.generateKeyPair().getPrivate();
        kg.initialize(new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_ENC, ke.getSecret()));
        KeyPair aliceEnc = kg.generateKeyPair();
        Signature wrong = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
        try
        {
            wrong.initSign(aliceEnc.getPrivate());
            Assert.fail("加密私钥不能签名");
        }
        catch (InvalidKeyException e)
        {
            log.info("[SM9-JCE] 拒绝用加密私钥签名：{}", e.getMessage());
        }
        log.info("[SM9-JCE] 签名 DER {} 字节，h = {}", der.length, Calc.hex(h));
    }

    // ---------------------------------------------------------------- ④加密 / 解密

    /**
     * JCE 加密与引擎 IBBE 在同一个 r 下逐字节相同；四类"解不开"必须统一报 BadPaddingException。
     */
    @Test
    public void cipherThroughJceMatchesEngineAndRejectsTampering()
        throws Exception
    {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("SM9", SM9Provider.NAME);
        kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_ENC));
        KeyPair master = kg.generateKeyPair();
        SM9PrivateKey ke = (SM9PrivateKey) master.getPrivate();
        kg.initialize(new SM9ParameterSpec(ID_BOB, SM9ParameterSpec.HID_ENC, ke.getSecret()));
        KeyPair bob = kg.generateKeyPair();

        BigInteger r = FIXED_R;
        Cipher enc = Cipher.getInstance("SM9", SM9Provider.NAME);
        enc.init(Cipher.ENCRYPT_MODE, bob.getPublic(), new FixedRandom(r));
        byte[] ct = enc.doFinal(MESSAGE);
        Assert.assertTrue("密文 = C1(65) + C3(32) + C2(len) 再加 DER 外层",
            ct.length > MESSAGE.length + 97);

        // 与引擎对照：同一把 ke、同一个 r，IBBE 的三个分量必须一字不差
        byte[] raw = Sm9Math.encrypt(ke.getMasterScalar(), ID_BOB, MESSAGE, r);
        ASN1Sequence parsed = ASN1Sequence.getInstance(ct);
        Assert.assertEquals("变换标记 0 = 明文用异或而不是分组密码", 0,
            ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue().signum());
        byte[] c1 = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        byte[] c3 = ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets();
        byte[] c2 = ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets();
        Assert.assertEquals(Calc.hex(Arrays.copyOfRange(raw, 0, 65)), Calc.hex(c1));
        Assert.assertEquals(Calc.hex(Arrays.copyOfRange(raw, 65, 97)), Calc.hex(c3));
        Assert.assertEquals(Calc.hex(Arrays.copyOfRange(raw, 97, raw.length)), Calc.hex(c2));

        // 用户私钥 de 解密
        Cipher dec = Cipher.getInstance("SM9", SM9Provider.NAME);
        dec.init(Cipher.DECRYPT_MODE, bob.getPrivate());
        Assert.assertArrayEquals(MESSAGE, dec.doFinal(ct));

        // KGC 视角：主私钥 ke + 收件人 ID 也能解（内部现算 de）
        Cipher decKgc = Cipher.getInstance("SM9/ECB/NoPadding", SM9Provider.NAME);
        decKgc.init(Cipher.DECRYPT_MODE, ke, new SM9ParameterSpec(ID_BOB, SM9ParameterSpec.HID_ENC), null);
        Assert.assertArrayEquals(MESSAGE, decKgc.doFinal(ct));

        // 1) 改 C2 一个字节 -> C3 对不上
        byte[] badC2 = ct.clone();
        badC2[badC2.length - 1] ^= 0x01;
        assertDecryptFails(badC2, bob.getPrivate(), "改 C2");

        // 2) 改 ID -> KDF 的输入里有 ID，掩码直接变，C3 对不上
        Cipher wrongId = Cipher.getInstance("SM9", SM9Provider.NAME);
        wrongId.init(Cipher.DECRYPT_MODE, bob.getPrivate(),
            new SM9ParameterSpec(ID_ALICE, SM9ParameterSpec.HID_ENC), null);
        try
        {
            wrongId.doFinal(ct);
            Assert.fail("换 ID 必须解不开");
        }
        catch (BadPaddingException e)
        {
            log.info("[SM9-JCE] 换 ID 解不开：{}", e.getMessage());
        }

        // 3) C1 换成不在 G₁ 上的点：B1 步就为了拦这个（错误预言攻击）
        assertDecryptFails(replaceC1(ct, offCurvePoint()), bob.getPrivate(), "C1 不在曲线上");

        // 4) 分组模式/填充：SM9 掩码从明文头部对齐，既不分块也不填充
        try
        {
            Cipher.getInstance("SM9/CBC/PKCS5Padding", SM9Provider.NAME);
            Assert.fail("SM9 没有分组模式");
        }
        catch (Exception e)
        {
            log.info("[SM9-JCE] 拒绝 CBC/PKCS5：{}", e.getMessage());
        }
        Cipher streaming = Cipher.getInstance("SM9", SM9Provider.NAME);
        streaming.init(Cipher.ENCRYPT_MODE, bob.getPublic());
        try
        {
            streaming.update(MESSAGE);
            Assert.fail("SM9 必须整段 doFinal");
        }
        catch (IllegalStateException e)
        {
            log.info("[SM9-JCE] 拒绝分块 update：{}", e.getMessage());
        }
        log.info("[SM9-JCE] 密文 {} 字节（明文 {} 字节 + C1 65 + C3 32 + DER 外层）",
            ct.length, MESSAGE.length);
    }

    /** 换掉密文里的 C1，其他分量原样保留 —— 模拟"塞一个非法点进来"的攻击。 */
    private static byte[] replaceC1(byte[] ct, byte[] fakeC1)
        throws Exception
    {
        ASN1Sequence parsed = ASN1Sequence.getInstance(ct);
        byte[] c3 = ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets();
        byte[] c2 = ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets();
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(new DERBitString(fakeC1));
        v.add(new DEROctetString(c3));
        v.add(new DEROctetString(c2));
        return new DERSequence(v).getEncoded();
    }

    /** x = 1 时 y² = 1 + 5 = 6 在 Fp 上不是平方，所以 (1, 随便一个 y) 基本必然不在曲线上。 */
    private static byte[] offCurvePoint()
    {
        return Calc.concat(new byte[]{ 0x04 }, Calc.toBytes(BigInteger.ONE, 32),
            Calc.toBytes(BigInteger.valueOf(2), 32));
    }

    private static void assertDecryptFails(byte[] ct, java.security.Key key, String label)
        throws Exception
    {
        Cipher c = Cipher.getInstance("SM9", SM9Provider.NAME);
        c.init(Cipher.DECRYPT_MODE, key);
        try
        {
            c.doFinal(ct);
            Assert.fail(label + " 之后必须解不开");
        }
        catch (BadPaddingException e)
        {
            // 关键断言：失败原因不外泄 —— 与"解开了但明文不对"区分不开才是安全的
            Assert.assertTrue("统一报 BadPaddingException", e.getMessage().startsWith("SM9 解密失败"));
            log.info("[SM9-JCE] {} -> {}", label, e.getMessage());
        }
    }

    // ---------------------------------------------------------------- ⑤注册表

    /**
     * Provider 就是一张"算法名 -> SPI 类名"的表；{@code getInstance} 只是查表 + 反射。
     * 这一条把表里的内容直接打印并核对，别让注册变成黑盒。
     */
    @Test
    public void registryIsJustAStringToClassNameMap()
        throws Exception
    {
        Provider provider = Security.getProvider(SM9Provider.NAME);
        Assert.assertEquals(SM9Provider.NAME, provider.getName());
        Assert.assertEquals("org.bouncycastle.learning.sm9.SM9CipherSpi",
            provider.get("Cipher.SM9"));
        Assert.assertEquals("org.bouncycastle.learning.sm9.SM9SignatureSpi",
            provider.get("Signature.SM3withSM9"));
        Assert.assertEquals("org.bouncycastle.learning.sm9.SM9KeyPairGeneratorSpi",
            provider.get("KeyPairGenerator.SM9"));

        int services = 0;
        int aliases = 0;
        for (String key : CryptoHelper.listAlgorithms(SM9Provider.NAME, null))
        {
            log.info("[SM9-JCE] 注册项 {}", key);
            if (key.startsWith("Alg.Alias."))
            {
                aliases++;
            }
            else if (key.startsWith("Cipher.") || key.startsWith("Signature.") || key.startsWith("KeyPairGenerator."))
            {
                services++;
            }
        }
        Assert.assertEquals("三个算法条目：Cipher/Signature/KeyPairGenerator 各一个", 3, services);
        Assert.assertEquals("三个别名：SM9WITHSM3、SM3WITHSM9、SM9", 3, aliases);

        // install() 幂等：重复调用不会塞第二个同名 Provider
        int before = countNamed(provider);
        SM9Provider.install();
        Assert.assertEquals(before, countNamed(provider));
    }

    private static int countNamed(Provider reference)
    {
        int n = 0;
        for (Provider p : Security.getProviders())
        {
            if (SM9Provider.NAME.equals(p.getName()))
            {
                n++;
            }
        }
        return n;
    }
}
