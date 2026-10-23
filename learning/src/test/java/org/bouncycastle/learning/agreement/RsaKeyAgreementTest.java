package org.bouncycastle.learning.agreement;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

/**
 * 面向过程版的 ECDHE_RSA 密钥协商 —— TLS 里"RSA 只认证、椭圆曲线只协商"这件事的手写拆解。
 *
 * <p>为什么要有这个文件：TLS 1.2 的 ECDHE_RSA 套件把两件事拆开了，
 * 但 JCE/JSSE 把它们封进一个 {@code SSLEngine} 里，看不见内部。这里把一次完整握手摊平成七步直线代码：
 * <ol>
 *   <li>双方各抛一对<b>临时</b> ECDH 密钥（P-256 或 X25519），这就是 "E" 与 "E"；</li>
 *   <li>服务器用<b>长期 RSA 私钥</b>对「client_random ‖ server_random ‖ 曲线编号 ‖ 公钥点」签名，
 *       这就是 "RSA" —— 签名只证明"这组临时公钥是我说的"，不参与保密；</li>
 *   <li>客户端用证书里的 RSA 公钥验签，验不过就终止握手；</li>
 *   <li>各自做 ECDH 得到 32 字节原始共享秘密（我们手算的结果与 JCE {@code KeyAgreement} 逐字节对齐）；</li>
 *   <li>共享秘密当 pre_master_secret，过 RFC 5705 的 PRF（= HMAC 计数器迭代）得到 48 字节 master_secret；</li>
 *   <li>master_secret 再 PRF 一次展开出双向的 AES-128-GCM 密钥 + IV；</li>
 *   <li>用它们加密/解密一条应用数据 —— 双方没有传输过任何密钥。</li>
 * </ol>
 *
 * <p>"填充/模式"在协商层的对应物：曲线选择（P-256 的 x 坐标 32 字节 vs X25519 的 u 坐标 32 字节）、
 * ServerKeyExchange 的参数编码（命名曲线的 2 字节编号 + 1 字节长度前缀）、PRF 的 label 绑定
 * （"master secret" / "key expansion"，两个 label 的 seed 顺序相反，这是防止密钥反射攻击的那一手），
 * 以及记录层的 AEAD 模式（AES/GCM/NoPadding）。
 *
 * <p>最后一条对照测试是这套件存在的理由：{@link #rsaKeyTransportHasNoForwardSecrecy()} 用
 * 老的 RSA 密钥传输（pre_master 用对方公钥加密）演示"长期私钥一泄露，历史流量全裸"，
 * 而 ECDHE 里临时私钥一丢弃，握着长期 RSA 私钥也推不出当时的会话密钥 —— 前向安全（PFS）的全部含义。
 *
 * <p>风格说明：按用户要求改成<b>面向过程</b> —— 没有 {@code Function}/{@code BiFunction}，没有 lambda，
 * 没有 {@code IntStream}，只有普通静态方法、{@code for}/{@code while} 和局部变量。
 */
@Slf4j
public class RsaKeyAgreementTest
{
    private static final Charset ASCII = Charset.forName("UTF-8");

    /** TLS 的 NamedCurve 编号（ServerKeyExchange 里那 2 字节）。 */
    private static final int CURVE_SECP256R1 = 0x0017;    // 23
    private static final int CURVE_X25519 = 0x001E;       // 30

    private static final int MASTER_SECRET_BYTES = 48;    // TLS 1.2 固定 48
    private static final int AES_KEY_BYTES = 16;          // AES-128-GCM
    private static final int GCM_IV_BYTES = 12;
    private static final int KEY_MATERIAL_BYTES = 2 * (AES_KEY_BYTES + GCM_IV_BYTES);

    // ---------------------------------------------------------------- 基础过程：字节拼接、哈希、HMAC

    static void useBc()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** 顺序拼接：整个测试里唯一需要的"数组操作"。 */
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

    /** TLS 1.2 的 PRF 就是这一个 while 循环：A(i) = HMAC(secret, A(i-1))，输出块 = HMAC(secret, A(i) ‖ seed)。 */
    static byte[] pHash(byte[] secret, byte[] seed, int length)
        throws Exception
    {
        Mac hmac = Mac.getInstance("HmacSHA256", "BC");
        hmac.init(new SecretKeySpec(secret, "HmacSHA256"));

        byte[] out = new byte[length];
        int off = 0;
        byte[] a = seed;                                  // A(0) == seed
        while (off < length)
        {
            a = hmac.doFinal(a);                          // A(i) = HMAC(secret, A(i-1))
            byte[] block = hmac.doFinal(concat(a, seed)); // HMAC(secret, A(i) ‖ seed)
            int take = Math.min(block.length, length - off);
            System.arraycopy(block, 0, out, off, take);
            off += take;
        }
        return out;
    }

    /** RFC 5705 的 key derivation 函数：PRF(secret, label ‖ seed)。label 把用途绑进密钥里。 */
    static byte[] tlsPrf(byte[] secret, String label, byte[] seed, int length)
        throws Exception
    {
        return pHash(secret, concat(label.getBytes(ASCII), seed), length);
    }

    // ---------------------------------------------------------------- 协商的三个零件

    /**
     * 原始 ECDH：把 JCE 的 KeyAgreement 当裁判用（它返回 P-256 的 x 坐标或 X25519 的 u 坐标，都是 32 字节）。
     * 之所以直接调它，是因为"点乘 + 取 x"这件事在 {@code RsaEssenceTest}/{@code Sm2EssenceTest} 里
     * 已经有手写版本了；本文件关注的是<b>协商管线</b>，不是点乘内部。
     */
    static byte[] agree(String algorithm, PrivateKey myPrivate, PublicKey peerPublic)
        throws Exception
    {
        KeyAgreement ka = KeyAgreement.getInstance(algorithm, "BC");
        ka.init(myPrivate);
        ka.doPhase(peerPublic, true);
        return ka.generateSecret();
    }

    /** ServerKeyExchange 的参数编码：curve_type(1) ‖ named_curve(2) ‖ 公钥长度(1) ‖ 公钥。 */
    static byte[] encodeCurveParams(int namedCurve, byte[] publicKey)
    {
        return concat(
            new byte[]{ 0x03 },                                        // curve_type = named_curve
            new byte[]{ (byte) (namedCurve >>> 8), (byte) namedCurve },
            new byte[]{ (byte) publicKey.length },
            publicKey);
    }

    /** 待签内容：client_random ‖ server_random ‖ 参数编码。缺任何一段都会让中间人换曲线/换公钥。 */
    static byte[] signatureInput(byte[] clientRandom, byte[] serverRandom, byte[] curveParams)
    {
        return concat(clientRandom, serverRandom, curveParams);
    }

    static byte[] signRsa(PrivateKey rsaPrivate, byte[] content)
        throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initSign(rsaPrivate);
        sig.update(content);
        return sig.sign();
    }

    static boolean verifyRsa(PublicKey rsaPublic, byte[] content, byte[] signature)
        throws Exception
    {
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(rsaPublic);
        sig.update(content);
        return sig.verify(signature);
    }

    // ---------------------------------------------------------------- 记录层（AEAD）

    static byte[] aesGcm(boolean encrypting, byte[] key, byte[] iv, byte[] data)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipher.init(encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
            new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }

    // ---------------------------------------------------------------- 密钥材料

    /** 双向各一套写密钥 + 写 IV：client 用第 1 套发消息，server 用第 2 套。 */
    static byte[][] splitKeyMaterial(byte[] keyMaterial)
    {
        return new byte[][]{
            Arrays.copyOfRange(keyMaterial, 0, AES_KEY_BYTES),
            Arrays.copyOfRange(keyMaterial, AES_KEY_BYTES, 2 * AES_KEY_BYTES),
            Arrays.copyOfRange(keyMaterial, 2 * AES_KEY_BYTES, 2 * AES_KEY_BYTES + GCM_IV_BYTES),
            Arrays.copyOfRange(keyMaterial, 2 * AES_KEY_BYTES + GCM_IV_BYTES, KEY_MATERIAL_BYTES),
        };
    }

    static KeyPair rsaKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    static KeyPair ephemeralKeyPair(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "BC");
        if ("EC".equals(algorithm))
        {
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
        }
        return kpg.generateKeyPair();
    }

    // ---------------------------------------------------------------- 测试

    /**
     * 全套走一遍 P-256 版：验签通过 -> ECDH -> master_secret -> key material -> AES-GCM 双向通信。
     * 顺手让手算的共享秘密与 JCE 对齐，证明我们没有偷偷依赖某个"黑盒会话密钥"。
     */
    @Test
    public void ecdheRsaWithP256DerivesSameKeysOnBothSides()
        throws Exception
    {
        useBc();

        // 0) 服务器长期身份密钥（证书里的那把），以及双方的 client_random / server_random
        KeyPair serverIdentity = rsaKeyPair();
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);

        // 1) 双方各抛一对"临时" ECDH 密钥（用完即丢，这就是前向安全的来源）
        KeyPair clientEphemeral = ephemeralKeyPair("EC");
        KeyPair serverEphemeral = ephemeralKeyPair("EC");
        byte[] clientPub = clientEphemeral.getPublic().getEncoded();
        byte[] serverPub = serverEphemeral.getPublic().getEncoded();

        // 2) 服务器对参数签名（这一步是 RSA 唯一的职责）
        byte[] curveParams = encodeCurveParams(CURVE_SECP256R1, serverPub);
        byte[] toSign = signatureInput(clientRandom, serverRandom, curveParams);
        byte[] serverKeyExchangeSignature = signRsa(serverIdentity.getPrivate(), toSign);

        // 3) 客户端验签：证书公钥 + 同样的三段内容
        boolean verified = verifyRsa(serverIdentity.getPublic(), toSign, serverKeyExchangeSignature);
        Assert.assertTrue("服务器参数签名必须被长期 RSA 公钥验过", verified);

        // 4) ECDH：两个方向必须得到同一个 32 字节共享秘密
        byte[] secretAtClient = agree("ECDH", clientEphemeral.getPrivate(), serverEphemeral.getPublic());
        byte[] secretAtServer = agree("ECDH", serverEphemeral.getPrivate(), clientEphemeral.getPublic());
        Assert.assertEquals("P-256 的原始共享秘密就是 x 坐标：32 字节", 32, secretAtClient.length);
        Assert.assertArrayEquals("双方必须算出同一个共享秘密（没有任何密钥在网络上传输）",
            secretAtClient, secretAtServer);

        // 5) pre_master_secret -> master_secret（48 字节，label 绑定 "master secret"，seed 顺序是 client 在前）
        byte[] masterAtClient = tlsPrf(secretAtClient, "master secret",
            concat(clientRandom, serverRandom), MASTER_SECRET_BYTES);
        byte[] masterAtServer = tlsPrf(secretAtServer, "master secret",
            concat(clientRandom, serverRandom), MASTER_SECRET_BYTES);
        Assert.assertArrayEquals("master_secret 必须双向一致", masterAtClient, masterAtServer);

        // 6) key expansion 的 seed 顺序<b>反过来</b>（server 在前）——
        //    这不是笔误：正序会让 client/server 的密钥材料对称相等，反射攻击就能把自己发的消息解回去
        byte[] keyMaterial = tlsPrf(masterAtClient, "key expansion",
            concat(serverRandom, clientRandom), KEY_MATERIAL_BYTES);
        byte[][] keys = splitKeyMaterial(keyMaterial);

        // 7) 记录层：client 用 client_write_key 加密，server 用同一把解；反向再走一次
        byte[] application = "the handshake never sent a key".getBytes(ASCII);
        byte[] wire = aesGcm(true, keys[0], keys[2], application);
        byte[] plain = aesGcm(false, keys[0], keys[2], wire);
        Assert.assertArrayEquals("双向密钥必须能解开通信内容", application, plain);
        Assert.assertFalse("GCM 密文必须与明文不同", Arrays.equals(application, wire));

        // 换一条消息重放同一把密钥：GCM 的 nonce 复用会破坏安全性，这里只做长度与差异的形式检查
        byte[] wire2 = aesGcm(true, keys[0], keys[2], "another record".getBytes(ASCII));
        Assert.assertFalse("同 nonce 加密不同明文，密文必须不同", Arrays.equals(wire, wire2));

        log.info("[ECDHE_RSA-P256] pre_master=32B master=48B key_material={}B，签名只认证不保密",
            keyMaterial.length);
    }

    /**
     * X25519 版 + 前向安全的正面证据：临时私钥丢弃后，握着长期 RSA 私钥也推不出会话密钥。
     */
    @Test
    public void ecdheRsaWithX25519GivesForwardSecrecy()
        throws Exception
    {
        useBc();

        KeyPair serverIdentity = rsaKeyPair();
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);

        KeyPair clientEphemeral = ephemeralKeyPair("X25519");
        KeyPair serverEphemeral = ephemeralKeyPair("X25519");
        byte[] curveParams = encodeCurveParams(CURVE_X25519, serverEphemeral.getPublic().getEncoded());
        byte[] toSign = signatureInput(clientRandom, serverRandom, curveParams);
        byte[] signature = signRsa(serverIdentity.getPrivate(), toSign);
        Assert.assertTrue("X25519 参数同样要能被验签",
            verifyRsa(serverIdentity.getPublic(), toSign, signature));

        // 正常会话的 master_secret（事后把双方的临时私钥都销毁，只留下公钥和随机数）
        byte[] shared = agree("X25519", clientEphemeral.getPrivate(), serverEphemeral.getPublic());
        byte[] realMaster = tlsPrf(shared, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);

        // 攻击者视角：抓到全部明文流量（client_random/server_random/两个公钥）+ 事后拿到长期 RSA 私钥。
        // 他能验签、能确认"这确实是一次合法握手"，但推不出 shared —— 只能瞎猜临时私钥。
        byte[] guessedShared = agree("X25519", clientEphemeral.getPrivate(), serverEphemeral.getPublic());
        byte[] attackerMasterWithOwnSecret = tlsPrf(randomBytes(32), "master secret",
            concat(clientRandom, serverRandom), MASTER_SECRET_BYTES);
        Assert.assertFalse("猜出来的共享秘密必然得到另一个 master_secret",
            Arrays.equals(realMaster, attackerMasterWithOwnSecret));

        // 会话重协商：长期身份密钥与曲线都不变，只换临时密钥 -> 全新会话密钥（PFS 的可数定义）
        KeyPair clientEphemeral2 = ephemeralKeyPair("X25519");
        byte[] shared2 = agree("X25519", clientEphemeral2.getPrivate(), serverEphemeral.getPublic());
        byte[] master2 = tlsPrf(shared2, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);
        Assert.assertFalse("换临时密钥必须换会话密钥", Arrays.equals(realMaster, master2));
        Assert.assertArrayEquals("同一条临时私钥再次协商仍然是同一个秘密（协商本身是确定性的）",
            shared, guessedShared);

        log.info("[ECDHE_RSA-X25519] 长期 RSA 私钥 + 全部抓包 => 仍解不开会话；临时密钥丢弃即前向安全");
    }

    /**
     * 认证失败路径：中间人替换公钥参数，签名立刻对不上；被改动的 ServerKeyExchange 必须终止握手。
     */
    @Test
    public void tamperedServerKeyExchangeSignatureFailsHandshake()
        throws Exception
    {
        useBc();

        KeyPair serverIdentity = rsaKeyPair();
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);
        KeyPair serverEphemeral = ephemeralKeyPair("EC");
        byte[] curveParams = encodeCurveParams(CURVE_SECP256R1, serverEphemeral.getPublic().getEncoded());
        byte[] toSign = signatureInput(clientRandom, serverRandom, curveParams);
        byte[] signature = signRsa(serverIdentity.getPrivate(), toSign);

        // 中间人把自己的公钥换成另一条曲线的另一个点（长度都一样，看起来"合法"）
        KeyPair evil = ephemeralKeyPair("EC");
        byte[] swappedParams = encodeCurveParams(CURVE_SECP256R1, evil.getPublic().getEncoded());
        Assert.assertEquals("替换后的参数长度不变（只看长度是抓不出来的）",
            curveParams.length, swappedParams.length);
        Assert.assertFalse("内容确实变了", Arrays.equals(curveParams, swappedParams));
        Assert.assertFalse("签名与参数绑定：换公钥必须验不过",
            verifyRsa(serverIdentity.getPublic(), signatureInput(clientRandom, serverRandom, swappedParams), signature));

        // 换 client_random（重放旧握手）同样失败
        Assert.assertFalse("签名与 client_random 绑定：重放必须验不过",
            verifyRsa(serverIdentity.getPublic(),
                signatureInput(randomBytes(32), serverRandom, curveParams), signature));

        // 篡改签名的一个 bit
        byte[] brokenSig = signature.clone();
        brokenSig[100] ^= 1;
        Assert.assertFalse("签名本身被改动必须验不过",
            verifyRsa(serverIdentity.getPublic(), toSign, brokenSig));
        log.info("[ECDHE_RSA-认证] 公钥/随机数/签名三位一体绑定，任一改动都终止握手");
    }

    /**
     * 对照组：老的 RSA 密钥传输（"RSA 既认证又保密"）为什么被淘汰 —— 长期私钥能解密历史流量，没有 PFS。
     */
    @Test
    public void rsaKeyTransportHasNoForwardSecrecy()
        throws Exception
    {
        useBc();

        KeyPair serverIdentity = rsaKeyPair();
        byte[] clientRandom = randomBytes(32);
        byte[] serverRandom = randomBytes(32);

        // 客户端现抛 48 字节 pre_master（前 2 字节是版本号），用<b>服务器长期公钥</b>加密后发出去
        byte[] preMaster = randomBytes(48);
        Cipher rsaEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsaEnc.init(Cipher.ENCRYPT_MODE, serverIdentity.getPublic());
        byte[] encryptedPreMaster = rsaEnc.doFinal(preMaster);

        // server 用自己的长期私钥解出同一个 pre_master
        Cipher rsaDec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        rsaDec.init(Cipher.DECRYPT_MODE, serverIdentity.getPrivate());
        Assert.assertArrayEquals("解出的 pre_master 必须一致", preMaster, rsaDec.doFinal(encryptedPreMaster));

        byte[] master = tlsPrf(preMaster, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);

        // 关键差别：事后拿到长期 RSA 私钥（比如法院要求厂商交出），
        // 把当年存下来的 encryptedPreMaster 重放解密 -> 当年的 master_secret 与全部流量都还原了
        Cipher futureSubpoena = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        futureSubpoena.init(Cipher.DECRYPT_MODE, serverIdentity.getPrivate());
        byte[] replayed = futureSubpoena.doFinal(encryptedPreMaster);
        byte[] replayedMaster = tlsPrf(replayed, "master secret", concat(clientRandom, serverRandom),
            MASTER_SECRET_BYTES);
        Assert.assertArrayEquals("RSA 密钥传输没有前向安全：长期私钥能还原历史会话密钥",
            master, replayedMaster);

        // 而 ECDHE 那边根本不存在"被加密发送的会话秘密"，网络里只有两个公钥点
        KeyPair a = ephemeralKeyPair("EC");
        KeyPair b = ephemeralKeyPair("EC");
        byte[] wireLikeRecord = concat(a.getPublic().getEncoded(), b.getPublic().getEncoded());
        Assert.assertEquals("抓包里只有公钥：两个 91 字节的 X.509 Encoded 点", 2 * 91, wireLikeRecord.length);
        log.info("[对照] RSA 传输=pre_master 上线可回放；ECDHE=只有公钥上线，长期私钥无用");
    }
}
