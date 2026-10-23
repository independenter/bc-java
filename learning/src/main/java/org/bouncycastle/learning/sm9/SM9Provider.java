package org.bouncycastle.learning.sm9;

import java.security.Provider;
import java.security.Security;

/**
 * SM9 的 JCE Provider —— 把 {@code Sm9Math} 那套"面向过程的数学"接成 Java 密码学的标准插座。
 *
 * <p>注册表就是本类的 {@link #register()}，一共六行，对标 BC 在
 * {@code org.bouncycastle.jcajce.provider.asymmetric.GM} 里给 SM2 注册的那四条：
 * <pre>
 *   Cipher.SM9                  → SM9CipherSpi            （基于标识的加密 IBBE）
 *   Signature.SM3withSM9        → SM9SignatureSpi         （SM9 签名，H2 用两遍 SM3）
 *   KeyPairGenerator.SM9        → SM9KeyPairGeneratorSpi  （主密钥生成 + 用户私钥提取）
 * </pre>
 * 用起来与 BC 的 SM2 手感一致：
 * <pre>
 *   SM9Provider.install();
 *   KeyPairGenerator kg = KeyPairGenerator.getInstance("SM9", SM9Provider.NAME);
 *   kg.initialize(new SM9ParameterSpec(SM9ParameterSpec.HID_SIGN));     // KGC 主密钥
 *   KeyPair master = kg.generateKeyPair();
 *   kg.initialize(new SM9ParameterSpec(aliceId, HID_SIGN, ks));         // KGC 给 Alice 发卡
 *   KeyPair alice = kg.generateKeyPair();
 *
 *   Signature sig = Signature.getInstance("SM3withSM9", SM9Provider.NAME);
 *   sig.initSign(alice.getPrivate());  sig.update(m);  byte[] der = sig.sign();
 *   sig.initVerify(alice.getPublic()); sig.update(m);  boolean ok = sig.verify(der);
 *
 *   Cipher c = Cipher.getInstance("SM9", SM9Provider.NAME);
 *   c.init(Cipher.ENCRYPT_MODE, alicePublicKeyForEncrypt);  byte[] ct = c.doFinal(m);
 *   c.init(Cipher.DECRYPT_MODE, alicePrivateKeyForEncrypt);  byte[] pt = c.doFinal(ct);
 * </pre>
 *
 * <p>两处刻意<b>没有</b>照抄 BC：
 * <ol>
 *   <li>不注册 OID 别名。BC 给 SM2 写了 {@code Alg.Alias.Signature.<oid>}，因为
 *       {@code GMObjectIdentifiers.sm2sign_with_sm3} 是 BC 自己定义并核对过的常量；SM9 的
 *       GB/T 标识体系 OID 在 BC 里根本没有（BC 没有 SM9），抄一个记不准的数字串比不写更糟，
 *       所以只留算法名与其别名。</li>
 *   <li>不写 {@code SupportedKeyClasses} 属性。写了它 JCE 会先按类名过滤再进 SPI，
 *       而本 Provider 的密钥类型检查全部放在 {@code engineInit} 里做，报错信息更直白
 *       （"这是签名体系的私钥，加密要用 hid=0x03 导出的那把"）。</li>
 * </ol>
 *
 * <p>也不依赖 BC 的 {@code ConfigurableProvider}：那个类要求 provider 由 BC 的
 * {@code ProviderConfiguration} 驱动，属于 BC 内部的装配体系；这里用 JDK 的 {@link Provider}
 * 直接 {@code put}，读者能看到"注册表就是一个字符串到类名的 Map"这件事的全部真相。
 *
 * <p>范围边界：BC 给 SM2 还注册了 {@code KeyAgreement.SM2}，SM9 对应的密钥交换
 * （GB/T 32915.4）在引擎里已经全部可用（{@code Sm9Math} 的 {@code exch*} 系列），
 * 但没有接成 {@code KeyAgreementSpi} —— 交换协议要交换 RA/RB 两个点并做双向确认标签，
 * 那已经不是一个 {@code doFinal()} 能装下的流程，硬塞进 JCE 反而看不清标准。
 */
public class SM9Provider
    extends Provider
{
    private static final long serialVersionUID = 1L;

    /** 注册名，所有 {@code getInstance(algorithm, provider)} 都用它。 */
    public static final String NAME = "SM9";

    private static final String INFO = "SM9 identity-based cipher suite (GB/T 32915), learning provider";

    /** SPI 类的全限定名前缀，与 BC 的 PREFIX 写法同源。 */
    private static final String PREFIX = "org.bouncycastle.learning.sm9.";

    /**
     * {@code Provider(String, double, String)} 在新 JDK 上打了过时标记，但仓库根 build.gradle
     * 给 learning 模块设的是 {@code options.release = 8} —— 三元 String 版本的构造器是 JDK 9 才有的，
     * 所以这里只能用 double 版本。
     */
    public SM9Provider()
    {
        super(NAME, 1.0, INFO);
        register(this);
    }

    /**
     * 注册表：算法名 -> SPI 类名。这就是 JCA 的全部机制，{@code getInstance} 只是查这张表再反射实例化。
     */
    private void register(Provider provider)
    {
        // 加密/解密：SM9 密文自带 C1（一次性公钥），不需要 IV，也没有分组模式
        provider.put("Cipher.SM9", PREFIX + "SM9CipherSpi");
        provider.put("Alg.Alias.Cipher.SM9WITHSM3", "SM9");

        // 签名/验签：H2 = 0x02‖M‖w 走两遍 SM3，所以名字沿用 SM2 的 "SM3with…" 惯例
        provider.put("Signature.SM3withSM9", PREFIX + "SM9SignatureSpi");
        provider.put("Alg.Alias.Signature.SM3WITHSM9", "SM3withSM9");
        provider.put("Alg.Alias.Signature.SM9", "SM3withSM9");

        // 密钥生成：SM9 只能生成主密钥，用户私钥由主私钥 + 标识推导
        provider.put("KeyPairGenerator.SM9", PREFIX + "SM9KeyPairGeneratorSpi");
    }

    /** 装到 JCE 环境里（幂等）：已存在同名 Provider 就不重复加。 */
    public static void install()
    {
        if (Security.getProvider(NAME) == null)
        {
            Security.addProvider(new SM9Provider());
        }
    }

    /** 从 JCE 环境里摘掉，供测试收尾用。 */
    public static void uninstall()
    {
        Security.removeProvider(NAME);
    }
}
