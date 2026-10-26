package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * SM9 标识加密 IBBE（GB/T 32915.3）的本质计算 —— 面向过程版。
 *
 * <p><b>符号表 —— 本文件每条公式里的字母/记号</b>
 * <pre>
 *   IBBE        Identity-Based Broadcast/Box Encryption，基于标识的加密：收件人的"公钥"= 他的标识字符串
 *   KEM         Key Encapsulation Mechanism，密钥封装：加密侧随机生成一把对称密钥 K 并"封"进密文，
 *               解密侧用私钥把同一个 K "解"出来；IBBE 只是把 K 的来源换成了配对
 *   ke          加密主私钥 (encryption master key)，Z_n 里的标量，只在 KGC 手里（GmSSL: hex_ke）
 *   Ppube       加密主公钥 = ke·P1 ∈ G₁，序列化成 65 字节（0x04‖x‖y）；全网公开
 *   de          加密用户私钥 = ke·(ke + H1(ID,0x03))⁻¹·P2 ∈ G₂，129 字节（0x04‖x₁‖x₀‖y₁‖y₀）
 *   ID          收件人标识字节串："Bob" = 42 6F 62（3 字节）、"Alice" = 41 6C 69 63 65
 *   hid         用途分隔符：加密固定 0x03（Sm9Math.HID_ENC）；签名 0x01、交换 0x02
 *   H1(ID,hid)  SM3(0x01‖ID‖hid‖00000001) ‖ SM3(0x01‖ID‖hid‖00000002) 共 64 字节，
 *               取前 40 字节当整数 z，返回 z mod (n−1) + 1 ⇒ 值域 [1, n−1]，永不为 0
 *   Q_B         收件人公钥点 = H1(ID,0x03)·P1 + Ppube = (H1 + ke)·P1 ∈ G₁（65 字节）
 *               ← 标识直接进了点，所以不需要证书、不需要目录，也不允许拼错
 *   r           本次加密的一次性随机数 (nonce / ephemeral private key)，Z_n 里取，只用一次
 *   C1          = r·Q_B ∈ G₁，65 字节，密文的第一段（"临时公钥"，任何人可见）
 *   w           共享秘密 = e(Ppube, P2)^r = e(C1, de) ∈ GT，展平 384 字节 —— 两侧同一个数
 *   Z           KDF 的输入种子 = C1 的<b>裸</b> x‖y（64 字节，不含 0x04 前缀）‖ w（384）‖ ID
 *   KDF         SM3 计数器流：T = SM3(Z‖00000001) ‖ SM3(Z‖00000002) ‖ … 拼够 klen 字节为止
 *   klen        要派生的字节数 = len(M) + 32（掩码段 + MAC 密钥段）
 *   K           = KDF(Z, klen)，整段共享密钥；K_mask = K[0, len(M))，K_mac = K[len(M), len(M)+32)
 *   M / len(M)  明文原文及其字节数（本文件 "Chinese IBS standard" = 20 字节）
 *   C2          = M ⊕ K_mask，与明文<b>等长</b>（没有分组密码、没有填充）
 *   C3          = HMAC-SM3(密钥 = K_mac, 消息 = C2)，32 字节完整性标签
 *   ⊕           逐字节异或；‖ 字节串拼接（不是异或）；+ 群加法；· 标量乘或域乘法
 *   ⁻¹ mod n    Z_n 里的模逆；指数与除法都在 Z_n（模 n）里算
 *   密文布局     C1(65) ‖ C3(32) ‖ C2(len) —— 标准把 MAC 放在明文<b>前面</b>
 * </pre>
 *
 * <p>看点只有一条：<b>没有证书、没有公钥，接收方的"公钥"就是他的标识字符串</b>。
 * 把标识塞进一个椭圆曲线点上，配对再把两个标量乘到同一个 Fp12 元素上，双方就能算出同一个 w：
 * <pre>
 *   Q_B  = H1(ID,0x03)·P1 + Ppube = (H1 + ke)·P1      ← 只用到 ID 和公开的 Ppube = ke·P1
 *   C1   = r·Q_B                                       ← 临时公钥，密文的第一段
 *   加密侧 w = e(Ppube, P2)^r          = e(P1,P2)^{ke·r}
 *   解密侧 w = e(C1, de) = e(r(H1+ke)P1, ke/(H1+ke)·P2) = e(P1,P2)^{r·ke}   ← 同一个数
 * </pre>
 * 分母 (H1+ke) 在配对里被消掉 —— 这正是"只有 KGC 能发私钥，别人连密文结构都凑不出"的原因。
 * <p><b>两侧 w 相等的逐字母读法</b>（就是上面第 3、4 行）：
 * <pre>
 *   e(Ppube, P2)^r          = e(ke·P1, P2)^r          ← Ppube 的定义
 *                         = e(P1, P2)^{ke·r}          ← 双线性把第一个参数的 ke 提到指数上，再乘 r
 *   e(C1, de)               = e(r·(ke+H1)·P1, ke·(ke+H1)⁻¹·P2)
 *                         = e(P1, P2)^{ r(ke+H1) · ke(ke+H1)⁻¹ } = e(P1,P2)^{ke·r}
 *                                       └──── (ke+H1) 与其逆元相消 ────┘
 * </pre>
 * 消掉的依据是"指数在 Z_n 里算"：(ke+H1)⁻¹·(ke+H1) ≡ 1 (mod n)。加密侧根本没用 de（用不到收件人
 * 私钥），解密侧根本没用 ke（用不到主私钥），但两边落在同一个 384 字节的群元素上 —— 这就是 IBBE 的
 * 全部内容。剩下的 (ke + H1)⁻¹ 那一项只有 KGC 能算，因为它同时需要 ke 与 H1。
 *
 * <p><b>标准步骤与本实现的对应</b>
 * <pre>
 *   加密侧 A1~A7（顺序即代码顺序，见 Sm9Math.kemEncryptToIdentity + encryptToIdentity）
 *     取 r ← Z_n；Q_B = H1(ID,0x03)·P1 + Ppube；w = e(Ppube,P2)^r；C1 = r·Q_B；
 *     K = KDF(C1_x‖C1_y‖w‖ID, len(M)+32)；C2 = M ⊕ K[0..len)；C3 = HMAC-SM3(K[len..len+32), C2)
 *   解密侧 B1~B4（Sm9Math.kemDecryptWithUserKey + decryptWithUserKey）
 *     B1 检查 C1 ∈ G₁（不在就抛，见方法里那句 throw）；B2 w = e(C1, de)；
 *     B3 K = 同一个 KDF（<b>输入必须逐字节相同</b>，包括它用的是裸坐标而非 0x04‖x‖y）；
 *     B4 核 C3 == HMAC(…) → 不等则抛异常，绝不返回明文；等则 M = C2 ⊕ K_mask
 * </pre>
 * <p>为什么 KDF 的输入要把 0x04 前缀<b>去掉</b>（只喂 64 字节的 x‖y）：标准规定 KDF 的种子是
 * C1 的<b>坐标</b>而不是它的编码，而传输/存储用的编码（0x04‖x‖y）只是为了让人认得出格式。
 * 少剥一个字节，两侧算出的 K 就不同 —— 这是最常见的 SM9 实现 bug 之一，本文件测试②③ 都把它钉住。
 * <p>为什么"一次异或 + 一个 HMAC"就敢叫加密：K 是 KDF 从一个计算性不可区分的随机量里取的
 * 字节流，作用等价于一次一密 (one-time pad)，因此密文与明文<b>等长</b>（无填充、无块对齐）；
 * 代价是 K 必须<b>整段一次取够</b> len(M)+32 字节，且 K 全零时（概率可忽略）标准要重回 A1 重采 r。
 * C3 是对<b>密文段</b> C2 做的 MAC，即 encrypt-then-MAC（先掩码、再认证），这是唯一安全的组合顺序：
 * 若反过来做 MAC-then-encrypt，攻击者可以在密文层制造碰撞而解密方无法察觉。
 * <p><b>托管 (key escrow) 与安全假设</b>：KGC 持有 ke 就能算出任何收件人的 de，因此<b>能解所有人的
 * 密文</b>；这是标识密码的定义性代价，不是实现缺陷（要规避只能上证书 PKI）。协议本身抵抗的是
 * 不知道 ke 的攻击者：不改密文的情况下区分 K，需要解 G₁/G₂ 上的双线性 Diffie–Hellman 问题
 * （GB/T 32915 声称约 128 bit 安全强度，来自 256 bit 素数阶群）。加密<b>不带</b>前向保密：
 * 密文录下来后只要 ke（或该收件人的 de）将来泄露，历史密文即可解出。
 *
 * <p>拿到 w 之后就没有密码学了：K = KDF(C1_x‖C1_y‖w‖ID) 是一段 SM3 计数器流，
 * <b>C2 = M ⊕ K 只有一次异或</b>（没有分组密码！），C3 = HMAC-SM3(key = K 尾部 32 字节, 消息 = C2)。
 * 于是 K 必须一次取"明文长度 + 32"字节 —— 与 GmSSL 的 sm9_do_encrypt 完全一致。
 *
 * <p><b>本文件的 KAT（known-answer test）出处</b>：ID = "Bob"、ke = hex_ke、de = hex_de 与消息都取自
 * GmSSL 的 {@code tests/sm9test.c}（GB/T 32915 附录 A 的示例值）。随机数 r 是这里额外固定的：
 * GmSSL 现采 r，标准文档里没有 C1/C2/C3 的样例，测试②③ 用同一个 r 才能把 C1、w、K 全钉成确定值。
 * HMAC-SM3(key, msg) 按 RFC 2104 的构造做：key 超过 64 字节先哈希一次，再分别与 ipad = 0x36、
 * opad = 0x5c 逐字节异或成两个 64 字节的分钥，最后 SM3(opad ‖ SM3(ipad ‖ msg))。
 */
@Slf4j
public class Sm9EncryptEssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /** GmSSL tests/sm9test.c 的加密样例：ID = "Bob"，消息 20 字节。 */
    private static final byte[] ID_BOB = "Bob".getBytes();
    /** 只出现在"拿错收件人私钥"的对照里：标识是公钥的一部分，换 ID 就等于换收件人。 */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    /** 明文 20 字节；SM9 的 IBBE 不预哈希、不分块，直接当异或掩码的字节流用。 */
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();
    /** 加密主私钥 ke（GmSSL: hex_ke）：255 bit 标量；Ppube = ke·P1，de 里的分子分母都由它决定。 */
    private static final BigInteger HEX_KE = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

    /** 标准答案 de = ke/(ke+H1(Bob,0x03))·P2（GmSSL: hex_de，四行 = x₁,x₀,y₁,y₀）。 */
    private static final String HEX_DE =
        "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683"
            + "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158"
            + "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F"
            + "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1";

    /** 加密的临时随机数 r（GmSSL 现采；这里固定，好让 C1、K 能逐字节复算）。 */
    private static final BigInteger R = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);

    /** KDF 输出的对称密钥长度。GmSSL 的 sm9_kem_encrypt 直接收 klen，这里取 16 字节够用。
     * 注意 KEM 层只吐 klen 字节，<b>不知道</b>明文多长；完整 IBBE 才把 klen 定成 len(M)+32。 */
    private static final int KLEN = 16;

    /**
     * 测试①：私钥提取对齐 hex_de，并确认它真的是 G₂ 上的 n 阶点。
     * <p>de 的字节形状是 0x04‖x₁‖x₀‖y₁‖y₀（129 字节）：G₂ 的点定义在 Fp2 上，
     * 而 Fp2 的元素写成 x₀ + x₁·u（u 是这条扩域引入的形式根，见 Sm9Math 的塔域说明），
     * 所以每个坐标是<b>两个</b> 32 字节，且<b>高次分量 x₁ 在前</b>。顺序写反（x₀ 在前）是最难查的 SM9 bug：
     * 它仍然是 129 字节、仍然能 parse，只是从此不在曲线上。
     * <p>三条断言分别检查：与标准答案逐字符相同 / 在扭曲曲线 E'(Fp2): y² = x³ + 5u 上 /
     * 阶整除 n（n·de 落到无穷远点）。第二、三条合起来才说明"它在 de 该在的那个子群里"。
     */
    @TraceExecution(value = "SM9 加密私钥提取对齐 GmSSL", algorithm = "SM9", flow = "SM9-ENCRYPT")
    @Test
    public void encryptionPrivateKeyMatchesGmsslAnswer()
    {
        Tracer.trace("start", new Object[]{"id", "Bob", "ke_bits", HEX_KE.bitLength(), "hid", Sm9Math.HID_ENC}, null, "start");

        BigInteger[][] de = Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC);
        Tracer.trace("privateKeyExtract", new Object[]{"ke", HEX_KE, "id", "Bob", "hid", Sm9Math.HID_ENC},
            Sm9Math.twistToOctets(de), "keygen");

        // HEX_DE 只有 128 个 hex 字符（x₁x₀y₁y₀ = 4×32 字节），补上未压缩点前缀才与
        // twistToOctets 的 129 字节输出对齐；toUpperCase 只是排版差异。
        Assert.assertEquals("04" + HEX_DE, Calc.hex(Sm9Math.twistToOctets(de)).toUpperCase());
        Assert.assertTrue("de 必须在 E'(Fp2): y² = x³ + 5u 上", Sm9Math.twistIsOnCurve(de));
        // G₂ 的阶是素数 n，非无穷远点的倍数只有 0 与 n ⇒ 这条断言确认 de ∈ G₂（不是更大群里的杂点）
        Assert.assertTrue("n·de 必须是无穷远点", Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, de)));
        Tracer.traceDecision("checkDe", new Object[]{"de", Sm9Math.twistToOctets(de), "onCurve", Sm9Math.twistIsOnCurve(de),
                "n_de_isInfinity", Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, de))},
            Sm9Math.twistIsOnCurve(de) && Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, de)),
            "keygen", "de ∈ G₂ 且 n·de = O");

        // 同一个 ke、同一个 Bob，换个 hid 就是另一把私钥：加密私钥绝不能拿来签名或交换
        // （公式只差 H1 的第二个字节：0x03 vs 0x01 ⇒ 分母不同 ⇒ G₂ 里完全不同的点）
        Assert.assertFalse(Arrays.equals(Sm9Math.twistToOctets(de),
            Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_SIGN))));
        Tracer.traceDecision("compare.answer", new Object[]{"actual", Sm9Math.twistToOctets(de),
                "expected", "04" + HEX_DE},
            ("04" + HEX_DE).equalsIgnoreCase(Calc.hex(Sm9Math.twistToOctets(de))),
            "compare", "de == GmSSL hex_de");
        Tracer.traceDecision("compare.hidIsolation", new Object[]{"de_enc", Sm9Math.twistToOctets(de),
                "de_sign", Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_SIGN))},
            !Arrays.equals(Sm9Math.twistToOctets(de),
                Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_SIGN))),
            "compare", "hid 0x03 与 0x01 导出不同私钥");
        // 换个标识就是另一把私钥 —— 这就是"标识即公钥"
        Assert.assertFalse(Arrays.equals(Sm9Math.twistToOctets(de),
            Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_ALICE, Sm9Math.HID_ENC))));
        Tracer.traceDecision("compare.idIsolation", new Object[]{"de_bob", Sm9Math.twistToOctets(de),
                "de_alice", Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_ALICE, Sm9Math.HID_ENC))},
            !Arrays.equals(Sm9Math.twistToOctets(de),
                Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_ALICE, Sm9Math.HID_ENC))),
            "compare", "Bob 与 Alice 的加密私钥不同");
        log.info("de = {}", Calc.hex(Sm9Math.twistToOctets(de)));
        Tracer.trace("end", new Object[]{"de", Sm9Math.twistToOctets(de)}, null, "end");
    }

    /**
     * 测试②：KEM 两侧对齐，并把"双线性把分母消掉"这件事写成字节断言：
     * 加密侧 {@code e(Ppube,P2)^r} 与解密侧 {@code e(C1,de)} 必须是同一段 384 字节。
     * <p>四段断言各管一件事：
     * <pre>
     *   输出长度 65 + klen       密文段 C1 定长 65 字节，K 恰好 klen 字节（KEM 层与明文长度无关）
     *   两侧 K 相同              同一个 w + 同一个 KDF 输入 ⇒ 同一段字节流（连 K 全零都要防）
     *   C1 = r·Q = r(ke+H1)·P1   临时公钥的两种算法：先加后乘 vs 先算标量再乘 —— 群律保证一致
     *   w 两侧 384 字节相同       本协议唯一的新算子（配对的双线性）在起作用
     *   KDF 是前缀流             取 52 字节的前 16 字节 == 直接取 16 字节（见下面那段说明）
     * </pre>
     */
    @TraceExecution(value = "SM9 KEM 两条路线因配对消去分母而一致", algorithm = "SM9", flow = "SM9-ENCRYPT")
    @Test
    public void kemRoutesAgreeBecausePairingCancelsTheDenominator()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"id", "Bob", "klen", KLEN, "r", R}, null, "start");

        byte[] out = Sm9Math.kemEncrypt(HEX_KE, ID_BOB, KLEN, R);
        Tracer.trace("kemEncrypt", new Object[]{"ke", HEX_KE, "id", "Bob", "klen", KLEN, "r", R}, out, "genR");
        Assert.assertEquals(65 + KLEN, out.length);
        // 前 65 字节 = C1 的 0x04‖x‖y（含未压缩点前缀），后面才是 KEM 吐出的 klen 字节密钥
        byte[] c1 = Arrays.copyOfRange(out, 0, 65);
        byte[] kEncrypt = Arrays.copyOfRange(out, 65, out.length);

        // 解密侧只拿 C1 和 de，必须还原出同一段 K
        byte[] kDecrypt = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, KLEN, c1);
        Assert.assertArrayEquals(kEncrypt, kDecrypt);
        // KDF 吐出全零意味着 K 失去信息量（掩码等于没掩）。概率约 2^-128（这里 klen=16），
        // 但标准要求真的检查一下并回到 A1 重采 r，GmSSL 用 mem_is_zero 做这件事。
        Assert.assertFalse("KDF 不能吐出全零（GmSSL 为此重采 r）", isAllZero(kDecrypt));

        // C1 = r·Q = r·(H1+ke)·P1 —— 两条路线同一个点
        BigInteger[] q = Sm9Math.kemQ(HEX_KE, ID_BOB);
        Tracer.trace("pointMul.C1", new Object[]{"r", R, "Q", Sm9Math.pointToOctets(q)},
            Sm9Math.pointToOctets(Sm9Math.pointMul(R, q)), "pointMul");
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(R, q))), Calc.hex(c1));
        // 第二个写法是"先把标量算齐 (H1+ke)·r mod n，再对 P1 乘一次"：
        // 群的结合律/分配律断言 r·(m·P1) = (r·m mod n)·P1。n 是 P1 的阶，所以标量可以mod n 化简。
        Assert.assertEquals(Calc.hex(c1), Calc.hex(Sm9Math.pointToOctets(
            Sm9Math.pointMul(Sm9Math.modnMul(R, Sm9Math.modnAdd(Sm9Math.hash1(ID_BOB, Sm9Math.HID_ENC), HEX_KE)),
                Sm9Math.P1))));

        // 双线性证据：e(C1, de) = e(P1,P2)^{ke·r} = e(Ppube,P2)^r
        // 注意 Java 侧 pairing(第二个参数, 第一个参数) 的实参顺序（见 Sm9PairingEssenceTest 的说明）：
        // 这里传 (de ∈ G₂, C1 ∈ G₁)，读作数学记号 e(C1, de)。
        BigInteger[] wDecrypt = Sm9Math.pairing(
            Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC), Sm9Math.pointFromOctets(c1));
        BigInteger[] wEncrypt = Sm9Math.fp12Pow(
            Sm9Math.pairing(Sm9Math.P2, Sm9Math.encMasterPublicKey(HEX_KE)), R);
        Tracer.trace("w.decrypt", new Object[]{"de", Sm9Math.twistToOctets(
            Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC)), "C1", c1},
            Sm9Math.fp12ToBytes(wDecrypt), "w");
        Tracer.trace("w.encrypt", new Object[]{"Ppube", Sm9Math.encMasterPublicKey(HEX_KE), "r", R},
            Sm9Math.fp12ToBytes(wEncrypt), "w");
        Tracer.trace("kemDecrypt.K", new Object[]{"ke", HEX_KE, "id", "Bob", "klen", KLEN, "C1", c1},
            kDecrypt, "kdf");
        // 两次 fp12ToBytes 之后再比字符串：384 个字节全等才算"同一个 GT 元素"，
        // 而不是"数值上大概是同一个"（GT 元素的表示在塔域里是唯一的，没有等价写法可容忍）。
        Assert.assertEquals(Calc.hex(Sm9Math.fp12ToBytes(wEncrypt)), Calc.hex(Sm9Math.fp12ToBytes(wDecrypt)));

        // KDF 是前缀流：先要 52 字节，再要 16 字节，前 16 字节必须一致（GmSSL 就靠这一点
        // 让 sm9_do_encrypt 用 sizeof(K) 全长取 K，而只用前 inlen+32 个字节）
        // 52 = MESSAGE.length(20) + 32 = 完整 IBBE 实际要的 klen；KLEN=16 是它的更短前缀。
        // 之所以能这么"截"：SM3 计数器流的第 i 段只依赖 Z 和 i，与总共要几段无关。
        byte[] longK = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, MESSAGE.length + 32, c1);
        Assert.assertArrayEquals(kDecrypt, Arrays.copyOfRange(longK, 0, KLEN));
        Tracer.trace("kdf.prefix", new Object[]{"klen", KLEN, "longKlen", MESSAGE.length + 32},
            Arrays.copyOfRange(longK, 0, KLEN), "kdf");
        Tracer.traceDecision("compare.K", new Object[]{"kEncrypt", kEncrypt, "kDecrypt", kDecrypt},
            Arrays.equals(kEncrypt, kDecrypt), "compare", "加密侧 K == 解密侧 K");
        Tracer.traceDecision("compare.w", new Object[]{"wEncrypt", Sm9Math.fp12ToBytes(wEncrypt),
                "wDecrypt", Sm9Math.fp12ToBytes(wDecrypt)},
            Arrays.equals(Sm9Math.fp12ToBytes(wEncrypt), Sm9Math.fp12ToBytes(wDecrypt)),
            "compare", "e(Ppube,P2)^r == e(C1,de)");
        Tracer.traceDecision("compare.kdfPrefix", new Object[]{"shortK", kDecrypt, "longK_prefix", Arrays.copyOfRange(longK, 0, KLEN)},
            Arrays.equals(kDecrypt, Arrays.copyOfRange(longK, 0, KLEN)), "compare", "KDF 是前缀流");
        log.info("C1 = {} K = {}", Calc.hex(c1), Calc.hex(kDecrypt));
        Tracer.trace("end", new Object[]{"C1", c1, "K", kDecrypt}, null, "end");
    }

    /**
     * 测试③：完整 IBBE 往返，并把 C2/C3 的来历逐字节复算 ——
     * C2 只是 M ⊕ K 的前段，C3 只是对 C2 的 HMAC-SM3，密钥是 K 的尾部 32 字节。
     * <p><b>本条公式的新字母</b>
     * <pre>
     *   len    明文字节数 = MESSAGE.length = 20（C2 与明文<b>等长</b>，因为没有分组密码）
     *   K      KDF 吐出的 len+32 字节共享秘密，切成两段用：
     *            K_mask = K[0, len)      异或掩码，逐字节作用在明文上
     *            K_mac  = K[len, len+32) HMAC-SM3 的密钥，正好 32 字节
     *   C3     = HMAC-SM3(K_mac, C2)，32 字节；只对 C2 认证，不对 C1 认证（C1 错了 K 就全变，
     *          MAC 自然对不上，所以不需要单独把它算进消息里）
     *   密文    C1(65) ‖ C3(32) ‖ C2(len) = 65 + 32 + 20 = 117 字节
     * </pre>
     * <p><b>为什么要切成"掩码 + MAC 密钥"两段，而不是一段 K 两用</b>：同一段字节既当异或掩码又当
     * HMAC 密钥会破坏两者的独立性（HMAC 的密钥被密文关系间接暴露）。标准用 KDF 计数器流一次取
     * len+32 字节，天然把两个用途分到互不重叠的字节上。
     * <p><b>四类拒绝各自拦在哪</b>（对应下面四段篡改对照，每段都只改一处）：
     * <pre>
     *   改 C2 的 1 bit   HMAC 先炸 → 抛"C3 校验失败"；若没有 C3，异或会让明文跟着翻同一位
     *   改 C3            MAC 直接对不上 → 抛
     *   换收件人 ID      KDF 输入里的 ID 变了<b>且</b> de 变了 ⇒ K 完全不同段 ⇒ MAC 对不上 → 抛
     *   C1 不在曲线上    B1 的群成员检查拦住 → 抛（根本不进配对）
     * </pre>
     * 这四条合起来就是"C2、C3、C1、ID 任一被改都无法骗出明文"，即密文完整性/抗篡改的最低要求；
     * 真实实现还要把这些拒绝的<b>错误信息与耗时统一</b>，否则"抛哪种异常"本身又是一个 oracle
     * （本测试的 decryptThrows 只看"有没有抛"，把消息文本丢了，就是为了不把这点差异当成安全证明）。
     */
    @TraceExecution(value = "SM9 密文就是异或加 K 尾部的 HMAC", algorithm = "SM9", flow = "SM9-ENCRYPT")
    @Test
    public void ciphertextIsJustXorPlusHmacOverTheTailOfK()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"id", "Bob", "message", MESSAGE, "r", R}, null, "start");

        byte[] ct = Sm9Math.encrypt(HEX_KE, ID_BOB, MESSAGE, R);
        // 布局：C1 定长 65（含 0x04 前缀）、C3 定长 32（HMAC-SM3 的输出）、C2 与明文等长
        Assert.assertEquals(65 + 32 + MESSAGE.length, ct.length);
        byte[] c1 = Arrays.copyOfRange(ct, 0, 65);
        byte[] c3 = Arrays.copyOfRange(ct, 65, 97);
        byte[] c2 = Arrays.copyOfRange(ct, 97, ct.length);

        // 解密侧独立复算 K（长度 = 明文 + 32）
        byte[] k = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, MESSAGE.length + 32, c1);
        Tracer.trace("kemDecrypt.K", new Object[]{"ke", HEX_KE, "id", "Bob", "klen", MESSAGE.length + 32, "C1", c1},
            k, "kdf");
        Assert.assertArrayEquals("C2 = M ⊕ K[0..len)",
            Calc.xor(Arrays.copyOfRange(k, 0, MESSAGE.length), MESSAGE), c2);
        Tracer.trace("xor.C2", new Object[]{"K_mask", Arrays.copyOfRange(k, 0, MESSAGE.length), "M", MESSAGE}, c2, "c2");
        Assert.assertArrayEquals("C3 = HMAC-SM3(K[len..len+32], C2)",
            Sm9Math.hmacSm3(Arrays.copyOfRange(k, MESSAGE.length, k.length), c2), c3);
        Tracer.trace("hmacSm3.C3", new Object[]{"K_mac", Arrays.copyOfRange(k, MESSAGE.length, k.length), "C2", c2},
            c3, "c3");

        // 正常路径
        Assert.assertArrayEquals(MESSAGE, Sm9Math.decrypt(HEX_KE, ID_BOB, c1, c2, c3));
        Tracer.traceDecision("compare.roundtrip", new Object[]{"M", MESSAGE, "decrypted",
                Sm9Math.decrypt(HEX_KE, ID_BOB, c1, c2, c3)},
            Arrays.equals(MESSAGE, Sm9Math.decrypt(HEX_KE, ID_BOB, c1, c2, c3)),
            "compare", "decrypt(encrypt(M)) == M");

        // 改 C2 的一个字节：异或会跟着翻一位（M' = M ⊕ 0x01），但 HMAC 先拦下它
        // 这一条就是"没有 MAC 的 SM9 加密 = 完全可延展 (malleable)"的反面教材：
        // 掩码方案本身对逐字节篡改毫无抵抗，全靠 C3。
        byte[] tamperedC2 = c2.clone();
        tamperedC2[0] ^= 0x01;
        Assert.assertTrue("C2 被改必须抛异常", decryptThrows(HEX_KE, ID_BOB, c1, tamperedC2, c3));
        Tracer.traceDecision("compare.rejectC2", new Object[]{"tamperedC2", tamperedC2, "C3", c3},
            decryptThrows(HEX_KE, ID_BOB, c1, tamperedC2, c3), "compare", "改 C2 必须被 C3 拦下");

        // 改 C3：MAC 直接对不上
        byte[] tamperedC3 = c3.clone();
        tamperedC3[31] ^= 0x01;
        Assert.assertTrue("C3 被改必须抛异常", decryptThrows(HEX_KE, ID_BOB, c1, c2, tamperedC3));
        Tracer.traceDecision("compare.rejectC3", new Object[]{"C2", c2, "tamperedC3", tamperedC3},
            decryptThrows(HEX_KE, ID_BOB, c1, c2, tamperedC3), "compare", "改 C3 必须被拒绝");

        // 换收件人：标识是公钥的一部分，拿 Alice 的私钥解 Bob 的密文只会 MAC 失败
        // （注意 KDF 的种子末尾也拼了 ID，所以"ID 用错"在两处同时改变 K：de 与 Z。）
        Assert.assertTrue("标识不符必须拒绝", decryptThrows(HEX_KE, ID_ALICE, c1, c2, c3));
        Tracer.traceDecision("compare.rejectId", new Object[]{"id", "Alice", "C1", c1, "C2", c2, "C3", c3},
            decryptThrows(HEX_KE, ID_ALICE, c1, c2, c3), "compare", "换收件人标识必须被拒绝");

        // C1 不在曲线上（比如被人塞了个乱点）也要被拒绝：这是 GmSSL B1 步的群成员检查
        byte[] bogusC1 = Sm9Math.pointToOctets(Sm9Math.pointAdd(Sm9Math.pointFromOctets(c1), Sm9Math.P1));
        bogusC1[40] ^= 0x01;   // 破坏 y，得到一个不在曲线上的"点"
        // 下标 40 落在 y 区间（C1 = 0x04 ‖ x[1..33) ‖ y[33..65)），改它不影响 x，
        // 于是这个"点"能顺利通过 pointFromOctets 的长度/前缀检查，只被 pointIsOnCurve 挡下。
        Assert.assertTrue("C1 不在 G₁ 上必须拒绝", decryptThrows(HEX_KE, ID_BOB, bogusC1, c2, c3));
        Tracer.traceDecision("compare.rejectC1", new Object[]{"bogusC1", bogusC1, "onCurve", Sm9Math.pointIsOnCurve(Sm9Math.pointFromOctets(bogusC1))},
            decryptThrows(HEX_KE, ID_BOB, bogusC1, c2, c3), "compare", "C1 不在 G₁ 上必须被拒绝");
        log.info("密文 {} 字节 = C1(65) ‖ C3(32) ‖ C2({})", ct.length, MESSAGE.length);
        Tracer.trace("end", new Object[]{"ciphertext", ct, "len", ct.length}, null, "end");
    }

    /**
     * 测试④：密文的 DER 结构对齐 GmSSL 的 sm9_ciphertext_to_der：
     * {@code SEQUENCE { INTEGER 0 (XOR 模式), BIT STRING C1(65), OCTET STRING C3(32), OCTET STRING C2 }}。
     * 注意顺序是 C1、C3、C2 —— 标准的 ASN.1 布局把 MAC 放在明文前面。
     * <p><b>本条公式的新字母</b>
     * <pre>
     *   DER / TLV   确定性编码规则 (Distinguished Encoding Rules)；每段都是 Tag ‖ Length ‖ Value
     *   0x30        SEQUENCE（有序容器）　0x02 INTEGER　0x04 OCTET STRING　0x03 BIT STRING
     *   type = 0    "用异或掩码加密"这个算法标识（GmSSL 的 SM9_ENCRYPT_TYPE_XOR）；
     *               标准还预留了 SM4 模式（GmSSL 里是 1），本实现只做异或，所以恒为 0
     *   pad byte    BIT STRING 的 Value 第一字节 = 末尾未用到的 bit 数；65 字节是整字节 ⇒ 必为 0
     * </pre>
     * <p>为什么 C1 用 BIT STRING 而 C2/C3 用 OCTET STRING：C1 是<b>群里的点</b>，标准按位串对待
     * （保住 0x04 前缀的语义）；C2/C3 是纯字节数据。INTEGER 0 编码成 {@code 02 01 00} 三字节
     * —— DER 要求最短形式，值 0 也必须留一个 0x00 字节（不能写成空内容）。
     * <p>整包大小可以直接数出来（本例 len(M) = 20）：
     * <pre>
     *   INTEGER 0        = 1 + 1 + 1                = 3
     *   BIT STRING C1    = 1 + 1 + 1(pad) + 65      = 68
     *   OCTET STRING C3  = 1 + 1 + 32               = 34
     *   OCTET STRING C2  = 1 + 1 + 20               = 22
     *   SEQUENCE         = 1 + 1 + 127              = 129   ← 内层总长 127 仍小于 128，Length 只占 1 字节
     * </pre>
     * 明文一旦长到让内层总长度 ≥ 128，Length 就要改成"0x81 + 1 字节"的两字节形式（DER 的
     * 长长度标记），整包字节数会比上面多 1 —— 这也是为什么 log 里那行数字值得看一眼。
     */
    @TraceExecution(value = "SM9 密文 DER：type=0、C1、C3、C2", algorithm = "SM9", flow = "SM9-ENCRYPT")
    @Test
    public void ciphertextDerKeepsTypeZeroC1C3ThenC2()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"id", "Bob", "message", MESSAGE, "r", R}, null, "start");

        byte[] ct = Sm9Math.encrypt(HEX_KE, ID_BOB, MESSAGE, R);
        // 先按"扁平布局"切出三段（C1 65 ‖ C3 32 ‖ C2 余下），再重新装进 ASN.1 结构
        byte[] c1 = Arrays.copyOfRange(ct, 0, 65);
        byte[] c3 = Arrays.copyOfRange(ct, 65, 97);
        byte[] c2 = Arrays.copyOfRange(ct, 97, ct.length);
        Tracer.trace("encrypt.split", new Object[]{"ciphertext", ct}, new Object[]{"C1", c1, "C3", c3, "C2", c2}, "c2");

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(0));
        vector.add(new DERBitString(c1));
        vector.add(new DEROctetString(c3));
        vector.add(new DEROctetString(c2));
        byte[] der = new DERSequence(vector).getEncoded();
        Tracer.trace("DERSequence.encode", new Object[]{"type", 0, "C1", c1, "C3", c3, "C2", c2}, der, "c3");

        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        Assert.assertEquals(4, parsed.size());
        Tracer.traceDecision("compare.fieldCount", new Object[]{"size", parsed.size()}, parsed.size() == 4,
            "compare", "SEQUENCE 含 4 个元素");
        // type 段：只检查"值是 0"（signum()==0），因为 INTEGER 的字节宽度属于编码细节
        Assert.assertEquals(0, ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue().signum());
        Tracer.traceDecision("compare.type", new Object[]{"type", ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue()},
            ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue().signum() == 0,
            "compare", "type == 0（XOR 模式）");
        byte[] parsedC1 = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        Assert.assertArrayEquals(c1, parsedC1);
        Assert.assertEquals(65, parsedC1.length);
        // 0x04 未压缩点前缀必须活着：BIT STRING 不做"去掉前导零"这类数值化约，
        // 所以取回来还是原样 65 字节，交给 pointFromOctets 时第一关就是认这个前缀。
        Assert.assertEquals(0x04, parsedC1[0] & 0xff);
        Tracer.traceDecision("compare.c1", new Object[]{"parsedC1", parsedC1, "C1", c1, "len", parsedC1.length,
                "prefix", parsedC1[0] & 0xff},
            Arrays.equals(c1, parsedC1) && parsedC1.length == 65 && (parsedC1[0] & 0xff) == 0x04,
            "compare", "BIT STRING C1 一致且保留 0x04 前缀");
        Assert.assertArrayEquals(c3, ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets());
        Tracer.traceDecision("compare.c3", new Object[]{"parsedC3", ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets(),
                "C3", c3}, Arrays.equals(c3, ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets()),
            "compare", "OCTET STRING C3 一致");
        Assert.assertArrayEquals(c2, ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets());
        Tracer.traceDecision("compare.c2", new Object[]{"parsedC2", ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets(),
                "C2", c2}, Arrays.equals(c2, ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets()),
            "compare", "OCTET STRING C2 一致");
        log.info("SM9 密文 DER {} 字节", der.length);
        Tracer.trace("end", new Object[]{"der", der, "derLen", der.length}, null, "end");
    }

    /** 全零判定（GmSSL 用 mem_is_zero 挡下 KDF 退化）。
     *  K 全零时 C2 = M ⊕ 0 = M，等于把明文原样发出去，所以标准要求检测并重采 r；
     *  本测试没有重采机制，就用这个助手确认"这一次没退化到那种灾难"。 */
    private static boolean isAllZero(byte[] buf)
    {
        for (int i = 0; i < buf.length; i++)
        {
            if (buf[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /** 期望解密抛 IllegalArgumentException（C3 校验或群成员检查失败），返回"有没有抛"。
     *  写成"返回布尔"而不是让测试直接期望异常，是因为这里 <b>不关心异常消息</b>：
     *  "C1 不在 G₁ 上"和"C3 校验失败"是两种不同的内部拒绝原因，测试只断言"绝不吐明文"。
     *  如果哪天解密把别的异常（比如空指针、数组越界）也抛出来，本助手会放行 —— 那是
     *  "拒绝方式不对"的信号，值得留意但不是这几条断言要覆盖的东西。 */
    private static boolean decryptThrows(BigInteger ke, byte[] id, byte[] c1, byte[] c2, byte[] c3)
    {
        try
        {
            Sm9Math.decrypt(ke, id, c1, c2, c3);
            return false;
        }
        catch (IllegalArgumentException e)
        {
            log.info("按预期拒绝：{}", e.getMessage());
            return true;
        }
    }
}
