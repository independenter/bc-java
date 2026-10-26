package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
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
 * SM9 签名（GB/T 32915.2）的本质计算 —— 面向过程版。
 *
 * <p><b>符号表 —— 本文件每条公式里的字母/记号</b>
 * <pre>
 *   KGC         密钥生成中心 (Key Generation Center)：唯一知道 ks 的一方，负责"私钥提取"
 *   ks          签名主私钥 (master private key)，Z_n 里的标量（[1, n−1] 的随机数）
 *   Ppubs       签名主公钥 = ks·P2 ∈ G₂，序列化成 129 字节；全网公开
 *   ID          签名者 (signer) 的标识字节串："Alice" = 41 6C 69 63 65（5 字节）、"Bob" = 42 6F 62（3 字节）
 *   hid         用途分隔符：签名固定 0x01（Sm9Math.HID_SIGN）；0x02 交换、0x03 加密
 *   H1(ID,hid)  把任意字符串折成 Z_n* 里的数：SM3(0x01‖ID‖hid‖00000001) ‖ SM3(0x01‖ID‖hid‖00000002)
 *               共 64 字节，取前 40 字节当整数 z，返回 z mod (n−1) + 1 ⇒ 值域 [1, n−1]（永远不会是 0）
 *   H2(M‖w)     同一条套路、前缀换成 0x02，把消息与 384 字节的 w 拼进摘要，再走 mod (n−1) + 1
 *   M           消息原文（本文件是 "Chinese IBS standard"，20 字节，不预哈希、直接进 H2）
 *   r           签名的临时随机数 (nonce / 一次性随机标量)，Z_n 里取，一条签名用一次，绝不能复用
 *   ds          签名用户私钥 = ks·(ks + H1(ID,0x01))⁻¹·P1 ∈ G₁（65 字节的点，签名方唯一持有的秘密）
 *   S           签名里的点 = l·ds ∈ G₁（65 字节）
 *   P1, P2      两条曲线的生成元；n 是它们的公共阶（256-bit 素数）
 *   e(P, Q)     双线性配对 G₁ × G₂ → GT；Java 侧实参顺序是 pairing(Q, P)，读作 e(P, Q)
 *   GT          Fp12* 的 n 阶子群，元素展平 384 字节 —— 本文件里 g、w、u、t 全是 GT 元素
 *   g           系统参数 g = e(P1, Ppubs) = e(P1, P2)^{ks} ∈ GT（对全体用户相同，可预先算好）
 *   w           签名中间量 = g^r ∈ GT（384 字节，就是 H2 里接在 M 后面那串）
 *   h           哈希挑战值 (challenge) = H2(M‖w)，Z_n 里的数，写进签名时定长 32 字节
 *   l           = (r − h) mod n，Z_n 里的数；S = l·ds
 *   P′          验签方拼出来的点 = H1(ID,0x01)·P2 + Ppubs = (H1 + ks)·P2 ∈ G₂
 *   u, t        验签中间量：u = e(S, P′) ∈ GT、t = g^h ∈ GT；w = u·t
 *   ⁻¹ mod n    Z_n 里的模逆（扩展欧几里得）；"−"、"·" 都在 Z_n 里做，见 modnSub/modnMul
 *   ·           椭圆曲线的标量乘（整数 × 点）或域/群里的普通乘法，按左右操作数类型区分
 *   +           群加法（点在曲线上作图相加），不是坐标逐分量相加
 *   ‖           字节串拼接（concatenate），不是异或
 *   ≡           同余：a ≡ b (mod n) 表示 n | (a − b)
 * </pre>
 *
 * <p>整套协议只有 5 行公式，配对是唯一的新东西（{@link Sm9Math#pairing}，已由
 * {@link Sm9PairingEssenceTest} 用 GmSSL 的三组 384 字节样例验过）：
 * <pre>
 *   主公钥  Ppubs = ks·P2 ∈ G₂            主私钥 ks 只在 KGC 手里
 *   私钥    ds = ks·(ks + H1(ID,0x01))⁻¹·P1 ∈ G₁   ← 标识 ID 进了分母，这就是"基于标识"
 *   签名    g = e(P1,Ppubs);  w = g^r;  h = H2(M‖w);  l = (r−h) mod n;  S = l·ds
 *   验签    P' = H1(ID,0x01)·P2 + Ppubs;  u = e(S,P');  t = g^h;  w = u·t;  核对 h == H2(M‖w)
 * </pre>
 * <p><b>标准里的步骤号（A1~A4 是签名、B1~B5 是验签）与每一步的含义</b>
 * <pre>
 *   A1  r ← Z_n          取一次性随机标量 (nonce) r ∈ [1, n−1]；r 只活在这一次签名里
 *   A2  g = e(P1,Ppubs)  系统常数，∈ GT（384 字节）。它等于 e(P1,P2)^{ks}：谁都能算，
 *                        因为 Ppubs 是公开的 —— 知道 ks 并不是算 g 的前提
 *   A3  w = g^r          GT 里的普通幂（fp12Pow），得到 384 字节的 w；
 *       h = H2(M‖w)      把消息与 w 拼起来折成 Z_n 里的挑战值 (challenge) h，32 字节大端写进签名
 *   A4  l = (r−h) mod n；S = l·ds
 *                        签名值 = h(32 字节) ‖ S(65 字节 = 0x04‖x‖y)，共 97 字节
 *                        若 l ≡ 0 (mod n)（概率约 2⁻²⁵⁶）则 S 会是无穷远点、这一式子也解不出
 *                        ds，标准规定回到 A2 重采 r —— Sm9Math.sign 里直接抛异常那一段
 *   B1  h1 = H1(ID,0x01)；P′ = h1·P2 + Ppubs
 *                        把标识"补回成私钥的分母"，得 G₂ 的点 P′ = (h1 + ks)·P2
 *   B2  u = e(S, P′)     签名点 S ∈ G₁ 配 P′ ∈ G₂ ⇒ u ∈ GT
 *   B3  t = g^h；w = u·t 把 h 那一格补回去，还原签名方当年算的那个 w
 *   B4  合法性检查        h ∈ [1, n−1] 且 S 真的是 G₁ 上的点（Sm9Math.verify 里直接 return false 那段）
 *   B5  核对 H2(M‖w) == h  只有同一条 w 才给出同一个 h —— 这一步才是"验过"的定义
 * </pre>
 * <p><b>为什么同一个主密钥要按用途导出不同私钥（hid 的作用）</b>：签名、密钥交换、加密三个协议
 * 的私钥公式形状完全一样，只有 H1 的第二个参数不同（0x01 / 0x02 / 0x03）。如果去掉 hid，
 * 同一个 ID 在三个用途里就是同一个标量分母、同一个私钥点，于是一条签名里泄露的信息可以立刻搬到
 * 解密或交换的应答里去用（协议之间的"密钥隔离"消失，交叉攻击面陡增）。加上 hid 之后，
 * H1(ID,0x01) ≠ H1(ID,0x02) ≠ H1(ID,0x03)，三把私钥点在群里彼此无关；代价只是哈希输入多一个字节。
 * 这也解释了"验签为什么只需要 ID"：P′ = H1(ID,0x01)·P2 + Ppubs 完全由公开量拼出来，
 * 不需要证书、不需要查任何目录 —— 标识本身（拼错一个字母就验不过）就是公钥。
 *
 * <p><b>验签为什么成立</b>（本文件用断言把这条推导逐字节跑出来）：
 * <pre>
 *   u = e(l·ds, H1·P2 + ks·P2)
 *     = e( l·ks/(ks+H1)·P1 , (H1+ks)·P2 )
 *     = e(P1,P2)^{ l·ks/(ks+H1) · (H1+ks) }      ← 双线性把两个标量提到指数上
 *     = e(P1,P2)^{ l·ks } = g^l
 *   w = u·t = g^l · g^h = g^{l+h} = g^r           ← l = r−h，除法在指数里被完全抵消
 * </pre>
 * 逐字母读这条推导：l = (r − h) mod n（签名方的标量）、ds 是私钥点、H1 = H1(ID,0x01)、
 * ks/(ks+H1) 应读成 Z_n 里的 ks·(ks+H1)⁻¹、g = e(P1,Ppubs) = e(P1,P2)^{ks}。
 * 第三步"把两个标量直接相乘搬到指数上"的依据就是双线性：e(a·P, b·Q) = e(P,Q)^{ab}
 * 对<b>两个变量分别</b>成立；指数在 Z_n 里算，于是 (ks+H1)⁻¹·(ks+H1) ≡ 1 (mod n)，
 * 私钥里那个刺眼的除法干净抵消，只剩下 ks —— 这正是"验签不需要主私钥"的数学原因。
 * 最后一步 w = u·t 用的是 GT 里的乘法（同指数的幂相加：g^l·g^h = g^{l+h}），
 * 而 l + h = (r − h) + h = r (mod n)，所以两边算出的 w 必然同一段 384 字节。
 * 所以验签方拿不到 ks 也算不出 ds（那需要解 e(P1,P2) 上的离散对数），但两边算出的 w 必然同一。
 *
 * <p>文件后半部分是<b>"r 一旦重用，私钥就当场掉出来"</b>：签名式子 S = (r−h)·ds 对 ds 是
 * 一次方程，两个用同一个 r 的签名相减就把 r 消掉了 —— 与 SM2 那套 k 重用攻击同构，
 * 只是这里解出来的是<b>点</b> ds 本身（在标识密码里，拿到这个点就等于能签名）。
 *
 * <p><b>正常情形下伪造为什么算不动</b>：伪造者只有 Ppubs 与公开的 g，要凑出一对 (h, S) 使得
 * e(S, P′)·g^h = g^r 且 h = H2(M‖g^r)。把 S 写成 l·ds 就需要知道 ds（否则要由 Ppubs = ks·P2 与
 * g = e(P1,P2)^{ks} 反解 ks·P1，即解 CDHP/离散对数）。256-bit 的 SM9 群对应的离散对数代价约 2¹²⁸，
 * 也就是标准宣称的<b>约 128 bit 安全强度</b>（256-bit 素数阶群，Pollard rho 的开方级别）。
 * "伪造不出来"还依赖把 H2 当成<b>随机 oracle (random oracle)</b>：这套 (r → w → h → l) 的形状
 * 就是一次 <b>Fiat–Shamir 变换</b> —— 先把承诺 (commitment) w 交给哈希、拿到挑战 h、再回答 l，
 * 于是把"交互式证明"变成"非交互签名"。
 *
 * <p><b>本文件的 KAT（known-answer test，已知答案测试）出处</b>：ID = "Alice"、消息 =
 * "Chinese IBS standard"、ks = hex_ks、ds = hex_ds 全部取自 GmSSL 的 {@code tests/sm9test.c}
 * （GB/T 32915 附录 A 的示例值）。只有随机数 r 是这里额外固定的：GmSSL 现采一个 r，
 * 所以标准文档里没有 h 与 S 的样例，测试②③④⑤ 用同一个 r 把 w、h、S 全钉成确定值，
 * 才能逐字节复算。
 */
@Slf4j
public class Sm9SignEssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /** GmSSL tests/sm9test.c 的签名样例：ID = "Alice"，消息 = "Chinese IBS standard"。 */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    /** 只在"换标识就验不过"的对照里出现：标识密码没有目录可查，读错三个字母 = 换了一把公钥。 */
    private static final byte[] ID_BOB = "Bob".getBytes();
    /** 消息原文 20 字节；SM9 签名<b>不预哈希</b>，整段直接进 H2(M‖w)。 */
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();
    /** 签名主私钥 ks（GmSSL: hex_ks），255 bit 的标量；实际部署里它只存在于 KGC 内部。 */
    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);

    /** 标准答案 ds = ks/(ks+H1(Alice,0x01))·P1（GmSSL: hex_ds，两行 = x、y）。 */
    private static final String HEX_DS =
        "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
            + "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3";

    /** 签名的随机数 r。GmSSL 用 sm9_z256_rand_range 现采，这里固定下来好让 h、S 能逐字节复算。 */
    private static final BigInteger R = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
    /** 第二个 r，专门用来证明"换 nonce 只换签名值、不换安全性"（测试④）与测试⑤的同 r 对照。 */
    private static final BigInteger R_OTHER = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);

    /**
     * 测试①：私钥提取对上 GmSSL 的已知答案，并且把 H1 的"取前 40 字节、模 n−1 再加 1"
     * 这套细节独立复算一遍 —— 少一个字节、多一个 1，ds 就不是标准里那个点。
     */
    @TraceExecution(value = "SM9 签名私钥提取与 H1 范围校验", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void privateKeyExtractMatchesGmsslAnswerAndHash1StaysInRange()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"id", "Alice", "message", MESSAGE, "ks_bits", HEX_KS.bitLength()}, null, "start");

        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);
        Tracer.trace("signPrivateKeyExtract", new Object[]{"ks", HEX_KS, "id", "Alice", "hid", Sm9Math.HID_SIGN},
            Sm9Math.pointToOctets(ds), "keygen");

        // 已知答案：ds 的 0x04‖x‖y 编码必须与 hex_ds 逐字符相同。
        // HEX_DS 抄自 GmSSL，只有 x(32)‖y(32) = 128 个 hex 字符，所以这里手工补上未压缩点前缀 "04"，
        // 与 pointToOctets 的输出（同样是 0x04‖x‖y = 65 字节）对齐；转大写只是大小写排版差异。
        Assert.assertEquals("04" + HEX_DS, Calc.hex(Sm9Math.pointToOctets(ds)).toUpperCase());
        // 在 E(Fp) 上：Y²Z ≡ X³ + b·Z³ (mod p)。这是"这个点真的是群成员"的判据。
        Assert.assertTrue("ds 必须在 E(Fp) 上", Sm9Math.pointIsOnCurve(ds));
        // 阶为 n：n·ds 必须回到无穷远点；本实现用长度为 0 的数组表示无穷远点，所以比 length。
        // G₁ 的阶是素数 n，非无穷远点的倍数只可能是 0 或 n ⇒ 这条断言同时确认了"它在 G₁ 里"。
        Assert.assertEquals("n·ds 必须是无穷远点", 0, Sm9Math.pointMul(Sm9Math.N, ds).length);
        Tracer.traceDecision("checkDs", new Object[]{"ds", Sm9Math.pointToOctets(ds), "onCurve", Sm9Math.pointIsOnCurve(ds),
                "n_ds_length", Sm9Math.pointMul(Sm9Math.N, ds).length},
            Sm9Math.pointIsOnCurve(ds) && Sm9Math.pointMul(Sm9Math.N, ds).length == 0,
            "keygen", "ds ∈ G₁ 且 n·ds = O");

        // 手工复算 H1(Alice, 0x01)：SM3(0x01‖ID‖hid‖1) ‖ SM3(0x01‖ID‖hid‖2) = 64 字节。
        // 四个拼件各有身份：0x01 是"H1 专用前缀"（H2 用 0x02，见测试②），作用是让同一批字节
        // 在两个哈希里落到不同的输入域；结尾 4 字节是大端计数器 1、2，因为 SM3 只出 32 字节、
        // 而这里需要 40 字节的有效位宽 —— 与 KDF 的计数器模式 (counter mode) 是同一个套路。
        byte[] head = Calc.concat(new byte[]{ 0x01 }, ID_ALICE, new byte[]{ (byte) Sm9Math.HID_SIGN });
        byte[] ha = Calc.concat(
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 })));
        // 只用前 40 字节（320 bit）当整数；对 n−1 取模后 +1，值域落在 [1, n−1]。
        // 取 40 字节是为了让"模 n−1 的偏斜 (bias)"小到可以忽略（2^320 相对 2^256 的模数）。
        BigInteger z = Calc.toBigInt(Arrays.copyOfRange(ha, 0, 40));
        BigInteger expected = z.mod(Sm9Math.N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        Tracer.trace("hash1.manual", new Object[]{"prefix", 0x01, "id", "Alice", "hid", Sm9Math.HID_SIGN,
            "material", ha}, Calc.hex(ha), "hash1");
        Tracer.trace("hash1.modN", new Object[]{"z", z, "n_minus_1", Sm9Math.N.subtract(BigInteger.ONE)}, expected, "hash1");
        Assert.assertEquals(expected, Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN));
        Assert.assertTrue("H1 必须 >= 1", Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN).compareTo(BigInteger.ONE) >= 0);
        Assert.assertTrue("H1 必须 <= n−1", Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN).compareTo(Sm9Math.N) < 0);

        // 那个 "+1" 不是装饰：H1 = 0 会让 P' = Ppubs，签名式里的除法也会失控。
        // hid 存在的全部理由：同一个主密钥、同一个标识，三个用途导出三把不同的私钥。
        //（H1(ID,0x01) ≠ H1(ID,0x02) ≠ H1(ID,0x03)，下面三行就是把这句话跑成断言。）
        BigInteger h1 = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN);
        BigInteger h1x = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_EXCH);
        BigInteger h1e = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_ENC);
        Assert.assertFalse(h1.equals(h1x));
        Assert.assertFalse(h1.equals(h1e));
        Assert.assertFalse(h1x.equals(h1e));
        // 标识不同 => H1 不同 => 私钥不同（"公钥就是那串字节"的代价是标识一字不能错）
        Assert.assertFalse(h1.equals(Sm9Math.hash1(ID_BOB, Sm9Math.HID_SIGN)));
        Tracer.traceDecision("hidIsolation", new Object[]{"h1_sign", h1, "h1_exch", h1x, "h1_enc", h1e},
            !h1.equals(h1x) && !h1.equals(h1e) && !h1x.equals(h1e), "compare",
            "H1(ID,0x01) / H1(ID,0x02) / H1(ID,0x03) 两两不同");
        Tracer.traceDecision("idIsolation", new Object[]{"alice", h1, "bob", Sm9Math.hash1(ID_BOB, Sm9Math.HID_SIGN)},
            !h1.equals(Sm9Math.hash1(ID_BOB, Sm9Math.HID_SIGN)), "compare", "H1(Alice) != H1(Bob)");
        log.info("ds = {}", Calc.hex(Sm9Math.pointToOctets(ds)));
        Tracer.trace("end", new Object[]{"ds", Calc.hex(Sm9Math.pointToOctets(ds))}, null, "end");
    }

    /**
     * 测试②：把"验签为什么成立"写成断言 —— 签名侧的 w = g^r 与验签侧的 w = e(S,P')·g^h
     * 必须是<b>同一段 384 字节</b>，并且 S 确实等于 (r−h)·ds。
     */
    @TraceExecution(value = "SM9 签名与验签算出同一个 w", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void signerAndVerifierComputeTheSame384ByteW()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"message", MESSAGE, "id", "Alice", "r", R}, null, "start");

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        Tracer.trace("sign", new Object[]{"ks", HEX_KS, "message", MESSAGE, "id", "Alice", "r", R},
            signature, "genK");

        Assert.assertEquals("签名 = h(32) ‖ S(65)", 97, signature.length);
        // 签名值的两半：h 是大端 32 字节（不足 32 字节时前面补 0，标准规定定长），
        // 后 65 字节是 S 的 0x04‖x‖y 未压缩编码 —— 与 G₁ 里任何点同一种写法。
        BigInteger h = Calc.toBigInt(Arrays.copyOfRange(signature, 0, 32));
        BigInteger[] sPoint = Sm9Math.pointFromOctets(Arrays.copyOfRange(signature, 32, 97));
        Tracer.trace("parseSignature", new Object[]{"signature", signature},
            new Object[]{"h", Calc.hex(Calc.toBytes(h, 32)), "S", sPoint}, "genK");

        // S = l·ds, l = (r − h) mod n —— 从签名反推回私钥的标量乘
        // 这一步只是"照抄 A4"，但它同时说明：S 里除了 ds 没有任何秘密，公开可核。
        BigInteger l = Sm9Math.modnSub(R, h);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(sPoint)),
            Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(l, ds))));
        Tracer.trace("pointMul(l,ds)", new Object[]{"l", l, "ds", Sm9Math.pointToOctets(ds)},
            Sm9Math.pointToOctets(Sm9Math.pointMul(l, ds)), "pointMul");

        // g = e(P1, Ppubs)：A2 的系统常数，384 字节，与用户无关，可预先算好缓存
        BigInteger[] g = Sm9Math.pairing(ppubs, Sm9Math.P1);
        Tracer.trace("pairing.g", new Object[]{"Ppubs", ppubs, "P1", Sm9Math.P1}, g, "pointMul");

        // 路线一（签名方）：w = g^r
        byte[] wSigner = Sm9Math.fp12ToBytes(Sm9Math.fp12Pow(g, R));
        Tracer.trace("fp12Pow.wSigner", new Object[]{"g", g, "r", R}, wSigner, "pointMul");
        // 路线二（验签方，手里只有 h、S、Ppubs）：w = e(S, H1·P2 + Ppubs) · g^h
        // P′ = H1·P2 + Ppubs 是 B1：两个 G₂ 点相加（twistMul 先做标量乘，twistAffineAdd 再作图加），
        // 它等于 (H1 + ks)·P2 —— 正好是私钥分母 (ks + H1) 出现在 G₂ 那一侧的镜像。
        BigInteger[][] pPrime = Sm9Math.twistAffineAdd(
            Sm9Math.twistMul(Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN), Sm9Math.P2), ppubs);
        Tracer.trace("twistAffineAdd.Pprime", new Object[]{"h1", Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN),
            "P2", Sm9Math.P2, "Ppubs", ppubs}, pPrime, "pointMul");
        byte[] wVerifier = Sm9Math.fp12ToBytes(
            Sm9Math.fp12Mul(Sm9Math.pairing(pPrime, sPoint), Sm9Math.fp12Pow(g, h)));

        Assert.assertEquals("两条路线必须给出同一个 384 字节的 w",
            Calc.hex(wSigner), Calc.hex(wVerifier));
        // H2 只是"前缀 0x02 + 消息 + w + 计数器"再走两遍 SM3。GmSSL 的流式 API
        // （sm9_sign_init/update/finish）不过是把这段拼接拆成多次喂入，字节上完全等价。
        // 注意 w 是<b>整段 384 字节</b>进哈希，不是它的摘要或前缀 —— 少喂一点，h 就变了。
        byte[] head = Calc.concat(new byte[]{ 0x02 }, MESSAGE, wSigner);
        BigInteger hManual = Sm9Math.modnFromHash(Calc.concat(
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 }))));
        Tracer.trace("hash2.head", new Object[]{"prefix", 0x02, "message", MESSAGE, "w", wSigner}, head, "hash2");
        Tracer.trace("hash2.modN", new Object[]{"message", MESSAGE, "w", wSigner}, hManual, "hash2");
        Assert.assertEquals(hManual, h);
        // w 相同 => H2(M‖w) 相同 => 验签通过
        Assert.assertTrue(Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));
        Tracer.traceDecision("w.compare", new Object[]{"wSigner", wSigner, "wVerifier", wVerifier},
            Arrays.equals(wSigner, wVerifier), "compare", "签名侧 g^r == 验签侧 e(S,P')·g^h");
        Tracer.traceDecision("h.compare", new Object[]{"hManual", hManual, "h", h},
            hManual.equals(h), "compare", "H2(M‖w) == 签名里的 h");
        log.info("h = {}", Calc.hex(Calc.toBytes(h, 32)));
        Tracer.trace("end", new Object[]{"w", wSigner, "h", h}, null, "end");
    }

    /**
     * 测试③：四种篡改都必须被拒。每种都换成"仍然是合法群元素、但数值不对"的形式，
     * 这样断言只可能因为算法被拒，不会因为碰到无穷远点之类而偶然抛异常。
     * <pre>
     *   改什么            动了公式里的哪个量                 被哪一步拦下
     *   消息 M 的 1 bit    h = H2(M‖w) 的输入                 B5：重算的 H2(M‖w) ≠ 签名里的 h
     *   标识 ID → Bob      H1(ID,0x01) → P′ = (H1+ks)·P2      B1/B2：u = e(S,P′) 换点，w 就对不上
     *   签名点 S +P1       S = (l+1)·ds                       B2/B3：w = g^{l+1}·g^h = g^{r+1} ≠ 原来的 w
     *   h 的 1 bit         l = (r−h) 反推的期望值             B3：t = g^h 变了，w 拼不回原值
     * </pre>
     * <p>四种都落在同一道闸门上：<b>验签的成败只由 B5 那一次字节比较决定</b>（B4 的群成员检查
     * 只把"根本不在群里"的粗糙伪造挡掉，这里刻意不依赖它）。换句话说 SM9 验签的安全性不是
     * "多项检查堆出来的"，而是"一个 384 字节的 w 必须一字不差"—— 想改任何一项，就得重算 w，
     * 而重算 w 需要 g^r 的离散对数或私钥点 ds。
     */
    @TraceExecution(value = "SM9 验签拒绝篡改消息、错误标识与偏移签名", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void verifyRejectsChangedMessageWrongIdAndShiftedSignature()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"message", MESSAGE, "id", "Alice", "r", R}, null, "start");

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);

        Assert.assertTrue("原签名必须通过",
            Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));
        Tracer.traceDecision("verify.original", new Object[]{"message", MESSAGE, "id", "Alice", "signature", signature},
            Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs), "verify", "原签名必须通过");

        // 1) 消息改一个字节：H2 变，h 对不上
        byte[] tamperedMessage = MESSAGE.clone();
        tamperedMessage[tamperedMessage.length - 1] ^= 0x01;
        Assert.assertFalse(Sm9Math.verify(tamperedMessage, signature, ID_ALICE, ppubs));
        Tracer.traceDecision("verify.tamperedMessage", new Object[]{"message", tamperedMessage, "id", "Alice",
            "signature", signature}, Sm9Math.verify(tamperedMessage, signature, ID_ALICE, ppubs),
            "verify", "改消息后验签必须为 false");

        // 2) 标识换成 Bob：H1 变，P' 变 —— 标识密码里"读错公钥"就是这么贵
        Assert.assertFalse(Sm9Math.verify(MESSAGE, signature, ID_BOB, ppubs));
        Tracer.traceDecision("verify.wrongId", new Object[]{"message", MESSAGE, "id", "Bob", "signature", signature},
            Sm9Math.verify(MESSAGE, signature, ID_BOB, ppubs), "verify", "换标识后验签必须为 false");

        // 3) 签名点加一个 P1：S' = S + P1 = (l + 1)·ds 仍在 n 阶群里，但 w 变了
        // 切片的两个边界就是签名的布局：[0,32) 是 h，[32,97) 是 S 的 0x04‖x‖y。
        byte[] shiftedS = Sm9Math.pointToOctets(
            Sm9Math.pointAdd(Sm9Math.pointFromOctets(Arrays.copyOfRange(signature, 32, 97)), Sm9Math.P1));
        Assert.assertFalse(Sm9Math.verify(MESSAGE,
            Calc.concat(Arrays.copyOfRange(signature, 0, 32), shiftedS), ID_ALICE, ppubs));
        Tracer.traceDecision("verify.shiftedS", new Object[]{"message", MESSAGE, "id", "Alice", "S_shifted", shiftedS},
            Sm9Math.verify(MESSAGE, Calc.concat(Arrays.copyOfRange(signature, 0, 32), shiftedS), ID_ALICE, ppubs),
            "verify", "S 换成 S+P1 后验签必须为 false");

        // 4) h 的最后一位改掉：l 变，S 也跟不上
        // 只改 h 不改 S 时，验签方算出的仍是 g^l·g^{h'} = g^{r + (h' − h)} —— 除非 h' = h，w 追不回来。
        byte[] bumpedH = signature.clone();
        bumpedH[31] = (byte) (bumpedH[31] ^ 0x01);
        Assert.assertFalse(Sm9Math.verify(MESSAGE, bumpedH, ID_ALICE, ppubs));
        Tracer.traceDecision("verify.bumpedH", new Object[]{"message", MESSAGE, "id", "Alice", "signature_bumpedH", bumpedH},
            Sm9Math.verify(MESSAGE, bumpedH, ID_ALICE, ppubs), "verify", "h 改一位后验签必须为 false");
        Tracer.traceDecision("compare.tamperedLayout", new Object[]{"signatureLen", signature.length,
                "shiftedSLen", shiftedS.length, "bumpedHLen", bumpedH.length},
            signature.length == 97 && shiftedS.length == 65 && bumpedH.length == 97, "compare",
            "篡改后的签名仍是合法长度（拒绝来自算法而非解析）");
        Tracer.trace("end", new Object[]{"signature", signature, "rejected", 4}, null, "end");
    }

    /** 测试④：另一个 r 同样能签成 —— 顺带说明签名对 r 敏感（同一 r 同一消息则完全确定）。
     * <pre>
     *   输入只有 r 换了 ⇒ w = g^r 换 ⇒ h = H2(M‖w) 换 ⇒ l = (r−h) 换 ⇒ S = l·ds 换
     * </pre>
     * 链条上任一格变，签名值就整体变；反过来，只要 r 固定，SM9 签名是<b>确定性</b>的
     * （没有任何一步掺了额外的随机源），这就是本文件能把 h、S 逐字节钉死复算的前提。
     * 实际部署里 r 必须由 CSPRNG 现采，一条签名用一次 —— 测试⑤演示复用的后果。
     */
    @TraceExecution(value = "SM9 换 nonce 得到不同但有效的签名", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void anotherNonceProducesADifferentButValidSignature()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"message", MESSAGE, "id", "Alice", "r", R, "r_other", R_OTHER}, null, "start");

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        byte[] first = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] second = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R_OTHER);
        Tracer.trace("sign.r", new Object[]{"ks", HEX_KS, "message", MESSAGE, "id", "Alice", "r", R}, first, "genK");
        Tracer.trace("sign.rOther", new Object[]{"ks", HEX_KS, "message", MESSAGE, "id", "Alice", "r", R_OTHER},
            second, "genK");

        Assert.assertTrue(Sm9Math.verify(MESSAGE, second, ID_ALICE, ppubs));
        Tracer.traceDecision("hash2.diff", new Object[]{"h_first", Arrays.copyOfRange(first, 0, 32),
                "h_second", Arrays.copyOfRange(second, 0, 32)},
            !Arrays.equals(Arrays.copyOfRange(first, 0, 32), Arrays.copyOfRange(second, 0, 32)),
            "hash2", "r 不同 ⇒ w 不同 ⇒ H2(M‖w) 不同");
        Tracer.trace("computeS.S", new Object[]{"S_first", Arrays.copyOfRange(first, 32, 97),
            "S_second", Arrays.copyOfRange(second, 32, 97)}, Arrays.copyOfRange(second, 32, 97), "computeS");
        Tracer.traceDecision("verify.second", new Object[]{"message", MESSAGE, "id", "Alice", "signature", second},
            Sm9Math.verify(MESSAGE, second, ID_ALICE, ppubs), "verify", "换 r 后的签名仍然有效");
        Assert.assertFalse("r 不同则 w、h、S 全不同", Arrays.equals(first, second));
        Tracer.traceDecision("compare.fullSignature", new Object[]{"first", first, "second", second},
            !Arrays.equals(first, second), "compare", "两枚签名整体不同");
        // S = (r−h)·ds：换了 r，S 必然换点（同一 r、同一消息才谈得上"确定性"）
        // 单独比 S 这一段，是为了确认差异不是"只有 h 变了"—— 点也换了，即整条链都跟着 r 走。
        Assert.assertFalse(Arrays.equals(Arrays.copyOfRange(first, 32, 97),
            Arrays.copyOfRange(second, 32, 97)));
        Tracer.traceDecision("compare.signatureS", new Object[]{"first.S", Arrays.copyOfRange(first, 32, 97),
                "second.S", Arrays.copyOfRange(second, 32, 97)},
            !Arrays.equals(Arrays.copyOfRange(first, 32, 97), Arrays.copyOfRange(second, 32, 97)),
            "compare", "S 段也不同（不只是 h 变了）");
        Tracer.trace("end", new Object[]{"first", first, "second", second}, null, "end");
    }

    /**
     * 测试⑤：<b>r 重用 = 私钥泄露</b>，而且是"解一次一元一次方程"级别的泄露。
     * <pre>
     *   S₁ = (r − h₁)·ds,  S₂ = (r − h₂)·ds   （同一个 r、两个不同消息）
     *   S₁ − S₂ = (h₂ − h₁)·ds                ← r 被减掉了
     *   ds = (h₂ − h₁)⁻¹ · (S₁ − S₂)          ← 右边的逆只要 mod n 求一次
     * </pre>
     * 解出来的点应当与标准答案 hex_ds 一字不差 —— 拿到 ds 就能直接冒充 Alice 签名，
     * 因为签名全程只用 ds 做一次标量乘，从没要求谁"知道 ds 的离散对数"。
     */
    @TraceExecution(value = "SM9 重用 nonce 泄露私钥点", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void reusedRandomLeaksThePrivateKeyPoint()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"message1", MESSAGE, "id", "Alice", "r", R}, null, "start");

        byte[] otherMessage = "Chinese IBS standarD".getBytes();  // 只改最后一个字节
        byte[] sig1 = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] sig2 = Sm9Math.sign(otherMessage, ID_ALICE, HEX_KS, R);
        Tracer.trace("sign.reusedR", new Object[]{"ks", HEX_KS, "id", "Alice", "r", R,
            "message1", MESSAGE, "message2", otherMessage}, new Object[]{"sig1", sig1, "sig2", sig2}, "genK");

        // 下标 1/2 只是"两条签名"；两条都是 97 字节，切片方式与测试③相同（h 在前 32 字节）。
        // 消息只差 1 bit 却必须换 w = g^r ⇒ 换 h，这正是 H2 抗碰撞在这里扮演的角色。
        BigInteger h1 = Calc.toBigInt(Arrays.copyOfRange(sig1, 0, 32));
        BigInteger h2 = Calc.toBigInt(Arrays.copyOfRange(sig2, 0, 32));
        Assert.assertFalse("消息不同则 h 不同", h1.equals(h2));
        Tracer.traceDecision("computeS.hDiff", new Object[]{"h1", h1, "h2", h2}, !h1.equals(h2), "computeS",
            "两条签名共用 r，但 H2 挑战不同");

        BigInteger[] s1 = Sm9Math.pointFromOctets(Arrays.copyOfRange(sig1, 32, 97));
        BigInteger[] s2 = Sm9Math.pointFromOctets(Arrays.copyOfRange(sig2, 32, 97));
        // 减法在群里做：S₁ − S₂ = S₁ + (−S₂)，pointNeg 就是 (x, −y mod p)（竖直对称，仍是曲线上的点）
        BigInteger[] diff = Sm9Math.pointAdd(s1, Sm9Math.pointNeg(s2));
        BigInteger coefficient = Sm9Math.modnSub(h2, h1);          // = h₂ − h₁ ≡ l₁ − l₂ (mod n)
        // 系数为 0 意味着两条签名的 h 相同（等价于 H2 碰撞），那 (h₂−h₁)⁻¹ 不存在，攻击解不出来；
        // 对随机 oracle 来说这个概率可忽略，断言只是把它写成"这次真的能解"。
        Assert.assertTrue("系数为 0 就解不出来（等价于两条消息同哈希）", coefficient.signum() != 0);
        Tracer.trace("computeS.pointDiff", new Object[]{"S1", s1, "S2", s2}, diff, "computeS");
        Tracer.trace("computeS.coefficient", new Object[]{"h2", h2, "h1", h1}, coefficient, "computeS");

        // modnInv = 扩展欧几里得求模逆；点乘上它，就是"群里除以一个整数"。
        BigInteger[] recovered = Sm9Math.pointMul(Sm9Math.modnInv(coefficient), diff);
        Assert.assertEquals("04" + HEX_DS, Calc.hex(Sm9Math.pointToOctets(recovered)).toUpperCase());
        Tracer.trace("computeS.recoveredDs", new Object[]{"coefficient", coefficient, "S1_minus_S2", diff},
            Sm9Math.pointToOctets(recovered), "computeS");
        Tracer.traceDecision("compare.recoveredDs", new Object[]{"recovered", Sm9Math.pointToOctets(recovered),
                "expected", "04" + HEX_DS},
            ("04" + HEX_DS).equalsIgnoreCase(Calc.hex(Sm9Math.pointToOctets(recovered))),
            "compare", "恢复出的私钥点 ds == GmSSL hex_ds");
        log.info("同一个 r 签两条消息 => 直接解出私钥点 ds");
        Tracer.trace("end", new Object[]{"recoveredDs", Sm9Math.pointToOctets(recovered)}, null, "end");
    }

    /**
     * 测试⑥：签名的 DER 结构对齐 GmSSL 的 sm9_signature_to_der / GM/T 0080-2020：
     * {@code SEQUENCE { OCTET STRING h(32), BIT STRING S(65) }}。
     * <p><b>本条公式的新字母</b>
     * <pre>
     *   ASN.1     描述"数据结构长什么样"的语言（只定义结构，不定义字节）；DER = 它唯一的
     *             确定性编码规则 (Distinguished Encoding Rules)：同一结构只有一种字节写法
     *   TLV       每段都是 Tag(类型) ‖ Length(长度) ‖ Value(值) 三段
     *   0x30      SEQUENCE（按顺序放的容器）的 Tag
     *   0x04      OCTET STRING（原样字节串）的 Tag —— h 是"一串数出来的字节"，用这个
     *   0x03      BIT STRING（按位算的数据）的 Tag —— S 用这个，与 GM/T 0080 对椭圆曲线点的约定一致
     *   pad byte  BIT STRING 的 Value 第一个字节 = 末尾有几个 bit 没用上；65 字节是整字节 ⇒ 必为 0
     * </pre>
     * <p>为什么 h 走 OCTET STRING 而 S 走 BIT STRING：h 是 Z_n 里的整数定长铺成 32 字节，
     * 语义就是"一串字节"；S 是群里的点，标准把它当位串处理（未压缩点 0x04‖x‖y 首字节 0x04
     * 在 BIT STRING 里必须原样保留，不能像 INTEGER 那样被"约掉前导 0"）。
     * 用 OCTET STRING 装点也是一种常见变体（BouncyCastle 的 SM2 签名就是纯 ASN.1 INTEGER 结构），
     * 本测试断言的是 GM/T 0080-2020 / GmSSL 对 SM9 的写法。
     */
    @TraceExecution(value = "SM9 签名 DER 结构（OCTET STRING h + BIT STRING S）", algorithm = "SM9", flow = "SM9-SIGN")
    @Test
    public void signatureDerWrapsOctetHAndBitStringS()
        throws Exception
    {
        Tracer.trace("start", new Object[]{"message", MESSAGE, "id", "Alice", "r", R}, null, "start");

        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] h = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 97);
        Tracer.trace("sign.split", new Object[]{"signature", signature}, new Object[]{"h", h, "S", s}, "computeS");

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DEROctetString(h));
        vector.add(new DERBitString(s));
        byte[] der = new DERSequence(vector).getEncoded();
        Tracer.trace("DERSequence.encode", new Object[]{"h", h, "S", s}, der, "computeS");

        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        Assert.assertEquals(2, parsed.size());
        Tracer.traceDecision("compare.fieldCount", new Object[]{"size", parsed.size()}, parsed.size() == 2,
            "compare", "SEQUENCE 含 2 个元素");
        Assert.assertArrayEquals(h, ASN1OctetString.getInstance(parsed.getObjectAt(0)).getOctets());
        Tracer.traceDecision("compare.octetStringH", new Object[]{"parsedH", ASN1OctetString.getInstance(parsed.getObjectAt(0)).getOctets(),
                "h", h}, Arrays.equals(h, ASN1OctetString.getInstance(parsed.getObjectAt(0)).getOctets()),
            "compare", "OCTET STRING h 与签名前半一致");
        byte[] fromBitString = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        Assert.assertArrayEquals(s, fromBitString);
        Tracer.traceDecision("compare.bitStringS", new Object[]{"parsedS", fromBitString, "s", s},
            Arrays.equals(s, fromBitString), "compare", "BIT STRING S 与签名后半一致");
        Assert.assertEquals(65, fromBitString.length);
        // 未压缩点的第一字节 0x04 是"格式前缀"(uncompressed)，不是坐标数据；
        // 用 BIT STRING 包装时它照样原样传输，取回来还得自己认这个前缀。
        Assert.assertEquals(0x04, fromBitString[0] & 0xff);
        // BIT STRING 的内容第一个字节是"填充位数"，65 字节正好是整字节，所以必须是 0
        byte[] bitStringEncoding = ASN1BitString.getInstance(parsed.getObjectAt(1)).getEncoded();
        Assert.assertEquals(0x03, bitStringEncoding[0] & 0xff);
        Assert.assertEquals(0, bitStringEncoding[2] & 0xff);
        Tracer.traceDecision("compare.bitStringLayout", new Object[]{"S_len", fromBitString.length,
                "S_prefix", fromBitString[0] & 0xff, "tag", bitStringEncoding[0] & 0xff, "padBits", bitStringEncoding[2] & 0xff},
            fromBitString.length == 65 && (fromBitString[0] & 0xff) == 0x04
                && (bitStringEncoding[0] & 0xff) == 0x03 && (bitStringEncoding[2] & 0xff) == 0,
            "compare", "S 为 65 字节未压缩点，BIT STRING tag=0x03、pad=0");
        // 逐字节数一下整包大小（这就是上面 TLV 的算术）：
        //   OCTET STRING h = 1(tag) + 1(len=32) + 32 = 34
        //   BIT STRING  S  = 1(tag) + 1(len=66) + 1(pad) + 65 = 68（Length 把 pad 字节自己也算进去）
        //   SEQUENCE       = 1(tag=0x30) + 1(len=102) + 34 + 68 = 104
        // 102 与 66 都小于 128，所以 Length 各占 1 字节；换成大于 127 的载荷才会出现多字节长度。
        log.info("SM9 签名 DER {} 字节", der.length);
        Tracer.trace("end", new Object[]{"der", der, "derLen", der.length}, null, "end");
    }
}
