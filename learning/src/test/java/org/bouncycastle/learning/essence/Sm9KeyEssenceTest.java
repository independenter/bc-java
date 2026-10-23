package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 的主密钥 / 私钥 —— 生成、结构与 DER 布局（对齐 GmSSL 的 sm9_key.c）。
 *
 * <p><b>符号表 —— 本文件每条公式里的字母/记号</b>
 * <pre>
 *   IBC         基于标识的密码 (identity-based cryptography)：用户的"公钥"就是他的标识字符串本身，
 *               不需要先申请证书；代价是私钥必须由 KGC 代发，因此 KGC 理论上能伪造任何人
 *   KGC         密钥生成中心 (Key Generation Center)：全网唯一掌握主私钥、替每个用户算私钥的那一方
 *   主私钥       标量（本文件里的 ks、ke、kex），[1, n−1] 里的随机数，永远不出 KGC 的门
 *   主公钥       主私钥乘生成元得到的公开点（Ppubs、Ppube），全网广播，任何人都能直接拿用
 *   私钥提取      private key extraction：KGC 把"主私钥 + 用户标识"套进公式算出用户私钥点的过程
 *   p           256-bit 素数，素域 Fp 的模数（Sm9Math.P）；曲线坐标都在 Fp 或它的扩域里
 *   n           G₁、G₂ 的公共阶（Sm9Math.N）；所有标量（ks、ke、kex、r、h、l）都在 Z_n 里运算
 *   Z_n         整数模素数 n 构成的域 {0, 1, …, n−1}；Z_n* 是去掉 0 的乘法群，共 n−1 个元素
 *   阶 (order)   一个群（或一个群元素）的元素个数；这里 G₁、G₂、GT 都是 n 阶素数阶群
 *   ⁻¹ mod n    模逆：a·a⁻¹ ≡ 1 (mod n)，扩展欧几里得求出；只有 a ≠ 0 才存在，公式里的"除法"就是它
 *   ·           按上下文两义：ks·P2 是椭圆曲线的标量乘（整数乘点）；modnMul 那种是 Z_n 里的普通乘法
 *   +           群加法：两个点合成第三个点（弦/切线作图），不是把坐标逐分量相加
 *   ‖           字节串拼接 (concatenate)，见 Calc.concat —— 不是异或
 *   P1, P2      生成元 (generator)：P1 生成 G₁、P2 生成 G₂；"生成元"指它的 1..n−1 倍正好铺满整个群
 *   G₁          E(Fp): y² = x³ + 5 的 n 阶子群，元素是仿射点 (x, y)，序列化 65 字节
 *   G₂          扭曲曲线 (twist) E'(Fp2): y² = x³ + 5u 的 n 阶子群，元素是射影点 {X, Y, Z}，序列化 129 字节
 *   GT          Fp12*（12 次扩域 Fp12 的乘法群）里唯一的 n 阶子群，配对的落点，元素展平后 384 字节
 *   e(P, Q)     双线性配对 (bilinear pairing)：G₁ × G₂ → GT，满足 e(a·P, b·Q) = e(P, Q)^{ab}；
 *               细节与三条 GmSSL 样例在 {@link Sm9PairingEssenceTest} 里，本文件只把它当黑盒
 *   ks          签名主私钥 (signature master private key) ∈ Z_n；签名主公钥 Ppubs = ks·P2 ∈ G₂
 *   ke          加密主私钥；加密主公钥 Ppube = ke·P1 ∈ G₁
 *   kex         密钥交换 (key exchange) 用的主私钥 —— 标准样例里 ke ≠ kex，是两个独立的主密钥
 *   ID          用户标识：任意字节串。"Alice" = 41 6C 69 63 65（5 字节）、"Bob" = 42 6F 62（3 字节）
 *   hid         用途分隔符 (hash function identifier)：0x01 签名、0x02 密钥交换、0x03 加密
 *   H1(ID,hid)  把任意字符串折成 Z_n* 里一个数的哈希。实现：SM3(0x01‖ID‖hid‖00000001) ‖
 *               SM3(0x01‖ID‖hid‖00000002) 得 64 字节，取前 40 字节当整数 z，返回 z mod (n−1) + 1
 *   ds          签名用户私钥 = ks·(ks + H1(ID,0x01))⁻¹·P1 ∈ G₁（一个 65 字节的点）
 *   de          加密/交换用户私钥 = ke·(ke + H1(ID,hid))⁻¹·P2 ∈ G₂（一个 129 字节的点）
 * </pre>
 *
 * <p>KGC 手里只有两个数：签名主私钥 {@code ks}、加密主私钥 {@code ke}（都是 [1, n−1] 里的随机数）。
 * 公开出去的只有两个点：{@code Ppubs = ks·P2 ∈ G₂}、{@code Ppube = ke·P1 ∈ G₁}。
 * 私钥提取则是把用户标识代数进公式里：
 * <pre>
 *   ds = ks·(ks + H1(ID,0x01))⁻¹·P1        de = ke·(ke + H1(ID,0x03))⁻¹·P2
 * </pre>
 * 逐字母读这两行：ks/ke 是主私钥标量；H1(ID,hid) 把"标识 + 用途"折成 Z_n* 里的一个数；
 * (ks + H1)⁻¹ 是 Z_n 里的模逆（不是实数除法）；最外面再拿这个标量去乘生成元 P1 或 P2。
 * <p><b>为什么除法要长成"主私钥 + 标识哈希"这个样子</b>
 * <pre>
 *   分子 ks        没有它就算不出私钥 ⇒ 只有 KGC（或泄露了 ks 的系统）能给任意 ID 发私钥
 *   分母 ks+H1     带上 ID ⇒ 每个标识的私钥都不同，且从 ds 反推 ks 要同时解一个含未知分母的方程
 *   乘的是 P1      ds 落在 G₁，而公开的 Ppubs 落在 G₂ ⇒ 想"由 Ppubs 推出 ds"就是解 CDHP（判定性
 *                  Diffie-Hellman 问题），在 256-bit SM9 上按约 128 bit 安全强度算不动
 * </pre>
 * 这个"分母"看起来刺眼，但它正是后面所有协议的机关：签名与加密都把同一个 (ks + H1) 再乘回去，
 * 除法就在配对的指数上被干净抵消（推导见 {@link Sm9SignEssenceTest} 与
 * {@link Sm9EncryptEssenceTest}）。另外 (ks + H1) ≡ 0 (mod n) 时逆不存在 —— H1 落在 [1, n−1]、
 * ks 均匀随机，撞上概率约 1/(n−1) ≈ 2⁻²⁵⁶，标准与 GmSSL 都不额外处理。
 *
 * <p><b>为什么 IBC 既没有证书也没有 CRL</b>：验证方要用的"公钥"就是 ID 本身（再加全网同一个
 * Ppubs/Ppube），根本没有需要第三方签名绑定的公钥文件，所以没有证书；没有签发出去的公钥，
 * 也就没有"吊销某人的公钥"这回事。想停用某个身份，标准给的手段是换标识或推进<b>主密钥更新周期</b>
 * （重跑一次 KGC），而不是发吊销列表。
 *
 * <p>DER 布局照 GmSSL：
 * <pre>
 *   签名主密钥  SEQUENCE { INTEGER ks,                 BIT STRING(129) Ppubs }
 *   加密主密钥  SEQUENCE { INTEGER ke,                 BIT STRING(65)  Ppube }
 *   签名用户私钥 SEQUENCE { BIT STRING(65) ds,          BIT STRING(129) Ppubs }
 *   加密用户私钥 SEQUENCE { BIT STRING(129) de,         BIT STRING(65)  Ppube }
 * </pre>
 * <p><b>符号表 —— 上面这四个结构里出现的 ASN.1 名词</b>
 * <pre>
 *   ASN.1        描述"数据长什么样"的元语言（结构、类型、约束），本身不是编码
 *   DER          Distinguished Encoding Rules：ASN.1 唯一确定的字节编码规则 —— 同一种值只有一种字节
 *                写法，所以才能拿断言逐字节比对；每个字段的写法都是 TLV = Tag ‖ Length ‖ Value
 *   SEQUENCE     "按顺序排列的结构体"，Tag 0x30；成员顺序是结构定义的一部分，换了顺序就不是同一个类型
 *   INTEGER      有符号大整数，Tag 0x02，二进制补码 + <b>最短</b>编码：正数若最高位为 1 要补一个 0x00
 *                字节表示正号，前导 0x00 又必须删干净 —— 于是定长 32 字节的 ks 常常编出 31 字节
 *   OCTET STRING 原样字节串，Tag 0x04，长度任意，不做任何数值解释（签名里的 h、密文里的 C2/C3 用它）
 *   BIT STRING   位串，Tag 0x03；内容第一个字节是"末尾补了几个 bit"的填充位数。本文件所有点都是整字节，
 *                所以填充恒为 0，看起来就跟 OCTET STRING 一样（选它是因为点本质是比特串）
 *   0x04‖x‖y     G₁ 点的 65 字节：0x04 是 SEC1"非压缩点 (uncompressed point)"前缀，x、y 各 32 字节大端
 *   0x04‖x₁‖x₀‖y₁‖y₀
 *                G₂ 点的 129 字节：Fp2 元素 a₀ + a₁u 按<b>高次分量在前</b>写，即先写 u 分量 a₁ 再写常数项 a₀
 *   384 字节     GT 元素 = 12 个 Fp 系数（每个 32 字节大端）串接，顺序是扁平下标 11 递减到 0（常数项最后）
 * </pre>
 * 那个 INTEGER 有个真实的坑：ks 是定长 32 字节，最高位可能是 0、首字节也可能本来就是 0x00，
 * 而 DER 的 INTEGER 是<b>有符号</b>的最短编码 —— GmSSL 专门有个
 * {@code test_sm9_master_key_from_der_leading_zero} 测试踩过这个雷。本文件的测试③就是把它写清楚：
 * 字节长度可以变，<b>值必须能一字不差地回到同一个标量</b>。
 *
 * <p><b>KAT (known-answer test，已知答案测试) 是什么</b>：从标准文档或参考实现里抄一组
 * "固定输入 → 固定输出"的样例，把输入硬编码进测试，只问一件事 —— 我的实现算出来的字节
 * 是不是和答案一模一样。它不测"性质"（那要靠双线性、分配律那类断言），只测"没有抄错常数/写反顺序"。
 * 本文件的 hex_ks、hex_ke、hex_kex、hex_ds、hex_de、hex_Pube 全部来自 GmSSL 的
 * {@code tests/sm9test.c}，也就是 GB/T 32915 附录 A（示例参数与中间值）那套样例；
 * 把它们当裁判，而不是当"设计依据"：公式来自标准，答案只是抄写检查。
 */
@Slf4j
public class Sm9KeyEssenceTest
{
    // 三个输入常量都是纯 ASCII，".getBytes()" 在任何平台默认字符集下都得到同样的字节：
    // ID_ALICE = 41 6C 69 63 65（5 字节），ID_BOB = 42 6F 62（3 字节），
    // MESSAGE = "Chinese IBS standard"（20 字节，标准样例的原文）。
    // ID 是"公钥"本身，所以长度和内容都不做补齐 —— 直接把这串字节喂进 H1。
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final byte[] ID_BOB = "Bob".getBytes();
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();

    // 三把主私钥标量（GmSSL: hex_ks / hex_ke / hex_kex），都是 64 个十六进制字符 = 32 字节大端。
    // 注意三个值都以 "0001…" / "0002…" 开头，即第 1 个字节就是 0x00、第 2 个字节只有 0x01/0x02，
    // 真正的 bitLength 只有 241~242（远不到 256）：
    // 这正是测试③要和 DER 最短编码对着干的那类值。
    //   HEX_KS  = 签名主私钥 ks，      Ppubs = ks·P2 ∈ G₂，ds = ks/(ks+H1(Alice,0x01))·P1
    //   HEX_KE  = 加密主私钥 ke，      Ppube = ke·P1 ∈ G₁，de = ke/(ke+H1(Bob,0x03))·P2
    //   HEX_KEX = 交换主私钥 kex，      标准样例里另一把，它的 kex·P1 就是下面那个 HEX_PUBE
    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
    private static final BigInteger HEX_KE = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);

    // 标准答案（KAT）：ds 是 G₁ 的点，所以只有 x(32) ‖ y(32) = 128 个十六进制字符，
    // 前缀 0x04 由测试里手动拼上去（见 "04" + HEX_DS）。
    private static final String HEX_DS =
        "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
            + "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3";
    // 标准答案 de 是 G₂ 的点，四个 Fp 分量各 32 字节 = 256 个十六进制字符，
    // 顺序是 GmSSL/国标的编排 x₁ ‖ x₀ ‖ y₁ ‖ y₀（x₁ 是 x 的 u 分量，写在前面；见 Sm9Math.twistToOctets）。
    private static final String HEX_DE =
        "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683"
            + "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158"
            + "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F"
            + "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1";
    /**
     * hex_kex·P1 就是标准样例里的 hex_Ppube（GmSSL: tests/sm9test.c）。
     * <p>两行各 32 字节 = x ‖ y（G₁ 点是仿射的，没有 u 分量，所以比 G₂ 少一半）。
     * 它是"交换主私钥 kex 对应的加密主公钥"，测试②与测试③都拿它当尺子：
     * 只要 Frobenius/生成元或者 x、y 的写出顺序错一处，这 64 个字节就全花。
     */
    private static final String HEX_PUBE =
        "9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"
            + "54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210";

    /**
     * 测试①：主私钥的值域 —— 与 GmSSL 的 sm9_z256_rand_range 同构，&gt;= n 就重采。
     * <pre>
     *   v        采出来的候选标量（32 字节大端读成的无符号整数），即"未来的 ks/ke"
     *   [1, n−1] 标准给主私钥定的值域，正好是 Z_n* 的全部元素
     *   n        G₁/G₂ 的阶（Sm9Math.N，256 bit 素数）
     *   resampled 统计"bitLength 不足 256"的个数，也就是需要补前导零才能写成定长 32 字节的那些
     * </pre>
     * <p><b>为什么边界要卡在 n，而且越界要重采而不是取模</b>
     * <pre>
     *   v = 0     ds = 0·(0+H1)⁻¹·P1 是无穷远点，Ppubs = O，整套协议当场塌掉 ⇒ 下界必须是 1
     *   v ≥ n     群里的 v·P 只由 v mod n 决定，所以大数并不带来新密钥，只是换个说不清的标量
     *   取模的坑   2²⁵⁶ 不是 n 的整数倍，"随机 32 字节再 mod n"会让小区间被多映射一次，
     *              分布不均匀（偏向低位）；拒绝采样 "≥ n 就重扔" 才是均匀的
     * </pre>
     * 采出 0 的概率是 2⁻²⁵⁶，所以 "主私钥必须 &gt;= 1" 这条断言事实上永远碰不到，但它把
     * 标准写下的值域钉在了测试里。
     */
    @Test
    public void generatedMasterKeysAlwaysLandInTheRangeOneToNMinusOne()
    {
        Random rnd = new Random(20261022L);
        int resampled = 0;
        for (int i = 0; i < 200; i++)
        {
            BigInteger v = Sm9Math.randScalar(rnd);
            Assert.assertTrue("主私钥必须 >= 1", v.compareTo(BigInteger.ONE) >= 0);
            Assert.assertTrue("主私钥必须 < n", v.compareTo(Sm9Math.N) < 0);
            if (v.bitLength() < 256)
            {
                resampled++;   // 高位被丢掉的那些，正是"定长 32 字节"与 DER 最短编码会打架的地方
            }
        }
        Assert.assertTrue("采出来的数应当有长有短，否则这个统计没意义", resampled > 0);
        log.info("200 个主私钥里 {} 个不足 256 bit", resampled);
    }

    /**
     * 测试②：两个主公钥点 —— Ppubs ∈ G₂、Ppube ∈ G₁，且 Ppube 对上标准样例 hex_Ppube。
     * <pre>
     *   ppubs  签名主公钥 = ks·P2，类型 BigInteger[][]：射影点 {X, Y, Z}，每个分量还是一个 Fp2 元素
     *   ppube  加密主公钥 = kex·P1，类型 BigInteger[]：仿射点 (x, y)，两个普通 Fp 元素
     *   N      G₁、G₂ 的公共阶 n（256-bit 素数）
     *   5u     E' 的曲线参数 b′：G₂ 的方程是 y² = x³ + 5u，u 是 Fp2 里那个满足 u² = −2 的符号
     * </pre>
     * <p><b>"n·P = 无穷远点"这条断言在测什么</b>：群元素的阶 = 让它回到单位元的最小正倍数。
     * 由拉格朗日定理，元素的阶必整除群的阶；这里群的阶是素数 n，所以只要点不是无穷远点，
     * 它的阶就只能等于 n。于是 n·P = O 同时验证了三件事：曲线实现没错、点真的落在那个 n 阶子群里、
     * 标量乘（twistMul / pointMul）没有把倍点公式写错。少一个常数、少一步进位，这个等式就不成立。
     */
    @Test
    public void masterPublicKeysLieOnTheRightCurves()
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        // 射影坐标下的曲线方程是 Y²Z = X³ + 5u·Z³（把仿射式 X = x/Z²、Y = y/Z³ 通分得到的），
        // 好处是加法全程不用求逆，Z 只在最后序列化时除掉
        Assert.assertTrue("Ppubs 必须在扭曲曲线上", Sm9Math.twistIsOnCurve(ppubs));
        // n·Ppubs = O ⇔ Ppubs 的阶整除 n；n 素数且 Ppubs ≠ O ⇒ 阶正好是 n
        Assert.assertTrue(Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, ppubs)));
        // 129 = 1 字节前缀 0x04 + x₁(32) + x₀(32) + y₁(32) + y₀(32)
        Assert.assertEquals(129, Sm9Math.twistToOctets(ppubs).length);

        BigInteger[] ppube = Sm9Math.encMasterPublicKey(HEX_KEX);
        // 仿射判定 y² = x³ + 5（G₁ 的 a = 0，所以式子里没有 x 项）
        Assert.assertTrue("Ppube 必须在 E(Fp) 上", Sm9Math.pointIsOnCurve(ppube));
        // 65 = 1 字节 0x04 + x(32) + y(32)
        Assert.assertEquals(65, Sm9Math.pointToOctets(ppube).length);
        Assert.assertEquals("ke·P1 必须等于 GmSSL 的 hex_Ppube",
            "04" + HEX_PUBE, Calc.hex(Sm9Math.pointToOctets(ppube)).toUpperCase());

        // 加密主密钥 ke 的 Ppube 与交换用的 ke 是两个不同的主密钥（样例里 ke ≠ kex），
        // 所以两个点必须不同 —— 混用主密钥就等于混用了私钥
        // 为什么"标量不同 ⇒ 点必然不同"：P1 的阶是 n，所以 ke·P1 = kex·P1 等价于 (ke−kex)·P1 = O，
        // 而后者只在 n | (ke−kex) 时成立；两个标量都取在 [1, n−1]，差的绝对值小于 n，除非常数相等否则不可能。
        // 换句话说，标量乘在 Z_n × ⟨P1⟩ 上是单射 —— 这也是"主公钥能公开"的根本原因。
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KE)),
            Sm9Math.pointToOctets(ppube)));
        log.info("Ppube = {}", Calc.hex(Sm9Math.pointToOctets(ppube)));
    }

    /**
     * 测试③：主密钥 DER —— INTEGER 是最短有符号编码，长度会变但值必须回得来。
     * <pre>
     *   ksBytes       定长 32 字节的 ks（大端，前导零补满）—— 拼接/KDF 里用的就是这个形状
     *   ASN1Integer   DER 的 INTEGER：可变长度、有符号、最短编码 —— 和上面那个形状天然不同
     *   DERBitString  DER 的 BIT STRING：装 Ppubs 那 129 字节的点
     *   2 + 31        TLV 里的 T（1 字节 tag 0x02）+ L（1 字节长度 0x1F = 31），内容只剩 31 字节
     *   ksBack        从 DER 里解出来的 BigInteger，断言它 == HEX_KS
     * </pre>
     * <p><b>为什么长度会从 32 变成 31</b>：DER 的 INTEGER 用二进制补码且要求最短。
     * ks 的真实大小只有 241 bit，最高字节本来就是 0x00，最高有效字节 0x01 的符号位是 0（正数），
     * 于是那个前导 0x00 属于"多余"，编码器必须扔掉；反之若最高有效字节是 0x80~0xFF（符号位为 1），
     * 就必须<b>补</b>一个 0x00，否则会被读成负数。GmSSL 的
     * {@code test_sm9_master_key_from_der_leading_zero} 踩的就是这两种情形对不齐的雷。
     * 结论：字节长度不可靠，<b>值</b>才可靠 —— 所以这里比的是 ksBack 与 HEX_KS 相等，
     * 再用 Calc.toBytes(ksBack, 32) 把形状补回定长。
     */
    @Test
    public void masterKeyDerRoundTripsEvenWithALeadingZeroByte()
        throws Exception
    {
        // hex_ks/hex_ke/hex_kex 首字节都是 0x00：DER 会把这个前导零省掉，编码只有 31 字节
        byte[] ksBytes = Calc.toBytes(HEX_KS, 32);
        Assert.assertEquals(0x00, ksBytes[0] & 0xff);

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(HEX_KS));
        vector.add(new DERBitString(Sm9Math.twistToOctets(ppubs)));
        byte[] der = new DERSequence(vector).getEncoded();

        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        // SEQUENCE 的两个成员顺序不能换：0 = INTEGER(主私钥标量)，1 = BIT STRING(主公钥点)
        Assert.assertEquals(2, parsed.size());
        BigInteger ksBack = ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue();
        Assert.assertEquals("INTEGER 值必须原样回到 ks", HEX_KS, ksBack);
        Assert.assertEquals(32, Calc.toBytes(ksBack, 32).length);
        Assert.assertArrayEquals(ksBytes, Calc.toBytes(ksBack, 32));
        ASN1Integer ksField = ASN1Integer.getInstance(parsed.getObjectAt(0));
        Assert.assertTrue("正数的最短编码不会带前导 0x00", ksField.getValue().signum() > 0);
        // 32 字节的 ks 最高两位都是 0，DER 只留 31 字节内容 + tag/len = 33 字节
        Assert.assertEquals(2 + 31, ksField.getEncoded().length);
        byte[] ppubsBack = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        // BIT STRING 取出来的就是原始 129 字节的点（getOctets() 已经把"填充位数"那一字节吃掉了），
        // 首字节 0x04 = 非压缩点前缀，后面依次是 x₁ x₀ y₁ y₀
        Assert.assertEquals(129, ppubsBack.length);
        Assert.assertEquals(0x04, ppubsBack[0] & 0xff);
        Assert.assertArrayEquals(Sm9Math.twistToOctets(ppubs), ppubsBack);

        // 加密主密钥同构，只是公钥点换成 65 字节的 G₁ 点
        ASN1EncodableVector encVector = new ASN1EncodableVector();
        encVector.add(new ASN1Integer(HEX_KEX));
        encVector.add(new DERBitString(Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KEX))));
        ASN1Sequence encParsed = ASN1Sequence.getInstance(new DERSequence(encVector).getEncoded());
        Assert.assertEquals(HEX_KEX, ASN1Integer.getInstance(encParsed.getObjectAt(0)).getValue());
        Assert.assertEquals("04" + HEX_PUBE, Calc.hex(
            ASN1BitString.getInstance(encParsed.getObjectAt(1)).getOctets()).toUpperCase());
    }

    /**
     * 测试④：用户私钥 DER 把私钥点和主公钥打包在一起（拿到它就能签/能解，不需要 ks、ke）。
     * <pre>
     *   ds    = ks·(ks + H1("Alice",0x01))⁻¹·P1 ∈ G₁  → 65 字节 BIT STRING
     *   de    = ke·(ke + H1("Bob",0x03))⁻¹·P2   ∈ G₂  → 129 字节 BIT STRING
     *   Ppubs = ks·P2 ∈ G₂（129）、Ppube = ke·P1 ∈ G₁（65）
     * </pre>
     * 两个结构都是 SEQUENCE{私钥点, 对应的主公钥点}，注意<b>两者的群是反的</b>：
     * 签名侧私钥在 G₁、公钥在 G₂；加密侧私钥在 G₂、公钥在 G₁。这正是配对 e(G₁, G₂) 要求的
     * 一左一右（详见 {@link Sm9SignEssenceTest} 与 {@link Sm9EncryptEssenceTest}）。
     * <p><b>为什么私钥文件里要捎带主公钥</b>：签名要算 g = e(P1, Ppubs)、验签要算
     * P′ = H1(ID,hid)·P2 + Ppubs，两步都离不开 Ppubs；把它和 ds 绑在同一个 ASN.1 结构里，
     * 用户拿到这一个文件就能离线干活，不必再去别处取"参数"（也避免取错曲线参数后算出自洽性极差的假签名）。
     * 断言 "ds/de 必须与标准答案一字不差" 说明这两把私钥点完全由 (主私钥, ID, hid) 决定：
     * 没有随机数、没有会话状态，所以 KAT 可以精确到字节。
     */
    @Test
    public void userKeyDerCarriesPrivateKeyPointPlusMasterPublicKey()
        throws Exception
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        byte[] ds = Sm9Math.pointToOctets(Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE));
        ASN1EncodableVector signKey = new ASN1EncodableVector();
        signKey.add(new DERBitString(ds));
        signKey.add(new DERBitString(Sm9Math.twistToOctets(ppubs)));
        ASN1Sequence parsedSign = ASN1Sequence.getInstance(new DERSequence(signKey).getEncoded());
        Assert.assertEquals("ds 必须与标准答案一字不差", "04" + HEX_DS,
            Calc.hex(ASN1BitString.getInstance(parsedSign.getObjectAt(0)).getOctets()).toUpperCase());
        Assert.assertEquals(65, ASN1BitString.getInstance(parsedSign.getObjectAt(0)).getOctets().length);

        // HID_ENC = 0x03（加密用途）。同一个 ke、同一个 Bob，把 hid 换成 0x01/0x02 就是另外两把私钥：
        // de = ke·(ke + H1(ID,hid))⁻¹·P2 里只有 H1 那一格受 hid 影响，其余完全相同。
        byte[] de = Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC));
        ASN1EncodableVector encKey = new ASN1EncodableVector();
        encKey.add(new DERBitString(de));
        encKey.add(new DERBitString(Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KE))));
        ASN1Sequence parsedEnc = ASN1Sequence.getInstance(new DERSequence(encKey).getEncoded());
        Assert.assertEquals(129, ASN1BitString.getInstance(parsedEnc.getObjectAt(0)).getOctets().length);
        Assert.assertEquals("04" + HEX_DE,
            Calc.hex(ASN1BitString.getInstance(parsedEnc.getObjectAt(0)).getOctets()).toUpperCase());
    }

    /**
     * 测试⑤：换一把<b>全新的</b>主密钥跑通"生成 → 提取 → 签名 → 验签"。
     * 前四个测试都在核对标准样例，这个测试证明流程不是"为了对上样例而写死的"。
     * <pre>
     *   性质测试 (property test) —— 与 KAT 相对：不问"输出等于哪个常数"，只问"协议自己的话是否自洽"，
     *                            即 verify(sign(M, ID_A)) == true，且换 ID 就 false
     *   ks        新采的签名主私钥 ∈ [1, n−1]
     *   ppubs     由新 ks 算出的主公钥（交给验签方的唯一东西）
     *   ds        由新 ks 与 ID_ALICE 提取出的用户私钥
     *   MESSAGE   "Chinese IBS standard"，20 字节，内容与标准样例无关，随便换
     * </pre>
     * 用 {@code new Random(固定种子)} 只是为了让这条测试可复现；randScalar 本身是拒绝采样，
     * 换任何种子都应当跑通 —— 双线性对任意 ks 都成立，这才是"实现正确"的强证据。
     */
    @Test
    public void freshlyGeneratedMasterKeySignsAndVerifiesEndToEnd()
        throws Exception
    {
        BigInteger ks = Sm9Math.randScalar(new Random(20261021L));
        Assert.assertTrue(ks.compareTo(BigInteger.ONE) >= 0 && ks.compareTo(Sm9Math.N) < 0);

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(ks);
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(ks, ID_ALICE);
        // ds 是 G₁（仿射、65 字节）的点，所以用 pointIsOnCurve 而不是 twistIsOnCurve 检查
        Assert.assertTrue(Sm9Math.pointIsOnCurve(ds));

        // 只把 ppubs（公钥）交给验签方：它不需要、也拿不到 ks
        // 最后一个入参是签名的临时标量 r ∈ [1, n−1]（nonce）：r 变则 w、h、S 全变，但都验得过
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, ks, Sm9Math.randScalar(new Random(991L)));
        Assert.assertTrue(Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));
        // 换成 ID_BOB 为什么必然失败：验签方算的 P′ = H1(ID,0x01)·P2 + Ppubs 里的 H1 变了，
        // 于是 u = e(S, P′) 变了、w = u·g^h 变了，最后 H2(M‖w) 与签名里那 32 字节的 h 对不上。
        // 标识密码里"把 ID 读错一个人"就是这样直接失败的，不需要任何吊销信息。
        Assert.assertFalse("换个人就验不过", Sm9Math.verify(MESSAGE, signature, ID_BOB, ppubs));
    }
}
