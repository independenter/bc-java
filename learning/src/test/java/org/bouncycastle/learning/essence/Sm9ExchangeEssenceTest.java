package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 密钥交换（GB/T 32915.4）的本质计算 —— 面向过程版。
 *
 * <p><b>符号表 —— 本文件每条公式里的字母/记号</b>
 * <pre>
 *   kex / ke    交换主私钥 ∈ Z_n（GmSSL: hex_kex）。它和加密主私钥是<b>同一条链</b>：
 *               Ppube = ke·P1 ∈ G₁，交换与加密共用；只是用户私钥靠 hid 分叉（0x02 vs 0x03）
 *   Ppube       交换/加密主公钥 = ke·P1，65 字节，全网公开
 *   ID_A, ID_B  两个参与方的标识字节串："Alice" = 41 6C 69 63 65、"Bob" = 42 6F 62
 *               下标 A = 发起方 (initiator)、B = 应答方 (responder)
 *   hid         用途分隔符：密钥交换固定 0x02（Sm9Math.HID_EXCH）
 *   H1(ID,0x02) SM3(0x01‖ID‖0x02‖00000001) ‖ SM3(0x01‖ID‖0x02‖00000002)，取前 40 字节，
 *               z mod (n−1) + 1 ⇒ 值域 [1, n−1]
 *   Q_A, Q_B    "对方的标识 + 公开主公钥"拼出来的点：Q_B = H1(ID_B,0x02)·P1 + Ppube = (h1_B+ke)·P1 ∈ G₁
 *               约定：谁算 Q，用的是<b>对方</b>的 ID（发起方算 Q_B，应答方算 Q_A）
 *   de_A, de_B  各自的交换私钥 = ke·(ke + H1(自己ID,0x02))⁻¹·P2 ∈ G₂（129 字节），只有 KGC 能发
 *   rA, rB      双方的临时随机数 (ephemeral private key)，各用一个会话，用完即删
 *   RA, RB      临时公钥 = 线上的两枚消息：RA = rA·Q_B、RB = rB·Q_A ∈ G₁（各 65 字节，裸坐标 64 字节）
 *   G           纸面基准 e(P1, P2) ∈ GT：只用它写指数，代码里对应 pairing(P2, P1)（实参顺序见测试②）
 *   base        代码里的变量 = e(P2, Ppube) = G^{ke} ∈ GT
 *   cross       代码里的变量 = e(de_自己, R_对方) ∈ GT：本方的"跨界"配对，是双线性相消发生的地方
 *   g1, g2, g3  三格 GT 元素（各 384 字节，见下面的角色表）：g1 = G^{ke·rA}、g2 = G^{ke·rB}、
 *               g3 = G^{ke·rA·rB} —— g3 才是 ECDH 型共享秘密，g1/g2 是"半截"
 *   sk          会话密钥 = KDF(ID_A‖ID_B‖RA‖RB‖g1‖g2‖g3, klen)，本文件 klen = 16 字节（演示用）
 *   KDF         SM3 计数器流 T = SM3(Z‖00000001) ‖ SM3(Z‖00000002) ‖ …
 *   hash        会话上下文摘要 = SM3(g2‖g3‖ID_A‖ID_B‖RA‖RB)，32 字节
 *   S_A / S_B   密钥确认标签 (key confirmation tag) = SM3(前缀‖g1‖hash)，各 32 字节
 *   0x83/0x82   标签前缀：0x83 = 发起方自己的标签 S_A，0x82 = 应答方的 S_B（GmSSL SM9_EXCH_*_CONFIRM）
 *               验对方的标签时，要传<b>对方</b>那个前缀
 *   RA/RB 裸化   KDF 与 hash 里用的是去掉 0x04 前缀的 x‖y（64 字节），不是 65 字节的点编码
 *   ·  +  ⁻¹  ‖ 同其余文件：标量乘 / 群加法 / Z_n 里的模逆 / 字节拼接（本文件没有异或）
 * </pre>
 *
 * <p>它要解决的问题和 ECDH 一样：两边只交换明文点，就凑出一个第三方算不出的共享密钥。
 * 区别在于"身份"不再是证书，而是标识字符串，于是临时公钥里直接混进对方的 ID：
 * <pre>
 *   Q_B = H1(ID_B,0x02)·P1 + Ppube        （发起方 A 算，用<b>对方</b>的标识）
 *   RA  = rA·Q_B ∈ G₁,  RB = rB·Q_A ∈ G₁ （这两枚点就是线上的全部消息）
 *
 *   A 侧：g1 = e(P2,Ppube)^{rA} = e(P1,P2)^{ke·rA}
 *          g2 = e(deA,RB)       = e(P1,P2)^{ke·rB}      ← 因为 deA = ke/(H1_A+ke)·P2, RB = rB(H1_A+ke)P1
 *          g3 = g2^{rA}         = e(P1,P2)^{ke·rA·rB}
 *   B 侧：g1 = e(deB,RA)         = e(P1,P2)^{ke·rA}
 *          g2 = e(P2,Ppube)^{rB} = e(P1,P2)^{ke·rB}
 *          g3 = g1^{rB}         = e(P1,P2)^{ke·rA·rB}
 *
 *   sk = KDF(ID_A ‖ ID_B ‖ RA_x,y ‖ RB_x,y ‖ g1 ‖ g2 ‖ g3)
 * </pre>
 * 三格 g 的<b>字节位置</b>在两边完全一致（g1 永远是 A 那一项、g2 永远是 B 那一项），
 * 变的只是"谁用哪把私钥去算它"。这就是本文件第二个测试要逐字节证明的事。
 *
 * <p><b>逐字母读那张角色表（为什么同一格 g 两边能算出同一段字节）</b>
 * <pre>
 *   g1（A 侧）e(P2,Ppube)^{rA} = e(P2, ke·P1)^{rA} = G^{ke·rA}          ← 只要 rA，不需要私钥
 *   g1（B 侧）e(de_B, R_A)     = e(ke·(ke+h1_B)⁻¹·P2, rA·(ke+h1_B)·P1)
 *                              = G^{ ke(ke+h1_B)⁻¹ · rA(ke+h1_B) } = G^{ke·rA}   ← (ke+h1_B) 相消
 *   g2（A 侧）e(de_A, R_B)  ← 自己的私钥配对方的临时点；B 侧同一格 = e(P2,Ppube)^{rB}
 *   g3 = g2^{rA}（A 侧）= g1^{rB}（B 侧）：把"另一边的半截秘密"再抬一次自己的 r
 * </pre>
 * 规律只有一条：指数里含<b>谁的 r</b>，谁就能只用公开量算那一格（base 的 r 次幂），
 * 另一边则必须拿自己的 de 去配对方发来的 R —— 所以"跨界配对"永远是收到对方临时点的那一方做的。
 * 相消之所以发生，全靠 Q 里写的是<b>对方</b>的标识：A 发的 RA 含 (ke + h1_A)，而 A 手里的 de_A
 * 含 (ke + h1_A)⁻¹ —— 互为倒数的两个标量分别出现在两个群里，配对把它们乘到一起就没了。
 * 于是每一格 g 都要花掉"某一边的一个秘密"才算得出：要么是自己的 r（配合公开量算 base 的幂），
 * 要么是自己的 de 配对方发来的 R（跨界那一格）。第三方两样都没有 ⇒ 只能看两枚点，算不出任何一格。
 * 这就是交换里的身份绑定，也是"少拿一把私钥就凑不出同一个 sk"的数学根据。
 * <p>三格各自的分工：
 * <pre>
 *   g3 = G^{ke·rA·rB}  真正的共享秘密。第三方只看 RA、RB 要算它，需解 G 上的 Diffie–Hellman 问题
 *   g1 = G^{ke·rA}     半截秘密，只跟 A 的临时数有关 —— A 自己就能算，B 必须有 de_B 才能算
 *   g2 = G^{ke·rB}     半截秘密，只跟 B 的临时数有关 —— 镜像
 * </pre>
 * 把 g1、g2 也塞进 KDF（而不是只用 g3）的作用是让 sk 同时绑定"双方各自的贡献 + 两个标识 + 两枚
 * 临时点"，任何一格被换都会分叉；标签里再单列 g1，是为了让"对方能算出这一格"成为它持有
 * 相应秘密的证据（谁必须花私钥、谁不用，见下面那段）。
 * <p><b>前向保密 (forward secrecy)</b>：与标识加密相反，交换的临时数 rA、rB 用完即删，
 * 所以事后泄露 de 或 ke 也不足以从录下来的 RA、RB、密文流量还原 sk（还要解一次 ECDLP 拿 r）。
 *
 * <p>确认标签（0x83 / 0x82）解决的是"对方真的算出了同一个 sk 吗"：
 * {@code hash = SM3(g2‖g3‖ID_A‖ID_B‖RA‖RB)}，{@code tag = SM3(prefix‖g1‖hash)} ——
 * 只有持有正确 de 的一边才算得出那格"跨界"秘密，所以标签本身就是密钥确认。
 * <p><b>两把私钥分别卡在标签的哪一格</b>（这条最容易看漏）：
 * <pre>
 *   A 算 SA：g1 = e(P2,Ppube)^{rA} = G^{ke·rA}        ← 只要自己的 rA，不要私钥
 *            但 hash 里有 g2 = e(de_A, R_B) = G^{ke·rB}（连同 g3 = g2^{rA}）
 *                                                     ← ⇒ <b>A 必须持 de_A</b>
 *   B 算 SB：g2 = e(P2,Ppube)^{rB}、g3 = g2^{rB}       ← 只要自己的 rB，不要私钥
 *            但 hash 外层有 g1 = e(de_B, R_A) = G^{ke·rA}
 *                                                     ← ⇒ <b>B 必须持 de_B</b>
 * </pre>
 * 也就是说：同一格 g1 在 A 侧是"公钥可算"的、在 B 侧是"必须花一把私钥"的，两侧的角色刚好互补，
 * 于是两枚标签各自证明了"发送方持有它声称的那个标识对应的私钥"。
 * <p>读法：hash 是"会话上下文摘要"（g2、g3、两个标识、两枚裸坐标点，全是双方都有的量），
 * tag 在这个摘要之外再套一层 SM3，把 <b>g1</b> 和前缀单独接进去。为什么要分两层 SM3、
 * 为什么 g1 被从 hash 里挪到外层，标准正文没有给动机，本实现照抄结构；从安全角度看，
 * 起作用的是"标签把全部 7 段输入都绑上了"这一事实（测试③ 逐格 tamper 就是在验这句话）。
 * 前缀 0x83/0x82 的作用是方向区分：同一会话里 A 与 B 手里的 g1..g3 完全相同，若不打前缀，
 * 两条标签就会字节相同，攻击者可以拿自己那一条去应答对方（反射攻击 / reflection attack）。
 *
 * <p><b>本文件的 KAT（known-answer test）出处</b>：kex = hex_kex、de_A = hex_deA、de_B = hex_deB、
 * RA = hex_RA 全部取自 GmSSL 的 {@code tests/sm9test.c}（GB/T 32915 附录 A 的示例值）。
 * rA、rB 与第三方的 rB' 是这里固定的（GmSSL 现采），只有把两个 nonce 钉住，g1..g3、sk、两枚标签
 * 才是可逐字节复算的确定值。
 */
@Slf4j
public class Sm9ExchangeEssenceTest
{
    /** 发起方 A 的标识（"Alice" = 41 6C 69 63 65）；应答方 B 用<b>它</b>算 Q_A，不是用自己的。 */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    /** 应答方 B 的标识（"Bob" = 42 6F 62）；发起方 A 用它算 Q_B。 */
    private static final byte[] ID_BOB = "Bob".getBytes();

    /** GmSSL tests/sm9test.c 的交换样例：hex_kex / hex_deA / hex_deB / hex_rA / hex_RA。 */
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
    /** 标准答案 de_A = kex/(kex+H1(Alice,0x02))·P2，四行 = x₁,x₀,y₁,y₀（G₂ 的点，129 字节）。 */
    private static final String HEX_DE_A =
        "0FE8EAB395199B56BF1D75BD2CD610B6424F08D1092922C5882B52DCD6CA832A"
            + "7DA57BC50241F9E5BFDDC075DD9D32C7777100D736916CFC165D8D36E0634CD7"
            + "83A457DAF52CAD464C903B26062CAF937BB40E37DADED9EDA401050E49C8AD0C"
            + "6970876B9AAD1B7A50BB4863A11E574AF1FE3C5975161D73DE4C3AF621FB1EFB";
    /** 标准答案 de_B（同一个公式、ID 换成 "Bob"）：两把私钥形状一样、点完全不同。 */
    private static final String HEX_DE_B =
        "74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"
            + "01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"
            + "44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"
            + "8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539";
    /** 标准答案 RA = rA·Q_B 的 x‖y（GmSSL: hex_RA 是<b>裸坐标</b> 64 字节，所以断言里补 "04"）。 */
    private static final String HEX_RA_POINT =
        "7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"
            + "A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599";
    /** 发起方的临时标量 rA（这里固定；GmSSL 现采，值与签名/加密文件里的 hex_r 相同，便于横向对照）。
     *  它同时决定 RA、g1、g3 —— 事后不删就等于把这次会话的密钥交给能看到 RA 的人。 */
    private static final BigInteger R_A = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
    /** 应答方的临时标量 rB：决定 RB、g2、g3。与签名/加密里的 r 一样，一次会话一个、用完即删。 */
    private static final BigInteger R_B = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
    /** 第三方（中间人）自采的一个 rB'，只用来做"改一个字节全盘皆变"的反例。 */
    private static final BigInteger R_B_OTHER = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);

    /** 会话密钥字节数：演示用 16 字节（128 bit）。真实部署按用途取 16/32 字节再喂给对称算法。 */
    private static final int KLEN = 16;

    /** 前缀字节：发起方自己的标签 0x83，应答方 0x82（GmSSL 的 SM9_EXCH_*_CONFIRM）。
     *  这两个字节是"角色/方向标识"：同一会话里两边的 g1..g3 完全相同，靠它把 S_A 与 S_B 分开，
     *  免得攻击者拿自己那条标签原样回发（反射攻击）。int 而非 byte 是为了调用处少一次强转。 */
    private static final int PREFIX_A = 0x83;
    private static final int PREFIX_B = 0x82;

    /**
     * 测试①：RA、deA、deB 三个已知答案对齐 GmSSL，并确认 Q 用的是<b>对方</b>的标识。
     * <p>四段断言的分工：
     * <pre>
     *   RA == hex_RA        线上第一枚消息的形状正确（rA·Q_B，Q_B 里写的是 Bob 的 ID）
     *   换 ID 就换点         证明"Q 用对方 ID"不是口头约定，是可验证的事实（也是身份绑定的源头）
     *   RB == rB·Q_A        标准没给 RB 样例，就用它与定义式逐字节相等来间接确认
     *   de_A / de_B         两把交换私钥对齐 hex_deA / hex_deB，且都在 E'(Fp2) 上
     * </pre>
     * <p>注意 de 与 Q 用的是<b>同一个</b> H1(ID,0x02)：de 里是 (ke + h1_自己)⁻¹·P2，
     * Q 里是 (ke + h1_对方)·P1 —— 一方持有的分子正好是另一方点里的分母，配对才消得掉。
     */
    @Test
    public void ephemeralPointAndBothPrivateKeysMatchGmsslAnswers()
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        // 第二个实参是"对方的标识"：发起方 A 算 RA 时传的是 ID_BOB，不是自己的 ID_ALICE
        Assert.assertEquals("04" + HEX_RA_POINT, Calc.hex(Sm9Math.pointToOctets(ra)).toUpperCase());

        // 同样的 rA、如果把标识写成自己的，得到的就是另一个点 —— "Q 用对方 ID"是可验证的事实
        // （这一句也是"写错 ID 会怎样"的演示：协议不会报错，只是双方再也算不出同一个 sk）
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(ra),
            Sm9Math.pointToOctets(Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_A))));

        // RB 没有现成样例，但它必须等于 rB·Q_A，而 Q_A = (H1(Alice,0x02)+ke)·P1
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);
        Assert.assertTrue(Sm9Math.pointIsOnCurve(rb));
        // 这里把 Q_A 直接按 (h1_A + ke)·P1 算（先合并标量），再乘 rB：与 exchEphemeral
        // "先加两个点再乘"的写法是分配律 (r·(m·P1) = (r·m mod n)·P1) 的两种实现路径。
        BigInteger[] qA = Sm9Math.pointMul(
            Sm9Math.modnAdd(Sm9Math.hash1(ID_ALICE, Sm9Math.HID_EXCH), HEX_KEX), Sm9Math.P1);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(R_B, qA))),
            Calc.hex(Sm9Math.pointToOctets(rb)));

        // 两把交换私钥（hid = 0x02）都必须是 G₂ 上的点，且与标准答案一字不差
        BigInteger[][] deA = Sm9Math.privateKeyExtract(HEX_KEX, ID_ALICE, Sm9Math.HID_EXCH);
        BigInteger[][] deB = Sm9Math.privateKeyExtract(HEX_KEX, ID_BOB, Sm9Math.HID_EXCH);
        Assert.assertEquals("04" + HEX_DE_A, Calc.hex(Sm9Math.twistToOctets(deA)).toUpperCase());
        Assert.assertEquals("04" + HEX_DE_B, Calc.hex(Sm9Math.twistToOctets(deB)).toUpperCase());
        // 在曲线上是"能用"的最低要求；G₂ 的阶是素数 n，所以曲线上的非无穷远点自动在正确的子群里
        Assert.assertTrue(Sm9Math.twistIsOnCurve(deA));
        Assert.assertTrue(Sm9Math.twistIsOnCurve(deB));
        log.info("RA = {}", Calc.hex(Sm9Math.pointToOctets(ra)));
    }

    /**
     * 测试②：两个角色各自算自己的三格 g，<b>字节必须完全相同</b>，sk 也因此相同。
     * 顺手再证明 g1 = e(P1,P2)^{ke·rA}、g2 = e(P1,P2)^{ke·rB} —— 双线性把 de 里的除法抵消掉。
     * <p><b>两个角色调同一个函数时，实参怎么摆</b>
     * <pre>
     *   A（发起方） exchSessionKey(true,  ke, ownId=Alice, peerId=Bob,  r=rA, ownR=RA, peerR=RB)
     *   B（应答方） exchSessionKey(false, ke, ownId=Bob,  peerId=Alice, r=rB, ownR=RB, peerR=RA)
     *                                    ↑ 只有 isInitiator 与"自己/对方"的视角换了，
     *                                      函数内部算的还是那两个配对：base^r 与 e(de_own, R_peer)
     * </pre>
     * <p>断言的三层含义：
     * <pre>
     *   g1/g2/g3 逐格同一段 384 字节   双线性相消真的发生了（否则 sk 不可能一致）
     *   rOut[0]/rOut[1] 两侧相同       RA 在前、RB 在后的"线上顺序"与角色无关（裸 64 字节）
     *   skA == skB                     KDF 的输入完全同一段 ⇒ 同长同字节；这就是"会话密钥建立成功"
     *   base^{ke·rA / ke·rB / ke·rA·rB} 三格各自只依赖一个标量积 —— 指数在 Z_n 里算，mod n 先约再乘
     * </pre>
     */
    @Test
    public void bothRolesProduceTheSameBytesAndTheSameSessionKey()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);

        // 两个出参数组由被调方填写：gOut[3] 是三格 GT 的 384 字节，rOut[2] 是 RA、RB 的裸坐标
        byte[][] gInitiator = new byte[3][];
        byte[][] rInitiator = new byte[2][];
        byte[] skA = Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rb, KLEN, gInitiator, rInitiator);

        byte[][] gResponder = new byte[3][];
        byte[][] rResponder = new byte[2][];
        byte[] skB = Sm9Math.exchSessionKey(false, HEX_KEX, ID_BOB, ID_ALICE, R_B, rb, ra, KLEN, gResponder, rResponder);

        // 三格 g 逐格相同，线上消息的顺序（A 的 RA 在前）也相同
        // 注意 ID 顺序也是"A 在前"：应答方传参时把 ownId=Bob 放第一个实参，但函数内部按
        // isInitiator 把 idA/idB 摆回 A-first —— KDF 输入不能依赖"谁先发起"以外的任何偶然因素。
        for (int i = 0; i < 3; i++)
        {
            Assert.assertEquals("g" + (i + 1) + " 两边必须同一段 384 字节",
                Calc.hex(gInitiator[i]), Calc.hex(gResponder[i]));
            Assert.assertEquals(384, gInitiator[i].length);
        }
        Assert.assertArrayEquals(rInitiator[0], rResponder[0]);
        Assert.assertArrayEquals(rInitiator[1], rResponder[1]);
        // 64 而不是 65：rOut 里存的是去掉 0x04 前缀的裸 x‖y，标准把裸坐标喂给 KDF 与 hash
        Assert.assertEquals(64, rInitiator[0].length);
        Assert.assertArrayEquals("会话密钥必须一致", skA, skB);

        // 双线性证明：g1 只该是 ke·rA 的函数，g2 只该是 ke·rB 的函数
        // base = pairing(P2, P1) 读作 e(P1, P2) = G（实参顺序与数学记号相反，见类头/配对文件的说明）
        BigInteger[] base = Sm9Math.pairing(Sm9Math.P2, Sm9Math.P1);
        // 三行合起来说的是：g1 = G^{ke·rA}、g2 = G^{ke·rB}、g3 = G^{ke·rA·rB}，
        // 也就是协议里那三格"看起来完全不同的算法"其实只是同一个指数的三种拆法。
        // 指数先用 modnMul 在 Z_n 里约好再抬幂：GT 的阶是 n，所以指数天然 mod n。
        Assert.assertEquals(Calc.hex(gInitiator[0]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(HEX_KEX, R_A)))));
        Assert.assertEquals(Calc.hex(gInitiator[1]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(HEX_KEX, R_B)))));
        Assert.assertEquals(Calc.hex(gInitiator[2]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(Sm9Math.modnMul(HEX_KEX, R_A), R_B)))));
        log.info("sk = {}", Calc.hex(skA));
    }

    /**
     * 测试③：确认标签在两条<b>独立计算</b>之间互验通过，改任何一个字节都验不过。
     * <p><b>标签公式的字母</b>（都出现在 Sm9Math.exchConfirmTag 里）：
     * <pre>
     *   hash = SM3(g2 ‖ g3 ‖ ID_A ‖ ID_B ‖ RA ‖ RB)      32 字节，"会话上下文摘要"，不含 g1
     *   tag  = SM3(prefix ‖ g1 ‖ hash)                     32 字节，prefix = 0x83（S_A）/ 0x82（S_B）
     *   输入共 7 段：g1、g2、g3、RA、RB、ID_A、ID_B —— 少绑一段就少一段保证
     * </pre>
     * <p>"互验"的意思是：A 用<b>自己</b>算出的 g/r 复现 B 那条 SB（前缀换成 0x82），
     * B 反过来复现 SA（前缀换回 0x83）。两边各跑各的计算、没交换过任何秘密字节，
     * 标签仍能对上 ⇒ 这才是"sk 相同"的可验证证据，而不是一句断言。
     * <p>最后六行是逐格 tamper：g1、g2、g3、RA、RB、以及把两个 ID 的顺序对调，
     * 每一种都让标签变。对调 ID 那行特别说明 ID 是<b>有位置</b>的：
     * "Alice‖Bob" 与 "Bob‖Alice" 是两个不同的摘要输入，所以对调后必须验不过
     * （标准规定 A-first 与角色无关，就是为了两侧不在这个字节序上分叉）。
     */
    @Test
    public void confirmTagsCrossValidateAndBreakOnTampering()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);

        // 两个角色各跑一遍自己的计算，得到各自的 g/r 数组
        // （注意这两次调用是"独立"的：gA/gB 数组里能逐字节相等，只可能来自数学上的相消）
        byte[][] gA = new byte[3][];
        byte[][] rA = new byte[2][];
        Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rb, KLEN, gA, rA);
        byte[][] gB = new byte[3][];
        byte[][] rB = new byte[2][];
        Sm9Math.exchSessionKey(false, HEX_KEX, ID_BOB, ID_ALICE, R_B, rb, ra, KLEN, gB, rB);

        // 线上：A 发 SA（前缀 0x83），B 发 SB（前缀 0x82）
        byte[] sa = Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_A);
        byte[] sb = Sm9Math.exchConfirmTag(gB[0], gB[1], gB[2], rB[0], rB[1], ID_ALICE, ID_BOB, PREFIX_B);
        Assert.assertEquals(32, sa.length);
        Assert.assertFalse("两个角色的标签必须不同（前缀就是角色标识）", Arrays.equals(sa, sb));

        // A 收到 SB 后用自己的计算结果重算 0x82 那个标签；B 收到 SA 后重算 0x83 的
        // 关键细节：验对方时传<b>对方</b>的前缀，而 ID 参数仍是 (Alice, Bob) 这个 A-first 顺序。
        Assert.assertArrayEquals("B 的标签必须能被 A 复现", sb,
            Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_B));
        Assert.assertArrayEquals("A 的标签必须能被 B 复现", sa,
            Sm9Math.exchConfirmTag(gB[0], gB[1], gB[2], rB[0], rB[1], ID_ALICE, ID_BOB, PREFIX_A));

        // 每一格输入动一下，标签就变 —— 标签绑定了 g1..g3、两个标识和两枚临时点
        // 六行分别打：g1、g2、g3、RA、RB、ID 顺序（前缀那一格由上一段的互验覆盖）
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(tamper(gA[0]), gA[1], gA[2], rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_A)));
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(gA[0], tamper(gA[1]), gA[2], rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_A)));
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(gA[0], gA[1], tamper(gA[2]), rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_A)));
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], tamper(rA[0]), rA[1], ID_ALICE, ID_BOB, PREFIX_A)));
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], rA[0], tamper(rA[1]), ID_ALICE, ID_BOB, PREFIX_A)));
        Assert.assertFalse(Arrays.equals(sa, Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], rA[0], rA[1], ID_BOB, ID_ALICE, PREFIX_A)));
    }

    /**
     * 测试④：中间人把 RB 换成自己那个 rB' 算出来的点 —— 两侧 sk 立刻分叉，
     * B 发来的标签也就验不过。这就是密钥确认存在的意义：不一致必须当场发现。
     * <pre>
     *   RB → RB' = rB'·Q_A 改变了什么：
     *     g2 = G^{ke·rB} → G^{ke·rB'}     A 的 cross = e(de_A, RB) 跟着换点 ⇒ 变
     *     g3 = g2^{rA}   → G^{ke·rA·rB'}  ⇒ 变
     *     g1 = G^{ke·rA}                   只含 rA，与 RB 无关 ⇒ <b>不变</b>（第三行断言）
     *     hash / sk                        含 g2、g3、RB ⇒ 全变
     * </pre>
     * <p>这个形状解释了两件事：其一，密钥确认<b>必须</b>把 g2、g3 也绑进 hash，
     * 否则只比 g1 的话，被换掉的 RB 根本不会反映到标签上；其二，g1 那一格"不变"不是弱点，
     * 而是它的用途 —— 验 SA 的那一方（B）只能靠 de_B 配 RA 才算得出 g1，
     * 所以"标签被对方验通过"证明的是<b>验标签的一方</b>持有对应 de；
     * 发起方 A 自己的 de_A 则是从 hash 里的 g2 那格参与证明的（类头有逐格的对照表）。
     * <p>诚实的边界：中间人在这里只做到了<b>破坏</b>（两侧发现分叉、会话中止），做不到<b>冒充</b>。
     * 想冒充 Bob 就得自己造出一个能让 A 算出一致 g2 的点，而那需要 de_B（KGC 才发得出来）；
     * 这也是标识密码的认证根基 —— 但反过来，KGC 本身能算出任何人的 de，故它天然可以冒充任何人。
     */
    @Test
    public void substitutedEphemeralPointSplitsTheSessionKey()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rbHonest = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);
        // 攻击者用自己的 rB' 造一枚"看起来一样合法"的点：它在 G₁ 上、编码也正确，
        // 所以任何只做格式检查的实现都发现不了 —— 只有密码学会发现。
        BigInteger[] rbEvil = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B_OTHER);
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(rbHonest), Sm9Math.pointToOctets(rbEvil)));

        byte[][] gHonest = new byte[3][];
        byte[][] rHonest = new byte[2][];
        byte[] skHonest = Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rbHonest, KLEN, gHonest, rHonest);

        byte[][] gVictim = new byte[3][];
        byte[][] rVictim = new byte[2][];
        // 同一个 A、同一枚 RA、同一个 rA，只是收到的 RB 被换了
        byte[] skVictim = Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rbEvil, KLEN, gVictim, rVictim);

        Assert.assertFalse("RB 一变，g2/g3 全变", Arrays.equals(gHonest[1], gVictim[1]));
        Assert.assertFalse("g3 也变", Arrays.equals(gHonest[2], gVictim[2]));
        Assert.assertTrue("g1 只跟 rA 有关，所以不变", Arrays.equals(gHonest[0], gVictim[0]));
        Assert.assertFalse("会话密钥必须分叉", Arrays.equals(skHonest, skVictim));

        // B 用自己的 RB 算出的 SB，A 用收到的（被换过的）RB 去验必然对不上
        byte[][] gB = new byte[3][];
        byte[][] rB = new byte[2][];
        Sm9Math.exchSessionKey(false, HEX_KEX, ID_BOB, ID_ALICE, R_B, rbHonest, ra, KLEN, gB, rB);
        byte[] sb = Sm9Math.exchConfirmTag(gB[0], gB[1], gB[2], rB[0], rB[1], ID_ALICE, ID_BOB, PREFIX_B);
        byte[] sbAsSeenByA = Sm9Math.exchConfirmTag(gVictim[0], gVictim[1], gVictim[2], rVictim[0], rVictim[1], ID_ALICE, ID_BOB, PREFIX_B);
        Assert.assertFalse(Arrays.equals(sb, sbAsSeenByA));
    }

    /** 改一个字节（用于"任何输入都绑进标签"的断言）。
     *  改<b>最后</b>一个字节而不是第一个：SM3 是按 512-bit 分组喂数据的，改哪一位对结果的影响
     *  都一样彻底，但动末位能顺手证明"这一段确实整份进了摘要"，不存在"只取前几字节"的实现偷懒。 */
    private static byte[] tamper(byte[] buf)
    {
        byte[] out = buf.clone();
        out[out.length - 1] ^= 0x01;
        return out;
    }
}
