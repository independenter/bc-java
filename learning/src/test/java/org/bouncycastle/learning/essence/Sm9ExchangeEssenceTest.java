package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;

import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 密钥交换（GB/T 32915.4）的本质计算 —— 面向过程版。
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
 * <p>确认标签（0x83 / 0x82）解决的是"对方真的算出了同一个 sk 吗"：
 * {@code hash = SM3(g2‖g3‖ID_A‖ID_B‖RA‖RB)}，{@code tag = SM3(prefix‖g1‖hash)} ——
 * 只有持有正确 de 的一边才算得出 g1，所以标签本身就是密钥确认。
 */
@Slf4j
public class Sm9ExchangeEssenceTest
{
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final byte[] ID_BOB = "Bob".getBytes();

    /** GmSSL tests/sm9test.c 的交换样例：hex_kex / hex_deA / hex_deB / hex_rA / hex_RA。 */
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);
    private static final String HEX_DE_A =
        "0FE8EAB395199B56BF1D75BD2CD610B6424F08D1092922C5882B52DCD6CA832A"
            + "7DA57BC50241F9E5BFDDC075DD9D32C7777100D736916CFC165D8D36E0634CD7"
            + "83A457DAF52CAD464C903B26062CAF937BB40E37DADED9EDA401050E49C8AD0C"
            + "6970876B9AAD1B7A50BB4863A11E574AF1FE3C5975161D73DE4C3AF621FB1EFB";
    private static final String HEX_DE_B =
        "74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"
            + "01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"
            + "44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"
            + "8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539";
    private static final String HEX_RA_POINT =
        "7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"
            + "A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599";
    private static final BigInteger R_A = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
    private static final BigInteger R_B = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
    /** 第三方（中间人）自采的一个 rB'，只用来做"改一个字节全盘皆变"的反例。 */
    private static final BigInteger R_B_OTHER = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);

    private static final int KLEN = 16;

    /** 前缀字节：发起方自己的标签 0x83，应答方 0x82（GmSSL 的 SM9_EXCH_*_CONFIRM）。 */
    private static final int PREFIX_A = 0x83;
    private static final int PREFIX_B = 0x82;

    /** 测试①：RA、deA、deB 三个已知答案对齐 GmSSL，并确认 Q 用的是<b>对方</b>的标识。 */
    @Test
    public void ephemeralPointAndBothPrivateKeysMatchGmsslAnswers()
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        Assert.assertEquals("04" + HEX_RA_POINT, Calc.hex(Sm9Math.pointToOctets(ra)).toUpperCase());

        // 同样的 rA、如果把标识写成自己的，得到的就是另一个点 —— "Q 用对方 ID"是可验证的事实
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(ra),
            Sm9Math.pointToOctets(Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_A))));

        // RB 没有现成样例，但它必须等于 rB·Q_A，而 Q_A = (H1(Alice,0x02)+ke)·P1
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);
        Assert.assertTrue(Sm9Math.pointIsOnCurve(rb));
        BigInteger[] qA = Sm9Math.pointMul(
            Sm9Math.modnAdd(Sm9Math.hash1(ID_ALICE, Sm9Math.HID_EXCH), HEX_KEX), Sm9Math.P1);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(R_B, qA))),
            Calc.hex(Sm9Math.pointToOctets(rb)));

        // 两把交换私钥（hid = 0x02）都必须是 G₂ 上的点，且与标准答案一字不差
        BigInteger[][] deA = Sm9Math.privateKeyExtract(HEX_KEX, ID_ALICE, Sm9Math.HID_EXCH);
        BigInteger[][] deB = Sm9Math.privateKeyExtract(HEX_KEX, ID_BOB, Sm9Math.HID_EXCH);
        Assert.assertEquals("04" + HEX_DE_A, Calc.hex(Sm9Math.twistToOctets(deA)).toUpperCase());
        Assert.assertEquals("04" + HEX_DE_B, Calc.hex(Sm9Math.twistToOctets(deB)).toUpperCase());
        Assert.assertTrue(Sm9Math.twistIsOnCurve(deA));
        Assert.assertTrue(Sm9Math.twistIsOnCurve(deB));
        log.info("RA = {}", Calc.hex(Sm9Math.pointToOctets(ra)));
    }

    /**
     * 测试②：两个角色各自算自己的三格 g，<b>字节必须完全相同</b>，sk 也因此相同。
     * 顺手再证明 g1 = e(P1,P2)^{ke·rA}、g2 = e(P1,P2)^{ke·rB} —— 双线性把 de 里的除法抵消掉。
     */
    @Test
    public void bothRolesProduceTheSameBytesAndTheSameSessionKey()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);

        byte[][] gInitiator = new byte[3][];
        byte[][] rInitiator = new byte[2][];
        byte[] skA = Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rb, KLEN, gInitiator, rInitiator);

        byte[][] gResponder = new byte[3][];
        byte[][] rResponder = new byte[2][];
        byte[] skB = Sm9Math.exchSessionKey(false, HEX_KEX, ID_BOB, ID_ALICE, R_B, rb, ra, KLEN, gResponder, rResponder);

        // 三格 g 逐格相同，线上消息的顺序（A 的 RA 在前）也相同
        for (int i = 0; i < 3; i++)
        {
            Assert.assertEquals("g" + (i + 1) + " 两边必须同一段 384 字节",
                Calc.hex(gInitiator[i]), Calc.hex(gResponder[i]));
            Assert.assertEquals(384, gInitiator[i].length);
        }
        Assert.assertArrayEquals(rInitiator[0], rResponder[0]);
        Assert.assertArrayEquals(rInitiator[1], rResponder[1]);
        Assert.assertEquals(64, rInitiator[0].length);
        Assert.assertArrayEquals("会话密钥必须一致", skA, skB);

        // 双线性证明：g1 只该是 ke·rA 的函数，g2 只该是 ke·rB 的函数
        BigInteger[] base = Sm9Math.pairing(Sm9Math.P2, Sm9Math.P1);
        Assert.assertEquals(Calc.hex(gInitiator[0]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(HEX_KEX, R_A)))));
        Assert.assertEquals(Calc.hex(gInitiator[1]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(HEX_KEX, R_B)))));
        Assert.assertEquals(Calc.hex(gInitiator[2]), Calc.hex(Sm9Math.fp12ToBytes(
            Sm9Math.fp12Pow(base, Sm9Math.modnMul(Sm9Math.modnMul(HEX_KEX, R_A), R_B)))));
        log.info("sk = {}", Calc.hex(skA));
    }

    /** 测试③：确认标签在两条<b>独立计算</b>之间互验通过，改任何一个字节都验不过。 */
    @Test
    public void confirmTagsCrossValidateAndBreakOnTampering()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rb = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);

        // 两个角色各跑一遍自己的计算，得到各自的 g/r 数组
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
        Assert.assertArrayEquals("B 的标签必须能被 A 复现", sb,
            Sm9Math.exchConfirmTag(gA[0], gA[1], gA[2], rA[0], rA[1], ID_ALICE, ID_BOB, PREFIX_B));
        Assert.assertArrayEquals("A 的标签必须能被 B 复现", sa,
            Sm9Math.exchConfirmTag(gB[0], gB[1], gB[2], rB[0], rB[1], ID_ALICE, ID_BOB, PREFIX_A));

        // 每一格输入动一下，标签就变 —— 标签绑定了 g1..g3、两个标识和两枚临时点
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
     */
    @Test
    public void substitutedEphemeralPointSplitsTheSessionKey()
        throws Exception
    {
        BigInteger[] ra = Sm9Math.exchEphemeral(HEX_KEX, ID_BOB, R_A);
        BigInteger[] rbHonest = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B);
        BigInteger[] rbEvil = Sm9Math.exchEphemeral(HEX_KEX, ID_ALICE, R_B_OTHER);
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(rbHonest), Sm9Math.pointToOctets(rbEvil)));

        byte[][] gHonest = new byte[3][];
        byte[][] rHonest = new byte[2][];
        byte[] skHonest = Sm9Math.exchSessionKey(true, HEX_KEX, ID_ALICE, ID_BOB, R_A, ra, rbHonest, KLEN, gHonest, rHonest);

        byte[][] gVictim = new byte[3][];
        byte[][] rVictim = new byte[2][];
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

    /** 改一个字节（用于"任何输入都绑进标签"的断言）。 */
    private static byte[] tamper(byte[] buf)
    {
        byte[] out = buf.clone();
        out[out.length - 1] ^= 0x01;
        return out;
    }
}
