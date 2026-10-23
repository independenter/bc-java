package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Random;

import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 最难的那一块 —— <b>Fp12 塔与 ate 配对</b> —— 的过程版实现与验证。
 *
 * <p>SM9 是"基于标识"的密码：没有证书，公钥就是用户的标识（一串字节）。之所以行得通，
 * 全靠一对满足双线性／非退化／可计算的映射：
 * <pre>
 *   e: G₁ × G₂ → Fp12*,   e(a·P, b·Q) = e(P, Q)^{ab}
 * </pre>
 * G₁ = E(Fp): y² = x³ + 5，G₂ = E'(Fp2): y² = x³ + 5u。两个群都取 n 阶。
 * 有了这条式子，"标量乘法"就能被搬到 Fp12 的"普通幂"上比较，于是
 * {@code e(ks/(ks+H1)·P1, (H1+ks)·P2) = e(P1,P2)^{ks}} —— 私钥提取里那个刺眼的除法被抵消掉了。
 *
 * <p>本测试用 GmSSL（GB/T 32915 的参考实现）{@code tests/sm9test.c} 里的<b>三组真实样例</b>
 * 当裁判：配对结果是一个 Fp12 元素，展平成 384 字节。只要有一个常数（α、β、abits、
 * 线函数的下标）抄反，384 字节就会全部对不上，所以这三组样例是极强的证据。
 */
@Slf4j
public class Sm9PairingEssenceTest
{
    /** 标准样例里 Alice 的标识与签名主私钥 ks（GmSSL: hex_ks）。 */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
    /** 密钥交换用的主私钥（GmSSL: hex_kex），它的 ke·P1 就是标准样例里的 hex_Ppube。 */
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);

    /** e(P1, ks·P2) 的期望值：12 行、每行一个 Fp 系数，顺序是 c₁₁ 递减到 c₀（与 GmSSL 的序列化一致）。 */
    private static final String PAIRING1 =
        "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d"
            + "28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000"
            + "38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f"
            + "a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db"
            + "67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f"
            + "5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6"
            + "1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b"
            + "93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439"
            + "b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d"
            + "4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b"
            + "84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a"
            + "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb";

    /** hex_deB（G₂ 私钥点，4 行 = x₁,x₀,y₁,y₀）与 hex_RA（G₁ 点）配对得到的 e(RA, deB)。 */
    private static final String DE_B =
        "74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"
            + "01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"
            + "44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"
            + "8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539";
    private static final String RA_POINT =
        "7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"
            + "A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599";
    private static final String PAIRING2 =
        "28542FB6954C84BE6A5F2988A31CB6817BA0781966FA83D9673A9577D3C0C134"
            + "5E27C19FC02ED9AE37F5BB7BE9C03C2B87DE027539CCF03E6B7D36DE4AB45CD1"
            + "A1ABFCD30C57DB0F1A838E3A8F2BF823479C978BD137230506EA6249C891049E"
            + "3497477913AB89F5E2960F382B1B5C8EE09DE0FA498BA95C4409D630D343DA40"
            + "4FEC93472DA33A4DB6599095C0CF895E3A7B993EE5E4EBE3B9AB7D7D5FF2A3D1"
            + "647BA154C3E8E185DFC33657C1F128D480F3F7E3F16801208029E19434C733BB"
            + "73F21693C66FC23724DB26380C526223C705DAF6BA18B763A68623C86A632B05"
            + "0F63A071A6D62EA45B59A1942DFF5335D1A232C9C5664FAD5D6AF54C11418B0D"
            + "8C8E9D8D905780D50E779067F2C4B1C8F83A8B59D735BB52AF35F56730BDE5AC"
            + "861CCD9978617267CE4AD9789F77739E62F2E57B48C2FF26D2E90A79A1D86B93"
            + "9B1CA08F64712E33AEDA3F44BD6CB633E0F722211E344D73EC9BBEBC92142765"
            + "6BA584CE742A2A3AB41C15D3EF94EDEB8EF74A2BDCDAAECC09ABA567981F6437";

    /** e(Ppube, P2)^{rB}：交换协议里"应答方的那一格"。 */
    private static final String PPUBE_POINT =
        "9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"
            + "54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210";
    private static final BigInteger RB = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
    private static final String PAIRING3 =
        "1052D6E9D13E381909DFF7B2B41E13C987D0A9068423B769480DACCE6A06F492"
            + "5FFEB92AD870F97DC0893114DA22A44DBC9E7A8B6CA31A0CF0467265A1FB48C7"
            + "2C5C3B37E4F2FF83DB33D98C0317BCBBBBF4AC6DF6B89ECA58268B280045E612"
            + "6CED9E2D7C9CD3D5AD630DEFAB0B831506218037EE0F861CF9B43C78434AEC38"
            + "0AE7BF3E1AEC0CB67A03440906C7DFB3BCD4B6EEEBB7E371F0094AD4A816088D"
            + "98DBC791D0671CACA12236CDF8F39E15AEB96FAEB39606D5B04AC581746A663D"
            + "00DD2B7416BAA91172E89D5309D834F78C1E31B4483BB97185931BAD7BE1B9B5"
            + "7EBAC0349F8544469E60C32F6075FB0468A68147FF013537DF792FFCE024F857"
            + "10CC2B561A62B62DA36AEFD60850714F49170FD94A0010C6D4B651B64F3A3A5E"
            + "58C9687BEDDCD9E4FEDAB16B884D1FE6DFA117B2AB821F74E0BF7ACDA2269859"
            + "2A430968F16086061904CE201847934B11CA0F9E9528F5A9D0CE8F015C9AEA79"
            + "934FDDA6D3AB48C8571CE2354B79742AA498CB8CDDE6BD1FA5946345A1A652F6";

    /** 测试①：常数自检 —— 生成元真的在曲线上，而且阶正好是 n。 */
    @Test
    public void generatorsLieOnTheirCurvesAndHaveOrderN()
    {
        Assert.assertTrue("P1 必须满足 y² = x³ + 5", Sm9Math.pointIsOnCurve(Sm9Math.P1));
        Assert.assertTrue("n·P1 必须是无穷远点（空数组）",
            Sm9Math.pointMul(Sm9Math.N, Sm9Math.P1).length == 0);
        Assert.assertTrue("P2 必须满足 twisted 曲线 y² = x³ + 5u", Sm9Math.twistIsOnCurve(Sm9Math.P2));
        Assert.assertTrue("n·P2 必须是无穷远点", Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, Sm9Math.P2)));
        Assert.assertTrue("n 是素数", Sm9Math.N.isProbablePrime(64));
        Assert.assertFalse("p ≠ n：素数域与标量域是两回事", Sm9Math.P.equals(Sm9Math.N));

        log.info("[SM9-常数] p 有 {} bit，n 有 {} bit，P1/P2 都在自己的曲线上且阶为 n",
            Sm9Math.P.bitLength(), Sm9Math.N.bitLength());
    }

    /**
     * 测试②：塔的三条规则 —— 每一次扩张只引入一条关系：u²=−2、v²=u、w³=v。
     * 整个 Fp12 的全部算术（几百行乘法）说到底只是这三条 + 普通多项式乘法。
     */
    @Test
    public void towerRulesInverseAndDistributivity()
    {
        // u² = −2（Fp2）
        BigInteger[] u = new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE };
        Assert.assertTrue("u² 必须等于 −2", Sm9Math.fp2IsZero(Sm9Math.fp2Add(Sm9Math.fp2Sqr(u),
            new BigInteger[]{ BigInteger.valueOf(2), BigInteger.ZERO })));

        // v² = u（Fp4）：v 是"只有 v 分量、且那个 Fp2 分量等于 1"的元素
        BigInteger[] v = new BigInteger[]{ BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO };
        BigInteger[] vSquaredExpect = new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO };
        Assert.assertTrue("v² 必须等于 u", java.util.Arrays.equals(Sm9Math.fp4Sqr(v), vSquaredExpect));

        // w³ = v（Fp12）：w 落在下标 4，v 落在下标 2
        BigInteger[] w = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            w[i] = BigInteger.ZERO;
        }
        w[4] = BigInteger.ONE;
        BigInteger[] vIn12 = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            vIn12[i] = BigInteger.ZERO;
        }
        vIn12[2] = BigInteger.ONE;
        Assert.assertTrue("w³ 必须等于 v", Sm9Math.fp12Equals(
            Sm9Math.fp12Mul(w, Sm9Math.fp12Mul(w, w)), vIn12));

        Random rnd = new Random(20261022L);
        for (int i = 0; i < 5; i++)
        {
            BigInteger[] x = randomFp12(rnd);
            BigInteger[] y = randomFp12(rnd);
            BigInteger[] zz = randomFp12(rnd);

            // 分配律：(x+y)·z = x·z + y·z —— 塔上的乘法确实是域乘法
            Assert.assertTrue("分配律必须成立", Sm9Math.fp12Equals(
                Sm9Math.fp12Mul(Sm9Math.fp12Add(x, y), zz),
                Sm9Math.fp12Add(Sm9Math.fp12Mul(x, zz), Sm9Math.fp12Mul(y, zz))));

            // 逆元：x·x⁻¹ = 1（一次 Fp12 逆 = 一次 Fp4 逆 + 若干 Fp2/Fp 逆）
            Assert.assertTrue("x·x⁻¹ 必须是 1",
                Sm9Math.fp12Equals(Sm9Math.fp12Mul(x, Sm9Math.fp12Inv(x)), Sm9Math.fp12One()));

            // 序列化往返：384 字节 <-> 12 个系数，必须严格互逆
            Assert.assertTrue("字节化必须严格互逆",
                Sm9Math.fp12Equals(x, Sm9Math.fp12FromBytes(Calc.unhex(Calc.hex(Sm9Math.fp12ToBytes(x))))));
        }
    }

    private static BigInteger[] randomFp12(Random rnd)
    {
        byte[] buf = new byte[384];
        rnd.nextBytes(buf);
        return Sm9Math.fp12FromBytes(buf);
    }

    /** 测试③：Frobenius —— "只乘常数"的捷径必须真的等于普通幂 x^p。 */
    @Test
    public void frobeniusMapsAgreeWithPlainExponentiation()
    {
        BigInteger p = Sm9Math.P;
        BigInteger p2 = p.multiply(p);
        BigInteger p6 = p2.multiply(p2).multiply(p2);
        Random rnd = new Random(20261021L);
        BigInteger[] x = randomFp12(rnd);
        for (int i = 0; i < 3; i++)
        {
            x = Sm9Math.fp12Mul(x, randomFp12(rnd));
            Assert.assertTrue("x^p 的快路径必须等于普通幂",
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius(x), Sm9Math.fp12Pow(x, p)));
            Assert.assertTrue("x^{p²} 同理", Sm9Math.fp12Equals(Sm9Math.fp12Frobenius2(x), Sm9Math.fp12Pow(x, p2)));
            Assert.assertTrue("x^{p⁶} 同理（最终幂的易算部分就靠它）",
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius6(x), Sm9Math.fp12Pow(x, p6)));
        }
    }

    /**
     * 测试④：配对的三组真实样例（GmSSL {@code test_sm9_z256_pairing}）。
     * 这三组各测一条路径：普通配对、非生成元的两点、配对后再取幂。
     */
    @Test
    public void pairingMatchesGmsslKnownAnswers()
    {
        BigInteger[] g = Sm9Math.pairing(Sm9Math.twistMul(HEX_KS, Sm9Math.P2), Sm9Math.P1);
        Assert.assertEquals("e(P1, ks·P2) 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g)), PAIRING1.toLowerCase());

        BigInteger[] g2 = Sm9Math.pairing(Sm9Math.twistFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(DE_B))),
            Sm9Math.pointFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(RA_POINT))));
        Assert.assertEquals("e(RA, deB) 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g2)), PAIRING2.toLowerCase());

        BigInteger[] g3 = Sm9Math.fp12Pow(Sm9Math.pairing(Sm9Math.P2,
            Sm9Math.pointFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(PPUBE_POINT)))), RB);
        Assert.assertEquals("e(Ppube, P2)^{rB} 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g3)), PAIRING3.toLowerCase());

        log.info("[SM9-配对] 三组 GmSSL 样例全部逐字节命中，e(P1,ks·P2) 的前 16 字节是 {}",
            Calc.hex(Sm9Math.fp12ToBytes(g)).substring(0, 32));
    }

    /**
     * 测试⑤：双线性 + 非退化 + 落到 n 阶子群 —— 这三条正是 SM9 全部协议的地基。
     */
    @Test
    public void pairingIsBilinearNonDegenerateAndLandsInOrderNGroup()
    {
        BigInteger a = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        BigInteger b = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

        BigInteger[] base = Sm9Math.pairing(Sm9Math.P2, Sm9Math.P1);
        BigInteger[] lhs = Sm9Math.pairing(Sm9Math.twistMul(b, Sm9Math.P2), Sm9Math.pointMul(a, Sm9Math.P1));
        BigInteger[] rhs = Sm9Math.fp12Pow(Sm9Math.fp12Pow(base, a), b);
        Assert.assertTrue("e(a·P1, b·P2) 必须等于 e(P1,P2)^{ab}", Sm9Math.fp12Equals(lhs, rhs));

        Assert.assertFalse("配对不能退化成 1，否则什么都证不了", Sm9Math.fp12Equals(base, Sm9Math.fp12One()));
        Assert.assertTrue("GT 元素的阶整除 n：g^n = 1",
            Sm9Math.fp12Equals(Sm9Math.fp12Pow(base, Sm9Math.N), Sm9Math.fp12One()));

        // 交叉验证标准里那条"抵消除法"的核心恒等式：e(ds, (h1+ks)·P2) = e(P1,P2)^{ks}
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);
        BigInteger h1 = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN);
        BigInteger[] left = Sm9Math.pairing(Sm9Math.twistMul(Sm9Math.modnAdd(h1, HEX_KS), Sm9Math.P2), ds);
        Assert.assertTrue("ds 与 (H1+ks)·P2 配对后，分母 (ks+H1) 必须被干净地抵消成 g^ks",
            Sm9Math.fp12Equals(left, Sm9Math.fp12Pow(base, HEX_KS)));

        log.info("[SM9-双线性] e(aP,bQ) = e(P,Q)^ab、g^n = 1、ds 里那个除法的抵消恒等式，三者全部成立");
    }

    /** 测试⑥：点的字节化 —— 65/129 字节的编排顺序（Fp2 先写 u 分量）最容易被写反。 */
    @Test
    public void pointEncodingsRoundTripAndMatchGmsslOrder()
    {
        byte[] p1 = Sm9Math.pointToOctets(Sm9Math.P1);
        Assert.assertEquals("G₁ 点是 0x04 打头的 65 字节", 65, p1.length);
        Assert.assertArrayEquals("再读回来必须一模一样", Sm9Math.P1, Sm9Math.pointFromOctets(p1));

        byte[] p2 = Sm9Math.twistToOctets(Sm9Math.P2);
        Assert.assertEquals("G₂ 点是 0x04 打头的 129 字节", 129, p2.length);
        // GmSSL 的顺序：x₁(高 u 分量) ‖ x₀ ‖ y₁ ‖ y₀
        Assert.assertEquals("第 1 段必须是 x 的 u 分量",
            Calc.hex(Calc.toBytes(Sm9Math.P2[0][1], 32)).toUpperCase(), Calc.hex(java.util.Arrays.copyOfRange(p2, 1, 33)).toUpperCase());
        BigInteger[][] back = Sm9Math.twistFromOctets(p2);
        Assert.assertTrue("G₂ 点往返必须落回同一点",
            Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[0], Sm9Math.P2[0]))
                && Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[1], Sm9Math.P2[1])));

        // 标准样例：kex·P1 就是 GmSSL 的 hex_Ppube，顺带确认交换测试那把主公钥的字节序
        byte[] ppube = Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KEX));
        Assert.assertEquals("kex·P1 必须等于 GmSSL 的 hex_Ppube",
            ("04" + PPUBE_POINT).toLowerCase(), Calc.hex(ppube));

        log.info("[SM9-序列化] G₁ 65 字节 / G₂ 129 字节 / Fp12 384 字节，三种编排都能严格往返");
    }
}
