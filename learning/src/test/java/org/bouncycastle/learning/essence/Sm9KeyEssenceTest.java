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
 * <p>KGC 手里只有两个数：签名主私钥 {@code ks}、加密主私钥 {@code ke}（都是 [1, n−1] 里的随机数）。
 * 公开出去的只有两个点：{@code Ppubs = ks·P2 ∈ G₂}、{@code Ppube = ke·P1 ∈ G₁}。
 * 私钥提取则是把用户标识代数进公式里：
 * <pre>
 *   ds = ks·(ks + H1(ID,0x01))⁻¹·P1        de = ke·(ke + H1(ID,0x03))⁻¹·P2
 * </pre>
 *
 * <p>DER 布局照 GmSSL：
 * <pre>
 *   签名主密钥  SEQUENCE { INTEGER ks,                 BIT STRING(129) Ppubs }
 *   加密主密钥  SEQUENCE { INTEGER ke,                 BIT STRING(65)  Ppube }
 *   签名用户私钥 SEQUENCE { BIT STRING(65) ds,          BIT STRING(129) Ppubs }
 *   加密用户私钥 SEQUENCE { BIT STRING(129) de,         BIT STRING(65)  Ppube }
 * </pre>
 * 那个 INTEGER 有个真实的坑：ks 是定长 32 字节，最高位可能是 0、首字节也可能本来就是 0x00，
 * 而 DER 的 INTEGER 是<b>有符号</b>的最短编码 —— GmSSL 专门有个
 * {@code test_sm9_master_key_from_der_leading_zero} 测试踩过这个雷。本文件的测试③就是把它写清楚：
 * 字节长度可以变，<b>值必须能一字不差地回到同一个标量</b>。
 */
@Slf4j
public class Sm9KeyEssenceTest
{
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final byte[] ID_BOB = "Bob".getBytes();
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();

    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
    private static final BigInteger HEX_KE = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);

    private static final String HEX_DS =
        "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
            + "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3";
    private static final String HEX_DE =
        "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683"
            + "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158"
            + "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F"
            + "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1";
    /** hex_kex·P1 就是标准样例里的 hex_Ppube（GmSSL: tests/sm9test.c）。 */
    private static final String HEX_PUBE =
        "9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"
            + "54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210";

    /** 测试①：主私钥的值域 —— 与 GmSSL 的 sm9_z256_rand_range 同构，>= n 就重采。 */
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

    /** 测试②：两个主公钥点 —— Ppubs ∈ G₂、Ppube ∈ G₁，且 Ppube 对上标准样例 hex_Ppube。 */
    @Test
    public void masterPublicKeysLieOnTheRightCurves()
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        Assert.assertTrue("Ppubs 必须在扭曲曲线上", Sm9Math.twistIsOnCurve(ppubs));
        Assert.assertTrue(Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, ppubs)));
        Assert.assertEquals(129, Sm9Math.twistToOctets(ppubs).length);

        BigInteger[] ppube = Sm9Math.encMasterPublicKey(HEX_KEX);
        Assert.assertTrue("Ppube 必须在 E(Fp) 上", Sm9Math.pointIsOnCurve(ppube));
        Assert.assertEquals(65, Sm9Math.pointToOctets(ppube).length);
        Assert.assertEquals("ke·P1 必须等于 GmSSL 的 hex_Ppube",
            "04" + HEX_PUBE, Calc.hex(Sm9Math.pointToOctets(ppube)).toUpperCase());

        // 加密主密钥 ke 的 Ppube 与交换用的 ke 是两个不同的主密钥（样例里 ke ≠ kex），
        // 所以两个点必须不同 —— 混用主密钥就等于混用了私钥
        Assert.assertFalse(Arrays.equals(Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KE)),
            Sm9Math.pointToOctets(ppube)));
        log.info("Ppube = {}", Calc.hex(Sm9Math.pointToOctets(ppube)));
    }

    /** 测试③：主密钥 DER —— INTEGER 是最短有符号编码，长度会变但值必须回得来。 */
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

    /** 测试④：用户私钥 DER 把私钥点和主公钥打包在一起（拿到它就能签/能解，不需要 ks、ke）。 */
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
     */
    @Test
    public void freshlyGeneratedMasterKeySignsAndVerifiesEndToEnd()
        throws Exception
    {
        BigInteger ks = Sm9Math.randScalar(new Random(20261021L));
        Assert.assertTrue(ks.compareTo(BigInteger.ONE) >= 0 && ks.compareTo(Sm9Math.N) < 0);

        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(ks);
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(ks, ID_ALICE);
        Assert.assertTrue(Sm9Math.pointIsOnCurve(ds));

        // 只把 ppubs（公钥）交给验签方：它不需要、也拿不到 ks
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, ks, Sm9Math.randScalar(new Random(991L)));
        Assert.assertTrue(Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));
        Assert.assertFalse("换个人就验不过", Sm9Math.verify(MESSAGE, signature, ID_BOB, ppubs));
    }
}
