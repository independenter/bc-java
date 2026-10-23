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
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 签名（GB/T 32915.2）的本质计算 —— 面向过程版。
 *
 * <p>整套协议只有 5 行公式，配对是唯一的新东西（{@link Sm9Math#pairing}，已由
 * {@link Sm9PairingEssenceTest} 用 GmSSL 的三组 384 字节样例验过）：
 * <pre>
 *   主公钥  Ppubs = ks·P2 ∈ G₂            主私钥 ks 只在 KGC 手里
 *   私钥    ds = ks·(ks + H1(ID,0x01))⁻¹·P1 ∈ G₁   ← 标识 ID 进了分母，这就是"基于标识"
 *   签名    g = e(P1,Ppubs);  w = g^r;  h = H2(M‖w);  l = (r−h) mod n;  S = l·ds
 *   验签    P' = H1(ID,0x01)·P2 + Ppubs;  u = e(S,P');  t = g^h;  w = u·t;  核对 h == H2(M‖w)
 * </pre>
 *
 * <p><b>验签为什么成立</b>（本文件用断言把这条推导逐字节跑出来）：
 * <pre>
 *   u = e(l·ds, H1·P2 + ks·P2)
 *     = e( l·ks/(ks+H1)·P1 , (H1+ks)·P2 )
 *     = e(P1,P2)^{ l·ks/(ks+H1) · (H1+ks) }      ← 双线性把两个标量提到指数上
 *     = e(P1,P2)^{ l·ks } = g^l
 *   w = u·t = g^l · g^h = g^{l+h} = g^r           ← l = r−h，除法在指数里被完全抵消
 * </pre>
 * 所以验签方拿不到 ks 也算不出 ds（那需要解 e(P1,P2) 上的离散对数），但两边算出的 w 必然同一。
 *
 * <p>文件后半部分是<b>"r 一旦重用，私钥就当场掉出来"</b>：签名式子 S = (r−h)·ds 对 ds 是
 * 一次方程，两个用同一个 r 的签名相减就把 r 消掉了 —— 与 SM2 那套 k 重用攻击同构，
 * 只是这里解出来的是<b>点</b> ds 本身（在标识密码里，拿到这个点就等于能签名）。
 */
@Slf4j
public class Sm9SignEssenceTest
{
    /** GmSSL tests/sm9test.c 的签名样例：ID = "Alice"，消息 = "Chinese IBS standard"。 */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final byte[] ID_BOB = "Bob".getBytes();
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();
    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);

    /** 标准答案 ds = ks/(ks+H1(Alice,0x01))·P1（GmSSL: hex_ds，两行 = x、y）。 */
    private static final String HEX_DS =
        "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
            + "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3";

    /** 签名的随机数 r。GmSSL 用 sm9_z256_rand_range 现采，这里固定下来好让 h、S 能逐字节复算。 */
    private static final BigInteger R = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);
    private static final BigInteger R_OTHER = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);

    /**
     * 测试①：私钥提取对上 GmSSL 的已知答案，并且把 H1 的"取前 40 字节、模 n−1 再加 1"
     * 这套细节独立复算一遍 —— 少一个字节、多一个 1，ds 就不是标准里那个点。
     */
    @Test
    public void privateKeyExtractMatchesGmsslAnswerAndHash1StaysInRange()
        throws Exception
    {
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);

        // 已知答案：ds 的 0x04‖x‖y 编码必须与 hex_ds 逐字符相同
        Assert.assertEquals("04" + HEX_DS, Calc.hex(Sm9Math.pointToOctets(ds)).toUpperCase());
        Assert.assertTrue("ds 必须在 E(Fp) 上", Sm9Math.pointIsOnCurve(ds));
        Assert.assertEquals("n·ds 必须是无穷远点", 0, Sm9Math.pointMul(Sm9Math.N, ds).length);

        // 手工复算 H1(Alice, 0x01)：SM3(0x01‖ID‖hid‖1) ‖ SM3(0x01‖ID‖hid‖2) = 64 字节
        byte[] head = Calc.concat(new byte[]{ 0x01 }, ID_ALICE, new byte[]{ (byte) Sm9Math.HID_SIGN });
        byte[] ha = Calc.concat(
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 })));
        // 只用前 40 字节（320 bit）当整数；对 n−1 取模后 +1，值域落在 [1, n−1]
        BigInteger z = Calc.toBigInt(Arrays.copyOfRange(ha, 0, 40));
        BigInteger expected = z.mod(Sm9Math.N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        Assert.assertEquals(expected, Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN));
        Assert.assertTrue("H1 必须 >= 1", Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN).compareTo(BigInteger.ONE) >= 0);
        Assert.assertTrue("H1 必须 <= n−1", Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN).compareTo(Sm9Math.N) < 0);

        // 那个 "+1" 不是装饰：H1 = 0 会让 P' = Ppubs，签名式里的除法也会失控。
        // hid 存在的全部理由：同一个主密钥、同一个标识，三个用途导出三把不同的私钥。
        BigInteger h1 = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN);
        BigInteger h1x = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_EXCH);
        BigInteger h1e = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_ENC);
        Assert.assertFalse(h1.equals(h1x));
        Assert.assertFalse(h1.equals(h1e));
        Assert.assertFalse(h1x.equals(h1e));
        // 标识不同 => H1 不同 => 私钥不同（"公钥就是那串字节"的代价是标识一字不能错）
        Assert.assertFalse(h1.equals(Sm9Math.hash1(ID_BOB, Sm9Math.HID_SIGN)));
        log.info("ds = {}", Calc.hex(Sm9Math.pointToOctets(ds)));
    }

    /**
     * 测试②：把"验签为什么成立"写成断言 —— 签名侧的 w = g^r 与验签侧的 w = e(S,P')·g^h
     * 必须是<b>同一段 384 字节</b>，并且 S 确实等于 (r−h)·ds。
     */
    @Test
    public void signerAndVerifierComputeTheSame384ByteW()
        throws Exception
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);

        Assert.assertEquals("签名 = h(32) ‖ S(65)", 97, signature.length);
        BigInteger h = Calc.toBigInt(Arrays.copyOfRange(signature, 0, 32));
        BigInteger[] sPoint = Sm9Math.pointFromOctets(Arrays.copyOfRange(signature, 32, 97));

        // S = l·ds, l = (r − h) mod n —— 从签名反推回私钥的标量乘
        BigInteger l = Sm9Math.modnSub(R, h);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(sPoint)),
            Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(l, ds))));

        BigInteger[] g = Sm9Math.pairing(ppubs, Sm9Math.P1);

        // 路线一（签名方）：w = g^r
        byte[] wSigner = Sm9Math.fp12ToBytes(Sm9Math.fp12Pow(g, R));
        // 路线二（验签方，手里只有 h、S、Ppubs）：w = e(S, H1·P2 + Ppubs) · g^h
        BigInteger[][] pPrime = Sm9Math.twistAffineAdd(
            Sm9Math.twistMul(Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN), Sm9Math.P2), ppubs);
        byte[] wVerifier = Sm9Math.fp12ToBytes(
            Sm9Math.fp12Mul(Sm9Math.pairing(pPrime, sPoint), Sm9Math.fp12Pow(g, h)));

        Assert.assertEquals("两条路线必须给出同一个 384 字节的 w",
            Calc.hex(wSigner), Calc.hex(wVerifier));
        // H2 只是"前缀 0x02 + 消息 + w + 计数器"再走两遍 SM3。GmSSL 的流式 API
        // （sm9_sign_init/update/finish）不过是把这段拼接拆成多次喂入，字节上完全等价。
        byte[] head = Calc.concat(new byte[]{ 0x02 }, MESSAGE, wSigner);
        BigInteger hManual = Sm9Math.modnFromHash(Calc.concat(
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 }))));
        Assert.assertEquals(hManual, h);
        // w 相同 => H2(M‖w) 相同 => 验签通过
        Assert.assertTrue(Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));
        log.info("h = {}", Calc.hex(Calc.toBytes(h, 32)));
    }

    /**
     * 测试③：四种篡改都必须被拒。每种都换成"仍然是合法群元素、但数值不对"的形式，
     * 这样断言只可能因为算法被拒，不会因为碰到无穷远点之类而偶然抛异常。
     */
    @Test
    public void verifyRejectsChangedMessageWrongIdAndShiftedSignature()
        throws Exception
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);

        Assert.assertTrue("原签名必须通过",
            Sm9Math.verify(MESSAGE, signature, ID_ALICE, ppubs));

        // 1) 消息改一个字节：H2 变，h 对不上
        byte[] tamperedMessage = MESSAGE.clone();
        tamperedMessage[tamperedMessage.length - 1] ^= 0x01;
        Assert.assertFalse(Sm9Math.verify(tamperedMessage, signature, ID_ALICE, ppubs));

        // 2) 标识换成 Bob：H1 变，P' 变 —— 标识密码里"读错公钥"就是这么贵
        Assert.assertFalse(Sm9Math.verify(MESSAGE, signature, ID_BOB, ppubs));

        // 3) 签名点加一个 P1：S' = S + P1 = (l + 1)·ds 仍在 n 阶群里，但 w 变了
        byte[] shiftedS = Sm9Math.pointToOctets(
            Sm9Math.pointAdd(Sm9Math.pointFromOctets(Arrays.copyOfRange(signature, 32, 97)), Sm9Math.P1));
        Assert.assertFalse(Sm9Math.verify(MESSAGE,
            Calc.concat(Arrays.copyOfRange(signature, 0, 32), shiftedS), ID_ALICE, ppubs));

        // 4) h 的最后一位改掉：l 变，S 也跟不上
        byte[] bumpedH = signature.clone();
        bumpedH[31] = (byte) (bumpedH[31] ^ 0x01);
        Assert.assertFalse(Sm9Math.verify(MESSAGE, bumpedH, ID_ALICE, ppubs));
    }

    /** 测试④：另一个 r 同样能签成 —— 顺带说明签名对 r 敏感（同一 r 同一消息则完全确定）。 */
    @Test
    public void anotherNonceProducesADifferentButValidSignature()
        throws Exception
    {
        BigInteger[][] ppubs = Sm9Math.signMasterPublicKey(HEX_KS);
        byte[] first = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] second = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R_OTHER);

        Assert.assertTrue(Sm9Math.verify(MESSAGE, second, ID_ALICE, ppubs));
        Assert.assertFalse("r 不同则 w、h、S 全不同", Arrays.equals(first, second));
        // S = (r−h)·ds：换了 r，S 必然换点（同一 r、同一消息才谈得上"确定性"）
        Assert.assertFalse(Arrays.equals(Arrays.copyOfRange(first, 32, 97),
            Arrays.copyOfRange(second, 32, 97)));
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
    @Test
    public void reusedRandomLeaksThePrivateKeyPoint()
        throws Exception
    {
        byte[] otherMessage = "Chinese IBS standarD".getBytes();  // 只改最后一个字节
        byte[] sig1 = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] sig2 = Sm9Math.sign(otherMessage, ID_ALICE, HEX_KS, R);

        BigInteger h1 = Calc.toBigInt(Arrays.copyOfRange(sig1, 0, 32));
        BigInteger h2 = Calc.toBigInt(Arrays.copyOfRange(sig2, 0, 32));
        Assert.assertFalse("消息不同则 h 不同", h1.equals(h2));

        BigInteger[] s1 = Sm9Math.pointFromOctets(Arrays.copyOfRange(sig1, 32, 97));
        BigInteger[] s2 = Sm9Math.pointFromOctets(Arrays.copyOfRange(sig2, 32, 97));
        BigInteger[] diff = Sm9Math.pointAdd(s1, Sm9Math.pointNeg(s2));
        BigInteger coefficient = Sm9Math.modnSub(h2, h1);          // = h₂ − h₁ ≡ l₁ − l₂ (mod n)
        Assert.assertTrue("系数为 0 就解不出来（等价于两条消息同哈希）", coefficient.signum() != 0);

        BigInteger[] recovered = Sm9Math.pointMul(Sm9Math.modnInv(coefficient), diff);
        Assert.assertEquals("04" + HEX_DS, Calc.hex(Sm9Math.pointToOctets(recovered)).toUpperCase());
        log.info("同一个 r 签两条消息 => 直接解出私钥点 ds");
    }

    /**
     * 测试⑥：签名的 DER 结构对齐 GmSSL 的 sm9_signature_to_der / GM/T 0080-2020：
     * {@code SEQUENCE { OCTET STRING h(32), BIT STRING S(65) }}。
     */
    @Test
    public void signatureDerWrapsOctetHAndBitStringS()
        throws Exception
    {
        byte[] signature = Sm9Math.sign(MESSAGE, ID_ALICE, HEX_KS, R);
        byte[] h = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 97);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DEROctetString(h));
        vector.add(new DERBitString(s));
        byte[] der = new DERSequence(vector).getEncoded();

        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        Assert.assertEquals(2, parsed.size());
        Assert.assertArrayEquals(h, ASN1OctetString.getInstance(parsed.getObjectAt(0)).getOctets());
        byte[] fromBitString = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        Assert.assertArrayEquals(s, fromBitString);
        Assert.assertEquals(65, fromBitString.length);
        Assert.assertEquals(0x04, fromBitString[0] & 0xff);
        // BIT STRING 的内容第一个字节是"填充位数"，65 字节正好是整字节，所以必须是 0
        byte[] bitStringEncoding = ASN1BitString.getInstance(parsed.getObjectAt(1)).getEncoded();
        Assert.assertEquals(0x03, bitStringEncoding[0] & 0xff);
        Assert.assertEquals(0, bitStringEncoding[2] & 0xff);
        log.info("SM9 签名 DER {} 字节", der.length);
    }
}
