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
import org.junit.Assert;
import org.junit.Test;

/**
 * SM9 标识加密 IBBE（GB/T 32915.3）的本质计算 —— 面向过程版。
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
 *
 * <p>拿到 w 之后就没有密码学了：K = KDF(C1_x‖C1_y‖w‖ID) 是一段 SM3 计数器流，
 * <b>C2 = M ⊕ K 只有一次异或</b>（没有分组密码！），C3 = HMAC-SM3(key = K 尾部 32 字节, 消息 = C2)。
 * 于是 K 必须一次取"明文长度 + 32"字节 —— 与 GmSSL 的 sm9_do_encrypt 完全一致。
 */
@Slf4j
public class Sm9EncryptEssenceTest
{
    /** GmSSL tests/sm9test.c 的加密样例：ID = "Bob"，消息 20 字节。 */
    private static final byte[] ID_BOB = "Bob".getBytes();
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final byte[] MESSAGE = "Chinese IBS standard".getBytes();
    private static final BigInteger HEX_KE = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

    /** 标准答案 de = ke/(ke+H1(Bob,0x03))·P2（GmSSL: hex_de，四行 = x₁,x₀,y₁,y₀）。 */
    private static final String HEX_DE =
        "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683"
            + "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158"
            + "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F"
            + "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1";

    /** 加密的临时随机数 r（GmSSL 现采；这里固定，好让 C1、K 能逐字节复算）。 */
    private static final BigInteger R = new BigInteger("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", 16);

    /** KDF 输出的对称密钥长度。GmSSL 的 sm9_kem_encrypt 直接收 klen，这里取 16 字节够用。 */
    private static final int KLEN = 16;

    /** 测试①：私钥提取对齐 hex_de，并确认它真的是 G₂ 上的 n 阶点。 */
    @Test
    public void encryptionPrivateKeyMatchesGmsslAnswer()
    {
        BigInteger[][] de = Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC);

        Assert.assertEquals("04" + HEX_DE, Calc.hex(Sm9Math.twistToOctets(de)).toUpperCase());
        Assert.assertTrue("de 必须在 E'(Fp2): y² = x³ + 5u 上", Sm9Math.twistIsOnCurve(de));
        Assert.assertTrue("n·de 必须是无穷远点", Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, de)));

        // 同一个 ke、同一个 Bob，换个 hid 就是另一把私钥：加密私钥绝不能拿来签名或交换
        Assert.assertFalse(Arrays.equals(Sm9Math.twistToOctets(de),
            Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_SIGN))));
        // 换个标识就是另一把私钥 —— 这就是"标识即公钥"
        Assert.assertFalse(Arrays.equals(Sm9Math.twistToOctets(de),
            Sm9Math.twistToOctets(Sm9Math.privateKeyExtract(HEX_KE, ID_ALICE, Sm9Math.HID_ENC))));
        log.info("de = {}", Calc.hex(Sm9Math.twistToOctets(de)));
    }

    /**
     * 测试②：KEM 两侧对齐，并把"双线性把分母消掉"这件事写成字节断言：
     * 加密侧 {@code e(Ppube,P2)^r} 与解密侧 {@code e(C1,de)} 必须是同一段 384 字节。
     */
    @Test
    public void kemRoutesAgreeBecausePairingCancelsTheDenominator()
        throws Exception
    {
        byte[] out = Sm9Math.kemEncrypt(HEX_KE, ID_BOB, KLEN, R);
        Assert.assertEquals(65 + KLEN, out.length);
        byte[] c1 = Arrays.copyOfRange(out, 0, 65);
        byte[] kEncrypt = Arrays.copyOfRange(out, 65, out.length);

        // 解密侧只拿 C1 和 de，必须还原出同一段 K
        byte[] kDecrypt = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, KLEN, c1);
        Assert.assertArrayEquals(kEncrypt, kDecrypt);
        Assert.assertFalse("KDF 不能吐出全零（GmSSL 为此重采 r）", isAllZero(kDecrypt));

        // C1 = r·Q = r·(H1+ke)·P1 —— 两条路线同一个点
        BigInteger[] q = Sm9Math.kemQ(HEX_KE, ID_BOB);
        Assert.assertEquals(Calc.hex(Sm9Math.pointToOctets(Sm9Math.pointMul(R, q))), Calc.hex(c1));
        Assert.assertEquals(Calc.hex(c1), Calc.hex(Sm9Math.pointToOctets(
            Sm9Math.pointMul(Sm9Math.modnMul(R, Sm9Math.modnAdd(Sm9Math.hash1(ID_BOB, Sm9Math.HID_ENC), HEX_KE)),
                Sm9Math.P1))));

        // 双线性证据：e(C1, de) = e(P1,P2)^{ke·r} = e(Ppube,P2)^r
        BigInteger[] wDecrypt = Sm9Math.pairing(
            Sm9Math.privateKeyExtract(HEX_KE, ID_BOB, Sm9Math.HID_ENC), Sm9Math.pointFromOctets(c1));
        BigInteger[] wEncrypt = Sm9Math.fp12Pow(
            Sm9Math.pairing(Sm9Math.P2, Sm9Math.encMasterPublicKey(HEX_KE)), R);
        Assert.assertEquals(Calc.hex(Sm9Math.fp12ToBytes(wEncrypt)), Calc.hex(Sm9Math.fp12ToBytes(wDecrypt)));

        // KDF 是前缀流：先要 52 字节，再要 16 字节，前 16 字节必须一致（GmSSL 就靠这一点
        // 让 sm9_do_encrypt 用 sizeof(K) 全长取 K，而只用前 inlen+32 个字节）
        byte[] longK = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, MESSAGE.length + 32, c1);
        Assert.assertArrayEquals(kDecrypt, Arrays.copyOfRange(longK, 0, KLEN));
        log.info("C1 = {} K = {}", Calc.hex(c1), Calc.hex(kDecrypt));
    }

    /**
     * 测试③：完整 IBBE 往返，并把 C2/C3 的来历逐字节复算 ——
     * C2 只是 M ⊕ K 的前段，C3 只是对 C2 的 HMAC-SM3，密钥是 K 的尾部 32 字节。
     */
    @Test
    public void ciphertextIsJustXorPlusHmacOverTheTailOfK()
        throws Exception
    {
        byte[] ct = Sm9Math.encrypt(HEX_KE, ID_BOB, MESSAGE, R);
        Assert.assertEquals(65 + 32 + MESSAGE.length, ct.length);
        byte[] c1 = Arrays.copyOfRange(ct, 0, 65);
        byte[] c3 = Arrays.copyOfRange(ct, 65, 97);
        byte[] c2 = Arrays.copyOfRange(ct, 97, ct.length);

        // 解密侧独立复算 K（长度 = 明文 + 32）
        byte[] k = Sm9Math.kemDecrypt(HEX_KE, ID_BOB, MESSAGE.length + 32, c1);
        Assert.assertArrayEquals("C2 = M ⊕ K[0..len)",
            Calc.xor(Arrays.copyOfRange(k, 0, MESSAGE.length), MESSAGE), c2);
        Assert.assertArrayEquals("C3 = HMAC-SM3(K[len..len+32], C2)",
            Sm9Math.hmacSm3(Arrays.copyOfRange(k, MESSAGE.length, k.length), c2), c3);

        // 正常路径
        Assert.assertArrayEquals(MESSAGE, Sm9Math.decrypt(HEX_KE, ID_BOB, c1, c2, c3));

        // 改 C2 的一个字节：异或会跟着翻一位，但 HMAC 先拦下它
        byte[] tamperedC2 = c2.clone();
        tamperedC2[0] ^= 0x01;
        Assert.assertTrue("C2 被改必须抛异常", decryptThrows(HEX_KE, ID_BOB, c1, tamperedC2, c3));

        // 改 C3：MAC 直接对不上
        byte[] tamperedC3 = c3.clone();
        tamperedC3[31] ^= 0x01;
        Assert.assertTrue("C3 被改必须抛异常", decryptThrows(HEX_KE, ID_BOB, c1, c2, tamperedC3));

        // 换收件人：标识是公钥的一部分，拿 Alice 的私钥解 Bob 的密文只会 MAC 失败
        Assert.assertTrue("标识不符必须拒绝", decryptThrows(HEX_KE, ID_ALICE, c1, c2, c3));

        // C1 不在曲线上（比如被人塞了个乱点）也要被拒绝：这是 GmSSL B1 步的群成员检查
        byte[] bogusC1 = Sm9Math.pointToOctets(Sm9Math.pointAdd(Sm9Math.pointFromOctets(c1), Sm9Math.P1));
        bogusC1[40] ^= 0x01;   // 破坏 y，得到一个不在曲线上的"点"
        Assert.assertTrue("C1 不在 G₁ 上必须拒绝", decryptThrows(HEX_KE, ID_BOB, bogusC1, c2, c3));
        log.info("密文 {} 字节 = C1(65) ‖ C3(32) ‖ C2({})", ct.length, MESSAGE.length);
    }

    /**
     * 测试④：密文的 DER 结构对齐 GmSSL 的 sm9_ciphertext_to_der：
     * {@code SEQUENCE { INTEGER 0 (XOR 模式), BIT STRING C1(65), OCTET STRING C3(32), OCTET STRING C2 }}。
     * 注意顺序是 C1、C3、C2 —— 标准的 ASN.1 布局把 MAC 放在明文前面。
     */
    @Test
    public void ciphertextDerKeepsTypeZeroC1C3ThenC2()
        throws Exception
    {
        byte[] ct = Sm9Math.encrypt(HEX_KE, ID_BOB, MESSAGE, R);
        byte[] c1 = Arrays.copyOfRange(ct, 0, 65);
        byte[] c3 = Arrays.copyOfRange(ct, 65, 97);
        byte[] c2 = Arrays.copyOfRange(ct, 97, ct.length);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(0));
        vector.add(new DERBitString(c1));
        vector.add(new DEROctetString(c3));
        vector.add(new DEROctetString(c2));
        byte[] der = new DERSequence(vector).getEncoded();

        ASN1Sequence parsed = ASN1Sequence.getInstance(der);
        Assert.assertEquals(4, parsed.size());
        Assert.assertEquals(0, ASN1Integer.getInstance(parsed.getObjectAt(0)).getValue().signum());
        byte[] parsedC1 = ASN1BitString.getInstance(parsed.getObjectAt(1)).getOctets();
        Assert.assertArrayEquals(c1, parsedC1);
        Assert.assertEquals(65, parsedC1.length);
        Assert.assertEquals(0x04, parsedC1[0] & 0xff);
        Assert.assertArrayEquals(c3, ASN1OctetString.getInstance(parsed.getObjectAt(2)).getOctets());
        Assert.assertArrayEquals(c2, ASN1OctetString.getInstance(parsed.getObjectAt(3)).getOctets());
        log.info("SM9 密文 DER {} 字节", der.length);
    }

    /** 全零判定（GmSSL 用 mem_is_zero 挡下 KDF 退化）。 */
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

    /** 期望解密抛 IllegalArgumentException（C3 校验或群成员检查失败），返回"有没有抛"。 */
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
