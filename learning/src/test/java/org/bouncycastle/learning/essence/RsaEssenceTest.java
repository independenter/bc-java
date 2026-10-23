package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.junit.Assert;
import org.junit.Test;

/**
 * RSA 的本质计算 —— 面向过程版，覆盖全部填充/编码方案。
 *
 * <p>RSA 是最容易被讲复杂的算法：一旦把 Cipher / Signature / KeyPairGenerator / Padding
 * 这些对象搬进来，数学就看不见了。本类把它还原成三条事实：
 * <ol>
 *   <li><b>RSA = 一个模幂</b>：{@code c = m^e mod n}，私钥运算只是 {@code m = c^d mod n}，
 *       CRT 只是把这个模幂拆成两个半尺寸的模幂。</li>
 *   <li><b>密钥 = 一组整数</b>：{@code (n, e, d, λ, dp, dq, qInv, p, q)} 用一个数组表达，
 *       不需要 RSAPublicKey / RSAPrivateCrtKey 类型层次。</li>
 *   <li><b>安全性全部来自填充</b>：裸模幂是确定性且可延展的；所谓"模式"
 *       （NoPadding、PKCS#1 v1.5 type 1 / type 2、OAEP、PSS）都是作用在模幂之前的
 *       {@code byte[] -> byte[]} 普通静态方法，与模幂正交，所以可以自由换摘要、换组合。</li>
 * </ol>
 *
 * <p>面向对象如何被消掉（风格说明：按用户要求改成<b>面向过程</b> —— 没有 lambda，
 * 没有 {@code Function}/{@code UnaryOperator}，没有 {@code IntStream}，
 * 只有普通静态方法、真实的参数、{@code for}/{@code while} 和局部变量）：
 * <ul>
 *   <li>构造器 → 普通静态方法 {@code keyGen(p, q, e)}，参数一次给全；</li>
 *   <li>策略模式 / if-else 分发 → 几张按下标对齐的"值表"（字符串数组 + 字节数组 + 名字数组），
 *       用 {@code for} 下标循环逐行处理；</li>
 *   <li>SecureRandom 依赖注入 → 直接调用静态方法 {@code randomBytes(len)}；</li>
 *   <li>累加/迭代 → 老老实实的 {@code for}/{@code while} 循环加局部变量。</li>
 * </ul>
 * BC 与 JCE 全程只当"第三方裁判"：算是我们自己算的，答案交给它们核。
 */
@Slf4j
public class RsaEssenceTest
{
    // ---------------------------------------------------------------- 密钥元组的下标

    /** 密钥就是数字元组：下面 9 个下标说明它到底包含什么。 */
    private static final int N = 0, E = 1, D = 2, LAM = 3, DP = 4, DQ = 5, QINV = 6, PP = 7, PQ = 8;

    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /** 业界标准公开指数：费马素数 F4 = 2^16+1，二进制只有一个 1，所以公钥运算特别快。 */
    private static final BigInteger F4 = BigInteger.valueOf(65537);

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] EMPTY = new byte[0];

    // ---------------------------------------------------------------- 摘要：按名字选用的普通方法

    /** 摘要算法名（JCE MessageDigest 的名字），值表里存的就是这些字符串。 */
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SM3 = "SM3";

    /**
     * 摘要过程：给定算法名 + 消息，返回摘要字节 —— 一个带真实参数的普通静态方法。
     * checked 异常属于"副作用"，必须关在边界里，边界之外的代码就是一条直线，不再谈"纯函数"这件事。
     */
    private static byte[] digestOf(String algorithm, byte[] bytes)
    {
        try
        {
            return Calc.digest(algorithm, bytes);
        }
        catch (Exception e)
        {
            throw new IllegalStateException(algorithm, e);
        }
    }

    /** 摘要长度：空消息过一次摘要就知道，不需要 Digest 对象。 */
    private static int digestSize(String algorithm)
    {
        return digestOf(algorithm, EMPTY).length;
    }

    /** 随机字节：整个文件唯一需要的"随机源"，直接调用，不做依赖注入。 */
    private static byte[] randomBytes(int count)
    {
        byte[] b = new byte[count];
        RANDOM.nextBytes(b);
        return b;
    }

    // ---------------------------------------------------------------- 本质：平方-乘

    /**
     * 模幂 = 一个从指数高位到低位的 for 循环：每轮 {@code acc = acc² · base^bit mod n}。
     * 局部变量 acc 一路更新到底 —— 这个循环就是整个"快速幂"。
     */
    private static BigInteger powMod(BigInteger base, BigInteger exp, BigInteger n)
    {
        BigInteger acc = ONE;
        for (int bit = exp.bitLength() - 1; bit >= 0; bit--)
        {
            acc = acc.multiply(acc).mod(n);
            if (exp.testBit(bit))
            {
                acc = acc.multiply(base).mod(n);
            }
        }
        return acc;
    }

    /**
     * 密钥生成只有三步算术：{@code n = pq}，{@code λ = lcm(p-1, q-1)}，{@code d = e⁻¹ mod λ}；
     * 再把 CRT 加速需要的三个分量 dp / dq / qInv 一起算出来，九个整数按顺序放进数组。
     * 注意用 λ（Carmichael 函数）而不是 φ —— 这才是最小可用的指数模数。
     */
    private static BigInteger[] keyGen(BigInteger p, BigInteger q, BigInteger e)
    {
        BigInteger lambda = lcm(p.subtract(ONE), q.subtract(ONE));
        BigInteger d = e.modInverse(lambda);
        return new BigInteger[]
        {
            p.multiply(q),                       // n
            e,                                   // e
            d,                                   // d
            lambda,                              // λ = lcm(p-1, q-1)
            d.mod(p.subtract(ONE)),              // dp = d mod (p-1)
            d.mod(q.subtract(ONE)),              // dq = d mod (q-1)
            q.modInverse(p),                     // qInv = q⁻¹ mod p
            p, q                                 // 分解本身
        };
    }

    private static BigInteger lcm(BigInteger a, BigInteger b)
    {
        return a.multiply(b).divide(a.gcd(b));
    }

    /** while(true) 重试直到"是素数，且 p-1 与 e 互素"。 */
    private static BigInteger primeCoprimeTo(int bits, BigInteger e)
    {
        while (true)
        {
            BigInteger p = BigInteger.probablePrime(bits, RANDOM);
            if (e.gcd(p.subtract(ONE)).equals(ONE) && e.gcd(p).equals(ONE))
            {
                return p;
            }
        }
    }

    // 2048-bit 密钥：全类共享。它只是 9 个整数，不是任何对象。
    private static final BigInteger P_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger Q_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger[] KEY = keyGen(P_BIG, Q_BIG, F4);

    /** k = 模数的字节数 —— 所有填充过程都以它为长度基准。 */
    private static final int K = (KEY[N].bitLength() + 7) / 8;

    /**
     * RFC 8017：modBits = bitLength(n)，emBits = modBits - 1，emLen = (emBits+7)/8。
     * 关键细节：n 是两个随机大素数的乘积，它的最高几位经常是 0 —— 本例的 n 就只有
     * 2046 个有效 bit，于是 8*k - emBits = 2，首位掩码是 0x3f 而不是 0x7f。
     * 用"8k-1"去算掩码是一个真实的、能导致互操作失败的 bug（BC 会拒绝我们的签名）。
     */
    private static final int EM_BITS = KEY[N].bitLength() - 1;
    private static final int EM_LEN = (EM_BITS + 7) / 8;

    // ---------------------------------------------------------------- 公钥 / 私钥运算

    /** 公钥运算：一次模幂 {@code m^e mod n}。 */
    private static BigInteger publicOp(BigInteger[] key, BigInteger m)
    {
        return powMod(m, key[E], key[N]);
    }

    /** 私钥运算（直路）：一次全尺寸模幂 {@code c^d mod n}。 */
    private static BigInteger privateOp(BigInteger[] key, BigInteger c)
    {
        return powMod(c, key[D], key[N]);
    }

    /**
     * 私钥运算（CRT 路）：两个半尺寸模幂 + 一次中国剩余定理合并。
     * 这就是"RSA 为什么实际能跑得快"的全部原因 —— 指数从 d 降到 d mod (p-1)，约省 4 倍算力。
     */
    private static BigInteger privateOpCrt(BigInteger[] key, BigInteger c)
    {
        BigInteger m1 = powMod(c, key[DP], key[PP]);
        BigInteger m2 = powMod(c, key[DQ], key[PQ]);
        BigInteger h = key[QINV].multiply(m1.subtract(m2).mod(key[PP])).mod(key[PP]);
        return m2.add(key[PQ].multiply(h));
    }

    /** 字节层运算：整数 -> 定宽大端字节，长度由模数决定。 */
    private static byte[] publicOpBytes(BigInteger[] key, byte[] block)
    {
        int size = (key[N].bitLength() + 7) / 8;
        return Calc.toBytes(publicOp(key, Calc.toBigInt(block)), size);
    }

    private static byte[] privateCrtBytes(BigInteger[] key, byte[] block)
    {
        int size = (key[N].bitLength() + 7) / 8;
        return Calc.toBytes(privateOpCrt(key, Calc.toBigInt(block)), size);
    }

    // ---------------------------------------------------------------- 填充：全是带真实参数的静态方法

    /** NoPadding 的本质就是"定宽大端编码"：没有随机性，也就没有语义安全。 */
    private static byte[] noPadding(int k, byte[] block)
    {
        return Calc.toBytes(Calc.toBigInt(block), k);
    }

    /** PKCS#1 v1.5 签名块：00 ‖ 01 ‖ FF…FF ‖ 00 ‖ T —— 确定性，所以签名字节可复现。 */
    private static byte[] pkcs1Type1(int k, byte[] data)
    {
        int psLen = k - data.length - 3;
        if (psLen < 8)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：填充体至少要 8 字节");
        }
        return Calc.concat(new byte[]{ 0x00, 0x01 }, Calc.repeatedByte(0xff, psLen), new byte[]{ 0x00 }, data);
    }

    /** PKCS#1 v1.5 加密块：00 ‖ 02 ‖ 非零随机 ‖ 00 ‖ M —— 随机体换来语义安全。 */
    private static byte[] pkcs1Type2(int k, byte[] data)
    {
        int psLen = k - data.length - 3;
        if (psLen < 8)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：明文不能超过 k-11 字节");
        }
        return Calc.concat(new byte[]{ 0x00, 0x02 }, nonZeroBytes(psLen), new byte[]{ 0x00 }, data);
    }

    /** while 循环取随机字节直到里面没有 0x00（0x00 是分隔符，混进填充体会让结构产生歧义）。 */
    private static byte[] nonZeroBytes(int len)
    {
        while (true)
        {
            byte[] b = randomBytes(len);
            boolean clean = true;
            for (int i = 0; i < len; i++)
            {
                if (b[i] == 0)
                {
                    clean = false;
                    break;
                }
            }
            if (clean)
            {
                return b;
            }
        }
    }

    /** 去 PKCS#1 v1.5 填充：结构任何一步不满足都是错误，不允许"尽力解析"。 */
    private static byte[] pkcs1Unpad(int blockType, int k, byte[] em)
    {
        if (em.length != k || (em[0] & 0xff) != 0 || (em[1] & 0xff) != blockType)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：头两字节必须是 00 ‖ 0" + blockType);
        }
        int sep = indexOf(em, 2, (byte)0x00);
        if (sep < 10)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：分隔符前必须至少 8 字节填充体");
        }
        if (blockType == 1)
        {
            for (int i = 2; i < sep; i++)
            {
                if ((em[i] & 0xff) != 0xff)
                {
                    throw new IllegalArgumentException("PKCS#1 v1.5 type 1：填充体必须全是 FF");
                }
            }
        }
        return Arrays.copyOfRange(em, sep + 1, em.length);
    }

    /** 从 from 起找第一个等于 v 的下标，找不到返回 -1 —— 一个最朴素的 for 循环。 */
    private static int indexOf(byte[] a, int from, byte v)
    {
        for (int i = from; i < a.length; i++)
        {
            if (a[i] == v)
            {
                return i;
            }
        }
        return -1;
    }

    /** [from, to) 是否全是 0。 */
    private static boolean allZero(byte[] a, int from, int to)
    {
        for (int i = from; i < to; i++)
        {
            if (a[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /** [from, to) 是否全非 0。 */
    private static boolean allNonZero(byte[] a, int from, int to)
    {
        for (int i = from; i < to; i++)
        {
            if (a[i] == 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * MGF1 —— "掩码生成函数"只是"摘要 + 计数器模式"：一个 for 循环把
     * {@code T = H(seed‖0) ‖ H(seed‖1) ‖ …} 逐块拼起来，最后截到 length 字节。
     * OAEP 和 PSS 的安全性都建立在这一个方法上，看懂它就看懂了两种填充的 80%。
     */
    private static byte[] mgf1(String hashName, byte[] seed, int length)
    {
        int hLen = digestSize(hashName);
        byte[] stream = EMPTY;
        int blocks = Calc.ceilDiv(length, hLen);
        for (int counter = 0; counter < blocks; counter++)
        {
            byte[] block = digestOf(hashName, Calc.concat(seed, Calc.toBytes(BigInteger.valueOf(counter), 4)));
            stream = Calc.concat(stream, block);
        }
        return Arrays.copyOf(stream, length);
    }

    /**
     * OAEP 编码：两次 MGF1 + 两次异或，把明文推到整块伪随机。
     * 结构 {@code 00 ‖ maskedSeed ‖ maskedDB}，DB 头部带着 Hash(label) —— 这就是 label 绑定的来源。
     * 注意 EME-OAEP 里"绑定 label 的哈希"和"生成掩码的哈希"是两个独立参数（Sun 的默认组合就是
     * SHA-256 + MGF1/SHA-1），所以这里把两个哈希名分开传 —— 面向对象 API 常把它俩焊成一个，反而看不清。
     */
    private static byte[] oaepEncode(String hashName, String mgfHashName, int emLen, byte[] label, byte[] message)
    {
        int hLen = digestSize(hashName);
        int psLen = emLen - message.length - 2 * hLen - 2;
        if (psLen < 0)
        {
            throw new IllegalArgumentException("OAEP：明文超过 k-2hLen-2");
        }
        byte[] db = Calc.concat(digestOf(hashName, label), new byte[psLen], new byte[]{ 0x01 }, message);
        byte[] seed = randomBytes(hLen);
        byte[] maskedDb = Calc.xor(db, mgf1(mgfHashName, seed, emLen - hLen - 1));
        byte[] maskedSeed = Calc.xor(seed, mgf1(mgfHashName, maskedDb, hLen));
        return Calc.concat(new byte[]{ 0x00 }, maskedSeed, maskedDb);
    }

    /** OAEP 解码：结构检查（首字节 00、lHash 相等、0x01 之前全零）就是它的完整性来源。 */
    private static byte[] oaepDecode(String hashName, String mgfHashName, int emLen, byte[] label, byte[] em)
    {
        int hLen = digestSize(hashName);
        if (em.length != emLen || em[0] != 0)
        {
            throw new IllegalArgumentException("OAEP：EM 必须以 0x00 开头");
        }
        byte[] maskedDb = Arrays.copyOfRange(em, 1 + hLen, emLen);
        byte[] seed = Calc.xor(Arrays.copyOfRange(em, 1, 1 + hLen), mgf1(mgfHashName, maskedDb, hLen));
        byte[] db = Calc.xor(maskedDb, mgf1(mgfHashName, seed, maskedDb.length));
        if (!Arrays.equals(Arrays.copyOf(db, hLen), digestOf(hashName, label)))
        {
            throw new IllegalArgumentException("OAEP：label 不匹配（lHash 校验失败）");
        }
        int sep = indexOf(db, hLen, (byte)0x01);
        if (sep < 0 || !allZero(db, hLen, sep))
        {
            throw new IllegalArgumentException("OAEP：0x01 分隔符缺失，或分隔符前的填充体非零");
        }
        return Arrays.copyOfRange(db, sep + 1, db.length);
    }

    /**
     * RFC 8017 的首位掩码：emLen 个字节比模数多出来的那些高位必须清零，否则 EM 作为整数
     * 可能 >= n。掩码宽度 = 8*emLen - emBits，而 emBits = bitLength(n) - 1 —— 它是跟着
     * 密钥走的量，绝不能写成常量 0x7f：本例的 n 只有 2046 个有效 bit，掩码其实是 0x3f。
     */
    private static int topBitMask(int emLen, int emBits)
    {
        return 0xff >>> (emLen * 8 - emBits);
    }

    /**
     * PSS 编码：{@code EM = maskedDB ‖ H ‖ BC}，其中 {@code H = Hash(0⁸ ‖ Hash(M) ‖ salt)}。
     * salt 作为真实参数传进来 —— 给定同一个 salt 就得到同一个 EM，这正是"随机预言"的用法。
     * DB 的分隔字节与 OAEP 一样是 0x01（很多资料写成 0x20，那是错的）。
     */
    private static byte[] pssEncode(String hashName, int emLen, int emBits, byte[] salt, byte[] message)
    {
        int hLen = digestSize(hashName);
        int firstByteMask = topBitMask(emLen, emBits);
        byte[] h = digestOf(hashName, Calc.concat(new byte[8], digestOf(hashName, message), salt));
        byte[] db = Calc.concat(new byte[emLen - salt.length - hLen - 2], new byte[]{ 0x01 }, salt);
        byte[] maskedDb = Calc.xor(db, mgf1(hashName, h, emLen - hLen - 1));
        // 模数只用掉了 8*emLen 位里的 emBits 位，多出来的最高位必须清零，否则 EM 可能 >= n
        maskedDb[0] &= (byte)firstByteMask;
        return Calc.concat(maskedDb, h, new byte[]{ (byte)0xbc });
    }

    /**
     * PSS 校验：salt 从 DB 里的 0x01 分隔符后面还原，所以验证方不需要知道 salt 长度。
     * 返回布尔 —— 验版本来就是一个返回 true/false 的过程。
     */
    private static boolean pssVerify(String hashName, int emLen, int emBits, byte[] message, byte[] em)
    {
        int hLen = digestSize(hashName);
        int firstByteMask = topBitMask(emLen, emBits);
        if (em.length != emLen || (em[emLen - 1] & 0xff) != 0xbc
            || (em[0] & ~firstByteMask) != 0)
        {
            return false;
        }
        byte[] maskedDb = Arrays.copyOfRange(em, 0, emLen - hLen - 1);
        byte[] h = Arrays.copyOfRange(em, emLen - hLen - 1, emLen - 1);
        byte[] db = Calc.xor(maskedDb, mgf1(hashName, h, maskedDb.length));
        db[0] &= (byte)firstByteMask;
        int sep = indexOf(db, 0, (byte)0x01);
        if (sep < 0 || !allZero(db, 0, sep))
        {
            return false;
        }
        byte[] salt = Arrays.copyOfRange(db, sep + 1, db.length);
        return Arrays.equals(h, digestOf(hashName, Calc.concat(new byte[8], digestOf(hashName, message), salt)));
    }

    /**
     * DigestInfo：ASN.1 写死的一段头 + 摘要 = "要签的东西"。
     * PKCS#1 v1.5 签名的全部协议就是这两行字节，没有更多了。
     */
    private static byte[] digestInfo(byte[] derPrefix, byte[] hashBytes)
    {
        return Calc.concat(derPrefix, hashBytes);
    }

    /** SHA-1 / SHA-256 的 DigestInfo DER 前缀（RFC 8017 §9.2 Note 1 的固定表）。 */
    private static final byte[] DER_SHA1 = Calc.unhex("3021300906052b0e03021a05000414");
    private static final byte[] DER_SHA256 = Calc.unhex("3031300d060960864801650304020105000420");

    /** 签名过程：拼 DigestInfo -> type 1 填充 -> 私钥模幂（CRT 路），三个真实参数一次给全。 */
    private static byte[] pkcs1Sign(String digestName, byte[] derPrefix, byte[] message)
    {
        byte[] em = pkcs1Type1(K, digestInfo(derPrefix, digestOf(digestName, message)));
        return privateCrtBytes(KEY, em);
    }

    // ---------------------------------------------------------------- 分段 RSA

    /** 分段处理的三种"单块操作"编号。 */
    private static final int SEG_PKCS1_ENCRYPT = 0;
    private static final int SEG_PKCS1_DECRYPT = 1;
    private static final int SEG_OAEP_ENCRYPT = 2;

    /**
     * RSA 一块最多搬 k-11 字节，"长消息"就是一个 for 循环：按 segmentSize 切块、
     * 逐块做单块操作、把结果依次拼接。加密和解密共用同一个循环，只是 switch 里换一段单块代码。
     */
    private static byte[] segmented(int op, int segmentSize, byte[] data)
    {
        byte[] out = EMPTY;
        List<byte[]> segments = Calc.chunks(data, segmentSize);
        for (int i = 0; i < segments.size(); i++)
        {
            byte[] seg = segments.get(i);
            byte[] done;
            if (op == SEG_PKCS1_ENCRYPT)
            {
                done = publicOpBytes(KEY, pkcs1Type2(K, seg));
            }
            else if (op == SEG_PKCS1_DECRYPT)
            {
                done = pkcs1Unpad(2, K, privateCrtBytes(KEY, seg));
            }
            else
            {
                done = publicOpBytes(KEY, oaepEncode(SHA256, SHA256, K, EMPTY, seg));
            }
            out = Calc.concat(out, done);
        }
        return out;
    }

    // ---------------------------------------------------------------- 裁判工具

    /** 从纯数字元组重建 JCE 密钥对 —— 证明"密钥是数，不是对象"。 */
    private static KeyPair jcePair(BigInteger[] k)
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        PublicKey pub = kf.generatePublic(new RSAPublicKeySpec(k[N], k[E]));
        PrivateKey priv = kf.generatePrivate(new RSAPrivateCrtKeySpec(
            k[N], k[E], k[D], k[PP], k[PQ], k[DP], k[DQ], k[QINV]));
        return new KeyPair(pub, priv);
    }

    // ================================================================ 测试

    /** 命题一：RSA 只有一个运算 —— 模幂。我们自己写的平方-乘必须与 BigInteger.modPow 逐位相同。 */
    @Test
    public void rsaIsJustOneModularExponentiation()
        throws Exception
    {
        Calc.useBc();
        BigInteger n = KEY[N], e = KEY[E], d = KEY[D];

        BigInteger[] samples = new BigInteger[]
            {
                ONE, TWO, F4,
                TWO.pow(700).add(BigInteger.valueOf(20261014)),
                Calc.toBigInt(randomBytes(K - 1))
            };

        for (int i = 0; i < samples.length; i++)
        {
            BigInteger m = samples[i];
            // 平方-乘 == 库里的模幂：这是我们全部算术的正确性证明
            Assert.assertEquals("自写 powMod 必须等于 modPow", m.modPow(e, n), powMod(m, e, n));
            BigInteger c = publicOp(KEY, m);
            Assert.assertEquals("直路私钥运算必须还原明文", m, privateOp(KEY, c));
            Assert.assertEquals("CRT 路私钥运算必须还原明文", m, privateOpCrt(KEY, c));
        }

        // e·d ≡ 1 (mod λ)：这才是"密钥对"的定义，φ(n) 只是它的一个（更宽松的）特例
        Assert.assertEquals("d 必须是 e 在 λ 下的逆", ONE, e.multiply(d).mod(KEY[LAM]));
        Assert.assertEquals("e 必须与 λ 互素，否则逆不存在", ONE, e.gcd(KEY[LAM]));
        log.info("[RSA-本质] 模数 {} bits，λ {} bits，自写平方-乘与 modPow 一致", n.bitLength(), KEY[LAM].bitLength());
    }

    /** 命题二：密钥只是一组整数。p,q -> n,λ,d -> CRT 分量，每一步都能被 JCE 复现。 */
    @Test
    public void keyIsANumberTupleNotAnObject()
        throws Exception
    {
        Calc.useBc();
        BigInteger p = KEY[PP], q = KEY[PQ], n = KEY[N];

        Assert.assertEquals("n 必须是 pq", n, p.multiply(q));
        Assert.assertEquals("λ 必须是 lcm(p-1, q-1)", lcm(p.subtract(ONE), q.subtract(ONE)), KEY[LAM]);
        Assert.assertEquals("dp = d mod (p-1)", KEY[D].mod(p.subtract(ONE)), KEY[DP]);
        Assert.assertEquals("dq = d mod (q-1)", KEY[D].mod(q.subtract(ONE)), KEY[DQ]);
        Assert.assertEquals("qInv = q⁻¹ mod p", q.modInverse(p), KEY[QINV]);
        Assert.assertTrue("两个素数不能相等", p.compareTo(q) != 0);

        // CRT 的数学根据：半尺寸指数运算与全尺寸运算在 mod p 下同余
        BigInteger c = Calc.toBigInt(randomBytes(K - 1));
        Assert.assertEquals("c^dp mod p 必须等于 (c^d mod n) mod p",
            powMod(c, KEY[D], n).mod(p), powMod(c, KEY[DP], p));

        // JCE 用同一组数字重建出的密钥，必须和我们的静态方法完全互操作
        KeyPair jce = jcePair(KEY);
        byte[] pt = "keys are numbers".getBytes("UTF-8");
        byte[] ours = publicOpBytes(KEY, pkcs1Type2(K, pt));

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jce.getPrivate());
        Assert.assertArrayEquals("JCE 私钥必须能解我们手写加密的块", pt, dec.doFinal(ours));

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, jce.getPublic());
        byte[] fromJce = enc.doFinal(pt);
        Assert.assertArrayEquals("我们的元组必须能解 JCE 的块", pt,
            pkcs1Unpad(2, K, privateCrtBytes(KEY, fromJce)));

        // 反向：JCE 生成的密钥拆成数字后，同一套静态方法照样自洽
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) kpg.generateKeyPair().getPrivate();
        BigInteger[] fromJceKey = keyGen(crt.getPrimeP(), crt.getPrimeQ(), crt.getPublicExponent());
        Assert.assertEquals("元组必须重建出同一个模数", crt.getModulus(), fromJceKey[N]);
        Assert.assertEquals("拆成数字后 CRT 路必须自洽", c,
            publicOp(fromJceKey, privateOpCrt(fromJceKey, c)));
        log.info("[RSA-密钥] 纯数字元组 <-> JCE KeyPair 双向互操作通过");
    }

    /** 命题三：没有填充的 RSA 一无是处 —— 确定性、可延展、固定点、小指数开根。 */
    @Test
    public void textbookRsaLeaksEverything()
        throws Exception
    {
        Calc.useBc();
        BigInteger n = KEY[N];
        BigInteger m1 = Calc.toBigInt("RSA has no semantic security".getBytes("UTF-8"));
        BigInteger m2 = Calc.toBigInt("RSA has no semantic security".getBytes("UTF-8"));

        // 1) 确定性：相同明文 -> 相同密文，于是密文泄露了"相等关系"
        Assert.assertEquals("教科书 RSA 是确定性加密",
            publicOp(KEY, m1), publicOp(KEY, m2));

        // 2) 乘法同态：攻击者不解密就能给明文乘一个常数 —— 语义安全的反面
        BigInteger c = publicOp(KEY, m1);
        BigInteger cTwice = c.multiply(powMod(TWO, KEY[E], n)).mod(n);
        Assert.assertEquals("密文乘 2^e 让明文翻倍", m1.multiply(TWO).mod(n),
            privateOp(KEY, cTwice));

        // 3) 固定点：0、1、n-1 永远不变，攻击者一眼看穿
        Assert.assertEquals(ZERO, publicOp(KEY, ZERO));
        Assert.assertEquals(ONE, publicOp(KEY, ONE));
        Assert.assertEquals(n.subtract(ONE), publicOp(KEY, n.subtract(ONE)));

        // 4) e=3 且 m^e < n：模数完全没起作用，开立方就还原了明文（Why e=65537 / 为什么必须填充）
        BigInteger[] smallE = keyGen(primeCoprimeTo(512, THREE), primeCoprimeTo(512, THREE), THREE);
        BigInteger msg = Calc.toBigInt("cube me".getBytes("UTF-8"));
        BigInteger cipher3 = publicOp(smallE, msg);
        Assert.assertEquals("m^3 没超过 n 时，密文就是 m^3 本身", msg.pow(3), cipher3);
        Assert.assertEquals("牛顿迭代开立方即可还原明文", msg, cubeRoot(cipher3));
        log.info("[RSA-教科书] 确定性 / 可延展 / 固定点 / 小指数开方 四种弱点全部复现");
    }

    /** 立方根的牛顿迭代：{@code x' = (2x + v/x²) / 3}，for 循环迭代 300 次足够收敛到精确整数根。 */
    private static BigInteger cubeRoot(BigInteger v)
    {
        BigInteger x = ONE.shiftLeft((v.bitLength() + 2) / 3);
        for (int i = 0; i < 300; i++)
        {
            x = x.multiply(TWO).add(v.divide(x.multiply(x))).divide(THREE);
        }
        return x;
    }

    /** PKCS#1 v1.5 type 2（加密填充）：与 JCE 双向互操作，畸形结构必须拒绝。 */
    @Test
    public void pkcs1v15Type2PaddingRoundTripsWithJce()
        throws Exception
    {
        Calc.useBc();
        byte[] pt = "PKCS#1 v1.5 encryption padding".getBytes("UTF-8");
        // 先看填充后的 EM 结构，再过一次公钥运算才是密文
        byte[] em = pkcs1Type2(K, pt);
        byte[] ours = publicOpBytes(KEY, em);

        Assert.assertEquals("EM 必须是 k 字节", K, em.length);
        Assert.assertEquals("首字节 00", 0, em[0] & 0xff);
        Assert.assertEquals("块类型 02", 2, em[1] & 0xff);
        // 结构：00 ‖ 02 ‖ PS(k-pt-3) ‖ 00 ‖ PT  ->  分隔符下标 = k - pt - 1
        Assert.assertEquals("分隔符 00 固定在明文之前", 0, em[K - pt.length - 1] & 0xff);
        Assert.assertTrue("填充体不能含 00", allNonZero(em, 2, K - pt.length - 1));

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate());
        Assert.assertArrayEquals("JCE 必须能解我们的 type-2 填充块", pt, dec.doFinal(ours));

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, jcePair(KEY).getPublic());
        Assert.assertArrayEquals("我们的 unpad 必须解出 JCE 的密文", pt,
            pkcs1Unpad(2, K, privateCrtBytes(KEY, enc.doFinal(pt))));

        // 同一条明文两次填充不同 —— 随机填充体带来的语义安全（对比教科书 RSA 的确定性）
        Assert.assertFalse("type 2 必须 randomized", Arrays.equals(em, pkcs1Type2(K, pt)));

        // 三种畸形结构：先克隆再就地改动一个字节（原块 em 保持不动，后面还要用）
        byte[] noLeadingZero = em.clone();
        noLeadingZero[0] = (byte)0x80;                            // 首字节不是 00
        byte[] wrongBlockType = em.clone();
        wrongBlockType[1] = (byte)0x01;                           // 块类型错（加密块必须是 02）
        byte[] noSeparator = em.clone();
        noSeparator[K - pt.length - 1] = (byte)0x7f;              // 分隔符消失
        byte[][] malformed = new byte[][]{ noLeadingZero, wrongBlockType, noSeparator };
        for (int i = 0; i < malformed.length; i++)
        {
            try
            {
                pkcs1Unpad(2, K, malformed[i]);
                Assert.fail("畸形 PKCS#1 v1.5 结构必须被拒绝");
            }
            catch (IllegalArgumentException expected)
            {
                log.info("[RSA-v1.5] 拒绝畸形结构：{}", expected.getMessage());
            }
        }

        // 长度上限 k-11：8 字节最小填充体 + 2 个结构字节 + 1 个分隔符
        try
        {
            pkcs1Type2(K, new byte[K - 10]);
            Assert.fail("超过 k-11 的明文必须被拒绝");
        }
        catch (IllegalArgumentException expected)
        {
            Assert.assertEquals("PKCS#1 v1.5：明文不能超过 k-11 字节", expected.getMessage());
        }
    }

    /** PKCS#1 v1.5 type 1（签名填充）：确定性 -> 我们的签名字节与 JCE 逐字节相同。 */
    @Test
    public void pkcs1v15Type1SignatureMatchesJceByteForByte()
        throws Exception
    {
        Calc.useBc();
        byte[] msg = "deterministic padding means byte-identical signatures".getBytes("UTF-8");

        // 一张"值表"：三行按下标对齐 —— 摘要名、DigestInfo DER 前缀、JCE 算法名
        String[] digestNames = new String[]{ SHA1, SHA256 };
        byte[][] derPrefixes = new byte[][]{ DER_SHA1, DER_SHA256 };
        String[] jceNames = new String[]{ "SHA1withRSA", "SHA256withRSA" };

        for (int i = 0; i < jceNames.length; i++)
        {
            String digestName = digestNames[i];
            byte[] der = derPrefixes[i];
            String jceName = jceNames[i];

            byte[] ours = pkcs1Sign(digestName, der, msg);
            KeyPair jce = jcePair(KEY);

            Signature sig = Signature.getInstance(jceName, "BC");
            sig.initSign(jce.getPrivate());
            sig.update(msg);
            byte[] ref = sig.sign();
            Assert.assertArrayEquals(jceName + "：手写签名必须与 JCE 逐字节相同", ref, ours);

            Signature ver = Signature.getInstance(jceName, "BC");
            ver.initVerify(jce.getPublic());
            ver.update(msg);
            Assert.assertTrue(jceName + "：JCE 必须认我们的签名", ver.verify(ours));

            // 反方向：公钥模幂 + 去 type1 填充，得到的必须正好是 DigestInfo —— 这也验证了硬编码的 DER 前缀
            byte[] recovered = pkcs1Unpad(1, K, publicOpBytes(KEY, ref));
            Assert.assertArrayEquals(jceName + "：去掉 type1 填充后必须正好是 DigestInfo",
                digestInfo(der, digestOf(digestName, msg)), recovered);

            log.info("[RSA-签名] {} 与 JCE 完全一致（DigestInfo 前缀 {}）", jceName, Calc.hex(der));
        }

        // 认证性：换一条消息，签名立刻失效
        Signature ver = Signature.getInstance("SHA256withRSA", "BC");
        ver.initVerify(jcePair(KEY).getPublic());
        ver.update("a different message".getBytes("UTF-8"));
        Assert.assertFalse("签名必须与消息绑定", ver.verify(pkcs1Sign(SHA256, DER_SHA256, msg)));
    }

    /** MGF1 = 摘要 + 计数器：在多种长度上与 BC 的 MGF1BytesGenerator 完全一致。 */
    @Test
    public void mgf1IsJustHashInCounterMode()
        throws Exception
    {
        Calc.useBc();
        // 两张按下标对齐的值表：我们的摘要名 + BC 的 Digest 裁判
        String[] hashNames = new String[]{ SHA1, SHA256, SM3 };
        Digest[] bcDigests = new Digest[]{ new SHA1Digest(), new SHA256Digest(), new SM3Digest() };

        for (int i = 0; i < hashNames.length; i++)
        {
            String hashName = hashNames[i];
            Digest bcDigest = bcDigests[i];

            byte[] seed = Calc.concat("seed".getBytes("UTF-8"), randomBytes(7));
            int hLen = digestSize(hashName);
            int[] lengths = new int[]{ 1, hLen - 1, hLen, hLen + 1, 300, K };
            for (int j = 0; j < lengths.length; j++)
            {
                int len = lengths[j];
                MGF1BytesGenerator gen = new MGF1BytesGenerator(bcDigest);
                gen.init(new MGFParameters(seed));
                byte[] ref = new byte[len];
                gen.generateBytes(ref, 0, len);
                Assert.assertArrayEquals("MGF1(hLen=" + hLen + ", len=" + len + ")",
                    ref, mgf1(hashName, seed, len));
            }
        }

        // 种子差一个 bit，整个掩码全变 —— 这就是"扩散"，也是 OAEP 随机性的载体
        byte[] s = "the same seed".getBytes("UTF-8");
        byte[] sChanged = s.clone();
        sChanged[0] = (byte)'T';                                   // 就地改克隆的首字节
        Assert.assertFalse("改一个 bit 必须改变整个掩码",
            Arrays.equals(mgf1(SHA256, s, 64), mgf1(SHA256, sChanged, 64)));
        Assert.assertArrayEquals("MGF1 是确定性的：同输入必同输出",
            mgf1(SHA256, s, 64), mgf1(SHA256, s, 64));
        log.info("[RSA-MGF1] 与 BC MGF1BytesGenerator 一致（SHA-1 / SHA-256 / SM3）");
    }

    /** OAEP：同一个静态方法，换摘要、甚至给 MGF1 换一个摘要，都能与裁判互操作。 */
    @Test
    public void oaepRoundTripsUnderThreeHashes()
        throws Exception
    {
        Calc.useBc();
        byte[] pt = "OAEP gives RSA semantic security".getBytes("UTF-8");

        // 三种"绑定 label 的哈希"：SHA-1 / SHA-256 / SM3。两张值表按下标对齐，裁判用 BC 的 crypto 层，参数完全显式。
        String[] hashNames = new String[]{ SHA1, SHA256, SM3 };
        Digest[] bcDigests = new Digest[]{ new SHA1Digest(), new SHA256Digest(), new SM3Digest() };
        for (int i = 0; i < hashNames.length; i++)
        {
            String hash = hashNames[i];
            OAEPEncoding referee = new OAEPEncoding(new RSAEngine(), bcDigests[i]);

            byte[] em = oaepEncode(hash, hash, K, EMPTY, pt);
            byte[] ours = publicOpBytes(KEY, em);
            Assert.assertEquals("OAEP 的 EM 也是 k 字节", K, em.length);
            Assert.assertEquals("首字节必须是 0", 0, em[0] & 0xff);

            referee.init(false, new RSAKeyParameters(true, KEY[N], KEY[D]));            // 解密用私钥
            Assert.assertArrayEquals("BC 必须能解我们的 OAEP 密文", pt,
                referee.processBlock(ours, 0, ours.length));

            referee.init(true, new RSAKeyParameters(false, KEY[N], KEY[E]));            // 加密用公钥
            byte[] fromBc = referee.processBlock(pt, 0, pt.length);
            Assert.assertArrayEquals("我们必须能解 BC 的 OAEP 密文", pt,
                oaepDecode(hash, hash, K, EMPTY, privateCrtBytes(KEY, fromBc)));

            Assert.assertFalse("OAEP 必须 randomized",
                Arrays.equals(em, oaepEncode(hash, hash, K, EMPTY, pt)));
            log.info("[RSA-OAEP] hLen={} 双向互操作通过，上限 k-2hLen-2 = {}",
                digestSize(hash), K - 2 * digestSize(hash) - 2);
        }

        // label 哈希与 MGF1 哈希是两个独立参数：SHA-256 绑 label，SHA-1 出掩码
        OAEPEncoding mixed = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), null);
        mixed.init(true, new RSAKeyParameters(false, KEY[N], KEY[E]));
        byte[] mixedFromBc = mixed.processBlock(pt, 0, pt.length);
        Assert.assertArrayEquals("label=SHA-256 / MGF1=SHA-1 的混合组合必须也能被我们的手写实现解开", pt,
            oaepDecode(SHA256, SHA1, K, EMPTY, privateCrtBytes(KEY, mixedFromBc)));

        // JCE 端到端：显式 OAEPParameterSpec，不依赖任何"名字里默认用什么哈希"的方言
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate(),
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        Assert.assertArrayEquals("JCE(OAEPParameterSpec) 必须能解我们的 OAEP 密文", pt,
            dec.doFinal(publicOpBytes(KEY, oaepEncode(SHA256, SHA256, K, EMPTY, pt))));

        // label 绑定：换个 label 就解不开 —— 这是 OAEP 唯一"额外"的能力。
        // 注意解码方法只看 EM 本身，不需要先做模幂 —— 填充与模幂正交的最好证据。
        byte[] withLabel = oaepEncode(SHA256, SHA256, K, "label-A".getBytes("UTF-8"), pt);
        try
        {
            oaepDecode(SHA256, SHA256, K, "label-B".getBytes("UTF-8"), withLabel);
            Assert.fail("label 不匹配必须失败");
        }
        catch (IllegalArgumentException expected)
        {
            log.info("[RSA-OAEP] label 绑定生效：{}", expected.getMessage());
        }

        // 长度上限 k-2hLen-2（对比 v1.5 的 k-11）：边界内侧可用，边界外侧立刻拒绝
        oaepEncode(SHA256, SHA256, K, EMPTY, new byte[K - 66]);
        try
        {
            oaepEncode(SHA256, SHA256, K, EMPTY, new byte[K - 65]);
            Assert.fail("超过 k-2hLen-2 的明文必须被拒绝");
        }
        catch (IllegalArgumentException expected)
        {
            Assert.assertEquals("OAEP：明文超过 k-2hLen-2", expected.getMessage());
        }
    }

    /** PSS：salt 决定一切。固定 salt 时我们的 EM 与 BC 的 PSSSigner 逐字节相同。 */
    @Test
    public void pssIsDeterminedByItsSalt()
        throws Exception
    {
        Calc.useBc();
        byte[] msg = "PSS is randomized but reproducible".getBytes("UTF-8");

        byte[][] salts = new byte[][]{ new byte[0], randomBytes(32), randomBytes(8) };
        for (int s = 0; s < salts.length; s++)
        {
            byte[] salt = salts[s];
            byte[] em = pssEncode(SHA256, EM_LEN, EM_BITS, salt, msg);
            Assert.assertEquals("PSS 的 EM 是 emLen 字节", EM_LEN, em.length);
            Assert.assertEquals("结尾固定 0xBC", 0xbc, em[EM_LEN - 1] & 0xff);
            // 掩码不是 0x7f 的"装饰"，它由 modBits 真实决定：本例 modBits=2046 -> 掩码 0x3f
            Assert.assertEquals("首位只有 emBits 个有效位（emBits = bitLength(n)-1）",
                0, em[0] & ~topBitMask(EM_LEN, EM_BITS));
            Assert.assertTrue("EM 作为整数必须小于 n", Calc.toBigInt(em).compareTo(KEY[N]) < 0);
            Assert.assertTrue("自校验必须通过", pssVerify(SHA256, EM_LEN, EM_BITS, msg, em));

            // 裁判：BC 的 PSSSigner 用同一个 salt -> 同一个 EM（这一步验证了 trailing-bit 掩码的细节）
            PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), salt);
            signer.init(true, new RSAKeyParameters(true, KEY[N], KEY[D]));
            signer.update(msg, 0, msg.length);
            byte[] ref = signer.generateSignature();
            byte[] refEm = publicOpBytes(KEY, ref);
            Assert.assertArrayEquals("sLen=" + salt.length + " 时手写签名必须等于 BC"
                + " ours=" + Calc.hex(em) + " | refEm=" + Calc.hex(refEm),
                ref, privateCrtBytes(KEY, em));

            Assert.assertFalse("同 salt 同消息，但换 salt 之后签名完全不同",
                Arrays.equals(ref, privateCrtBytes(KEY,
                    pssEncode(SHA256, EM_LEN, EM_BITS, randomBytes(32), msg))));
        }

        byte[] fixed = "fixed-salt".getBytes("UTF-8");
        Assert.assertArrayEquals("给定 salt 后 PSS 是确定性的（同输入必同输出）",
            pssEncode(SHA256, EM_LEN, EM_BITS, fixed, msg),
            pssEncode(SHA256, EM_LEN, EM_BITS, fixed, msg));

        // 与 JCE 的 RSASSA-PSS 互验：JCE 用随机 salt，我们的 pssVerify 能把 salt 从 DB 里找回来
        Signature jceSign = Signature.getInstance("SHA256withRSA/PSS", "BC");
        jceSign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        jceSign.initSign(jcePair(KEY).getPrivate());
        jceSign.update(msg);
        byte[] jceEm = publicOpBytes(KEY, jceSign.sign());
        Assert.assertTrue("我们的 pssVerify 必须能验 JCE 的随机 salt 签名",
            pssVerify(SHA256, EM_LEN, EM_BITS, msg, jceEm));

        // 反向互操作：JCE 必须认我们固定 salt 的签名（这一步之前会失败 —— 掩码算错时只有它抓得住）
        Signature jceVerify = Signature.getInstance("SHA256withRSA/PSS", "BC");
        jceVerify.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        jceVerify.initVerify(jcePair(KEY).getPublic());
        jceVerify.update(msg);
        Assert.assertTrue("JCE 必须认我们的固定 salt 签名",
            jceVerify.verify(privateCrtBytes(KEY,
                pssEncode(SHA256, EM_LEN, EM_BITS, randomBytes(32), msg))));

        // 认证性：改一位，pssVerify 必须返回 false
        byte[] tampered = jceEm.clone();
        tampered[40] ^= 1;
        Assert.assertFalse("篡改 EM 必须让 PSS 校验失败", pssVerify(SHA256, EM_LEN, EM_BITS, msg, tampered));
        Assert.assertFalse("换消息必须让 PSS 校验失败",
            pssVerify(SHA256, EM_LEN, EM_BITS, "other".getBytes("UTF-8"), jceEm));
        log.info("[RSA-PSS] sLen=0/32/8 与 BC 逐字节一致，并能验 JCE 的随机 salt 签名");
    }

    // ---------------------------------------------------------------- 九种填充的"值表"分派

    /** 九种填充方案的下标，与 names 表逐行对应。 */
    private static final int[] SCHEMES = new int[]{ 0, 1, 2, 3, 4, 5, 6, 7, 8 };

    /**
     * 按编号给 body 做填充 —— "策略模式"在这里就退化成一个带 switch 的普通静态方法：
     * 没有 interface，没有 new，编号与 names 表逐行对应。
     */
    private static byte[] padByScheme(int scheme, byte[] body)
    {
        switch (scheme)
        {
            case 0:  return noPadding(K, body);                                        // NoPadding
            case 1:  return pkcs1Type1(K, body);                                       // PKCS#1 v1.5 type 1
            case 2:  return pkcs1Type2(K, body);                                       // PKCS#1 v1.5 type 2
            case 3:  return oaepEncode(SHA1, SHA1, K, EMPTY, body);                    // OAEP/SHA-1
            case 4:  return oaepEncode(SHA256, SHA256, K, EMPTY, body);                // OAEP/SHA-256
            case 5:  return oaepEncode(SM3, SM3, K, EMPTY, body);                      // OAEP/SM3
            case 6:  return oaepEncode(SHA256, SHA1, K, EMPTY, body);                  // label=SHA-256, MGF1=SHA-1
            case 7:  return pssEncode(SHA256, EM_LEN, EM_BITS, new byte[0], body);     // PSS/sLen=0
            default: return pssEncode(SHA256, EM_LEN, EM_BITS, randomBytes(32), body); // PSS/sLen=hLen
        }
    }

    /** 按编号去填充 / 校验 —— 与 padByScheme 共用同一套编号。body 只有 0（截尾）和 7、8（PSS 校验）用得到。 */
    private static byte[] unpadByScheme(int scheme, byte[] em, byte[] body)
    {
        switch (scheme)
        {
            // NoPadding 的"去填充"只是重新取定宽整数的尾部
            case 0:  return Arrays.copyOfRange(em, K - body.length, K);
            case 1:  return pkcs1Unpad(1, K, em);
            case 2:  return pkcs1Unpad(2, K, em);
            case 3:  return oaepDecode(SHA1, SHA1, K, EMPTY, em);
            case 4:  return oaepDecode(SHA256, SHA256, K, EMPTY, em);
            case 5:  return oaepDecode(SM3, SM3, K, EMPTY, em);
            case 6:  return oaepDecode(SHA256, SHA1, K, EMPTY, em);
            case 7:  return requirePss(em, body);
            default: return requirePss(em, body);
        }
    }

    /** PSS 的"去填充"就是校验：校验不过抛异常，好让九种方案共用同一套断言。 */
    private static byte[] requirePss(byte[] em, byte[] body)
    {
        if (!pssVerify(SHA256, EM_LEN, EM_BITS, body, em))
        {
            throw new IllegalArgumentException("PSS 校验失败");
        }
        return body;
    }

    /** 断言"这个 EM 必须被对应方案的校验过程拒绝"。 */
    private static void assertRejected(String name, int scheme, byte[] em, byte[] body)
    {
        try
        {
            unpadByScheme(scheme, em, body);
            Assert.fail(name + "：结构字节被翻转必须被拒绝");
        }
        catch (IllegalArgumentException expected)
        {
            log.info("[RSA-填充] {} 拒绝篡改：{}", name, expected.getMessage());
        }
    }

    /**
     * 命题四：填充是与模幂正交的计算过程。
     * 九种方案就是 names 表 + 两个按编号分派的静态方法（padByScheme / unpadByScheme）。
     */
    @Test
    public void everyPaddingSchemeIsAPureFunctionOrthogonalToTheModExp()
        throws Exception
    {
        Calc.useBc();
        byte[] body = Calc.concat("one body, eight paddings".getBytes("UTF-8"), randomBytes(8));

        String[] names = new String[]
            {
                "NoPadding", "PKCS#1 v1.5 type 1", "PKCS#1 v1.5 type 2",
                "OAEP/SHA-1", "OAEP/SHA-256", "OAEP/SM3", "OAEP/SHA-256+MGF1/SHA-1",
                "PSS/sLen=0", "PSS/sLen=hLen"
            };

        for (int row = 0; row < SCHEMES.length; row++)
        {
            int scheme = SCHEMES[row];
            String name = names[scheme];
            byte[] em = padByScheme(scheme, body);
            Assert.assertEquals(name + "：EM 必须正好填满一个模数块", K, em.length);
            Assert.assertTrue(name + "：EM 作为整数必须 < n", Calc.toBigInt(em).compareTo(KEY[N]) < 0);

            // 同一条模幂管线走一遍：私钥 -> 公钥 -> 去填充。填充方法不知道 RSA 的任何事
            byte[] signed = privateCrtBytes(KEY, em);
            byte[] recoveredEm = publicOpBytes(KEY, signed);
            Assert.assertArrayEquals(name + "：模幂往返必须还原 EM", em, recoveredEm);
            Assert.assertArrayEquals(name + "：unpad(pad(M)) 必须等于 M", body,
                unpadByScheme(scheme, recoveredEm, body));

            // 结构字节（最高位必须为 0）翻转：先克隆再就地改，除 NoPadding 外全部拒绝
            byte[] flipped = recoveredEm.clone();
            flipped[0] = (byte)(flipped[0] ^ 0x80);
            if (scheme == 0)
            {
                Assert.assertArrayEquals("NoPadding 连结构都没有，篡改被静默接受",
                    body, unpadByScheme(0, flipped, body));
            }
            else
            {
                assertRejected(name, scheme, flipped, body);
            }
            log.info("[RSA-填充] {}：k={} 字节，独立于模幂且能拒绝结构篡改", name, K);
        }

        // 诚实的结论，也是"填充模式"之间真正的差别：
        // PKCS#1 v1.5 只检查填充结构，明文本身被改了它毫无察觉 -> 静默返回损坏的明文；
        // OAEP/PSS 的明文处在"由自己算出的掩码"之下，改一个 bit 会让整块结构校验失败 -> 拒绝。
        for (int i = 1; i <= 2; i++)
        {
            byte[] emForFlip = padByScheme(i, body);
            // 只翻转代表消息的最后一字节（异或 1，保证内容确实变了）
            byte[] dataFlipped = emForFlip.clone();
            dataFlipped[K - 1] = (byte)(dataFlipped[K - 1] ^ 0x01);
            byte[] back = unpadByScheme(i, publicOpBytes(KEY, privateCrtBytes(KEY, dataFlipped)), body);
            Assert.assertEquals(names[i] + "：明文长度不变", body.length, back.length);
            Assert.assertFalse(names[i] + "：消息内容被静默破坏（v1.5 没有完整性）", Arrays.equals(body, back));
        }
        for (int i = 3; i <= 6; i++)
        {
            byte[] emForFlip = padByScheme(i, body);
            // OAEP 里 EM 的倒数第二字节正好落在 maskedDB 的最后一字节 = 明文的最后一个字节
            byte[] dataFlipped = emForFlip.clone();
            dataFlipped[K - 2] = (byte)(dataFlipped[K - 2] ^ 0x01);
            assertRejected(names[i] + "（改消息位）", i,
                publicOpBytes(KEY, privateCrtBytes(KEY, dataFlipped)), body);
        }

        // PSS 的 EM 末尾是固定 trailer 0xBC；它的 maskedDB 覆盖整条消息，所以改任何一位都会失败
        int[] pssPositions = new int[]{ 100, K - 2, K - 1 };
        for (int i = 7; i <= 8; i++)
        {
            byte[] emForFlip = padByScheme(i, body);
            for (int j = 0; j < pssPositions.length; j++)
            {
                int at = pssPositions[j];
                byte[] oneFlipped = emForFlip.clone();
                oneFlipped[at] = (byte)(oneFlipped[at] ^ 0x01);
                assertRejected(names[i] + "（改第 " + at + " 字节）", i,
                    publicOpBytes(KEY, privateCrtBytes(KEY, oneFlipped)), body);
            }
        }
    }

    /** 长消息 = 一个 for 循环逐块处理再拼接。RSA 从不"流式"，所谓流式只是外面套了一层分块循环。 */
    @Test
    public void longMessageRsaIsALoopOverBlocks()
        throws Exception
    {
        Calc.useBc();
        byte[] longMsg = Calc.repeat("RSA can carry at most k-11 bytes, so anything longer must be split into blocks. ", 12)
            .getBytes("UTF-8");
        int segmentSize = K - 11;
        Assert.assertTrue("这条消息必须超过单个 RSA 块", longMsg.length > segmentSize);

        // 加密方向：每段 -> type 2 填充 -> 公钥模幂 -> 拼接
        byte[] ct = segmented(SEG_PKCS1_ENCRYPT, segmentSize, longMsg);
        Assert.assertEquals("密文长度 = 段数 × k", Calc.ceilDiv(longMsg.length, segmentSize) * K, ct.length);

        // 解密方向：密文按 k 切块 -> 私钥模幂 -> 去填充 -> 拼接（同一个循环，换一段单块代码）
        Assert.assertArrayEquals("分段 for 循环往返必须还原长消息", longMsg,
            segmented(SEG_PKCS1_DECRYPT, K, ct));

        // 裁判：JCE 逐段解我们的密文
        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate());
        List<byte[]> cipherSegments = Calc.chunks(ct, K);
        List<byte[]> plainSegments = Calc.chunks(longMsg, segmentSize);
        for (int i = 0; i < cipherSegments.size(); i++)
        {
            Assert.assertArrayEquals("第 " + i + " 段必须与 JCE 解密一致",
                plainSegments.get(i), dec.doFinal(cipherSegments.get(i)));
        }

        // 用 OAEP 时上限就变成 k-2hLen-2 —— 同一个分段循环，换一段单块代码就换个上限
        Assert.assertEquals("OAEP 分段密文同样是段数 × k",
            Calc.ceilDiv(longMsg.length, K - 66) * K,
            segmented(SEG_OAEP_ENCRYPT, K - 66, longMsg).length);

        try
        {
            segmented(SEG_PKCS1_ENCRYPT, K - 10, new byte[K - 9]);
            Assert.fail("分段超过 k-11 必须失败");
        }
        catch (IllegalArgumentException expected)
        {
            Assert.assertEquals("PKCS#1 v1.5：明文不能超过 k-11 字节", expected.getMessage());
        }
        log.info("[RSA-分段] {} 字节明文 / {} 段，for 循环逐块与 JCE 互操作通过",
            longMsg.length, cipherSegments.size());
    }
}
