package org.bouncycastle.learning.functional;

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
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

import static org.bouncycastle.learning.functional.Fp.fold;
import static org.bouncycastle.learning.functional.Fp.foldRange;

/**
 * RSA 的本质计算 —— 纯函数版，覆盖全部填充/编码方案。
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
 *       {@code byte[] -> byte[]} 纯函数，与模幂正交，所以可以自由换摘要、换组合子。</li>
 * </ol>
 *
 * <p>面向对象如何被消掉：
 * <ul>
 *   <li>构造器 → 柯里化函数 {@code p -> q -> e -> 密钥元组}；</li>
 *   <li>策略模式 / if-else 分发 → 一张 {@code List<Function<byte[], byte[]>>}；</li>
 *   <li>SecureRandom 依赖注入 → 一个 {@code Function<Integer, byte[]>} 参数；</li>
 *   <li>for 循环累加 → {@link Fp#fold} / {@link Fp#foldRange}。</li>
 * </ul>
 * BC 与 JCE 全程只当"第三方裁判"：算是我们自己算的，答案交给它们核。
 */
@Slf4j
public class RsaFunctionalTest
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

    /** 随机源以"函数"注入 —— 这是函数式风格里唯一需要的依赖注入形式。 */
    private static final Function<Integer, byte[]> RANDOM_BYTES = len ->
    {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    };

    private static final byte[] EMPTY = new byte[0];

    // ---------------------------------------------------------------- 摘要：byte[] -> byte[] 的纯函数

    /**
     * 把 JCE 的 MessageDigest 包成 {@code Function<byte[], byte[]>}。
     * checked 异常属于"副作用"，必须关在边界里，边界之外才能保持纯函数。
     */
    private static Function<byte[], byte[]> hashOf(String algorithm)
    {
        return bytes ->
        {
            try
            {
                return Fp.digest(algorithm, bytes);
            }
            catch (Exception e)
            {
                throw new IllegalStateException(algorithm, e);
            }
        };
    }

    private static final Function<byte[], byte[]> SHA1 = hashOf("SHA-1");
    private static final Function<byte[], byte[]> SHA256 = hashOf("SHA-256");
    private static final Function<byte[], byte[]> SM3 = hashOf("SM3");

    /** 摘要长度也是纯函数算出来的：Digest 对象在这里是多余的。 */
    private static int digestSize(Function<byte[], byte[]> hash)
    {
        return hash.apply(EMPTY).length;
    }

    // ---------------------------------------------------------------- 本质：平方-乘

    /**
     * 模幂 = 把指数的 bit 从高位到低位折叠：每轮 {@code acc = acc² · base^bit mod n}。
     * 没有分支、没有可变累加器 —— 一次 fold 就是整个"快速幂"。
     */
    private static BigInteger powMod(BigInteger base, BigInteger exp, BigInteger n)
    {
        List<Integer> highToLow = IntStream.range(0, exp.bitLength()).boxed()
            .sorted(Comparator.<Integer>reverseOrder()).collect(Collectors.toList());
        return fold(highToLow, ONE,
            (acc, bit) -> acc.multiply(acc).mod(n).multiply(exp.testBit(bit) ? base : ONE).mod(n));
    }

    /** 柯里化模幂：先喂指数、再喂模数、最后喂底数 —— 前两个合起来就是"密钥"。 */
    static final Function<BigInteger, Function<BigInteger, Function<BigInteger, BigInteger>>> EXP =
        e -> n -> m -> powMod(m, e, n);

    /**
     * 密钥生成只有三步算术：{@code n = pq}，{@code λ = lcm(p-1, q-1)}，{@code d = e⁻¹ mod λ}；
     * 再把 CRT 加速需要的三个分量 dp / dq / qInv 一起算出来。
     * 注意用 λ（Carmichael 函数）而不是 φ —— 这才是最小可用的指数模数。
     */
    static final Function<BigInteger, Function<BigInteger, Function<BigInteger, BigInteger[]>>> KEY_GEN =
        p -> q -> e ->
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
        };

    private static BigInteger lcm(BigInteger a, BigInteger b)
    {
        return a.multiply(b).divide(a.gcd(b));
    }

    /** 递归重试直到"是素数，且 p-1 与 e 互素"，用它代替 while 循环。 */
    private static BigInteger primeCoprimeTo(int bits, BigInteger e)
    {
        BigInteger p = BigInteger.probablePrime(bits, RANDOM);
        return e.gcd(p.subtract(ONE)).equals(ONE) && e.gcd(p).equals(ONE) ? p : primeCoprimeTo(bits, e);
    }

    static final Function<Integer, Function<BigInteger, BigInteger>> PRIME_COPRIME_TO =
        bits -> e -> primeCoprimeTo(bits, e);

    // 2048-bit 密钥：全类共享。它只是 9 个整数，不是任何对象。
    private static final BigInteger P_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger Q_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger[] KEY = KEY_GEN.apply(P_BIG).apply(Q_BIG).apply(F4);

    /** k = 模数的字节数 —— 所有填充函数都以它为长度基准。 */
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

    static final Function<BigInteger[], Function<BigInteger, BigInteger>> PUBLIC_OP =
        k -> m -> EXP.apply(k[E]).apply(k[N]).apply(m);

    /** 私钥运算（直路）：一次全尺寸模幂。 */
    static final Function<BigInteger[], Function<BigInteger, BigInteger>> PRIVATE_OP =
        k -> c -> EXP.apply(k[D]).apply(k[N]).apply(c);

    /**
     * 私钥运算（CRT 路）：两个半尺寸模幂 + 一次中国剩余定理合并。
     * 这就是"RSA 为什么实际能跑得快"的全部原因 —— 指数从 d 降到 d mod (p-1)，约省 4 倍算力。
     */
    static final Function<BigInteger[], Function<BigInteger, BigInteger>> PRIVATE_OP_CRT = k -> c ->
    {
        BigInteger m1 = powMod(c, k[DP], k[PP]);
        BigInteger m2 = powMod(c, k[DQ], k[PQ]);
        BigInteger h = k[QINV].multiply(m1.subtract(m2).mod(k[PP])).mod(k[PP]);
        return m2.add(k[PQ].multiply(h));
    };

    /** 字节层运算：整数 -> 定宽大端字节，长度由模数决定。 */
    private static UnaryOperator<byte[]> pubBytes(BigInteger[] k)
    {
        int size = (k[N].bitLength() + 7) / 8;
        return block -> Fp.toBytes(PUBLIC_OP.apply(k).apply(Fp.toBigInt(block)), size);
    }

    private static UnaryOperator<byte[]> privCrtBytes(BigInteger[] k)
    {
        int size = (k[N].bitLength() + 7) / 8;
        return block -> Fp.toBytes(PRIVATE_OP_CRT.apply(k).apply(Fp.toBigInt(block)), size);
    }

    // ---------------------------------------------------------------- 填充：全是纯函数

    /** NoPadding 的本质就是"定宽大端编码"：没有随机性，也就没有语义安全。 */
    static final Function<Integer, UnaryOperator<byte[]>> NO_PADDING =
        k -> block -> Fp.toBytes(Fp.toBigInt(block), k);

    /** PKCS#1 v1.5 签名块：00 ‖ 01 ‖ FF…FF ‖ 00 ‖ T —— 确定性，所以签名字节可复现。 */
    static final Function<Integer, UnaryOperator<byte[]>> PKCS1_TYPE1 = k -> data ->
    {
        int psLen = k - data.length - 3;
        if (psLen < 8)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：填充体至少要 8 字节");
        }
        return Fp.concat(new byte[]{ 0x00, 0x01 }, Fp.repeatedByte(0xff, psLen), new byte[]{ 0x00 }, data);
    };

    /** PKCS#1 v1.5 加密块：00 ‖ 02 ‖ 非零随机 ‖ 00 ‖ M —— 随机体换来语义安全。 */
    static final Function<Integer, Function<Function<Integer, byte[]>, UnaryOperator<byte[]>>> PKCS1_TYPE2 =
        k -> random -> data ->
        {
            int psLen = k - data.length - 3;
            if (psLen < 8)
            {
                throw new IllegalArgumentException("PKCS#1 v1.5：明文不能超过 k-11 字节");
            }
            return Fp.concat(new byte[]{ 0x00, 0x02 }, nonZeroBytes(random, psLen), new byte[]{ 0x00 }, data);
        };

    /** 递归取随机字节直到里面没有 0x00（0x00 是分隔符，混进填充体会让结构产生歧义）。 */
    private static byte[] nonZeroBytes(Function<Integer, byte[]> random, int len)
    {
        final byte[] b = random.apply(len);
        boolean clean = foldRange(0, len, true, (ok, i) -> ok && b[i] != 0);
        return clean ? b : nonZeroBytes(random, len);
    }

    /** 去 PKCS#1 v1.5 填充：结构任何一步不满足都是错误，不允许"尽力解析"。 */
    private static UnaryOperator<byte[]> pkcs1Unpad(final int blockType, final int k)
    {
        return em ->
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
            if (blockType == 1 && !foldRange(2, sep, true, (ok, i) -> ok && (em[i] & 0xff) == 0xff))
            {
                throw new IllegalArgumentException("PKCS#1 v1.5 type 1：填充体必须全是 FF");
            }
            return Arrays.copyOfRange(em, sep + 1, em.length);
        };
    }

    private static int indexOf(byte[] a, int from, byte v)
    {
        return IntStream.range(from, a.length).filter(i -> a[i] == v).findFirst().orElse(-1);
    }

    /**
     * MGF1 —— "掩码生成函数"只是"摘要 + 计数器模式"：{@code T = H(seed‖0) ‖ H(seed‖1) ‖ …}。
     * OAEP 和 PSS 的安全性都建立在这一个函数上，看懂它就看懂了两种填充的 80%。
     */
    static final Function<Function<byte[], byte[]>, Function<byte[], Function<Integer, byte[]>>> MGF1 =
        hash -> seed -> length ->
        {
            int hLen = digestSize(hash);
            byte[] stream = foldRange(0, Fp.ceilDiv(length, hLen), EMPTY,
                (acc, counter) -> Fp.concat(acc,
                    hash.apply(Fp.concat(seed, Fp.toBytes(BigInteger.valueOf(counter), 4)))));
            return Arrays.copyOf(stream, length);
        };

    /**
     * OAEP 编码：两次 MGF1 + 两次异或，把明文推到整块伪随机。
     * 结构 {@code 00 ‖ maskedSeed ‖ maskedDB}，DB 头部带着 Hash(label) —— 这就是 label 绑定的来源。
     * 注意 EME-OAEP 里"绑定 label 的哈希"和"生成掩码的哈希"是两个独立参数（Sun 的默认组合就是
     * SHA-256 + MGF1/SHA-1），所以这里把两个哈希分开传 —— 面向对象 API 常把它俩焊成一个，反而看不清。
     */
    private static Function<byte[], Function<Function<Integer, byte[]>, UnaryOperator<byte[]>>> oaepEncode(
        final Function<byte[], byte[]> hash, final Function<byte[], byte[]> mgfHash, final int emLen)
    {
        final int hLen = digestSize(hash);
        return label -> random -> message ->
        {
            int psLen = emLen - message.length - 2 * hLen - 2;
            if (psLen < 0)
            {
                throw new IllegalArgumentException("OAEP：明文超过 k-2hLen-2");
            }
            byte[] db = Fp.concat(hash.apply(label), new byte[psLen], new byte[]{ 0x01 }, message);
            byte[] seed = random.apply(hLen);
            byte[] maskedDb = Fp.xor(db, MGF1.apply(mgfHash).apply(seed).apply(emLen - hLen - 1));
            byte[] maskedSeed = Fp.xor(seed, MGF1.apply(mgfHash).apply(maskedDb).apply(hLen));
            return Fp.concat(new byte[]{ 0x00 }, maskedSeed, maskedDb);
        };
    }

    /** OAEP 解码：结构检查（首字节 00、lHash 相等、0x01 之前全零）就是它的完整性来源。 */
    private static Function<byte[], UnaryOperator<byte[]>> oaepDecode(
        final Function<byte[], byte[]> hash, final Function<byte[], byte[]> mgfHash, final int emLen)
    {
        final int hLen = digestSize(hash);
        return label -> em ->
        {
            if (em.length != emLen || em[0] != 0)
            {
                throw new IllegalArgumentException("OAEP：EM 必须以 0x00 开头");
            }
            byte[] maskedDb = Arrays.copyOfRange(em, 1 + hLen, emLen);
            byte[] seed = Fp.xor(Arrays.copyOfRange(em, 1, 1 + hLen),
                MGF1.apply(mgfHash).apply(maskedDb).apply(hLen));
            byte[] db = Fp.xor(maskedDb, MGF1.apply(mgfHash).apply(seed).apply(maskedDb.length));
            if (!Arrays.equals(Arrays.copyOf(db, hLen), hash.apply(label)))
            {
                throw new IllegalArgumentException("OAEP：label 不匹配（lHash 校验失败）");
            }
            int sep = indexOf(db, hLen, (byte)0x01);
            if (sep < 0 || !foldRange(hLen, sep, true, (ok, i) -> ok && db[i] == 0))
            {
                throw new IllegalArgumentException("OAEP：0x01 分隔符缺失，或分隔符前的填充体非零");
            }
            return Arrays.copyOfRange(db, sep + 1, db.length);
        };
    }

    /**
     * PSS 编码：{@code EM = maskedDB ‖ H ‖ BC}，其中 {@code H = Hash(0⁸ ‖ Hash(M) ‖ salt)}。
     * salt 由外部注入 —— 给定同一个 salt 就得到同一个签名，这正是"随机预言"的用法。
     * DB 的分隔字节与 OAEP 一样是 0x01（很多资料写成 0x20，那是错的）。
     */
    /**
     * RFC 8017 的首位掩码：emLen 个字节比模数多出来的那些高位必须清零，否则 EM 作为整数
     * 可能 >= n。掩码宽度 = 8*emLen - emBits，而 emBits = bitLength(n) - 1 —— 它是跟着
     * 密钥走的量，绝不能写成常量 0x7f：本例的 n 只有 2046 个有效 bit，掩码其实是 0x3f。
     */
    private static int topBitMask(int emLen, int emBits)
    {
        return 0xff >>> (emLen * 8 - emBits);
    }

    private static Function<byte[], UnaryOperator<byte[]>> pssEncode(
        final Function<byte[], byte[]> hash, final int emLen, final int emBits)
    {
        final int hLen = digestSize(hash);
        final int firstByteMask = topBitMask(emLen, emBits);
        return salt -> message ->
        {
            byte[] h = hash.apply(Fp.concat(new byte[8], hash.apply(message), salt));
            byte[] db = Fp.concat(new byte[emLen - salt.length - hLen - 2], new byte[]{ 0x01 }, salt);
            byte[] maskedDb = Fp.xor(db, MGF1.apply(hash).apply(h).apply(emLen - hLen - 1));
            // 模数只用掉了 8*emLen 位里的 emBits 位，多出来的最高位必须清零，否则 EM 可能 >= n
            maskedDb[0] &= (byte)firstByteMask;
            return Fp.concat(maskedDb, h, new byte[]{ (byte)0xbc });
        };
    }

    /**
     * PSS 校验：salt 从 DB 里的 0x01 分隔符后面还原，所以验证方不需要知道 salt 长度。
     * 返回布尔 —— 验版本来就是"谓词"（Predicate），不是"函数"。
     */
    private static Function<byte[], Function<byte[], Boolean>> pssVerify(
        final Function<byte[], byte[]> hash, final int emLen, final int emBits)
    {
        final int hLen = digestSize(hash);
        final int firstByteMask = topBitMask(emLen, emBits);
        return message -> em ->
        {
            if (em.length != emLen || (em[emLen - 1] & 0xff) != 0xbc
                || (em[0] & ~firstByteMask) != 0)
            {
                return false;
            }
            byte[] maskedDb = Arrays.copyOfRange(em, 0, emLen - hLen - 1);
            byte[] h = Arrays.copyOfRange(em, emLen - hLen - 1, emLen - 1);
            byte[] db = Fp.xor(maskedDb, MGF1.apply(hash).apply(h).apply(maskedDb.length));
            db[0] &= (byte)firstByteMask;
            int sep = indexOf(db, 0, (byte)0x01);
            if (sep < 0 || !foldRange(0, sep, true, (ok, i) -> ok && db[i] == 0))
            {
                return false;
            }
            byte[] salt = Arrays.copyOfRange(db, sep + 1, db.length);
            return Arrays.equals(h, hash.apply(Fp.concat(new byte[8], hash.apply(message), salt)));
        };
    }

    /**
     * DigestInfo：ASN.1 写死的一段头 + 摘要 = "要签的东西"。
     * PKCS#1 v1.5 签名的全部协议就是这两行字节，没有更多了。
     */
    static final Function<byte[], Function<byte[], byte[]>> DIGEST_INFO =
        derPrefix -> hashBytes -> Fp.concat(derPrefix, hashBytes);

    /** SHA-1 / SHA-256 的 DigestInfo DER 前缀（RFC 8017 §9.2 Note 1 的固定表）。 */
    private static final byte[] DER_SHA1 = Fp.unhex("3021300906052b0e03021a05000414");
    private static final byte[] DER_SHA256 = Fp.unhex("3031300d060960864801650304020105000420");

    /** 纯函数签名：DigestInfo -> type 1 填充 -> 私钥模幂（CRT 路）。 */
    private static byte[] pkcs1Sign(Function<byte[], byte[]> h, byte[] der, byte[] msg)
    {
        byte[] em = PKCS1_TYPE1.apply(K).apply(DIGEST_INFO.apply(der).apply(h.apply(msg)));
        return privCrtBytes(KEY).apply(em);
    }

    // ---------------------------------------------------------------- 组合子：分段 RSA

    /**
     * RSA 一块最多搬 k-11 字节，"长消息"就是 fold：把每块的密文依次拼接。
     * 加密和解码共用同一个组合子，只是喂进去的单块函数不同。
     */
    static final Function<UnaryOperator<byte[]>, Function<Integer, UnaryOperator<byte[]>>> SEGMENTED =
        blockOp -> segmentSize -> data ->
            fold(Fp.chunks(data, segmentSize), EMPTY, (acc, seg) -> Fp.concat(acc, blockOp.apply(seg)));

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
        Fp.useBc();
        BigInteger n = KEY[N], e = KEY[E], d = KEY[D];

        List<BigInteger> samples = Arrays.asList(ONE, TWO, F4,
            TWO.pow(700).add(BigInteger.valueOf(20261014)), Fp.toBigInt(RANDOM_BYTES.apply(K - 1)));

        for (BigInteger m : samples)
        {
            // 平方-乘 == 库里的模幂：这是我们全部算术的正确性证明
            Assert.assertEquals("自写 powMod 必须等于 modPow", m.modPow(e, n), powMod(m, e, n));
            BigInteger c = PUBLIC_OP.apply(KEY).apply(m);
            Assert.assertEquals("直路私钥运算必须还原明文", m, PRIVATE_OP.apply(KEY).apply(c));
            Assert.assertEquals("CRT 路私钥运算必须还原明文", m, PRIVATE_OP_CRT.apply(KEY).apply(c));
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
        Fp.useBc();
        BigInteger p = KEY[PP], q = KEY[PQ], n = KEY[N];

        Assert.assertEquals("n 必须是 pq", n, p.multiply(q));
        Assert.assertEquals("λ 必须是 lcm(p-1, q-1)", lcm(p.subtract(ONE), q.subtract(ONE)), KEY[LAM]);
        Assert.assertEquals("dp = d mod (p-1)", KEY[D].mod(p.subtract(ONE)), KEY[DP]);
        Assert.assertEquals("dq = d mod (q-1)", KEY[D].mod(q.subtract(ONE)), KEY[DQ]);
        Assert.assertEquals("qInv = q⁻¹ mod p", q.modInverse(p), KEY[QINV]);
        Assert.assertTrue("两个素数不能相等", p.compareTo(q) != 0);

        // CRT 的数学根据：半尺寸指数运算与全尺寸运算在 mod p 下同余
        BigInteger c = Fp.toBigInt(RANDOM_BYTES.apply(K - 1));
        Assert.assertEquals("c^dp mod p 必须等于 (c^d mod n) mod p",
            powMod(c, KEY[D], n).mod(p), powMod(c, KEY[DP], p));

        // JCE 用同一组数字重建出的密钥，必须和我们的纯函数完全互操作
        KeyPair jce = jcePair(KEY);
        byte[] pt = "keys are numbers".getBytes("UTF-8");
        byte[] ours = pubBytes(KEY).apply(PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES).apply(pt));

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jce.getPrivate());
        Assert.assertArrayEquals("JCE 私钥必须能解我们纯函数加密的块", pt, dec.doFinal(ours));

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, jce.getPublic());
        byte[] fromJce = enc.doFinal(pt);
        Assert.assertArrayEquals("我们的元组必须能解 JCE 的块", pt,
            pkcs1Unpad(2, K).apply(privCrtBytes(KEY).apply(fromJce)));

        // 反向：JCE 生成的密钥拆成数字后，同一套纯函数照样自洽
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) kpg.generateKeyPair().getPrivate();
        BigInteger[] fromJceKey = KEY_GEN.apply(crt.getPrimeP()).apply(crt.getPrimeQ()).apply(crt.getPublicExponent());
        Assert.assertEquals("元组必须重建出同一个模数", crt.getModulus(), fromJceKey[N]);
        Assert.assertEquals("拆成数字后 CRT 路必须自洽", c,
            PUBLIC_OP.apply(fromJceKey).apply(PRIVATE_OP_CRT.apply(fromJceKey).apply(c)));
        log.info("[RSA-密钥] 纯数字元组 <-> JCE KeyPair 双向互操作通过");
    }

    /** 命题三：没有填充的 RSA 一无是处 —— 确定性、可延展、固定点、小指数开根。 */
    @Test
    public void textbookRsaLeaksEverything()
        throws Exception
    {
        Fp.useBc();
        BigInteger n = KEY[N];
        BigInteger m1 = Fp.toBigInt("RSA has no semantic security".getBytes("UTF-8"));
        BigInteger m2 = Fp.toBigInt("RSA has no semantic security".getBytes("UTF-8"));

        // 1) 确定性：相同明文 -> 相同密文，于是密文泄露了"相等关系"
        Assert.assertEquals("教科书 RSA 是确定性加密",
            PUBLIC_OP.apply(KEY).apply(m1), PUBLIC_OP.apply(KEY).apply(m2));

        // 2) 乘法同态：攻击者不解密就能给明文乘一个常数 —— 语义安全的反面
        BigInteger c = PUBLIC_OP.apply(KEY).apply(m1);
        BigInteger cTwice = c.multiply(EXP.apply(KEY[E]).apply(n).apply(TWO)).mod(n);
        Assert.assertEquals("密文乘 2^e 让明文翻倍", m1.multiply(TWO).mod(n),
            PRIVATE_OP.apply(KEY).apply(cTwice));

        // 3) 固定点：0、1、n-1 永远不变，攻击者一眼看穿
        Assert.assertEquals(ZERO, PUBLIC_OP.apply(KEY).apply(ZERO));
        Assert.assertEquals(ONE, PUBLIC_OP.apply(KEY).apply(ONE));
        Assert.assertEquals(n.subtract(ONE), PUBLIC_OP.apply(KEY).apply(n.subtract(ONE)));

        // 4) e=3 且 m^e < n：模数完全没起作用，开立方就还原了明文（Why e=65537 / 为什么必须填充）
        BigInteger[] smallE = KEY_GEN.apply(primeCoprimeTo(512, THREE))
            .apply(primeCoprimeTo(512, THREE)).apply(THREE);
        BigInteger msg = Fp.toBigInt("cube me".getBytes("UTF-8"));
        BigInteger cipher3 = PUBLIC_OP.apply(smallE).apply(msg);
        Assert.assertEquals("m^3 没超过 n 时，密文就是 m^3 本身", msg.pow(3), cipher3);
        Assert.assertEquals("牛顿迭代开立方即可还原明文", msg, cubeRoot(cipher3));
        log.info("[RSA-教科书] 确定性 / 可延展 / 固定点 / 小指数开方 四种弱点全部复现");
    }

    /** 立方根的牛顿迭代：{@code x' = (2x + v/x²) / 3}，折叠 300 次足够收敛到精确整数根。 */
    private static BigInteger cubeRoot(BigInteger v)
    {
        BigInteger start = ONE.shiftLeft((v.bitLength() + 2) / 3);
        return foldRange(0, 300, start,
            (x, i) -> x.multiply(TWO).add(v.divide(x.multiply(x))).divide(THREE));
    }

    /** PKCS#1 v1.5 type 2（加密填充）：与 JCE 双向互操作，畸形结构必须拒绝。 */
    @Test
    public void pkcs1v15Type2PaddingRoundTripsWithJce()
        throws Exception
    {
        Fp.useBc();
        byte[] pt = "PKCS#1 v1.5 encryption padding".getBytes("UTF-8");
        // 先看填充后的 EM 结构，再过一次公钥运算才是密文
        final byte[] em = PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES).apply(pt);
        byte[] ours = pubBytes(KEY).apply(em);

        Assert.assertEquals("EM 必须是 k 字节", K, em.length);
        Assert.assertEquals("首字节 00", 0, em[0] & 0xff);
        Assert.assertEquals("块类型 02", 2, em[1] & 0xff);
        // 结构：00 ‖ 02 ‖ PS(k-pt-3) ‖ 00 ‖ PT  ->  分隔符下标 = k - pt - 1
        Assert.assertEquals("分隔符 00 固定在明文之前", 0, em[K - pt.length - 1] & 0xff);
        Assert.assertTrue("填充体不能含 00",
            foldRange(2, K - pt.length - 1, true, (ok, i) -> ok && em[i] != 0));

        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate());
        Assert.assertArrayEquals("JCE 必须能解我们的 type-2 填充块", pt, dec.doFinal(ours));

        Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        enc.init(Cipher.ENCRYPT_MODE, jcePair(KEY).getPublic());
        Assert.assertArrayEquals("我们的 unpad 必须解出 JCE 的密文", pt,
            pkcs1Unpad(2, K).apply(privCrtBytes(KEY).apply(enc.doFinal(pt))));

        // 同一条明文两次填充不同 —— 随机填充体带来的语义安全（对比教科书 RSA 的确定性）
        Assert.assertFalse("type 2 必须 randomized", Arrays.equals(em,
            PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES).apply(pt)));

        List<byte[]> malformed = Arrays.asList(
            Fp.replace(em, 0, (byte)0x80),                       // 首字节不是 00
            Fp.replace(em, 1, (byte)0x01),                       // 块类型错（加密块必须是 02）
            Fp.replace(em, K - pt.length - 1, (byte)0x7f));      // 分隔符消失
        for (byte[] bad : malformed)
        {
            try
            {
                pkcs1Unpad(2, K).apply(bad);
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
            PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES).apply(new byte[K - 10]);
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
        Fp.useBc();
        byte[] msg = "deterministic padding means byte-identical signatures".getBytes("UTF-8");

        for (Object[] entry : new Object[][]
            { { SHA1, DER_SHA1, "SHA1withRSA" }, { SHA256, DER_SHA256, "SHA256withRSA" } })
        {
            @SuppressWarnings("unchecked")
            Function<byte[], byte[]> h = (Function<byte[], byte[]>) entry[0];
            byte[] der = (byte[]) entry[1];
            String jceName = (String) entry[2];

            byte[] ours = pkcs1Sign(h, der, msg);
            KeyPair jce = jcePair(KEY);

            Signature sig = Signature.getInstance(jceName, "BC");
            sig.initSign(jce.getPrivate());
            sig.update(msg);
            byte[] ref = sig.sign();
            Assert.assertArrayEquals(jceName + "：纯函数签名必须与 JCE 逐字节相同", ref, ours);

            Signature ver = Signature.getInstance(jceName, "BC");
            ver.initVerify(jce.getPublic());
            ver.update(msg);
            Assert.assertTrue(jceName + "：JCE 必须认我们的签名", ver.verify(ours));

            // 反方向：公钥模幂 + 去 type1 填充，得到的必须正好是 DigestInfo —— 这也验证了硬编码的 DER 前缀
            byte[] recovered = pkcs1Unpad(1, K).apply(pubBytes(KEY).apply(ref));
            Assert.assertArrayEquals(jceName + "：去掉 type1 填充后必须正好是 DigestInfo",
                DIGEST_INFO.apply(der).apply(h.apply(msg)), recovered);

            log.info("[RSA-签名] {} 与 JCE 完全一致（DigestInfo 前缀 {}）", jceName, Fp.hex(der));
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
        Fp.useBc();
        for (Object[] entry : new Object[][]
            { { SHA1, new SHA1Digest() }, { SHA256, new SHA256Digest() }, { SM3, new SM3Digest() } })
        {
            @SuppressWarnings("unchecked")
            Function<byte[], byte[]> hash = (Function<byte[], byte[]>) entry[0];
            Digest bcDigest = (Digest) entry[1];

            byte[] seed = Fp.concat("seed".getBytes("UTF-8"), RANDOM_BYTES.apply(7));
            int hLen = digestSize(hash);
            for (int len : new int[]{ 1, hLen - 1, hLen, hLen + 1, 300, K })
            {
                MGF1BytesGenerator gen = new MGF1BytesGenerator(bcDigest);
                gen.init(new MGFParameters(seed));
                byte[] ref = new byte[len];
                gen.generateBytes(ref, 0, len);
                Assert.assertArrayEquals("MGF1(hLen=" + hLen + ", len=" + len + ")",
                    ref, MGF1.apply(hash).apply(seed).apply(len));
            }
        }

        // 种子差一个 bit，整个掩码全变 —— 这就是"扩散"，也是 OAEP 随机性的载体
        byte[] s = "the same seed".getBytes("UTF-8");
        Assert.assertFalse("改一个 bit 必须改变整个掩码", Arrays.equals(
            MGF1.apply(SHA256).apply(s).apply(64),
            MGF1.apply(SHA256).apply(Fp.replace(s, 0, (byte)'T')).apply(64)));
        Assert.assertArrayEquals("MGF1 是纯函数：同输入必同输出",
            MGF1.apply(SHA256).apply(s).apply(64), MGF1.apply(SHA256).apply(s).apply(64));
        log.info("[RSA-MGF1] 与 BC MGF1BytesGenerator 一致（SHA-1 / SHA-256 / SM3）");
    }

    /** OAEP：同一个纯函数，换摘要、甚至给 MGF1 换一个摘要，都能与裁判互操作。 */
    @Test
    public void oaepRoundTripsUnderThreeHashes()
        throws Exception
    {
        Fp.useBc();
        byte[] pt = "OAEP gives RSA semantic security".getBytes("UTF-8");

        // 三种"绑定 label 的哈希"：SHA-1 / SHA-256 / SM3。裁判用 BC 的 crypto 层，参数完全显式。
        for (Object[] entry : new Object[][]
            { { SHA1, new SHA1Digest(), SHA1 }, { SHA256, new SHA256Digest(), SHA256 }, { SM3, new SM3Digest(), SM3 } })
        {
            @SuppressWarnings("unchecked")
            Function<byte[], byte[]> hash = (Function<byte[], byte[]>) entry[2];
            OAEPEncoding referee = new OAEPEncoding(new RSAEngine(), (Digest) entry[1]);

            byte[] em = oaepEncode(hash, hash, K).apply(EMPTY).apply(RANDOM_BYTES).apply(pt);
            byte[] ours = pubBytes(KEY).apply(em);
            Assert.assertEquals("OAEP 的 EM 也是 k 字节", K, em.length);
            Assert.assertEquals("首字节必须是 0", 0, em[0] & 0xff);

            referee.init(false, new RSAKeyParameters(true, KEY[N], KEY[D]));            // 解密用私钥
            Assert.assertArrayEquals("BC 必须能解我们的 OAEP 密文", pt,
                referee.processBlock(ours, 0, ours.length));

            referee.init(true, new RSAKeyParameters(false, KEY[N], KEY[E]));            // 加密用公钥
            byte[] fromBc = referee.processBlock(pt, 0, pt.length);
            Assert.assertArrayEquals("我们必须能解 BC 的 OAEP 密文", pt,
                oaepDecode(hash, hash, K).apply(EMPTY).apply(privCrtBytes(KEY).apply(fromBc)));

            Assert.assertFalse("OAEP 必须 randomized", Arrays.equals(em,
                oaepEncode(hash, hash, K).apply(EMPTY).apply(RANDOM_BYTES).apply(pt)));
            log.info("[RSA-OAEP] {} 双向互操作通过，上限 k-2hLen-2 = {}",
                hash.apply(EMPTY).length, K - 2 * digestSize(hash) - 2);
        }

        // label 哈希与 MGF1 哈希是两个独立参数：SHA-256 绑 label，SHA-1 出掩码
        OAEPEncoding mixed = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), null);
        mixed.init(true, new RSAKeyParameters(false, KEY[N], KEY[E]));
        byte[] mixedFromBc = mixed.processBlock(pt, 0, pt.length);
        Assert.assertArrayEquals("label=SHA-256 / MGF1=SHA-1 的混合组合必须也能被我们的纯函数解开", pt,
            oaepDecode(SHA256, SHA1, K).apply(EMPTY).apply(privCrtBytes(KEY).apply(mixedFromBc)));

        // JCE 端到端：显式 OAEPParameterSpec，不依赖任何"名字里默认用什么哈希"的方言
        Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate(),
            new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        Assert.assertArrayEquals("JCE(OAEPParameterSpec) 必须能解我们的 OAEP 密文", pt,
            dec.doFinal(pubBytes(KEY).apply(
                oaepEncode(SHA256, SHA256, K).apply(EMPTY).apply(RANDOM_BYTES).apply(pt))));

        // label 绑定：换个 label 就解不开 —— 这是 OAEP 唯一"额外"的能力。
        // 注意解码函数只看 EM 本身，不需要先做模幂 —— 填充与模幂正交的最好证据。
        byte[] withLabel = oaepEncode(SHA256, SHA256, K).apply("label-A".getBytes("UTF-8")).apply(RANDOM_BYTES).apply(pt);
        try
        {
            oaepDecode(SHA256, SHA256, K).apply("label-B".getBytes("UTF-8")).apply(withLabel);
            Assert.fail("label 不匹配必须失败");
        }
        catch (IllegalArgumentException expected)
        {
            log.info("[RSA-OAEP] label 绑定生效：{}", expected.getMessage());
        }

        // 长度上限 k-2hLen-2（对比 v1.5 的 k-11）：边界内侧可用，边界外侧立刻拒绝
        oaepEncode(SHA256, SHA256, K).apply(EMPTY).apply(RANDOM_BYTES).apply(new byte[K - 66]);
        try
        {
            oaepEncode(SHA256, SHA256, K).apply(EMPTY).apply(RANDOM_BYTES).apply(new byte[K - 65]);
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
        Fp.useBc();
        byte[] msg = "PSS is randomized but reproducible".getBytes("UTF-8");

        for (byte[] salt : new byte[][]{ new byte[0], RANDOM_BYTES.apply(32), RANDOM_BYTES.apply(8) })
        {
            byte[] em = pssEncode(SHA256, EM_LEN, EM_BITS).apply(salt).apply(msg);
            Assert.assertEquals("PSS 的 EM 是 emLen 字节", EM_LEN, em.length);
            Assert.assertEquals("结尾固定 0xBC", 0xbc, em[EM_LEN - 1] & 0xff);
            // 掩码不是 0x7f 的"装饰"，它由 modBits 真实决定：本例 modBits=2046 -> 掩码 0x3f
            Assert.assertEquals("首位只有 emBits 个有效位（emBits = bitLength(n)-1）",
                0, em[0] & ~topBitMask(EM_LEN, EM_BITS));
            Assert.assertTrue("EM 作为整数必须小于 n", Fp.toBigInt(em).compareTo(KEY[N]) < 0);
            Assert.assertTrue("自校验必须通过", pssVerify(SHA256, EM_LEN, EM_BITS).apply(msg).apply(em));

            // 裁判：BC 的 PSSSigner 用同一个 salt -> 同一个 EM（这一步验证了 trailing-bit 掩码的细节）
            PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), salt);
            signer.init(true, new RSAKeyParameters(true, KEY[N], KEY[D]));
            signer.update(msg, 0, msg.length);
            byte[] ref = signer.generateSignature();
            byte[] refEm = pubBytes(KEY).apply(ref);
            Assert.assertArrayEquals("sLen=" + salt.length + " 时纯函数签名必须等于 BC"
                + " ours=" + Fp.hex(em) + " | refEm=" + Fp.hex(refEm),
                ref, privCrtBytes(KEY).apply(em));

            Assert.assertFalse("同 salt 同消息，但换 salt 之后签名完全不同",
                Arrays.equals(ref, privCrtBytes(KEY).apply(
                    pssEncode(SHA256, EM_LEN, EM_BITS).apply(RANDOM_BYTES.apply(32)).apply(msg))));
        }

        byte[] fixed = "fixed-salt".getBytes("UTF-8");
        Assert.assertArrayEquals("给定 salt 后 PSS 是纯函数",
            pssEncode(SHA256, EM_LEN, EM_BITS).apply(fixed).apply(msg),
            pssEncode(SHA256, EM_LEN, EM_BITS).apply(fixed).apply(msg));

        // 与 JCE 的 RSASSA-PSS 互验：JCE 用随机 salt，我们的 pssVerify 能把 salt 从 DB 里找回来
        Signature jceSign = Signature.getInstance("SHA256withRSA/PSS", "BC");
        jceSign.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        jceSign.initSign(jcePair(KEY).getPrivate());
        jceSign.update(msg);
        byte[] jceEm = pubBytes(KEY).apply(jceSign.sign());
        Assert.assertTrue("我们的 pssVerify 必须能验 JCE 的随机 salt 签名",
            pssVerify(SHA256, EM_LEN, EM_BITS).apply(msg).apply(jceEm));

        // 反向互操作：JCE 必须认我们固定 salt 的签名（这一步之前会失败 —— 掩码算错时只有它抓得住）
        Signature jceVerify = Signature.getInstance("SHA256withRSA/PSS", "BC");
        jceVerify.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        jceVerify.initVerify(jcePair(KEY).getPublic());
        jceVerify.update(msg);
        Assert.assertTrue("JCE 必须认我们的固定 salt 签名",
            jceVerify.verify(privCrtBytes(KEY).apply(
                pssEncode(SHA256, EM_LEN, EM_BITS).apply(RANDOM_BYTES.apply(32)).apply(msg))));

        // 认证性：改一位，pssVerify 必须返回 false
        byte[] tampered = jceEm.clone();
        tampered[40] ^= 1;
        Assert.assertFalse("篡改 EM 必须让 PSS 校验失败", pssVerify(SHA256, EM_LEN, EM_BITS).apply(msg).apply(tampered));
        Assert.assertFalse("换消息必须让 PSS 校验失败", pssVerify(SHA256, EM_LEN, EM_BITS)
            .apply("other".getBytes("UTF-8")).apply(jceEm));
        log.info("[RSA-PSS] sLen=0/32/8 与 BC 逐字节一致，并能验 JCE 的随机 salt 签名");
    }

    /**
     * 命题四：填充是与模幂正交的纯函数。
     * "策略模式"在这里就退化成一张函数表 —— 没有 interface，没有 switch，没有 new。
     */
    @Test
    public void everyPaddingSchemeIsAPureFunctionOrthogonalToTheModExp()
        throws Exception
    {
        Fp.useBc();
        final byte[] body = Fp.concat("one body, eight paddings".getBytes("UTF-8"), RANDOM_BYTES.apply(8));

        List<String> names = Arrays.asList(
            "NoPadding", "PKCS#1 v1.5 type 1", "PKCS#1 v1.5 type 2",
            "OAEP/SHA-1", "OAEP/SHA-256", "OAEP/SM3", "OAEP/SHA-256+MGF1/SHA-1",
            "PSS/sLen=0", "PSS/sLen=hLen");

        List<UnaryOperator<byte[]>> paders = Arrays.<UnaryOperator<byte[]>>asList(
            NO_PADDING.apply(K),
            PKCS1_TYPE1.apply(K),
            PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES),
            oaepEncode(SHA1, SHA1, K).apply(EMPTY).apply(RANDOM_BYTES),
            oaepEncode(SHA256, SHA256, K).apply(EMPTY).apply(RANDOM_BYTES),
            oaepEncode(SM3, SM3, K).apply(EMPTY).apply(RANDOM_BYTES),
            oaepEncode(SHA256, SHA1, K).apply(EMPTY).apply(RANDOM_BYTES),
            pssEncode(SHA256, EM_LEN, EM_BITS).apply(new byte[0]),
            pssEncode(SHA256, EM_LEN, EM_BITS).apply(RANDOM_BYTES.apply(32)));

        List<UnaryOperator<byte[]>> checkers = Arrays.<UnaryOperator<byte[]>>asList(
            // NoPadding 的"去填充"只是重新取定宽整数的尾部
            em -> Arrays.copyOfRange(em, K - body.length, K),
            pkcs1Unpad(1, K),
            pkcs1Unpad(2, K),
            oaepDecode(SHA1, SHA1, K).apply(EMPTY),
            oaepDecode(SHA256, SHA256, K).apply(EMPTY),
            oaepDecode(SM3, SM3, K).apply(EMPTY),
            oaepDecode(SHA256, SHA1, K).apply(EMPTY),
            em -> requirePss(em, body),
            em -> requirePss(em, body));

        for (int i = 0; i < names.size(); i++)
        {
            String name = names.get(i);
            byte[] em = paders.get(i).apply(body);
            Assert.assertEquals(name + "：EM 必须正好填满一个模数块", K, em.length);
            Assert.assertTrue(name + "：EM 作为整数必须 < n", Fp.toBigInt(em).compareTo(KEY[N]) < 0);

            // 同一条模幂管线走一遍：私钥 -> 公钥 -> 去填充。填充函数不知道 RSA 的任何事
            byte[] signed = privCrtBytes(KEY).apply(em);
            byte[] recoveredEm = pubBytes(KEY).apply(signed);
            Assert.assertArrayEquals(name + "：模幂往返必须还原 EM", em, recoveredEm);
            Assert.assertArrayEquals(name + "：unpad(pad(M)) 必须等于 M", body, checkers.get(i).apply(recoveredEm));

            // 结构字节（最高位必须为 0）翻转：除 NoPadding 外全部拒绝
            byte[] flipped = Fp.replace(recoveredEm, 0, (byte)(recoveredEm[0] ^ 0x80));
            if (i == 0)
            {
                Assert.assertArrayEquals("NoPadding 连结构都没有，篡改被静默接受",
                    body, checkers.get(0).apply(flipped));
            }
            else
            {
                assertRejected(name, checkers.get(i), flipped);
            }
            log.info("[RSA-填充] {}：k={} 字节，独立于模幂且能拒绝结构篡改", name, K);
        }

        // 诚实的结论，也是"填充模式"之间真正的差别：
        // PKCS#1 v1.5 只检查填充结构，明文本身被改了它毫无察觉 -> 静默返回损坏的明文；
        // OAEP/PSS 的明文处在"由自己算出的掩码"之下，改一个 bit 会让整块结构校验失败 -> 拒绝。
        for (int i : new int[]{ 1, 2 })
        {
            byte[] emForFlip = paders.get(i).apply(body);
            // 只翻转代表消息的最后一字节（异或 1，保证内容确实变了）
            byte[] dataFlipped = Fp.replace(emForFlip, K - 1, (byte)(emForFlip[K - 1] ^ 0x01));
            byte[] back = checkers.get(i).apply(pubBytes(KEY).apply(privCrtBytes(KEY).apply(dataFlipped)));
            Assert.assertEquals(names.get(i) + "：明文长度不变", body.length, back.length);
            Assert.assertFalse(names.get(i) + "：消息内容被静默破坏（v1.5 没有完整性）", Arrays.equals(body, back));
        }
        for (int i : new int[]{ 3, 4, 5, 6 })
        {
            byte[] emForFlip = paders.get(i).apply(body);
            // OAEP 里 EM 的倒数第二字节正好落在 maskedDB 的最后一字节 = 明文的最后一个字节
            byte[] dataFlipped = Fp.replace(emForFlip, K - 2, (byte)(emForFlip[K - 2] ^ 0x01));
            assertRejected(names.get(i) + "（改消息位）", checkers.get(i),
                pubBytes(KEY).apply(privCrtBytes(KEY).apply(dataFlipped)));
        }

        // PSS 的 EM 末尾是固定 trailer 0xBC；它的 maskedDB 覆盖整条消息，所以改任何一位都会失败
        for (int i : new int[]{ 7, 8 })
        {
            byte[] emForFlip = paders.get(i).apply(body);
            for (int at : new int[]{ 100, K - 2, K - 1 })
            {
                assertRejected(names.get(i) + "（改第 " + at + " 字节）", checkers.get(i),
                    pubBytes(KEY).apply(privCrtBytes(KEY).apply(
                        Fp.replace(emForFlip, at, (byte)(emForFlip[at] ^ 0x01)))));
            }
        }
    }

    private static byte[] requirePss(byte[] em, byte[] body)
    {
        if (!pssVerify(SHA256, EM_LEN, EM_BITS).apply(body).apply(em))
        {
            throw new IllegalArgumentException("PSS 校验失败");
        }
        return body;
    }

    private static void assertRejected(String name, UnaryOperator<byte[]> checker, byte[] em)
    {
        try
        {
            checker.apply(em);
            Assert.fail(name + "：结构字节被翻转必须被拒绝");
        }
        catch (IllegalArgumentException expected)
        {
            log.info("[RSA-填充] {} 拒绝篡改：{}", name, expected.getMessage());
        }
    }

    /** 长消息 = fold over 块。RSA 从不"流式"，所谓流式只是外面套了一层分块折叠。 */
    @Test
    public void longMessageRsaIsAFoldOverBlocks()
        throws Exception
    {
        Fp.useBc();
        byte[] longMsg = Fp.repeat("RSA can carry at most k-11 bytes, so anything longer is a fold. ", 12)
            .getBytes("UTF-8");
        int segmentSize = K - 11;
        Assert.assertTrue("这条消息必须超过单个 RSA 块", longMsg.length > segmentSize);

        // 加密方向：每段 -> type 2 填充 -> 公钥模幂 -> 拼接
        UnaryOperator<byte[]> encryptOne = seg ->
            pubBytes(KEY).apply(PKCS1_TYPE2.apply(K).apply(RANDOM_BYTES).apply(seg));
        byte[] ct = SEGMENTED.apply(encryptOne).apply(segmentSize).apply(longMsg);
        Assert.assertEquals("密文长度 = 段数 × k", Fp.ceilDiv(longMsg.length, segmentSize) * K, ct.length);

        // 解密方向：密文按 k 切块 -> 私钥模幂 -> 去填充 -> 拼接（同一个组合子，不同单块函数）
        UnaryOperator<byte[]> decryptOne = block -> pkcs1Unpad(2, K).apply(privCrtBytes(KEY).apply(block));
        Assert.assertArrayEquals("分段 fold 往返必须还原长消息", longMsg,
            SEGMENTED.apply(decryptOne).apply(K).apply(ct));

        // 裁判：JCE 逐段解我们的密文
        Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        dec.init(Cipher.DECRYPT_MODE, jcePair(KEY).getPrivate());
        List<byte[]> cipherSegments = Fp.chunks(ct, K);
        List<byte[]> plainSegments = Fp.chunks(longMsg, segmentSize);
        for (int i = 0; i < cipherSegments.size(); i++)
        {
            Assert.assertArrayEquals("第 " + i + " 段必须与 JCE 解密一致",
                plainSegments.get(i), dec.doFinal(cipherSegments.get(i)));
        }

        // 用 OAEP 时上限就变成 k-2hLen-2 —— 同一个 fold，换个单块函数就换个上限
        UnaryOperator<byte[]> oaepEncryptOne = seg ->
            pubBytes(KEY).apply(oaepEncode(SHA256, SHA256, K).apply(EMPTY).apply(RANDOM_BYTES).apply(seg));
        Assert.assertEquals("OAEP 分段密文同样是段数 × k",
            Fp.ceilDiv(longMsg.length, K - 66) * K,
            SEGMENTED.apply(oaepEncryptOne).apply(K - 66).apply(longMsg).length);

        try
        {
            SEGMENTED.apply(encryptOne).apply(K - 10).apply(new byte[K - 9]);
            Assert.fail("分段超过 k-11 必须失败");
        }
        catch (IllegalArgumentException expected)
        {
            Assert.assertEquals("PKCS#1 v1.5：明文不能超过 k-11 字节", expected.getMessage());
        }
        log.info("[RSA-分段] {} 字节明文 / {} 段，纯 fold 与 JCE 互操作通过",
            longMsg.length, cipherSegments.size());
    }
}
