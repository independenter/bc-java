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
 *
 * <p><b>符号表 —— 本文件每条公式里的字母/记号</b>（后文各公式组还会重复一份精简版）
 * <pre>
 *   ── 密钥 = 九个整数（keyGen 返回的数组，下标常量 N/E/D/LAM/DP/DQ/QINV/PP/PQ 就是它们）──
 *   p, q    两枚大素数，整套密钥的秘密来源；本文件各取 1024 bit，p ≠ q，于是 n 约 2048 bit
 *   n       模数 n = p·q，公钥/私钥共用的"取模范围"；任何进模幂的整数都必须落在 [0, n)
 *   e       公钥指数，唯一要求 gcd(e, λ) = 1；业界恒用 65537 = 费马素数 F4 = 2^16 + 1
 *   d       私钥指数：e·d ≡ 1 (mod λ)，等价写法 d = e⁻¹ mod λ；不知道 λ 就算不出来
 *   λ       Carmichael 函数 λ(n) = lcm(p−1, q−1)：使 a^λ ≡ 1 (mod n) 对所有与 n 互素的 a
 *           同时成立的最小正指数；λ = φ(n)/gcd(p−1, q−1)，比欧拉 φ(n)=(p−1)(q−1) 更小更"够用"
 *   dp      dp = d mod (p−1)：CRT 私钥运算在 p 这条"半边"上的短指数
 *   dq      dq = d mod (q−1)：CRT 私钥运算在 q 这条"半边"上的短指数
 *   qInv    qInv = q⁻¹ mod p（方向很重要：q 的逆元、模 p）：CRT 合并时把两个半答案焊成一个的系数
 *   ── 运算与消息 ──
 *   m       明文整数（更准确：编码成 EM 之后当作大端整数读出来的那个数，m ∈ [0, n)）
 *   c       密文整数 c = m^e mod n，即公钥运算 publicOp 的返回值
 *   s       签名整数 s = EMS^d mod n（私钥运算），验签算 s^e mod n 还原 EMS
 *   x^y     模幂 (modular exponentiation, 口语 modexp)：本文件里永远带模数，写作 x^y mod n
 *   ⁻¹ mod  模逆元 (modular inverse)：a⁻¹ 是满足 a·a⁻¹ ≡ 1 (mod m) 的唯一数，用扩展欧几里得求
 *   ≡       同余 (congruence)：a ≡ b (mod m) 意思是 m | (a−b)，读作"m 整除 (a−b)"
 *   a | b   "a 整除 b"，即存在整数 k 使 b = k·a
 *   gcd     最大公约数 (greatest common divisor)；lcm 最小公倍数 (least common multiple)，
 *           lcm(a, b) = a·b / gcd(a, b)
 *   ⌈x⌉     向上取整，例如字节数 = ⌈bit 数 / 8⌉
 *   ‖       字节串接 (concatenation)；⊕ 等长字节串逐字节异或 (xor)，x ⊕ x = 0 所以掩码可逆
 *   ── 编码层（填充/掩码）的字母 ──
 *   k       模数字节数 k = ⌈bitLength(n)/8⌉（本例 2048 bit ⇒ k = 256）；v1.5 与 OAEP 的 EM 正好 k 字节
 *   hLen    所选摘要的输出字节数：SHA-1 为 20，SHA-256 与 SM3 为 32
 *   modBits emBits emLen   RFC 8017 的三个量：modBits = bitLength(n)，emBits = modBits − 1，
 *           emLen = ⌈emBits/8⌉；PSS 的 EM 是 emLen 字节（本例 256，与 k 相等；RFC 允许少一字节），
 *           v1.5 与 OAEP 则固定用 k 字节
 *   PS      Padding String 填充体：v1.5 加密里是非零随机字节，OAEP 的 DB 里是全零字节
 *   M       真正的消息/明文；T = DigestInfo（签名侧"要签的那段字节"）
 *   EM/EMS  Encoded Message / Encoded Message for Signature：填充好的整块字节，模幂真正的输入。
 *           RFC 8017 里加密与签名的这块都叫 EM，EMS 只是文献（和本文件注释）为区分签名侧起的别名
 *   seed, DB, maskedSeed, maskedDb   OAEP 的四个量；salt, H, maskedDB   PSS 的三个量
 * </pre>
 *
 * <p><b>术语速查 —— 首次出现的专业名词都在这里给一句白话解释，后文直接使用</b>
 * <pre>
 *   公钥 / 私钥   公钥 (n, e) 公开，只做"正向模幂"（加密、验签）；私钥 (d 与 p,q,dp,dq,qInv) 保密，
 *                 做"反向模幂"（解密、签名）。二者是同一个 n 上的一对互逆指数。
 *   模幂 (modexp) RSA 里唯一的重型算术：整数的幂再取余。加密/解密/签名/验签全是它，只是指数不同。
 *   单向函数 (one-way function)   正向 m ↦ m^e mod n 很便宜；反过来从 (n, e, c) 求 m 目前没有
 *                 可行算法（最快路径是先分解 n），这种"正向易、逆向难"就叫单向。
 *   陷门 (trapdoor)   单向函数里只留给持钥人的后门：知道 p、q（于是知道 λ）就能求 d 反向算。
 *   欧拉函数 φ(n)   1..n 中与 n 互素的整数个数；n = p·q 时 φ(n) = (p−1)(q−1)。
 *   Carmichael λ(n)  使 a^λ ≡ 1 (mod n) 对所有 gcd(a,n)=1 的 a 成立的最小正指数；λ(n)=lcm(p−1,q−1)。
 *   大端序列化 (big-endian)   最高有效字节排在最前的字节串写法；RSA 的一个"块"就是 k 字节大端
 *                 无符号整数（Calc.toBytes / Calc.toBigInt 负责来回换算，无符号、不带符号位）。
 *   ASN.1 DER   一套"用字节描述数据结构"的编码规则：每个字段是 标签(tag) ‖ 长度(len) ‖ 内容。
 *                 DigestInfo 就是 DER 写死的 SEQUENCE{ SEQUENCE{OID, NULL}, OCTET STRING }。
 *   OID (对象标识符, Object Identifier)   全球给每种算法分配的数字串，如
 *                 SHA-1 = 1.3.14.3.2.26，SHA-256 = 2.16.840.1.101.3.4.2.1；DER 前缀里含的就是它。
 *   KAT (Known-Answer Test，已知答案测试)   拿一个外部"标准答案"（这里是 JCE / BC 的实现，或
 *                 RFC 里写死的字节）与自写实现逐字节比对；本类的每个测试都是 KAT。
 *   textbook RSA（裸 RSA）   不加任何填充直接 m ↦ m^e mod n。它确定性（同明文必同密文）、
 *                 可延展（密文能做代数变形）、有固定点、小指数还能直接开方，所以没有任何
 *                 真实协议直接用它 —— 这就是"安全性全部来自填充"的反面论证。
 *   语义安全 (semantic security)   攻击者即使能自选明文，也无法从密文区分它对应哪条明文；
 *                 来源是填充里的随机字节，所以同一明文每次得到不同密文。
 *   不可延展 / 可延展 (malleable)   能从密文 c 造出 c′ 使解密结果与原文有"已知关系"（如 2m）
 *                 就叫可延展；OAEP/PSS 的结构自检把它堵住，v1.5 与裸 RSA 堵不住。
 *   选择密文攻击 (CCA) / 解密 oracle   攻击者能把任意字节串递给私钥持有者解，并根据"报错/不报错"
 *                 等信息调整下一次提问；v1.5 的解析差异正好提供这种信息（Bleichenbacher 攻击）。
 *   Miller–Rabin 素性测试   概率性判定大数是否为素数：见 primeCoprimeTo 的注释。
 *   随机预言 (random oracle)   可证明安全分析里的理想化哈希模型；PSS/OAEP 的安全性是在这个模型下
 *                 归约到"分解 n / 求模 e 次根"这一困难问题的。
 * </pre>
 *
 * <p><b>几条主干推导分别写在哪里</b>：为什么 (m^e)^d ≡ m (mod n)（含 m 与 n 不互素时用中国剩余定理
 * 分 p/q 两边论证）在 privateOp；CRT 合并式逐字母推导与"快约 4 倍"的算术在 privateOpCrt；
 * 素性测试 / 随机素数 / gcd 在 primeCoprimeTo 与 lcm；乘法同态为什么是攻击面在
 * textbookRsaLeaksEverything；v1.5 的 PS 约束与 Bleichenbacher 计数攻击直觉在 pkcs1Type2 与 pkcs1Unpad；
 * MGF1 的计数器结构在 mgf1；OAEP 的 seed/DB/maskedSeed/maskedDb 与"改一字节整包废"在
 * oaepEncode 与 oaepDecode；PSS 的 salt/H/DB/trailer 在 pssEncode 与 pssVerify；
 * DigestInfo 的 ASN.1 DER 字段拆解与"e 为什么能当验证指数"在 DER_SHA1 附近与 pkcs1Sign。
 */
@Slf4j
public class RsaEssenceTest
{
    // ---------------------------------------------------------------- 密钥元组的下标

    /**
     * 密钥就是数字元组：下面 9 个下标说明它到底包含什么。
     * <pre>
     *   每个下标"数学上是什么 / 算法为什么非要它不可"：
     *     N    = 0  n     模数 n = p·q：公钥私钥共用的取模范围，也决定分组/填充的字节长度 k
     *     E    = 1  e     公钥指数：只要求 gcd(e, λ)=1；固定 65537 是因为它二进制只有一个 1，
     *                     平方-乘时几乎每轮都只平方不乘，公钥运算（加密 + 验签）最便宜
     *     D    = 2  d     私钥指数：e·d ≡ 1 (mod λ) 在 [1, λ) 内的唯一解，"反向模幂"用的指数
     *     LAM  = 3  λ     Carmichael λ(n) = lcm(p−1, q−1)：求 d 时的模数；算它必须先知道 p、q，
     *                     所以 λ 就是陷门 (trapdoor) 本身，也是"能分解 n ⇔ 能求 d"的依据
     *     DP   = 4  dp    d mod (p−1)：CRT 私钥运算 p 分支的短指数（Fermat 小定理保证可以这么降）
     *     DQ   = 5  dq    d mod (q−1)：CRT 私钥运算 q 分支的短指数
     *     QINV = 6  qInv  q⁻¹ mod p：CRT 合并系数。本文件的方向是"q 的逆元、模 p"，
     *                     于是它乘 (m1 − m2) 后正好把 m2 抬到与 m1 同余 —— 见 privateOpCrt
     *     PP   = 7  p     素数本身：半尺寸模幂要 mod p，没有 p 就没有"半边"可算；也是重算 λ 的原料
     *     PQ   = 8  q     同上，q 分支
     *   提醒：PKCS#1 的 ASN.1 DER 私钥结构 RSAPrivateKey 的字段顺序是
     *     SEQUENCE{ version, n, e, d, p, q, dp, dq, qInv }（JCE 的 RSAPrivateCrtKeySpec 同序），
     *   与本数组的下标顺序（… DP DQ QINV PP PQ）不同 —— jcePair() 就是按 JCE 的顺序传参的。
     * </pre>
     */
    private static final int N = 0, E = 1, D = 2, LAM = 3, DP = 4, DQ = 5, QINV = 6, PP = 7, PQ = 8;

    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * 业界标准公开指数：费马素数 F4 = 2^16+1，二进制只有一个 1，所以公钥运算特别快。
     * 补一句公式里的字母：e = F4 = 2^(2^4) + 1 = 65537，二进制是 1_0000_0000_0000_0001，
     * 平方-乘扫描 17 位里只有 2 个 1 ⇒ 约 17 次平方 + 2 次乘法；比 e=3 抗小指数开方攻击，
     * 又比随机 2048-bit 指数便宜得多。要求始终是 gcd(e, λ) = 1，否则 d = e⁻¹ mod λ 不存在
     * （这也是 primeCoprimeTo 要额外检查 gcd(e, p−1) = 1 的原因）。
     */
    private static final BigInteger F4 = BigInteger.valueOf(65537);

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] EMPTY = new byte[0];

    // ---------------------------------------------------------------- 摘要：按名字选用的普通方法

    // 这三种摘要在 ASN.1 DER 里的"算法身份"是各自的 OID（对象标识符，全球唯一的数字编号串），
    // 签名填充 DigestInfo 里写死的正是它（完整前缀的逐字节拆解见 DER_SHA1 / DER_SHA256 附近）：
    //   SHA-1    1.3.14.3.2.26            DER 里编成 06 05 2b 0e 03 02 1a
    //   SHA-256  2.16.840.1.101.3.4.2.1   DER 里编成 06 09 60 86 48 01 65 03 04 02 01
    //   SM3      1.2.156.10197.1.401      中国 GM/T 0004 为 SM3 分配的 OID；RFC 8017 的 v1.5 表里没有它，
    //                                      所以本文件只用它做 OAEP/MGF1 的摘要，不做 DigestInfo
    /** 摘要算法名（JCE MessageDigest 的名字），值表里存的就是这些字符串。 */
    private static final String SHA1 = "SHA-1";
    private static final String SHA256 = "SHA-256";
    private static final String SM3 = "SM3";

    /**
     * 摘要过程：给定算法名 + 消息，返回摘要字节 —— 一个带真实参数的普通静态方法。
     * checked 异常属于"副作用"，必须关在边界里，边界之外的代码就是一条直线，不再谈"纯函数"这件事。
     * <pre>
     *   记号：digestOf(alg, M) = Hash(M)，输出长度固定，记作 hLen = ‖Hash(·)‖；
     *         SHA-1 的 hLen = 20，SHA-256 与 SM3 的 hLen = 32（digestSize 就是在量这个数）。
     *   术语：哈希 / 摘要 (hash, message digest) —— 把任意长度的字节压成固定长度字节、并且
     *         抗碰撞（找不到 M ≠ M′ 使 Hash(M) = Hash(M′)）的公开函数。RSA 里它干三件事：
     *         把"要签的东西"变成定长（DigestInfo）、绑定 label（OAEP 的 lHash）、
     *         当掩码生成器的内核（MGF1 = 摘要 + 计数器）。
     * </pre>
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

    /**
     * 摘要长度：空消息过一次摘要就知道，不需要 Digest 对象。
     * 这就是符号表里的 hLen：OAEP 的 seed 正好取 hLen 字节，DB 头部也正好放 hLen 字节的 lHash，
     * PSS 的 H 与 salt 长度（sLen）同样以它为尺子 —— 所有填充方案的长度算术都从这个数出发。
     */
    private static int digestSize(String algorithm)
    {
        return digestOf(algorithm, EMPTY).length;
    }

    /**
     * 随机字节：整个文件唯一需要的"随机源"，直接调用，不做依赖注入。
     * 术语：SecureRandom 是密码学安全伪随机数生成器 (CSPRNG, cryptographically secure PRNG)：
     * 输出不可预测，所以 OAEP 的 seed、v1.5 的 PS、PSS 的 salt 都由它供给 —— 语义安全
     * (semantic security) 的"随机性"就是这几个字节，模幂本身一点都不随机。
     */
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
     * <pre>
     *   记号：powMod(base, exp, n) = base^exp mod n
     *         bit  = 指数 exp 从最高位到最低位的下标；exp.bitLength() = exp 的最高有效位位置
     *         acc  = 累加器（不变量：acc ≡ base^(exp 已扫描过的高位前缀) (mod n)）
     *   术语：平方-乘 / 二进制左到右快速幂 (square-and-multiply, left-to-right binary method)。
     *         原理是 exp = Σ bit_i·2^i，于是 base^exp = Π (base^(2^i))^(bit_i)：
     *         每轮平方一次（对应 i 升一位），该位为 1 才额外乘一次 base。
     *   为什么非要它：直接算 base^exp 会得到几万个 bit 的天文数字，再取余也存不下；
     *         这里"每步都 mod n"，中间量始终不超过 n，代价约 2·bitLength(exp) 次模乘。
     *         这就是 RSA 能用的前提：模幂是多项式时间，而分解 n 不是（单向性来自这里）。
     * </pre>
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
     * <pre>
     *   逐字母的公式（左边是本方法的局部变量，右边是它数学上的定义）：
     *     p, q      两枚输入素数（primeCoprimeTo 现取），要求 p ≠ q
     *     n  = p·q                    取模范围；k = ⌈bitLength(n)/8⌉ 决定后面所有填充的长度
     *     λ  = lcm(p−1, q−1)          Carmichael 函数；lcm(a,b) = a·b / gcd(a,b)，见下面的 lcm
     *     d  = e⁻¹ mod λ              扩展欧几里得求模逆；存在 ⟺ gcd(e, λ) = 1（测试里断言过）
     *     dp = d mod (p−1)            CRT 的 p 分支短指数
     *     dq = d mod (q−1)            CRT 的 q 分支短指数
     *     qInv = q⁻¹ mod p            CRT 合并系数（注意方向：q 的逆、模 p，不是 p 的逆）
     *   为什么 e·d ≡ 1 (mod λ) 就够了（而不是必须 mod φ）：
     *     解密要用 m^(e·d) ≡ m (mod n)。λ 是"对所有与 n 互素的 a 都有 a^λ ≡ 1"的最小指数，
     *     所以 e·d = 1 + t·λ 直接给出 m^(e·d) = m·(m^λ)^t ≡ m；完整推导（含 m 与 n 不互素时
     *     怎么用 CRT 分 p、q 两边论证）写在 privateOp 的注释里。
     *   为什么不用 φ：φ(n) = (p−1)(q−1) = λ·gcd(p−1, q−1)，λ 整除 φ，用 φ 求逆同样能解密，
     *     但模数更大、得到的 d 不唯一且偏大；λ 才是"最小可用"的那个 —— 也是标准实现的取值。
     *   为什么 λ 是陷门 (trapdoor) 信息：算 p−1、q−1 必须先知道 p、q，也就是必须先分解 n；
     *     只知道 (n, e) 的人求不出 λ，也就求不出 d —— 单向性的全部内容都在这里。
     * </pre>
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

    /**
     * 最小公倍数 (least common multiple, lcm)：{@code lcm(a, b) = a·b / gcd(a, b)}，
     * 其中 gcd 是最大公约数 (greatest common divisor)，BigInteger.gcd 用欧几里得算法求
     * （gcd(a,b) = gcd(b, a mod b)，一路降到余数为 0）。
     * 先乘后除是为了避免"a/gcd 再乘 b"之外的写法差异；大整数除法精确整除，没有舍入问题。
     * RSA 里 λ = lcm(p−1, q−1)：指数周期在 mod p 下是 p−1 的倍数、在 mod q 下是 q−1 的倍数，
     * 两边同时满足的最小正数就是它们的最小公倍数。
     */
    private static BigInteger lcm(BigInteger a, BigInteger b)
    {
        return a.multiply(b).divide(a.gcd(b));
    }

    /**
     * while(true) 重试直到"是素数，且 p-1 与 e 互素"。
     * <pre>
     *   probablePrime(bits, RANDOM) 内部流程（BigInteger 的实现，等价于教科书做法）：
     *     1) 随机取 bits 位整数，把最高位置 1（保证真的是 bits 位）、最低位置 1（保证是奇数）；
     *     2) 用一批小素数试除，先把明显合数的候选廉价地扔掉；
     *     3) 若干轮 Miller–Rabin 概率素性测试（primality test）：
     *        写 p−1 = 2^s · r（r 奇数），取随机见证 a ∈ [2, p−2]，
     *        若 a^r 不 ≡ 1 (mod p)，且序列 a^r, a^(2r), …, a^(2^(s−1)r) 里也没有 ≡ −1 (mod p) 的项，
     *        则 p 必为合数（a 称为"合数见证"witness）。每过一轮，"其实是伪素数"的概率至少减到 1/4。
     *     所以它是"probable prime"（可能素数）而非证明素数；bits 足够大时错误概率小到可以忽略。
     *   bits 与强度：这里 p、q 各 1024 bit ⇒ n = p·q 约 2048 bit，就是业界说的"2048 位 RSA"。
     *   密钥长度 ≠ 安全位数 (security strength, 也按 bit 计)：RSA 的强度不在 n 的位数，而在"分解 n"
     *     有多难；已知最快是数域筛法 NFS (Number Field Sieve)，是亚指数复杂度，所以"位数"换不来
     *     线性的强度 —— 这是它和对称密钥最本质的区别（AES-128 就实打实是 128 位安全）。
     *     经验对照（NIST SP 800-57 / ECRYPT 强度表）：n≈3072 bit ↔ 约 128 位、2048 ↔ 约 112 位、
     *     7680 左右 ↔ 约 192 位、1024 ↔ 约 80 位（已被认为不安全）。想要"128 位安全"必须用 3072 位
     *     RSA，而不是 128 位；本文件用 2048 位只为教学跑得动，生产环境早已建议 ≥3072。
     *   两个附加条件：
     *     gcd(e, p−1) = 1  —— e 必须在 mod (p−1) 下可逆，否则 d = e⁻¹ mod λ 可能不存在
     *     gcd(e, p)     = 1  —— 防御性检查：e 不能等于 p 本身（例如 e=3 且 p=3 时整个结构退化）
     * </pre>
     */
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
    //   P_BIG / Q_BIG 各 1024 bit 的（概率）素数，且都满足 gcd(e, p−1) = 1 —— 见 primeCoprimeTo
    //   KEY 就是 keyGen 返回的九元组，按上面对齐的下标读：KEY[N] = n, KEY[E] = e, KEY[D] = d,
    //   KEY[LAM] = λ, KEY[DP] = dp, KEY[DQ] = dq, KEY[QINV] = qInv, KEY[PP] = p, KEY[PQ] = q。
    //   放在静态字段里只算一次：所有测试共用同一把钥匙，这样"手写实现 vs JCE/BC"的每次对照
    //   都在同一个 n 上进行，失败时可以直接比对字节。
    private static final BigInteger P_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger Q_BIG = primeCoprimeTo(1024, F4);
    private static final BigInteger[] KEY = keyGen(P_BIG, Q_BIG, F4);

    // 位长 / 字节长度的换算（本文件所有 k、emLen、hLen、psLen 都是这套算术）：
    //   bitLength(x) = x 的最高有效 1 位的位置，等于 ⌊log2 x⌋ + 1（x = 0 时定义为 0）
    //   (bits + 7) / 8 = ⌈bits/8⌉：整数除法版的"向上取整"，即表示 x 所需的最少字节数
    //   本例 n 是 2048-bit 级的模数 ⇒ k = 256 字节；"一个 RSA 块"就是 k 字节大端无符号整数
    //   注意 bitLength(n) 常常比"p、q 位数之和"少几位：两个随机素数相乘，n 的最高几位经常是 0，
    //   于是"1024+1024 的密钥"里 n 实际可能只有 2047 位 —— 这个细节正是下面 EM_BITS 的看点。
    /** k = 模数的字节数 —— 所有填充过程都以它为长度基准。 */
    private static final int K = (KEY[N].bitLength() + 7) / 8;

    /**
     * RFC 8017：modBits = bitLength(n)，emBits = modBits - 1，emLen = (emBits+7)/8。
     * 关键细节：n 是两个随机大素数的乘积，它的最高几位经常是 0 —— 本例的 n 就只有
     * 2046 个有效 bit，于是 8*k - emBits = 2，首位掩码是 0x3f 而不是 0x7f。
     * 用"8k-1"去算掩码是一个真实的、能导致互操作失败的 bug（BC 会拒绝我们的签名）。
     * <pre>
     *   逐字母（这三个量就是 PSS 那两条公式里全部的"长度算术"）：
     *     modBits = bitLength(n)             n 真正占用的位数。两枚 1024-bit 素数相乘只会落在
     *                                        2047 或 2048 位（名义上的"2048-bit 密钥"就是这个意思）
     *     emBits  = modBits − 1              EM 当作整数时被允许使用的位数；故意少 1 位，是为了让
     *                                        编出来的 EM 一定满足 EM 小于 n（否则模幂的输入越界，
     *                                        RFC 8017 的 RSACRYPT 会直接失败）
     *     emLen   = ⌈emBits/8⌉              EM 的字节数；本例是 256，与 k 相等（RFC 允许它比 k 少 1 字节，
     *                                        所以 PSS 的两个方法都显式收 emLen 参数，不假设 emLen == k）
     *     掩码宽度 = 8·emLen − emBits        emLen 个字节能表达到 8·emLen 位，比允许的 emBits 位多出几位
     *     首位掩码 = 0xff 右移"掩码宽度"位   modBits = 2047 ⇒ 宽 2 ⇒ 0x3f；modBits = 2048 ⇒ 宽 1 ⇒ 0x7f，
     *                                        两种都可能出现（密钥是运行时随机生成的），所以只能现算
     *   三个量互相独立、都能变，所以掩码绝不能写死成常量 —— 这正是上面那条"真实 bug"的成因。
     * </pre>
     */
    private static final int EM_BITS = KEY[N].bitLength() - 1;
    private static final int EM_LEN = (EM_BITS + 7) / 8;

    // ---------------------------------------------------------------- 公钥 / 私钥运算

    /**
     * 公钥运算：一次模幂 {@code m^e mod n}。
     * <pre>
     *   公式：c = m^e mod n      m ∈ [0, n) 明文整数；e = KEY[E] 公钥指数；n = KEY[N] 模数；c 输出
     *   加密时输入是"编码后的 EM 当大端整数读出的 m"；验签时同一个函数换成 s^e mod n，
     *   即把签名整数 s 还原成 EMS —— e 能当"验证指数"完全来自 e·d ≡ 1 (mod λ)：
     *     s = EMS^d mod n ⇒ s^e ≡ EMS^(d·e) = EMS^(1 + t·λ) ≡ EMS (mod n)（推导见 privateOp）。
     *   注意这里不需要 d：公钥运算只有 (n, e) 两个整数，所以任何人都能算，但没人能反向。
     * </pre>
     */
    private static BigInteger publicOp(BigInteger[] key, BigInteger m)
    {
        return powMod(m, key[E], key[N]);
    }

    /**
     * 私钥运算（直路）：一次全尺寸模幂 {@code c^d mod n}。
     *
     * <p><b>正确性推导：为什么 (m^e)^d ≡ m (mod n)</b>
     * <pre>
     *   密钥关系   e·d ≡ 1 (mod λ)  ⇒  存在整数 t 使 e·d = 1 + t·λ     （λ = lcm(p−1, q−1)）
     *   于         (m^e)^d = m^(e·d) = m^(1 + t·λ) = m · (m^λ)^t
     *   只要       m^λ ≡ 1 (mod n)，就有  m · (m^λ)^t ≡ m · 1^t ≡ m  (mod n)。
     *
     *   "m^λ ≡ 1" 从哪来 —— 分两种情况，用的定理不同：
     *   ① gcd(m, n) = 1（m 与 n 互素，绝大多数情况）
     *      · 欧拉定理 (Euler's theorem)：gcd(m,n)=1 ⇒ m^φ(n) ≡ 1 (mod n)，φ(n)=(p−1)(q−1)。
     *      · Carmichael 函数 λ(n) 的定义就是"使上式对所有互素的 m 同时成立的最小指数"，
     *        它满足 λ | φ（λ 整除 φ），所以 m^λ ≡ 1 更强、也更省。
     *      · λ = lcm(p−1, q−1) 的证明用中国剩余定理 (Chinese Remainder Theorem, CRT) 分两边：
     *          mod p：λ 是 p−1 的整数倍，设 λ = u·(p−1) ⇒ m^λ = (m^(p−1))^u ≡ 1^u = 1 (mod p)
     *                 ← 这一步是 Fermat 小定理（p 素数、p 不整除 m 时 m^(p−1) ≡ 1 (mod p)）
     *          mod q：同理 m^λ ≡ 1 (mod q)。
     *          两个素数模上都是 1 ⇒ m^λ − 1 同时被 p 和 q 整除 ⇒ 被 n = p·q 整除 ⇒ mod n 也是 1。
     *   ② m 与 n 不互素（m 是 p 或 q 的倍数；这是 φ 版论证覆盖不到、而 λ 版仍然成立的缺口）
     *      不妨设 p | m 且 q ∤ m（m 是 n 的倍数则两边都是 0，更简单）：
     *          mod p：m ≡ 0 ⇒ m^(e·d) ≡ 0 ≡ m (mod p)。     ← 只要指数 ≥ 1 就成立，e·d 当然 ≥ 1
     *          mod q：gcd(m, q) = 1 ⇒ 由 ① 的 mod q 论证 m^λ ≡ 1 (mod q)
     *                 ⇒ m^(1 + t·λ) ≡ m·1^t ≡ m (mod q)。
     *      两边都同余 ⇒ 差值同时被 p、q 整除 ⇒ 被 n 整除 ⇒ m^(e·d) ≡ m (mod n)。
     *   结论：对一切 m ∈ [0, n)（共 n 个取值，没有任何限制条件）都有 (m^e)^d ≡ m (mod n)，
     *   RSA 解密不需要"明文必须与模数互素"这个前提。签名侧同理：(EMS^d)^e ≡ EMS。
     *
     *   反过来为什么不行（单向性 / 陷门 trapdoor）：从 (n, e, c) 求 m 等价于"开 e 次模根"，
     *   已知最快的办法是先分解 n = p·q（进而算出 λ、再算出 d）；2048-bit 的 n 分解不动，
     *   所以正向易、逆向难。这也是为什么 d、λ、p、q 任一个泄露，其它全塌。
     * </pre>
     */
    private static BigInteger privateOp(BigInteger[] key, BigInteger c)
    {
        return powMod(c, key[D], key[N]);
    }

    /**
     * 私钥运算（CRT 路）：两个半尺寸模幂 + 一次中国剩余定理合并。
     * 这就是"RSA 为什么实际能跑得快"的全部原因 —— 指数从 d 降到 d mod (p-1)，约省 4 倍算力。
     * <pre>
     *   符号表（本条公式新出现的字母；m1、m2、h 就是下面三个局部变量）：
     *     p, q      = KEY[PP], KEY[PQ]        两枚素数；n = p·q
     *     dp, dq    = d mod (p−1), d mod (q−1) 两条"半边"上的短指数，各约 1024 bit
     *     qInv      = q⁻¹ mod p                q 在模 p 意义下的逆元（方向：q 的逆、模 p，不是 p 的逆）
     *     m1 = c^dp mod p     m2 = c^dq mod q   —— 两个半尺寸模幂，各自只有 1024 bit 规模
     *     h  = qInv·(m1 − m2) mod p             —— CRT 的"修正量"，注意先 mod p 保证落在 [0, p)
     *     m  = m2 + h·q                         —— 最终明文整数，落在 [0, n)
     *
     *   第一步：为什么短指数 dp 可以顶替 d（Fermat 小定理，p−1 是 mod p 的指数周期）
     *     d = dp + u·(p−1)（u 是某个整数）⇒ c^d = c^dp · (c^(p−1))^u ≡ c^dp · 1 (mod p)
     *     —— 中间那步是 Fermat 小定理，要求 gcd(c, p) = 1；若 p | c，则两边都 ≡ 0 (mod p)，
     *     同余照样成立。所以 m1 ≡ c^dp ≡ c^d (mod p)，即 m1 就是"答案 mod p"这半个余数。
     *     同理 m2 ≡ c^d (mod q) —— 这就是测试里断言 (c^d mod n) mod p == c^dp mod p 的数学根据。
     *
     *   第二步：为什么 m = m2 + h·q 把两个半余数焊成完整答案（CRT 构造式解）
     *     目标：找一个 m ∈ [0, n) 使 m ≡ m1 (mod p) 且 m ≡ m2 (mod q)。
     *     先取基准 m = m2 + h·q：它对 mod q 自动满足（h·q ≡ 0 (mod q)），只剩 mod p 一个自由度 h。
     *     mod p：m ≡ m2 + q·h，要求它等于 m1，即 q·h ≡ m1 − m2 (mod p)。
     *     两边乘 q⁻¹（qInv 的存在要求 gcd(q, p) = 1 —— 两个不同素数当然互素）得
     *       h ≡ qInv·(m1 − m2) (mod p)。  代回去即 m = m2 + h·q。
     *     验证：m ≡ m2 + q·qInv·(m1−m2) ≡ m2 + 1·(m1−m2) ≡ m1 (mod p) ✓，m ≡ m2 (mod q) ✓。
     *     两个素数模上都与 c^d 同余 ⇒ n = p·q 整除差值 ⇒ m ≡ c^d (mod n)，与直路完全同值；
     *     唯一性由 0 ≤ m 且 m 小于 n 保证（m2 小于 q、h 小于 p ⇒ m 不超过 (q−1) + (p−1)q = p·q − 1），
     *     所以两条路必须逐位相同（测试命题一就是这么断言的）。
     *
     *   第三步："快约 4 倍"的算术从哪来（这里的 B 指位数，别和字节数 k 混）
     *     设 B = bitLength(n)（本例 2047 或 2048）。模幂代价 ≈ 指数位数 × 每步大数乘法的代价，
     *     而 B-bit 大数乘法是 O(B²)：
     *       直路：B 位指数、B 位模数 ⇒ B · B² = B³
     *       CRT ：两条半边，各约 B/2 位指数、B/2 位模数 ⇒ 2 · (B/2) · (B/2)² = B³/4
     *     即约 1/4 的算力：指数减半贡献 1/2，模数减半让每步乘法贡献 1/4，两半各算一遍再乘回 2。
     *     合并那几步（一次减法、一次模乘、一次加法）是 B² 量级，可忽略。
     *     前提是私钥里要带上 p、q（半尺寸模幂就得 mod 它们）：这两枚素数本身是最大的秘密，
     *     知道 p、q 就等于知道 λ、也就能立刻算出 d —— 所以 CRT 私钥格式比"只有 d"更敏感。
     * </pre>
     */
    private static BigInteger privateOpCrt(BigInteger[] key, BigInteger c)
    {
        // m1 = c^dp mod p：p 这半条上的余数（1024-bit 模幂），等价于 (c^d mod n) mod p
        BigInteger m1 = powMod(c, key[DP], key[PP]);
        // m2 = c^dq mod q：q 那半条上的余数
        BigInteger m2 = powMod(c, key[DQ], key[PQ]);
        // h = qInv·(m1 − m2) mod p：把"以 m2 为基准"抬到与 m1 同余所需的修正量；先 mod p 保证 0 ≤ h 小于 p
        BigInteger h = key[QINV].multiply(m1.subtract(m2).mod(key[PP])).mod(key[PP]);
        // m = m2 + h·q：h·q 在 mod q 下为 0（保住 m2），在 mod p 下补出 m1 − m2（抬到 m1）—— CRT 的解
        return m2.add(key[PQ].multiply(h));
    }

    /**
     * 字节层运算：整数 -> 定宽大端字节，长度由模数决定。
     * <pre>
     *   记号：size = ⌈bitLength(n)/8⌉ = k（本例 256 字节）
     *   两次换算就是 RSA 的"序列化协议"，双向都必须按同一套约定，否则互操作失败：
     *     Calc.toBigInt(block)  = 把这 k 字节当"无符号大端整数"读入
     *                             （BigInteger(1, b)：强行视为正数，不等价于有符号的 new BigInteger(b) ——
     *                             最高位是 1 的字节若按有符号读会变成负数，这是一个经典坑）
     *     Calc.toBytes(x, k)    = 把整数写回正好 k 字节大端：高位补 0，长度不足在左边填 0
     *   术语：大端 (big-endian) = 最高有效字节排在数组下标 0 的位置；"定宽"是必须的，
     *         否则 0x00 开头的块会与短块混淆，填充层看到的分隔符位置就全错了。
     * </pre>
     */
    private static byte[] publicOpBytes(BigInteger[] key, byte[] block)
    {
        int size = (key[N].bitLength() + 7) / 8;
        return Calc.toBytes(publicOp(key, Calc.toBigInt(block)), size);
    }

    /** 与 publicOpBytes 同一套大端定宽换算，只是把模幂换成 privateOpCrt（CRT 路），见 privateOpCrt 的符号表。 */
    private static byte[] privateCrtBytes(BigInteger[] key, byte[] block)
    {
        int size = (key[N].bitLength() + 7) / 8;
        return Calc.toBytes(privateOpCrt(key, Calc.toBigInt(block)), size);
    }

    // ---------------------------------------------------------------- 填充：全是带真实参数的静态方法

    /**
     * NoPadding 的本质就是"定宽大端编码"：没有随机性，也就没有语义安全。
     * <pre>
     *   EM = I2OSP(M, k)   —— I2OSP/OS2IP 是 RFC 8017 给"整数 ↔ 定宽大端字节"这两个换算起的名字：
     *                         I2OSP(M, k) 把整数 M 写成 k 字节，OS2IP 反过来把 k 字节读成整数。
     *   约束：M 必须小于 n（否则模幂输入越界）；M 开头若为 0x00 会被"补回来"，所以长度信息全丢。
     *   后果（测试命题三逐条复现）：确定性 ⇒ 泄露"两条密文相等"；可延展 ⇒ 密文能做代数变形；
     *                         固定点 ⇒ 0、1、n−1 原地不动；小 e ⇒ 直接开方。
     * </pre>
     */
    private static byte[] noPadding(int k, byte[] block)
    {
        return Calc.toBytes(Calc.toBigInt(block), k);
    }

    /**
     * PKCS#1 v1.5 签名块：00 ‖ 01 ‖ FF…FF ‖ 00 ‖ T —— 确定性，所以签名字节可复现。
     * <pre>
     *   记号（EMS = Encoded Message for Signature，签名侧的 EM）：
     *     EMS = 00 ‖ 01 ‖ PS ‖ 00 ‖ T，各段长度之和必须正好 k 字节
     *     00    第一个字节固定为 0：把整数的最高位空出来，保证 EMS 小于 n（k 字节的满值可超过 n）
     *     01    block type（块类型）= 1，表示"这是签名块"；加密块用 2。两种类型不能混用，
     *           同一段字节既能当明文又能当签名会被利用（这是类型字节存在的全部意义）
     *     PS    Padding String = psLen 个 0xFF（签名块要求填充体全 FF，且 FF 不是分隔符 00）
     *     00    分隔符 (separator)，唯一允许出现在 PS 之后的 0x00
     *     T     要签的字节串 = DigestInfo = DER 前缀 ‖ Hash(M)（见 digestInfo）
     *   长度算术：psLen = k − ‖T‖ − 3（减去首字节 00、类型 01、分隔符 00；01 不占额外空间）
     *     约束 psLen ≥ 8 ⇒ ‖T‖ ≤ k − 11 —— 这就是"RSA 一块最多搬 k−11 字节"这条经验的出处，
     *     它不是拍脑袋：分隔符必须能被唯一认出，太短的填充体会让结构产生歧义。
     *   为什么 PS 全填 FF 而不是随机：签名要确定性 —— 同一消息 + 同一密钥必须得到逐字节相同的
     *     签名（本类命题就是这么和 JCE 对照的）。随机化签名是 PSS 的路线（用 salt）。
     * </pre>
     */
    private static byte[] pkcs1Type1(int k, byte[] data)
    {
        int psLen = k - data.length - 3;
        if (psLen < 8)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：填充体至少要 8 字节");
        }
        return Calc.concat(new byte[]{ 0x00, 0x01 }, Calc.repeatedByte(0xff, psLen), new byte[]{ 0x00 }, data);
    }

    /**
     * PKCS#1 v1.5 加密块：00 ‖ 02 ‖ 非零随机 ‖ 00 ‖ M —— 随机体换来语义安全。
     * <pre>
     *   EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M（各段合计正好 k 字节；m = OS2IP(EM)，密文 c = m^e mod n）
     *     00   保证 EM 作为整数小于 n（同 type 1）
     *     02   block type = 2：加密块；解密时只接受 2，不能被当成签名块用
     *     PS   非零随机字节，长度 psLen = k − ‖M‖ − 3，要求 psLen ≥ 8 ⇒ ‖M‖ ≤ k − 11
     *          "非零"是硬要求：0x00 已被占用为分隔符，PS 里若混进 0x00，解码时 indexOf 会停在
     *          第一个 0x00 上，明文被从错误位置切开 —— 结构产生歧义，所以必须重取随机字节。
     *     00   分隔符：PS 与 M 之间唯一的 0x00
     *     M    明文（这里就是消息本身，没有摘要参与，所以 M 可以任意长到 k−11）
     *   随机性带来语义安全 (semantic security)：同一条 M 每次得到不同的 EM，从而不同的密文；
     *   但它不带来完整性 —— 密文被改动时解码器要么报"结构错"要么静默给出错误明文，
     *   这两种可区分的回答就是 Bleichenbacher 攻击的 oracle（详见 pkcs1Unpad 的注释）。
     * </pre>
     */
    private static byte[] pkcs1Type2(int k, byte[] data)
    {
        int psLen = k - data.length - 3;
        if (psLen < 8)
        {
            throw new IllegalArgumentException("PKCS#1 v1.5：明文不能超过 k-11 字节");
        }
        return Calc.concat(new byte[]{ 0x00, 0x02 }, nonZeroBytes(psLen), new byte[]{ 0x00 }, data);
    }

    /**
     * while 循环取随机字节直到里面没有 0x00（0x00 是分隔符，混进填充体会让结构产生歧义）。
     * 术语：rejection sampling（拒绝采样）—— 每次成功的概率是 (255/256)^len，psLen ≈ 226 时约 41%，
     * 所以平均循环两轮多；循环次数依赖随机数，属于"运行时长随秘密变化"的旁路 (side channel) 关注点。
     */
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

    /**
     * 去 PKCS#1 v1.5 填充：结构任何一步不满足都是错误，不允许"尽力解析"。
     * <pre>
     *   输入：em = k 字节的 EM（私钥模幂还原出来的那个大端块），blockType = 1（签名）或 2（加密）
     *   逐条检查，每条对应下面一行 if：
     *     ‖em‖ = k                     块长度本身就是协议的一部分
     *     em[0] = 0x00                 保证整数小于 n 的那个前置零字节
     *     em[1] = blockType            类型必须与用途一致（签名块 01、加密块 02），混用即拒绝
     *     sep = indexOf(em, 2, 0x00)   PS 之后第一个分隔符 0x00 的下标
     *     sep ≥ 10                     因为 PS 从下标 2 起、要求 psLen = sep − 2 ≥ 8，移项就是 sep ≥ 10
     *     type 1 时 em[2..sep) 必须全是 0xFF（type 2 只要求这段非零，编码时已由 nonZeroBytes 保证）
     *     返回值 em[sep+1 .. k)        剥掉结构后的 M（加密）或 T = DigestInfo（签名）
     *   Bleichenbacher 计数攻击 (chosen-ciphertext attack against PKCS#1 v1.5, CRYPTO 1998) 的直觉：
     *     裸 RSA 有乘法同态（见 textbookRsaLeaksEverything）：c′ = c·y^e mod n 解出来正好是 m·y mod n，
     *     于是攻击者能"定向地把未知明文乘上一个自己选的常数 y"，再把 c′ 递给解密器，只问一个问题：
     *       报错"结构不对" ⇒ m·y mod n 不是一个 00 ‖ 02 ‖ 非零 ‖ 00 ‖ … 形状的块
     *       回答"成功"     ⇒ m·y mod n 落在某个狭窄整数区间里。把"首两字节是 00 02"翻译成整数语言：
     *                        m·y mod n ∈ [2B, 3B)，其中 B = 256^(k−2) = 2^(8(k−2))，
     *                        也就是"去掉首两字节之后剩下 k−2 字节"的那个尺度。
     *                        这个区间只占整个 [0, n) 的约 1/65536，所以"合法/不合法"是一次很贵的提问
     *     每次回答都是对未知 m 的一次"计数提问"：m 所在的候选区间集合被按比例不断收窄，
     *     几万到几十万次解密提问之后区间就只剩一个值 —— 全程不需要分解 n，只需要一个
     *     会区分失败原因的解密 oracle (decryption oracle)。
     *     防御结论：所有失败必须对外表现为同一个不可区分的错误（同一句提示、同一条路径、同样耗时），
     *     这正是现代协议改用 OAEP、或外层再套 encrypt-then-MAC 的根本原因。
     * </pre>
     */
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

    /**
     * 从 from 起找第一个等于 v 的下标，找不到返回 -1 —— 一个最朴素的 for 循环。
     * 它就是"分隔符 (separator) 在哪里"的求法。注意取的是第一个匹配位置，所以协议要求
     * 它之前的字节一律不能等于分隔符（v1.5 的 PS 必须非零、OAEP 要求 0x01 之前全是 0x00），
     * 否则同一块字节会有两种合法切法，明文长度就有歧义。
     */
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

    /**
     * [from, to) 是否全是 0（区间左闭右开：下标 from 起、到 to−1 止）。
     * OAEP 解码用它检查"0x01 分隔符之前的 PS 段确实全零"，PSS 校验用它检查同样的事 ——
     * 这一段检查是 OAEP/PSS 完整性的来源：掩码下任何一位被改，这里几乎必然露出一堆非零字节。
     */
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

    /**
     * [from, to) 是否全非 0（左闭右开）。
     * v1.5 type 2 的 PS 必须满足它：0x00 已经被"占用"为分隔符，填充体里出现 0x00 会让
     * indexOf 停在错误位置，明文被从错误的地方切开（见 pkcs1Type2 与 nonZeroBytes）。
     */
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
     * <pre>
     *   符号表（本条公式的每个字母）：
     *     mgf1(hashName, seed, length) = MGF1(seed, length) —— 从任意长的 seed 造出任意长的伪随机流
     *     seed        输入种子：OAEP 里是 hLen 字节随机数，PSS 里是 hLen 字节的 H；长度不受限制
     *     length (l)  要产出的字节数，例如 OAEP 需要 l = emLen − hLen − 1，PSS 需要 l = emLen − hLen − 1
     *     hLen        所选摘要的输出长度（SHA-1 20 / SHA-256、SM3 32）—— 一块掩码正好 hLen 字节
     *     counter     32 位大端整数 0, 1, 2, …，即"第几块"；每块 = H(seed ‖ I2OSP(counter, 4))
     *     blocks      ⌈length/hLen⌉ = ceilDiv(length, hLen)，拼够 l 字节就停，最后一块截断使用
     *   计数器结构 (counter mode) 的含义：不依赖上一次输出，所以可以任意位置取任意长度；
     *     I2OSP(counter, 4) 就是"把 counter 写成 4 字节大端"（Calc.toBytes 的那个约定），
     *     4 字节上限 = 2^32 块 ⇒ 最长能造 2^32·hLen 字节，比任何模数都大得多，够用。
     *   为什么这东西"够用"：H 是抗碰撞哈希，输出看起来没有规律 ⇒ 从一个短的随机 seed 展开出
     *     一整块伪随机字节；把它 XOR 到数据上，数据就把自己的全部结构藏了起来（掩码可逆是因为
     *     异或自己抵消：(X ⊕ M) ⊕ M = X）。安全性证明里 MGF1 被建模成随机预言 (random oracle)。
     *   术语：扩散 (avalanche) —— 输入差 1 bit，输出几乎全变（测试里就是断言这一条）。
     * </pre>
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
     * <pre>
     *   符号表 —— 本方法里出现的每个字母（OAEP = Optimal Asymmetric Encryption Padding，"最优异步加密
     *   填充"，作用在明文编码层，完整方案名 EME-OAEP；"optimal" 指它在随机预言模型 (random oracle
     *   model) 下可证明达到 IND-CCA2 —— "选择密文攻击下的语义安全"这一最强安全档位，同时明文开销最小）：
     *     EME / EMSA  编码层的两个统称（英文全称）：EME = Encryption-Message Encoding（加密侧的"消息
     *                 编码"，本方法就是 EME-OAEP，v1.5 加密是 EME-PKCS1-v1_5）；
     *                 EMSA = Encoding Method for Signatures with Appendix（签名侧的编码方法，
     *                 v1.5 签名 = EMSA-PKCS1-v1_5、PSS = EMSA-PSS）；
     *                 MGF = Mask Generation Function（掩码生成函数，即下面的 mgf1）
     *     hashName     绑定 label 用的哈希（记作 Hash）；mgfHashName 是 MGF1 内部的哈希，两者可以不同
     *     hLen         = ‖Hash(·)‖，也是 seed 与 lHash 的字节数
     *     emLen        EM 的字节数；加密填充用 k（本例 256），前面那个 0x00 就占 1 字节
     *     label        可选的"上下文标签"（不传就是空串 EMPTY）；只以 lHash 的形式进入
     *     lHash        = Hash(label)，放在 DB 最前面 hLen 字节
     *     PS           全零填充体，psLen = emLen − ‖M‖ − 2·hLen − 2 字节（可以正好为 0）
     *                    ⇒ 明文上限 ‖M‖ ≤ k − 2·hLen − 2（SHA-256 时 256 − 66 = 190 字节，对比 v1.5 的 245）
     *     0x01         DB 里 PS 与 M 之间的分隔字节（注意不是 0x00：0x00 已被 PS 占满）
     *     DB           Data Block = lHash ‖ PS ‖ 0x01 ‖ M，长度 = emLen − hLen − 1
     *     seed         hLen 字节随机数 —— 整个 OAEP 唯一的随机来源，也是语义安全的来源
     *     dbMask       = MGF1(seed, emLen − hLen − 1)，与 DB 等长
     *     maskedDb     = DB ⊕ dbMask（⊕ 是逐字节异或，自逆：再 ⊕ 一次 dbMask 就回到 DB）
     *     seedMask     = MGF1(maskedDb, hLen)
     *     maskedSeed   = seed ⊕ seedMask
     *     EM           = 00 ‖ maskedSeed ‖ maskedDb，正好 emLen 字节；密文 c = OS2IP(EM)^e mod n
     *   为什么两个掩码要互相撑着（这就是"不可延展 non-malleable"的来源）：
     *     解码时 seed 要从 maskedSeed ⊕ MGF1(maskedDb) 反推，dbMask 又要从反推出的 seed 展开。
     *     改动 maskedDb 里任意一个字节 ⇒ seedMask 全变 ⇒ seed 全变 ⇒ dbMask 全变 ⇒ 整个 DB 变成
     *     一整块随机字节 ⇒ 头 hLen 字节的 lHash 对不上、0x01 也几乎不可能出现在"前面全零"的位置。
     *     也就是说：攻击者无法通过改密文得到"与原明文有已知关系的新明文"，只能得到一个完全无关
     *     的拒绝 —— 一个字节变了整包作废。v1.5 的解析器会给出"结构错 / 明文错"两种可区分回答，
     *     OAEP 的解码只给出"这一整块不是有效编码"，Bleichenbacher 那类计数提问因此没有 oracle。
     *   label 的用途：同一条密文换一个 label 就解不开（见本类的 label-A/label-B 断言），
     *     于是可以把密文绑定到某个用途、某个会话或某个接收者 —— 这是 OAEP 相对 v1.5 唯一"额外"的能力。
     * </pre>
     */
    private static byte[] oaepEncode(String hashName, String mgfHashName, int emLen, byte[] label, byte[] message)
    {
        int hLen = digestSize(hashName);
        int psLen = emLen - message.length - 2 * hLen - 2;
        if (psLen < 0)
        {
            throw new IllegalArgumentException("OAEP：明文超过 k-2hLen-2");
        }
        // DB = lHash ‖ PS ‖ 0x01 ‖ M：三段拼起来，长度正好 emLen − hLen − 1
        byte[] db = Calc.concat(digestOf(hashName, label), new byte[psLen], new byte[]{ 0x01 }, message);
        // seed：唯一的随机来源，hLen 字节
        byte[] seed = randomBytes(hLen);
        // maskedDb = DB ⊕ MGF1(seed, …)：用短的 seed 展开成长掩码，把 DB（含明文）整块盖住
        byte[] maskedDb = Calc.xor(db, mgf1(mgfHashName, seed, emLen - hLen - 1));
        // maskedSeed = seed ⊕ MGF1(maskedDb, hLen)：反过来用密文自己盖 seed，两者互为掩码、彼此锁死
        byte[] maskedSeed = Calc.xor(seed, mgf1(mgfHashName, maskedDb, hLen));
        // EM = 00 ‖ maskedSeed ‖ maskedDb：前置 00 保证 EM 作为整数小于 n
        return Calc.concat(new byte[]{ 0x00 }, maskedSeed, maskedDb);
    }

    /**
     * OAEP 解码：结构检查（首字节 00、lHash 相等、0x01 之前全零）就是它的完整性来源。
     * <pre>
     *   公式（与编码严格互逆；下面每行注释都对应代码里的一步）：
     *     maskedDb   = em[1+hLen .. emLen)                 从 EM 里切出掩码后的数据块
     *     seed       = em[1 .. 1+hLen) ⊕ MGF1(maskedDb, hLen)   先还原 seed（它被 maskedDb 掩着）
     *     DB         = maskedDb ⊕ MGF1(seed, ‖maskedDb‖)       再用还原出的 seed 还原 DB
     *   为什么 xor 两次就回到原文：异或自逆且满足结合律 ——
     *     DB = maskedDb ⊕ MGF1(seed) = (DB ⊕ MGF1(seed)) ⊕ MGF1(seed) = DB ⊕ 0 = DB
     *   三条结构检查（任何一条不过就直接拒绝，不"尽力解析"）：
     *     ‖em‖ = emLen 且 em[0] = 0x00         块长度与前置零字节
     *     DB[0 .. hLen) = Hash(label)          即 lHash 校验：label 必须一模一样
     *     存在 sep 使 DB[sep] = 0x01 且 DB[hLen .. sep) 全 0x00   PS 段必须真的是全零填充
     *   返回 DB[sep+1 ..) = M。注意这三步检查合起来等价于"证明我知道一个合法编码"，
     *   所以解码失败的回答必须是同一种、且耗时一致，否则又变成 Bleichenbacher 式的 oracle。
     *   另外：填充与模幂正交 —— 本方法只吃 EM 字节，不关心它是怎么从密文算回来的。
     * </pre>
     */
    private static byte[] oaepDecode(String hashName, String mgfHashName, int emLen, byte[] label, byte[] em)
    {
        int hLen = digestSize(hashName);
        if (em.length != emLen || em[0] != 0)
        {
            throw new IllegalArgumentException("OAEP：EM 必须以 0x00 开头");
        }
        // maskedDb：EM 去掉前置 00 与 hLen 字节的 maskedSeed，剩下的就是它
        byte[] maskedDb = Arrays.copyOfRange(em, 1 + hLen, emLen);
        // seed = maskedSeed ⊕ MGF1(maskedDb, hLen)：先用密文自身展开掩码，把随机种子还原出来
        byte[] seed = Calc.xor(Arrays.copyOfRange(em, 1, 1 + hLen), mgf1(mgfHashName, maskedDb, hLen));
        // DB = maskedDb ⊕ MGF1(seed, ‖maskedDb‖)：再用还原出的 seed 展开长掩码，把数据块揭开
        byte[] db = Calc.xor(maskedDb, mgf1(mgfHashName, seed, maskedDb.length));
        if (!Arrays.equals(Arrays.copyOf(db, hLen), digestOf(hashName, label)))
        {
            throw new IllegalArgumentException("OAEP：label 不匹配（lHash 校验失败）");
        }
        // sep：从 lHash 之后找 0x01 分隔符；要求它之前（lHash 除外）全是 0x00 的 PS
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
     * <pre>
     *   记号与推导（这就是 mgf/编码里那一句"maskedDB 首字节与掩码按位相与"的全部数学）：
     *     emLen   EM 的字节数 ⇒ 它能表达的整数范围是 [0, 2^(8·emLen))
     *     emBits  协议允许的位数 = modBits − 1 = bitLength(n) − 1
     *     掩码宽度 w = 8·emLen − emBits  多出来的最高位个数（本例 n 的 modBits = 2047 ⇒ w = 2）
     *     掩码   = 0xff 右移 w 位         即二进制 0011 1111 = 0x3f：保留低 8−w = emBits mod 8 位
     *   为什么必须清高位：编码得到的 EM 要当作整数喂给模幂，而模幂的输入必须在 [0, n) 内。
     *     允许位数取 bitLength(n) − 1 而不是 bitLength(n)，是为了无论 n 的最高几位是什么都能
     *     保证 EM 小于 n（少一位 ⇒ EM 最大也只有 n/2 量级，必然落在范围内）。
     *   为什么不能写死 0x7f：0x7f 只在 "w = 1"（即 bitLength(n) = 8·emLen − 7）时才对；
     *     本例 w = 2，若按 0x7f 清位就多留了一个高位，EM 有可能 >= n，BC 会直接拒绝我们的签名。
     * </pre>
     */
    private static int topBitMask(int emLen, int emBits)
    {
        return 0xff >>> (emLen * 8 - emBits);
    }

    /**
     * PSS 编码：{@code EM = maskedDB ‖ H ‖ BC}，其中 {@code H = Hash(0⁸ ‖ Hash(M) ‖ salt)}。
     * salt 作为真实参数传进来 —— 给定同一个 salt 就得到同一个 EM，这正是"随机预言"的用法。
     * DB 的分隔字节与 OAEP 一样是 0x01（很多资料写成 0x20，那是错的）。
     * <pre>
     *   符号表（PSS = Probabilistic Signature Scheme，概率性签名方案；RFC 8017 里的完整名字
     *   RSASSA-PSS 中 SSA = RSA Signature Scheme with Appendix，"带附录的 RSA 签名方案"）：
     *     M          待签消息；mHash = Hash(M)，hLen 字节
     *     salt       sLen 字节的随机数（本文件的盐；sLen = 0 就退化成"确定性"的 PSS）。
     *                "salt"直译"盐"：往哈希里掺一点一次性随机，使同一输入的产出每次不同。
     *     M'         = 00⁸ ‖ mHash ‖ salt —— 8 个前置零字节的"域分隔"写法：它保证
     *                "H(0⁸‖mHash‖salt)" 不可能与任何别的拼接结构（例如把 salt 放到前面的伪造）撞车
     *     H          = Hash(M')，hLen 字节，放在 EM 尾部、trailer 之前（它不被掩码，明文出现）
     *     DB         = PS ‖ 0x01 ‖ salt，Data Block；PS 是 emLen − sLen − hLen − 2 个 0x00
     *                  DB 总长 = emLen − hLen − 1（减掉 H 的 hLen 字节和尾部 trailer 1 字节）
     *     maskedDB   = DB ⊕ MGF1(H, emLen − hLen − 1)，再把首字节与首位掩码相与（topBitMask）
     *     EM         = maskedDB ‖ H ‖ 0xBC
     *     0xBC       trailing single byte（结尾固定字节）：RFC 8017 选定的"这是 PSS 块"的魔数，
     *                  验签第一步就检查它；1 字节的存在让 DB 与 H 的切分不会有歧义
     *     emLen/emBits 与掩码见 EM_BITS 与 topBitMask 的注释（PSS 是唯一用 emLen 而不用 k 的方案）
     *   流程一句话：把 salt 掺进 H，再用 H 反过来掩住"装着 salt 的 DB"——
     *     salt 在明面（H 里含它）又在掩码里（DB 尾部含它），两者互相钉死，改一位就对不上。
     *   为什么 salt 让签名随机化：H = Hash(0⁸‖mHash‖salt) 依赖 salt，换 salt 就换 H、换 maskedDB、
     *     换整个 EM，于是同一条消息 + 同一把私钥可以得到海量（约 256^sLen 量级）都合法的不同签名
     *     （v1.5 是唯一的；这既是特性也是实现坑：验签方不能靠"字节相等"判断，必须真的验）。
     *     salt 也顺手挡掉"两个不同消息碰巧得到同一摘要"之类的应用层纠缠。
     *   为什么 PSS 可证明安全 (provable security)：伪造签名要先造出一个合法 EM，即要找到
     *     salt 与 maskedDB 使 H = Hash(0⁸‖mHash‖salt) 与 maskedDB 的结构同时自洽；在随机预言模型
     *     下这一步可以被归约 (reduction) 到"给定 n、e，求任意的 e 次模根"，也就是打破 RSA 本身。
     *     v1.5 只有启发式论证，实测也确实被 Bleichenbacher 类攻击打穿；PSS 是现代协议的首选。
     *   为什么这里传 salt 而不是内部生成：同一 salt 必得同一 EM，测试才能和 BC 逐字节对照（KAT）。
     * </pre>
     */
    private static byte[] pssEncode(String hashName, int emLen, int emBits, byte[] salt, byte[] message)
    {
        int hLen = digestSize(hashName);
        int firstByteMask = topBitMask(emLen, emBits);
        // H = Hash(M') = Hash(00⁸ ‖ mHash ‖ salt)：8 个零字节是域分隔，mHash 已经在里面
        byte[] h = digestOf(hashName, Calc.concat(new byte[8], digestOf(hashName, message), salt));
        // DB = PS ‖ 0x01 ‖ salt：PS 的长度由 emLen 倒推，保证 DB 正好 emLen − hLen − 1 字节
        byte[] db = Calc.concat(new byte[emLen - salt.length - hLen - 2], new byte[]{ 0x01 }, salt);
        // maskedDB = DB ⊕ MGF1(H, …)：用 H 当种子展开掩码，把"装着 salt 的 DB"整个盖住
        byte[] maskedDb = Calc.xor(db, mgf1(hashName, h, emLen - hLen - 1));
        // 模数只用掉了 8*emLen 位里的 emBits 位，多出来的最高位必须清零，否则 EM 可能 >= n
        maskedDb[0] &= (byte)firstByteMask;
        // EM = maskedDB ‖ H ‖ 0xBC：H 明文放在尾部，trailer 固定 0xBC 作为"我是 PSS 块"的记号
        return Calc.concat(maskedDb, h, new byte[]{ (byte)0xbc });
    }

    /**
     * PSS 校验：salt 从 DB 里的 0x01 分隔符后面还原，所以验证方不需要知道 salt 长度。
     * 返回布尔 —— 验版本来就是一个返回 true/false 的过程。
     * <pre>
     *   步骤与符号（这就是 RFC 8017 的 EMSA-PSS-VERIFY，输入只有公钥、消息和签名块）：
     *     1) 结构检查：‖em‖ = emLen，em[emLen−1] = 0xBC（trailer），且 em[0] 的高位（掩码外的位）全 0
     *     2) 切分：maskedDb = em[0 .. emLen−hLen−1)，h = em[emLen−hLen−1 .. emLen−1)
     *     3) db = maskedDb ⊕ MGF1(h, ‖maskedDb‖)，并再打一次首位掩码（与编码同一动作，异或自逆）
     *     4) 找 0x01：sep = indexOf(db, 0, 0x01)，要求它存在且 db[0 .. sep) 全是 0x00
     *        ⇒ salt = db[sep+1 .. ‖db‖)：盐的长度由分隔符的位置自然确定，验证方无需事先知道 sLen
     *     5) 最后一条等式：h 是否等于 Hash(00⁸ ‖ Hash(M) ‖ salt) —— 这是真正的密码学检查
     *   为什么第 5 步就是"验签"：签名值 s 已经用公钥指数 e 还原成 EM（见 pkcs1Sign / publicOp），
     *     能推出这个自洽的 EM 的人必须知道私钥 d；伪造者要么找不到满足 h = Hash(…) 的 salt
     *     （等于打破哈希），要么必须能求 e 次模根（等于打破 RSA）。
     *   为什么用 allZero + 分隔符 + trailer + 高位掩码这四道结构关卡：任缺其一都会给伪造者
     *     留下"随便拼一块字节也能过"的空间；四道关卡加上最后那条哈希等式一起，随机拼出的字节串
     *     全部通过的概率小到可以忽略（trailer 要正好 0xBC、掩码外的高位要全 0、0x01 之前要全 0，
     *     最后还要 h 真等于 Hash(0⁸‖mHash‖salt) —— 单这最后一条就是 hLen 字节的巧合）。
     *   为什么改一位必须返回 false：测试里 tampered[40] ^= 1 —— 那一位在 maskedDB 里，
     *     解开后 db 全乱，第 4 步的"全零 + 0x01"或第 5 步的哈希比对必然失败。
     * </pre>
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
        // maskedDb 与 h 的切分点：从尾巴往前数，1 字节 trailer、hLen 字节 H，其余全是 maskedDB
        byte[] maskedDb = Arrays.copyOfRange(em, 0, emLen - hLen - 1);
        byte[] h = Arrays.copyOfRange(em, emLen - hLen - 1, emLen - 1);
        // db = maskedDb ⊕ MGF1(h, …)：用明文出现的那个 H 当种子，把 DB 揭开（异或自逆）
        byte[] db = Calc.xor(maskedDb, mgf1(hashName, h, maskedDb.length));
        db[0] &= (byte)firstByteMask;
        // 0x01 之前必须全零：分隔符位置一起决定了 salt 的长度（sLen 不需要外部提供）
        int sep = indexOf(db, 0, (byte)0x01);
        if (sep < 0 || !allZero(db, 0, sep))
        {
            return false;
        }
        byte[] salt = Arrays.copyOfRange(db, sep + 1, db.length);
        // 唯一的密码学等式：H 是否真的等于 Hash(00⁸ ‖ Hash(M) ‖ salt)
        return Arrays.equals(h, digestOf(hashName, Calc.concat(new byte[8], digestOf(hashName, message), salt)));
    }

    /**
     * DigestInfo：ASN.1 写死的一段头 + 摘要 = "要签的东西"。
     * PKCS#1 v1.5 签名的全部协议就是这两行字节，没有更多了。
     * <pre>
     *   T = DigestInfo = SEQUENCE{ SEQUENCE{ digestAlgorithm OID, parameters }, OCTET STRING(digest) }
     *     记号：derPrefix = 上面那个 SEQUENCE 的固定字节（不含摘要），hashBytes = Hash(M)，hLen 字节
     *     T 就是 pkcs1Type1 里的 T；EMS = 00 ‖ 01 ‖ FF…FF ‖ 00 ‖ T
     *   为什么要把"用的是哪个哈希"也一起签名（而不只签摘要）：如果只签 Hash(M)，攻击者可以声称
     *     "这其实是另一个哈希的摘要"，从而把签名挪用到别的算法上（历史上的哈希替换攻击）。
     *     DER 前缀把算法身份钉死，验签时连算法一起核对。
     *   ASN.1 DER 里用到的四个标签字节 (tag)：30 = SEQUENCE，06 = OBJECT IDENTIFIER，
     *     05 = NULL，04 = OCTET STRING；
     *     紧跟在标签后的那个字节是"内容长度"（本例都是几十字节以内，所以长度不需用长形式编码）。
     * </pre>
     */
    private static byte[] digestInfo(byte[] derPrefix, byte[] hashBytes)
    {
        return Calc.concat(derPrefix, hashBytes);
    }

    /**
     * SHA-1 / SHA-256 的 DigestInfo DER 前缀（RFC 8017 §9.2 Note 1 的固定表）。
     * <pre>
     *   逐字节拆解（这就是"硬编码的两串十六进制"到底写了什么）：
     *   SHA-1   30 21  30 09  06 05  2b 0e 03 02 1a  05 00  04 14
     *     30 21   SEQUENCE，内容长 0x21 = 33 字节（= 11 + 2 + 20）
     *     30 09     内层 SEQUENCE（AlgorithmIdentifier：算法身份），内容长 9
     *     06 05       OBJECT IDENTIFIER，内容长 5；2b 0e 03 02 1a 解出 1.3.14.3.2.26 = SHA-1
     *                 （第一字节 0x2b = 43 = 40·1 + 3 ⇒ 前两段是 1.3；后面每字节是一段十进制数）
     *     05 00       NULL 参数（SHA-1 的参数就写成空）
     *     04 14     OCTET STRING，内容长 0x14 = 20 —— 后面接的正是 20 字节的 SHA-1 摘要
     *   SHA-256 30 31  30 0d  06 09  60 86 48 01 65 03 04 02 01  05 00  04 20
     *     30 31   SEQUENCE，内容长 0x31 = 49（= 15 + 2 + 32）
     *     30 0d     AlgorithmIdentifier SEQUENCE，内容长 0x0d = 13
     *     06 09       OID，内容长 9；60 86 48 01 65 03 04 02 01 解出 2.16.840.1.101.3.4.2.1 = SHA-256
     *                 （0x60 = 96 ⇒ 前两段 2.16；0x86 0x48 是两个字节拼一段：6·128 + 72 = 840，
     *                   即著名的"美国国家标准与技术研究院 NIST"那一枝；后续 01 65 03 04 02 01 各一段，
     *                   最后两段 2.1 在 NIST 的算法树里就是 SHA-256）
     *     05 00       NULL 参数
     *     04 20     OCTET STRING，内容长 0x20 = 32 —— 后面接的正是 32 字节的 SHA-256 摘要
     *   这两串前缀就是 KAT 的"标准答案"：本类用它们手拼 DigestInfo，再和 JCE 的
     *   SHA1withRSA / SHA256withRSA 逐字节比对 —— 前缀写错一个字节都对不上（命题就是这么设计的）。
     * </pre>
     */
    private static final byte[] DER_SHA1 = Calc.unhex("3021300906052b0e03021a05000414");
    private static final byte[] DER_SHA256 = Calc.unhex("3031300d060960864801650304020105000420");

    /**
     * 签名过程：拼 DigestInfo -> type 1 填充 -> 私钥模幂（CRT 路），三个真实参数一次给全。
     * <pre>
     *   公式：sig = EMS^d mod n，其中 EMS = I2OSP(00 ‖ 01 ‖ FF…FF ‖ 00 ‖ DigestInfo, k)
     *     记号：K = k（模数字节数）；derPrefix = 上表里的 DER 前缀；digestOf(digestName, M) = mHash
     *     sig 就是"签名"（signature，k 字节大端整数）；它是"对整个 EMS 求 d 次幂"，不是"对 M"
     *   验签为什么用 e（"e 当验证指数"）：签名用 d、验证用 e，因为 e·d ≡ 1 (mod λ) ⇒
     *     sig^e ≡ (EMS^d)^e ≡ EMS^(e·d) = EMS^(1 + t·λ) ≡ EMS (mod n)（完整推导见 privateOp）。
     *     只有持有 d 的人能造出这个能还原成合法 EMS 的整数；而验证只需要公开的 (n, e) —— 这正是
     *     "认证性 (authenticity) 只靠公钥就能核"的含义，也是 RSA 签名与 RSA 加密共用一套数学的原因。
     *   验签的三步：publicOpBytes 用 e 还原 EMS → pkcs1Unpad(1, …) 剥掉 type 1 结构 →
     *     把剩下的字节与"自己重算的 DigestInfo(derPrefix ‖ Hash(M))"逐字节比对。
     *     注意"确定性"：没有 salt，所以同一消息同一密钥的签名字节永远相同（对比 PSS）。
     * </pre>
     */
    private static byte[] pkcs1Sign(String digestName, byte[] derPrefix, byte[] message)
    {
        byte[] em = pkcs1Type1(K, digestInfo(derPrefix, digestOf(digestName, message)));
        return privateCrtBytes(KEY, em);
    }

    // ---------------------------------------------------------------- 分段 RSA

    // 三个编号各自对应的"单块操作"（segmented 的 switch 就按它们分发，op = operation 的缩写）：
    //   SEG_PKCS1_ENCRYPT  v1.5 type 2 填充 + 公钥模幂      EM = pkcs1Type2(K, seg) → publicOpBytes
    //   SEG_PKCS1_DECRYPT  私钥 CRT 模幂 + 去 v1.5 填充    seg(=k 字节密文块) → privateCrtBytes → pkcs1Unpad(2, …)
    //   SEG_OAEP_ENCRYPT   OAEP/SHA-256 填充 + 公钥模幂     EM = oaepEncode(SHA256, SHA256, K, EMPTY, seg)
    /** 分段处理的三种"单块操作"编号。 */
    private static final int SEG_PKCS1_ENCRYPT = 0;
    private static final int SEG_PKCS1_DECRYPT = 1;
    private static final int SEG_OAEP_ENCRYPT = 2;

    /**
     * RSA 一块最多搬 k-11 字节，"长消息"就是一个 for 循环：按 segmentSize 切块、
     * 逐块做单块操作、把结果依次拼接。加密和解密共用同一个循环，只是 switch 里换一段单块代码。
     * <pre>
     *   记号：k = 256（模数字节数）；segmentSize = 每段明文长度，v1.5 加密上限 k − 11 = 245，
     *   OAEP/SHA-256 上限 k − 2·hLen − 2 = 256 − 66 = 190（见 oaepEncode 的长度算术）；
     *   Calc.chunks(data, size) 把 data 切成若干段，最后一段可以短于 size；
     *   段数 = ⌈‖data‖ / segmentSize⌉ = Calc.ceilDiv(‖data‖, segmentSize)，
     *   密文总长 = 段数 × k（每段独立编码成 k 字节的 EM，再各求一次模幂，拼接起来）。
     *   为什么密文比明文长这么多、还必须是 k 的倍数：RSA 是"块密码"，永远一次只处理一个模数块，
     *   它自己不会流式；所谓流式全是外面套分块循环。
     *   真实协议不这么用：这样逐段加密的密文没有"顺序/整体"绑定（段可被重排、删除而各自仍合法），
     *   标准做法是混合加密 / 信封加密 (hybrid encryption) —— 用 RSA-OAEP 只传一把对称密钥，
     *   长消息交给 AES-GCM 之类的对称算法；分段循环在这里只用来证明"上限就是那两条减法公式"。
     * </pre>
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

    /**
     * 从纯数字元组重建 JCE 密钥对 —— 证明"密钥是数，不是对象"。
     * <pre>
     *   两个 spec 就是"公钥/私钥分别由哪几个整数构成"的官方答案：
     *     RSAPublicKeySpec(n, e)                         公钥只有两个整数 ⇒ 谁都能算公钥运算
     *     RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qInv)   CRT 版私钥八个整数，顺序与 PKCS#1 的
     *       ASN.1 DER 结构 RSAPrivateKey 一致：SEQUENCE{ version, n, e, d, prime1 p, prime2 q,
     *       exponent1 dp, exponent2 dq, coefficient qInv }
     *       （注意与本数组的下标顺序 N E D LAM DP DQ QINV PP PQ 不同；λ 不在 DER 里，
     *        它能由 p、q 现算 —— 这就是"λ 是陷门信息，但不必随私钥一起发布"的具体体现）
     *   DER 里各字段的含义：prime1/prime2 = 两枚素数；exponent1/exponent2 = dp/dq（RFC 8017 里
     *   也叫 dP/dQ）；coefficient = qInv（也叫 q⁻¹ mod p 的那个"系数"）。
     *   只要能这样把九个数字交回去，就说明 RSAPublicKey / RSAPrivateCrtKey 这些类型层次
     *   只是包装纸：里面装的还是整数，本类的静态方法完全能替代它们。
     * </pre>
     */
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

    /**
     * 命题一：RSA 只有一个运算 —— 模幂。我们自己写的平方-乘必须与 BigInteger.modPow 逐位相同。
     * <pre>
     *   精简符号表（详见类头，本条公式新出现的字母）：
     *     n = KEY[N]（模数），e = KEY[E]（公钥指数），d = KEY[D]（私钥指数），λ = KEY[LAM]
     *     m 明文整数，c = m^e mod n 密文整数，powMod(x, y, n) = x^y mod n（自写平方-乘）
     *   这里断言的四件事，一条一个数学身份：
     *     1) powMod(m, e, n) = m.modPow(e, n)：算术层面"我们没算错"（modPow 是第三方实现，当裁判）
     *     2) privateOp(publicOp(m)) = m：直路解密成立 —— 即 (m^e)^d ≡ m (mod n)，推导见 privateOp
     *     3) privateOpCrt(publicOp(m)) = m：CRT 路与直路同值，推导见 privateOpCrt
     *     4) e·d ≡ 1 (mod λ) 与 gcd(e, λ) = 1：这才叫"一对密钥"；φ 版只是它的更宽松特例
     *   samples 里的五个 m 是有代表性的取样（不是随机凑数）：
     *     1、2、65537 —— 最小值与固定点附近的边界值（1 是平凡固定点，见命题三）
     *     2^700 + 20261014 —— 一个刻意造出来的"中间大小"整数，位数不满 n
     *     随机 K−1 字节读成的整数 —— 接近 n 量级的大明文；取 K−1 字节（而不是 K 字节）是为了
     *     让 m 必然小于 n：m 最大只有 2^(8·255) − 1 = 2^2040 − 1，而 n 至少 2^2046，稳稳落在 [0, n) 内
     * </pre>
     */
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
            // c = m^e mod n；下面两行就是 (m^e)^d ≡ m (mod n) 的两种算法路径（直路与 CRT 路）
            Assert.assertEquals("直路私钥运算必须还原明文", m, privateOp(KEY, c));
            Assert.assertEquals("CRT 路私钥运算必须还原明文", m, privateOpCrt(KEY, c));
        }

        // e·d ≡ 1 (mod λ)：这才是"密钥对"的定义，φ(n) 只是它的一个（更宽松的）特例
        // 左边 e·d mod λ 必须等于 1；因为 λ = lcm(p−1, q−1) 整除 φ(n) = (p−1)(q−1)，
        // 用 φ 求出的逆同样满足这条同余式，但模数更大、d 也更大，所以标准实现取 λ。
        Assert.assertEquals("d 必须是 e 在 λ 下的逆", ONE, e.multiply(d).mod(KEY[LAM]));
        // 逆元存在 ⟺ gcd(e, λ) = 1（扩展欧几里得的判定条件）；不互素时 d 根本不存在，密钥作废
        Assert.assertEquals("e 必须与 λ 互素，否则逆不存在", ONE, e.gcd(KEY[LAM]));
        log.info("[RSA-本质] 模数 {} bits，λ {} bits，自写平方-乘与 modPow 一致", n.bitLength(), KEY[LAM].bitLength());
    }

    /**
     * 命题二：密钥只是一组整数。p,q -> n,λ,d -> CRT 分量，每一步都能被 JCE 复现。
     * <pre>
     *   精简符号表（这一组断言逐条验证 keyGen 的公式，字母含义见类头）：
     *     p = KEY[PP]  q = KEY[PQ]  n = KEY[N] = p·q  e = KEY[E]  d = KEY[D]  λ = KEY[LAM]
     *     dp = KEY[DP] = d mod (p−1)   dq = KEY[DQ] = d mod (q−1)   qInv = KEY[QINV] = q⁻¹ mod p
     *   断言与公式一一对应：
     *     n = p·q            —— 模数就是两个素数之积（"分解 n 即破密钥"由此而来）
     *     λ = lcm(p−1, q−1)  —— Carmichael 函数；lcm(a,b) = a·b/gcd(a,b)
     *     dp、dq 的定义式     —— 短指数只是 d 在各自周期 (p−1)/(q−1) 下的余数
     *     qInv = q.modInverse(p) —— 方向必须钉死：q 的逆元、模 p（写反了 CRT 就拼不回来）
     *     p ≠ q              —— 两枚素数相同则 n = p²，λ 的结构与 Fermat 论证都不再成立
     *     (c^d mod n) mod p = c^dp mod p —— CRT 的数学根据（Fermat 小定理给出指数周期 p−1，
     *       所以 d 可以换成 dp；推导见 privateOpCrt 的第一步）
     *   最后三段是互操作 KAT（已知答案测试）：JCE 用同一组数字重建 KeyPair 之后，
     *     我们加密的块它能解、它加密的块我们能解；
     *     反过来把 JCE 生成的密钥拆成九个整数（getPrimeP/getPrimeQ/getPublicExponent），
     *     我们的静态方法照样自洽 —— 说明"元组 ⇔ 对象"是双向无损的。
     *   注意拆 JCE 密钥时 d 是从 crt.getPrivateExponent() 来的、而我们这里用 keyGen 现算：
     *     两者可能不同（d 只在 mod λ 意义下唯一，实现可以取 d + t·λ），但模幂结果一定相同；
     *     本例只比对模数与 CRT 自洽性，所以这个差异不影响断言。
     * </pre>
     */
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

    /**
     * 命题三：没有填充的 RSA 一无是处 —— 确定性、可延展、固定点、小指数开根。
     * <pre>
     *   精简符号表：n = KEY[N]，e = KEY[E] = 65537，d = KEY[D]，publicOp(m) = m^e mod n，
     *   privateOp(c) = c^d mod n，m1、m2 两条明文，c 密文，y 是攻击者任选的整数（本测试取 y = 2）。
     *   四条弱点各自对应的公式：
     *   1) 确定性 (deterministic)：m1 = m2 ⇒ m1^e mod n = m2^e mod n。
     *      没有任何随机字节参与，所以密文直接泄露"相等关系"：观察到两条相同密文就知道明文相同，
     *      连"频率统计"这种最古典的手段都还有效 —— 语义安全 (semantic security) 的第一个反例。
     *   2) 乘法同态 (multiplicative homomorphism)：对任意 y，
     *        (m^e mod n)·(y^e mod n) ≡ (m·y)^e (mod n)
     *      证明只用交换律：m^e·y^e = (m·y)^e，两边同取 mod n 仍是同一个余数。
     *      攻击面（这就是"可延展 malleable"）：攻击者不解密就能造出 c′ = c·y^e mod n，
     *      私钥一方老老实实解密得到的却是 m·y mod n —— 他能把未知明文乘上任意已知常数！
     *      取 y = 2 得到"翻倍明文"；取 y = 2⁻¹ mod n（模逆）得到"减半明文"。
     *      更深的一层：把 c′ 递给解密器并根据它返回的明文/错误调整下一个 s，就构成
     *      选择密文攻击 (chosen-ciphertext attack, CCA) 所需的解密 oracle；v1.5 的
     *      Bleichenbacher 计数攻击正是建立在这个同态 + 可区分的错误回答之上。
     *      签名侧同样中招：s1·s2 ≡ (m1·m2)^d ⇒ 两条已有签名可以拼出"两条明文之积"的新签名。
     *      盲签名 (blind signature) 反过来把这个同态当工具用：取随机盲化因子 r（要求 gcd(r,n)=1），
     *      请持有者签"看不见的块" r^e·m mod n；他返回 s′ = (r^e·m)^d ≡ r·m^d (mod n)，
     *      自己再乘 r⁻¹ mod n 就摘掉随机因子，得到 m 的合法签名 s = m^d —— 全靠 2) 这条同态。
     *      本文件不实现盲签名，但它能成立的全部原因就是乘法同态。
     *   3) 固定点 (fixed point)：0^e = 0；1^e = 1；(n−1)^e ≡ (−1)^e ≡ ±1 (mod n) ——
     *      因为 e = 65537 是奇数，(−1)^e = −1，所以 n−1 也是不动点。
     *      这些值一眼就能认出，等于给攻击者一个"密文是否等于这几个特殊明文"的免费判定器。
     *   4) 小指数 + 短明文（e=3 且 m^e 小于 n）：此时 "mod n" 完全没起作用，
     *      c = m^3 就是整数意义的立方，直接开立方（牛顿迭代，见 cubeRoot）即可还原 m，
     *      连 n 都不用知道。这也是为什么教科书推荐 e 不能太小、更必须填充：
     *      填充会把 m 顶到接近 n 的量级（k 字节），使 m^e 远远超过 n，模运算才真正生效。
     * </pre>
     */
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
        // cTwice = c · 2^e mod n ≡ (m1 · 2)^e (mod n)，所以解出来是 2·m1，而攻击者全程没碰私钥
        BigInteger c = publicOp(KEY, m1);
        BigInteger cTwice = c.multiply(powMod(TWO, KEY[E], n)).mod(n);
        Assert.assertEquals("密文乘 2^e 让明文翻倍", m1.multiply(TWO).mod(n),
            privateOp(KEY, cTwice));

        // 3) 固定点：0、1、n-1 永远不变，攻击者一眼看穿
        // 0^e = 0；1^e = 1；(n−1) ≡ −1 (mod n)，e = 65537 为奇数 ⇒ (−1)^e = −1 ≡ n−1
        Assert.assertEquals(ZERO, publicOp(KEY, ZERO));
        Assert.assertEquals(ONE, publicOp(KEY, ONE));
        Assert.assertEquals(n.subtract(ONE), publicOp(KEY, n.subtract(ONE)));

        // 4) e=3 且 m^e < n：模数完全没起作用，开立方就还原了明文（Why e=65537 / 为什么必须填充）
        // 这里现造一把 512-bit×512-bit 的小密钥（n 约 1024 bit），8 字节明文 "cube me" 的 m^3
        // 只有约 192 bit，远小于 n ⇒ 取模是恒等操作，密文里就藏着 m 的整数立方
        BigInteger[] smallE = keyGen(primeCoprimeTo(512, THREE), primeCoprimeTo(512, THREE), THREE);
        BigInteger msg = Calc.toBigInt("cube me".getBytes("UTF-8"));
        BigInteger cipher3 = publicOp(smallE, msg);
        Assert.assertEquals("m^3 没超过 n 时，密文就是 m^3 本身", msg.pow(3), cipher3);
        Assert.assertEquals("牛顿迭代开立方即可还原明文", msg, cubeRoot(cipher3));
        log.info("[RSA-教科书] 确定性 / 可延展 / 固定点 / 小指数开方 四种弱点全部复现");
    }

    /**
     * 立方根的牛顿迭代：{@code x' = (2x + v/x²) / 3}，for 循环迭代 300 次足够收敛到精确整数根。
     * <pre>
     *   记号：v 是被开方的整数（本例就是密文 c = m^3），x 当前的近似根，x' 下一轮近似值。
     *   公式从哪来（牛顿法 Newton's method / Newton–Raphson）：求 f(x) = x³ − v = 0 的根，
     *     迭代式 x' = x − f(x)/f′(x)，而 f′(x) = 3x²（导数：x³ 的斜率），代入得
     *     x' = x − (x³ − v)/(3x²) = (3x³ − x³ + v)/(3x²) = (2x³ + v)/(3x²) = (2x + v/x²)/3
     *     —— 这就是代码里 x.multiply(TWO).add(v.divide(x.multiply(x))).divide(THREE) 那一行。
     *   初值 x = 2^⌈bitLength(v)/3⌉：位数除以 3 就是立方根的量级（1000 ≈ 10³ 那个道理），
     *     shiftLeft 是乘 2 的幂；牛顿法二次收敛（每轮正确位数大约翻倍），300 轮对这个量级绰绰有余。
     *   整数除法 divide 会向下取整，但迭代到不动点时 x 已经正好是精确整数立方根（v = m³ 时成立）。
     *   为什么这个辅助小方法配得上放在命题三里：它证明"m^e 小于 n 时模数是空气" ——
     *     不需要分解、不需要 Coppersmith 那类格约化，一个 for 循环就把明文开了出来。
     * </pre>
     */
    private static BigInteger cubeRoot(BigInteger v)
    {
        BigInteger x = ONE.shiftLeft((v.bitLength() + 2) / 3);
        for (int i = 0; i < 300; i++)
        {
            x = x.multiply(TWO).add(v.divide(x.multiply(x))).divide(THREE);
        }
        return x;
    }

    /**
     * PKCS#1 v1.5 type 2（加密填充）：与 JCE 双向互操作，畸形结构必须拒绝。
     * <pre>
     *   精简符号表（详细见 pkcs1Type2 / pkcs1Unpad）：
     *     K = k = ‖EM‖ = 256 字节；M = pt 明文；PS = 非零随机填充体，psLen = k − ‖M‖ − 3
     *     EM = 00 ‖ 02 ‖ PS ‖ 00 ‖ M；密文 = publicOpBytes(EM) = OS2IP(EM)^e mod n 再写回 k 字节
     *   结构下标的算术（断言里那几个 K − pt.length − 1 是怎么来的）：
     *     M 的起始下标 = 2 + psLen + 1 = 2 + (k − ‖M‖ − 3) + 1 = k − ‖M‖
     *     ⇒ 分隔符 00 的下标 = k − ‖M‖ − 1，PS 覆盖 [2, k − ‖M‖ − 1) —— allNonZero 检查的就是这段
     *   三种畸形结构各自打掉一条协议不变量：em[0] 非 0（整数可能 >= n）、
     *     em[1] 类型错（加密块被当签名块用）、分隔符消失（明文长度无从确定）。
     *   "随机化"断言（两次填充不相等）就是语义安全的直接体现：同一条 M 得到两个不同的 EM，
     *     从而两个不同的密文 —— 对比命题三第一条"确定性"。
     *   这三处畸形正是 Bleichenbacher 攻击者会去试探的地方；本类的解码器对它们统统抛
     *     IllegalArgumentException 而绝不"尽力解析"。生产环境里还得更狠一步：把所有失败对外
     *     表现成同一条回答（连提示文本与耗时都不能分档），否则错误差异本身就变成 oracle ——
     *     完整攻击直觉与这条防御结论见 pkcs1Unpad 的注释。
     * </pre>
     */
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

    /**
     * PKCS#1 v1.5 type 1（签名填充）：确定性 -> 我们的签名字节与 JCE 逐字节相同。
     * <pre>
     *   精简符号表（详见 digestInfo / DER_SHA1 / pkcs1Sign）：
     *     M = msg 消息；mHash = Hash(M)；T = DigestInfo = derPrefix ‖ mHash
     *     EMS = 00 ‖ 01 ‖ FF…FF(psLen = k − ‖T‖ − 3) ‖ 00 ‖ T；签名 sig = OS2IP(EMS)^d mod n
     *   三段断言的数学身份：
     *     1) 逐字节相同：因为整条管线没有任何随机数 —— Hash 是确定的、DER 前缀是写死的、
     *        PS 全 FF、模幂是确定函数，所以"我们的签名 = JCE 的签名"必须成立（KAT）。
     *     2) JCE 用公钥验我们的签名：验证 = sig^e mod n 还原 EMS，再解析 type 1 结构与 DigestInfo。
     *        这里 e 能当"验证指数"的原因是 e·d ≡ 1 (mod λ)（推导见 privateOp）。
     *     3) 反向恢复：pkcs1Unpad(1, K, publicOpBytes(KEY, ref)) 得到的必须正好是
     *        derPrefix ‖ Hash(M) —— 这一步同时验证了硬编码的 DER 前缀（写错一个字节就比不齐）。
     *   最后一行"换一条消息签名立刻失效"是认证性 (authenticity)：EMS 里的 mHash 与
     *     新消息的摘要不同，结构检查就过不去，所以签名与消息被绑死。
     *   值表三行按下标对齐：digestNames（摘要名）、derPrefixes（该摘要的 DigestInfo 前缀）、
     *     jceNames（JCE 的签名算法名 "摘要withRSA"）；换摘要 = 换一行，代码不用动。
     * </pre>
     */
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

    /**
     * MGF1 = 摘要 + 计数器：在多种长度上与 BC 的 MGF1BytesGenerator 完全一致。
     * <pre>
     *   精简符号表（详见 mgf1）：MGF1(seed, l) = 截取前 l 字节的 ( H(seed‖0₄) ‖ H(seed‖1₄) ‖ … )，
     *     一共 ⌈l/hLen⌉ 块；seed 输入种子；hLen 摘要输出长度；counter（写作 0₄、1₄）是 4 字节大端计数器；
     *     l = len 要产出的字节数
     *   lengths = {1, hLen−1, hLen, hLen+1, 300, K} 是刻意挑的边界：
     *     1（只要 1 字节，验证"截断"）、hLen−1 / hLen / hLen+1（一块不够 / 正好一块 / 两块加截断）、
     *     300（跨多块）、K = 256（真实掩码长度 —— OAEP/PSS 实际用的就是这个量级）
     *   裁判 BC 的 MGF1BytesGenerator 是同一个构造的另一种实现，逐字节相同 ⇒ 我们的循环没错。
     *   最后两条断言是哈希的两个基本性质在掩码上的体现：
     *     扩散 (avalanche)：改一个 bit（这里是首个字节 't' → 'T'）⇒ 整条掩码全变；
     *     确定性：MGF1 内部没有随机数，随机性只能来自 seed —— 这保证解码方自己能重算出同一个掩码。
     * </pre>
     */
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

    /**
     * OAEP：同一个静态方法，换摘要、甚至给 MGF1 换一个摘要，都能与裁判互操作。
     * <pre>
     *   精简符号表（详细的四个量都在 oaepEncode / oaepDecode 的注释里）：
     *     hLen = ‖Hash(·)‖（SHA-1 20 / SHA-256、SM3 32）；lHash = Hash(label)，label 传 EMPTY 时为"空串的摘要"
     *     seed（hLen 字节随机）→ maskedSeed = seed ⊕ MGF1(maskedDb, hLen)
     *     DB = lHash ‖ PS ‖ 0x01 ‖ M → maskedDb = DB ⊕ MGF1(seed, emLen − hLen − 1)
     *     EM = 00 ‖ maskedSeed ‖ maskedDb，emLen = k = 256；密文 = m^e mod n，m = OS2IP(EM)
     *   明文上限的算术：‖M‖ ≤ k − 2·hLen − 2（两个 hLen 是给 seed 与 lHash 的，两个 1 是
     *     前置 0x00 与 DB 里的 0x01 分隔符）。SHA-256 时 = 256 − 64 − 2 = 190 字节；
     *     测试最后一段用 K−66 与 K−65 正好卡在这条边界两侧（66 = 2·32 + 2）。
     *   BC 的 OAEPEncoding 是裁判：它内部自带 RSAEngine（模幂）与 OAEP 编解码；
     *     我们只把"填充"这一层交给它对照 —— 双向互操作（它解我们的、我们解它的）证明
     *     两件事：长度算术一致、掩码顺序（谁掩谁）一致。
     *   RSAKeyParameters 的三个参数是 (isPublic 标志, n 模数, 指数)：BC 只用那个布尔做合规策略
     *     (purpose) 检查，真正决定方向的是 init 的第一个参数 forEncryption（true=正向/加密或签名生成，
     *     false=反向/解密或验签）与实际交进去的指数 —— 所以裁判这里传 (n, d) 走解密、(n, e) 走加密；
     *     这正好又说明一次"RSA 原函数只吃 (n, 指数) 这一对整数"。
     *   混合哈希那一段（label 用 SHA-256、MGF1 用 SHA-1）说明 OAEP 的两个哈希参数是独立的，
     *     这也是历史上 Sun JDK 的默认组合；把它焊成一个参数就看不出这层自由度了。
     *   label 绑定：同一份 EM 换个 label 就解不开（lHash 比对失败）—— OAEP 唯一"额外"的能力，
     *     可把密文钉在某个用途/某个会话上。
     * </pre>
     */
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

    /**
     * PSS：salt 决定一切。固定 salt 时我们的 EM 与 BC 的 PSSSigner 逐字节相同。
     * <pre>
     *   精简符号表（详见 pssEncode / pssVerify）：
     *     sLen = ‖salt‖（本例跑 0、32、8 三种）；hLen = 32（SHA-256）
     *     H = Hash(00⁸ ‖ Hash(M) ‖ salt)；DB = PS ‖ 0x01 ‖ salt；maskedDB = DB ⊕ MGF1(H, …)
     *     EM = maskedDB ‖ H ‖ 0xBC（emLen 字节）；签名 sig = OS2IP(EM)^d mod n；验签用 e 还原 EM
     *   salts 表里三行的意义：
     *     new byte[0]（sLen=0）—— "不带盐"，此时 PSS 退化成确定性方案，与固定摘要一一对应；
     *     32 = hLen —— 最常用的推荐取值（盐长等于摘要长度；RFC 8017 允许的上限是 emLen − hLen − 2），
     *     也正是 JCE 那一侧 PSSParameterSpec 里写死的 32；
     *     8 —— 任意非边界值，检查长度算术在 PS 段变长时仍然自洽。
     *   EM_LEN / EM_BITS（= modBits − 1）不是 k：这是 PSS 与 v1.5/OAEP 唯一在"长度基准"上不同
     *     的地方，而且它没有前置 0x00 字节 —— 取而代之的是把 maskedDB 首字节的最高位清掉
     *     （topBitMask），两者都在保证 EM 作为整数小于 n（测试里就断言了这条）。
     *   BC 的 PSSSigner 用同一个 salt 得到同一个 EM ⇒ 掩码、trailer、DB 拼接全部一致；
     *     这一步是"逐字节 KAT"，也是注释里说的"掩码算错时只有它抓得住"。
     *   "换 salt 之后签名完全不同"就是概率性 (probabilistic) 的来源：同一消息有非常多合法签名，
     *     所以任何"签名必须唯一"的假设都不成立，只能真验（对比 type 1 的逐字节可复现）。
     *   JCE 那一侧用随机 salt：我们的 pssVerify 能从 DB 里把 salt 找回来（0x01 之后的全部），
     *     所以验证方无需知道 sLen —— 这是 DB 结构设计的直接好处。
     *   最后两条断言（tampered[40] ^= 1、换消息）说明完整性来自"改一位 → 掩码全乱 →
     *     结构关卡或哈希等式过不去"，pssVerify 返回 false 而不是抛异常：验签就是布尔判定。
     * </pre>
     */
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
     * <pre>
     *   编号 → 方案 → 结构（body = 待填充的字节，K = k = 256，EMPTY = 空 label，SHA256/SHA1/SM3 是摘要名）：
     *     0 NoPadding              I2OSP(body, K)：定宽大端，没有结构、没有随机
     *     1 PKCS#1 v1.5 type 1     00 ‖ 01 ‖ FF…FF ‖ 00 ‖ body（确定性，签名用）
     *     2 PKCS#1 v1.5 type 2     00 ‖ 02 ‖ 非零随机 ‖ 00 ‖ body（随机，加密用；上限 K−11）
     *     3 OAEP/SHA-1             EM = 00 ‖ maskedSeed ‖ maskedDb，hLen = 20，上限 K−42
     *     4 OAEP/SHA-256           同上，hLen = 32，上限 K−66
     *     5 OAEP/SM3               同上，hLen = 32（国密摘要顶替 SHA-256，结构不变）
     *     6 OAEP label=SHA-256 / MGF1=SHA-1   两个哈希参数独立的最直白演示
     *     7 PSS/sLen=0             EM = maskedDB ‖ H ‖ 0xBC，salt 空 ⇒ 确定性
     *     8 PSS/sLen=hLen=32       同上但 salt 随机 ⇒ 同一 body 每次得到不同 EM
     *   3~6 的 label 都传 EMPTY，所以 lHash = Hash(空串) —— 它仍然是固定的 hLen 字节，占长度。
     * </pre>
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

    /**
     * 按编号去填充 / 校验 —— 与 padByScheme 共用同一套编号。body 只有 0（截尾）和 7、8（PSS 校验）用得到。
     * <pre>
     *   输入 em 是"私钥/公钥模幂还原出来的那块 k 字节 EM"（大端整数 → 字节，见 publicOpBytes）。
     *   每个编号的反向动作：
     *     0 直接取尾部 ‖body‖ 字节：NoPadding 没有结构可查，所以"去填充"就是重新切长度 ——
     *       这也意味着它连"被篡改"都检测不出来（测试里就是这条断言）；
     *     1 / 2 pkcs1Unpad(blockType, K, em)：查 00 头、类型字节、分隔符、PS 段，返回其后的字节；
     *     3~6 oaepDecode(哈希名…, K, EMPTY, em)：还原 seed 与 DB，再查 lHash / 0x01 / 全零 PS；
     *     7 / 8 requirePss(em, body)：PSS 的"去填充"其实是校验（pssVerify 返回布尔），
     *       所以它需要原始消息 body 才能重算 H = Hash(0⁸ ‖ Hash(body) ‖ salt)。
     *   注意 3~6 与 7~8 用的摘要必须与 padByScheme 里那一行完全一致：MGF1 是确定性的，
     *     换个摘要就展开出另一条掩码，DB 立刻变成随机字节 → 结构检查必失败。
     * </pre>
     */
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

    /**
     * PSS 的"去填充"就是校验：校验不过抛异常，好让九种方案共用同一套断言。
     * 记号：em = 待校验的 emLen 字节 EM，body = 原始消息（PSS 必须拿它重算 mHash）；
     * 返回值仍是 body —— 因为 PSS 不"携带"明文，它只证明"这块 EM 是这块 body 的合法编码"。
     * 这也是 RSA 签名的本质：签名是对编码的验证，不是可逆的容器。
     */
    private static byte[] requirePss(byte[] em, byte[] body)
    {
        if (!pssVerify(SHA256, EM_LEN, EM_BITS, body, em))
        {
            throw new IllegalArgumentException("PSS 校验失败");
        }
        return body;
    }

    /**
     * 断言"这个 EM 必须被对应方案的校验过程拒绝"。
     * 记号：name = 方案名（只为把话说清楚），scheme = 编号，em = 被篡改过的 EM，body = 原始消息。
     * 期望的路径是 unpadByScheme 抛 IllegalArgumentException：走到 Assert.fail 就说明"篡改没被发现"，
     * 那本身就是弱点 —— 测试里只有 NoPadding（编号 0）会被排除在这个断言之外，单独断言它"静默接受篡改"。
     */
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
     * <pre>
     *   符号表：scheme = 方案编号 0..8（见 padByScheme 的表）；body = 待编码字节；
     *     em = padByScheme(scheme, body)，断言它长度正好 K（本例 PSS 的 emLen 也等于 K = 256），
     *     并且 OS2IP(em) 小于 n —— 后者是"任何填充都必须遵守的前置条件"，否则会撞模幂的边界；
     *     signed = privateCrtBytes(KEY, em) = OS2IP(em)^d mod n（CRT 私钥模幂）；
     *     recoveredEm = publicOpBytes(KEY, signed) = OS2IP(signed)^e mod n → 回到 em。
     *   模幂往返为什么必然还原 em：这就是 (x^d)^e ≡ x (mod n) 那一式（privateOp 的推导），
     *     与用哪种填充毫无关系 —— 填充函数只看见 byte[]，不知道 n、e、d 的任何数字，
     *     模幂也只看一个整数，不认识 0x00/0x01/0xBC 这些结构字节。"正交 (orthogonal)"就是指
     *     这两个 byte[]↔byte[] / int↔int 的过程可以各自独立替换（换摘要、换组合、换裁判）。
     *   三种篡改实验（同一套 unpadByScheme，差别只在结构）：
     *     · 翻最高位（flipped[0] ^= 0x80）：NoPadding 静默接受（它没有结构可查），
     *       其余八种全部拒绝 —— v1.5 查首字节/类型，OAEP 查 0x00 与 lHash，PSS 查首位掩码与 trailer。
     *     · 翻代表消息的最后一字节（v1.5：em[K−1]）：type 1/2 只查结构，明文本身被改它毫无察觉，
     *       于是长度不变、内容悄悄坏了 —— 这就是"v1.5 没有完整性"的诚实结论。
     *     · 翻 OAEP 的 maskedDb（em[K−2]，正好是明文最后那一位）与 PSS 的 100/K−2/K−1：
     *       掩码由数据自身撑起，改一位 ⇒ 整块 DB/maskedDB 全乱 ⇒ 结构或哈希等式过不去 → 拒绝。
     *   这正是"不可延展 (non-malleable)"与"可延展"在实现层面的分界，也是命题三那条同态攻击
     *     在填充层被堵住的直接证据。
     * </pre>
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

    /**
     * 长消息 = 一个 for 循环逐块处理再拼接。RSA 从不"流式"，所谓流式只是外面套了一层分块循环。
     * <pre>
     *   记号与长度算术（详细见 segmented）：
     *     segmentSize = 每段明文长度；v1.5 type 2 的上限是 K − 11 = 245（11 = 00 + 02 + 00 + 8 字节最小 PS）
     *     OAEP/SHA-256 的上限是 K − 2·hLen − 2 = K − 66 = 190（两个 hLen 给 seed 与 lHash）
     *     段数 blocks = ⌈‖longMsg‖ / segmentSize⌉ = Calc.ceilDiv(...)；密文总长 = blocks × K
     *   为什么密文必须正好是 K 的整数倍：每个明文段独立编码成一块 K 字节的 EM，独立做一次模幂，
     *     输出永远是 K 字节（定宽大端，Calc.toBytes 左补零）—— 所以解密侧也照 K 切块就行。
     *   最后一组断言（segmentSize = K−10 时必须抛错）验证的是那条不等式：
     *     psLen = K − ‖seg‖ − 3 = K − (K−10) − 3 = 7 小于 8 ⇒ 违反 "PS 至少 8 字节"，
     *     所以 8 + 3 = 11 就是"k−11"这个魔数的全部来历。
     *   注意：这是为了看清上限而做的教学式分段；真实协议用混合加密（RSA-OAEP 只传对称密钥），
     *     因为逐段 RSA 既慢，段与段之间又没有顺序/整体绑定（可被重排、删段而各自仍"合法"）。
     * </pre>
     */
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
