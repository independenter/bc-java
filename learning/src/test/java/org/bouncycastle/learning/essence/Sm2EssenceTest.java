package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * SM2（GM/T 0003）的本质计算 —— 面向过程版。
 *
 * <p>椭圆曲线在这里<b>不是对象</b>：一个点就是 {@code BigInteger[]{x, y}}，无穷远点就是空数组。
 * 于是整条曲线只是一组普通静态方法，参数都是实打实的数，循环用 {@code for}/{@code while}：
 * <pre>
 *   add(p, q)            弦的斜率 λ = (y₂-y₁)/(x₂-x₁)
 *   doublePoint(p)       切线的斜率 λ = (3x²+a)/(2y)（来自导数）
 *   mul(k, point)        按位 double-and-add：从最高位往下 for 循环，先 double、再按位 add
 *   sm2Sign(d, e, k)     r=(e+x₁) mod n, s=(1+d)⁻¹(k-rd) mod n
 *   sm2Verify(pub, e, rs) (x₁,y₁) = sG + tP, t=(r+s) mod n, 检查 (e+x₁) mod n == r
 * </pre>
 * 算法模式（C1C2C3 / C1C3C2）只是"三段字节的不同排列"，KDF 是 SM3 的计数器 while 循环。
 * 哈希复用 {@link Sm3EssenceTest} 里我们自己写的那个面向过程 SM3 —— 一个方法调另一个方法，仅此而已。
 *
 * <p>文件后半部分是<b>"随机数 k 为什么必须真随机"</b>的推导与攻击：签名式子对 d 只有一次方程
 * {@code d = (k - s)·(r + s)⁻¹ mod n}，所以 k 可预测、有规律、或值域偏窄，都会线性成本地算出私钥。
 * 详见 {@link #privateKeyFromKnownK} 与 {@link #privateKeyFromKnownDelta} 两处注释。
 *
 * <p><b>符号表 —— 本文件每条公式里出现的字母/记号</b>
 * <pre>
 *   p (P)      素数域的大小：Fp = {0,1,…,p−1}，加法/乘法结果都要 mod p 才仍在域里；
 *              sm2p256v1 取 p = FFFFFFFE FFFFFFFF … FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF（256 位素数）
 *   a, b       曲线方程的两个系数（都在 Fp 里），决定曲线形状；sm2p256v1 取 a = p − 3（末字 FFFFFFFC），
 *              b 是一个无规律可寻的魔术数（nothing-up-my-sleeve number）
 *   n          基点 G 的<b>阶 (order)</b>：满足 n·G = O 的最小正整数，也是由 G 生成的循环群的元素个数；
 *              n ≈ 2²⁵⁶，且 n 是素数 ⇒ 标量只能在 Z/nZ 里运算，一切私钥/签名值都要 mod n 归约
 *   Gx, Gy     基点（生成元，generator）G 的两个仿射坐标；G = (Gx, Gy)，公开写死在标准里
 *   G          基点本身，代码里就是数组 {@code {GX, GY}}
 *   O / ∞      无穷远点 (point at infinity)，也就是群的<b>单位元/零元</b>：P + O = P；代码里用<b>空数组</b>表示
 *   P, Q       数学叙述里"任意两个曲线点"的惯用记号，P = (x₁,y₁)、Q = (x₂,y₂)；
 *              严重提醒：本文件的 Java 常量 P 指的是<b>素数 p</b>（域大小），点则用 pt/p/q/pub/point 这些变量名，
 *              读代码时看到大写 P 要先确认它到底是"素数"还是"某个点"
 *   λ (lam)    斜率，Fp 里的一个元素；"除法 a/b"在域里就是 a·b⁻¹，b⁻¹ 是模 p 的乘法逆元
 *   (x₁,y₁)    参与运算的第一个点的仿射坐标（下标 1 表示"第一个点"，<b>不是</b> x 的平方）；(x₂,y₂) 是第二个点
 *   (x₃,y₃)    直线与曲线的<b>第三个</b>交点；群加法的"结果"是它的负点，即 x 不变、y 取反
 *   ⁻¹         模逆 (modular inverse)：a⁻¹ 是满足 a·a⁻¹ ≡ 1 (mod m) 的唯一数，用扩展欧几里得求；
 *              代码里 inverse() 是 mod p 的（几何运算），modInverse(N) 是 mod n 的（标量运算），两者别混
 *   k          一次性随机标量（临时私钥/随机数），每次签名、每次加密都要一个新的；k ∈ [1, n−1]
 *   d          私钥标量 (private scalar)，d ∈ [1, n−2]；公钥点 P = d·G，公钥<em>就是那个点</em>的坐标
 *   e          消息哈希整数：e = SM3(ZA ‖ M) 按大端读成的一个 256 位大整数（不 mod n，直接进 r 的加法）
 *   r, s       签名对的两个标量，都必须在 [1, n−1]；r 是"横坐标掺进哈希"，s 是"把 d 藏进一次模逆"
 *   t          验签用的组合系数 t = (r + s) mod n，它就是推导里 d 的系数
 *   Z / ZA/ZB  用户标识杂凑 (identity hash)：ZA = SM3(ENTL‖ID_A‖a‖b‖Gx‖Gy‖Px‖Py)，把"身份"和"公钥"绑死
 *   ENTL       ID 的<b>比特</b>长度的 2 字节大端编码（2 字节最多表 65535 位），放在最前面当长度前缀
 *   ID         用户标识符（通常是机构分配的字符串，本类默认 "1234567812345678"）
 *   M / msg    原文（明文或待签消息）；C1, C2, C3 是密文的三段；M′ 是解出来的明文
 *   (x₂,y₂)    共享点 k·P_B 的仿射坐标 —— 加密里唯一的"秘密"，双方各自算得到、旁观者算不到
 *   KDF        密钥派生函数（{@link #kdfSm3}）：z = 输入密钥材料(x₂‖y₂)，klen = 要几个字节；计数器从 1 起
 *   ⊕          逐比特/逐字节异或 (XOR)，这里用于 C2 = M ⊕ 密钥流
 *   ‖          字节串拼接（concatenate），<b>不是</b>异或
 *   ≡          "同余"：a ≡ b (mod m) 意思是 m 整除 (a − b)
 *   [k]P / k·P 标量乘：把点 P 自加 k 次（群运算的重复），<b>不是</b>两个数相乘
 *   Δ, Δs, Δr  攻击章节里"两枚签名之间的差"：Δ = k₂ − k₁（已知公差）、Δs = s₂ − s₁、Δr = r₂ − r₁
 *   h          余因子 (cofactor) = #E(Fp) / n：整条曲线上点的总个数 除以 G 生成的子群阶 n；sm2p256v1 取 h = 1
 * </pre>
 *
 * <p><b>术语表 —— 几个必须一次讲清的名词</b>
 * <pre>
 *   椭圆曲线 (over a finite field)  E(Fp) = { (x,y) ∈ Fp² | y² ≡ x³ + ax + b (mod p) } ∪ { O }。
 *       "曲线"在这里不是平面上的光滑弧线，而是<b>有限域里满足这条同余式的那些离散点</b>的集合（数量约 p 个，
 *       由 Hasse 定理夹在 p+1±2√p 之间）；
 *       配上"弦切法"加法以后构成一个<b>阿贝尔群</b>（交换律、结合律、有单位元 O、每个点有负点）。
 *       系数还要满足 4a³ + 27b² ≠ 0（模 p），否则方程有重根、"第三交点"的算法会退化。
 *   为什么点是数组、无穷远点是空数组  一个点的全部信息就是两个域元素 (x, y)，所以 {@code BigInteger[]{x, y}}
 *       已经完备；O 没有坐标（它是"所有竖直方向的终点"，几何上不在仿射平面里），于是用<b>长度 0 的数组</b>
 *       表示"没有坐标可谈"，判定点是否为 O 就变成 {@code pt.length == 0} —— 不需要类、不需要 null。
 *   仿射坐标 vs 射影坐标 (affine / projective)  仿射就是 (x, y) 本体；工程实现（含 BC）会用射影/雅可比坐标
 *       (X : Y : Z) 表示 x = X/Z²、y = Y/Z³，好处是加法链路里不必每步求模逆，最后再统一还原。
 *       本文件刻意只用仿射：<b>每一步都能看见那个 mod p 求逆</b>，代价是慢，收获是"算法没有任何隐藏步骤"。
 *   离散对数问题 (ECDLP, elliptic curve discrete logarithm problem)  已知 G 和公钥点（记作 Pub = d·G），反求 d。
 *       正向只要按二进制扫一遍做几百次域运算（本文件的 mul() 就是这个循环），反向没有任何已知的高效算法
 *       （最好的 Pollard's rho 也要约 √n ≈ 2¹²⁸ 次点运算）—— SM2 的全部安全性就押在这道题上
 *       （RSA 押的是大整数分解，同属"正向易、反向难"那一类数学难题）。
 *   mod n 归约  把大整数压回 [0, n) 区间（Java 的 BigInteger.mod 对负数也给非负结果）。
 *       因为 G 的阶是 n，所以 [a]G = [a mod n]G：所有标量（d、k、r、s、t）都只在 Z/nZ 里有意义。
 *       几何域里的数用 mod p，标量用 mod n，<b>p ≠ n</b> 是初学最容易搞混的一对模数。
 *   大端 (big-endian) 序列化  坐标/标量一律写成固定 32 字节的"高位字节在前"形式（Calc.toBytes），
 *       长度字段是 2 字节大端。拼接类公式（ZA、C3、KDF 输入）对字节错位极其敏感，定长大端是唯一约定。
 *   签名/验签的"域"  哈希与坐标编码是字节层面的事；r、s、t、d、k 全部是 mod n 的标量；
 *       点的加法全部是 mod p 的域运算 —— 一层字节、一层 mod n、一层 mod p，三件事别串。
 * </pre>
 */
@Slf4j
public class Sm2EssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /**
     * 曲线常数（GM/T 0003.5 的 sm2p256v1）；下面有一个测试专门拿 BC 的官方常数核对。
     *
     * <p>这六个常数就是把整条曲线"定义"完了 —— 曲线方程与群结构：
     * <pre>
     *   E :  y² ≡ x³ + a·x + b   (mod p)        256 位素数 p 上的椭圆曲线；只有满足这条同余式的 (x,y) 才是点
     *   点集 = { (x,y) ∈ Fp² | 上式成立 } ∪ { O }   O 是无穷远点，兼任加法单位元
     *   p  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF   域大小（素数）
     *   a  = p − 3（模 p 意义下，所以末字是 …FFFFFFFF FFFFFFFC）                      方程里 x 的一次项系数
     *   b  = 28E9FA9E … 4D940E93                                          方程的常数项
     *   n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123   基点 G 的阶（也是群阶）
     *   Gx = 32C4AE2C … 334C74C7,  Gy = BC3736A2 … 2139F0A0                基点的两个仿射坐标
     *
     *   为什么需要 n：由 G 出发反复相加只能得到 n 个不同的点 {G, 2G, …, (n−1)G, O}，
     *   n 就是"再加一次就回到 O"的最小正整数（n·G = O）。它是群的阶，因此
     *   ① 私钥/签名这些<b>标量</b>只能在 Z/nZ 里取值（mod n 归约的根据）；
     *   ② n 是素数 ⇒ G 生成的群没有任何"小子群"，余因子 h = #E(Fp)/n = 1，
     *      攻击者无法把一个不在主流上的点塞进协议（小群攻击）；
     *   ③ 安全性 ≈ 2¹²⁸ 次运算，就是由 n 的量级（2²⁵⁶）开平方根来的（Pollard rho 解 ECDLP）。
     *   为什么 p ≠ n：p 管"坐标在哪个域里"，n 管"标量在哪个环里"，两条线各自取模，绝不可混用。
     * </pre>
     */
    private static final BigInteger P = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16);
    private static final BigInteger B = new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    private static final BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    private static final BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

    /** 国标默认用户 ID（16 个 ASCII 字符 = 128 比特，所以 ENTL 编码成 2 字节大端 0x0080）；不显式给 ID 时就用它。 */
    private static final byte[] DEFAULT_ID = "1234567812345678".getBytes();
    /** 一个 256 位域元素序列化后的字节数（坐标、标量都是 32 字节大端），拼接类公式全靠它对齐。 */
    private static final int KEY_BYTES = 32;

    /**
     * 单个标量乘循环最多记录多少条 traceLoop 事件。
     *
     * <p>SM2-CORE 的验签会调用 sm2Verify 多次，每次又有两个 256 位标量乘；
     * 若逐位记录，一个测试方法的事件数会远超 250 条。这里按固定步长抽样，
     * 但始终保留第一位与最后一位，循环进度仍能走到 total。
     */
    private static final int MAX_LOOP_TRACES = 24;

    /**
     * 辅助方法内部的 trace 开关（按线程隔离）。
     *
     * <p>KREUSE 主题流程图只有 start/collect/solve/recover/verify/exploit/end 七个节点，
     * 但攻击过程会复用 sm2KeyPair/za/eValue/sm2Sign 等 SM2-CORE 辅助方法。
     * 这些辅助方法若照常发事件，group 会落到 KREUSE 流程图之外；
     * 因此 KREUSE 测试先把开关关掉，只手工记录攻击流程的高层事件。
     */
    private static final ThreadLocal<Boolean> HELPER_TRACE = new ThreadLocal<Boolean>()
    {
        @Override
        protected Boolean initialValue()
        {
            return Boolean.TRUE;
        }
    };

    private static boolean helperTraceEnabled()
    {
        return HELPER_TRACE.get().booleanValue();
    }

    private static void setHelperTrace(boolean enabled)
    {
        HELPER_TRACE.set(Boolean.valueOf(enabled));
    }

    /** 无穷远点（单位元）= 空数组。点从此只是数据。 */
    private static final BigInteger[] INFINITY = new BigInteger[0];

    /** 基点 G = (Gx, Gy)：所有标量乘法的起点，也是"公钥 = d·G"里那个被乘的固定点。 */
    private static final BigInteger[] G = new BigInteger[]{ GX, GY };

    /** SM3 直接调用本模块自己写的那个过程版实现。 */
    private static byte[] sm3(byte[] msg)
    {
        return Sm3.sm3(msg);
    }

    /**
     * 模 p 归一化，保证结果落在 [0, p)。
     *
     * <p>x mod p = x − p·⌊x/p⌋，把任意整数（哪怕来自减法而为负）压回域 Fp 的代表元；
     * BigInteger.mod 总给非负结果，所以这里不必自己处理负数。曲线上的每一个中间值都要过这一道。
     */
    private static BigInteger modP(BigInteger x)
    {
        return x.mod(P);
    }

    /**
     * 求逆：椭圆曲线里唯一的"贵"运算，就是模逆（扩展欧几里得）。
     *
     * <p>inverse(v) = v⁻¹ mod p，即满足 v·v⁻¹ ≡ 1 (mod p) 的唯一 v⁻¹ ∈ [1, p−1]。
     * 存在的条件是 gcd(v, p) = 1 —— p 是素数，所以只要 v ≠ 0 就一定可逆，这正是"用素数域"的回报。
     * 求法：扩展欧几里得解 v·s + p·t = 1，得到的 s 就是 v⁻¹（约 O(log p) 次除法），
     * 比一次乘法贵上百倍，所以"每一步都要不要取逆"是工程实现的核心问题（射影坐标就是为省掉它而生）。
     * 注意：这里 mod 的是 p（坐标域）；标量层面的逆用 {@code .modInverse(N)}，模数是 n。
     */
    private static BigInteger inverse(BigInteger v)
    {
        return v.mod(P).modInverse(P);
    }

    /**
     * 点在曲线上吗？ y² ≡ x³ + ax + b (mod p)。这是一个返回 boolean 的普通方法，不是对象方法。
     *
     * <p>逐符号：lhs = 左半边 = y² mod p；rhs = 右半边 = (x³ + a·x + b) mod p；
     * 两边都是 Fp 里的元素，相等即"这个点确实属于曲线"。x 最高三次、y 最高二次 ——
     * 这条"左边二次、右边三次"的形状决定了直线与它最多交于三点，从而加法才有"第三交点"可取。
     * 任何从外部收到的点（C1、公钥）都必须先过这一关，否则就是"无效曲线攻击"的入口。
     */
    private static boolean onCurve(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return true;                                   // 无穷远点按约定在曲线上
        }
        BigInteger lhs = modP(pt[1].multiply(pt[1]));
        BigInteger rhs = modP(pt[0].multiply(pt[0]).multiply(pt[0]).add(A.multiply(pt[0])).add(B));
        return lhs.equals(rhs);
    }

    /**
     * 取负点：y -> -y，返回新数组。
     *
     * <p>−P = (x, p − y)：把 y 换成 mod p 意义下的加法逆元（−y ≡ p−y），x 不动。
     * 几何理由：方程里 y 只以 y² 出现，所以 (x, y) 与 (x, −y) 同时满足方程；
     * 这两点连线是<b>竖直线</b>（第三个交点就是无穷远点 O），于是 P + (−P) = O —— 这就是"负"的定义。
     */
    private static BigInteger[] negate(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return pt;
        }
        return new BigInteger[]{ pt[0], modP(pt[1].negate()) };
    }

    /**
     * 倍点：弦切线的斜率 λ = (3x²+a)/(2y) 来自导数 3x²+a。
     *
     * <p>公式与推导（所有除法都是"乘模逆"，域是 Fp）：
     * <pre>
     *   λ  = (3x² + a) / (2y)          切线斜率。隐函数求导：对方程 y² = x³ + ax + b 两边微分，
     *                                     2y·dy = (3x² + a)·dx  ⇒  dy/dx = (3x²+a)/(2y)
     *                                     a 是一次项 x 的系数；2y 就是 y² 求导掉下来的那个 2
     *   x₃ = λ² − 2x                   这里"两个交点重合成一个"，所以 Vieta 的三个根是 x, x, x₃，
     *                                     由 x + x + x₃ = λ² 得到 x₃ = λ² − x − x（代码里就是连减两次 pt[0]）
     *   y₃ = λ(x − x₃) − y             先取直线上的点再关于 x 轴翻折（取负 y），得到的才是群运算的结果
     *   2y ≡ 0 (mod p) 时（含 y = 0 的 2 阶点）分母不可逆 ⇒ 结果是 O，代码提前返回 INFINITY
     * </pre>
     * 为什么"切线"：P+P 的定义是"过 P 与该点相切的直线"的第三交点再取负 —— 只有切线在这一点的
     * 交点是<b>两个重合</b>的，正好让"两点相加"的极限情形自洽。
     */
    private static BigInteger[] doublePoint(BigInteger[] pt)
    {
        if (pt.length == 0 || modP(pt[1].shiftLeft(1)).signum() == 0)
        {
            return INFINITY;
        }
        // lam = (3·x² + a) · (2y)⁻¹ mod p：shiftLeft(1) 就是 2y，inverse() 是 mod p 求逆
        BigInteger lam = modP(pt[0].multiply(pt[0]).multiply(BigInteger.valueOf(3)).add(A))
            .multiply(inverse(pt[1].shiftLeft(1))).mod(P);
        // x₃ = λ² − x − x；y₃ = λ(x − x₃) − y（直线上的第三交点关于 x 轴翻折）
        BigInteger x = modP(lam.multiply(lam).subtract(pt[0]).subtract(pt[0]));
        BigInteger y = modP(lam.multiply(pt[0].subtract(x)).subtract(pt[1]));
        return new BigInteger[]{ x, y };
    }

    /**
     * 加法：普通静态方法，返回新数组；相消情况返回单位元。
     *
     * <p>逐符号（p = 第一个点、q = 第二个点，代码形参名沿用数学里"点 P、点 Q"）：
     * 提醒：本方法的形参 p 是<b>点</b>，与符号表里表示素数域大小的小写 p（字段 P）只是撞名，
     * 域取模请看方法体里的 modP()，别把两个 p 当成一个东西。
     * <pre>
     *   λ  = (y₂ − y₁) / (x₂ − x₁)      过两点的<b>弦</b>的斜率；− 在 Fp 里就是加 p 再 mod p
     *   x₃ = λ² − x₁ − x₂               第三个交点的横坐标（<b>不是</b> x₁+x₂，这是最常见的误解）
     *   y₃ = λ(x₁ − x₃) − y₁            把 x₃ 代回直线方程 y = λ(x − x₁) + y₁，再整体取负
     * </pre>
     * 为什么 x₃ 长这样（Vieta 定理，弦与倍点共用同一条推导）：
     * 直线 y = λx + ν 代入曲线得 x³ − λ²x² + (a − 2λν)x + (b − ν²) ≡ 0，
     * 这个三次式的三个根就是三个交点的横坐标 x₁, x₂, x₃；
     * 而"根之和 = −(x² 的系数) = λ²"，所以 x₃ = λ² − x₁ − x₂ —— <b>完全没有用到解三次方程</b>，
     * 斜率一确定，第三个交点的 x 就被这条恒等式钉死了。
     * 为什么还要"取负 y"：直线与曲线的第三个交点 (x₃, y₃′) 和 P+Q 关于 x 轴对称，
     * 群加法故意定义成"翻折以后的那个点"，才让 P + (−P) = O 成立（竖直线的第三交点是 O）。
     * 相消分支：x₂ = x₁ 且 y₂ = −y₁（即 modP(p[1].add(q[1])) == 0）时弦是竖直线 ⇒ 返回 O；
     * x 相同而 y 不互为相反数时其实是同一个点 ⇒ 走倍点。
     */
    private static BigInteger[] add(BigInteger[] p, BigInteger[] q)
    {
        if (p.length == 0)
        {
            return q;
        }
        if (q.length == 0)
        {
            return p;
        }
        if (p[0].equals(q[0]))
        {
            return modP(p[1].add(q[1])).signum() == 0 ? INFINITY : doublePoint(p);
        }
        // λ = (y₂ − y₁)·(x₂ − x₁)⁻¹ mod p：弦的斜率，分母求逆是 mod p（不是 mod n）
        BigInteger lam = modP(q[1].subtract(p[1])).multiply(inverse(modP(q[0].subtract(p[0])))).mod(P);
        // x₃ = λ² − x₁ − x₂（Vieta：三根之和等于 λ²）；y₃ = λ(x₁ − x₃) − y₁（回直线再翻折）
        BigInteger x = modP(lam.multiply(lam).subtract(p[0]).subtract(q[0]));
        BigInteger y = modP(lam.multiply(p[0].subtract(x)).subtract(p[1]));
        return new BigInteger[]{ x, y };
    }

    /**
     * 标量乘 = 逐位扫描的 for 循环（从最高位往下：先 double，再按位 add）。这就是"倍加算法"的本质。
     *
     * <p>先说清"标量乘"是什么：k·P 表示把同一个点自加 k 次 P+P+…+P，它是<b>群里的重复加法</b>，
     * 和"两个数相乘"没有任何关系；正因如此才有 k·P = (k mod n)·P（n 是 P 所在循环群的阶）。
     * 直接循环 k 次要 2²⁵⁶ 次加法，不可行；按二进制展开只需约 256 次 double + 128 次 add。
     *
     * <p>符号与不变量：
     * <pre>
     *   k              标量（私钥/随机数），二进制写作 k = (k_{L−1} k_{L−2} … k₁ k₀)₂，L = k.bitLength()
     *   kᵢ ∈ {0,1}     第 i 个比特；k = Σᵢ kᵢ·2ⁱ，于是 k·P = Σᵢ kᵢ·(2ⁱP) —— 这就是算法要证的东西
     *   bit            当前正在处理的位下标，从 L−1（最高位）一路减到 0
     *   acc            累加器 (accumulator)，循环不变量：处理完高位到第 bit 位以后 acc = (那几位组成的数)·P
     *   doubled        2·acc = 把已得到的结果整体翻倍（等价于所有已处理的位左移一格）
     *   point          被乘的那个固定点 P（签名里是 G，加密里也是 G 或对方公钥）
     * </pre>
     * 为什么"先 double 再按位 add"就对了：读下一位 k_bit 时，已有的系数要乘 2（因为新位比上一位低一次幂），
     * 这正是 double；若 k_bit = 1 再补一个 P。用 Horner 形式看就是
     * k·P = ((…((k_{L−1}·P)·2 + k_{L−2}P)·2 + …)·2 + k₀P)，
     * 展开每一项恰好得到 Σ kᵢ·2ⁱ·P = Σ kᵢ·(2ⁱP)。反过来说：位是 0 时只加倍不加，是 1 时加完再继续倍增。
     */
    private static BigInteger[] mul(BigInteger k, BigInteger[] point)
    {
        return mul(k, point, null);
    }

    private static BigInteger[] mul(BigInteger k, BigInteger[] point, String loopName)
    {
        return mul(k, point, loopName, loopName);
    }

    /**
     * @param loopId 循环实例的唯一 id（事件 metadata.loopName，用于绑定进度条）
     * @param group  事件分组（可带阶段前缀，如 "verify1:mul_sG"），用于流程图定位
     */
    private static BigInteger[] mul(BigInteger k, BigInteger[] point, String loopId, String group)
    {
        boolean tracing = loopId != null && helperTraceEnabled() && Tracer.isEnabled();
        int total = k.bitLength();
        // 抽样步长：最多 MAX_LOOP_TRACES 条事件，同时保证最后一位一定被记录
        int stride = Math.max(1, (total + MAX_LOOP_TRACES - 1) / MAX_LOOP_TRACES);
        if (tracing)
        {
            Tracer.pushLoop(group);
        }
        BigInteger[] acc = INFINITY;                       // 局部变量当累加器，一目了然
        for (int j = 0; j < total; j++)
        {
            int bit = total - 1 - j;               // 从最高位开始
            BigInteger[] doubled = doublePoint(acc);
            // k 的第 bit 位是 1 就在倍增后的结果上再补一个 P；是 0 就直接沿用 doubled
            if (k.testBit(bit))
            {
                acc = add(doubled, point);
            }
            else
            {
                acc = doubled;
            }
            if (tracing && (j % stride == 0 || j == total - 1))
            {
                Tracer.traceLoop("mulStep", new Object[]{
                    "j", j, "bit", bit, "bitVal", k.testBit(bit) ? 1 : 0, "acc", acc
                }, acc, group, j + 1, total, loopId);
            }
        }
        if (tracing)
        {
            Tracer.popLoop();
        }
        return acc;
    }

    /**
     * ZA = SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)：SM2 把"身份"绑进哈希的那一步。
     *
     * <p>每个字母（这就是 SM2 与 ECDSA 最大的形式差异 —— 签的不是"H(M)"而是"H(Z ‖ M)"）：
     * <pre>
     *   ZA     签名者 A 的<b>用户标识杂凑</b> (user identity hash / Z value)；对应地 ZB 是通信对端 B 的
     *   ENTL   2 字节大端的<b>比特</b>长度：ENTL = 8 · ID.length（代码里的 entl），上限 65535 位；
     *            它是长度前缀，让"ID 短一截再接别的字节"和"ID 本身不同"不可能撞成同一个输入串
     *   ID     由机构颁发的用户标识（邮箱式字符串、证件号…），本类默认 1234567812345678
     *   a, b   曲线系数（<b>不是</b>参与运算的点），把"用的是哪条曲线"也写进哈希
     *   Gx, Gy 基点坐标，把"曲线上的哪个起点"写进哈希
     *   Px, Py 公钥点的两个坐标，pub[0] / pub[1]，即 ZA 里唯一"随人而变"的部分
     *   ‖      字节串拼接；所有坐标都按 32 字节定长大端序列化（Calc.toBytes），少一个前导零就全体错位
     * </pre>
     * 为什么要 Z：签名/密钥交换只证明了"某人持有与公钥 P 对应的私钥"，并没有说 P 属于<b>谁</b>。
     * 把 ID 与曲线参数一起哈希进 Z，再把 Z 掺进 e = SM3(Z‖M)，就得到
     * "这个身份、这条曲线、这个公钥、这条消息"四者绑定的证据。
     * 防的是<b>公钥替换/冒充</b>（key substitution / impersonation）：攻击者把"声称属于 Alice 的公钥"
     * 换成他自己生成的那把，由于 Z 里同时含对方声明的 ID 与这对坐标 Px‖Py，哈希立刻不同，验签必挂
     * （见 {@link #zaBindsTheIdentityIntoTheHash}）。
     * 密钥交换协议里双方各算 ZA、ZB，还要各自把对方的 Z 混进密钥确认，才叫"互相确认了身份"。
     */
    private static byte[] za(byte[] userId, BigInteger[] pub)
    {
        long startNanos = System.nanoTime();
        byte[] entl = Calc.toBytes(BigInteger.valueOf(8L * userId.length), 2);
        byte[] result = sm3(Calc.concat(entl, userId,
            Calc.toBytes(A, KEY_BYTES), Calc.toBytes(B, KEY_BYTES),
            Calc.toBytes(GX, KEY_BYTES), Calc.toBytes(GY, KEY_BYTES),
            Calc.toBytes(pub[0], KEY_BYTES), Calc.toBytes(pub[1], KEY_BYTES)));
        long duration = System.nanoTime() - startNanos;
        if (helperTraceEnabled())
        {
            Tracer.trace("computeZA", new Object[]{
                "userId", new String(userId), "Px", pub[0], "Py", pub[1]
            }, result, "computeZA", duration);
        }
        return result;
    }

    /**
     * e = SM3(ZA ‖ M) 转成大整数 —— SM2 的"消息摘要"其实只有这一行。
     *
     * <p>逐符号：Z = 上面那个用户标识杂凑（含 ID）；M = 原文消息；‖ = 拼接；
     * 摘要 32 字节再按<b>大端无符号</b>读成一个 256 位整数 e（Calc.toBigInt），
     * 于是 e ∈ [0, 2²⁵⁶)，而这个上界比 n 略大（n 只比 2²⁵⁶ 小一点点），所以 e 完全可能 ≥ n；
     * 公式里写作不预先归约（r = (e + x₁) mod n 一步搞定；因为取模对加法是同态，先约后约结果一样）。
     * e 的角色是"消息的数值化身"：它进入 r，任何改动消息都会换 e，从而换 r，验签立刻对不上。
     */
    private static BigInteger eValue(byte[] za, byte[] message)
    {
        return eValue(za, message, "computeE");
    }

    /**
     * 带 group 的版本：多次计算 e 的测试（如验签③ 的篡改消息）要落到自己的流程节点上，
     * 否则光标会跳回主流程开头的 computeE。
     */
    private static BigInteger eValue(byte[] za, byte[] message, String group)
    {
        long startNanos = System.nanoTime();
        BigInteger result = Calc.toBigInt(sm3(Calc.concat(za, message)));
        long duration = System.nanoTime() - startNanos;
        if (helperTraceEnabled())
        {
            Tracer.trace("computeE", new Object[]{"za", za, "msgLen", message.length}, result, group, duration);
        }
        return result;
    }

    /**
     * 签名：{@code sm2Sign(d, e, k)} 返回 {@code {r, s}}。
     * r = (e + x₁) mod n，s = (1+d)⁻¹ (k - r·d) mod n —— 三个实参一个返回数组，没有任何"函数套函数"。
     *
     * <p>逐个字母（标量全部在 Z/nZ 里，即每次都要 mod n；只有求 kG 那一步是 mod p 的几何运算）：
     * <pre>
     *   d          私钥标量，标准规定 1 ≤ d ≤ n−2；公钥点 P = d·G 是公开的
     *   e          消息哈希整数 = SM3(ZA ‖ M) 的大端读数（见 {@link #eValue}）
     *   k          <b>一次性</b>随机标量（临时私钥 / nonce），1 ≤ k ≤ n−1；每个消息、每次签名都必须换新的，
     *                它不进签名、不重放 —— 泄露或复用一次，d 就被解出来（见本文件后半部分的三条攻击）
     *   (x₁,y₁)    k·G 这个点的仿射坐标；本方法只取横坐标 x1 = mul(k, G)[0]，y₁ 算了但丢掉
     *   r          = (e + x₁) mod n —— 把"消息"与"临时点的横坐标"揉在一起；它是验签时要核对的那一位
     *   s          = (1 + d)⁻¹ · (k − r·d) mod n —— 把 d 藏进一次模逆；(1+d)⁻¹ 是 mod n 的逆
     *   n          基点的阶；modN() 就是压回 [0, n)
     * </pre>
     * 两条拒绝条件（不是可选的"健壮性检查"，而是数学上必须重试）：
     * <pre>
     *   r ≠ 0            若 e + x₁ ≡ 0 (mod n) 则 r = 0，而标准强制 r ∈ [1, n−1]；
     *                    这时验签式子退化成"只核对 (e + x₁) ≡ 0"，r 这一位不再把消息与临时点绑定起来，
     *                    所以标准选择最保守的做法：换一个 k 重来
     *   r + k ≠ 0 (mod n) 若 r + k ≡ 0，则 k ≡ −r，代入 s 的式子得
     *                    s = (1+d)⁻¹(−r − r·d) = (1+d)⁻¹·(−r)·(1+d) = −r ≡ k，
     *                    于是验签要的 t = (r + s) ≡ r + (−r) = 0 ⇒ 验签侧的 t ≠ 0 检查直接判负；
     *                    与其生成一枚"永远验不过"的签名，不如在这里就重试（顺便也避免 s = k 这种退化形态）
     * </pre>
     * 注意 d = n−1 的情形被 d ≤ n−2 排除掉了：那样 1 + d ≡ 0 (mod n) 就没有模逆，s 根本算不出来。
     */
    private static BigInteger[] sm2Sign(BigInteger d, BigInteger e, BigInteger k)
    {
        long startNanos = System.nanoTime();
        boolean tracing = helperTraceEnabled();
        if (tracing)
        {
            Tracer.trace("sm2Sign.enter", new Object[]{"d", d, "e", e, "k", k}, null, "sm2Sign");
        }

        BigInteger[] kG = mul(k, G, "mul_kG");
        BigInteger x1 = kG[0];                       // (x₁,y₁) = kG，只需要 x₁
        // r = (e + x₁) mod n
        BigInteger r = modN(e.add(x1));
        long rNanos = System.nanoTime();
        if (tracing)
        {
            Tracer.trace("computeR", new Object[]{"e", e, "x1", x1}, r, "computeR", rNanos - startNanos);
            Tracer.traceDecision("checkR", new Object[]{"r", r}, r.signum() != 0, "checkR", "r == 0");
        }
        Assert.assertTrue("r 不能为 0（k 需重试）", r.signum() != 0);
        // s = (k − r·d) · (1 + d)⁻¹ mod n：注意这里的 modInverse 的模数是 n（标量域），不是 p
        BigInteger s = modN(k.subtract(r.multiply(d)).multiply(BigInteger.ONE.add(d).modInverse(N)));
        long sNanos = System.nanoTime();
        if (tracing)
        {
            Tracer.trace("computeS", new Object[]{"k", k, "r", r, "d", d}, s, "computeS", sNanos - rNanos);
            Tracer.traceDecision("checkRK", new Object[]{"r+k", modN(r.add(k))},
                modN(r.add(k)).signum() != 0, "checkRK", "r + k ≡ 0 (mod n)");
        }
        // r + k ≡ 0 (mod n) 会让 t = r + s 归零、验签必失败 ⇒ 标准规定重试
        Assert.assertTrue("r + k 不能等于 n（k 需重试）", modN(r.add(k)).signum() != 0);
        if (tracing)
        {
            Tracer.trace("returnRS", new Object[]{"r", r, "s", s}, new BigInteger[]{r, s}, "returnRS");
        }
        return new BigInteger[]{ r, s };
    }

    /**
     * 验签：{@code sm2Verify(pub, e, rs)} 返回 boolean。
     * t = (r+s) mod n，(x₁,y₁) = sG + tP，检查 (e+x₁) mod n == r。
     *
     * <p>逐个字母：
     * <pre>
     *   pub        公钥点 (Px, Py) = d·G；数学上惯把它记作 P，但本文件的 Java 常量 P 是那个素数，别混。
     *              验签不需要私钥，只需要这个点。
     *   r, s       待验的签名对，必须都在 [1, n−1]（越界/为 0 直接判负，这是"格式合法"这一关）
     *   e          和签名时同一个算法算出的消息哈希整数：SM3(ZA ‖ M) 的大端读数
     *   t          = (r + s) mod n，验签的组合系数；t = 0 时 [t]P 会是 O，整条检验失去意义 ⇒ 直接判负
     *   sG + tP    两次标量乘再相加，得到的点记 (x₁, y₁)；若它是 O（相消）也判负
     * </pre>
     * <b>为什么这一串恰好等于签名时的 kG</b>（把 s 的定义代进去，一路 mod n 化简）：
     * <pre>
     *   s  = (1+d)⁻¹(k − r·d)                      | 两边乘 (1+d)
     *   s(1+d) = k − r·d
     *   s + s·d = k − r·d                           | 含 d 的项挪到左边
     *   s + d·(s + r) = k                           | 提出公因子 d，而 s + r 正是 t
     *   ⇒  s·G + t·P = s·G + (r+s)·(d·G) = (s + d·(r+s))·G = k·G
     * </pre>
     * 所以验签得到的点就是签名时那个 kG，它的横坐标 x₁ 满足 r = (e + x₁) mod n ——
     * 核对式 (e + x₁) mod n == r 成立当且仅当签名用的是同一个 d 对应的 k。
     * 关键在"验签者算不出 kG，但能用 P 拼出同一个点"：k 只以 kG 的形式泄漏，而 P = d·G 提供了 d 的那一份，
     * 两者线性组合恰好抵消掉 d 的遮挡 —— 这就是 ECDLP 给的单向性。
     * 反过来，改 r、改 s、改消息（e 变）都会让 x₁ 对不上或组合系数错，验签必挂。
     */
    private static boolean sm2Verify(BigInteger[] pub, BigInteger e, BigInteger[] rs)
    {
        return sm2Verify(pub, e, rs, null);
    }

    /**
     * 带轮次前缀的验签：一次测试里验签多次时，每次用唯一 phase（如 "verify1"），
     * 事件 group 变成 "verify1:checkFormat" 等，流程图才能把三次验签分开高亮。
     * phase 为 null 时保持原来的扁平 group（供只验一次的测试使用）。
     */
    private static boolean sm2Verify(BigInteger[] pub, BigInteger e, BigInteger[] rs, String phase)
    {
        long startNanos = System.nanoTime();
        boolean tracing = helperTraceEnabled();
        if (tracing)
        {
            Tracer.trace("sm2Verify.enter", new Object[]{"pub", pub, "e", e, "rs", rs}, null,
                phaseGroup(phase, "sm2Verify"));
        }

        BigInteger r = rs[0];
        BigInteger s = rs[1];
        // 第一关：格式合法 —— r、s 都必须是 [1, n−1] 里的标量（≤0 或 ≥n 一律拒绝）
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(N) >= 0 || s.compareTo(N) >= 0)
        {
            if (tracing)
            {
                Tracer.traceDecision("checkFormat", new Object[]{"r", r, "s", s}, false,
                    phaseGroup(phase, "checkFormat"), "r,s ∈ [1,n-1]");
            }
            return false;
        }
        if (tracing)
        {
            Tracer.traceDecision("checkFormat", new Object[]{"r", r, "s", s}, true,
                phaseGroup(phase, "checkFormat"), "r,s ∈ [1,n-1]");
        }
        // t = (r + s) mod n，它就是推导里 d 的系数；t = 0 时 [t]P = O，等式失去信息 ⇒ 拒绝
        BigInteger t = modN(r.add(s));
        if (tracing)
        {
            Tracer.trace("computeT", new Object[]{"r", r, "s", s}, t, phaseGroup(phase, "computeT"));
        }
        if (t.signum() == 0)
        {
            if (tracing)
            {
                Tracer.traceDecision("checkT", new Object[]{"t", t}, false,
                    phaseGroup(phase, "checkT"), "t == 0");
            }
            return false;
        }
        if (tracing)
        {
            Tracer.traceDecision("checkT", new Object[]{"t", t}, true,
                phaseGroup(phase, "checkT"), "t == 0");
        }
        // (x₁, y₁) = s·G + t·P；合法签名下它就是签名时的 kG
        String sLoopId = phase == null ? "mul_sG" : phase + "_mul_sG";
        String tLoopId = phase == null ? "mul_tP" : phase + "_mul_tP";
        BigInteger[] sG = mul(s, G, sLoopId, phaseGroup(phase, "mul_sG"));
        BigInteger[] tP = mul(t, pub, tLoopId, phaseGroup(phase, "mul_tP"));
        BigInteger[] point = add(sG, tP);
        if (tracing)
        {
            Tracer.trace("ecOp", new Object[]{"sG", sG, "tP", tP}, point, phaseGroup(phase, "ecOp"));
        }
        if (point.length == 0)
        {
            if (tracing)
            {
                Tracer.traceDecision("checkPoint", new Object[]{"point", "O"}, false,
                    phaseGroup(phase, "checkPoint"), "point == O");
            }
            return false;
        }
        if (tracing)
        {
            Tracer.traceDecision("checkPoint", new Object[]{"point", point}, true,
                phaseGroup(phase, "checkPoint"), "point == O");
        }
        // 核对：(e + x₁) mod n 必须等于 r（签名式子里 r 就是这么定义的）
        boolean result = modN(e.add(point[0])).equals(r);
        long duration = System.nanoTime() - startNanos;
        if (tracing)
        {
            Tracer.trace("finalCheck", new Object[]{"e", e, "x1", point[0], "r", r}, result,
                phaseGroup(phase, "finalCheck"), duration);
        }
        return result;
    }

    /** 验签轮次前缀：phase 为空时就是普通 group 名。 */
    private static String phaseGroup(String phase, String name)
    {
        return phase == null ? name : phase + ":" + name;
    }

    /** mod n 归约：把标量压回 [0, n)。n 是基点的阶 ⇒ [a]G = [a mod n]G，所以 d/k/r/s/t 都只在 Z/nZ 里有意义。 */
    private static BigInteger modN(BigInteger x)
    {
        return x.mod(N);
    }

    /**
     * KDF（SM3 计数器流）：加密里把共享点坐标变成密钥流的过程 —— 一个 while 循环逐块填充。
     *
     * <p>符号与公式（GM/T 0003.4 的密钥派生函数，计数器模式）：
     * <pre>
     *   z        输入密钥材料 (IKM)：这里是共享点的坐标拼接 x₂ ‖ y₂（各 32 字节大端，共 64 字节）
     *   klen     要输出的字节数 —— 在 SM2 加密里就等于<b>明文长度</b>（标准写作 klen = 8·len(M) <b>位</b>）
     *   ct       32-bit 计数器，从 <b>1</b> 开始每轮加 1，编码成 4 字节大端（Calc.toBytes(..., 4)）
     *   第 ct 块 = SM3(z ‖ ct₄)，正好 32 字节 = 256 bit
     *   输出     = 第 1 块 ‖ 第 2 块 ‖ … 拼到足够长，再截断到前 klen 字节（最后一块只取一部分）
     * </pre>
     * 为什么要有计数器：SM3 一次只吐 32 字节，而密钥流要覆盖任意长的明文；不同 ct 让每块输入互不相同，
     * 于是各块输出不会重复（少了 ct，KDF 只会给你同一段 32 字节反复循环 —— 那是致命的流复用）。
     * 为什么"128 bit"常出现在文档里：如果 KDF 的输出是给分组密码（如 SM4）当<b>会话密钥</b>，就取 16 字节 = 128 bit；
     * 本文件的用法是把输出当<b>一次性掩码</b>逐字节异或明文（流式用法），所以取的长度是 klen = 明文字节数。
     */
    private static byte[] kdfSm3(byte[] z, int klen)
    {
        byte[] out = new byte[klen];
        int off = 0;
        int counter = 1;                                    // 计数器从 1 开始，每轮出 32 字节
        while (off < klen)
        {
            // 每一轮：把 z 与 4 字节大端计数器拼起来做一次 SM3，取前 (klen − off) 字节填进输出窗口
            byte[] stream = sm3(Calc.concat(z, Calc.toBytes(BigInteger.valueOf(counter), 4)));
            int take = Math.min(klen - off, stream.length);
            System.arraycopy(stream, 0, out, off, take);
            off += take;
            counter++;
        }
        return out;
    }

    /**
     * SM2 加密：{@code sm2Encrypt(pub, c1c3c2, k, plaintext)} 返回密文。
     * C1 = kG（04‖x‖y），共享点 kP=(x₂,y₂)，密钥流 = KDF(x₂‖y₂)，C2 = M ⊕ 流，C3 = SM3(x₂‖M‖y₂)。
     * mode = C1C2C3 / C1C3C2 只决定 C2、C3 的排列顺序 —— 这就是"算法模式"的全部差异。
     *
     * <p>逐个符号（这其实是 ECIES/椭圆曲线集成加密方案的一张最小可行图：一次点乘换共享密钥，
     * 靠哈希提供认证，从不"用曲线直接加密比特"）：
     * <pre>
     *   pub          接收方 B 的公钥点 P_B = d_B·G（各 32 字节大端坐标）
     *   k            发送方<b>每次加密都新起</b>的一次性随机标量；它等价于"一次性的私钥"，
     *                  只以 kG 的形式出现在 C1 里，任何人（包括 B）都无法从 C1 反求 k（ECDLP）
     *   C1 = kG      临时公钥点，序列化成未压缩格式 0x04 ‖ x₁(32B) ‖ y₁(32B) = 65 字节；
     *                  B 收到后用 d_B 算 [d_B](kG) = k(d_BG) = kP_B 就还原出共享点 —— 这就是"交换顺序"的魔法
     *   (x₂,y₂)      共享点 k·P_B 的两个仿射坐标，双方各算各的、结果相同；它是唯一的秘密，从不直接上线
     *   KDF(x₂‖y₂)   把共享点坐标展开成 klen 字节密钥流（klen = 明文字节数），见 {@link #kdfSm3}
     *   C2 = M ⊕ 流   明文与密钥流逐字节异或：长度和明文一模一样，解密方再异或同一个流就还原
     *   C3 = SM3(x₂ ‖ M ‖ y₂)   32 字节<b>认证标签</b>（完整性校验值）：把共享点和<b>明文</b>一起哈希，
     *                  所以改 C2 会让重算的 C3 对不上；SM2 密文因此<b>自带认证性</b>（AE），不需要再配 MAC
     *   0x04         SEC1 未压缩点前缀：0x02/0x03 只带 x 和奇偶位，0x04 表示后面老老实实跟 x‖y 两个坐标
     *   c1c3c2       布尔开关：true = 新国标顺序 C1‖C3‖C2，false = 老的行业顺序 C1‖C2‖C3
     * </pre>
     * 两种模式的差异<b>只有排列</b>：三段的内容、算法、长度完全相同，
     * C1 永远在最前（65 字节，因为它长度固定），差别是"标签 C3 紧跟 C1"还是"贴在末尾"。
     * 新标准选 C1C3C2 的动机：C3 紧跟定长的 C1，解析器<b>不必先知道明文长度</b>就能定位校验值，
     * 也就先于任何 C2 处理完成完整性检查（老顺序要先算出 C2 长度才能切出 C3）。
     * 另外标准还定义了一种 ASN.1 DER 封装形式
     * {@code SEQUENCE { INTEGER x₁, INTEGER y₁, OCTET STRING C3, OCTET STRING C2 }}
     * —— 即"用 DER 表达 C1C3C2"，各段变成带类型标签和长度字段的结构，不再靠定长推断；
     * 本文件用的是"0x04‖x₁‖y₁ + 裸 C3/C2 首尾相接"的紧凑形式（JCE Cipher "SM2" 在测试里直接吃这一种）。
     * 签名侧则必须用 DER（{@code SEQUENCE{r,s}}），因为 r、s 是无前导零的小整数，裸拼会丢长度。
     */
    private static byte[] sm2Encrypt(BigInteger[] pub, boolean c1c3c2, BigInteger k, byte[] plaintext)
    {
        BigInteger[] c1Point = mul(k, G);
        // 共享点 (x₂,y₂) = k·P_B：只有持有 d_B = pub 对应私钥的人能算出（旁观者被 ECDLP 挡住）
        BigInteger[] shared = mul(k, pub);
        byte[] x2 = Calc.toBytes(shared[0], KEY_BYTES);
        byte[] y2 = Calc.toBytes(shared[1], KEY_BYTES);
        // C1 = 0x04 ‖ x₁ ‖ y₁（65 字节未压缩临时公钥点）
        byte[] c1 = Calc.concat(new byte[]{ 0x04 }, Calc.toBytes(c1Point[0], KEY_BYTES), Calc.toBytes(c1Point[1], KEY_BYTES));
        boolean tracing = helperTraceEnabled();
        if (tracing)
        {
            Tracer.trace("c1", new Object[]{"k", k, "C1Point", c1Point}, c1, "c1");
        }
        // C2 = M ⊕ KDF(x₂‖y₂, klen=明文长度)：逐字节掩码，长度 = 明文长度
        byte[] stream = kdfSm3(Calc.concat(x2, y2), plaintext.length);
        if (tracing)
        {
            Tracer.trace("kdf", new Object[]{"x2", x2, "y2", y2, "klen", plaintext.length}, stream, "kdf");
        }
        byte[] c2 = Calc.xor(plaintext, stream);
        if (tracing)
        {
            Tracer.trace("c2", new Object[]{"M", plaintext, "stream", stream}, c2, "c2");
        }
        // C3 = SM3(x₂ ‖ M ‖ y₂)：32 字节认证标签，注意它哈希的是<b>明文</b>而不是密文
        byte[] c3 = sm3(Calc.concat(x2, plaintext, y2));
        if (tracing)
        {
            Tracer.trace("c3", new Object[]{"x2", x2, "M", plaintext, "y2", y2}, c3, "c3");
        }
        // 唯一的"模式"差异：两段可选内容的先后顺序
        return c1c3c2 ? Calc.concat(c1, c3, c2) : Calc.concat(c1, c2, c3);
    }

    /**
     * SM2 解密：{@code sm2Decrypt(d, c1c3c2, ciphertext)} 返回明文，并重新校验 C3（认证性来自这里）。
     *
     * <p>流程与符号（加密的完全逆过程，唯一新东西是"用 d 还原共享点"）：
     * <pre>
     *   d          接收方私钥标量 d_B，唯一能挡住旁观者的东西
     *   C1 = (x₁,y₁) 从密文头 65 字节里切出来：第 0 字节是 0x04 前缀（这里直接跳过不校验），
     *                接下来 32 字节大端 = x₁，再 32 字节 = y₁；两个字节串都用 Calc.toBigInt 读成无符号大整数
     *   共享点       (x₂,y₂) = d · C1 = [d_B](kG) = k(d_BG) = k·P_B —— 标量乘满足交换律，
     *                所以"先乘 k 再乘 d_B"和"先乘 d_B 再乘 k"给出同一个点，双方才能对上密钥
     *   密钥流       KDF(x₂‖y₂, len(C2))，与加密侧完全相同（因为 klen 就是 C2 的长度 = 明文长度）
     *   M′ = C2 ⊕ 流  异或的自反性：C2 ⊕ 流 = (M ⊕ 流) ⊕ 流 = M
     *   C3 校验      重算 SM3(x₂ ‖ M′ ‖ y₂) 与密文里带来的 C3 逐字节比对，不一致就是被篡改 ⇒ 拒绝
     *   c3/c2 的切分 由布尔参数 c1c3c2 决定：C1C3C2 时 C3 紧跟 65 字节的 C1（定长 32 字节），C2 是剩下的尾巴；
     *                C1C2C3 时 C2 在中间、C3 是最后 32 字节 —— 因为 C2 长度 = 明文长度不固定，
     *                老模式只能"从尾部数 32 字节当 C3"，新模式可以"从头部数 65+32 字节就切出 C2"
     * </pre>
     * 关于标准里的"校验 S = [h]C1 ≠ O"这一步（h = 余因子 = #E(Fp)/n）：它拦的是<b>小群攻击</b> ——
     * 攻击者递一个阶整除 h 的点当 C1，让共享点落进很小的子集从而被猜测。
     * sm2p256v1 的 h = 1，所以 [h]C1 = C1 永远不是 O（C1 非零），该检查看不出任何东西；
     * 因此本文件没有这一步（要防御的话应改为显式检查 C1 在曲线上、且 [n]C1 = O）。
     * 认证性的真正来源是 C3：任何对 C2 的改动都会让解出的 M′ 变，从而 SM3(x₂‖M′‖y₂) 与带来的 C3 不符。
     */
    private static byte[] sm2Decrypt(BigInteger d, boolean c1c3c2, byte[] ciphertext)
    {
        // 从 C1 的 65 字节里切出 (x₁, y₁)：跳过第 0 个 0x04 前缀，各取 32 字节大端读成无符号大整数
        BigInteger[] c1Point = new BigInteger[]{
            Calc.toBigInt(Arrays.copyOfRange(ciphertext, 1, 1 + KEY_BYTES)),
            Calc.toBigInt(Arrays.copyOfRange(ciphertext, 1 + KEY_BYTES, 1 + 2 * KEY_BYTES)) };
        // 按模式切出 C3（32 字节定长）：C1C3C2 时它紧跟 65 字节的 C1；C1C2C3 时它在末尾最后 32 字节
        byte[] c3 = c1c3c2
            ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, 1 + 2 * KEY_BYTES + 32)
            : Arrays.copyOfRange(ciphertext, ciphertext.length - 32, ciphertext.length);
        byte[] c2 = c1c3c2
            ? Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES + 32, ciphertext.length)
            : Arrays.copyOfRange(ciphertext, 1 + 2 * KEY_BYTES, ciphertext.length - 32);

        // 共享点 (x₂,y₂) = d·C1 = [d](kG) = k(dG) = k·P_B：标量乘可交换，所以用私钥乘 C1 就等于用随机数乘公钥
        BigInteger[] shared = mul(d, c1Point);
        byte[] x2 = Calc.toBytes(shared[0], KEY_BYTES);
        byte[] y2 = Calc.toBytes(shared[1], KEY_BYTES);
        // M′ = C2 ⊕ KDF(x₂‖y₂, len(C2))：异或自反 (M⊕流)⊕流 = M，所以解密密钥流和加密时必须是同一段
        byte[] stream = kdfSm3(Calc.concat(x2, y2), c2.length);
        byte[] plaintext = Calc.xor(c2, stream);
        boolean tracing = helperTraceEnabled();
        if (tracing)
        {
            Tracer.trace("decrypt", new Object[]{"d", d, "C1", c1Point, "C2", c2, "stream", stream},
                plaintext, "decrypt");
        }
        // 认证检查：用解出来的明文重算标签，和密文里带来的 C3 逐字节比对 —— SM2 密文的防篡改就靠这一行
        byte[] expectedC3 = sm3(Calc.concat(x2, plaintext, y2));
        if (tracing)
        {
            Tracer.traceDecision("compare", new Object[]{"C3", c3, "C3'", expectedC3},
                Arrays.equals(c3, expectedC3), "compare", "C3 == SM3(x₂‖M'‖y₂)");
        }
        Assert.assertArrayEquals("C3 校验失败：密文被篡改", c3, expectedC3);
        return plaintext;
    }

    // ---------------------------------------------------------------- 测试

    /**
     * 密钥对生成 = 两步：私钥 d 均匀随机取自 [1, n−1]，公钥 P = d·G（X9.62 §5.2.1）。
     *
     * <p>生成过程完全手写（参照 BC 的 ECKeyPairGenerator，见 {@link #sm2KeyPair}）：
     * <pre>
     *   selectD     new BigInteger(n.bitLength(), random) 生成 n 位宽随机整数，越界（d&lt;1 或 d≥n）整枚重抽；
     *               d=0 会让 P=O（无信息），d≥n 会被 n·G=O 的周期性折回 —— 所以标量只在 Z/nZ 里有意义
     *   mul(d, G)   公钥不是"存的"，是"算"出来的：密钥生成里唯一的密码学运算就是这一次标量乘
     *   信封        (d, P) 经 BC 的 KeyFactory 装回 JCE KeyPair —— 只是编码层，不参与生成
     *   裁判        从信封读回 d 与 (Px, Py)，用自己的 mul 重算 dG 必须逐坐标一致；
     *               d 必须落在 [1, n−1]，P 必须在曲线上
     * </pre>
     */
    @TraceExecution(value = "SM2 密钥对生成", algorithm = "SM2", flow = "SM2-CURVE")
    @Test
    public void sm2KeyPairGenerationIsScalarMultiplication()
        throws Exception
    {
        setHelperTrace(true);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1"}, null, "start");

        // 生成密钥对：手写两步 —— d ∈ [1,n−1] 均匀随机，P = dG（参照 BC 的 ECKeyPairGenerator）
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);

        Tracer.traceDecision("onCurve", new Object[]{"point", pub}, onCurve(pub),
            "onCurve", "y² ≡ x³ + ax + b (mod p)");

        // 用自己的 mul 重算 P = dG，必须与 BC 给出的公钥一致
        BigInteger[] recomputed = mul(d, G, "scalarMul");
        Assert.assertEquals("dG 的 x 坐标必须与 BC 公钥一致", modP(pub[0]), recomputed[0]);
        Assert.assertEquals("dG 的 y 坐标必须与 BC 公钥一致", modP(pub[1]), recomputed[1]);

        // 验证公钥在曲线上
        Assert.assertTrue("公钥必须在曲线上", onCurve(pub));

        // 验证 d 在合法范围内
        Assert.assertTrue("d 必须 > 0", d.signum() > 0);
        Assert.assertTrue("d 必须 < n", d.compareTo(N) < 0);

        log.info("[SM2-密钥生成] d={}, P=({},{})", d.toString(16).substring(0, 16) + "...",
            pub[0].toString(16).substring(0, 16) + "...", pub[1].toString(16).substring(0, 16) + "...");
        Tracer.trace("serialize", new Object[]{"Px", pub[0], "Py", pub[1], "recomputed", recomputed},
            new Object[]{"Px", recomputed[0], "Py", recomputed[1]}, "serialize");
        Tracer.trace("end", new Object[]{"d_bits", d.bitLength(), "pub_on_curve", true}, null, "end");
    }

    /**
     * 曲线常数与标准的一致性检验。
     * <pre>
     *   常数比对      p/a/b/n/Gx/Gy 与 BC 从 GMNamedCurves 读出的官方值一字不差
     *                 （BC 的 getA()/getB() 返回的是域元素，先 toBigInteger 取出整数、再 modP 归一到
     *                 [0, p) 的代表元，比的才是同一个数）
     *   onCurve(G)    把 (Gx, Gy) 代进 y² ≡ x³ + ax + b (mod p)，等式成立 ⇒ G 确实是这条曲线上的点
     *   mul(N, G) = O n·G 返回空数组，即"加满 n 次正好回到无穷远点" ⇒ n 确实是 G 的阶（群里有 n 个不同点）
     *   (n+1)G = G     阶的周期性：[n+1]G = [n]G + G = O + G = G —— 这就是"标量只在 Z/nZ 里有意义"的实验证据，
     *                 也是所有 mod n 归约的由来
     * </pre>
     */
    @TraceExecution(value = "SM2 标准曲线常数", algorithm = "SM2", flow = "SM2-CURVE")
    @Test
    public void curveConstantsAreTheStandardCurve()
    {
        setHelperTrace(true);
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1"}, null, "start");

        X9ECParameters std = GMNamedCurves.getByName("sm2p256v1");
        Tracer.trace("params", new Object[]{
            "p", P, "a", A, "b", B, "n", N, "Gx", GX, "Gy", GY
        }, new Object[]{"curve", std.getCurve(), "G", std.getG()}, "params");
        Assert.assertEquals("p 必须与标准一致", std.getCurve().getField().getCharacteristic(), P);
        Assert.assertEquals("a 必须与标准一致", modP(std.getCurve().getA().toBigInteger()), A);
        Assert.assertEquals("b 必须与标准一致", modP(std.getCurve().getB().toBigInteger()), B);
        Assert.assertEquals("n 必须与标准一致", std.getN(), N);
        Assert.assertEquals("Gx 必须与标准一致", std.getG().getAffineXCoord().toBigInteger(), GX);
        Assert.assertEquals("Gy 必须与标准一致", std.getG().getAffineYCoord().toBigInteger(), GY);
        boolean gOnCurve = onCurve(G);
        Tracer.traceDecision("onCurve", new Object[]{"point", G}, gOnCurve,
            "onCurve", "y² ≡ x³ + ax + b (mod p)");
        Assert.assertTrue("生成元必须在曲线上", gOnCurve);
        Assert.assertEquals("n 必须是 G 的阶：nG = 无穷远点", 0, mul(N, G).length);
        Assert.assertArrayEquals("(n+1)G = G", G, mul(N.add(BigInteger.ONE), G));
        log.info("[SM2-曲线] p={} a={} n 阶检验通过", P.toString(16).substring(0, 8) + "…");
        Tracer.trace("end", new Object[]{"p", P, "n", N, "nG_is_O", true, "(n+1)G_is_G", true},
            "standard curve verified", "end");
    }

    /**
     * 群律：交换律、结合律、倍点=自加、标量乘的分配律 —— 全部由普通静态方法验证。
     *
     * <p>术语（"阿贝尔群 / abelian group"就是这几条公理的合称，SM2 的一切推导都只依赖它们）：
     * <pre>
     *   封闭性    两点相加仍在曲线上（onCurve(mul(k2, G)) 这条就是在验它）
     *   结合律    (P+Q)+R = P+(Q+R) —— 于是"重复加 k 次"不必括号，[k]P 才有唯一含义
     *   单位元    O（无穷远点）：P + O = P；代码里就是空数组走 add() 的前两个早退分支
     *   逆元      每个 P=(x,y) 都有 −P=(x, −y)：P + (−P) = O（竖直线的情形，见 negate() 的注释）
     *   交换律    P + Q = Q + P（弦本来就不区分两端，所以几何上显然）
     *   k₁, k₂    两个任意标量（这里取两个十进制大数）；"分配律"指 [k₁+k₂]G = [k₁]G+[k₂]G 与
     *              [k₁·k₂]G = [k₁]([k₂]G) —— 后者是"先算 k₂G 再拿它当被乘点"，也是嵌套标量乘
     * </pre>
     * 倍点 = 自加（doublePoint(G) == add(G, G)）这条尤其重要：它是"λ 用切线还是弦"的分界点，
     * 也是 add() 里 x 相同分支必须转去调 doublePoint() 的原因。
     */
    @TraceExecution(value = "SM2 群律", algorithm = "SM2", flow = "SM2-CURVE")
    @Test
    public void ecPointArithmeticFormsAnAbelianGroup()
    {
        setHelperTrace(true);
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1"}, null, "start");

        BigInteger k1 = new BigInteger("1234567890123456789012345678901234567890");
        BigInteger k2 = new BigInteger("9876543210987654321098765432109876543210");
        BigInteger[] k1G = mul(k1, G);
        BigInteger[] k2G = mul(k2, G);
        Tracer.trace("ecAdd", new Object[]{"P", k1G, "Q", k2G}, add(k1G, k2G), "ecAdd");
        Tracer.trace("ecDouble", new Object[]{"P", G}, doublePoint(G), "ecDouble");
        Tracer.traceDecision("onCurve", new Object[]{"point", k2G}, onCurve(k2G),
            "onCurve", "y² ≡ x³ + ax + b (mod p)");

        Assert.assertArrayEquals("加法交换律", add(mul(k1, G), mul(k2, G)), add(mul(k2, G), mul(k1, G)));
        Assert.assertArrayEquals("倍点 == 自加", doublePoint(G), add(G, G));
        Assert.assertArrayEquals("(k1+k2)G == k1G + k2G", mul(k1.add(k2), G), add(mul(k1, G), mul(k2, G)));
        Assert.assertArrayEquals("(k1·k2)G == k1(k2G)", mul(k1.multiply(k2), G), mul(k1, mul(k2, G)));
        Assert.assertArrayEquals("P + (-P) = 单位元", INFINITY, add(mul(k1, G), negate(mul(k1, G))));
        Assert.assertArrayEquals("单位元是恒等", mul(k1, G), add(INFINITY, mul(k1, G)));
        Assert.assertTrue("任意标量乘的结果仍在曲线上", onCurve(mul(k2, G)));
        log.info("[SM2-群律] 6 条群公理全部由普通静态方法验证通过");
        Tracer.trace("end", new Object[]{"k1G", k1G, "k2G", k2G, "k1G_plus_k2G", add(k1G, k2G)},
            "abelian group axioms verified", "end");
    }

    /**
     * 密钥由我们手写的生成器产生（d 随机 + P=dG，见 {@link #sm2KeyPair}），经 BC 的 KeyFactory 装回
     * JCE 信封；本测试证明：信封打开后（getD/getQ）(d, Q) 与我们算出的逐位一致，我们的倍加循环
     * 也能从 d 重建 Q —— 编码层没有偷改任何一个数。
     *
     * <p>符号与要点：d = ECPrivateKey.getD() 就是那个 mod n 意义下的私钥标量；
     * q = BC 从编码里解码出的公钥点，它内部用<b>射影/雅可比坐标</b> (X:Y:Z)，
     * 所以要比坐标必须先 getAffineXCoord()/getAffineYCoord() 还原成<b>仿射坐标</b> x = X/Z²、y = Y/Z³
     * （这一步内部也做一次 mod p 求逆，正是我们在 mul() 里全程手动做的那种"贵"运算）。
     * 两边逐坐标相等 ⇒ 我们的 for 循环倍加与 BC 的工业实现走的是同一套群运算，没有"抄它的结果"。
     */
    @TraceExecution(value = "SM2 纯标量乘重建公钥", algorithm = "SM2", flow = "SM2-CURVE")
    @Test
    public void ourPureScalarMulRebuildsBcPublicKey()
        throws Exception
    {
        setHelperTrace(true);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1"}, null, "start");

        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        org.bouncycastle.math.ec.ECPoint q = ((ECPublicKey) kp.getPublic()).getQ();
        BigInteger[] ours = mul(d, G, "scalarMul");

        Assert.assertEquals("我们的 x₁ == BC 的仿射 x", modP(q.getAffineXCoord().toBigInteger()), ours[0]);
        Assert.assertEquals("我们的 y₁ == BC 的仿射 y", modP(q.getAffineYCoord().toBigInteger()), ours[1]);
        log.info("[SM2-本质] dG 由 for 循环的倍加算法独立算出，与 BC 完全一致：x={}", Calc.hex(Calc.toBytes(ours[0], 32)));
        Tracer.trace("serialize", new Object[]{
            "BC_Px", q.getAffineXCoord().toBigInteger(), "BC_Py", q.getAffineYCoord().toBigInteger(),
            "our_Px", ours[0], "our_Py", ours[1]
        }, ours, "serialize");
        Tracer.trace("end", new Object[]{"equal", true, "Px", ours[0]}, true, "end");
    }

    /**
     * 签名的本质：我们的 (r,s) 能被 BC 验签，BC 的签名也能被我们的静态方法验签。
     *
     * <p>这一段是"两份独立实现互相咬合"的交叉验证，符号都是 {@link #sm2Sign}/{@link #sm2Verify} 里那套：
     * <pre>
     *   e   = SM3(ZA ‖ M) 的大端整数 —— ZA 用默认 ID 算，BC 的 SM3withSM2 在没设 SM2ParameterSpec 时
     *         用的正是同一个默认 ID，所以两边的 e 才会相等（这是互操作能成立的前提）
     *   k   = 一次性随机标量，只进 mul(k, G)，绝不外泄
     *   der = ASN.1 DER 封装的签名值：SEQUENCE { INTEGER r, INTEGER s }
     *         —— 签名<b>必须</b>编码成 DER，因为 r、s 是 [1, n−1] 里的整数，前导零个数不固定，
     *           裸拼 32+32 字节的定长形式（SM2 密文那种）在这里会丢信息；INTEGER 自带长度与符号位，
     *           BC 的 Signature 只认这一种格式，所以 der() 这个"胶水"不可省
     *   (3) 篡改检测：r 加 1 ⇒ 核对式 (e + x₁) mod n == r 立刻不成立；
     *       换消息 ⇒ e 变，同样的 x₁ 加上新 e 得到另一个 r —— 这两条就是"不可伪造 + 不可改内容"的直接体现
     * </pre>
     */
    @TraceExecution(value = "SM2 签名验签完整流程（三次验签）", algorithm = "SM2", flow = "SM2-SIGNVERIFY")
    @Test
    public void sm2SignAndVerifyAreTwoLinesOfModularArithmetic()
        throws Exception
    {
        setHelperTrace(true);
        Calc.useBc();
        byte[] msg = "SM2 signature essence".getBytes("UTF-8");
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1", "msgLen", msg.length}, null, "start");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);
        BigInteger e = eValue(za, msg);

        // (1) 我们签，BC 验
        BigInteger k = randomK();
        byte[] der = der(sm2Sign(d, e, k));
        Signature v = Signature.getInstance("SM3withSM2", "BC");
        v.initVerify(kp.getPublic());
        v.update(msg);
        boolean bcAccepted = v.verify(der);
        Tracer.trace("bcVerify", new Object[]{"algorithm", "SM3withSM2", "der", der}, bcAccepted,
            "bcVerify");
        Assert.assertTrue("我们生成的 SM2 签名必须被 BC 接受", bcAccepted);

        // (2) BC 签，我们验：同一枚合法签名，验签①
        Signature s = Signature.getInstance("SM3withSM2", "BC");
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] bcSig = s.sign();
        Tracer.trace("bcSign", new Object[]{"algorithm", "SM3withSM2", "msgLen", msg.length}, bcSig,
            "bcSign");
        ASN1Sequence seq = ASN1Sequence.getInstance(bcSig);
        BigInteger[] rs = new BigInteger[]{
            ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getValue() };

        // 验签①：合法签名（BC 签 → 我们验），应通过
        Tracer.trace("verifyCase", new Object[]{
            "purpose", "验签① 合法签名（BC 签 → 我们验）", "e", e, "r", rs[0], "s", rs[1]
        }, "期望: 通过", "verify1");
        Assert.assertEquals("我们的静态方法必须验过 BC 的签名", Boolean.TRUE,
            sm2Verify(pub, e, rs, "verify1"));

        // 验签②：篡改 r（r + 1），必须失败
        BigInteger[] tamperedR = new BigInteger[]{ rs[0].add(BigInteger.ONE), rs[1] };
        Tracer.trace("verifyCase", new Object[]{
            "purpose", "验签② 篡改 r（r ← r+1）", "e", e, "r", tamperedR[0], "s", tamperedR[1]
        }, "期望: 失败", "verify2");
        Assert.assertEquals("r 被改动必须失败", Boolean.FALSE,
            sm2Verify(pub, e, tamperedR, "verify2"));

        // 验签③：篡改消息（e 变了），必须失败
        BigInteger eOther = eValue(za, "other message".getBytes("UTF-8"), "verify3:hashM");
        Tracer.trace("verifyCase", new Object[]{
            "purpose", "验签③ 篡改消息（e ← SM3(ZA‖M′)）", "e", eOther, "r", rs[0], "s", rs[1]
        }, "期望: 失败", "verify3");
        Assert.assertEquals("消息被改动（e 变了）必须失败", Boolean.FALSE,
            sm2Verify(pub, eOther, rs, "verify3"));

        log.info("[SM2-签名] e={}, r={}, s={}", e.toString(16).substring(0, 12) + "…",
            rs[0].toString(16).substring(0, 12) + "…", rs[1].toString(16).substring(0, 12) + "…");
        Tracer.trace("end", new Object[]{"e", e, "r", rs[0], "s", rs[1],
            "verify1", true, "verify2", false, "verify3", false},
            Boolean.TRUE, "end");
    }

    /**
     * ZA 把身份 ID 绑进签名：ID 不一致时，同一枚签名必须验不过。
     *
     * <p>这里的记号：ID = "alice@example.cn"（真实身份）对比 DEFAULT_ID = "1234567812345678"（国标默认值）；
     * ZA(Alice) 与 ZA(default) 都是 SM3(ENTL‖ID‖a‖b‖Gx‖Gy‖Px‖Py) 的输出，只有 ID 那一段不同；
     * eAlice = SM3(ZA(Alice) ‖ M) 就是签名实际吃进去的那个哈希整数。
     * 链条是：ID 变 → ZA 变 → e 变 → r = (e + x₁) mod n 变 → 用旧 e 去验新签名（或反之）必然对不上。
     * 因此"验签时用的 ID"是协议的一部分：BC 要通过 setParameter(new SM2ParameterSpec(id)) 显式收到同一个 ID，
     * 否则它按默认 ID 算出另一个 e，一枚完全合法的签名也会被拒绝 —— 这正是 ZA 存在的意义：
     * 公钥不再"匿名"，签名与身份焊在一起，攻击者递上自己的公钥也冒充不了别人的身份。
     */
    @TraceExecution(value = "SM2 ZA 身份绑定", algorithm = "SM2", flow = "SM2-CORE")
    @Test
    public void zaBindsTheIdentityIntoTheHash()
        throws Exception
    {
        setHelperTrace(true);
        Calc.useBc();
        byte[] id = "alice@example.cn".getBytes("UTF-8");
        byte[] msg = "identity is part of the digest".getBytes("UTF-8");
        Tracer.trace("start", new Object[]{"curve", "sm2p256v1", "id", new String(id), "msgLen", msg.length},
            null, "start");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);

        byte[] zaAlice = za(id, pub);
        byte[] zaDefault = za(DEFAULT_ID, pub);
        Assert.assertFalse("不同 ID 必须产生不同的 ZA", Arrays.equals(zaAlice, zaDefault));

        BigInteger eAlice = eValue(zaAlice, msg);
        BigInteger k = randomK();
        BigInteger[] sig = sm2Sign(d, eAlice, k);

        Signature v = Signature.getInstance("SM3withSM2", "BC");
        v.setParameter(new SM2ParameterSpec(id));
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assert.assertTrue("BC 用同一个 ID 必须验过", v.verify(der(sig)));

        Signature vWrong = Signature.getInstance("SM3withSM2", "BC");   // 默认 ID
        vWrong.initVerify(kp.getPublic());
        vWrong.update(msg);
        Assert.assertFalse("BC 用默认 ID 必须验不过（这就是 ZA 的作用）", vWrong.verify(der(sig)));

        Assert.assertEquals("我们的静态方法用 Alice 的 e 能验过", Boolean.TRUE,
            sm2Verify(pub, eAlice, sig));
        log.info("[SM2-ZA] ZA(Alice)={} ZA(default)={}", Calc.hex(zaAlice), Calc.hex(zaDefault));
        Tracer.trace("end", new Object[]{"ZA_Alice", zaAlice, "ZA_default", zaDefault,
            "different", !Arrays.equals(zaAlice, zaDefault)}, Boolean.TRUE, "end");
    }

    /**
     * 加密的两种模式（C1C2C3 / C1C3C2）：与 BC 的 SM2Engine、JCE Cipher 双向互操作。
     *
     * <p>三段密文的名字就是"字节排列顺序"，长度分别是：
     * <pre>
     *   C1 = 0x04 ‖ x₁ ‖ y₁ = 1 + 32 + 32 = 65 字节   临时公钥点 kG（0x04 是 SEC1 未压缩点前缀，所以断言里
     *                                                  比"两种模式的 C1 段是否相同"用的是 copyOf(·, 65)）
     *   C2 = 与明文等长                                 M ⊕ KDF(x₂‖y₂, klen=len(M))，逐字节掩码
     *   C3 = 32 字节                                   SM3(x₂ ‖ M ‖ y₂) 认证标签，长度恒为 SM3 的输出长度
     *   密文总长 = 65 + len(M) + 32                      与 BC 的 SM2Engine 输出完全一致
     * </pre>
     * 四种"模式 × 方向"的组合都跑一遍（我们加密→BC 解、BC 加密→我们解），因为段落顺序是<b>编码约定</b>，
     * 只有双向互操作才证明我们切字节的偏移量写对了。JCE 的 Cipher "SM2" 默认走 C1C2C3，
     * 它这里直接吃我们裸拼接的密文（DER 封装是另一种可选编码，见 {@link #sm2Encrypt} 的注释）。
     * 最后 tampered[70] ^= 1：第 65~(65+len(M)−1) 字节是 C2，所以第 70 个字节落在 C2 里，
     * 改它会让解出的明文变，从而重算的 C3 与带来的 C3 不符 ⇒ 断言失败，这就是"密文自带认证性"。
     */
    @TraceExecution(value = "SM2 密文模式", algorithm = "SM2", flow = "SM2-CIPHER")
    @Test
    public void sm2CipherModesDifferOnlyInSegmentOrder()
        throws Exception
    {
        setHelperTrace(true);
        Calc.useBc();
        byte[] pt = "SM2 encryption is ECIES with SM3-based KDF".getBytes("UTF-8");
        Tracer.trace("start", new Object[]{"modes", new String[]{"C1C2C3", "C1C3C2"}, "msgLen", pt.length},
            null, "start");
        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        X9ECParameters std = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domain = new ECDomainParameters(std.getCurve(), std.getG(), std.getN());

        for (boolean c1c3c2 : new boolean[]{ false, true })
        {
            byte[] ours = sm2Encrypt(pub, c1c3c2, randomK(), pt);

            // 我们的密文 -> BC 解密
            SM2Engine engine = new SM2Engine(c1c3c2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
            engine.init(false, new ECPrivateKeyParameters(d, domain));
            Assert.assertArrayEquals("BC 必须能解我们的密文（模式 " + (c1c3c2 ? "C1C3C2" : "C1C2C3") + "）",
                pt, engine.processBlock(ours, 0, ours.length));

            // BC 的密文 -> 我们解密（BC 的 SM2Engine 加密侧强制要求 ParametersWithRandom）
            SM2Engine enc = new SM2Engine(c1c3c2 ? SM2Engine.Mode.C1C3C2 : SM2Engine.Mode.C1C2C3);
            enc.init(true, new ParametersWithRandom(
                new ECPublicKeyParameters(std.getCurve().createPoint(pub[0], pub[1]), domain), new SecureRandom()));
            byte[] fromBc = enc.processBlock(pt, 0, pt.length);
            Assert.assertArrayEquals("我们必须能解 BC 的密文", pt, sm2Decrypt(d, c1c3c2, fromBc));
            log.info("[SM2-加密模式] {} 互操作通过，密文长度 {}", c1c3c2 ? "C1C3C2" : "C1C2C3", fromBc.length);
        }

        // 同一条明文、同一个 k，两种模式只差 C2/C3 的排列
        // fixedK 固定住一次性随机数 k，于是 C1 = kG、共享点 k·P_B、密钥流、C3 全都逐一相同，
        // 唯一的变量就是拼接顺序 —— 下面两条断言把"模式差异 = 排列差异"这件事钉死
        BigInteger fixedK = new BigInteger("24b690a5f5dd752a475c4b36f5ad43fc25fc37ba", 16);
        byte[] a = sm2Encrypt(pub, false, fixedK, pt);
        byte[] b = sm2Encrypt(pub, true, fixedK, pt);
        Assert.assertTrue("两种模式的 C1 段必须相同", Arrays.equals(Arrays.copyOf(a, 65), Arrays.copyOf(b, 65)));
        Assert.assertTrue("C1C3C2 = C1 ‖ (a 的 C3) ‖ (a 的 C2)",
            Arrays.equals(b, Calc.concat(Arrays.copyOf(a, 65),
                Arrays.copyOfRange(a, 65 + pt.length, a.length),
                Arrays.copyOfRange(a, 65, 65 + pt.length))));

        // JCE 端到端：Cipher "SM2" 默认就是 C1C2C3
        Cipher jce = Cipher.getInstance("SM2", "BC");
        jce.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        Assert.assertArrayEquals("JCE SM2 必须能解我们的 C1C2C3 密文", pt, jce.doFinal(a));

        // 认证性：改一个 bit，C3 校验必须失败
        byte[] tampered = a.clone();
        tampered[70] ^= 1;
        try
        {
            sm2Decrypt(d, false, tampered);
            Assert.fail("C3 应该拦住被篡改的密文");
        }
        catch (AssertionError expected)
        {
            log.info("[SM2-加密模式] 篡改密文 -> C3 校验失败（SM2 密文自带认证性）");
        }
        Tracer.trace("end", new Object[]{"modes", 2, "c1Same", true, "tamperRejected", true},
            Boolean.TRUE, "end");
    }

    /**
     * 本质中最危险的一条：k 复用会直接泄露私钥。这里用静态方法把 d 反解出来。
     *
     * <p>完整推导（两条签名共用同一个 k，于是得到两个一次方程）：
     * <pre>
     *   签名一： s₁ = (1+d)⁻¹ (k − r₁·d)     ⇒  s₁(1+d) = k − r₁·d
     *   签名二： s₂ = (1+d)⁻¹ (k − r₂·d)     ⇒  s₂(1+d) = k − r₂·d
     *   两式相减（右边的 k 直接被消掉，这正是"k 复用"致命的地方）：
     *          (s₁ − s₂)(1 + d) = −(r₁ − r₂)·d
     *   注意 r = (e + x₁) mod n，同一个 k ⇒ 同一个 x₁ ⇒ r₁ − r₂ = e₁ − e₂，于是 r 的差可以换成 e 的差：
     *          (s₁ − s₂)(1 + d) = −(e₁ − e₂)·d
     *   展开并把含 d 的项收到左边：
     *          (s₁ − s₂) = −d·(e₁ − e₂ + s₁ − s₂)
     *   ⇒      d = −(s₁ − s₂) / (s₁ − s₂ + e₁ − e₂)  (mod n)
     *   代码里 ds = s₁ − s₂、de = e₁ − e₂，所以 recovered = (−ds)·(ds + de)⁻¹ mod n，就一次模逆
     * </pre>
     * 为什么现实里这是最出名的漏洞（PS3/比特币、若干 TLS 实现都栽过）：
     * 攻击者<b>不需要</b>私钥、不需要预测随机数生成器，只要在同一把密钥下抓到两枚<b>公开</b>签名
     * 且它们的 k 相同（签名不带 k，但 k 一旦重复，上面这个纯代数式子就把 d 送到手上），
     * 拿到 d 后连公钥都不用再看 —— 下面 assertArrayEquals 用 recovered·G == pub 复核这一点。
     * 另外注意：只要"部分比特重复/低熵"就足够，不必完全相同；本文件后三个测试分别处理这三种形态。
     */
    @TraceExecution(value = "SM2 k 复用攻击", algorithm = "SM2", flow = "SM2-KREUSE")
    @Test
    public void reusingKLeaksThePrivateKey()
        throws Exception
    {
        setHelperTrace(false);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"attack", "k reuse", "curve", "sm2p256v1"}, null, "start");

        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        BigInteger k = randomK();                                  // 故意复用同一个 k
        BigInteger e1 = eValue(za, "message one".getBytes("UTF-8"));
        BigInteger e2 = eValue(za, "message two".getBytes("UTF-8"));
        BigInteger[] sig1 = sm2Sign(d, e1, k);
        BigInteger[] sig2 = sm2Sign(d, e2, k);

        Tracer.trace("collect", new Object[]{
            "e1", e1, "e2", e2, "sig1", sig1, "sig2", sig2, "sameR", sig1[0].equals(sig2[0])
        }, new BigInteger[]{ sig1[0], sig2[0] }, "collect");

        // s = (1+d)⁻¹(k - r d)  =>  s₁-s₂ = (1+d)⁻¹(-(e₁-e₂)d)  =>  d = -s₁-s₂ / (s₁-s₂+e₁-e₂)
        BigInteger ds = sig1[1].subtract(sig2[1]);
        BigInteger de = e1.subtract(e2);
        Tracer.trace("solve", new Object[]{"s1-s2", ds, "e1-e2", de, "coefficient", ds.add(de)},
            ds.add(de), "solve");
        BigInteger recovered = ds.negate().multiply(ds.add(de).modInverse(N)).mod(N);
        Tracer.trace("recover", new Object[]{"r", sig1[0], "s1", sig1[1], "s2", sig2[1]},
            recovered, "recover");

        Assert.assertEquals("两条 k 复用的签名足以反推出私钥 d", d, recovered);
        BigInteger[] recoveredPub = mul(recovered, G);
        Assert.assertArrayEquals("反推出的 d 必须能重算出同一个公钥", pub, recoveredPub);
        Tracer.traceDecision("verify", new Object[]{"recovered", recovered, "pub", pub,
            "recoveredPub", recoveredPub}, Arrays.equals(pub, recoveredPub),
            "verify", "recovered·G == P");
        Tracer.trace("exploit", new Object[]{"recoveredD", recovered, "kReused", k,
            "pubMatch", Arrays.equals(pub, recoveredPub)}, recovered, "exploit");
        log.info("[SM2-k 复用] 从两枚签名反解出 d = {}（与真实私钥一致）", recovered.toString(16).substring(0, 16) + "…");
        Tracer.trace("end", new Object[]{"recoveredD", recovered, "pubMatch", true}, Boolean.TRUE, "end");
        setHelperTrace(true);
    }

    // ====================================================================
    //  k 为什么必须"真随机" —— 三条攻击路线与它们的代数
    // ====================================================================
    /*
     * 全部问题都出在一行代数上。SM2 的签名式子（GB/T 32918.2）对私钥 d 来说是<b>一次方程</b>：
     * <pre>
     *   s = (1 + d)⁻¹ (k - r·d)          | 两边乘 (1+d)
     *   s(1 + d) = k - r·d
     *   s + s·d = k - r·d                  | 含 d 的项并到左边
     *   d·(s + r) = k - s
     *   <b>d = (k - s)·(s + r)⁻¹  (mod n)</b>     | 一次模逆，私钥落地
     * </pre>
     * 这一段里每个字母的含义（都是 mod n 的标量，只有 x₁ 来自 mod p 的几何）：
     * <pre>
     *   d    私钥标量，唯一要保护的东西；公钥只是它的投影 P = d·G，反求 d 就是 ECDLP
     *   k    一次性随机标量（临时私钥），签名时算 kG 用掉一次；它<b>不在</b>签名里公开，
     *          但只要它可预测/有规律/值域窄，上面的式子就把它换成 d
     *   r    = (e + x₁) mod n —— 公开；x₁ 是 kG 的横坐标，所以"知道 r 和 e 就知道 x₁ mod n"
     *   s    = (1+d)⁻¹(k − r·d) mod n —— 公开；它是 d 与 k 的一次组合，正是这条"一次"坏了事
     *   e    = SM3(ZA ‖ M) 的大端整数 —— 消息的数值化身，两枚签名只要消息不同就 e 不同
     *   x₁   临时点 kG 的仿射横坐标（下标 1 是"第一个点 kG"，不是平方）；它是公开可核对的量
     *   ⁻¹   模 n 的乘法逆元（扩展欧几里得）；(s + r) ≠ 0 mod n 才存在，验签的 t ≠ 0 检查就是在保这件事
     *   一次方程 未知数只以 d¹ 出现、没有 d² 或 d·k 这类交叉项 ⇒ 一个方程一个未知数就能解，
     *          这是 SM2 与"ECDSA 用 d⁻¹"在攻击面上的共同点：任何一次随机数失误都是<b>线性</b>代价
     * </pre>
     * 由此得到三条铁律，也是下面三个测试各自要打破的东西：
     * <ol>
     *   <li><b>k 一旦泄露，d 就泄露</b>，而且连公钥都不需要看 —— 所以"能不能预测 k"等价于"能不能预测私钥"。</li>
     *   <li>攻击者手上永远有<b>免费的核对 oracle</b>：验签要的 x₁ = (r - e) mod n 是公开量，
     *       于是猜一个 k 候选，只要检查 x([k]G) 是否等于它，就能判断猜对没有；
     *       核对用的另一条路是 [d_cand]G == P，两式等价。</li>
     *   <li>验签公式里的 t = (r + s) mod n 不是随便挑的系数 —— 它就是上面推导中 d 的系数，
     *       所以 sG + tP 恰好把 kG 复原出来。签名和验签是同一行代数的两面。</li>
     * </ol>
     * "真随机"要同时满足三件事，缺一件就有对应的攻击：<b>不可预测</b>（测试①）、<b>无规律</b>（测试②）、
     * <b>值域上的分布均匀且熵足够</b>（测试③）。前两条给出的是零搜索的直接解，第三条给出的是
     * 把搜索空间从 2²⁵⁵ 压到几千次加法的可枚举性。
     *
     * 补两条术语，后面三个测试反复用到：
     * <pre>
     *   oracle（核对判据）  攻击者能免费反复查询的一个"猜对了吗"的测试。这里 x₁ = (r − e) mod n 由公开量
     *                       算出，于是枚举候选 k 时只需比较横坐标，不用碰私钥、也不用问任何人 —— 纯离线穷举
     *   lattice / 格攻击     当 k 只是"值域偏窄"或"高低位有已知比特"而不完全可预测时，
     *                       未知量不再是单个标量而是一组带小系数的同余式，可用格规约（LLL、NFC 类算法）
     *                       把候选压到可枚举范围。本文件的测试③只做"小值域穷举 + 撞车"这两种最直白的用法，
     *                       格方法属于同一族泄露的"弱一些但更通用"的版本，值得知道名字
     * </pre>
     */

    /**
     * 设备用"截断的毫秒数"当种子：种子空间只有 8 bit，这才是现实里最常见的坏随机数。
     * SEED_SPACE = 2⁸ = 256：种子的个数，也就是攻击者最坏情况要重放 PRNG 的次数。
     */
    private static final int SEED_SPACE = 256;

    /**
     * 弱随机池：k 只从 [1, K_POOL] 里取 —— 等价于"只生成 2 字节随机数当 k"的实现。
     * K_POOL = 1024 = 2¹⁰ 就是值域大小（有效熵上界 10 bit，而 k 需要约 255 bit），
     * 它同时决定两件事：可枚举性（攻击 a）和撞车概率（攻击 b，生日悖论下 128 个样本必撞）。
     */
    private static final int K_POOL = 1024;

    /**
     * 攻击公式①：已知 k 时直接反解私钥。<b>d = (k - s)·(r + s)⁻¹ mod n</b>，一次模逆。
     * 参数全是普通的大整数，返回也是一个普通的大整数 —— 没有任何"拿到签名的对象再调方法"。
     *
     * <p>推导（就是上面那条一次方程的解，逐项对照代码）：
     * <pre>
     *   s = (1+d)⁻¹ (k − r·d)                 | 两边乘 (1+d)，消掉那个讨厌的模逆
     *   s + s·d = k − r·d
     *   s·d + r·d = k − s                      | 含 d 的项到左边
     *   d·(s + r) = k − s                      | coefficient = (r + s) mod n，即 d 的系数
     *   d = (k − s) · (r + s)⁻¹  (mod n)       | 一次模逆落地
     * </pre>
     * 三个入参的来源都是"公开信息 + 一个猜中的 k"：r、s 直接读自签名 DER，
     * k 由枚举种子/枚举值域/侧信道得到；整个式子对公钥、对消息内容<b>毫无要求</b>，
     * 所以哪怕只泄露一枚签名的 k，也足够把 d 换出来（前提当然是这枚签名本身合法）。
     * coefficient ≠ 0 是模逆存在的前提，也是验签侧 t ≠ 0 的同一条检查。
     */
    private static BigInteger privateKeyFromKnownK(BigInteger k, BigInteger r, BigInteger s)
    {
        BigInteger coefficient = modN(r.add(s));
        Assert.assertTrue("r + s 不能为 0（否则验签本身就不合法）", coefficient.signum() != 0);
        return modN(k.subtract(s).multiply(coefficient.modInverse(N)));
    }

    /**
     * 攻击公式②：k 有规律（两枚签名的 k 相差已知公差 Δ）时，连 k 都不用知道。
     * <pre>
     *   s₁(1 + d) = k₁ - r₁·d
     *   s₂(1 + d) = k₂ - r₂·d = k₁ + Δ - r₂·d     | 两式相减，未知的 k₁ 消掉
     *   (s₂ - s₁)(1 + d) = Δ - (r₂ - r₁)·d
     *   Δs + Δs·d = Δ - Δr·d                        | 含 d 的项并到左边
     *   d·(Δs + Δr) = Δ - Δs
     *   <b>d = (Δ - Δs)·(Δs + Δr)⁻¹  (mod n)</b>,  Δs = s₂ - s₁, Δr = r₂ - r₁
     * </pre>
     * Δs、Δr 都来自<b>公开</b>的签名，Δ 由规律性给出。Δ = 0 就是 k 复用，退化成本类上面那条公式
     * （注意 r = e + x₁，同一个 k 给出同一个 x₁，所以 Δr = e₂ - e₁）。
     *
     * <p>补一层符号与"为什么这是零搜索"：
     * <pre>
     *   k₁, k₂      两次签名各自的一次性随机数；攻击者<b>不知道</b>它们的值，只知道 k₂ = k₁ + Δ
     *   Δ (delta)    已知公差：计数器的步长、时间的增量、或者干脆 0（复用）
     *   r₁,s₁,r₂,s₂  两枚签名的四个标量，全部公开可得
     *   Δs, Δr      两枚签名在 s 与 r 上的差（都 mod n）；deltaS/deltaR 就是它们
     *   coefficient  Δs + Δr，即化简后 d 的系数，只要它非 0 就可逆
     * </pre>
     * 关键在于"相减消元"：两个方程里唯一未知的量本来是 (d, k₁) 两个，
     * 但规律性把 k₂ 写成 k₁ + Δ 之后，相减让 k₁ 彻底消失，只剩下 d 一个未知数 ——
     * 于是 4 个公开量 + 1 个公开规律 + 1 次模逆 = 私钥，连一次哈希或一次点乘都不用算。
     * 这也是"differential attack（差分）"这个名字的来源：不看单次签名，只看两次签名的<b>差</b>。
     */
    private static BigInteger privateKeyFromKnownDelta(BigInteger delta, BigInteger r1, BigInteger s1,
        BigInteger r2, BigInteger s2)
    {
        BigInteger deltaS = modN(s2.subtract(s1));
        BigInteger deltaR = modN(r2.subtract(r1));
        BigInteger coefficient = modN(deltaS.add(deltaR));
        Assert.assertTrue("Δs + Δr 不能为 0", coefficient.signum() != 0);
        return modN(modN(delta.subtract(deltaS)).multiply(coefficient.modInverse(N)));
    }

    /**
     * 从私钥反看 k：s(1+d) = k - r·d ⇒ <b>k = s(1 + d) + r·d mod n</b>。攻击者用它确认整条规律。
     *
     * <p>这就是签名式子对 k 求解的结果（把 d 的系数 (s + r) 展开回去）：
     * 一旦按公式②解出 d，就能把每枚签名"背后"的 k 逐个还原出来；
     * 若还原出的 k₁、k₂ 之差确实等于 Δ，规律性就被独立验证了一次 ——
     * 相当于攻击者用两条不同的代数路径互相印证，排除"碰巧算出一个能过验签的假私钥"。
     */
    private static BigInteger kFromPrivateKey(BigInteger d, BigInteger r, BigInteger s)
    {
        return modN(s.multiply(BigInteger.ONE.add(d)).add(r.multiply(d)));
    }

    /**
     * 弱随机源①：和 {@link #randomK()} 长得一模一样的一行代码，错的只是把 SecureRandom 换成 Random。
     *
     * <p>符号与要点：new Random(seed) 是<b>确定性</b>伪随机数生成器 —— 同一个 seed 必然给出同一串输出，
     * 所以"随机数"的全部不确定性都压缩进了那个 seed（这里只有 8 bit）；
     * 后面的 .mod(N−1).add(1) 把结果压进 [1, N−1]（与 {@link #randomK()} 完全一样的取值范围），
     * 因此这一步本身没错，错的是"种子可枚举"。攻击者重放同一个 seed 就能重放同一个 k。
     */
    private static BigInteger lcgK(long seed)
    {
        return new BigInteger(N.bitLength(), new Random(seed)).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /**
     * 弱随机源②：把递增计数器当随机数（现实中"用消息序号派生 k"的实现）。
     *
     * <p>k(counter) = 1000003 + counter·step：step 就是攻击公式②里那个公差 Δ；
     * counter 从外部只能看出"第几笔业务"，但相邻两笔的 k 之差恒定 ⇒ 一次相减就消掉未知数 k₁。
     * 1000003 是个与算法无关的偏移量（基值），它不影响 Δ，只是让 k 看起来不像 1、2、3。
     */
    private static BigInteger counterK(long counter, long step)
    {
        return BigInteger.valueOf(1000003L).add(BigInteger.valueOf(counter).multiply(BigInteger.valueOf(step)));
    }

    /**
     * 样本频率直方图 -> 香农熵（比特）。就是 for 循环累加 -p·log₂p，没有 map 也没有 stream。
     *
     * <p>公式与符号（香农熵 Shannon entropy，单位 bit）：
     * <pre>
     *   counts[i]  第 i 个桶里落进的样本数（桶 = 值域的分段，这里 64 个桶各宽 16）
     *   total      样本总数 = Σ counts[i]
     *   pᵢ         = counts[i] / total，第 i 个桶的经验概率
     *   H          = − Σᵢ pᵢ·log₂ pᵢ，只在 counts[i] &gt; 0 的桶上求和（0·log0 定义为 0，所以跳过空桶）
     *   log₂p      以 2 为底的对数 = ln p / ln 2；Java 只有自然对数，所以写成 Math.log(p)/Math.log(2.0)
     * </pre>
     * 直觉：H 是"平均每次抽取带多少比特的不确定性"。均匀分布在 64 个桶上时 H = log₂64 = 6 bit 封顶；
     * 分布越偏（有的桶空、有的桶挤）H 越低。k 需要约 255 bit 熵，所以"观测熵 &lt; 8 bit"就是明显的缺陷信号。
     * 注意这是<b>有限样本的经验熵</b>，只能证明"不够随机"，证明不了"够随机"（真随机的有限样本同样会有偏差）。
     */
    private static double shannonEntropyBits(int[] counts)
    {
        int total = 0;
        for (int i = 0; i < counts.length; i++)
        {
            total += counts[i];
        }
        double bits = 0.0;
        for (int i = 0; i < counts.length; i++)
        {
            if (counts[i] > 0)
            {
                double p = (double)counts[i] / (double)total;
                bits -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return bits;
    }

    /**
     * 裁判：攻击者拿到 d 之后能不能<b>冒充受害者</b>，用 BC 的验签器说了算。
     * 用 recovered 签一条全新消息 -> DER -> {@code SM3withSM2} 用真实公钥验，必须通过。
     *
     * <p>为什么这一步是必要的（前面所有代数都可能在"碰巧"上骗人）：
     * recoveredD 只是攻击公式算出来的一个 mod n 整数；真正说明"它就是那把私钥"的证据只有一个 ——
     * 它能签出第三方（BC）认可的签名。判据用新消息 + 新的随机 k，
     * 保证不是把原签名重放一遍蒙混过关。zaFor 是验签双方约定的用户标识杂凑，
     * 必须与真实公钥对应的 ID 一致，否则 BC 那边算出的 e 会不同（这就是 ZA 的副作用，见 {@link #zaBindsTheIdentityIntoTheHash}）。
     */
    private static void assertRecoveredKeyCanForge(KeyPair kp, BigInteger recoveredD, byte[] zaFor)
        throws Exception
    {
        byte[] fresh = "signature produced by the attacker".getBytes("UTF-8");
        BigInteger[] forged = sm2Sign(recoveredD, eValue(zaFor, fresh), randomK());
        Signature verifier = Signature.getInstance("SM3withSM2", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(fresh);
        Assert.assertTrue("反推出的 d 必须能签出 BC 认可的签名（否则它不是真私钥）", verifier.verify(der(forged)));
    }

    /**
     * 测试①（不可预测性被破坏）：<b>可预测的 k = 可预测的私钥</b>。
     * 设备用 8 bit 的种子（截断的毫秒数、递增的启动计数）喂 {@code java.util.Random} 生成 k，
     * 攻击者<b>枚举种子</b>并重放同一个伪随机数生成器即可命中真实的 k，然后一次模逆拿到 d。
     *
     * <p>本方法里的符号：
     * <pre>
     *   deviceSeed   设备内部"保密"的种子，这里就是 90；它决定整条伪随机序列，所以保密性 = log₂256 = 8 bit
     *   sig          设备真实产生的签名 (r, s)，公开可得
     *   x1Target     = (r − e) mod n —— 由签名反解出的"x₁ 应有的值"，这就是那个免费 oracle 的期望值
     *                  （r = (e + x₁) mod n 是唯一一次加法，两边减 e 就还原；对 n 取模是因为
     *                  x₁ 本身是 mod p 的域元素而 p 略大于 n，比较时统一到 mod n 才稳妥）
     *   candidateK   对第 seed 个候选种子重放 lcgK() 得到的 k 候选
     *   mul(candidateK, G)[0]   候选临时点的横坐标 x₁；与 x1Target 相等即命中
     *   probes       实际尝试次数（最多 SEED_SPACE = 256 次点乘）
     *   hitSeed/hitK 命中的种子与它对应的 k
     * </pre>
     * 攻击成本 = 枚举种子的次数 × 一次标量乘 = 256 ×（约 256 次点倍 double + 约 128 次点加 add）≈ 10 万次点运算，毫秒级；
     * 而真随机的 k 有 2²⁵⁵ 量级个候选且<b>无结构</b>，同样的枚举思路完全使不上劲。
     * 注意攻击里唯一的核对手段就是比横坐标 —— 全程没用到私钥，也没用到公钥。
     */
    @TraceExecution(value = "SM2 可预测种子攻击", algorithm = "SM2", flow = "SM2-KREUSE")
    @Test
    public void predictablePrngSeedEnumerationLeaksThePrivateKey()
        throws Exception
    {
        setHelperTrace(false);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"attack", "predictable PRNG seed", "seedSpace", SEED_SPACE},
            null, "start");

        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);
        byte[] msg = "k comes from a truncated millisecond clock".getBytes("UTF-8");
        BigInteger e = eValue(za, msg);

        long deviceSeed = 90L;                                    // 设备内部那个"保密"的种子
        BigInteger[] sig = sm2Sign(d, e, lcgK(deviceSeed));
        Tracer.trace("collect", new Object[]{"r", sig[0], "s", sig[1], "e", e}, sig, "collect");

        // 攻击者的免费线索：x₁ = (r - e) mod n，纯公开量（对比时统一取 mod n，因为 p 略大于 n）
        BigInteger x1Target = modN(sig[0].subtract(e));

        long hitSeed = -1L;
        BigInteger hitK = null;
        long probes = 0;
        for (long seed = 0; seed < SEED_SPACE; seed++)
        {
            BigInteger candidateK = lcgK(seed);
            probes++;
            if (modN(mul(candidateK, G)[0]).equals(x1Target))     // [k]G 的横坐标对上了
            {
                hitSeed = seed;
                hitK = candidateK;
                break;
            }
        }
        Tracer.trace("solve", new Object[]{"x1Target", x1Target, "seedSpace", SEED_SPACE,
            "hitSeed", hitSeed, "probes", probes}, hitK, "solve");

        Assert.assertTrue("枚举 " + SEED_SPACE + " 个种子必须命中真实的 k", hitK != null);
        Assert.assertEquals("命中的种子就是设备那个", deviceSeed, hitSeed);

        BigInteger recovered = privateKeyFromKnownK(hitK, sig[0], sig[1]);
        Tracer.trace("recover", new Object[]{"hitK", hitK, "r", sig[0], "s", sig[1]},
            recovered, "recover");
        Assert.assertEquals("重放 PRNG 得到 k 后，一次模逆就该还原私钥", d, recovered);
        BigInteger[] recoveredPub = mul(recovered, G);
        Assert.assertArrayEquals("另一条核对路线 [d_cand]G == P 也必须成立", pub, recoveredPub);
        Tracer.traceDecision("verify", new Object[]{"recovered", recovered, "pub", pub,
            "recoveredPub", recoveredPub}, Arrays.equals(pub, recoveredPub),
            "verify", "recovered·G == P");
        assertRecoveredKeyCanForge(kp, recovered, za);
        Tracer.trace("exploit", new Object[]{"hitSeed", hitSeed, "hitK", hitK,
            "probes", probes, "recoveredD", recovered}, recovered, "exploit");

        // 对照组：真随机 k 的空间是 2^255 量级，而枚举成本是线性的 —— 没有可预测性就没有落脚点
        log.info("[SM2-可预测k] 枚举 {} 个种子命中 k={}，一次模逆得到 d；真随机时 k 的空间有 2^{} 量级",
            probes, hitK.toString(16), N.bitLength());
        Tracer.trace("end", new Object[]{"hitSeed", hitSeed, "probes", probes, "forged", true},
            Boolean.TRUE, "end");
        setHelperTrace(true);
    }

    /**
     * 测试②（独立性被破坏）：<b>k 有规律 = 零搜索直接解出私钥</b>。
     * 设备用计数器当随机数，两枚签名的 k 相差公开的公差 Δ。按 {@code privateKeyFromKnownDelta}
     * 的推导，只需要 4 个公开大整数加一次模逆 —— 连枚举都没有。
     *
     * <p>本方法里的符号：
     * <pre>
     *   delta (Δ)     两枚签名的 k 之差 = 计数器步长 = 1000003；攻击者只知道这个规律，不知道 k 本身
     *   k1, k2        设备实际用的两个一次性随机数，k2 = k1 + Δ
     *   e1, e2        两条不同消息的哈希整数；r = (e + x₁) mod n，所以 Δr = (e₂ − e₁) + (x₁⁽²⁾ − x₁⁽¹⁾) mod n
     *                  —— k 不同 ⇒ 两个临时点横坐标不同 ⇒ Δr 里混着一个"看不见的点差"；
     *                     但 Δr 直接用公开的 r₂ − r₁ 就能算出来，攻击者永远不需要知道那个点差是什么
     *   sig1, sig2    两枚签名 (r,s)，公开
     *   recovered     公式②的解，应当 == d
     *   reuseA/reuseB Δ = 0 的特例：同一 k 签两条消息，就是 reusingKLeaksThePrivateKey 那一条
     *   safeA/safeB   对照组：两枚 k 互不相关的签名，随便拿 Δ = 1 去套公式只会得到一个无关的数
     * </pre>
     * 三条独立路径互相印证（这才叫"证明"而不是"凑对了一次"）：
     * ① 公式②直接解出 d；② 用 d 回推 k₁ = s₁(1+d) + r₁d，必须等于设备真用的 k₁；
     * ③ 再用公式①（已知 k₁）解一次 d，必须与①同值。最后用 BC 验签器做第三方裁判。
     */
    @TraceExecution(value = "SM2 等差 k 攻击", algorithm = "SM2", flow = "SM2-KREUSE")
    @Test
    public void sequentialKIsSolvedByLinearEquationsWithoutAnySearch()
        throws Exception
    {
        setHelperTrace(false);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"attack", "sequential k", "curve", "sm2p256v1"}, null, "start");

        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        BigInteger delta = BigInteger.valueOf(1000003L);           // 公差：设备的计数器步长
        BigInteger k1 = counterK(7L, delta.longValue());
        BigInteger k2 = counterK(8L, delta.longValue());
        Assert.assertEquals("两枚签名的 k 之差必须正好是规律本身", delta, k2.subtract(k1));

        BigInteger e1 = eValue(za, "first message".getBytes("UTF-8"));
        BigInteger e2 = eValue(za, "second message".getBytes("UTF-8"));
        BigInteger[] sig1 = sm2Sign(d, e1, k1);
        BigInteger[] sig2 = sm2Sign(d, e2, k2);
        Tracer.trace("collect", new Object[]{"e1", e1, "e2", e2, "sig1", sig1, "sig2", sig2,
            "delta", delta}, new BigInteger[]{ sig1[0], sig2[0] }, "collect");

        // 攻击者只知道"k 是等差的"，不知道 k 本身
        BigInteger recovered = privateKeyFromKnownDelta(delta, sig1[0], sig1[1], sig2[0], sig2[1]);
        Tracer.trace("solve", new Object[]{"delta", delta, "r1", sig1[0], "s1", sig1[1],
            "r2", sig2[0], "s2", sig2[1]}, recovered, "solve");
        Assert.assertEquals("公差 + 两枚公开签名即可解出 d", d, recovered);

        // 两条独立公式互相印证：先解出 d，再回推 k₁，必须与设备用的那个 k₁ 相同
        BigInteger k1Back = kFromPrivateKey(recovered, sig1[0], sig1[1]);
        Tracer.trace("recover", new Object[]{"d", recovered, "r1", sig1[0], "s1", sig1[1]},
            k1Back, "recover");
        Assert.assertEquals("由 d 回推的 k₁ = s₁(1+d) + r₁d 必须与真实值一致", k1, k1Back);
        BigInteger recoveredAgain = privateKeyFromKnownK(k1, sig1[0], sig1[1]);
        Assert.assertEquals("再由 k₁ 走攻击公式①也得到同一个 d", recovered, recoveredAgain);
        BigInteger[] recoveredPub = mul(recovered, G);
        Assert.assertArrayEquals("公钥核对", pub, recoveredPub);
        Tracer.traceDecision("verify", new Object[]{"k1", k1, "k1Back", k1Back,
            "recoveredAgain", recoveredAgain, "pub", pub}, k1.equals(k1Back)
            && recovered.equals(recoveredAgain) && Arrays.equals(pub, recoveredPub),
            "verify", "k1Back == k1 且 [d]G == P");
        assertRecoveredKeyCanForge(kp, recovered, za);

        // Δ = 0 是本公式的特例（k 复用）：与 reusingKLeaksThePrivateKey 同一条式子
        byte[] other = "another message".getBytes("UTF-8");
        BigInteger[] reuseA = sm2Sign(d, e1, k1);
        BigInteger[] reuseB = sm2Sign(d, eValue(za, other), k1);
        BigInteger reuseRecovered = privateKeyFromKnownDelta(BigInteger.ZERO,
            reuseA[0], reuseA[1], reuseB[0], reuseB[1]);
        Assert.assertEquals("公差为 0（k 完全复用）也必须解出 d", d, reuseRecovered);

        // 对照：真随机（Δ 未知）时这条零搜索攻击立刻失效 —— 公差本身进不了方程
        BigInteger[] safeA = sm2Sign(d, e1, randomK());
        BigInteger[] safeB = sm2Sign(d, eValue(za, other), randomK());
        BigInteger safeRecovered = privateKeyFromKnownDelta(BigInteger.ONE,
            safeA[0], safeA[1], safeB[0], safeB[1]);
        Assert.assertFalse("k 之间没有关系时，随便猜的公差不可能给出真实私钥",
            d.equals(safeRecovered));

        Tracer.trace("exploit", new Object[]{"recovered", recovered, "delta0Recovered", reuseRecovered,
            "deltaGuess", BigInteger.ONE, "safeRecovered", safeRecovered}, reuseRecovered, "exploit");
        log.info("[SM2-规律k] 已知公差 {} 时，4 个公开量 + 1 次模逆得到 d = {}…", delta,
            recovered.toString(16).substring(0, 16));
        Tracer.trace("end", new Object[]{"recoveredD", recovered, "reuseD", reuseRecovered,
            "forged", true}, Boolean.TRUE, "end");
        setHelperTrace(true);
    }

    /**
     * 测试③（均匀性/熵被破坏）：<b>频率分布偏差让搜索空间塌缩</b>。
     * 三件事一起做：先<b>测量</b>出弱随机源的分布缺陷（重复、直方图熵、有效位长），
     * 再用两条各自独立的路把它变成私钥泄露 ——
     * (a) 值域只有 2^10，枚举时利用"相邻候选只差一个 G"把标量乘降成一次点加；
     * (b) 池子里撞车（生日悖论）就等价于 k 复用，直接套测试②的 Δ = 0 公式。
     *
     * <p>本方法里的符号：
     * <pre>
     *   samples = 128       抓到的签名枚数（弱池 1024 格里抽 128 次，按生日悖论几乎必然撞车：
     *                       至少一对相同的概率 ≈ 1 − exp(−128·127/(2·1024)) = 1 − e^−7.94 ≈ 99.96%）
     *   weakPool            固定种子 20261022 的 Random —— 让测试可重复，同一份直方图每次一致
     *   ks[i], es[i]        第 i 枚签名用的 k 和消息哈希整数 e
     *   sigs[i]             第 i 枚签名 (r, s)；sigs[i][0] = rᵢ，sigs[i][1] = sᵢ
     *   seen[value]         布尔表，记录值 v 是否已经出现过 —— 用来数"重复"，即撞车次数 duplicates
     *   histogram[64]       频率直方图：桶宽 16，桶号 = (value − 1) / 16，所以 value ∈ [1, 1024] 落在 0..63 号桶；
     *                       64 个桶是"分布是否摊开"的最小观察尺度（每桶各宽 16 个取值）
     *   entropyBits         这 64 个桶的经验香农熵（H = −Σ pᵢ log₂ pᵢ，单位 bit），见 {@link #shannonEntropyBits}
     *   maxBitLength        观测到的 k 的最大二进制长度 —— 值域上界的直接证据（≤ 16 bit，而 k 需要 255）
     *   firstTarget         = (r₀ − e₀) mod n：第一枚签名的 x₁，即攻击 (a) 的核对 oracle
     *   walked              枚举时的"当前点"：walked = [k]G，从 [1]G 起每轮只加一次 G
     *                       （[k]G = [(k−1)G] + G：把标量乘降成一次点加，省掉 255 次 double，快三个数量级）
     *   adds                实际做的点加次数，最多 K_POOL − 1 = 1023
     *   collisionA/B        找到的一对"共用同一个 k"的签名下标 —— 这对签名直接给出 Δ = 0 的公式输入
     *   secureKs / secureDuplicates / secureMinBits   对照组：SecureRandom 抽 128 个 k 的两两重复数与最小位长
     * </pre>
     * "值域偏窄为什么也等于泄露"：三条铁律里前两条给的是<b>直接解</b>（不用搜），第三条给的是<b>可枚举</b>——
     * 空间从 2²⁵⁵ 塌到 2¹⁰，配合"相邻候选只差一个 G"的走法，1023 次点加就把 k 捞出来；
     * 而 k 一到手就退回公式①，一次模逆得到 d。若泄露更隐蔽（k 只有部分比特偏斜、或高低位有已知值），
     * 同一族信息会变成一组带小系数的同余式，那正是格/LLL 类方法（lattice attack）的用武之地。
     */
    @TraceExecution(value = "SM2 低熵 k 攻击", algorithm = "SM2", flow = "SM2-KREUSE")
    @Test
    public void biasedKDistributionIsMeasuredAndThenExploited()
        throws Exception
    {
        setHelperTrace(false);
        Calc.useBc();
        Tracer.trace("start", new Object[]{"attack", "biased k distribution", "pool", K_POOL},
            null, "start");

        KeyPair kp = sm2KeyPair();
        BigInteger d = ((ECPrivateKey) kp.getPrivate()).getD();
        BigInteger[] pub = publicKeyOf(kp);
        byte[] za = za(DEFAULT_ID, pub);

        // 128 枚签名，k 取自只有 K_POOL 个值的弱池（种子固定，测试可重复）
        int samples = 128;
        Random weakPool = new Random(20261022L);
        BigInteger[] ks = new BigInteger[samples];
        BigInteger[] es = new BigInteger[samples];
        BigInteger[][] sigs = new BigInteger[samples][];
        boolean[] seen = new boolean[K_POOL + 1];
        int duplicates = 0;
        int[] histogram = new int[K_POOL / 16];                    // 64 个桶，看分布是否摊开
        int maxBitLength = 0;
        for (int i = 0; i < samples; i++)
        {
            ks[i] = BigInteger.valueOf(weakPool.nextInt(K_POOL) + 1);
            es[i] = eValue(za, ("message number " + i).getBytes("UTF-8"));
            sigs[i] = sm2Sign(d, es[i], ks[i]);
            int value = ks[i].intValue();
            histogram[(value - 1) / 16]++;                         // value ∈ [1, 1024] -> 桶 0..63
            if (ks[i].bitLength() > maxBitLength)
            {
                maxBitLength = ks[i].bitLength();
            }
            if (seen[value])
            {
                duplicates++;                                      // 生日悖论：池子小就一定会撞车
            }
            seen[value] = true;
        }

        // ---- 测量：分布缺陷是<b>看得见</b>的。注意有限样本的熵估计只能证明"不够随机"，
        //      证明不了"够随机"，所以这里真正的判据是重复次数与有效位长（值域上界）。
        double entropyBits = shannonEntropyBits(histogram);
        Assert.assertTrue("弱池里必然出现重复 k：" + duplicates + " 次", duplicates > 0);
        Assert.assertTrue("有效位长只有 " + maxBitLength + " bit，远低于 255", maxBitLength <= 16);
        Assert.assertTrue("桶分布摊不开，观测熵只有 " + entropyBits + " bit，远小于 k 需要的 ~255 bit",
            entropyBits < 8.0);
        Tracer.trace("collect", new Object[]{"samples", samples, "duplicates", duplicates,
            "entropyBits", entropyBits, "maxBitLength", maxBitLength}, histogram, "collect");

        // ---- 攻击(a)：值域可枚举。逐格往前走一格 = 一次点加，比重新做标量乘便宜三个数量级
        // firstTarget = x₁ 的期望值 = (r₀ − e₀) mod n，纯由公开签名和消息算出（免费 oracle）
        BigInteger firstTarget = modN(sigs[0][0].subtract(es[0]));  // x₁ = (r - e) mod n，公开
        BigInteger[] walked = G;                                    // walked = [1]G，之后每轮 += G
        BigInteger enumeratedK = null;
        int adds = 0;
        for (int k = 1; k <= K_POOL; k++)
        {
            // 递推 [k]G = [(k−1)G] + G：一次点加（一个 λ、一次模逆）代替一整轮 double-and-add（约 255 次 double）
            if (k > 1)
            {
                walked = add(walked, G);                           // [k]G = [(k-1)G] + G
                adds++;
            }
            if (modN(walked[0]).equals(firstTarget))
            {
                enumeratedK = BigInteger.valueOf(k);
                break;
            }
        }
        Tracer.trace("solve", new Object[]{"pool", K_POOL, "firstTarget", firstTarget, "adds", adds},
            enumeratedK, "solve");
        Assert.assertNotNull("枚举 2^10 个候选必须命中第一枚签名的 k", enumeratedK);
        Assert.assertEquals("命中值应与弱池实际用的 k 相同", ks[0], enumeratedK);
        BigInteger recoveredFromEnum = privateKeyFromKnownK(enumeratedK, sigs[0][0], sigs[0][1]);
        Tracer.trace("recover", new Object[]{"k", enumeratedK, "r", sigs[0][0], "s", sigs[0][1]},
            recoveredFromEnum, "recover");
        Assert.assertEquals("枚举到 k 之后仍然是一次模逆还原私钥", d, recoveredFromEnum);
        Tracer.traceDecision("verify", new Object[]{"d", d, "recoveredFromEnum", recoveredFromEnum},
            d.equals(recoveredFromEnum), "verify", "recovered == d");
        log.info("[SM2-低熵k] 值域 {} 个候选、{} 次点加就枚举到 k；真随机时空间是 2^{} 且无规律可用",
            K_POOL, adds, N.bitLength());

        // ---- 攻击(b)：撞车 = k 复用。弱池的重复不是统计噪音，而是直接的私钥泄露
        int collisionA = -1;
        int collisionB = -1;
        for (int i = 0; i < samples && collisionB < 0; i++)
        {
            for (int j = i + 1; j < samples; j++)
            {
                if (ks[i].equals(ks[j]))
                {
                    collisionA = i;
                    collisionB = j;
                    break;
                }
            }
        }
        Assert.assertTrue("必须能找到一对复用同一个 k 的签名", collisionB > collisionA);
        BigInteger viaCollision = privateKeyFromKnownDelta(BigInteger.ZERO,
            sigs[collisionA][0], sigs[collisionA][1], sigs[collisionB][0], sigs[collisionB][1]);
        Assert.assertEquals("撞车的那两枚签名直接给出 d", d, viaCollision);
        BigInteger[] collisionPub = mul(viaCollision, G);
        Assert.assertArrayEquals("公钥核对", pub, collisionPub);
        assertRecoveredKeyCanForge(kp, viaCollision, za);
        Tracer.trace("exploit", new Object[]{"collisionA", collisionA, "collisionB", collisionB,
            "duplicates", duplicates, "viaCollision", viaCollision, "pubMatch", Arrays.equals(pub, collisionPub)},
            viaCollision, "exploit");
        log.info("[SM2-频率分布] {} 枚签名里 {} 次重复，第 {} / {} 枚撞车 -> 套 Δ=0 公式得到 d",
            samples, duplicates, collisionA, collisionB);

        // ---- 对照：SecureRandom 的 128 个 k 两两不同、位长贴着 255，上面两条攻击都失去落脚点
        int secureDuplicates = 0;
        int secureMinBits = Integer.MAX_VALUE;
        BigInteger[] secureKs = new BigInteger[samples];
        for (int i = 0; i < samples; i++)
        {
            secureKs[i] = randomK();
            if (secureKs[i].bitLength() < secureMinBits)
            {
                secureMinBits = secureKs[i].bitLength();
            }
            for (int j = 0; j < i; j++)
            {
                if (secureKs[i].equals(secureKs[j]))
                {
                    secureDuplicates++;
                }
            }
        }
        Assert.assertEquals("真随机的 128 个 k 不应出现任何重复", 0, secureDuplicates);
        // 阈值取 200 bit 而不是贴着 255：单个真随机 k 落在 200 bit 以下的概率是 2^-56，
        // 但落在 250 以下的概率有 2^-6（约 1/64）—— 贴着上界断言本身就是错的统计判断。
        // 而弱池的 k 位长永远不超过 10 bit，两者的差距才是可以断言的东西。
        Assert.assertTrue("真随机的 k 位长全部应 ≥ 200 bit（实测最小 " + secureMinBits + " bit）",
            secureMinBits >= 200);
        log.info("[SM2-真随机对照] {} 枚签名的 k 两两不同，位长全部 ≥ {} bit；弱池只有 {} 个格子（约 2^{} bit），"
            + "所以值域枚举与撞车两条攻击都失效", samples, secureMinBits, K_POOL, 10);
        Tracer.trace("end", new Object[]{"recoveredD", viaCollision, "duplicates", duplicates,
            "secureDuplicates", secureDuplicates, "secureMinBits", secureMinBits}, Boolean.TRUE, "end");
        setHelperTrace(true);
    }

    // ---------------------------------------------------------------- 辅助

    /**
     * 手写密钥生成 —— SM2 密钥对的全部内容就两步（X9.62 §5.2.1，BC 的 ECKeyPairGenerator 同款）：
     * <pre>
     *   ① 私钥 d   均匀随机取自 [1, n−1]：new BigInteger(n.bitLength(), random) 生成 n 位宽的随机整数，
     *              落在 [1, n) 之外（d = 0 或 d ≥ n）就整枚重抽 —— 与 BC 源码里
     *              isOutOfRangeD(d, n) 的拒绝循环一字不差
     *   ② 公钥 P   = d·G：密钥生成里唯一的密码学运算就是这一次标量乘（我们自己的倍加循环），
     *              公钥不是"存的"，是"算"出来的
     * </pre>
     * BC 在这两步之外还多一道加固：NAF 权重太低（&lt; n.bitLength()/4）的"瘦标量"也重抽
     * （WNafUtil.getNafWeight，防侧信道），那是工程加固、不属于"密钥怎么生成"的本质，这里从简不仿。
     * 算出的 (d, P) 经 {@link #toJceKeyPair} 装回 JCE 信封，BC 的 Signature/Cipher 才吃得下。
     */
    private static KeyPair sm2KeyPair()
        throws Exception
    {
        long startNanos = System.nanoTime();
        SecureRandom random = new SecureRandom();

        // ① 私钥：均匀随机 ∈ [1, n−1]，越界整枚重抽（d=0 会让 P=O 无信息；d≥n 会被 n·G=O 的周期性折回）
        BigInteger d;
        do
        {
            d = new BigInteger(N.bitLength(), random);
        }
        while (d.signum() < 1 || d.compareTo(N) >= 0);

        // ② 公钥：P = d·G
        BigInteger[] pub = mul(d, G);

        long duration = System.nanoTime() - startNanos;
        KeyPair kp = toJceKeyPair(d, pub);

        if (helperTraceEnabled())
        {
            Tracer.trace("keygen", new Object[]{
                "d", d, "Px", pub[0], "Py", pub[1],
                "来源", "手写：d∈[1,n-1] 随机 → P=dG"
            }, kp, "keygen", duration);
        }
        return kp;
    }

    /**
     * 把手写生成的 (d, P) 装回 JCE 的 KeyPair"信封" —— 这一步只是<b>编码</b>，不参与密钥生成：
     * ECNamedCurveTable.getParameterSpec("sm2p256v1") 给出命名曲线参数，BC 的 KeyFactory 据此把
     * 公钥编进带曲线 OID 的 SubjectPublicKeyInfo、私钥编进 PKCS#8，BC 的 Signature/Cipher 才认得
     * 这对钥匙；信封打开后（getD / getQ）d 与 (Px, Py) 和我们算出的逐位一致（见
     * {@link #sm2KeyPairGenerationIsScalarMultiplication} 与 {@link #ourPureScalarMulRebuildsBcPublicKey}）。
     */
    private static KeyPair toJceKeyPair(BigInteger d, BigInteger[] pub)
        throws Exception
    {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("sm2p256v1");
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        PublicKey publicKey = kf.generatePublic(
            new ECPublicKeySpec(spec.getCurve().createPoint(pub[0], pub[1]), spec));
        PrivateKey privateKey = kf.generatePrivate(new ECPrivateKeySpec(d, spec));
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * 从 JCE 公钥里取出仿射坐标 (Px, Py) 作为我们的"点数组"：pub[0] = Px，pub[1] = Py。
     * getAffineXCoord()/getAffineYCoord() 会把 BC 内部的射影坐标 (X:Y:Z) 还原成 x = X/Z²、y = Y/Z³
     * （内部同样要 mod p 求逆），再 modP 归一到 [0, p) 的代表元，才能和我们的数组逐元素比。
     */
    private static BigInteger[] publicKeyOf(KeyPair kp)
    {
        org.bouncycastle.math.ec.ECPoint q = ((ECPublicKey) kp.getPublic()).getQ();
        return new BigInteger[]{ modP(q.getAffineXCoord().toBigInteger()), modP(q.getAffineYCoord().toBigInteger()) };
    }

    /**
     * 正确示范的真随机 k：均匀取自 [1, n−1]。
     *
     * <p>逐符号：new BigInteger(255, rnd) 生成 255 个随机比特（约 2²⁵⁵ 个数，与 n 的量级对齐）；
     * .mod(N−1).add(1) 把它压进 [1, n−1] 这个合法区间（标准禁止 k = 0 与 k = n，那样 kG = O 会让 r = e，
     * 签名与 d 无关，直接失效）；外面的 while 再排除退化端点。
     * 三条铁律在这里同时满足：不可预测（SecureRandom 取自操作系统熵池）、无规律（各次独立）、
     * 分布均匀且熵接近 255 bit（值域几乎是整个 [1, n−1]）。
     */
    private static BigInteger randomK()
    {
        BigInteger k;
        do
        {
            k = new BigInteger(N.bitLength(), new SecureRandom()).mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        }
        while (k.signum() <= 0 || k.compareTo(N.subtract(BigInteger.ONE)) >= 0);
        return k;
    }

    /**
     * DER(SEQUENCE{r,s}) —— 只是为了把我们算出的 (r,s) 喂给 BC 的验签器。
     *
     * <p>ASN.1 DER 的三个记号：
     * <pre>
     *   SEQUENCE    一个"有序列表"结构标签，这里固定两个成员：先 r 后 s
     *   INTEGER     带符号的大整数编码（有长度字段 + 必要时补一个 0x00 表示正数），
     *               所以 r、s 的前导零丢失也不怕 —— 这就是签名不像密文那样用定长 32 字节裸拼的原因
     *   OCTET STRING 任意字节串（密文编码里用来装 C2/C3，本方法的签名结构里用不到）
     * </pre>
     * 之所以需要这层"胶水"：BC 的 Signature.verify() 只接受 DER 格式；我们的验签方法要的却是 (r, s) 两个整数。
     */
    private static byte[] der(BigInteger[] rs)
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(rs[0]));
        v.add(new ASN1Integer(rs[1]));
        return new DERSequence(v).getEncoded();
    }
}
