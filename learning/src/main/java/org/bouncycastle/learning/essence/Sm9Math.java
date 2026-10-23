package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.List;

/**
 * SM9（GB/T 32915，基于标识的密码算法）的本质计算 —— 面向过程的数学引擎。
 *
 * <p>SM9 的全部难点只有一个：<b>双线性配对 e(P, Q) = Fp12 里的一个元素</b>。这里没有任何
 * "域对象""曲线对象""配对器"，每个元素都是一个普通数组，每个运算都是一个普通静态方法：
 * <pre>
 *   Fp   = 一个 BigInteger（0 <= x < p）
 *   Fp2  = BigInteger[2]  a₀ + a₁u,   u² = −2      （Fp[u]/(u²+2)）
 *   Fp4  = BigInteger[4]  b₀ + b₁v,   v² = u       （Fp2[v]/(v²−u)）
 *   Fp12 = BigInteger[12] c₀ + c₁w + c₂w², w³ = v  （Fp4[w]/(w³−v)）
 *   下标规则：i = u位 + 2·v位 + 4·w位，于是 Fp12 的第 k 组 Fp4 就是 a[4k..4k+3]
 * </pre>
 * 曲线两层：G₁ = E(Fp): y² = x³ + 5（仿射点就是 {@code BigInteger[2]}，无穷远点是空数组），
 * G₂ = E'(Fp2): y² = x³ + 5u（射影点 {@code BigInteger[3][2]} = {X, Y, Z}）。
 * 配对是 GB/T 32915 推荐的 ate 配对：主线循环按 6u+2 的带符号三进制（NAF）逐位扫描，
 * 每步"先平方、再乘切线、按位乘线"，最后加上 π₁(Q) 与 −π₂(Q) 两条线，再做最终幂
 * {@code f^((p¹²−1)/n)}（拆成易算部分 p⁶−1、p²+1 与难算部分）。
 *
 * <p><b>符号表（一）—— 域与曲线里每个字母代表什么</b>
 * <pre>
 *   p, n     p 是素域的模数（256 位素数，{@link #P}）；n 是 G₁、G₂ 的公共阶（另一个 256 位
 *            素数，{@link #N}）。凡是"标量"（ks、ke、r、h、l、hid 折出来的 h1）都在
 *            Z_n = {0,1,…,n−1} 里算；凡是"坐标"都在 Fp 或它的扩域里算。两套模数不能混。
 *   Fp       素域 {0,1,…,p−1}：加减乘完就 mod p；除法不存在，写成乘逆元 a·b⁻¹。
 *   u, v, w  三层扩域各自引入的"形式根"：u²=−2、v²=u、w³=v。它们不是数，是<b>基</b> ——
 *            一个 Fp12 元素 = 这 12 个基的线性组合，组合系数（Fp 里的数）才是数据。
 *   a₀,a₁    Fp2 元素 a = a₀ + a₁u 的两个 Fp 系数（下标 = u 的次数）。
 *   b₀,b₁    Fp4 元素 b = b₀ + b₁v 的两个 Fp2 系数。
 *   c₀,c₁,c₂ Fp12 元素 c = c₀ + c₁w + c₂w² 的三个 Fp4 系数。
 *   i        扁平数组下标规则：i = (u 的次数) + 2·(v 的次数) + 4·(w 的次数)；
 *            于是"第 k 组 Fp4"正好是 a[4k..4k+3]，取半区就是 fp4Half(a, 0/1)。
 *   E, E'    E: y² = x³ + 5 在 Fp 上（G₁ 住在里面）；E': y² = x³ + 5u 在 Fp2 上（G₂ 住在里面）。
 *            E' 是 E 的六次扭曲 (sextic twist)：两条方程只差常数项 5 变成 5u。
 *   (x,y)    仿射坐标 (affine coordinates)：点就是真坐标，但每次加法都要一次模逆（很慢）。
 *   {X,Y,Z}  射影坐标 (projective coordinates)：代表仿射点 (X/Z², Y/Z³)。用它是为了在
 *            Miller 循环里<b>完全不做模逆</b>；Z = (1,0)（Fp2 里的 1）时就等于仿射点。
 *   O        无穷远点 = 群的单位元（加法群的"0"）：G₁ 里表示成空数组，G₂ 里表示成 Z 在
 *            Fp2 中为零。任何点加 O 还是它自己；x 相同而 y 互为相反数的两点相加就是 O。
 * </pre>
 *
 * <p><b>符号表（二）—— 配对 (pairing) 里的字母</b>
 * <pre>
 *   e(P,Q)   双线性配对：G₁ × G₂ → GT。{@code pairing(qTwist, pAffine)} 的入参顺序固定是
 *            "G₂ 在前、G₁ 在后"，因为 e 不对称（两个参数来自不同的群）。
 *   双线性   e(a·P, b·Q) = e(P,Q)^{a·b}：SM9 每一条正确性证明都只靠这一行 ——
 *            签名/验签、加密/解密的"两边算出同一个 w"全部由它推出。
 *   GT       Fp12* 中唯一的 n 阶子群，配对像住的地方。元素就是 384 字节（12 个 Fp 系数），
 *            乘法用 fp12Mul、幂用 fp12Pow；它的阶是 n，所以对任何 a∈GT 有 a^n = 1。
 *   阶       (order) 元素 a 的阶 = 使 a^k = 1 的最小正整数 k；群的阶 = 元素个数。
 *   ate      本文件用的配对型号（ate pairing）：先沿一条"扫描位串"的循环攒出一个 Fp12
 *            中间值，再做一次最终幂。换成 tate 配对流程不同，但双线性性质一样。
 *   Miller   攒中间值的那条 for 循环（{@link #pairing}），逐位扫描 {@link #ABITS}。
 *   ABITS    |6u+2| 的带符号三进制 (signed ternary，NAF 的近亲)：'0' = 只倍点，
 *            '1' = 倍点后加 Q，'2' = 倍点后减 Q。这里的 u 是 BN 曲线的<b>参数</b>
 *            （曲线常数由它算出），和符号表（一）里那个"形式根 u"不是同一个东西。
 *   T        Miller 循环里的累计点：起点是 Q，每步变成 2T 或 2T±Q，它同时决定下一步的
 *            切线/割线是哪条。
 *   f        Miller 循环积累的 Fp12 值（"还没做完的配对"），循环结束交给最终幂。
 *   l_{A,B}  过 G₂ 上两点 A、B 的直线，代入 G₁ 点 P 的坐标后得到的 Fp12 元素。它是<b>稀疏</b>
 *            的：L = lw₀ + lw₁·w² + lw₂·w³，而 w³ = v，所以 12 个系数里只有 6 个非零
 *            （见 {@link #fp12FromLine} 的下标 0,1 / 2,3 / 8,9）。
 *   lw₀..lw₂ 线函数的三个 Fp2 系数，内部用 {@code BigInteger[3][2]} 传递；lw₁ 已经乘过 P 的
 *            x 坐标、lw₂ 已经乘过 P 的 y 坐标（"把 P 代进直线方程"就发生在这里）。
 *   π₁, π₂   Frobenius 映射（x ↦ x^p）作用在 G₂ 点上的两个组合，Miller 收尾要用它们各画
 *            一条线：l_{T,π₁Q} 与 l_{T,−π₂Q}。
 *   x^{p^k}  Fp12 上的 Frobenius（fp12Frobenius/2/3/6）：指数的 p 次幂在塔基下只是
 *            "共轭 + 乘几个常数"，所以<b>不用真做幂运算</b>，这是最终幂便宜的原因。
 *   β, α₁..α₅ Frobenius 在塔基下的 6 个 Fp 常数，GB/T 32915.1 附录直接把数给出来。
 *            α₃ = β 不是抄错：α³ = β 是它们本来的关系。
 *   最终幂    f^((p¹²−1)/n)：把 Fp12* 的元素"压"进唯一的 n 阶子群 GT（同余类的代表元）。
 *            指数拆两半 —— 易算部分 (p⁶−1)(p²+1) 只要一次逆 + 两次 Frobenius；
 *            难算部分 (p⁴−p²+1)/n 无法用 Frobenius 表示，只能用 a₂、a₃、9 次幂组成的加法链。
 *   a₂, a₃   难算部分里的两个小指数（{@link #FINAL_A2}、{@link #FINAL_A3}），标准给值。
 * </pre>
 *
 * <p><b>符号表（三）—— 协议层的字母（谁是谁的密钥）</b>
 * <pre>
 *   ID       用户标识字节串（邮箱、工号一类）。IBC 的全部意义就在这：ID 参与构成公钥，
 *            所以<b>没有证书、没有 CRL</b> —— 见 {@link #kemQ}，标识被直接乘进公钥点里。
 *   KGC      密钥生成中心 (Key Generation Center)：全网唯一持有主私钥的角色，负责"私钥提取"。
 *   hid      用途分隔符字节：0x01 签名、0x02 密钥交换、0x03 加密。同一个 ID 在三个 hid 下
 *            折出三个不同的 h1，于是导出三把互不相干的用户私钥 —— 拿签名私钥去解密密文
 *            这种跨用途攻击就从根上堵掉。
 *   ks       签名主私钥 ∈ Z_n（只有 KGC 知道）；Ppubs = ks·P2 ∈ G₂ 是签名主公钥（全网公开）。
 *   ke       加密主私钥 ∈ Z_n；Ppube = ke·P1 ∈ G₁ 是加密主公钥（全网公开）。
 *   h1       H1(ID, hid) ∈ [1, n−1]：把任意长度字符串折成标量。实现 = 双次 SM3 拼成 40 字节，
 *            再 z mod (n−1) + 1（见 {@link #modnFromHash}，+1 是为了永不取 0）。
 *   ds       签名用户私钥 = ks·(ks + h1)⁻¹ · P1 ∈ G₁。分母含 ks，所以只有 KGC 能算。
 *   de       解密/交换用户私钥 = ke·(ke + h1)⁻¹ · P2 ∈ G₂。
 *   ⁻¹ mod n 模逆：a⁻¹ 是满足 a·a⁻¹ ≡ 1 (mod n) 的唯一数，扩展欧几里得求得；a = 0 不存在。
 *   ≡        同余：a ≡ b (mod m) 意思是 m 整除 (a−b)。
 *   ‖        字节串<b>拼接</b>（concatenate），不是异或；⊕ 才是按位异或。
 *   M        明文消息字节数组；len = 明文长度，klen = 要派生的字节数。
 *   r        一次性随机标量（"临时私钥"）：签名、加密、密钥交换各自采一个，<b>绝不能复用</b>
 *            —— 和 SM2 的 k 一样，复用即泄密。
 *   g        g = e(P1, Ppubs) ∈ GT：签名流程里反复当幂的基准元素（一个值走天下）。
 *   w        w = g^r ∈ GT。签名侧它是喂给 H2 的 384 字节；加密侧它是 e(Ppube,P2)^r = e(C1,de)。
 *   h        h = H2(M‖w) 折出来的标量，即"消息哈希"；签名值的前 32 字节就是它。
 *   l        l = (r − h) mod n：签名里把 r 与 h 缝起来的标量。
 *   S        S = l·ds ∈ G₁：签名的点部分。签名值 = h(32 字节) ‖ S(65 字节，0x04 打头)。
 *   P'       P' = h1·P2 + Ppubs ∈ G₂：验签基准点，作用是把"只有 ID"补成一把可用的公钥。
 *   u        u = e(S, P') ∈ GT：验签里等于 g^l（推导见 {@link #verify}）。t = g^h，w = u·t。
 *   C1,C2,C3 密文三段：C1 = r·Q ∈ G₁（65 字节，"给收信人的临时公钥"）、
 *            C2 = M ⊕ K[0:len]（与明文等长，纯异或）、C3 = HMAC-SM3(K[len:len+32], C2)
 *            （32 字节完整性标签）。存储顺序 C1‖C3‖C2，与国标一致。
 *   K        KDF 出来的密钥流，长度 = 明文长度 + 32：前段当掩码，后段当 HMAC 密钥。
 *   Q        Q = h1(ID,0x03)·P1 + Ppube ∈ G₁：收信人的"标识公钥点"，C1 = r·Q。
 *   RA,RB    密钥交换双方的临时点 = r·(用<b>对方</b> ID 算的 Q)，各 64 字节（去掉 0x04 前缀）。
 *   g1,g2,g3 交换里的三个 GT 元素（各 384 字节）；sk = KDF(ID_A‖ID_B‖RA‖RB‖g1‖g2‖g3)。
 * </pre>
 *
 * <p><b>术语表（本文件出现的名词，一句话解释）</b>
 * <pre>
 *   基于标识的密码 (Identity-Based Cryptography, IBC)
 *            公钥 = "ID + 主公钥"算出来的点，私钥 = KGC 用主私钥推导出来的点。
 *            省掉证书体系，代价是 KGC 理论上能算出任何人的私钥（key escrow，密钥托管）。
 *   私钥提取 (private key extraction)
 *            {@link #signPrivateKeyExtract}/{@link #privateKeyExtract} 那一步：主私钥 + ID → 用户私钥。
 *   嵌入次数 (embedding degree)
 *            把配对像放进 Fp^k 所需的最小 k；SM9 的 BN 曲线 k = 12，所以要搭到 Fp12。
 *   KAT (known-answer test，已知答案测试)
 *            标准/参考实现给定的输入-输出对；本仓库用的是 GmSSL sm9test.c 里的国标样例。
 *   大端 (big-endian)
 *            高位字节在前。所有坐标序列化、哈希计数器、字节拼接都按这个约定，写反就全错。
 *   KDF / HMAC
 *            KDF = 用 SM3 计数器把一串输入拉伸成任意长度字节流；
 *            HMAC = 用哈希构造的带密钥认证码（ipad 0x36 / opad 0x5c，分组 64 字节）。
 *   错误预言 (error oracle)
 *            攻击者靠"这次解密成功/失败"的信号反复试探。所以解密失败必须<b>只说一种话</b>，
 *            C1 不在曲线上也要立刻拒绝（{@link #kemDecryptWithUserKey} 的 B1 步）。
 *   密钥确认 (key confirmation)
 *            交换完再各发一个用 sk 派生的标签（前缀 0x83/0x82），证明"我真的拿到了同一个密钥"。
 * </pre>
 *
 * <p>算术一律用 {@link BigInteger} 明文模 p，不做 Montgomery 变换 —— 慢一点，但每一步都能
 * 直接和纸上的公式对照；这也让"常数是否抄对"这类错误一眼可见（有测试专门核对）。
 *
 * <p>本类在 src/main，除了被 {@code essence} 包里的测试逐公式核对，还是
 * {@code learning.sm9.SM9Provider} 那个 JCE Provider 的内核：Provider 只做参数校验与
 * ASN.1 包装，公式全部在这里，所以同一条公式只有一份实现。带 {@code ks}/{@code ke} 入参的
 * 方法是"KGC 视角"（照 GmSSL 的高层 API），带 {@code WithUserKey}/{@code ToIdentity} 的是
 * "用户视角"（签名方只拿 ds、加密方只拿公开的 Ppube），后者的推导过程写在各自注释里。
 */
public final class Sm9Math
{
    private Sm9Math()
    {
    }

    // ---------------------------------------------------------------- 域与曲线常数（GB/T 32915.5 的 256-bit 参数）

    /** p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d。 */
    public static final BigInteger P = new BigInteger("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d", 16);

    /** n = b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25（G₁、G₂ 的公共阶）。 */
    public static final BigInteger N = new BigInteger("b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25", 16);

    /** G₁ 的生成元 P1 = (x, y) ∈ E(Fp)，E: y² = x³ + 5。 */
    public static final BigInteger[] P1 = new BigInteger[]{
        new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
        new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16) };

    /**
     * G₂ 的生成元 P2 ∈ E'(Fp2)，直接写成引擎内部用的射影三元组 {X, Y, Z}：
     * 每个分量都是 Fp2（两个 Fp 系数），Z = (1,0) 表示这就是仿射点。
     */
    public static final BigInteger[][] P2 = new BigInteger[][]{
        new BigInteger[]{
            new BigInteger("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16),
            new BigInteger("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16) },
        new BigInteger[]{
            new BigInteger("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16),
            new BigInteger("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", 16) },
        new BigInteger[]{ BigInteger.ONE, BigInteger.ZERO } };

    /** G₁ 仿射点的"无穷远" = 空数组；G₂ 射影点的"无穷远" = Z 为 Fp2 的 0。 */
    public static final BigInteger[] INFINITY_1 = new BigInteger[0];

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    /** Frobenius 映射要用的 6 个 Fp 常数（GB/T 32915.1 附录里给的就是这几个数）。 */
    public static final BigInteger BETA = new BigInteger("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011", 16);
    public static final BigInteger ALPHA1 = new BigInteger("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b", 16);
    public static final BigInteger ALPHA2 = new BigInteger("f300000002a3a6f2780272354f8b78f4d5fc11967be65334", 16);
    public static final BigInteger ALPHA3 = BETA;                                       // 与 beta 相同，不是巧合：α³ = β
    public static final BigInteger ALPHA4 = new BigInteger("f300000002a3a6f2780272354f8b78f4d5fc11967be65333", 16);
    public static final BigInteger ALPHA5 = new BigInteger("2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686", 16);

    /** ate 配对主线循环：|6u+2| 的带符号三进制，'1' = +Q，'2' = −Q，'0' = 只倍点。 */
    public static final String ABITS = "00100000000000000000000000000000000000010000101100020200101000020";

    /** 最终幂难算部分用的两个指数（GB/T 32915.1 里的 a₂、a₃）。 */
    public static final BigInteger FINAL_A2 = new BigInteger("d8000000019062ed0000b98b0cb27659", 16);
    public static final BigInteger FINAL_A3 = new BigInteger("2400000000215d941", 16);
    private static final BigInteger FINAL_NINE = BigInteger.valueOf(9);

    // ---------------------------------------------------------------- Fp：一个 BigInteger 就是一个域元素

    public static BigInteger fpAdd(BigInteger a, BigInteger b)
    {
        return a.add(b).mod(P);
    }

    public static BigInteger fpSub(BigInteger a, BigInteger b)
    {
        return a.subtract(b).mod(P);
    }

    public static BigInteger fpNeg(BigInteger a)
    {
        return a.negate().mod(P);
    }

    public static BigInteger fpDbl(BigInteger a)
    {
        return a.shiftLeft(1).mod(P);
    }

    public static BigInteger fpMul(BigInteger a, BigInteger b)
    {
        return a.multiply(b).mod(P);
    }

    public static BigInteger fpSqr(BigInteger a)
    {
        return a.multiply(a).mod(P);
    }

    /** 域里唯一的"贵"运算：模逆，就是扩展欧几里得。 */
    public static BigInteger fpInv(BigInteger a)
    {
        return a.modInverse(P);
    }

    // ---------------------------------------------------------------- Fp2 = Fp[u]/(u²+2)，元素 = (a₀, a₁)

    public static BigInteger[] fp2Of(BigInteger a0, BigInteger a1)
    {
        return new BigInteger[]{ a0.mod(P), a1.mod(P) };
    }

    public static BigInteger[] fp2Add(BigInteger[] a, BigInteger[] b)
    {
        return new BigInteger[]{ fpAdd(a[0], b[0]), fpAdd(a[1], b[1]) };
    }

    public static BigInteger[] fp2Sub(BigInteger[] a, BigInteger[] b)
    {
        return new BigInteger[]{ fpSub(a[0], b[0]), fpSub(a[1], b[1]) };
    }

    public static BigInteger[] fp2Neg(BigInteger[] a)
    {
        return new BigInteger[]{ fpNeg(a[0]), fpNeg(a[1]) };
    }

    public static BigInteger[] fp2Dbl(BigInteger[] a)
    {
        return new BigInteger[]{ fpDbl(a[0]), fpDbl(a[1]) };
    }

    public static BigInteger[] fp2Tri(BigInteger[] a)
    {
        return new BigInteger[]{ a[0].multiply(THREE).mod(P), a[1].multiply(THREE).mod(P) };
    }

    /**
     * u² = −2 是整条塔的根：(a₀+a₁u)(b₀+b₁u) = (a₀b₀ − 2a₁b₁) + (a₀b₁ + a₁b₀)u。
     * 后面 Fp4、Fp12 的乘法都是把这一条套上去，没有新东西。
     */
    public static BigInteger[] fp2Mul(BigInteger[] a, BigInteger[] b)
    {
        BigInteger t0 = fpMul(a[0], b[0]);
        BigInteger t1 = fpMul(a[1], b[1]);
        return new BigInteger[]{
            fpSub(t0, fpMul(TWO, t1)),
            fpSub(fpMul(fpAdd(a[0], a[1]), fpAdd(b[0], b[1])), fpAdd(t0, t1)) };
    }

    public static BigInteger[] fp2Sqr(BigInteger[] a)
    {
        return fp2Mul(a, a);
    }

    /** 乘 u：(a₀+a₁u)·u = −2a₁ + a₀u。 */
    public static BigInteger[] fp2MulU(BigInteger[] a)
    {
        return new BigInteger[]{ fpNeg(fpMul(TWO, a[1])), a[0] };
    }

    /** 乘 Fp 里的标量（Frobenius 的 α、β 都是以这个方式进来的）。 */
    public static BigInteger[] fp2MulFp(BigInteger[] a, BigInteger c)
    {
        return new BigInteger[]{ fpMul(a[0], c), fpMul(a[1], c) };
    }

    /** 共轭 = Fp2 上的 p 次 Frobenius：a₀ + a₁u -> a₀ − a₁u。 */
    public static BigInteger[] fp2Conj(BigInteger[] a)
    {
        return new BigInteger[]{ a[0], fpNeg(a[1]) };
    }

    /** 范数 N(a) = a₀² + 2a₁²（因为 u² = −2），逆 = 共轭 / 范数。 */
    public static BigInteger[] fp2Inv(BigInteger[] a)
    {
        BigInteger norm = fpAdd(fpSqr(a[0]), fpMul(TWO, fpSqr(a[1])));
        BigInteger inv = fpInv(norm);
        return new BigInteger[]{ fpMul(a[0], inv), fpMul(fpNeg(a[1]), inv) };
    }

    /** Fp2 元素是否等于 0（两个系数都为零）—— 射影点判定无穷远就看这个。 */
    public static boolean fp2IsZero(BigInteger[] a)
    {
        return a[0].signum() == 0 && a[1].signum() == 0;
    }

    // ---------------------------------------------------------------- Fp4 = Fp2[v]/(v²−u)，元素 = 4 个 Fp 系数

    public static BigInteger[] fp4Of(BigInteger[] c0, BigInteger[] c1)
    {
        BigInteger[] out = new BigInteger[4];
        out[0] = c0[0];
        out[1] = c0[1];
        out[2] = c1[0];
        out[3] = c1[1];
        return out;
    }

    /** 取 Fp4 元素的两个 Fp2 半边：v⁰ 部分与 v¹ 部分。 */
    public static BigInteger[] fp4Half(BigInteger[] a, int which)
    {
        return new BigInteger[]{ a[2 * which], a[2 * which + 1] };
    }

    public static BigInteger[] fp4Add(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpAdd(a[i], b[i]);
        }
        return out;
    }

    public static BigInteger[] fp4Sub(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpSub(a[i], b[i]);
        }
        return out;
    }

    public static BigInteger[] fp4Neg(BigInteger[] a)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpNeg(a[i]);
        }
        return out;
    }

    /** (a₀+a₁v)(b₀+b₁v) = (a₀b₀ + u·a₁b₁) + (a₀b₁ + a₁b₀)v，因为 v² = u。 */
    public static BigInteger[] fp4Mul(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] a0 = fp4Half(a, 0);
        BigInteger[] a1 = fp4Half(a, 1);
        BigInteger[] b0 = fp4Half(b, 0);
        BigInteger[] b1 = fp4Half(b, 1);
        return fp4Of(fp2Add(fp2Mul(a0, b0), fp2MulU(fp2Mul(a1, b1))),
            fp2Add(fp2Mul(a0, b1), fp2Mul(a1, b0)));
    }

    public static BigInteger[] fp4Sqr(BigInteger[] a)
    {
        return fp4Mul(a, a);
    }

    /** 乘 v：(x₀ + x₁v)·v = u·x₁ + x₀·v。 */
    public static BigInteger[] fp4MulV(BigInteger[] x)
    {
        return fp4Of(fp2MulU(fp4Half(x, 1)), fp4Half(x, 0));
    }

    /** 乘 Fp 里的标量：Fp4 的每一半各自乘同一个数（Frobenius 的 α 就落在 Fp 里）。 */
    public static BigInteger[] fp4MulFp(BigInteger[] a, BigInteger c)
    {
        return fp4Of(fp2MulFp(fp4Half(a, 0), c), fp2MulFp(fp4Half(a, 1), c));
    }

    /** Fp4 的共轭 = 翻 v 的符号；范数 = a₀² − u·a₁²。 */
    public static BigInteger[] fp4Conj(BigInteger[] a)
    {
        return fp4Of(fp4Half(a, 0), fp2Neg(fp4Half(a, 1)));
    }

    public static BigInteger[] fp4Inv(BigInteger[] a)
    {
        BigInteger[] a0 = fp4Half(a, 0);
        BigInteger[] a1 = fp4Half(a, 1);
        BigInteger[] norm = fp2Sub(fp2Sqr(a0), fp2MulU(fp2Sqr(a1)));
        BigInteger[] inv = fp2Inv(norm);
        return fp4Of(fp2Mul(inv, a0), fp2Mul(inv, fp2Neg(a1)));
    }

    // ---------------------------------------------------------------- Fp12 = Fp4[w]/(w³−v)，元素 = 12 个 Fp 系数

    public static BigInteger[] fp12One()
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = BigInteger.ZERO;
        }
        out[0] = BigInteger.ONE;
        return out;
    }

    /** 取/放 Fp12 元素里第 which 组 Fp4（对应 w^which）。 */
    public static BigInteger[] fp12Group(BigInteger[] a, int which)
    {
        BigInteger[] out = new BigInteger[4];
        System.arraycopy(a, 4 * which, out, 0, 4);
        return out;
    }

    public static BigInteger[] fp12Of(BigInteger[] g0, BigInteger[] g1, BigInteger[] g2)
    {
        BigInteger[] out = new BigInteger[12];
        System.arraycopy(g0, 0, out, 0, 4);
        System.arraycopy(g1, 0, out, 4, 4);
        System.arraycopy(g2, 0, out, 8, 4);
        return out;
    }

    public static BigInteger[] fp12Add(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = fpAdd(a[i], b[i]);
        }
        return out;
    }

    public static BigInteger[] fp12Sub(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = fpSub(a[i], b[i]);
        }
        return out;
    }

    public static boolean fp12Equals(BigInteger[] a, BigInteger[] b)
    {
        for (int i = 0; i < 12; i++)
        {
            if (!a[i].equals(b[i]))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * 三次扩张的乘法，只有 w³ = v 这一条规则：
     * <pre>
     *   (a₀+a₁w+a₂w²)(b₀+b₁w+b₂w²)
     *     = (a₀b₀ + v(a₁b₂ + a₂b₁)) + (a₀b₁ + a₁b₀ + v·a₂b₂)w + (a₀b₂ + a₁b₁ + a₂b₀)w²
     * </pre>
     */
    public static BigInteger[] fp12Mul(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] a0 = fp12Group(a, 0);
        BigInteger[] a1 = fp12Group(a, 1);
        BigInteger[] a2 = fp12Group(a, 2);
        BigInteger[] b0 = fp12Group(b, 0);
        BigInteger[] b1 = fp12Group(b, 1);
        BigInteger[] b2 = fp12Group(b, 2);

        BigInteger[] g0 = fp4Add(fp4Mul(a0, b0), fp4MulV(fp4Add(fp4Mul(a1, b2), fp4Mul(a2, b1))));
        BigInteger[] g1 = fp4Add(fp4Mul(a0, b1), fp4Mul(a1, b0));
        g1 = fp4Add(g1, fp4MulV(fp4Mul(a2, b2)));
        BigInteger[] g2 = fp4Add(fp4Add(fp4Mul(a0, b2), fp4Mul(a1, b1)), fp4Mul(a2, b0));
        return fp12Of(g0, g1, g2);
    }

    public static BigInteger[] fp12Sqr(BigInteger[] a)
    {
        return fp12Mul(a, a);
    }

    /**
     * Fp12 求逆用三次扩张的"三次共轭"公式（ξ = v）：
     * <pre>
     *   c₀ = a₀² − v·a₁a₂,  c₁ = v·a₂² − a₀a₁,  c₂ = a₁² − a₀a₂
     *   N  = a₀c₀ + v(a₁c₂ + a₂c₁)  ∈ Fp4,   a⁻¹ = N⁻¹·(c₀ + c₁w + c₂w²)
     * </pre>
     * 字母：a₀/a₁/a₂ 是入参 a 的三个 Fp4 分量（w⁰/w¹/w² 的系数）；c₀/c₁/c₂ 是它们组合出的
     * "三次共轭"分量；N 是 a 从 Fp12 降到 Fp4 的<b>范数</b>（norm：一路乘共轭把 w 消光，只剩
     * Fp4 里的一个数）。为什么这样做对 —— (a₀+a₁w+a₂w²)(c₀+c₁w+c₂w²) 展开后 w¹、w² 项恰好
     * 互相抵消，只剩 N·w⁰ = N，于是 a⁻¹ = N⁻¹·(共轭)。贵的是一个 Fp4 逆，比 Fp12 逆便宜得多。
     */
    public static BigInteger[] fp12Inv(BigInteger[] a)
    {
        BigInteger[] a0 = fp12Group(a, 0);
        BigInteger[] a1 = fp12Group(a, 1);
        BigInteger[] a2 = fp12Group(a, 2);

        BigInteger[] c0 = fp4Sub(fp4Sqr(a0), fp4MulV(fp4Mul(a1, a2)));
        BigInteger[] c1 = fp4Sub(fp4MulV(fp4Sqr(a2)), fp4Mul(a0, a1));
        BigInteger[] c2 = fp4Sub(fp4Sqr(a1), fp4Mul(a0, a2));

        BigInteger[] norm = fp4Add(fp4Mul(a0, c0), fp4MulV(fp4Add(fp4Mul(a1, c2), fp4Mul(a2, c1))));
        BigInteger[] nInv = fp4Inv(norm);
        return fp12Of(fp4Mul(nInv, c0), fp4Mul(nInv, c1), fp4Mul(nInv, c2));
    }

    /**
     * 逐位扫描的 for 循环：先平方，再按位乘 —— 和 SM2 里那个 mul 一模一样的结构。
     * <pre>
     *   acc = 1;  for j = 高位→低位:  acc = acc²;  if (e 的第 j 位 = 1) acc = acc·base
     * </pre>
     * 字母：{@code base} 是底（一个 Fp12 元素，通常是配对像 g 或 w 的基准）；{@code e} 是
     * <b>指数</b>（Z_n 里的标量，比如签名里的一次性随机数 r、验签里的哈希 h）—— 和配对记号
     * e(P,Q) 里的 e 只是重名，毫无关系。为什么循环等价于 base^e：把 e 写成二进制
     * e = Σ e_j·2^j，则 base^e = Π (base^{2^j})^{e_j}，循环里的"平方"就是在推进 base^{2^j}。
     * GT 里的元素满足 a^n = 1，所以指数可以对 n 取模 —— 这是签名侧 l=(r−h) mod n 能还原的前提。
     */
    public static BigInteger[] fp12Pow(BigInteger[] base, BigInteger e)
    {
        BigInteger[] acc = fp12One();
        for (int j = 0; j < e.bitLength(); j++)
        {
            int bit = e.bitLength() - 1 - j;
            BigInteger[] squared = fp12Sqr(acc);
            if (e.testBit(bit))
            {
                acc = fp12Mul(squared, base);
            }
            else
            {
                acc = squared;
            }
        }
        return acc;
    }

    /**
     * 线函数在 Fp12 里的位置：GmSSL 里线元素是稀疏的 {@code lw₀ + lw₁·w² + lw₂·w³}，
     * 而 w³ = v，所以非零系数只落在下标 0,1（lw₀）、2,3（lw₂·v）、8,9（lw₁·w²）。
     */
    public static BigInteger[] fp12FromLine(BigInteger[][] lw)
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = BigInteger.ZERO;
        }
        out[0] = lw[0][0];
        out[1] = lw[0][1];
        out[2] = lw[2][0];
        out[3] = lw[2][1];
        out[4] = BigInteger.ZERO;
        out[5] = BigInteger.ZERO;
        out[6] = BigInteger.ZERO;
        out[7] = BigInteger.ZERO;
        out[8] = lw[1][0];
        out[9] = lw[1][1];
        out[10] = BigInteger.ZERO;
        out[11] = BigInteger.ZERO;
        return out;
    }

    /** Fp12 -> 384 字节：12 个 Fp 系数按大端、下标 11 递减到 0 排列（签名里那枚 w 就是这个形状）。 */
    public static byte[] fp12ToBytes(BigInteger[] a)
    {
        byte[] out = new byte[32 * 12];
        int at = 0;
        for (int i = 11; i >= 0; i--)
        {
            byte[] one = Calc.toBytes(a[i], 32);
            System.arraycopy(one, 0, out, at, 32);
            at += 32;
        }
        return out;
    }

    /** 384 字节 -> Fp12，与 {@link #fp12ToBytes} 严格互逆（每个系数顺手归约到 [0,p)）。 */
    public static BigInteger[] fp12FromBytes(byte[] buf)
    {
        List<byte[]> parts = Calc.chunks(buf, 32);
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[11 - i] = Calc.toBigInt(parts.get(i)).mod(P);
        }
        return out;
    }

    // ---------------------------------------------------------------- Fp12 的 Frobenius：x -> x^p, x^p², x^p³, x^p⁶

    /**
     * x^p：每半边共轭，再乘对应的 α —— 这些 α 就是"Frobenius 在塔基下的表"。
     * 下标顺序：Fp12 的第 k 组 Fp4 = (c_{4k}, c_{4k+1}, c_{4k+2}, c_{4k+3})。
     */
    public static BigInteger[] fp12Frobenius(BigInteger[] x)
    {
        BigInteger[] a = fp12Group(x, 0);
        BigInteger[] b = fp12Group(x, 1);
        BigInteger[] c = fp12Group(x, 2);

        BigInteger[] ra = fp4Of(fp2Conj(fp4Half(a, 0)),
            fp2MulFp(fp2Conj(fp4Half(a, 1)), ALPHA3));
        BigInteger[] rb = fp4Of(fp2MulFp(fp2Conj(fp4Half(b, 0)), ALPHA1),
            fp2MulFp(fp2Conj(fp4Half(b, 1)), ALPHA4));
        BigInteger[] rc = fp4Of(fp2MulFp(fp2Conj(fp4Half(c, 0)), ALPHA2),
            fp2MulFp(fp2Conj(fp4Half(c, 1)), ALPHA5));
        return fp12Of(ra, rb, rc);
    }

    /** x^{p²}：Fp4 层共轭，第 1、2 组再乘 α₂、α₄。 */
    public static BigInteger[] fp12Frobenius2(BigInteger[] x)
    {
        BigInteger[] a = fp4Conj(fp12Group(x, 0));
        BigInteger[] b = fp4MulFp(fp4Conj(fp12Group(x, 1)), ALPHA2);
        BigInteger[] c = fp4MulFp(fp4Conj(fp12Group(x, 2)), ALPHA4);
        return fp12Of(a, b, c);
    }

    /** x^{p³}：每组共轭后按 β 的规则带符号地错一层。 */
    public static BigInteger[] fp12Frobenius3(BigInteger[] x)
    {
        BigInteger[] a = fp12Group(x, 0);
        BigInteger[] b = fp12Group(x, 1);
        BigInteger[] c = fp12Group(x, 2);

        BigInteger[] ra = fp4Of(fp2Conj(fp4Half(a, 0)),
            fp2Neg(fp2Mul(fp2Conj(fp4Half(a, 1)), fp2Of(BETA, BigInteger.ZERO))));
        BigInteger[] rb = fp4Of(fp2Mul(fp2Conj(fp4Half(b, 0)), fp2Of(BETA, BigInteger.ZERO)),
            fp2Conj(fp4Half(b, 1)));
        BigInteger[] rc = fp4Of(fp2Neg(fp2Conj(fp4Half(c, 0))),
            fp2Mul(fp2Conj(fp4Half(c, 1)), fp2Of(BETA, BigInteger.ZERO)));
        return fp12Of(ra, rb, rc);
    }

    /** x^{p⁶} = (a₀, −a₁, a₂) 的 Fp4 共轭组合 —— 最终幂的"易算部分"全靠它。 */
    public static BigInteger[] fp12Frobenius6(BigInteger[] x)
    {
        BigInteger[] a = fp4Conj(fp12Group(x, 0));
        BigInteger[] b = fp4Neg(fp4Conj(fp12Group(x, 1)));
        BigInteger[] c = fp4Conj(fp12Group(x, 2));
        return fp12Of(a, b, c);
    }

    // ---------------------------------------------------------------- G₁ = E(Fp): y² = x³ + 5（仿射，点 = BigInteger[2]）

    public static boolean pointIsOnCurve(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return true;
        }
        BigInteger lhs = fpSqr(pt[1]);
        BigInteger rhs = fpAdd(fpMul(fpSqr(pt[0]), pt[0]), FIVE);
        return lhs.equals(rhs);
    }

    public static BigInteger[] pointNeg(BigInteger[] pt)
    {
        return pt.length == 0 ? pt : new BigInteger[]{ pt[0], fpNeg(pt[1]) };
    }

    /**
     * 弦的斜率 λ = (y₂−y₁)/(x₂−x₁)；a = 0 所以加法公式里没有曲线参数。
     * <pre>
     *   λ  = (y₂ − y₁)·(x₂ − x₁)⁻¹ mod p     过 P、Q 两点那条直线（弦）的斜率
     *   x₃ = λ² − x₁ − x₂                     结果点的 x 坐标
     *   y₃ = λ(x₁ − x₃) − y₁                 结果点的 y 坐标
     * </pre>
     * 字母：(x₁,y₁) = 入参 p 的仿射坐标，(x₂,y₂) = q 的坐标；下标"1/2/3"只是"第一个点/
     * 第二个点/结果点"，<b>不是幂</b>；λ⁻¹ 型的除法一律是"乘模逆"（扩展欧几里得）。
     * <p>为什么是这三行：把直线 y = λ(x − x₁) + y₁ 代入曲线 y² = x³ + 5，得到关于 x 的三次方程，
     * 它的三个根就是直线与曲线的三个交点 x₁、x₂、x₃'。三次方程"根之和 = −(x² 项系数)"（Vieta），
     * 展开后给出 x₁ + x₂ + x₃' = λ²，于是 x₃' = λ² − x₁ − x₂。而群加法定义成"第三个交点关于
     * x 轴的对称点"（对称点 y 取反，正好把和变成 0，单位元才有意义），所以结果 x 与 x₃' 相同，
     * y 用直线方程回代再取反：y₃ = −(λ(x₃ − x₁) + y₁) = λ(x₁ − x₃) − y₁。
     * <p>两个特例走捷径：x 相同而 y 互为相反数 ⇒ 结果是无穷远点 O；p = q ⇒ 用切线（{@link #pointDouble}）。
     */
    public static BigInteger[] pointAdd(BigInteger[] p, BigInteger[] q)
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
            return fpAdd(p[1], q[1]).signum() == 0 ? INFINITY_1 : pointDouble(p);
        }
        BigInteger lam = fpMul(fpSub(q[1], p[1]), fpInv(fpSub(q[0], p[0])));
        BigInteger x = fpSub(fpSub(fpSqr(lam), p[0]), q[0]);
        BigInteger y = fpSub(fpMul(lam, fpSub(p[0], x)), p[1]);
        return new BigInteger[]{ x, y };
    }

    /**
     * 切线的斜率 λ = 3x²/(2y)（a = 0，导数只剩 3x²）。
     * <pre>
     *   λ  = 3x₁²·(2y₁)⁻¹ mod p     曲线在该点处切线的斜率
     *   x₃ = λ² − 2x₁               （加法公式里 x₃ = λ²−x₁−x₂，取 Q=P 就退化成这一行）
     *   y₃ = λ(x₁ − x₃) − y₁
     * </pre>
     * λ 从哪来：对 y² = x³ + 5 两边做隐函数求导，2y·dy = 3x²·dx，移项即 dy/dx = 3x²/(2y)。
     * 一般曲线 y² = x³ + ax + b 时分子还有 +a 一项，SM9 的 G₁ 取 a = 0 才剩 3x²。
     * <p>2y₁ = 0（含 y₁ = 0）⇒ 切线垂直，与曲线只有一个交点，结果就是无穷远点 O —— 代码里
     * 用 {@code fpDbl(p[1]).signum() == 0} 判这一步，漏掉它会除零（模逆不存在）。
     */
    public static BigInteger[] pointDouble(BigInteger[] p)
    {
        if (p.length == 0 || fpDbl(p[1]).signum() == 0)
        {
            return INFINITY_1;
        }
        BigInteger lam = fpMul(fpMul(THREE, fpSqr(p[0])), fpInv(fpDbl(p[1])));
        BigInteger x = fpSub(fpSqr(lam), fpDbl(p[0]));
        BigInteger y = fpSub(fpMul(lam, fpSub(p[0], x)), p[1]);
        return new BigInteger[]{ x, y };
    }

    /**
     * 标量乘 = 从最高位往下的 double-and-add for 循环。
     * <pre>
     *   k·P = P + P + … + P（k 次）   —— 加法的重复，<b>不是</b>两个数相乘
     *       = Σⱼ (k 的第 j 位为 1 ? 2ʲ·P : O)
     * </pre>
     * 字母：k 是标量（Z_n 里的数，如 ks、ke、r、l、h1）；acc 是累计点，起点为无穷远点 O
     * （加法群的"0"，加它不变）。循环每轮先 pointDouble（把累计量翻倍 = 前进一个二进制位），
     * 再按当前位决定加不加 point —— 所以 k = 6 = 0b110 走的是 ((O·2+P)·2+P)·2 = 4P+2P = 6P。
     * <p>为什么安全：已知 k·P 反求 k 是椭圆曲线离散对数问题 (ECDLP)，目前只能暴力，代价约
     * 2^128 次点加 —— 这就是 SM9 标称 128 位安全强度的来源。为什么循环到 n：n 是 P 的阶，
     * n·P = O，所以标量可以随意 mod n（这也是所有 modn* 函数存在的理由）。
     */
    public static BigInteger[] pointMul(BigInteger k, BigInteger[] point)
    {
        BigInteger[] acc = INFINITY_1;
        for (int j = 0; j < k.bitLength(); j++)
        {
            int bit = k.bitLength() - 1 - j;
            BigInteger[] doubled = pointDouble(acc);
            acc = k.testBit(bit) ? pointAdd(doubled, point) : doubled;
        }
        return acc;
    }

    // ---------------------------------------------------------------- G₂ = E'(Fp2): y² = x³ + 5u（射影点 = {X, Y, Z}）
    //
    // 符号（这一节里每个坐标都是 Fp2 元素 = BigInteger[2]，不是 Fp）：
    //   X, Y, Z  射影坐标，代表仿射点 (x, y) = (X/Z², Y/Z³)；Z = (1,0) 即 Fp2 的 1 时就是仿射。
    //   O        无穷远点：判定条件只有一个 —— Z 在 Fp2 里为零（X、Y 里写什么都无所谓）。
    //   5u       扭曲曲线的常数项 b' = 5u = (0,5)，即 fp2FiveU()；仿射方程 y² = x³ + 5u。
    //   λ        斜率，这次落在 Fp2 里，所以求逆用 fp2Inv（共轭/范数），不是 BigInteger.modInverse。
    // 为什么 G₂ 要"扭曲"到 Fp2 上：配对要求两个群来自同一条曲线的两个不同域，且它们的 n 阶
    // 子群互不相同；扭曲把 G₂ 的坐标抬到 Fp2，配对像才刚好落在 Fp12（嵌入次数 k = 12）。

    /** Fp2 里的 1 与 0，以及 E'(Fp2) 的 b' = 5u。 */
    public static BigInteger[] fp2One()
    {
        return new BigInteger[]{ BigInteger.ONE, BigInteger.ZERO };
    }

    public static BigInteger[] fp2FiveU()
    {
        return new BigInteger[]{ BigInteger.ZERO, BigInteger.valueOf(5) };
    }

    /** G₂ 的无穷远点：Z = 0。用同一个表示，配对和密钥运算才不会走两条路。 */
    public static BigInteger[][] twistInfinity()
    {
        return new BigInteger[][]{ fp2One(), fp2One(), new BigInteger[]{ BigInteger.ZERO, BigInteger.ZERO } };
    }

    /** 仿射 (x, y) ∈ Fp2² 变成射影 {X, Y, Z=(1,0)} —— 配对内部要的是射影坐标。 */
    public static BigInteger[][] twistFromAffine(BigInteger[] x, BigInteger[] y)
    {
        return new BigInteger[][]{ x, y, fp2One() };
    }

    public static BigInteger[][] twistNeg(BigInteger[][] pt)
    {
        return new BigInteger[][]{ pt[0], fp2Neg(pt[1]), pt[2] };
    }

    /**
     * 点在不在 E'(Fp2) 上。字母：X/Y/Z 是 G₂ 射影坐标的三个分量（各自是 Fp2 元素）。
     * <pre>
     *   Z = 0（Fp2 的零）      ⇒ 无穷远点 O，按定义算"在曲线上"
     *   否则核对 Y²·Z = X³ + 5u·Z³ —— 这是<b>齐次坐标</b> (x,y) = (X/Z, Y/Z) 下的曲线方程形状：
     *                   把 y² = x³ + 5u 两边乘 Z³ 就得到它。
     * </pre>
     * <p><b>一个要记住的坐标约定坑</b>：本文件其它地方（{@link #twistToAffine}、
     * {@link #evalGTangent} 的 Z₃ = 2Y₁Z₁）用的是 <b>Jacobian 权重</b>
     * (x,y) = (X/Z², Y/Z³)，那种约定下的判定式应是 Y² = X³ + 5u·Z⁶。两条式子只有在 Z = (1,0)
     * 时才等价 —— 而 {@code twistIsOnCurve} 目前只用来核对 {@link #twistMul}/私钥提取的产物
     * （它们都由 {@link #twistFromAffine} 生成，Z 恒为 1），所以测试一直是绿的。
     * 如果以后把 Miller 循环中间的点（Z ≠ 1）拿来做判定，必须换成 Z⁶ 那一条，否则会误报
     * "点不在曲线上"。注释留在这里，是为了让下一个读代码的人不必再推一遍权重。
     */
    public static boolean twistIsOnCurve(BigInteger[][] pt)
    {
        BigInteger[] z = pt[2];
        if (fp2IsZero(z))
        {
            return true;
        }
        // 射影判定：Y²Z = X³ + 5u·Z³
        BigInteger[] lhs = fp2Mul(fp2Sqr(pt[1]), z);
        BigInteger[] rhs = fp2Add(fp2Mul(fp2Sqr(pt[0]), pt[0]), fp2Mul(fp2FiveU(), fp2Mul(fp2Sqr(z), z)));
        return fp2IsZero(fp2Sub(lhs, rhs));
    }

    /**
     * G₂ 仿射加法（斜率 λ ∈ Fp2）。射影那套只服务于配对主线，密钥运算用仿射更直观。
     */
    public static BigInteger[][] twistAffineAdd(BigInteger[][] p, BigInteger[][] q)
    {
        if (fp2IsZero(p[2]) || fp2IsZero(q[2]))
        {
            return fp2IsZero(p[2]) ? q : p;
        }
        if (fp2IsZero(fp2Sub(p[0], q[0])))
        {
            return fp2IsZero(fp2Add(p[1], q[1])) ? twistInfinity() : twistAffineDouble(p);
        }
        BigInteger[] lam = fp2Mul(fp2Sub(q[1], p[1]), fp2Inv(fp2Sub(q[0], p[0])));
        BigInteger[] x = fp2Sub(fp2Sub(fp2Sqr(lam), p[0]), q[0]);
        BigInteger[] y = fp2Sub(fp2Mul(lam, fp2Sub(p[0], x)), p[1]);
        return twistFromAffine(x, y);
    }

    /** 切线 λ = 3x²/(2y)：a = 0，所以导数只剩 3x²，和 G₁ 那条完全同构。 */
    public static BigInteger[][] twistAffineDouble(BigInteger[][] p)
    {
        if (fp2IsZero(p[2]))
        {
            return p;
        }
        if (fp2IsZero(fp2Dbl(p[1])))
        {
            return twistInfinity();
        }
        BigInteger[] lam = fp2Mul(fp2Tri(fp2Sqr(p[0])), fp2Inv(fp2Dbl(p[1])));
        BigInteger[] x = fp2Sub(fp2Sqr(lam), fp2Dbl(p[0]));
        BigInteger[] y = fp2Sub(fp2Mul(lam, fp2Sub(p[0], x)), p[1]);
        return twistFromAffine(x, y);
    }

    public static BigInteger[][] twistMul(BigInteger k, BigInteger[][] point)
    {
        BigInteger[][] acc = twistInfinity();
        for (int j = 0; j < k.bitLength(); j++)
        {
            int bit = k.bitLength() - 1 - j;
            BigInteger[][] doubled = twistAffineDouble(acc);
            acc = k.testBit(bit) ? twistAffineAdd(doubled, point) : doubled;
        }
        return acc;
    }

    /**
     * π₁(Q)：共轭再让 Z 乘 α₁（GB/T 32915.1 里那个未声明倍的 Frobenius 组合）。
     * 字母：π₁ = "G₂ 点上的 p 次 Frobenius"，即把每个坐标各分量升到 p 次幂再按塔的规矩化回来。
     * 为什么"共轭"就是 p 次幂：Fp2 里 (a₀+a₁u)^p = a₀ − a₁u，因为 u² = −2 而 u^p = −u（p ≡ 3 mod 4）。
     * 为什么 α₁ 乘在 Z 上：射影坐标里把 Z 乘 s 等于把仿射 x 除 s²、y 除 s³ —— 扭曲曲线的
     * Frobenius 正好差这样一个尺度，标准给的补偿常数就是 α₁，代码照抄即可（配对的测试向量
     * 会证明这套组合是对的，见 Sm9PairingEssenceTest）。
     */
    public static BigInteger[][] twistPi1(BigInteger[][] q)
    {
        return new BigInteger[][]{ fp2Conj(q[0]), fp2Conj(q[1]), fp2MulFp(fp2Conj(q[2]), ALPHA1) };
    }

    /**
     * −π₂(Q)：只翻 y 的符号，Z 乘 α₂。
     * 前缀减号是字面意思：π₂ 之后再取群的逆元（y 变 −y，x 不变）—— 这是 ate 配对定义里
     * 除子"和为零"条件的要求。α₂ 同样是扭曲尺度补偿，与 α₁ 一样来自标准附录。
     */
    public static BigInteger[][] twistNegPi2(BigInteger[][] q)
    {
        return new BigInteger[][]{ q[0], fp2Neg(q[1]), fp2MulFp(q[2], ALPHA2) };
    }

    // ---------------------------------------------------------------- 配对的两条主线：切线 / 割线（照 GB/T 32915 的压缩公式）

    /**
     * 切线评估 + 倍点，一次算完（省一半中间量，这是所有实用实现的写法）。
     * 出参：{@code rOut} = 2·pt，{@code lwOut} = 切线在仿射点 q ∈ G₁ 处的取值（3 个 Fp2 系数）。
     * 逐行对应 GmSSL 的 sm9_z256_eval_g_tangent，只把 mont 换成了明文。
     *
     * <p><b>字母表 —— 入参与出参</b>
     * <pre>
     *   pt     T ∈ G₂ 的射影坐标 (X₁,Y₁,Z₁)，每个分量都是 Fp2 元素（BigInteger[2]）
     *   q      P ∈ G₁ 的仿射坐标 (x_P, y_P)，每个分量是普通 Fp 元素（一个 BigInteger）
     *   rOut   结果点 2T 的射影坐标 (x3, y3, z3)
     *   lwOut  线函数的三个 Fp2 系数 (l0, l1, l2)，含义见下面"线函数怎么拼"
     * </pre>
     *
     * <p><b>中间量都是谁</b>（名字沿用 GmSSL，纯粹为了"同一个平方只算一次"，没有新数学）：
     * <pre>
     *   t1 = Z₁²            a = X₁²          b = Y₁²          c = Y₁⁴
     *   d = 2·((X₁+b)² − a − c) = 4·X₁·Y₁²  —— 用 (u+v)²−u²−v² = 2uv 的技巧，省一次乘法
     *   a = 3X₁²（切线斜率的分子）→ b = 9X₁⁴ → x3 = b − 2d = 9X₁⁴ − 8X₁Y₁²
     *   y3 = a·(d − x3) − 8c = 3X₁²·(d − x3) − 8Y₁⁴
     *   z3 = (Y₁+Z₁)² − b − t1 = 2·Y₁·Z₁（同样靠完全平方展开省乘法；Z₁=1 时就是 2Y₁）
     *   l0 = (X₁ + 3X₁²)² − (X₁² + 4Y₁² + 9X₁⁴)     线函数的常数部分（不含 P 的坐标）
     *   l1 = −2·(3X₁²)·Z₁² · x_P                    已经乘过 P 的 x 坐标
     *   l2 =  2·z3·Z₁²       · y_P                   已经乘过 P 的 y 坐标
     * </pre>
     *
     * <p><b>线函数怎么拼</b>：L = l0 + l1·w² + l2·w³，而 w³ = v，所以三个 Fp2 系数分别落到
     * Fp12 的 1、w²、v 三个基上 —— 这正是 {@link #fp12FromLine} 只写下标 0,1 / 2,3 / 8,9 的原因。
     * 直觉：Miller 循环要的是"过 T 的切线在 P 这一点取值"，直线方程是 X₁·x − Y₁·y + Z₁ 一类的
     * 线性组合，把 P 的坐标代进去就把系数 l1、l2 变成了数（上面两行的 x_P、y_P 就是这么来的）。
     */
    public static void evalGTangent(BigInteger[][] rOut, BigInteger[][] lwOut, BigInteger[][] pt, BigInteger[] q)
    {
        BigInteger[] x1 = pt[0];
        BigInteger[] y1 = pt[1];
        BigInteger[] z1 = pt[2];

        BigInteger[] t1 = fp2Sqr(z1);
        BigInteger[] a = fp2Sqr(x1);
        BigInteger[] b = fp2Sqr(y1);
        BigInteger[] c = fp2Sqr(b);
        BigInteger[] d = fp2Sqr(fp2Add(x1, b));
        d = fp2Sub(fp2Sub(d, a), c);
        d = fp2Dbl(d);
        BigInteger[] z3 = fp2Sqr(fp2Add(y1, z1));
        z3 = fp2Sub(fp2Sub(z3, b), t1);

        BigInteger[] l0 = fp2Dbl(fp2Dbl(b));
        l0 = fp2Add(l0, a);
        a = fp2Tri(a);
        b = fp2Sqr(a);
        BigInteger[] x3 = fp2Sub(b, fp2Dbl(d));
        l0 = fp2Add(l0, b);
        BigInteger[] y3 = fp2Mul(fp2Sub(d, x3), a);
        c = fp2Dbl(fp2Dbl(fp2Dbl(c)));
        y3 = fp2Sub(y3, c);

        BigInteger[] l2 = fp2Dbl(fp2Mul(z3, t1));
        BigInteger[] l1 = fp2Neg(fp2Dbl(fp2Mul(a, t1)));
        l0 = fp2Sub(fp2Sqr(fp2Add(x1, a)), l0);
        l1 = fp2MulFp(l1, q[0]);
        l2 = fp2MulFp(l2, q[1]);

        rOut[0] = x3;
        rOut[1] = y3;
        rOut[2] = z3;
        lwOut[0] = l0;
        lwOut[1] = l1;
        lwOut[2] = l2;
    }

    /**
     * 割线评估 + 加法，一次算完。{@code acc} 是累计点 T，{@code addend} 是要加上去的 Q（或 −Q、π₁Q）。
     * 逐行对应 GmSSL 的 sm9_z256_eval_g_line_no_pre：先按 addend 与 q 算 5 个预置量 pre[0..4]，
     * 再走一遍加法公式。注意 pre 只用 addend 与 q，所以配对的整条主线里它对 '1'/'2' 两个分支是一样的。
     *
     * <p><b>字母表 —— 入参与出参</b>
     * <pre>
     *   acc     T = (X₁,Y₁,Z₁) ∈ G₂ 射影 —— 累计点（"已经加出来的部分"）
     *   addend  Q = (X₂,Y₂,Z₂) ∈ G₂ 射影 —— 这一步要加上去的点；'2' 分支传 −Q，收尾传 π₁Q / −π₂Q
     *   q       P = (x_P, y_P) ∈ G₁ 仿射 —— 线函数在这一点取值
     *   rOut    T + Q 的射影坐标；lwOut = 割线的三个 Fp2 系数 (l0,l1,l2)，拼法同切线：l0 + l1·w² + l2·w³
     * </pre>
     *
     * <p><b>中间量都是谁</b>（同一子表达式只平方一次的复用名）：
     * <pre>
     *   pre0 = Y₂²        pre1 = Z₂³        pre4 = 2·X₂·Z₂
     *   pre2 = 2·Z₂³·y_P  pre3 = −2·Z₂³·x_P —— 这两个已经把 P 的坐标代进直线方程了
     *   t1 = Z₁²  t2 = Z₂²  初值 z3 = (Z₁+Z₂)² − t1 − t2 = 2·Z₁·Z₂
     *   a  = X₁·Z₂²               b  = X₂·Z₁² − a   ← 射影加法里的"Δx"，b = 0 说明两点重合或对映
     *   c  = 2·Y₁·Z₂³             d  = ((Y₂+Z₁)² − Y₂² − Z₁²)·Z₁² = 2·Y₂·Z₁³
     *   z3 = 2·Z₁·Z₂·b
     *   记 t = (2b)² = 4b²，则结果点：x3 = (d−c)² − t·(b + 2a)，y3 = (a − x3)·(d−c) − t·b·c
     *   （代码是就地推进这几个名字：先 x3 = b·t，再 x3 += 2·a·t，最后 x3 = (d−c)² − x3；
     *     y3 的减数在第一步就存成 c·(b·t)，所以看起来"顺序奇怪"，其实只是变量复用）
     *   l0 = b·(2X₂Z₂) − 2·Y₂·z3        l1 = b·pre3        l2 = z3·pre2
     * </pre>
     * 为什么先算 b 再乘进 z3：b 是这条割线的"方向量"，射影坐标里除 b 要用模逆，把它塞进 Z₃
     * 就等于把这次逆推迟到整个配对结束后的 {@code twistToAffine}，一次都不多花。
     */
    public static void evalGLine(BigInteger[][] rOut, BigInteger[][] lwOut, BigInteger[][] acc,
        BigInteger[][] addend, BigInteger[] q)
    {
        BigInteger[] x1 = acc[0];
        BigInteger[] y1 = acc[1];
        BigInteger[] z1 = acc[2];
        BigInteger[] x2 = addend[0];
        BigInteger[] y2 = addend[1];
        BigInteger[] z2 = addend[2];

        BigInteger[] pre0 = fp2Sqr(y2);
        BigInteger[] pre4 = fp2Dbl(fp2Mul(x2, z2));
        BigInteger[] pre1 = fp2Mul(fp2Sqr(z2), z2);
        BigInteger[] pre2 = fp2Dbl(fp2MulFp(pre1, q[1]));
        BigInteger[] pre3 = fp2Neg(fp2Dbl(fp2MulFp(pre1, q[0])));

        BigInteger[] t1 = fp2Sqr(z1);
        BigInteger[] t2 = fp2Sqr(z2);
        BigInteger[] z3 = fp2Sqr(fp2Add(z1, z2));
        z3 = fp2Sub(fp2Sub(z3, t1), t2);
        BigInteger[] a = fp2Mul(x1, t2);
        BigInteger[] b = fp2Sub(fp2Mul(x2, t1), a);
        BigInteger[] c = fp2Dbl(fp2Mul(y1, pre1));
        BigInteger[] d = fp2Mul(fp2Sub(fp2Sub(fp2Sqr(fp2Add(y2, z1)), pre0), t1), t1);
        z3 = fp2Mul(z3, b);
        t1 = fp2Sqr(fp2Dbl(b));
        BigInteger[] x3 = fp2Mul(b, t1);
        BigInteger[] y3 = fp2Mul(c, x3);
        a = fp2Mul(a, t1);
        b = fp2Sub(d, c);
        x3 = fp2Add(x3, fp2Dbl(a));
        x3 = fp2Sub(fp2Sqr(b), x3);
        y3 = fp2Sub(fp2Mul(fp2Sub(a, x3), b), y3);

        BigInteger[] l2 = fp2Mul(z3, pre2);
        BigInteger[] l1 = fp2Mul(b, pre3);
        BigInteger[] l0 = fp2Sub(fp2Mul(b, pre4), fp2Dbl(fp2Mul(y2, z3)));

        rOut[0] = x3;
        rOut[1] = y3;
        rOut[2] = z3;
        lwOut[0] = l0;
        lwOut[1] = l1;
        lwOut[2] = l2;
    }

    // ---------------------------------------------------------------- ate 配对与最终幂

    /**
     * e(P, Q)：P ∈ G₁（仿射），Q ∈ G₂（射影）。主线按 ABITS 逐位扫描：
     * <pre>
     *   f = f²            （平方）
     *   f = f · l_{T,T}(P), T = 2T      （切线）
     *   位为 '1'：f = f · l_{T,Q}(P), T = T + Q
     *   位为 '2'：f = f · l_{T,−Q}(P), T = T − Q
     * 收尾两条线：l_{T,π₁Q}(P) 与 l_{T,−π₂Q}(P)，然后做最终幂。
     * </pre>
     * 字母：{@code qTwist} = Q ∈ G₂（射影），{@code pAffine} = P ∈ G₁（仿射）—— 注意方法参数
     * 顺序是"G₂ 在前"，而公式里习惯写 e(P,Q)，两者指同一个配对，别被形参顺序绕晕。
     * {@code f} 是 Miller 值（Fp12 元素，初值 1），{@code t} 是累计点 T（起点就是 Q），
     * {@code lw} 是每步线函数的三个 Fp2 系数，{@code digit} 是 ABITS 的当前三进制位。
     * <p>为什么"先平方再乘线"：每扫一位相当于把倍数翻倍，f 里累积的是
     * Π l_{A,B}(P) —— 而把 T 变成 2T 的那条切线要<b>先按老的 T 算</b>，所以平方（对应
     * f ↦ f²，即把已有除子整体加倍）必须排在乘线之前，顺序错了配对就不双线性了。
     * <p>为什么收尾要 π₁Q 与 −π₂Q 两条线：ate 配对的定义里要把除子换成
     * "Q 的 Frobenius 组合"才能保证结果与代表元选取无关（GB/T 32915.1 的 A.2 就是这么给的），
     * π₁/π₂ 的具体做法见 {@link #twistPi1} 与 {@link #twistNegPi2}。
     */
    public static BigInteger[] pairing(BigInteger[][] qTwist, BigInteger[] pAffine)
    {
        BigInteger[][] t = new BigInteger[][]{ qTwist[0], qTwist[1], qTwist[2] };
        BigInteger[][] negQ = twistNeg(qTwist);
        BigInteger[][] lw = new BigInteger[3][];
        BigInteger[] f = fp12One();

        for (int i = 0; i < ABITS.length(); i++)
        {
            f = fp12Sqr(f);
            evalGTangent(t, lw, t, pAffine);
            f = fp12Mul(f, fp12FromLine(lw));

            char digit = ABITS.charAt(i);
            if (digit == '1')
            {
                evalGLine(t, lw, t, qTwist, pAffine);
                f = fp12Mul(f, fp12FromLine(lw));
            }
            else if (digit == '2')
            {
                evalGLine(t, lw, t, negQ, pAffine);
                f = fp12Mul(f, fp12FromLine(lw));
            }
        }

        BigInteger[][] q1 = twistPi1(qTwist);
        BigInteger[][] q2 = twistNegPi2(qTwist);
        evalGLine(t, lw, t, q1, pAffine);
        f = fp12Mul(f, fp12FromLine(lw));
        evalGLine(t, lw, t, q2, pAffine);
        f = fp12Mul(f, fp12FromLine(lw));

        return finalExponent(f);
    }

    /**
     * 最终幂：把 Fp12 的元素压到唯一的 n 阶子群 GT 里，分两半算才划算。
     * <pre>
     *   易算部分  f^((p⁶−1)(p²+1)) = (π₆(f)/f)·π₂(π₆(f)/f)
     *   难算部分  用 a₂、a₃、9 次幂与三次 π 组合出 (p⁴−p²+1)/n 那一坨
     * </pre>
     * 字母：这里的 f 是 Miller 值（还住在整个 Fp12* 里，不是配对结果）；π₆/π₂ 就是
     * {@link #fp12Frobenius6}/{@link #fp12Frobenius2}，即 x ↦ x^{p⁶}、x ↦ x^{p²} 的快捷算法。
     * <p>为什么"易算"：x^{p⁶} 在塔基下只是"翻 v 的符号"（共轭），一次乘法都不用做，
     * 所以 f^{p⁶−1} = π₆(f)·f⁻¹ 只要一次求逆 + 一次乘法；再乘 (p²+1) 就是多套一次 π₂。
     * 幂 (p⁶−1) 的作用是 f ↦ f^{p⁶}/f —— 把元素射到"Fp6 子域里"（因为 g^{p⁶} = g^{−1} 对
     * GT 元素成立，所以这一步已经把一半的自由度砍掉）。
     * <p>为什么剩下那坨"难算"：(p⁴−p²+1)/n 是 (p¹²−1)/n 去掉易算部分后的商，它没法用
     * Frobenius 拼出来，只能用 a₂、a₃（标准给的两个小指数，位长很短）与 9 次幂组成一条
     * 加法链（addition chain：一串"平方/相乘"的最短路线）来近似 exp —— 见
     * {@link #finalExponentHardPart}。
     * <p>为什么必须做最终幂：Miller 值依赖直线代表元的选法，只有升到这个幂之后才是
     * <b>唯一确定的 n 阶根 of unity</b>，双线性 e(aP,bQ)=e(P,Q)^{ab} 才成立。
     */
    public static BigInteger[] finalExponent(BigInteger[] f)
    {
        BigInteger[] t0 = fp12Mul(fp12Frobenius6(f), fp12Inv(f));
        t0 = fp12Mul(t0, fp12Frobenius2(t0));
        return finalExponentHardPart(t0);
    }

    /**
     * 难算部分的加法链（GmSSL 的 sm9_z256_final_exponent_hard_part，逐步对应）。
     * 字母：入参 {@code f} 这里已经是"易算部分做完"的元素（住在 Fp6 子域那一侧）；
     * t0..t3 只是四个<b>中间幂寄存器</b>的名字，没有数学含义，作用就是让每个幂只算一次；
     * FINAL_A3 = a₃（十六进制只有 15 位，即不到 60 位）、FINAL_A2 = a₂（32 位十六进制 = 128 位）、
     * FINAL_NINE = 9 —— 三个都远短于 p 的 256 位，所以这条链里最贵的只有两次短指数模幂，
     * 其余是平方与乘法。
     * <p>整体效果 = f^((p⁴−p²+1)/n)。这条链不是推导出来的、而是标准与参考实现给定的
     * <b>固定路线</b>（GB/T 32915.1 附录 A.5 / GmSSL 同一串顺序），逐行照抄；它的正确性由
     * KAT 保证 —— Sm9PairingEssenceTest 拿 GmSSL sm9test.c 的三组 384 字节配对样例逐一比对，
     * 少一行、错一行都会让配对像对不上。想改效率可以，改完必须让那三组向量仍然相等。
     */
    public static BigInteger[] finalExponentHardPart(BigInteger[] f)
    {
        BigInteger[] t0 = fp12Inv(fp12Pow(f, FINAL_A3));
        BigInteger[] t1 = fp12Mul(t0, fp12Frobenius(t0));
        t0 = fp12Mul(t0, t1);
        BigInteger[] t2 = fp12Frobenius(f);
        BigInteger[] t3 = fp12Pow(fp12Mul(t2, f), FINAL_NINE);
        t0 = fp12Mul(t0, t3);
        t3 = fp12Sqr(fp12Sqr(f));
        t0 = fp12Mul(t0, t3);
        t2 = fp12Mul(fp12Sqr(t2), t1);
        t1 = fp12Mul(fp12Frobenius2(f), t2);
        t0 = fp12Mul(fp12Pow(t1, FINAL_A2), t0);
        return fp12Mul(fp12Frobenius3(f), t0);
    }

    /** G₂ 的射影点是否落在无穷远：只看 Z 是否为零。 */
    public static boolean twistIsInfinity(BigInteger[][] pt)
    {
        return fp2IsZero(pt[2]);
    }

    /** 射影 -> 仿射（同除 Z），只用于结果核对；配对内部一直保持射影。 */
    public static BigInteger[][] twistToAffine(BigInteger[][] pt)
    {
        BigInteger[] zInv = fp2Inv(pt[2]);
        return twistFromAffine(fp2Mul(pt[0], fp2Sqr(zInv)), fp2Mul(fp2Mul(pt[1], zInv), fp2Sqr(zInv)));
    }

    // ---------------------------------------------------------------- 模 n 的标量运算与"哈希 -> [1,n-1]"

    public static BigInteger modnAdd(BigInteger a, BigInteger b)
    {
        return a.add(b).mod(N);
    }

    public static BigInteger modnSub(BigInteger a, BigInteger b)
    {
        return a.subtract(b).mod(N);
    }

    public static BigInteger modnMul(BigInteger a, BigInteger b)
    {
        return a.multiply(b).mod(N);
    }

    public static BigInteger modnInv(BigInteger a)
    {
        return a.modInverse(N);
    }

    /**
     * GB/T 32915 的"把哈希当成 [1, n−1] 里的数"：取摘要的前 40 字节（320 bit）当整数，
     * <b>对 n−1 取模再加 1</b>。加 1 这一步不是装饰 —— 它保证 k、h 永远不等于 0，
     * 而 0 会让 r = e(P,Q)⁰ 变成单位元，签名立刻退化成公开可伪造。
     */
    public static BigInteger modnFromHash(byte[] ha)
    {
        BigInteger z = Calc.toBigInt(java.util.Arrays.copyOfRange(ha, 0, 40));
        return z.mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /**
     * H1(ID, hid) = 模 n 归约(SM3(0x01‖ID‖hid‖00000001) ‖ SM3(0x01‖ID‖hid‖00000002))。
     * 字母：0x01 是 H1 的用法前缀（H2 用 0x02，见 {@link #hash2}）；ID 是任意长度字节串；
     * hid 是用途分隔字节 0x01/0x02/0x03；00000001/00000002 是 4 字节大端<b>计数器</b> ct ——
     * SM3 只出 32 字节，不够一个 256 位以上均匀分布的标量，所以按计数器拼两段得 64 字节，
     * 实际只用前 40 字节（320 bit，比 n 略宽，偏差可忽略，见 {@link #modnFromHash}）。
     */
    public static BigInteger hash1(byte[] id, int hid)
    {
        byte[] ha = Calc.concat(
            Sm3.sm3(Calc.concat(new byte[]{ 0x01 }, id, new byte[]{ (byte)hid }, new byte[]{ 0, 0, 0, 1 })),
            Sm3.sm3(Calc.concat(new byte[]{ 0x01 }, id, new byte[]{ (byte)hid }, new byte[]{ 0, 0, 0, 2 })));
        return modnFromHash(ha);
    }

    /**
     * H2(M, w) = 同一个套路，前缀换成 0x02，把 384 字节的 w 接在消息后面。
     * 字母：M = 原文消息；w = g^r 序列化后的 384 字节（GT 元素）—— 把它接进来就是
     * "承诺绑定消息"的意思：换一个 w 就换一个 h，伪造者无法先定 h 再凑 w。
     */
    public static BigInteger hash2(byte[] message, byte[] w)
    {
        byte[] head = Calc.concat(new byte[]{ 0x02 }, message, w);
        byte[] ha = Calc.concat(
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 })));
        return modnFromHash(ha);
    }

    /**
     * SM3 计数器 KDF：T = SM3(Z‖1) ‖ SM3(Z‖2) ‖ …，一个 while 循环填够 klen 字节。
     * 字母：Z = 输入的种子（这里固定是 C1 的裸坐标 ‖ w ‖ ID 这类"共享秘密 + 上下文"）；
     * 1、2、… 是 4 字节大端计数器（counter = 1,2,3…，所以最长能派生 2^32·32 字节）；
     * klen = 要的字节数；KDF = key derivation function，密钥派生函数 —— 把"一个短秘密"
     * 拉成"任意长的、彼此独立的字节流"。为什么必须带计数器：只用 SM3(Z) 的话所有派生密钥
     * 都是同一个 32 字节，掩码段和 HMAC 密钥段就会重复使用。
     */
    public static byte[] kdfSm3(byte[] z, int klen)
    {
        byte[] out = new byte[klen];
        int off = 0;
        int counter = 1;
        while (off < klen)
        {
            byte[] block = Sm3.sm3(Calc.concat(z, Calc.toBytes(BigInteger.valueOf(counter), 4)));
            int take = Math.min(klen - off, block.length);
            System.arraycopy(block, 0, out, off, take);
            off += take;
            counter++;
        }
        return out;
    }

    /**
     * HMAC-SM3（分组 64 字节）：加密侧的 C3 完整性标签用它。
     * <pre>
     *   HMAC(k, m) = SM3( (k⊕opad) ‖ SM3( (k⊕ipad) ‖ m ) )
     *   k     密钥：这里是 K 的最后 32 字节（掩码段与认证段分开用，同一份 KDF 输出）
     *   ipad / opad 两个 64 字节的填充块，逐字节 0x36 / 0x5c（"in"/"out" Padding）
     *   ⊕     按位异或；过长密钥先压成 SM3(k)，再右侧补零到 64 字节
     * </pre>
     * 为什么要绕两层哈希：直接 SM3(k‖m) 会被长度扩展攻击 (length-extension) 伪造；
     * HMAC 用两个不同的掩码把密钥"包"成一个固定长度的伪随机前缀，只用"哈希函数"这一个
     * 抽象就拿到了带密钥的认证码 (MAC)。
     */
    public static byte[] hmacSm3(byte[] key, byte[] msg)
    {
        byte[] k = key.length > 64 ? Sm3.sm3(key) : key;
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        System.arraycopy(k, 0, ipad, 0, k.length);
        System.arraycopy(k, 0, opad, 0, k.length);
        for (int i = 0; i < 64; i++)
        {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5c;
        }
        return Sm3.sm3(Calc.concat(opad, Sm3.sm3(Calc.concat(ipad, msg))));
    }

    // ---------------------------------------------------------------- 点的字节化（和 GmSSL 的 DER/八位组表示一致）
    //
    // 三种"把数学对象变成字节"的约定，本文件的测试与 Provider 层都按它来：
    //   G₁ 点  0x04 ‖ x(32) ‖ y(32)                = 65 字节（0x04 = 未压缩点标记，国标沿用 SEC1 习惯）
    //   G₂ 点  0x04 ‖ x₁(32) ‖ x₀(32) ‖ y₁ ‖ y₀    = 129 字节；x = x₀ + x₁u，<b>高次分量 x₁ 在前</b>
    //   GT     12 个 Fp 系数，各 32 字节，下标 11→0 递减排列 = 384 字节
    //   无穷远点 单字节 0x00（避免和合法点混淆）
    // 下标 0/1 指 u 的次数（a₀ + a₁u），不是"第一个/第二个字节"；写反顺序是最常见的 SM9 实现 bug。

    /** G₁ 点 -> 0x04 ‖ x(32) ‖ y(32)；无穷远点用 0x00 打头，避免歧义。 */
    public static byte[] pointToOctets(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return new byte[]{ 0x00 };
        }
        return Calc.concat(new byte[]{ 0x04 }, Calc.toBytes(pt[0], 32), Calc.toBytes(pt[1], 32));
    }

    public static BigInteger[] pointFromOctets(byte[] octets)
    {
        if (octets.length != 65 || octets[0] != 0x04)
        {
            throw new IllegalArgumentException("G₁ 点必须是 0x04 开头的 65 字节");
        }
        return new BigInteger[]{
            Calc.toBigInt(ArraysRange(octets, 1, 33)), Calc.toBigInt(ArraysRange(octets, 33, 65)) };
    }

    /**
     * G₂ 点 -> 0x04 ‖ x₁ ‖ x₀ ‖ y₁ ‖ y₀（129 字节）。
     * 顺序里"高的 u 分量在前"是 GmSSL/标准的约定：Fp2 元素按 (a₁, a₀) 大端写，别写反。
     */
    public static byte[] twistToOctets(BigInteger[][] pt)
    {
        if (twistIsInfinity(pt))
        {
            return new byte[]{ 0x00 };
        }
        BigInteger[][] affine = twistToAffine(pt);
        return Calc.concat(new byte[]{ 0x04 },
            Calc.toBytes(affine[0][1], 32), Calc.toBytes(affine[0][0], 32),
            Calc.toBytes(affine[1][1], 32), Calc.toBytes(affine[1][0], 32));
    }

    public static BigInteger[][] twistFromOctets(byte[] octets)
    {
        if (octets.length != 129 || octets[0] != 0x04)
        {
            throw new IllegalArgumentException("G₂ 点必须是 0x04 开头的 129 字节");
        }
        BigInteger[] x = new BigInteger[]{
            Calc.toBigInt(ArraysRange(octets, 33, 65)), Calc.toBigInt(ArraysRange(octets, 1, 33)) };
        BigInteger[] y = new BigInteger[]{
            Calc.toBigInt(ArraysRange(octets, 97, 129)), Calc.toBigInt(ArraysRange(octets, 65, 97)) };
        return twistFromAffine(x, y);
    }

    private static byte[] ArraysRange(byte[] src, int from, int to)
    {
        return java.util.Arrays.copyOfRange(src, from, to);
    }

    // ================================================================ SM9 四条流程：主密钥、签名、加密、密钥交换
    //
    // 下面每个方法都对应 GB/T 32915 的一条公式，没有抽象层：调用者把标识、消息、随机数
    // 一个参数一个参数地传进来，看到的返回值就是标准里那个量。
    //
    // 三视角分工（记号见文件头"符号表（三）"）：
    //   KGC   持 ks / ke（主私钥标量）→ 唯一能算 ds、de 的人，也是唯一能伪造任何人的角色
    //   签名方 / 收信人   只持自己的 ds / de（点）+ 公开的主公钥 → signWithUserKey、decryptWithUserKey
    //   验签方 / 发信人   只要对方 ID + 公开主公钥 → verify、encryptToIdentity
    // 同一件事若有两种写法（sign 与 signWithUserKey），前者只是"当场把 ds 算出来"再走后者，
    // 所以两条路的输出字节必须完全相同 —— 测试就是拿这一点做断言的。

    /** 三个用途的 hid 字节：签名 0x01、密钥交换 0x02、加密 0x03。 */
    public static final int HID_SIGN = 0x01;
    public static final int HID_EXCH = 0x02;
    public static final int HID_ENC = 0x03;

    /** 主密钥的随机数：与 GmSSL 的 sm9_z256_rand_range 同构 —— 采 32 字节大端，>= n 就重采。 */
    public static BigInteger randScalar(java.util.Random rnd)
    {
        while (true)
        {
            byte[] buf = new byte[32];
            rnd.nextBytes(buf);
            BigInteger v = Calc.toBigInt(buf);
            if (v.compareTo(N) < 0)
            {
                return v;
            }
        }
    }

    /** 签名主公钥 Ppubs = ks·P2 ∈ G₂。 */
    public static BigInteger[][] signMasterPublicKey(BigInteger ks)
    {
        return twistMul(ks, P2);
    }

    /**
     * 私钥提取 ds = ks·(ks + H1(ID,0x01))⁻¹ · P1 ∈ G₁。
     * 分母是"主私钥 + 标识哈希"，这就是基于标识密码的特征：标识本身进了标量。
     */
    public static BigInteger[] signPrivateKeyExtract(BigInteger ks, byte[] id)
    {
        BigInteger t = modnAdd(hash1(id, HID_SIGN), ks);
        return pointMul(modnMul(ks, modnInv(t)), P1);
    }

    /**
     * 签名（GB/T 32915.2 的 A1~A4）：
     * <pre>
     *   g = e(P1, Ppubs);  w = g^r;  h = H2(M‖w);  l = (r − h) mod n;  S = l·ds
     * </pre>
     * 返回 97 字节：h(32) ‖ S(65，0x04 打头)。
     * <p><b>字母表 —— 每一步在做什么</b>
     * <pre>
     *   r    一次性随机标量 ∈ [1,n−1]，调用方传入（= SM2 里的 k）；泄露或复用就等于泄露私钥
     *   g    e(P1, Ppubs) ∈ GT：由公开量算出的基准元素，全网同一个 ID 集合里人人可算
     *   w    g^r ∈ GT：本轮签名的"承诺"(commitment)，384 字节；它进哈希，所以签名不可预测
     *   M    待签消息原文（字节数组）；‖ = 拼接
     *   h    H2(M‖w) 折出的标量 ∈ [1,n−1]："挑战"，把承诺与消息缝成 32 字节
     *   l    (r − h) mod n：把 r 藏进"r = l + h"里 —— 验签方只需要知道 l + h 就够了
     *   ds   用户签名私钥 ∈ G₁（只有 KGC 能用 ks 算出来）
     *   S    l·ds ∈ G₁：私钥点被标量 l 遮一层，攻击者无法从 S 反解 ds（又是 ECDLP）
     * </pre>
     * 为什么这套东西能验得过：见 {@link #verify} 里 u = g^l 的推导 —— 验签方算出的 w 与签名方
     * 算出的 w 是同一个 G^{r}，于是 H2(M‖w) 必然等于 h。
     */
    public static byte[] sign(byte[] message, byte[] id, BigInteger ks, BigInteger r)
    {
        // 主私钥视角只是"先把 ds 与 Ppubs 算出来"，真正的签名过程与用户视角一模一样
        return signWithUserKey(message, id,
            pointToOctets(signPrivateKeyExtract(ks, id)), twistToOctets(signMasterPublicKey(ks)), r);
    }

    /**
     * 签名（用户视角）：签名方手里只有 <b>ds</b> 和公开的 Ppubs，没有主私钥 ks ——
     * 这才是真实产品里的形态，GB/T 32915.2 的"用户私钥"结构就是 ds ‖ Ppubs 两个点。
     * JCE 层（{@code Signature.initSign}）走这条路；上面的 {@link #sign} 只是主密钥中心的便利封装。
     *
     * @param dsOctets    用户私钥点 ds（G₁，0x04 打头 65 字节）
     * @param ppubsOctets 签名主公钥 Ppubs（G₂，0x04 打头 129 字节）
     */
    public static byte[] signWithUserKey(byte[] message, byte[] id, byte[] dsOctets,
        byte[] ppubsOctets, BigInteger r)
    {
        BigInteger[] g = pairing(twistFromOctets(ppubsOctets), P1);
        byte[] wbuf = fp12ToBytes(fp12Pow(g, r));
        BigInteger h = hash2(message, wbuf);
        BigInteger l = modnSub(r, h);
        if (l.signum() == 0)
        {
            // GB/T 32915.2 要求这里回到 A2 重采 r。GmSSL 的 sm9_do_sign 是在 do-while 里
            // 调 sm9_z256_fp12_pow(g, g, r) —— 原地覆盖 g，重采后用的其实是 g^(r1·r2)，
            // 属于它的实现 bug（发生概率约 2^-256）。本实现选择直接抛出来，绝不复制这个 bug。
            throw new IllegalArgumentException("l = 0：这个 r 不能用，必须重采（GmSSL 在这里重试）");
        }
        return Calc.concat(Calc.toBytes(h, 32),
            pointToOctets(pointMul(l, pointFromOctets(dsOctets))));
    }

    /**
     * 验签（B1~B5）：验签方只要 Ppubs，不需要主私钥。
     * <pre>
     *   P' = H1(ID,0x01)·P2 + Ppubs;   u = e(S, P');   t = g^h;   w = u·t;   核对 H2(M‖w) == h
     *   代入 S = l·ds、ds = ks/(ks+h1)·P1 可得 u = g^l，于是 w = g^{l+h} = g^r —— 与签名侧同一个 w。
     * </pre>
     * <p><b>字母表</b>：{@code signature} = h(32)‖S(65) 那 97 字节；h、S 从里面拆出来；
     * {@code ppubs} = 签名主公钥 ks·P2 ∈ G₂；{@code g} = e(Ppubs, P1) ∈ GT（与签名侧同一个）；
     * {@code pp} = P' ∈ G₂；{@code u,t,w} ∈ GT，w 最终序列化成的 384 字节就是 H2 的第二段输入。
     * <p><b>推导（为什么 u = g^l）</b>：
     * <pre>
     *   P' = h1·P2 + Ppubs = h1·P2 + ks·P2 = (h1 + ks)·P2      ← 两个项同在 G₂，可以合并标量
     *   S  = l·ds = l · ks·(ks + h1)⁻¹ · P1
     *   u  = e(S, P') = e(P1, P2)^{ l·ks·(ks+h1)⁻¹ · (h1+ks) } = e(P1, P2)^{l·ks}
     *                                                          └ (ks+h1) 上下相消 ┘
     *   g  = e(P1, Ppubs) = e(P1, ks·P2) = e(P1, P2)^{ks}      ⇒  u = g^l
     *   w  = u·t = g^l · g^h = g^{l+h} = g^{(r−h)+h} = g^r                          ← 签名侧的 w
     * </pre>
     * 相消的机理和密钥交换那次一模一样：ds 里的 (ks+h1)⁻¹ 遇到 P' 里的 (ks+h1) 就没了，
     * 而 P' 之所以含 (ks+h1)，是因为把"ID"折进了公钥点 —— 这正是基于标识密码的定义。
     * <p>为什么 B3/B4 的合法性检查不能省：见方法体里那句注释（h 的范围、S 是否在曲线上）。
     */
    public static boolean verify(byte[] message, byte[] signature, byte[] id, BigInteger[][] ppubs)
    {
        BigInteger h = Calc.toBigInt(ArraysRange(signature, 0, 32));
        BigInteger[] S = pointFromOctets(ArraysRange(signature, 32, 97));
        if (h.signum() <= 0 || h.compareTo(N) >= 0 || S.length == 0 || !pointIsOnCurve(S))
        {
            // 标准 B3/B4 的合法性检查：h ∈ [1,n−1]、S ∈ G₁。少写这一句，畸形签名就可能
            // 在配对里走进"无穷远点分支"，把"验不过"变成"抛异常"甚至"验得过"。
            return false;
        }
        BigInteger[] g = pairing(ppubs, P1);
        BigInteger[] t = fp12Pow(g, h);
        BigInteger[][] pp = twistAffineAdd(twistMul(hash1(id, HID_SIGN), P2), ppubs);
        byte[] wbuf = fp12ToBytes(fp12Mul(pairing(pp, S), t));
        return h.equals(hash2(message, wbuf));
    }

    /** 加密主公钥 Ppube = ke·P1 ∈ G₁。 */
    public static BigInteger[] encMasterPublicKey(BigInteger ke)
    {
        return pointMul(ke, P1);
    }

    /**
     * 私钥提取 de = ke·(ke + H1(ID,hid))⁻¹ · P2 ∈ G₂。加密用 hid = 0x03，密钥交换用 0x02，
     * 同一个主密钥给两个用途导出<b>两把不同的私钥</b> —— 这就是 hid 存在的全部理由。
     */
    public static BigInteger[][] privateKeyExtract(BigInteger ke, byte[] id, int hid)
    {
        BigInteger t = modnAdd(hash1(id, hid), ke);
        return twistMul(modnMul(ke, modnInv(t)), P2);
    }

    /** KEM 里的 Q_B = H1(ID,0x03)·P1 + Ppube —— 标识直接拼进公钥点，所以没有证书。 */
    public static BigInteger[] kemQ(BigInteger ke, byte[] id)
    {
        return pointAdd(pointMul(hash1(id, HID_ENC), P1), encMasterPublicKey(ke));
    }

    /**
     * KEM 加密（A1~A7）：C1 = r·Q；w = e(Ppube, P2)^r；K = KDF(C1_x‖C1_y‖w‖ID, klen)。
     * 返回值 = C1(0x04 打头 65 字节) ‖ K(klen 字节)。
     *
     * <p>r 由调用方给（对应 GmSSL 循环里的 A2）：标准还要求 K 全零时回到 A2 重采，
     * GmSSL 的重试用同一个 {@code C} 当 Q 的暂存再乘一遍，会算成 r₂·(r₁·Q) —— 这里不复制该行为。
     */
    public static byte[] kemEncrypt(BigInteger ke, byte[] id, int klen, BigInteger r)
    {
        return kemEncryptToIdentity(id, pointToOctets(encMasterPublicKey(ke)), klen, r);
    }

    /**
     * KEM 加密（加密方视角）：只需要收信人的 ID 与<b>公开</b>的 Ppube —— 主私钥 ke 全程不出现，
     * 这正是基于标识加密"发信人不需要向 KGC 申请任何东西"的原因。JCE 的 {@code Cipher.doFinal} 走这条路。
     * <pre>
     *   A1~A7：Q = h1(ID,0x03)·P1 + Ppube;  C1 = r·Q;  w = e(Ppube, P2)^r;  K = KDF(C1_x‖C1_y‖w‖ID, klen)
     * </pre>
     * 字母：Q ∈ G₁ 是收信人"带标识的公钥点"；r ∈ [1,n−1] 是一次性随机标量（明文长度无关）；
     * C1 ∈ G₁ 就是"这次的临时公钥"，65 字节 0x04 打头；w ∈ GT（384 字节）是双方共享的秘密；
     * K 是 KDF 拉伸出来的密钥流；ID 进 KDF 是为了把密钥绑到"这个收信人"身上。
     * <p>为什么只有收信人解得开：w 写成 e(Ppube,P2)^r 时用的是<b>公开</b>量，但等价的算法是
     * e(C1, de)（见 {@link #kemDecryptWithUserKey}）—— 后者必须有主私钥导出的 de。
     *
     * @param ppubeOctets 加密主公钥 Ppube（G₁，0x04 打头 65 字节）
     */
    public static byte[] kemEncryptToIdentity(byte[] id, byte[] ppubeOctets, int klen, BigInteger r)
    {
        BigInteger[] ppube = pointFromOctets(ppubeOctets);
        byte[] c1 = pointToOctets(pointMul(r, pointAdd(pointMul(hash1(id, HID_ENC), P1), ppube)));
        byte[] wbuf = fp12ToBytes(fp12Pow(pairing(P2, ppube), r));
        byte[] k = kdfSm3(Calc.concat(ArraysRange(c1, 1, 65), wbuf, id), klen);
        return Calc.concat(c1, k);
    }

    /**
     * KEM 解密（B1~B4）：w = e(C1, de)，其余与加密侧逐字节相同。
     * B1 的"先检查 C1 在 G₁ 上"不是可选的 —— 塞一个不在曲线上的点进来，配对会算出
     * 一个跟真密钥无关的 w，攻击者就能靠"解密成功与否"的信号做错误预言攻击。
     */
    public static byte[] kemDecrypt(BigInteger ke, byte[] id, int klen, byte[] c1)
    {
        return kemDecryptWithUserKey(id, twistToOctets(privateKeyExtract(ke, id, HID_ENC)), klen, c1);
    }

    /**
     * KEM 解密（收信人视角）：手里只有自己的 de，没有主私钥 ke。
     * <p><b>为什么 e(C1, de) 就是加密侧那个 w = e(Ppube,P2)^r</b>：
     * <pre>
     *   C1 = r·Q = r·(h1·P1 + ke·P1) = r·(ke + h1)·P1
     *   de = ke·(ke + h1)⁻¹·P2
     *   e(C1, de) = e(P1,P2)^{ r(ke+h1) · ke(ke+h1)⁻¹ } = e(P1,P2)^{ke·r} = e(ke·P1, P2)^r = w
     *                        └────── (ke + h1) 上下相消 ──────┘
     * </pre>
     * 也就是"公钥点里的 (ke+h1)"与"私钥点里的 (ke+h1)⁻¹"抵消，剩下谁都算不出来的 G^{ke·r}。
     *
     * @param deOctets 用户私钥点 de（G₂，0x04 打头 129 字节）
     */
    public static byte[] kemDecryptWithUserKey(byte[] id, byte[] deOctets, int klen, byte[] c1)
    {
        BigInteger[] point = pointFromOctets(c1);
        if (!pointIsOnCurve(point))
        {
            throw new IllegalArgumentException("C1 不在 G₁ 上：拒绝（GB/T 32915.3 的 B1 步）");
        }
        byte[] wbuf = fp12ToBytes(pairing(twistFromOctets(deOctets), point));
        return kdfSm3(Calc.concat(ArraysRange(c1, 1, 65), wbuf, id), klen);
    }

    /**
     * 完整 IBBE（主密钥视角）：返回 C1(65) ‖ C3(32) ‖ C2。
     */
    public static byte[] encrypt(BigInteger ke, byte[] id, byte[] message, BigInteger r)
    {
        return encryptToIdentity(id, pointToOctets(encMasterPublicKey(ke)), message, r);
    }

    /**
     * 完整 IBBE（GmSSL 的 sm9_do_encrypt）：K 一次取 <b>明文长度 + 32</b> 字节，
     * 前 len 字节当异或掩码，后 32 字节当 HMAC-SM3 的密钥 —— 没有分组密码，只有一次异或。
     * 返回 C1(65) ‖ C3(32) ‖ C2。
     */
    public static byte[] encryptToIdentity(byte[] id, byte[] ppubeOctets, byte[] message, BigInteger r)
    {
        byte[] full = kemEncryptToIdentity(id, ppubeOctets, message.length + 32, r);
        byte[] c1 = ArraysRange(full, 0, 65);
        byte[] kbuf = ArraysRange(full, 65, full.length);
        byte[] c2 = Calc.xor(ArraysRange(kbuf, 0, message.length), message);
        byte[] c3 = hmacSm3(ArraysRange(kbuf, message.length, message.length + 32), c2);
        return Calc.concat(c1, c3, c2);
    }

    /** 解密（主密钥视角）：先用 de 还原同一个 K，核 C3，再异或回来。 */
    public static byte[] decrypt(BigInteger ke, byte[] id, byte[] c1, byte[] c2, byte[] c3)
    {
        return decryptWithUserKey(id, twistToOctets(privateKeyExtract(ke, id, HID_ENC)), c1, c2, c3);
    }

    /** 解密（收信人视角）：只有 de。C3 不匹配或 C1 不在曲线上都直接抛异常，绝不返回明文。 */
    public static byte[] decryptWithUserKey(byte[] id, byte[] deOctets, byte[] c1, byte[] c2, byte[] c3)
    {
        byte[] kbuf = kemDecryptWithUserKey(id, deOctets, c2.length + 32, c1);
        byte[] mac = hmacSm3(ArraysRange(kbuf, c2.length, c2.length + 32), c2);
        if (!java.util.Arrays.equals(mac, c3))
        {
            throw new IllegalArgumentException("C3 校验失败：密文被改过");
        }
        return Calc.xor(ArraysRange(kbuf, 0, c2.length), c2);
    }

    /**
     * 密钥交换的三个 GT 元素（GmSSL 的 sm9_key_exchange_compute_g）。
     * 两个角色算出的 <b>字节序列完全相同</b>，靠的是双线性：
     * <pre>
     *   发起方 A：g1 = e(P2,Ppube)^{rA} = G^{ke·rA};  g2 = e(deA,RB) = G^{ke·rB};  g3 = g2^{rA} = G^{ke·rA·rB}
     *   应答方 B：g1 = e(deB,RA)         = G^{ke·rA};  g2 = e(P2,Ppube)^{rB} = G^{ke·rB}; g3 = g1^{rB}
     * 所以 g1 永远是 A 的那一项，g2 永远是 B 的那一项 —— 变量名按角色换了，字节位置没换。
     * </pre>
     * <p><b>字母表</b>
     * <pre>
     *   G      配对的基准值 e(P1, P2) ∈ GT（谁都不用算它，只是纸面上方便写指数）
     *   ke     加密主私钥；Ppube = ke·P1 ⇒ e(P2, Ppube) = G^{ke}（双线性把 ke 提到指数上）
     *   rA,rB  双方各自的一次性随机标量；ownR/peerR = 自己/对方的临时点 R = r·Q
     *   ownId  自己的标识；de = ke·(ke + H1(ownId,0x02))⁻¹·P2 —— 用<b>自己</b>的 ID 提取
     *   h1     简写 H1(ID, 0x02)；下标 A/B 表示是谁的标识
     *   isInitiator 角色开关：只决定 g1/g2 谁先谁后，不改变任何一次配对计算
     * </pre>
     * <p><b>为什么 e(de_A, R_B) = G^{ke·rB}（整场交换唯一的关键一步）</b>：
     * <pre>
     *   R_B = rB·Q_A = rB·(h1_A·P1 + ke·P1) = rB·(ke + h1_A)·P1     ← B 用 A 的 ID 造 R_B！
     *   de_A = ke·(ke + h1_A)⁻¹ · P2
     *   e(de_A, R_B) = e(P2, P1)^{ ke·(ke+h1_A)⁻¹ · rB·(ke+h1_A) } = G^{ke·rB}
     *                        └────── (ke + h1_A) 上下相消 ──────┘
     * </pre>
     * 相消之所以发生，全靠 {@link #exchEphemeral} 里"Q 用对方的标识"这一条规矩：我发出的
     * R 里含 (ke + h1_对方)，而对方手里的 de 里含 (ke + h1_对方)⁻¹，两边恰好互为倒数。
     * 少拿一个私钥就算不出 G^{ke·r?} —— 这就是交换的"身份绑定"：密钥确认标签（{@link
     * #exchConfirmTag}）之后再证明对方真持有 de。
     * <p>出参：{@code gOut[0..2]} 各 384 字节（GT 的字节形状），{@code rOut[0]} = RA(64)、
     * {@code rOut[1]} = RB(64) —— 去掉 0x04 前缀后的裸 x‖y，因为 KDF 的输入按标准就是裸坐标。
     */
    public static void exchComputeG(boolean isInitiator, BigInteger ke, byte[] ownId,
        BigInteger r, BigInteger[] ownR, BigInteger[] peerR, byte[][] gOut, byte[][] rOut)
    {
        BigInteger[] ppube = encMasterPublicKey(ke);
        BigInteger[][] de = privateKeyExtract(ke, ownId, HID_EXCH);
        BigInteger[] ra;
        BigInteger[] rb;
        BigInteger[] base = pairing(P2, ppube);
        // 两个角色都是"自己的私钥 de 去配对方发来的 R"，只是这一项落在 g1 还是 g2 上不同
        BigInteger[] cross = pairing(de, peerR);
        if (isInitiator)
        {
            ra = ownR;
            rb = peerR;
            gOut[0] = fp12ToBytes(fp12Pow(base, r));
            gOut[1] = fp12ToBytes(cross);
            gOut[2] = fp12ToBytes(fp12Pow(cross, r));
        }
        else
        {
            ra = peerR;
            rb = ownR;
            gOut[0] = fp12ToBytes(cross);
            gOut[1] = fp12ToBytes(fp12Pow(base, r));
            gOut[2] = fp12ToBytes(fp12Pow(cross, r));
        }
        rOut[0] = ArraysRange(pointToOctets(ra), 1, 65);
        rOut[1] = ArraysRange(pointToOctets(rb), 1, 65);
    }

    /** 会话密钥 = KDF(ID_A ‖ ID_B ‖ RA ‖ RB ‖ g1 ‖ g2 ‖ g3, klen)。注意 ID 顺序是 A 在前，与角色无关。 */
    public static byte[] exchSessionKey(boolean isInitiator, BigInteger ke, byte[] ownId, byte[] peerId,
        BigInteger r, BigInteger[] ownR, BigInteger[] peerR, int klen, byte[][] gOut, byte[][] rOut)
    {
        exchComputeG(isInitiator, ke, ownId, r, ownR, peerR, gOut, rOut);
        byte[] idA = isInitiator ? ownId : peerId;
        byte[] idB = isInitiator ? peerId : ownId;
        return kdfSm3(Calc.concat(idA, idB, rOut[0], rOut[1], gOut[0], gOut[1], gOut[2]), klen);
    }

    /**
     * 确认标签：hash = SM3(g2‖g3‖ID_A‖ID_B‖RA‖RB)，tag = SM3(prefix‖g1‖hash)。
     * 发起方自己的标签前缀 0x83，应答方 0x82；验对方时传对方那个前缀。
     */
    public static byte[] exchConfirmTag(byte[] g1, byte[] g2, byte[] g3,
        byte[] ra, byte[] rb, byte[] idA, byte[] idB, int prefix)
    {
        byte[] hash = Sm3.sm3(Calc.concat(g2, g3, idA, idB, ra, rb));
        return Sm3.sm3(Calc.concat(new byte[]{ (byte) prefix }, g1, hash));
    }

    /** 交换里 A 的临时点 RA = rA·(H1(ID_B,0x02)·P1 + Ppube)：Q 用的是<b>对方</b>的标识。 */
    public static BigInteger[] exchEphemeral(BigInteger ke, byte[] peerId, BigInteger r)
    {
        return pointMul(r, pointAdd(pointMul(hash1(peerId, HID_EXCH), P1), encMasterPublicKey(ke)));
    }
}
