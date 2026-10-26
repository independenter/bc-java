package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Random;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * SM9 最难的那一块 —— <b>Fp12 塔与 ate 配对</b> —— 的过程版实现与验证。
 *
 * <p><b>符号表 —— 域与群：谁的元素长什么样</b>
 * <pre>
 *   Fp          素域 (prime field)：元素就是一个 [0, p) 里的整数，加减乘除之后一律 mod p；
 *               p 是 256-bit 素数（Sm9Math.P）。"素域"= 元素个数是素数的域，所以它没有真子域、
 *               非零元全都可逆
 *   Fp*         去掉 0 之后的乘法群；同理 Fp12* = Fp12 里所有非零元素构成的乘法群，阶为 p¹²−1
 *   u, v, w     三层扩域各自引入的"形式符号 (symbol)"，每个只带一条化简规则：
 *               u² = −2（Fp2）、v² = u（Fp4）、w³ = v（Fp12）。整条塔上几百行乘法，
 *               说到底只有"普通多项式乘法 + 这三条回代"
 *   Fp2         = Fp[u]/(u²+2)：元素 a₀ + a₁u，存成 BigInteger[2]{a₀, a₁}（"扩域"= 把 Fp 放大成
 *               低次多项式的全体，模掉一个不可约多项式；u²+2 在 Fp 里不可约，所以真构成域）
 *   Fp4         = Fp2[v]/(v²−u)：元素 b₀ + b₁v，每个 bᵢ 仍是 Fp2 ⇒ BigInteger[4]
 *   Fp12        = Fp4[w]/(w³−v)：元素 c₀ + c₁w + c₂w²，每个 cᵢ 仍是 Fp4 ⇒ BigInteger[12]
 *   i           扁平下标规则：12 个 Fp 系数分别代表单项式 u^a·v^b·w^c（a、b ∈ {0,1}，c ∈ {0,1,2}），
 *               下标 i = u位 + 2·v位 + 4·w位。例：1 = u、2 = v、3 = u·v、4 = w、6 = v·w、8 = w²、
 *               11 = u·v·w²。序列化按 i = 11 递减到 0 写，每个系数 32 字节 ⇒ 384 字节
 *   ⁻¹          域逆：a·a⁻¹ = 1。Fp/Fp2/Fp4 各直接用一次扩展欧几里得；Fp12 用"三次共轭 + 范数"
 *               把 12 次域的逆压回 Fp4 层，所以一次 fp12Inv = 一次 Fp4 逆 + 若干 Fp2/Fp 逆
 *   n           G₁、G₂、GT 三条群的公共阶（Sm9Math.N，256-bit 素数）；所有标量都在 Z_n 里运算
 *   阶 (order)   群（或单个元素）的元素个数。"素数阶群"里非单位元的阶必然等于群的阶 —— 测试① 就是在用这条
 *   生成元        一个元素 G，使得 1·G, 2·G, …, (n−1)·G 恰好铺满整个群（记号 ⟨G⟩）
 *   G₁          E(Fp): y² = x³ + 5 的 n 阶子群，生成元 P1；仿射点 = BigInteger[2]，无穷远点 = 空数组
 *   G₂          扭曲曲线 (twist) E'(Fp2): y² = x³ + 5u 的 n 阶子群，生成元 P2；射影点 = BigInteger[3][2]
 *               = {X, Y, Z}，无穷远 ⇔ Z 在 Fp2 中为 0
 *   GT          Fp12* 里唯一的 n 阶子群 = {g : g^n = 1}，配对的落点；元素展平 384 字节
 *   e(P, Q)     双线性配对 (bilinear pairing)：G₁ × G₂ → GT，见下面第二条符号表
 *   ‖           字节串拼接（concatenate），不是异或
 * </pre>
 *
 * <p><b>符号表 —— ate 配对的流水线（Sm9Math.pairing / finalExponent）</b>
 * <pre>
 *   u           GB/T 32915.1 里那个 63-bit 曲线参数（p、n 都由它生成）。反解 6u² + 1 = p + 1 − n
 *               得 |u| = 0x600000000058F98A，本文件只用 |6u+2|，符号不影响指数大小
 *   s = 6u+2    ate 配对的 Miller 长度（Miller length）= 41505174165881477438
 *   ABITS       主线扫的那串数码，65 个字符：'0' = 只倍点，'1' = 再加 Q，'2' = 减 Q（即数码 −1）。
 *               递推是 m ← 2m + d（每步"先平方 + 倍点"，位权为 2），串首还隐含一个最高位 1
 *               （因为累加起点取 T = Q，不是无穷远点）。核对过：2^65 + Σ dᵢ·2^(64−i) = 6u+2，
 *               所以整条循环跑完 T 恰好 = (6u+2)·Q。数码集是 {−1, 0, +1} 三个值，标准与 GmSSL
 *               把这串写作"|6u+2| 的带符号三进制"（NAF = non-adjacent form，带符号数码展开的一类）；
 *               命名之争不用管，这条循环要保证的只有"跑完 T = s·Q 且 f 与 s 的展开一一对应"
 *   T           主线里的累计点（G₂/扭曲曲线上，射影坐标），从 Q 出发按上面的递推被倍、加、减
 *   f           Miller 函数 (Miller function) 的累乘器，一个 Fp12 元素，初值 = 1
 *   l_{A,B}     线函数 (line function)：过扭曲点 A、B 的那条直线在 P ∈ G₁ 处的取值。
 *               实现里存成 3 个 Fp2 系数 lw[0]、lw[1]、lw[2]，摊进 Fp12 后是稀疏的：
 *               L = lw[0] + lw[2]·v + lw[1]·w²，非零系数只落在下标 0,1 / 2,3 / 8,9
 *               （见 Sm9Math.fp12FromLine；lw 的下标与 Fp12 下标不一致，最容易抄反的就是这里）
 *   evalGTangent 切线（A = B = T）评估 + 把 T 更新为 2T；evalGLine 割线（A = T，B = 要加上的点）
 *               评估 + 把 T 更新为 T + B。两者都"算线和更新点一次做完"，省掉一半中间量
 *   π₁, π₂      Frobenius 映射：π₁(Q) = Q 的 p 次（Frobenius）像，π₂(Q) = Q 的 p² 次像。
 *               ate 配对收尾要再补两条线 l_{T,π₁Q}(P) 与 l_{T,−π₂Q}(P)，才与 GB/T 32915 的定义一致
 *   β, α₁..α₅   预计算的 Fp 常数（标准附录给死值），作用是把"p 次幂"降级成"共轭 + 乘常数"。
 *               它们的来历：塔上 u^p、v^p、w^p 各等于"原符号 × 某个 Fp 常数"，这些常数就是 α、β。
 *               α₃ = β 不是把同一个数抄了两遍：塔规则必然给出 α³ = β
 *   a₂, a₃      最终幂难算部分的两个小辅助指数（Sm9Math.FINAL_A2 约 128 bit、FINAL_A3 约 65 bit），
 *               配合 9 次幂与三次 π 组合出 (p⁴−p²+1)/n 那一坨
 * </pre>
 *
 * <p>SM9 是"基于标识"的密码：没有证书，公钥就是用户的标识（一串字节）。之所以行得通，
 * 全靠一对满足双线性／非退化／可计算的映射：
 * <pre>
 *   e: G₁ × G₂ → Fp12*,   e(a·P, b·Q) = e(P, Q)^{ab}
 * </pre>
 * 逐字母说清：P 是 G₁ 里的点（仿射，来自 Fp）、Q 是 G₂ 里的点（射影，来自 Fp2）、
 * a、b 是 Z_n 里的标量、e(P,Q) 的结果是 Fp12 里的一个元素（384 字节）；
 * 左边的 a·P、b·Q 是椭圆曲线的标量乘，右边的 ^{ab} 是 Fp12 里的普通幂 ——
 * <b>双线性 (bilinear) 就是把"群里的乘法"翻译成"域里的指数"</b>，这正是整套 SM9 唯一的魔法。
 * 三条要求：<b>双线性</b>（上面那条）、<b>非退化 (non-degenerate)</b>（存在 P、Q 使 e(P,Q) ≠ 1，
 * 否则什么都证不了）、<b>可计算 (computable)</b>（有像 Miller 循环这样的多项式时间算法）。
 * G₁ = E(Fp): y² = x³ + 5，G₂ = E'(Fp2): y² = x³ + 5u。两个群都取 n 阶。
 * 有了这条式子，"标量乘法"就能被搬到 Fp12 的"普通幂"上比较，于是
 * {@code e(ks/(ks+H1)·P1, (H1+ks)·P2) = e(P1,P2)^{ks}} —— 私钥提取里那个刺眼的除法被抵消掉了
 * （ks、ke 是主私钥标量，H1 = H1(ID,hid) 也是 Z_n 里的数，测试⑤ 会把这条恒等式单独跑一遍）。
 *
 * <p><b>为什么需要 12 次扩域才放得下配对像（嵌入次数 embedding degree = 12）</b>：
 * 配对要把"G₁/G₂ 上的离散对数"搬进"Fp12* 里的离散对数"，所以 n 阶子群必须真的存在于某个扩张里。
 * Fp^k 的乘法群阶是 p^k − 1，由柯西定理它含 n 阶子群当且仅当 n | p^k − 1（n 是素数）。
 * 拿 Sm9Math 里的 p、n 逐个试 k = 1, 2, …：k = 1 到 11 全都不能整除，最小的是 <b>k = 12</b>，
 * 这个最小的 k 就叫做<b>嵌入次数</b>。域必须开到 Fp12，配对像才有地方放；塔按 2 · 2 · 3 = 12
 * 的次数一层层搭起来（Fp → Fp2 → Fp4 → Fp12），既刚好到 12，又让每个元素能拆成小系数分别乘。
 * <p>顺带一个有用的推论：p¹² − 1 = (p⁶ − 1)(p⁶ + 1)，而 n ∤ p⁶ − 1、n | p¹² − 1，
 * 所以 <b>n | p⁶ + 1</b>。这正是最终幂第一步 f^(p⁶−1) = π₆(f)/f 能把结果压进"分圆子群"
 * （阶整除 p⁶+1 的那个子群）的原因 —— 后半段难算部分就在这个更小的集合里做。
 *
 * <p><b>安全级别约 128 bit</b>：p 与 n 都是 256 bit。攻击这套 SM9 的最快已知方法是解 G₁/G₂ 上的
 * 离散对数（把问题搬到 GT 上会更慢），代价约 2¹²⁸ 量级；这与 3072-bit RSA、AES-128 大致同一档，
 * 所以标准把 SM9 定位在 128 bit 安全强度。域长度（384 字节）比标量长度（32 字节）大十倍，
 * 就是"用体积换配对可用"的直接体现。
 *
 * <p><b>参数顺序的坑（读代码前先记住）</b>：Java 里的调用是 {@code pairing(Q, P)}，第一个参数是
 * <b>G₂ 的射影点 Q</b>，第二个才是 <b>G₁ 的仿射点 P</b>；而数学记号按惯例写成 {@code e(P, Q)}，
 * G₁ 在前。所以 {@code pairing(twistMul(ks, P2), P1)} 读作 e(P1, ks·P2)。本文件的注释一律用
 * 数学记号 e(P, Q)，对照代码时请按上面这条规则换顺序。
 *
 * <p><b>本测试三组 KAT 向量各自测的路径</b>（KAT = known-answer test，已知答案测试：
 * 把标准/参考实现里"固定输入 → 固定输出"的样例硬编码进来，只问字节是否一致，专门抓抄错常数、
 * 写反顺序、下标错位这类"逻辑全对但结果全错"的 bug）。样例全部出自 GmSSL 的
 * {@code tests/sm9test.c} —— GmSSL 是 GB/T 32915（SM9）的参考实现，本文件拿它当裁判而不是当依据：
 * <pre>
 *   PAIRING1  e(P1, ks·P2)        —— 生成元 × 生成元的倍数，走完整主线 + 最终幂，最常用的形状
 *   PAIRING2  e(RA, deB)          —— 两个都<b>不是</b>生成元的点（密钥交换样例里的临时点与用户私钥），
 *                                   这条能抓到"只在生成元上才碰巧对"的实现
 *   PAIRING3  e(Ppube, P2)^{rB}   —— 配对<b>之后</b>再取 n 阶以内的幂，验证结果真的落在 GT 里
 * </pre>
 * 每一组都是 12 行 × 32 字节 = 384 字节，顺序是扁平下标 c₁₁ 递减到 c₀（与 GmSSL 的序列化一致）。
 * 只要有一个常数（α、β、abits、线函数的下标）抄反，384 字节就会全部对不上。
 *
 */
@Slf4j
public class Sm9PairingEssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /**
     * 标准样例里 Alice 的标识与签名主私钥 ks（GmSSL: hex_ks）。
     * ID_ALICE = "Alice" = 41 6C 69 63 65（5 字节，纯 ASCII，不做补齐）；
     * HEX_KS 是 Z_n 里的标量（32 字节大端），测试⑤ 拿它算 ds，测试④ 拿它算 ks·P2。
     */
    private static final byte[] ID_ALICE = "Alice".getBytes();
    private static final BigInteger HEX_KS = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
    /**
     * 密钥交换用的主私钥（GmSSL: hex_kex），它的 ke·P1 就是标准样例里的 hex_Ppube。
     * 记号：kex 是标量 ∈ Z_n；Ppube = kex·P1 ∈ G₁（65 字节），下面 PPUBE_POINT 存的就是它的 x ‖ y。
     */
    private static final BigInteger HEX_KEX = new BigInteger("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", 16);

    /**
     * e(P1, ks·P2) 的期望值：12 行、每行一个 Fp 系数，顺序是 c₁₁ 递减到 c₀（与 GmSSL 的序列化一致）。
     * <p>读法：这里 P = P1 ∈ G₁（仿射，第二个实参）、Q = ks·P2 ∈ G₂（射影，第一个实参）；
     * 结果 c = c₀ + c₁w + c₂w² ∈ Fp12 展平成 384 字节，"c₁₁ 在前"意思是<b>扁平下标从 11 写到 0</b>，
     * 而 c₁₁ 是单项式 u·v·w² 的系数、c₀ 是常数项（见类注释的下标规则 i = u位 + 2·v位 + 4·w位）。
     * 第一行是 c₁₁、最后一行是 c₀，中间那 10 行的 c₈、c₆ 等按同一个规则各自对应一个混合单项式。
     */
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

    /**
     * hex_deB（G₂ 私钥点，4 行 = x₁,x₀,y₁,y₀）与 hex_RA（G₁ 点）配对得到的 e(RA, deB)。
     * <p>两个输入都取自 GmSSL 的<b>密钥交换</b>样例（见 {@link Sm9ExchangeEssenceTest}）：
     * deB = ke_x·(ke_x + H1("Bob",0x02))⁻¹·P2 ∈ G₂，其中 ke_x 就是上面的 HEX_KEX；
     * RA = rA·Q_B ∈ G₁，Q_B = H1("Bob",0x02)·P1 + Ppube。
     * x₁、x₀ 是 x 这个 Fp2 元素 a₀ + a₁u 的两个 Fp 系数（a₁ = x₁ 是 u 分量），
     * 序列化时高次在前 —— 这一组的字节顺序如果写反，本文件测试④立刻花掉。
     */
    private static final String DE_B =
        "74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"
            + "01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"
            + "44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"
            + "8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539";
    // RA_POINT = G₁ 的仿射点，2 行 = x(32 字节) ‖ y(32 字节)；测试④ 在外面拼上 0x04 前缀再解成点。
    private static final String RA_POINT =
        "7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"
            + "A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599";
    // PAIRING2 = e(RA, deB) 的答案，同样 12 行 384 字节、c₁₁ 递减到 c₀。
    // 这条样例的价值在于两个点都不是生成元：如果 Miller 循环里某条线的符号、或最终幂的某一步
    // 只在"输入正好是 P1/P2"时才碰巧抵消，这一组就会立刻暴露出来。
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

    /**
     * e(Ppube, P2)^{rB}：交换协议里"应答方的那一格"。
     * <p>PPUBE_POINT 是加密/交换主公钥 Ppube = kex·P1 ∈ G₁ 的 2 行（x ‖ y，各 32 字节），
     * 它同时是 GmSSL 的 hex_Ppube 样例 —— 测试⑥ 还拿它核对字节序。
     * 下面 RB 是应答方 B 的临时标量 rB ∈ Z_n（32 字节大端），PAIRING3 是 g₂ 的期望字节。
     */
    private static final String PPUBE_POINT =
        "9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"
            + "54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210";
    // RB = 应答方的临时私钥 rB（一次性随机标量，用完即弃），测试④ 用它对配对结果再取一次幂。
    private static final BigInteger RB = new BigInteger("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE", 16);
    // PAIRING3 = e(Ppube, P2)^{rB} = e(P1,P2)^{kex·rB} 的答案（12 行、384 字节）。
    // 这一组专门验证"最终幂之后还能继续在 GT 里做幂运算"：若某个系数落错了下标，
    // fp12Pow 的平方-乘路径就会在 256 次迭代里把错误放大成完全不同的 384 字节。
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

    /**
     * 测试①：常数自检 —— 生成元真的在曲线上，而且阶正好是 n。
     * <pre>
     *   P1 = (x, y)     G₁ 的生成元，两个坐标都是 Fp 里的数；曲线 E: y² = x³ + 5（a = 0、b = 5）
     *   P2 = {X,Y,Z}    G₂ 的生成元，三个分量都是 Fp2 里的数；Z = (1,0) 表示它就是仿射的
     *   E': y² = x³ + 5u   扭曲曲线 (twist)：把 b = 5 换成 5u，系数搬到 Fp2 上，却仍能装下一个 n 阶群
     *   n (N)           群的阶 = 标量域的大小；"n·P = 无穷远点 O"里的 n·P 是标量乘（P 自加 n 次）
     *   O (无穷远点)     群的单位元：G₁ 里用空数组表示，G₂ 里用 Z = 0 表示
     *   isProbablePrime(64)  Miller-Rabin 概率素性测试，做 64 轮；合数被误判成素数的概率不超过 2⁻¹²⁸
     * </pre>
     * <p><b>为什么 "n·P = O" 就等于"阶正好是 n"</b>：元素的阶 ord(P) 是使 k·P = O 的最小正整数 k，
     * 由拉格朗日定理 ord(P) | 群阶。这里群阶取的是素数 n，故 ord(P) ∈ {1, n}；P ≠ O 排除 1，
     * 于是 n·P = O 一次同时验证了"点在群里""倍点/加法公式正确""n 确实整除群阶"。
     * <p><b>p ≠ n 为什么值得单独断言</b>：坐标算术 mod p（域），标量算术 mod n（群阶），两套模数
     * 只差最后几个字节，抄串了不会报错却会全算错 —— 比如拿 p 去约减标量，ds 就不是标准里那个点了。
     */
    @TraceExecution(value = "生成元曲线与阶检查", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void generatorsLieOnTheirCurvesAndHaveOrderN()
    {
        Tracer.trace("start", new Object[]{"p_bits", Sm9Math.P.bitLength(), "n_bits", Sm9Math.N.bitLength()},
            null, "start");

        Assert.assertTrue("P1 必须满足 y² = x³ + 5", Sm9Math.pointIsOnCurve(Sm9Math.P1));
        Tracer.trace("pointIsOnCurve", new Object[]{"point", Sm9Math.P1},
            Sm9Math.pointIsOnCurve(Sm9Math.P1), "generators");
        // G₁ 的无穷远点在这个实现里就是"空数组"，所以判 O 只要看 length == 0（没有单独的 isInfinity）
        Assert.assertTrue("n·P1 必须是无穷远点（空数组）",
            Sm9Math.pointMul(Sm9Math.N, Sm9Math.P1).length == 0);
        Tracer.trace("nTimesP1", new Object[]{"n", Sm9Math.N, "P1", Sm9Math.P1},
            Sm9Math.pointMul(Sm9Math.N, Sm9Math.P1).length, "generators");
        Assert.assertTrue("P2 必须满足 twisted 曲线 y² = x³ + 5u", Sm9Math.twistIsOnCurve(Sm9Math.P2));
        Tracer.trace("twistIsOnCurve", new Object[]{"P2", Sm9Math.P2},
            Sm9Math.twistIsOnCurve(Sm9Math.P2), "generators");
        // G₂ 的无穷远点只看 Z：twistIsInfinity(pt) 就是 fp2IsZero(pt[2])
        Assert.assertTrue("n·P2 必须是无穷远点", Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, Sm9Math.P2)));
        Tracer.trace("nTimesP2", new Object[]{"n", Sm9Math.N, "P2", Sm9Math.P2},
            Sm9Math.twistIsInfinity(Sm9Math.twistMul(Sm9Math.N, Sm9Math.P2)), "generators");
        Assert.assertTrue("n 是素数", Sm9Math.N.isProbablePrime(64));
        Tracer.traceDecision("nIsPrime", new Object[]{"n", Sm9Math.N, "rounds", 64},
            Sm9Math.N.isProbablePrime(64), "generators", "n 通过 64 轮 Miller-Rabin");
        Assert.assertFalse("p ≠ n：素数域与标量域是两回事", Sm9Math.P.equals(Sm9Math.N));
        Tracer.traceDecision("pNotN", new Object[]{"p", Sm9Math.P, "n", Sm9Math.N},
            !Sm9Math.P.equals(Sm9Math.N), "generators", "p != n");

        log.info("[SM9-常数] p 有 {} bit，n 有 {} bit，P1/P2 都在自己的曲线上且阶为 n",
            Sm9Math.P.bitLength(), Sm9Math.N.bitLength());
        Tracer.trace("end", new Object[]{"p1_on_curve", true, "p2_on_curve", true},
            "generators verified", "end");
    }

    /**
     * 测试②：塔的三条规则 —— 每一次扩张只引入一条关系：u²=−2、v²=u、w³=v。
     * 整个 Fp12 的全部算术（几百行乘法）说到底只是这三条 + 普通多项式乘法。
     * <pre>
     *   记号（每一层都是"低次多项式的全体"，次数被化简规则压死）
     *   Fp2 元素 = a₀ + a₁u，存 {a₀, a₁}；u 本身写作 {0, 1}（常数项 0、u 分量 1）
     *   Fp4 元素 = b₀ + b₁v，bᵢ = {系数0, 系数1(u)}；展平成 4 个数 {b₀₀, b₀₁, b₁₀, b₁₁}
     *            所以 v 写作 {0, 0, 1, 0}：v⁰ 那半边全 0，v¹ 那半边的常数项是 1
     *   Fp12 元素 = c₀ + c₁w + c₂w²，cᵢ 是 Fp4；展平成 12 个数，第 k 组就是下标 4k..4k+3
     *            所以 w 落在下标 4（c₁ 的常数项），v 在 Fp12 里落在下标 2（c₀ 的 v 分量）
     *   i = u位 + 2·v位 + 4·w位    这条扁平规则把上面三个"落在下标几"一次性解释完：
     *            u → 1，v → 2，w → 4，w² → 8，u·v·w² → 1 + 2 + 8 = 11
     *   "−2"      Fp 里的 p−2，所以断言写成 fp2Add(u², {2, 0}) 是否等于 0（加回去看是不是零）
     * </pre>
     * <p><b>为什么这三条规则"够用了"</b>：u²+2 在 Fp 里不可约（−2 不是模 p 的二次剩余），
     * 所以 Fp[u]/(u²+2) 真的是域；v²−u、w³−v 同理在上一层的域里不可约。不可约 + 首一 ⇒ 每个非零元
     * 都有逆，而乘法只需把多项式相乘后按度数从高到低用这三条关系回代即可 —— 断言里的
     * <b>分配律</b> (distributivity，(x+y)z = xz + yz) 证明我们得到的确实是"域乘法"而不是某个
     * 看起来像的双线性映射；<b>x·x⁻¹ = 1</b> 证明 fp12Inv 的那套"三次共轭 + 范数"没有抄错符号；
     * <b>384 字节往返</b>证明序列化与反序列化互为真逆（下标方向写反就在这里暴露）。
     */
    @TraceExecution(value = "扩域塔三条规则与分配律", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void towerRulesInverseAndDistributivity()
    {
        Tracer.trace("start", new Object[]{"rules", "u²=-2, v²=u, w³=v", "iterations", 5}, null, "start");

        // u² = −2（Fp2）
        // u 本身 = 0 + 1·u，所以在 Fp2 的 {常数项, u 项} 里写作 {0, 1}；
        // "等于 −2" 的写法是"加 2 之后是不是 0"：fp2Add(u², {2, 0}) 必须是 Fp2 的零元
        BigInteger[] u = new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE };
        Assert.assertTrue("u² 必须等于 −2", Sm9Math.fp2IsZero(Sm9Math.fp2Add(Sm9Math.fp2Sqr(u),
            new BigInteger[]{ BigInteger.valueOf(2), BigInteger.ZERO })));
        Tracer.trace("fp2SquareU", new Object[]{"u", u}, Sm9Math.fp2Sqr(u), "tower");

        // v² = u（Fp4）：v 是"只有 v 分量、且那个 Fp2 分量等于 1"的元素
        BigInteger[] v = new BigInteger[]{ BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO };
        BigInteger[] vSquaredExpect = new BigInteger[]{ BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO };
        Assert.assertTrue("v² 必须等于 u", java.util.Arrays.equals(Sm9Math.fp4Sqr(v), vSquaredExpect));
        Tracer.trace("fp4SquareV", new Object[]{"v", v}, Sm9Math.fp4Sqr(v), "tower");

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
        Tracer.trace("fp12CubeW", new Object[]{"w", w, "expected_v", vIn12},
            Sm9Math.fp12Mul(w, Sm9Math.fp12Mul(w, w)), "tower");

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
            Tracer.traceLoop("fp12FieldChecks", new Object[]{"x", x, "y", y, "z", zz},
                "分配律 / 逆元 / 序列化往返全部成立", "tower", i + 1, 5);
        }
        Tracer.trace("end", new Object[]{"iterations", 5}, "tower rules verified", "end");
    }

    /**
     * 造一个"随机 Fp12 元素"：扔 384 个随机字节，再按 c₁₁ 递减到 c₀ 的顺序解成 12 个系数。
     * <p>fp12FromBytes 会把每个系数 mod p 归约，所以任意字节串都能安全地变成一个合法域元素
     * （不需要像随机点那样先检查是否在曲线上 —— 这是"取域元素比取群元素容易得多"的一个侧面）。
     */
    private static BigInteger[] randomFp12(Random rnd)
    {
        byte[] buf = new byte[384];
        rnd.nextBytes(buf);
        return Sm9Math.fp12FromBytes(buf);
    }

    /**
     * 测试③：Frobenius —— "只乘常数"的捷径必须真的等于普通幂 x^p。
     * <pre>
     *   x          任意一个 Fp12 元素（12 个 Fp 系数）
     *   p          素域的模数（Sm9Math.P）；p² = p·p、p⁶ = p²·p²·p² 是它的高次，只用来当"普通幂"的指数
     *   π₁, π₂, π₃, π₆   Fp12 上的 Frobenius 自同构 (Frobenius automorphism)：π_k(x) = x^{p^k}。
     *                fp12Frobenius = π₁，Frobenius2 = π₂，Frobenius3 = π₃，Frobenius6 = π₆
     *   α₁..α₅, β    标准给死的 Fp 常数，本质是"塔基各元素被 p 次幂之后剩下的那个倍数"的表：
     *                u^p、v^p、w^p 用化简规则回代后各自等于 原符号 × 常数，这些常数就是 α、β。
     *                α₃ 与 β 相同（Sm9Math.ALPHA3 = BETA）不是复制粘贴，塔规则必然给出 α³ = β
     *   fp12Pow(x,e) 老老实实的平方-乘（square-and-multiply）循环，e 是几百位的普通指数
     * </pre>
     * <p><b>为什么 x^{p} 可以"不真的做幂"就算出来</b>
     * <pre>
     *   (a + b)^p ≡ a^p + b^p   特征 p 下二项式系数 C(p,i) = p·…/i! 全被 p 整除 ⇒ 中间项归零
     *                            （俗称 freshman's dream，新生美梦；这是"Frobenius 是同态"的唯一原因）
     *   a^p = a  (mod p)         对 Fp 里的系数用费马小定理，所以 π₁ 只动 u、v、w，不动系数
     *   u^p = u·(u²)^((p−1)/2) = u·(−2)^((p−1)/2) = −u
     *                            欧拉判别式：(−2)^((p−1)/2) ≡ (−2/p) = −1（−2 是模 p 的非剩余），
     *                            所以"Fp2 分量的 p 次幂"退化成 a₀ + a₁u ↦ a₀ − a₁u，就是 fp2Conj（共轭）
     *   v^p、w^p                 同一套路数下去就不再等于自身，而是"自身 × 一个 Fp 常数" ⇒ α 登场
     * </pre>
     * 合起来：π₁(x) = 各层共轭 + 按组乘 α₁..α₅，成本只有十几次 Fp 乘法，而 fp12Pow(x, p) 要做
     * 256 次 Fp12 平方/乘。这条测试就是在确认"便宜的那条路"和"昂贵但定义明确的那条路"逐系数相等。
     * <p>为什么最终幂特别需要它：易算部分 f^{(p⁶−1)(p²+1)} 被写成 π₆(f)·f⁻¹ 再乘 π₂(·) ——
     * 两次 Frobenius + 两次乘法，代替了 p⁶+p² 这两个 1500 位指数的幂运算。
     */
    @TraceExecution(value = "Frobenius 与普通幂一致性", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void frobeniusMapsAgreeWithPlainExponentiation()
    {
        Tracer.trace("start", new Object[]{"seed", 20261021L, "iterations", 3}, null, "start");

        BigInteger p = Sm9Math.P;
        BigInteger p2 = p.multiply(p);
        BigInteger p6 = p2.multiply(p2).multiply(p2);
        Tracer.trace("modulusPowers", new Object[]{"p_bits", p.bitLength(), "p2_bits", p2.bitLength(),
            "p6_bits", p6.bitLength()}, p, "frobenius");
        Random rnd = new Random(20261021L);
        BigInteger[] x = randomFp12(rnd);
        Tracer.trace("randomFp12", new Object[]{"seed", 20261021L}, x, "frobenius");
        for (int i = 0; i < 3; i++)
        {
            // 每轮先把 x 乘成"更一般"的元素：随机系数元素有概率落在子域里（比如整个 Fp4 半边全是 0），
            // 那种退化元素在子域上碰巧也能满足 Frobenius 公式，测不出 α 常数错没错；乘一次基本就离开子域了
            x = Sm9Math.fp12Mul(x, randomFp12(rnd));
            Assert.assertTrue("x^p 的快路径必须等于普通幂",
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius(x), Sm9Math.fp12Pow(x, p)));
            Tracer.traceDecision("pi1EqualsPowP", new Object[]{"x", x, "p_bits", p.bitLength()},
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius(x), Sm9Math.fp12Pow(x, p)), "frobenius",
                "π₁(x) == x^p");
            Assert.assertTrue("x^{p²} 同理", Sm9Math.fp12Equals(Sm9Math.fp12Frobenius2(x), Sm9Math.fp12Pow(x, p2)));
            Tracer.traceDecision("pi2EqualsPowP2", new Object[]{"x", x, "p2_bits", p2.bitLength()},
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius2(x), Sm9Math.fp12Pow(x, p2)), "frobenius",
                "π₂(x) == x^{p²}");
            Assert.assertTrue("x^{p⁶} 同理（最终幂的易算部分就靠它）",
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius6(x), Sm9Math.fp12Pow(x, p6)));
            Tracer.traceDecision("pi6EqualsPowP6", new Object[]{"x", x, "p6_bits", p6.bitLength()},
                Sm9Math.fp12Equals(Sm9Math.fp12Frobenius6(x), Sm9Math.fp12Pow(x, p6)), "frobenius",
                "π₆(x) == x^{p⁶}");
        }
        Tracer.trace("end", new Object[]{"iterations", 3}, "Frobenius shortcuts verified", "end");
    }

    /**
     * 测试④：配对的三组真实样例（GmSSL {@code test_sm9_z256_pairing}）。
     * 这三组各测一条路径：普通配对、非生成元的两点、配对后再取幂。
     * <pre>
     *   输入项（每组都是"一个 G₂ 的点 + 一个 G₁ 的点"，注意 Java 的实参顺序是 (Q, P)）
     *   ks·P2       签名主私钥标量 ks（Z_n 里的 32 字节大端数）乘生成元 P2 ⇒ G₂ 的射影点
     *   deB         = HEX_KEX·(HEX_KEX + H1("Bob",0x02))⁻¹·P2，G₂ 的点，从 DE_B 那 129 字节解出来
     *   RA          = rA·Q_B，G₁ 的点，从 RA_POINT 那 65 字节解出来
     *   Ppube       = HEX_KEX·P1，G₁ 的点（标准样例 hex_Ppube）
     *   rB          = RB，应答方的临时标量 ∈ Z_n
     *   0x04        SEC1 非压缩点前缀；DE_B / RA_POINT / PPUBE_POINT 存的都是<b>不含</b>前缀的纯坐标，
     *               所以代码里要用 Calc.concat(new byte[]{0x04}, unhex(...)) 现场拼回去
     *   期望值       PAIRING1/2/3 各 384 字节；比对时把实现输出的字节 hex() 成小写，
     *               与常量的 toLowerCase() 比 —— 常量按十六进制文本存，大小写只是可读性问题
     * </pre>
     * <p>三组样例覆盖的三条不同代码路径：
     * <pre>
     *   e(P1, ks·P2)         Q 由标量乘得到、P 是生成元：验证主线 + 收尾两条线 + 最终幂
     *   e(RA, deB)           两个点都与生成元无关：验证"任意点"都不会碰巧对上
     *   e(Ppube, P2)^{rB}    配完对再在 GT 里取幂：验证结果真的落在 n 阶子群里，能继续参与运算
     * </pre>
     */
    @TraceExecution(value = "配对结果对照 GmSSL 样例", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void pairingMatchesGmsslKnownAnswers()
    {
        Tracer.trace("start", new Object[]{"cases", 3, "source", "GmSSL tests/sm9test.c"}, null, "start");

        BigInteger[] g = Sm9Math.pairing(Sm9Math.twistMul(HEX_KS, Sm9Math.P2), Sm9Math.P1);
        Tracer.trace("pairingP1KsP2", new Object[]{"ks", HEX_KS, "P1", Sm9Math.P1,
            "Q", Sm9Math.twistMul(HEX_KS, Sm9Math.P2)}, Calc.hex(Sm9Math.fp12ToBytes(g)), "pairing");
        Assert.assertEquals("e(P1, ks·P2) 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g)), PAIRING1.toLowerCase());

        // 第二个入参是 G₁ 的仿射点（BigInteger[2]），第一个是 G₂ 的射影点：
        // twistFromOctets 把 x₁ ‖ x₀ 还原成 Fp2 元素 a₀ + a₁u（注意它按"高次在前"读），
        // 再补 Z = (1,0) 变成射影三元组，配对内部才走的是射影那套切线/割线公式
        BigInteger[] g2 = Sm9Math.pairing(Sm9Math.twistFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(DE_B))),
            Sm9Math.pointFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(RA_POINT))));
        Tracer.trace("pairingRaDeB", new Object[]{"RA", RA_POINT, "deB", DE_B},
            Calc.hex(Sm9Math.fp12ToBytes(g2)), "pairing");
        Assert.assertEquals("e(RA, deB) 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g2)), PAIRING2.toLowerCase());

        // 第三组先配对、再取 rB 次幂：fp12Pow 是 Fp12 里的普通平方-乘，指数 rB 在 [1, n−1] 里，
        // 因为配对输出已经在 n 阶子群 GT 中，这个幂的结果仍然在 GT 里（阶至多 n）
        BigInteger[] g3 = Sm9Math.fp12Pow(Sm9Math.pairing(Sm9Math.P2,
            Sm9Math.pointFromOctets(Calc.concat(new byte[]{ 0x04 }, Calc.unhex(PPUBE_POINT)))), RB);
        Tracer.trace("pairingPpubeP2PowRb", new Object[]{"Ppube", PPUBE_POINT, "P2", Sm9Math.P2, "rB", RB},
            Calc.hex(Sm9Math.fp12ToBytes(g3)), "pairing");
        Assert.assertEquals("e(Ppube, P2)^{rB} 必须逐字节等于标准样例",
            Calc.hex(Sm9Math.fp12ToBytes(g3)), PAIRING3.toLowerCase());

        Tracer.traceDecision("katPairing1", new Object[]{"case", "e(P1, ks·P2)",
            "expected", PAIRING1, "actual", Calc.hex(Sm9Math.fp12ToBytes(g))},
            Calc.hex(Sm9Math.fp12ToBytes(g)).equals(PAIRING1.toLowerCase()), "bilinear",
            "与 GmSSL PAIRING1 逐字节一致");
        Tracer.traceDecision("katPairing2", new Object[]{"case", "e(RA, deB)",
            "expected", PAIRING2, "actual", Calc.hex(Sm9Math.fp12ToBytes(g2))},
            Calc.hex(Sm9Math.fp12ToBytes(g2)).equals(PAIRING2.toLowerCase()), "bilinear",
            "与 GmSSL PAIRING2 逐字节一致");
        Tracer.traceDecision("katPairing3", new Object[]{"case", "e(Ppube, P2)^{rB}",
            "expected", PAIRING3, "actual", Calc.hex(Sm9Math.fp12ToBytes(g3))},
            Calc.hex(Sm9Math.fp12ToBytes(g3)).equals(PAIRING3.toLowerCase()), "bilinear",
            "与 GmSSL PAIRING3 逐字节一致");

        log.info("[SM9-配对] 三组 GmSSL 样例全部逐字节命中，e(P1,ks·P2) 的前 16 字节是 {}",
            Calc.hex(Sm9Math.fp12ToBytes(g)).substring(0, 32));
        Tracer.trace("end", new Object[]{"cases", 3, "allMatched", true}, null, "end");
    }

    /**
     * 测试⑤：双线性 + 非退化 + 落到 n 阶子群 —— 这三条正是 SM9 全部协议的地基。
     * <pre>
     *   a, b      Z_n 里的两个标量（这里直接借用标准样例的 ks、ke 两个数，换成别的也一样）
     *   base      e(P1, P2) ∈ GT —— 曲线的"系统配对常数"，签名里的 g = e(P1, Ppubs) 就是 base^{ks}
     *   lhs       e(a·P1, b·P2)：先在<b>群里</b>做两次标量乘，再配对
     *   rhs       (base^a)^b = e(P1,P2)^{ab}：先在<b>域里</b>做两次普通幂
     *   h1        H1(ID_ALICE, HID_SIGN) = H1("Alice", 0x01)，Z_n* 里的一个数（值域 [1, n−1]）
     *   left      e(ds, (h1 + ks)·P2) —— 把用户私钥与"分母乘回去"的那个点配对
     * </pre>
     * <p><b>双线性为什么让 lhs 与 rhs 相等</b>：e(a·P, b·Q) 对<b>每个变量分别</b>是同态
     * （群加法进、域乘法出），所以两个标量都可以提出到指数上：
     * <pre>
     *   e(a·P1, b·P2) = e(P1, P2)^{a·b} = (base^a)^b      ← 指数在 Z_n 里算，a·b 可交换
     * </pre>
     * <p><b>为什么 g^n = 1</b>：最终幂的指数正好是 (p¹² − 1)/n。Fp12* 的阶是 p¹² − 1，
     * 由拉格朗日定理任何 f 都满足 f^{p¹²−1} = 1，于是 (f^{(p¹²−1)/n})^n = f^{p¹²−1} = 1。
     * 也就是说最终幂把<b>任意</b> Fp12 元素压进 n 阶子群 GT —— 这正是"最终幂"存在的理由：
     * Miller 循环的原始输出带着任意子群的分量，两边没法直接比；压进 GT 后表示才唯一。
     * <p><b>"抵消除法"那条恒等式的完整推导</b>（SM9 全协议的核心一步）：
     * <pre>
     *   ds = ks·(ks + h1)⁻¹·P1                          （KGC 算的私钥，带除法）
     *   (h1 + ks)·P2                                     （只靠公开的 Ppubs = ks·P2 与 ID 就能拼出的点）
     *   e(ds, (h1+ks)·P2)
     *     = e(P1, P2)^{ [ks·(ks+h1)⁻¹] · (h1 + ks) }     ← 双线性把两个标量都提到指数上
     *     = e(P1, P2)^{ ks }                             ← (ks+h1)⁻¹ 与 (ks+h1) 在 Z_n 里正好抵消
     *     = base^{ks}
     * </pre>
     * 验签方/加密方一辈子都不用知道 ks：它们只要把"分母"乘到另一个变量上，除法就在指数里消掉了。
     */
    @TraceExecution(value = "双线性 / 非退化 / n 阶子群", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void pairingIsBilinearNonDegenerateAndLandsInOrderNGroup()
    {
        Tracer.trace("start", new Object[]{"P1", Sm9Math.P1, "P2", Sm9Math.P2}, null, "start");

        BigInteger a = new BigInteger("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4", 16);
        BigInteger b = new BigInteger("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22", 16);

        BigInteger[] base = Sm9Math.pairing(Sm9Math.P2, Sm9Math.P1);
        Tracer.trace("pairingBase", new Object[]{"P1", Sm9Math.P1, "P2", Sm9Math.P2},
            Calc.hex(Sm9Math.fp12ToBytes(base)), "pairing");
        BigInteger[] lhs = Sm9Math.pairing(Sm9Math.twistMul(b, Sm9Math.P2), Sm9Math.pointMul(a, Sm9Math.P1));
        Tracer.trace("pairingLhs", new Object[]{"a", a, "b", b}, Calc.hex(Sm9Math.fp12ToBytes(lhs)), "pairing");
        BigInteger[] rhs = Sm9Math.fp12Pow(Sm9Math.fp12Pow(base, a), b);
        Tracer.trace("powRhs", new Object[]{"base", Calc.hex(Sm9Math.fp12ToBytes(base)), "a", a, "b", b},
            Calc.hex(Sm9Math.fp12ToBytes(rhs)), "pairing");
        Assert.assertTrue("e(a·P1, b·P2) 必须等于 e(P1,P2)^{ab}", Sm9Math.fp12Equals(lhs, rhs));

        // 非退化 (non-degenerate)：只要 e(P1,P2) = 1，所有 e(·,·) 都恒等于 1（因为它对每个变量是同态），
        // 那"用配对验证一个等式"就退化成"验证 1 = 1"，整套 SM9 的签名/加密全部失去意义
        Assert.assertFalse("配对不能退化成 1，否则什么都证不了", Sm9Math.fp12Equals(base, Sm9Math.fp12One()));
        Assert.assertTrue("GT 元素的阶整除 n：g^n = 1",
            Sm9Math.fp12Equals(Sm9Math.fp12Pow(base, Sm9Math.N), Sm9Math.fp12One()));

        // 交叉验证标准里那条"抵消除法"的核心恒等式：e(ds, (h1+ks)·P2) = e(P1,P2)^{ks}
        // 三个量各自是：ds ∈ G₁（带除法的私钥点）、h1 = H1("Alice",0x01) ∈ [1, n−1]、
        // modnAdd(h1, ks) 就是 (h1 + ks) mod n（必须在 Z_n 里加，不能拿整数加完就乘点），
        // twistMul 再把那个和乘到 P2 上得到 G₂ 的点；fp12One() 是 Fp12 的乘法单位元 1 = {1,0,…,0}
        BigInteger[] ds = Sm9Math.signPrivateKeyExtract(HEX_KS, ID_ALICE);
        BigInteger h1 = Sm9Math.hash1(ID_ALICE, Sm9Math.HID_SIGN);
        BigInteger[] left = Sm9Math.pairing(Sm9Math.twistMul(Sm9Math.modnAdd(h1, HEX_KS), Sm9Math.P2), ds);
        Tracer.trace("pairingDsH1KsP2", new Object[]{"ds", Sm9Math.pointToOctets(ds), "h1", h1,
            "ks", HEX_KS, "Q", Sm9Math.twistMul(Sm9Math.modnAdd(h1, HEX_KS), Sm9Math.P2)},
            Calc.hex(Sm9Math.fp12ToBytes(left)), "pairing");
        Assert.assertTrue("ds 与 (H1+ks)·P2 配对后，分母 (ks+H1) 必须被干净地抵消成 g^ks",
            Sm9Math.fp12Equals(left, Sm9Math.fp12Pow(base, HEX_KS)));

        Tracer.traceDecision("bilinear", new Object[]{"lhs", Calc.hex(Sm9Math.fp12ToBytes(lhs)),
            "rhs", Calc.hex(Sm9Math.fp12ToBytes(rhs))}, Sm9Math.fp12Equals(lhs, rhs), "bilinear",
            "e(a·P1, b·P2) == e(P1,P2)^{ab}");
        Tracer.traceDecision("nonDegenerate", new Object[]{"base", Calc.hex(Sm9Math.fp12ToBytes(base))},
            !Sm9Math.fp12Equals(base, Sm9Math.fp12One()), "bilinear", "e(P1,P2) != 1");
        Tracer.traceDecision("orderN", new Object[]{"n", Sm9Math.N},
            Sm9Math.fp12Equals(Sm9Math.fp12Pow(base, Sm9Math.N), Sm9Math.fp12One()), "bilinear",
            "g^n == 1（GT 是 n 阶子群）");
        Tracer.traceDecision("dsCancellation", new Object[]{"h1", h1, "ks", HEX_KS},
            Sm9Math.fp12Equals(left, Sm9Math.fp12Pow(base, HEX_KS)), "bilinear",
            "e(ds, (h1+ks)·P2) == g^ks，除法被抵消");

        log.info("[SM9-双线性] e(aP,bQ) = e(P,Q)^ab、g^n = 1、ds 里那个除法的抵消恒等式，三者全部成立");
        Tracer.trace("end", new Object[]{"bilinear", true, "nonDegenerate", true, "orderN", true},
            null, "end");
    }

    /**
     * 测试⑥：点的字节化 —— 65/129 字节的编排顺序（Fp2 先写 u 分量）最容易被写反。
     * <pre>
     *   三种官方长度（同一个"扁平化 (flattening)"思想的三个实例：把代数值拆成一串普通 32 字节大端整数）
     *   G₁ 点  65 字节  = 0x04 ‖ x(32) ‖ y(32)
     *          0x04 = SEC1"非压缩点"前缀；无穷远点例外，写成单个 0x00 字节（避免与合法的 (0,0) 混）
     *   G₂ 点  129 字节 = 0x04 ‖ x₁(32) ‖ x₀(32) ‖ y₁(32) ‖ y₀(32)
     *          x = x₀ + x₁u 是 Fp2 元素，标准/GmSSL 约定<b>高次分量 x₁（u 的系数）先写</b>；
     *          代码里 P2[0] 是 X、P2[0][1] 是它的 u 分量 —— 所以断言比的是 P2[0][1]
     *   GT 元  384 字节 = c₁₁ ‖ c₁₀ ‖ … ‖ c₀，12 个 Fp 系数按扁平下标 i = u位+2·v位+4·w位<b>从 11 递减到 0</b>
     *   射影 → 仿射：twistToOctets 内部先做同除 Z（x = X·Z⁻²、y = Y·Z⁻³），所以"字节形状"永远是仿射的；
     *          配对内部则一直保持射影，两条路不会互相污染
     * </pre>
     * <p>往返 (round-trip) 断言的作用：toOctets 与 fromOctets 必须严格互逆，否则 DER 里存进去的点
     * 读出来就是另一个点 —— 而且因为 Fp2 的两个分量都是 32 字节，<b>写反顺序不会报任何错</b>，
     * 只会安静地给出一个不在曲线上的点。这就是"最容易写反"的具体含义。
     */
    @TraceExecution(value = "点编码往返与 GmSSL 字节序", algorithm = "SM9", flow = "SM9-PAIRING")
    @Test
    public void pointEncodingsRoundTripAndMatchGmsslOrder()
    {
        Tracer.trace("start", new Object[]{"P1", Sm9Math.P1, "P2", Sm9Math.P2}, null, "start");

        byte[] p1 = Sm9Math.pointToOctets(Sm9Math.P1);
        Tracer.trace("pointToOctetsG1", new Object[]{"P1", Sm9Math.P1}, p1, "encode");
        Assert.assertEquals("G₁ 点是 0x04 打头的 65 字节", 65, p1.length);
        Assert.assertArrayEquals("再读回来必须一模一样", Sm9Math.P1, Sm9Math.pointFromOctets(p1));
        Tracer.traceDecision("roundTripG1", new Object[]{"length", p1.length},
            java.util.Arrays.equals(Sm9Math.P1, Sm9Math.pointFromOctets(p1)), "encode",
            "G1 点 65 字节严格往返");

        byte[] p2 = Sm9Math.twistToOctets(Sm9Math.P2);
        Tracer.trace("twistToOctetsG2", new Object[]{"P2", Sm9Math.P2}, p2, "encode");
        Assert.assertEquals("G₂ 点是 0x04 打头的 129 字节", 129, p2.length);
        // GmSSL 的顺序：x₁(高 u 分量) ‖ x₀ ‖ y₁ ‖ y₀
        Assert.assertEquals("第 1 段必须是 x 的 u 分量",
            Calc.hex(Calc.toBytes(Sm9Math.P2[0][1], 32)).toUpperCase(), Calc.hex(java.util.Arrays.copyOfRange(p2, 1, 33)).toUpperCase());
        Tracer.traceDecision("fp2ComponentOrder", new Object[]{"expected", Sm9Math.P2[0][1],
            "actual", Calc.hex(java.util.Arrays.copyOfRange(p2, 1, 33))},
            Calc.hex(Calc.toBytes(Sm9Math.P2[0][1], 32)).toUpperCase()
                .equals(Calc.hex(java.util.Arrays.copyOfRange(p2, 1, 33)).toUpperCase()), "encode",
            "G2 点第 1 段是 x 的 u 分量（x₁ 在前）");
        BigInteger[][] back = Sm9Math.twistFromOctets(p2);
        // 为什么要"逐坐标相减再判零"而不是直接比数组：
        // (1) Java 数组的 equals 比的是引用，assertEquals 对 BigInteger[][] 比不出"值相等"
        //     （上面 G₁ 那条可以用 assertArrayEquals，因为它只有一层数组）；
        // (2) 射影坐标的代表不唯一 —— {λ²X, λ³Y, λZ} 与 {X, Y, Z} 是同一个仿射点，
        //     所以"同一个点"的正确定义是仿射坐标 (x, y) 相同，即 fp2IsZero(fp2Sub(X₁, X₂)) 且 Y 同理
        Assert.assertTrue("G₂ 点往返必须落回同一点",
            Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[0], Sm9Math.P2[0]))
                && Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[1], Sm9Math.P2[1])));
        Tracer.traceDecision("roundTripG2", new Object[]{"backX", back[0], "backY", back[1]},
            Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[0], Sm9Math.P2[0]))
                && Sm9Math.fp2IsZero(Sm9Math.fp2Sub(back[1], Sm9Math.P2[1])), "encode",
            "G2 点 129 字节往返落回同一点");

        // 标准样例：kex·P1 就是 GmSSL 的 hex_Ppube，顺带确认交换测试那把主公钥的字节序
        byte[] ppube = Sm9Math.pointToOctets(Sm9Math.encMasterPublicKey(HEX_KEX));
        Tracer.trace("pointToOctetsPpube", new Object[]{"kex", HEX_KEX}, ppube, "encode");
        Assert.assertEquals("kex·P1 必须等于 GmSSL 的 hex_Ppube",
            ("04" + PPUBE_POINT).toLowerCase(), Calc.hex(ppube));
        Tracer.traceDecision("ppubeOrder", new Object[]{"expected", ("04" + PPUBE_POINT).toLowerCase(),
            "actual", Calc.hex(ppube)},
            ("04" + PPUBE_POINT).toLowerCase().equals(Calc.hex(ppube)), "encode",
            "kex·P1 == GmSSL hex_Ppube");

        log.info("[SM9-序列化] G₁ 65 字节 / G₂ 129 字节 / Fp12 384 字节，三种编排都能严格往返");
        Tracer.trace("end", new Object[]{"g1_bytes", p1.length, "g2_bytes", p2.length},
            "encodings verified", "end");
    }
}
