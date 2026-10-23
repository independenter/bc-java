package org.bouncycastle.learning.essence;

import java.util.List;

import static org.bouncycastle.learning.essence.Calc.M32;
import static org.bouncycastle.learning.essence.Calc.rotl;
import static org.bouncycastle.learning.essence.Calc.u32;

/**
 * SM3（GB/T 32905-2016）的本质计算 —— 面向过程的数学引擎，供 SM2/SM9 与 JCE 层复用。
 *
 * <p>没有 Digest 对象、没有继承体系，SM3 只是几个普通静态方法串起来的直线代码：
 * <pre>
 *   sm3(msg) = 大端序列化( 逐块压缩( MD填充(msg) ) )
 *   逐块压缩：用一个 for 循环把链接值 V 一块一块往前推：V = cf(V, block)   // Merkle–Damgård 迭代
 *   展开写就是：V₀ = IV；Vᵢ = CF(Vᵢ₋₁, Bᵢ₋₁)（i = 1..n，Bᵢ₋₁ = 填充后第 i 个 64 字节分组）；H = bytes32(Vₙ)
 *   这里 n = 分组个数 = 填充后总字节数 / 64；"大端序列化"= 把 Vₙ 的 8 个 32-bit 字按高位字节在前摊平成 32 字节
 * </pre>
 * "状态"就是循环里的局部变量（一个 long[8]），每轮就地改写它 —— 不克隆、不套函数、不传参绕圈。
 * 这正是面向过程写法的核心：一条命令一条命令地执行，而不是把函数当值来回传递。
 *
 * <p>本类是从 {@code Sm3EssenceTest} 里抽出来的：抽到 src/main 之后，SM9 引擎（同样在 main）
 * 和 JCE Provider 才可能引用它；测试仍然逐块核对这些方法的输出。
 *
 * <p><b>符号表 —— 本文件每条公式里出现的字母/记号（下标 j 一律指"第 j 轮"，j = 0..63）</b>
 * <pre>
 *   H()        SM3 这个哈希函数本身：输入任意长字节串，输出固定 256 bit（32 字节 = 8 个 32-bit 字）
 *   msg / m    待摘要的消息（message），任意长度字节串；填充后切成若干个 512-bit 分组
 *   block      消息块 (message block)：固定 64 字节 = 512 bit = 16 个 32-bit 字，是压缩函数的输入单位
 *              （一个 64 字节分组里最高 16 个字直接取自消息，记 W₀..W₁₅；其余全是"扩展"出来的）
 *   V          链接值 (chaining value)：8 个 32-bit 字组成的中间状态，形如 V = A‖B‖C‖D‖E‖F‖G‖H
 *   A..H       链接值的 8 个分量，也叫 8 个寄存器/字：v[0]→A, v[1]→B, …, v[7]→H（每轮都会整体改写一遍）
 *   IV         初始值 (initial value)：第 0 个链接值 V₀，8 个标准常量字，作用是把迭代起点固定下来
 *   CF()       压缩函数 (compression function)：CF(V, block) -> 新的 8 字链接值，内部跑满 64 步
 *   j          轮号/步号 (step index)，0 ≤ j &lt; 64；SM3 一共 64 步，前 16 步和后 48 步用不同的布尔函数
 *   W[j]       第 j 轮用的"扩展字"：由消息分组的前 16 个字按递推式（见 {@link #wExpand}）推出 W₁₆..W₆₇
 *   W'[j]      第 j 轮的"差分字"：W′[j] = W[j] ⊕ W[j+4]，把两个相隔 4 轮的扩展字配对，喂给 E..H 那一半
 *   T_j        轮常数 (round constant)：j &lt; 16 取 0x79cc4519，否则取 0x7a879d8a（SM3 里唯一的两个魔术数）
 *   FF_j       第 j 轮的三输入布尔函数（作用于 A,B,C）；前 16 轮 = a⊕b⊕c（线性），
 *              后 48 轮 = (a∧b)∨(a∧c)∨(b∧c)（多数函数 majority，非线性）
 *   GG_j       第 j 轮的三输入布尔函数（作用于 E,F,G）；前 16 轮 = a⊕b⊕c，
 *              后 48 轮 = (a∧b)∨(¬a∧c)（选择函数 choose，非线性）
 *   P0, P1     扩散置换 (permutation)：P0(x) = x ⊕ rotl(x,9) ⊕ rotl(x,17)，P1(x) = x ⊕ rotl(x,15) ⊕ rotl(x,23)，
 *              把 1 比特的影响摊到整字；两者都由移位+异或构成，所以是线性映射（可逆）
 *   ⊕          按比特异或 (XOR)，32-bit 字之间逐位做，等价于 mod 2 的加法
 *   ∧ ¬ ∨      按位与 / 非 / 或（"非"必须 &amp; M32 截断，否则 long 里会冒出一串符号位 1）
 *   rotl(x,n)  32-bit 循环左移 n 位；n 只取低 5 位，所以 n=32 等于不移（见 Calc.rotl）
 *   u32 / M32  把结果截断到 32 位（mod 2³²）；M32 = 2³²−1 是掩码。加法进位超出 32 位的一律丢弃
 *   ‖          字节串拼接（concatenate），不是异或
 *   len₆₄(m)   消息 m 的<b>比特</b>长度（不是字节长度！），写成 8 字节大端放在填充尾部
 *   ≡          "同余"：a ≡ b (mod m) 表示 m 整除 (a−b)
 * </pre>
 *
 * <p><b>术语表 —— 几个反复出现、必须一次讲清的名词</b>
 * <pre>
 *   Merkle–Damgård 构造   先用 CF 把消息逐块"折叠"成一个链接值 V，最后把 V 当成摘要：
 *                         V₀=IV, V₁=CF(V₀,B₀), V₂=CF(V₁,B₁), …, H(m)=Vₙ（{@link #sm3} 里就是那个 for 循环）。
 *                         它给出：① 支持任意长度输入；② 可拼接/可流式（update 一段段喂与一次喂完等价）。
 *                         它<b>不</b>给出：抗长度扩展 —— 拿到 H(m) 就等于拿到中间态 Vₙ，攻击者可以直接从
 *                         Vₙ 继续往后折叠，算出 H(m‖填充(m)‖m′) 而无需知道 m。要认证就得用 HMAC 或（SM3 因为
 *                         长度字段覆盖全消息而稍有缓解）显式把长度/前缀绑进哈希。
 *   雪崩/扩散 (avalanche) 输入翻 1 比特 -> 输出平均翻一半比特；靠 P0/P1 的移位异或和 FF/GG 的非线性达成
 *   摘要 /  digest        H(m) 的最终 256 bit 输出，即 8 个大端 32-bit 字（Calc.bytes32(V)）
 * </pre>
 */
public final class Sm3
{
    private Sm3()
    {
    }

    /**
     * SM3 的分组长度（字节），HMAC / KDF 里也要用。
     * 64 字节 = 512 bit = 16 个 32-bit 字；HMAC 的 block-size B、"密钥长于 B 就先哈希"的阈值都是它。
     */
    public static final int BLOCK_SIZE = 64;

    /**
     * 轮常数 T_j：前 16 轮取 0x79cc4519，后 48 轮取 0x7a879d8a —— SM3 里唯一的"魔术数"，就两个常量。
     * 写成普通静态方法：传进轮号 j，返回一个 32-bit 字。
     *
     * <p>j = 轮号（0..63）；T_j 在每轮里只被用一次，而且是<b>先循环左移 j 位再相加</b>
     * （见 {@link #cf} 里的 rotl(tConstant(j), j)），所以"两个常数 + 64 种移位"就够了 ——
     * 不像 SHA-256 需要 64 个各不相同的轮常数。
     */
    public static long tConstant(int j)
    {
        return j < 16 ? 0x79cc4519L : 0x7a879d8aL;
    }

    /**
     * FF_j：布尔函数写成带三个参数 (a/b/c) 加轮号 j 的普通静态方法 —— 这就是它的本质。
     * 前 16 轮只用异或（线性），后 48 轮才引入与/或（多数函数，非线性）—— 这是 SM3 抗碰撞的关键设计。
     *
     * <p>作用对象是链接值的<b>高半部</b>三个连续字 (A, B, C)：a = A, b = B, c = C。
     * <pre>
     *   j &lt; 16：FF_j(a,b,c) = a ⊕ b ⊕ c                线性（每个输出比特是输入的 mod 2 加）
     *   j ≥ 16：FF_j(a,b,c) = (a∧b) ∨ (a∧c) ∨ (b∧c)    多数函数 majority：取三个输入里占多数的那个比特值
     *   ¬ 是逐位取反；(a∧b) 是逐位与；外层 u32 保证截断回 32 位
     * </pre>
     * "前 16 轮线性"的目的是让差分特征容易算（安全性靠后 48 轮的非线性撑住），
     * 这也是 SM3 与 SHA-256（64 轮全用多数函数/选择函数）最大的结构差异。
     */
    public static long ff(long j, long a, long b, long c)
    {
        return u32(j < 16 ? (a ^ b ^ c) : ((a & b) | (a & c) | (b & c)));
    }

    /**
     * GG_j：同理，前 16 轮纯异或（线性），后 48 轮是选择函数（非线性）。
     *
     * <p>作用对象是链接值的<b>低半部</b>三个连续字 (E, F, G)：a = E, b = F, c = G。
     * <pre>
     *   j &lt; 16：GG_j(a,b,c) = a ⊕ b ⊕ c
     *   j ≥ 16：GG_j(a,b,c) = (a∧b) ∨ (¬a∧c)           选择函数 choose：a 的每个比特当"开关"，
     *                                                   a=1 输出 b，a=0 输出 c
     *   ~a &amp; M32 就是 ¬a（Java 的 ~ 会连 long 的高 32 位一起翻成 1，必须用 M32 截回来）
     * </pre>
     */
    public static long gg(long j, long a, long b, long c)
    {
        return u32(j < 16 ? (a ^ b ^ c) : ((a & b) | ((~a & M32) & c)));
    }

    /**
     * P0 是"扩散函数"：一个字的每一位靠它摊到 32 位上，本质只有 异或 + 循环左移。
     * 普通静态方法，一个入参 x。
     *
     * <p>P0(x) = x ⊕ rotl(x, 9) ⊕ rotl(x, 17)；x 是 32-bit 字，9/17 是标准规定的两个移位量。
     * 用在压缩函数的新 E 上：E′ = P0(tt2)。它是个线性置换（对 ⊕ 是同态），但把每个输入比特
     * 映射到 3 个输出比特上，于是 1 比特差异会迅速摊满整字。
     */
    public static long p0(long x)
    {
        return u32(x ^ rotl(x, 9) ^ rotl(x, 17));
    }

    /**
     * P1 也是扩散函数。注意它的第二段移位是 23 位，不是 22 位 —— 网上大量资料把这一处抄错。
     *
     * <p>P1(x) = x ⊕ rotl(x, 15) ⊕ rotl(x, 23)；只用在消息扩展的递推式里（见 {@link #wExpand}），
     * 不进压缩函数的轮方程 —— 记住这一点，就不会把它和 P0 用错位置。
     */
    public static long p1(long x)
    {
        return u32(x ^ rotl(x, 15) ^ rotl(x, 23));
    }

    /**
     * 初始值 IV —— 标准的 8 个 32-bit 字。
     *
     * <p>IV = V₀ = (A₀,B₀,C₀,D₀,E₀,F₀,G₀,H₀)，即第一个链接值；它没有输入消息，是"从零开始折叠"的起点。
     * 这 8 个字不是随便挑的：标准里说明它们取自无理性数的分数部分小数（和 SHA 系列同一个套路），
     * 目的是让初始状态看不出人为构造的规律（nothing-up-my-sleeve number，"我不是藏了后门才选这些数"）。
     */
    public static long[] iv()
    {
        return new long[]{
            0x7380166fL, 0x4914b2b9L, 0x172442d7L, 0xda8a0600L,
            0xa96f30bcL, 0x163138aaL, 0xe38dee4dL, 0xb0fb0e4eL
        };
    }

    /**
     * SM3 全流程：MD 填充 -> 逐块压缩（for 循环往前推链接值）-> 大端序列化。
     *
     * <p>三步对应的符号：msg = 原始消息；blocks = 填充切块后的 B₀..Bₙ₋₁（每块 64 字节）；
     * v = 链接值 V（8 个 32-bit 字，初值 V₀ = IV）；循环体 V = CF(V, B) 就是 Merkle–Damgård 折叠；
     * 返回的 32 字节 = 256 bit 摘要，即把最终的 Vₙ 按大端摊平。
     */
    public static byte[] sm3(byte[] msg)
    {
        List<byte[]> blocks = mdPad(msg);
        long[] v = iv();
        for (int i = 0; i < blocks.size(); i++)
        {
            v = cf(v, blocks.get(i));
        }
        return Calc.bytes32(v);
    }

    /**
     * MD 填充：m ‖ 0x80 ‖ 0^k ‖ len₆₄(m)。返回 64 字节块的列表 —— 一个普通过程，就地算完返回。
     *
     * <p>每个记号：
     * <pre>
     *   m            原始消息字节串，长度记 msg.length 字节 = 8·msg.length 比特
     *   ‖            拼接，不是异或
     *   0x80         单个字节 1000 0000₂：它是"比特流末尾补 1"这一步（先补一个 1，再补若干个 0）
     *                因为一个字节装不下"半个 1"，所以 1 必须占满字节的最高位 —— 这就是 0x80 的来历
     *   0^k          k 个全零字节，k 是<b>唯一满足</b> (msg.length + 1 + k) ≡ 56 (mod 64) 的最小非负整数
     *                （代码里写成 zeros = (56 − (len+1) % 64 + 64) % 64；加 64 再 %64 是把负数绕回正值域）
     *   len₆₄(m)     消息<b>比特</b>长度的 64-bit 大端表示（代码里的 bitLen = 8·msg.length 和 bits[8]）
     *   56 / 64      为什么边界是 56：长度字段要占 8 字节，而一个块只有 64 字节，
     *                所以"1 个 0x80 + k 个 0"之后必须正好停在 56 的偏移上，剩下 64−56 = 8 字节给长度。
     *                若 msg.length ≡ 56..63 (mod 64)，56 已经放不下，只能再开一整块（k 最大 55）
     * </pre>
     * 填充后总长一定是 64 的倍数，因此 {@code Calc.chunks(padded, 64)} 不会出现残块。
     * 长度字段的意义：让"不同长度的消息"不可能填成同一个字节串（消掉一大批平凡碰撞），
     * 也是 MD 构造里对长度扩展攻击的一点缓解 —— 详见类注释的术语表。
     */
    public static List<byte[]> mdPad(byte[] msg)
    {
        int zeros = (56 - (msg.length + 1) % 64 + 64) % 64;
        byte[] bits = new byte[8];
        long bitLen = 8L * msg.length;
        for (int i = 0; i < 8; i++)
        {
            bits[i] = (byte)(bitLen >>> (56 - 8 * i));
        }
        byte[] padded = Calc.concat(msg, new byte[]{ (byte)0x80 }, Calc.repeatedByte(0, zeros), bits);
        return Calc.chunks(padded, 64);
    }

    /**
     * 消息扩展：W[0..67]。递推式即标准公式，用一个 for 循环从 j=16 直接就地写进数组 w[j]。
     * 只有 W[j-3] 和 W[j-13] 带循环移位，W[j-6] 是原值 —— 背错这一项是最常见的实现 bug。
     *
     * <p>记号与完整公式（每一项都是 32-bit 字，全部运算 mod 2³²）：
     * <pre>
     *   W[0..15]   直接来自本分组：Calc.words32(block) 把 64 字节按大端切成 16 个字（代码里的 seeded）
     *   W[j]       第 j 个扩展字，j = 16..67（比 64 轮多出 4 个，正因为 W′[j] 要取到 W[j+4]）
     *   seeded     由消息"种子"出来的前 16 个字；后面 52 个字全靠递推，与消息不再直接相关
     *   16, 13, 9, 6, 3  递推里的五个回看距离（下标差），必须与标准完全一致，否则整条流就偏了
     *
     *   W[j] = P1( W[j−16] ⊕ W[j−9] ⊕ rotl(W[j−3], 15) ) ⊕ rotl(W[j−13], 7) ⊕ W[j−6]
     *          └────────── 送进 P1 的那三项 ──────────┘   └── 这两项原样异或进去 ──┘
     * </pre>
     * 扩展的作用：把一个分组的 512 bit 摊成 68 个互相纠缠的字，让每一轮看到的"消息"都不同，
     * 从而把差分/仿射结构打散 —— 这也是 SM3 的轮数虽多但每轮很轻的原因。
     */
    public static long[] wExpand(byte[] block)
    {
        long[] w = new long[68];
        long[] seeded = Calc.words32(block);
        System.arraycopy(seeded, 0, w, 0, 16);
        for (int j = 16; j < 68; j++)
        {
            w[j] = u32(p1(u32(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15)))
                ^ rotl(w[j - 13], 7) ^ w[j - 6]);
        }
        return w;
    }

    /**
     * 压缩函数 CF：一个 for 循环跑满 64 步，最后与上一个链接值逐字异或。
     * 状态是 8 个局部变量 a..h（对应 A..H），每轮用临时变量算出新值再整体赋值 —— 就地推进，不克隆数组。
     *
     * <p><b>入参与中间量的符号（这一段的公式全在这里，逐个字母说明）</b>
     * <pre>
     *   v            进来的链接值 V（上一块的输出，第一块就是 IV）；v[0..7] = A..H，本方法把它当作轮的初值
     *   block        本块的 64 字节消息分组；w = W[0..67] 是它的扩展字，wp = W′[0..63]
     *   W′[j]        = W[j] ⊕ W[j+4]：与 W[j] 配对使用、只喂给低半部 (E..H) 的那一路
     *   j            轮号 0..63；a,b,c,d,e,f,g,h 是<b>本轮开始时</b>的 8 个字（= 上一轮的输出）
     *   rotl(a,12)   本轮里 A 的一个固定变形，SS1/SS2 都用它，代码里先算一次复用
     *   T_j          轮常数（代码里的 tConstant(j)）；rotl(T_j, j) 是把它循环左移 j 位（j≥32 时按 mod 32 折算）
     *   SS1          两个轮临时量之一（标准里写作 SS₁⁽ʲ⁾）：把 A、E、轮常数 T_j 搅在一起得到的"轮混合值"，
     *                它同时进入 TT1 和 TT2，是把状态上下两半耦合起来的那根线
     *   SS2          SS1 的伴生量（标准里写作 SS₂⁽ʲ⁾）：SS1 ⊕ rotl(A,12)，即把 SS1 里那份 A 的变形揭掉
     *   TT1          A′（下一轮的 A）的候选值：高半部 FF_j(A,B,C) + D + SS2 + W′[j]，四项 mod 2³² 相加
     *   TT2          E′（下一轮的 E）的候选值：低半部 GG_j(E,F,G) + H + SS1 + W[j]，四项 mod 2³² 相加
     *   na..nh       下一轮 (A′,B′,C′,D′,E′,F′,G′,H′) 的临时存放；先用它们是因为 8 个值必须同时更新，
     *                否则后面的赋值会读到已被改写的前值（Java 里没有元组赋值，只能先存 8 个临时变量）
     *   + 与 mod     加法一律用 u32() 截断到 32 位（mod 2³²）；⊕ 是逐比特异或，两者都不要写混
     * </pre>
     *
     * <p>标准里那四行轮方程（和下面代码一一对应）：
     * <pre>
     *   SS1 = rotl( rotl(A,12) + E + rotl(T_j,j), 7 )
     *   SS2 = SS1 ⊕ rotl(A,12)
     *   TT1 = FF_j(A,B,C) + D + SS2 + W′[j]
     *   TT2 = GG_j(E,F,G) + H + SS1 + W[j]
     *   A′ = TT1      B′ = A      C′ = rotl(B,9)     D′ = C
     *   E′ = P0(TT2)  F′ = E      G′ = rotl(F,19)    H′ = G
     * </pre>
     * 注意 C′/G′ 带了循环移位：状态往"下游"流动时不只是平移一格，还顺手做一次扩散，
     * 于是同一个字的差异要经过好几轮才走完全程 —— 这正是 64 轮的"传播路径"设计。
     * 最后的输出异或（把 8 个新字与进来的 v[i] 逐字异或）：V′ = (A′..H′) ⊕ (A..H)，
     * 作用是把"这一轮折叠出来的东西"和"上一块的链接值"再混一次，
     * 攻击者无法只看到最终状态的一部分就反推中间态（与 Davies–Meyer 同一思路的防碰撞加固）。
     */
    public static long[] cf(long[] v, byte[] block)
    {
        // w = W[0..67]：本分组的消息扩展字；wp = W′[0..63] = W[j] ⊕ W[j+4]，与 w[j] 成对使用
        long[] w = wExpand(block);
        long[] wp = new long[64];
        for (int i = 0; i < 64; i++)
        {
            wp[i] = u32(w[i] ^ w[i + 4]);
        }

        // 把进来的链接值 V 拆成 8 个局部变量：a=A=v[0], b=B=v[1], … h=H=v[7]
        long a = v[0], b = v[1], c = v[2], d = v[3];
        long e = v[4], f = v[5], g = v[6], h = v[7];
        for (int j = 0; j < 64; j++)
        {
            // SS1 = rotl( rotl(A,12) + E + rotl(T_j, j), 7 )：先把 A 的变形、E、轮常数三项相加（mod 2³²），
            // 再整体左移 7 位。u32 包在里面是因为三个 32-bit 相加最多溢出 2 位，必须先截断再移位。
            long ss1 = rotl(u32(rotl(a, 12) + e + rotl(tConstant(j), j)), 7);
            // SS2 = SS1 ⊕ rotl(A,12)：把 SS1 里"已经含着的 A 变形"揭掉，得到纯粹的 E + T_j 部分
            long ss2 = u32(ss1 ^ rotl(a, 12));
            // TT1 = FF_j(A,B,C) + D + SS2 + W′[j]：高半部（A,B,C,D）这一路的四轮输入，将成为下一轮的 A′
            long tt1 = u32(ff(j, a, b, c) + d + ss2 + wp[j]);
            // TT2 = GG_j(E,F,G) + H + SS1 + W[j]：低半部（E,F,G,H）这一路，经 P0 扩散后成为下一轮的 E′
            long tt2 = u32(gg(j, e, f, g) + h + ss1 + w[j]);
            // 先算出下一轮的 8 个字，再整体写回局部变量（不新建数组）
            // 下一轮状态 = 本轮值沿曲线"滑动"一格：
            //   na = A′ = TT1              新注入的高半部结果
            //   nb = B′ = A                旧的 A 平移过来
            //   nc = C′ = rotl(B, 9)       旧的 B 平移并循环左移 9 位（顺带扩散）
            //   nd = D′ = C                旧的 C 平移过来
            //   ne = E′ = P0(TT2)          新注入的低半部结果，先过扩散置换 P0
            //   nf = F′ = E                旧的 E 平移过来
            //   ng = G′ = rotl(F, 19)      旧的 F 平移并循环左移 19 位
            //   nh = H′ = G                旧的 G 平移过来
            long na = tt1;
            long nb = a;
            long nc = rotl(b, 9);
            long nd = c;
            long ne = p0(tt2);
            long nf = e;
            long ng = rotl(f, 19);
            long nh = g;
            a = na;
            b = nb;
            c = nc;
            d = nd;
            e = ne;
            f = nf;
            g = ng;
            h = nh;
        }
        // 输出异或：新的链接值 V′ = (A′..H′) ⊕ (A..H)，即逐字与进来的 v[i] 再异或一次；
        // 每个 u32 只是防御性截断（异或本身已落在 32 位内），返回的 8 个字就是下一块的链接值 V
        return new long[]{
            u32(a ^ v[0]), u32(b ^ v[1]), u32(c ^ v[2]), u32(d ^ v[3]),
            u32(e ^ v[4]), u32(f ^ v[5]), u32(g ^ v[6]), u32(h ^ v[7])
        };
    }
}
