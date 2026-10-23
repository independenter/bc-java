package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.kems.mlkem.MLKEMEngine;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.mldsa.MLDSAEngine;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.junit.Assert;
import org.junit.Test;

/**
 * 后量子密码（PQC）的本质计算 —— 面向过程版，覆盖 ML-DSA(FIPS 204) 与 ML-KEM(FIPS 203)。
 *
 * <p>格密码之所以难懂，是因为教科书先给你 Matrix、Polynomial、NTTDomain、Key 四类对象，
 * 于是"多项式环上的乘法"看起来像一门代数课。本类把它压回三条事实：
 * <ol>
 *   <li><b>元素就是数组</b>：R_q = Z_q[X]/(X^256+1) 的一个元素 == {@code int[256]}，
 *       "X^256 = -1" 这一条规则就是乘法循环里的那个负号，除此之外没有任何魔法。</li>
 *   <li><b>NTT 只是换基</b>：它是"在 256 个根上求值"这个线性映射，把卷积变成逐点乘。
 *       本类用教科书定义（O(n^2) 求值，两层 for 循环）和蝴蝶版（O(n log n)，就地交换的三级嵌套 for）
 *       各写一遍，然后断言两者逐系数相等 —— 快速算法没有引入任何新数学。</li>
 *   <li><b>安全性全部来自"分解 + 压缩 + 拒绝采样 + 打包"</b>：这四件事就是格密码里的"填充模式"。
 *       它们同样是与环乘法互不相干的普通静态方法：t = t1·2^13 + t0、compress(q, d, x) = round(2^d·x/q)、
 *       rejection = 在随机字节流上"while 抽到够为止"、pack = 低位在前的比特流。</li>
 * </ol>
 *
 * <p>"算法模式"在这里的可数对应物：ML-DSA 的三个安全级别 × {pure, SHA-512 预哈希} 共 6 种，
 * ML-KEM 的三个级别；以及 ML-DSA 的 mu-mode（先算 mu = SHAKE256(tr‖M) 再签，结果必须与直接签完全相同）。
 *
 * <p>面向对象与高阶函数在这里如何被消掉：多项式没有类，只有 {@code int[]}；
 * 所有运算都是带真实参数的静态方法 —— {@code mulPoly(q, a, b)}、{@code nttBook(q, psi, a)}、
 * {@code compress(q, d, x)}，没有柯里化，也没有 {@code q -> d -> x -> ...} 这种一层层传参的写法；
 * "随机数生成器"是一个普通方法 {@code shakeBytes(seed, count)}（SHAKE256 现场展开）；
 * "采样器"就是一个 while-重试循环；循环变量、累加器、局部数组都明明白白写出来。
 * BC 与 JCE 只当裁判：环运算、NTT、分解、打包全部我们自己写，字节数与密钥材料拿去和 BC 对。
 *
 * <p>两个必须记对的数字：Dilithium 的 q = <b>8380417</b> = 2^23 - 2^13 + 1（不是 8380427），
 * Kyber 的 q = <b>3329</b> = 13·2^8 + 1。为什么是这两个数，见 {@link #moduliAreChosenForRootsOfUnity()}；
 * 密文长度 768/1088/1568 的由来见 {@link #kemCiphertextLengthIsJustTheSumOfCompressedCoefficients()}。
 *
 * <p><b>为什么需要后量子（动机三句话）</b>：RSA/ECC 的安全性建立在"整数分解"与"离散对数"上，
 * 而 Shor 算法在量子机上把两者都化成"求周期"（用量子傅里叶变换），多项式时间可解 —— 一次性报废整族算法。
 * 格密码换用两个新问题：<b>SIS（短整数解, Short Integer Solution）</b>：给定随机 A 与 t = A·s (mod q)，
 * 找非零的短向量 s（或短组合）；<b>LWE（容错学习, Learning With Errors）</b>：区分样本 (A, A·s + e) 与均匀随机对，
 * 小噪声 e 把"解线性方程组"变成带误差的最优化，可归约到格上的<b>最短向量问题 (SVP, Shortest Vector Problem)</b>，
 * 已知最好（经典与量子）算法对 256 维格都是指数时间。<b>模块 LWE (Module-LWE)</b> 是 LWE 的省内存变体：
 * 把矩阵换成立在多项式环 R_q 上的 k×l 矩阵（乘法 = 环乘），ML-DSA 与 ML-KEM 都建在它上面。
 * 量子下唯一通用的加速是 <b>Grover 搜索</b>：它只把安全性<b>减半</b>（2^128 强度 → 2^64），
 * 所以标准把哈希/对称长度统统翻倍取：128-bit 级别用 SHAKE256/SHA3-256，这就是 32 字节尾巴的由来。
 *
 * <p><b>两个安全目标（各一句话）</b>：<b>EUF-CMA</b>（选择消息攻击下的存在性不可伪造, existential unforgeability
 * under chosen-message attack）是对<b>签名</b>的要求：拿到任意多条合法签名，也造不出一个新的 (消息, 签名) 对过验；
 * <b>IND-CCA</b>（选择密文攻击下的不可区分, indistinguishability under chosen-ciphertext attack）是对<b>KEM</b>的要求：
 * 敌人带着解密 oracle 也分不清"密文对应的密钥"与一串随机字节 —— ML-KEM 用 Fujisaki-Okamoto 变换把
 * 只有 IND-CPA（无解密 oracle 的不可区分）的内核升级到 IND-CCA（见命题九的隐式拒绝）。
 *
 * <p><b>KAT 与"安全级别 1/3/5"</b>：NIST 随 FIPS 203/204 发布一组 <b>KAT（已知答案测试, known-answer test）</b>：
 * 固定 seed，公布期望的 pk/sk/签名/密文 hex 串；本类不抄这些向量，只对照标准正文的<b>参数表</b>
 * （q、ψ=1753、q=13·2^8+1、签名 2420/3309/4627、密文 768/1088/1568 等 —— 每个断言里的"常识值"都是官方表值）。
 * "级别 1/3/5"指 NIST 安全强度等级，≈ 与 AES-128/192/256 暴力同级；名字里的 44/65/87 与 512/768/1024
 * 只是 k、l、哈希位数的组合编号，不是强度本身。
 *
 * <p><b>符号表 —— 全类公式共享的字母/记号（各节另有局部表）</b>
 * <pre>
 *   q          模数。ML-DSA：q = 8380417 = 2^23 − 2^13 + 1；ML-KEM：q = 3329 = 13·2^8 + 1
 *   Z_q        {0, 1, ..., q−1}，加减乘后都要 mod q 折回来（mod()）；center() 换成对称代表元区间 (−q/2, q/2]
 *   N（书面的 d）  多项式次数 = 256；环元素 == int[256]，下标 i 是 X^i 的系数
 *   X          形式不定元 (formal indeterminate)，不是数值；环规则 X^256 = −1（即 X^256 + 1 = 0）
 *   R_q        商环 Z_q[X]/(X^256+1)："多项式模 X^256+1"。乘法 = 卷积 + 越界项乘 (−1)，见 mulPoly() 里的负号；
 *              X^d ≡ −1 让次数永远折回 255（系数不爆炸），且卷积是负循环的 —— 这正是 NTT 能对角化的形式
 *   ψ (PSI)    单位根 (root of unity) = 1753：ψ^256 ≡ −1、ψ^512 ≡ 1 (mod q)。"本原 (primitive)"= 阶恰好 512
 *   r_i        第 i 个求值点 = ψ^(2i+1)，是 X^256+1 的 256 个根（roots()；奇数次幂才满足 r^256 = −1）
 *   ω          = ψ^2，256 次本原单位根（ω^256 ≡ 1），nttFast 蝴蝶的旋转因子由它现场算
 *   â = NTT(a) â[i] = a(r_i) = Σ_j a[j]·ψ^((2i+1)·j)：换到"求值坐标"后环乘 == 逐点乘，仅此而已
 *   ξ (xi)     私钥种子，固定 32 字节；整把钥匙（ρ、K、tr、s1、s2、t0）都只是 ξ 的确定性展开
 *   ρ (rho)    由 ξ 展开出的种子，用来展开公钥里的随机矩阵 A（拒绝采样出均匀多项式）
 *   A          k×l 的多项式矩阵（ML-DSA）/ k×k（ML-KEM）；A·s 指环上矩阵乘，∘ 或 pointwiseMul 指逐点乘
 *   s1, s2     私钥"短多项式"：系数限制在小范围（ML-DSA 的 [−η,η]；ML-KEM 的中心二项式），格"短基"的载体
 *   t          公钥主体 t = A·s1 + s2 (mod q)；噪声 s2 让从 t 反解 s1 变成 LWE 难题
 *   d (=D_T)   t 的拆分位宽 = 13：t = t1·2^d + t0（power2Round()）；t1 进公钥，t0 留私钥
 *   y          签名掩码多项式：系数均匀、幅度 &lt; γ1 的一次性随机数（一次签名一枚）
 *   c          挑战多项式：恰好 τ 个非零系数、系数只取 ±1 的稀疏多项式（sampleInBall()）
 *   τ (tau)    挑战多项式的汉明权重 (hamming weight)。FIPS 204 真值 39/49/60；命题七的 demo 借用了 80（见该处说明）
 *   c~         写进签名的挑战摘要，截断到 32/48/64 字节；验签时由它现场重新展开成 c
 *   z          签名响应多项式 z = y + c·s1 (mod q)，签名里最大的一块（ml-dsa-44 每系数 18 bit）
 *   w          签名侧 w = A·y；验签侧重构 w' = A·z − c·t（相差一个可控小噪声），两者高位要一致
 *   w1, w0     w 经 decompose(α) 得到的高/低部分：a = a1·α + a0，α = 2γ2，a1 ∈ [0, M)，M = (q−1)/α = 44 或 16
 *   h          hint 多项式/向量：每系数只补 1 bit，修复 a1 在模 M"绕回"边界处的歧义（MakeHint/UseHint 的对象）
 *   ω提示上限   FIPS 204 用同一希腊字母记"每条签名允许的非零 hint 位数"（80/55/75）—— 与本表的单位根 ω 无关，
 *              文件里 countCrossings() 数出来的就是 hint 密度，sampleInBall 的 demo 权重也借了这个 80
 *   γ1, γ2     幅度参数：γ1 管 y 与 z（2^17 或 2^19），γ2 管 w0 与 hint（(q−1)/88 或 (q−1)/32）
 *   η (eta)    噪声幅度：ML-DSA s1/s2 系数 ∈ [−η,η]（2/4/2）；ML-KEM 用 η1 抽密钥、η2 抽舍入噪声（3/2/2 与 2）
 *   k, l       A 的行数/列数：ML-DSA (4,4)/(6,5)/(8,7)；ML-KEM 是 k×k 方矩阵，k = 2/3/4。
 *              注意 MLDSAParameters.getK() 返回的是 FIPS 等级（2/3/5），引擎 getDilithiumK() 才是行数
 *   μ (mu)     SHAKE256(tr ‖ M, 64)：签名算法真正吃的唯一消息表示；tr = SHAKE256(pk, 64) 是公钥指纹
 *   ‖          字节串拼接 (concatenate)，Calc.concat 同款；不是异或
 *   K, r, z′   ML-KEM：K = 32 字节共享密钥；r/coin = 封装随机硬币；z′ = 私钥尾部的 32 字节"拒绝密钥"
 *              （与上面的 t0/短基符号无关，KEM 一节另有局部表）
 *   d_u, d_v   ML-KEM 密文两段的压缩位数（compress() 的 d 参数：10/10/11 与 4/4/5）
 *   R, qInv    Montgomery 记号（redc()）：R = 2^32，qInv = q^−1 mod R = 58728449，红字见该方法的符号表
 *   Barrett /  Montgomery 是一对"把除 q 换成乘+移位"的工程技巧；本类演示 Montgomery（redc），
 *              Barrett（预乘 ⌊2^k/q⌋ 的近似倒数）是另一族常用做法；q = 2^23 − 2^13 + 1 的形状还能直接移位折位
 * </pre>
 *
 * <p><b>术语一行定义（后文直接使用，不再展开）</b>：
 * <b>格 (lattice)</b> = 一组基向量的全部整数组合构成的点阵；<b>短基 (short basis)</b> = 基向量都很短的表示 ——
 * 私钥本质上就是一把短基，公钥是它经过随机线性变换 + mod q"搅浑"之后的样子。
 * <b>范数 (norm)</b>：本类主要用无穷范数 ‖a‖∞ = max|a[i]|（allAbsAtMost() 就是在查它）；
 * <b>内积 (inner product)</b> ⟨a,b⟩ = Σ a[i]·b[i]。<b>模约减 (mod reduction)</b> = 把系数折回代表元区间
 * （mod()/center()）。<b>中心表示</b>：把 [0,q) 的系数折成对称区间 (−q/2,q/2] —— 签名协议里"短"是用绝对量度的
 * （‖z‖∞ 有界），中心化后小正数与小负数相邻，界检查与 hint 语义都只对"离零多远"敏感，不必在 [0,q) 里绕一大圈。
 * <b>XOF（可扩展输出函数, extendable-output function）</b>= 输入任意短、输出可无限流的哈希（SHAKE128/256），
 * 本类的一切"随机"都来自 shakeBytes() 这一处调用。<b>拒绝采样 (rejection sampling)</b> = 抽到不合格就丢、再抽。
 * <b>高斯采样 (Gaussian sampling)</b> = 按高斯权重在格点上抽点（GPV/Falcon 一系签名的核心，本文件未实现），
 * ML-DSA 改用"均匀 y + 拒绝"绕开它，ML-KEM 用中心二项式（cbd()）当它的廉价近似。
 * <b>可表达性 vs 安全性</b>：断言"t1 装得进 10 bit""密文恰好 768 字节"讲的是可表达性（编码是否够用）；
 * 安全性讲的是敌人能否从这些字节算出 s —— 两者互不蕴含，本类的长度断言只证明前者没有被高估。
 * <b>签名是概率性的</b>：FIPS 204 签名内部有 while 重试环（y 要抽到 z 不越界、hint 数 ≤ ω 才接受），
 * 所以一张签名可能要试多次；但默认确定性模式把重试用的随机数也由 ξ 导出，同一 (ξ, 消息) 仍逐字节可重复 ——
 * 命题八断言的正是这一点。
 */
@Slf4j
public class PqcEssenceTest
{
    /** 环 R_q 的维数（教科书里也写作 d 或 n）：所有多项式都是 256 个系数，X^256 被折回 −X^0。 */
    private static final int N = 256;

    /** ML-DSA 的模数 q = 2^23 − 2^13 + 1（BC 把它作为 public 常量暴露，我们直接引用它当裁判）。 */
    private static final int Q_DSA = MLDSAEngine.DilithiumQ;

    /** ML-KEM 的模数 q = 13·2^8 + 1：q−1 只含 2^8，所以它的 NTT 只能做 8 级（见命题三）。 */
    private static final int Q_KEM = 3329;

    /** BC 源码里被注释掉的 DilithiumRootOfUnity —— 本类现场证明它确实是 512 次本原单位根：ψ^256 ≡ −1。 */
    private static final int PSI_DSA = 1753;

    /** ML-DSA 公私钥分离 t = t1·2^d + t0 时用的比特数 d = 13（BC public 常量 DilithiumD）。 */
    private static final int D_T = MLDSAEngine.DilithiumD;

    /**
     * t1 的位宽 = bitlen(q-1) - d = 23 - 13 = <b>10</b> -> 256·10/8 = 320 字节。
     * 注意不是 "32 - d"：t1 的取值范围由 q 决定，不是由 int 决定。
     * 这是"可表达性"的账（10 bit 装不装得下 t1）；"安全"是另一回事 ——
     * 敌人要从高 10 bit 反推 s1，得先解 Module-LWE，两件事互不蕴含。
     */
    private static final int T1_BITS = (64 - Long.numberOfLeadingZeros(Q_DSA - 1L)) - D_T;

    private static final SecureRandom ANY = new SecureRandom();

    // ---------------------------------------------------------------- 边界：整数取模 / 中心化 / 幂

    /**
     * 非负取模：数学上的 Z_q 元素代表元必须落在 [0,q)。
     * mod 约减 (modular reduction)：x mod q = x − q·⌊x/q⌋，把整数折回 {0,...,q−1} 这 q 个"刻度"之一。
     */
    private static int mod(long x, int q)
    {
        long r = x % q;
        return (int)(r < 0 ? r + q : r);
    }

    /**
     * 中心化代表元：把 [0,q) 折到对称区间 (−q/2, q/2]，这就是"负系数"的唯一来源。
     *
     * <p>为什么签名/噪声侧要用"中心"表示：格问题的"短"是按绝对量度的（‖a‖∞ = max|a[i]|），
     * 而 mod q 后 −1 与 q−1 是同一个元素。若坚持 [0,q) 表示，小负数会变成接近 q 的大正数，
     * 界检查、CBD 噪声、hint 的"越界"语义全都乱掉；折成对称区间后，"离零多远"直接可读，
     * center() 就是这条同构 [0,q) -> (−q/2, q/2] 的落地。
     */
    private static int center(long x, int q)
    {
        int v = mod(x, q);
        return v > q / 2 ? v - q : v;
    }

    /** 模逆：和 RSA 里 d = e^-1 mod λ 用的是同一件事（扩展欧几里得），JDK 已经实现好了。 */
    private static int invMod(int a, int q)
    {
        return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(q)).intValue();
    }

    /**
     * 平方-乘模幂：和 RsaEssenceTest 里的 powMod 是同一个算法，只是这次工作在 32-bit 域。
     * 求单位根、求 256 的模逆、验证 Montgomery 约减都要用它。
     *
     * <p>一个 for 循环<b>从低位到高位</b>扫指数的比特（i = 0 先），只带两个局部变量：
     * sq 记录"base 平到 2^(2^i) 次"，acc 累积答案。方向必须是从低往高数 ——
     * 之前吃过一次亏：把循环方向写反，整条链就全错了。
     */
    private static int powMod(int base, long exp, int q)
    {
        int bits = Math.max(1, 64 - Long.numberOfLeadingZeros(exp));
        int acc = 1;
        int sq = mod(base, q);
        for (int i = 0; i < bits; i++)
        {
            acc = (int)mod((long)acc * ((exp & (1L << i)) != 0 ? sq : 1), q);
            sq = (int)mod((long)sq * sq, q);
        }
        return acc;
    }

    /** 第 k 个 bit（低位在前）—— 所有打包/采样都只用到这一个原语。 */
    private static int bitAt(byte[] src, int k)
    {
        return (src[k >>> 3] >>> (k & 7)) & 1;
    }

    private static byte[] bytesOf(int[] v)
    {
        byte[] out = new byte[v.length];
        for (int i = 0; i < v.length; i++)
        {
            out[i] = (byte)v[i];
        }
        return out;
    }

    /**
     * 从"字节流"里取第 index 个 23-bit 字（低位在前）—— ML-DSA 均匀采样的窗口。
     * <pre>
     *   word = ( b[3i] + b[3i+1]·2^8 + b[3i+2]·2^16 ) mod 2^23     （&amp; 0x7fffff 就是截到 23 位）
     *   i      = index，第几个窗口；ML-DSA 规范写作"从 XOF 流里滑 23-bit 窗口"
     *   23     = bitlen(q) 的下取整：2^23 = 8388608 只比 q = 8380417 大 8191，所以 v ≥ q 的概率约 0.1%
     * </pre>
     */
    private static int word23(byte[] seed, int index)
    {
        byte[] b = shakeBytes(seed, 3 * index + 3);
        int o = 3 * index;
        return ((b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16)) & 0x7fffff;
    }

    // ---------------------------------------------------------------- 随机源：一个普通静态方法

    /**
     * 把"随机数生成器"降回它的真面目：shakeBytes(seed, count) 就是把种子喂进 SHAKE256、
     * 现场展开 count 个字节 —— 同一种子永远给出同一串字节。
     * 给定同一个 seed，所有采样、所有密钥导出都逐字节可重复 —— 这就是 BC 内部
     * "Internal functions are deterministic. No randomness is sampled inside them" 注释的意思。
     *
     * <p><b>XOF（可扩展输出函数, extendable-output function）</b>：SHAKE128/SHAKE256 是 SHA-3 家族的
     * "absorb 任意长输入，squeeze 任意长输出"函数 —— 与普通哈希（输出定长 256/512 bit）的区别只在"能续着流"。
     * 格密码里所有 H / G / ExpandA / ExpandS 都只是"换个前缀再 squeeze 若干字节"：
     * 在随机 oracle 假设 (Random Oracle Model, ROM，把哈希理想成真随机函数) 下它就是免费随机源，
     * ML-DSA 甚至因此能在真机上"现场展开"密钥而不必存储（seed 32 字节 == 全部私钥信息）。
     */
    private static byte[] shakeBytes(byte[] seed, int count)
    {
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(seed, 0, seed.length);
        byte[] out = new byte[count];
        d.doOutput(out, 0, count);
        return out;
    }

    /** 字符串种子版：调用点写 "ring" 就够了（字节内容与直接 getBytes() 完全一致）。 */
    private static byte[] shakeBytes(String seed, int count)
    {
        return shakeBytes(seed.getBytes(), count);
    }

    // ---------------------------------------------------------------- 环 R_q：元素是 int[256]

    /** 加法：逐系数模 q。没有 Polynomial.plus()，只有一个 for 循环。 */
    private static int[] addPoly(int q, int[] a, int[] b)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = mod((long)a[i] + b[i], q);
        }
        return out;
    }

    /** 减法：逐系数模 q。 */
    private static int[] subPoly(int q, int[] a, int[] b)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = mod((long)a[i] - b[i], q);
        }
        return out;
    }

    /** 乘常数：R_q 是 Z_q 的模，所以"数乘"也是逐点的。 */
    private static int[] scalePoly(int q, int c, int[] a)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = mod((long)c * a[i], q);
        }
        return out;
    }

    /** 逐点乘（NTT 域里的乘法）。 */
    private static int[] pointwiseMul(int q, int[] a, int[] b)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = mod((long)a[i] * b[i], q);
        }
        return out;
    }

    /**
     * 环乘法 = 卷积 + "绕回来的那一项取负"。
     * X^256 + 1 = 0 写成 X^256 = -1，所以指数越界时多乘一个 -1 —— 这就是"negacyclic"的全部含义。
     * <pre>
     *   out[i] = Σ_{j=0}^{255} sgn · a[j] · b[(i−j) mod N]，        sgn = +1 (i ≥ j)，−1 (i &lt; j)
     *   i, j            结果的次数下标与求和变量（卷积的两个来源多项式系数）
     *   (i−j) mod N     X^{i−j} 当 i−j &lt; 0 时：X^{i−j} = X^{N+(i−j)}·X^{−N} = X^{N+(i−j)}·(X^N)^{−1}，
     *                   而 X^256 ≡ −1 ⇒ 多出的那个 −1 就是循环里的 (i−j)&gt;=0 ? 1 : −1
     *   acc             long 累加器：256 项、每项 &lt; q² ≈ 2^46，必须借 long 才不会溢出，最后统一 mod q
     * </pre>
     * "绕回取负"（负卷积, negacyclic convolution）同时干了两件事：次数永远折回 &lt; 256（系数不爆炸），
     * 以及让 R_q 恰好能被 NTT 在 256 个根 r_i 上对角化 —— 普通循环卷积对应 X^256−1，根的条件就不同了。
     */
    private static int[] mulPoly(int q, int[] a, int[] b)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            long acc = 0;
            for (int j = 0; j < N; j++)
            {
                acc += ((i - j) >= 0 ? 1L : -1L) * (long)a[j] * b[mod(i - j, N)];
            }
            out[i] = mod(acc, q);
        }
        return out;
    }

    /** 单项式 X^k：只在第 k 个位置是 1。用它来"证明" X^256 = -1。 */
    private static int[] monomial(int k)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = i == mod(k, N) ? 1 : 0;
        }
        return out;
    }

    /** 乘 X：整个系数数组左移一位，绕出去的那一项变号 —— 分组密码里的"移位寄存器"同款。 */
    private static int[] mulByX(int q, int[] a)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = i == 0 ? mod(-a[N - 1], q) : a[i - 1];
        }
        return out;
    }

    /** X^k · a：for 循环里乘 k 次 X —— 稀疏多项式乘法的全部成本就是"移位 + 加"。 */
    private static int[] shifted(int[] a, int k)
    {
        int[] acc = a;
        for (int i = 0; i < k; i++)
        {
            acc = mulByX(Q_DSA, acc);
        }
        return acc;
    }

    /** 随机环元素（裁判用的输入；随机源就是 shakeBytes 展开的 N*4 个字节）。 */
    private static int[] randomPoly(int q, byte[] seed)
    {
        byte[] raw = shakeBytes(seed, N * 4);
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = mod(((raw[4 * i] & 0xffL) << 24) | ((raw[4 * i + 1] & 0xffL) << 16)
                | ((raw[4 * i + 2] & 0xffL) << 8) | (raw[4 * i + 3] & 0xffL), q);
        }
        return out;
    }

    /** 数组版相等断言的助手（int[] 没有 equals）。 */
    private static boolean same(int[] a, int[] b)
    {
        if (a.length != b.length)
        {
            return false;
        }
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }
        return true;
    }

    /** 全部系数都是 0。 */
    private static boolean allZero(int[] a)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /** 除 skip 这一个下标外，其余系数全是 0。 */
    private static boolean allZeroExcept(int[] a, int skip)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (i != skip && a[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /** 所有系数都落在 [lo, hi) 内。 */
    private static boolean allInRange(int[] a, int lo, int hi)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] < lo || a[i] >= hi)
            {
                return false;
            }
        }
        return true;
    }

    /** 所有系数的绝对值都不超过 bound（采样器的支撑集检查）。 */
    private static boolean allAbsAtMost(int[] a, int bound)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (Math.abs(a[i]) > bound)
            {
                return false;
            }
        }
        return true;
    }

    /** 数组里有没有值 v（O(n) 的线性查找，够用）。 */
    private static boolean contains(int[] a, int v)
    {
        for (int i = 0; i < a.length; i++)
        {
            if (a[i] == v)
            {
                return true;
            }
        }
        return false;
    }

    /** 互不相同的值有几个（根表 / 挑战位置的唯一性检查）。 */
    private static int countDistinct(int[] a)
    {
        int n = 0;
        for (int i = 0; i < a.length; i++)
        {
            boolean seen = false;
            for (int j = 0; j < i; j++)
            {
                if (a[j] == a[i])
                {
                    seen = true;
                    break;
                }
            }
            if (!seen)
            {
                n++;
            }
        }
        return n;
    }

    /** 把累加出来的整数逐个折回 [0, q)。 */
    private static int[] modPoly(int[] v)
    {
        int[] out = new int[v.length];
        for (int i = 0; i < v.length; i++)
        {
            out[i] = mod(v[i], Q_DSA);
        }
        return out;
    }

    // ---------------------------------------------------------------- NTT：换基，不是新数学

    /** base^0 .. base^(count-1)，一个 for 循环逐格填。 */
    private static int[] powers(int q, int base, int count)
    {
        int[] out = new int[count];
        for (int i = 0; i < count; i++)
        {
            out[i] = powMod(base, i, q);
        }
        return out;
    }

    /**
     * X^256+1 的 256 个根：r_i = ψ^(2i+1)。ψ^256 = -1 保证每个 r_i 都满足 r_i^256 = -1。
     * <pre>
     *   r_i^256 = (ψ^(2i+1))^256 = (ψ^256)^(2i+1) = (−1)^(2i+1) = −1   —— 奇数次幂是关键：
     *   ψ 的偶数次幂（如 ω^j = ψ^2j）满足的是 X^256 = +1，那是 X^256−1 的根，插值会把符号搞反
     *   互不相同：ψ 的阶是 512，2i+1 (i=0..255) 恰好遍历全部 256 个奇指数 —— 这是"X^256+1 在 Z_q
     *   上完全分裂成一次因子"的构造性证明，也是 NTT 是双射的前提
     * </pre>
     */
    private static int[] roots(int q, int psi)
    {
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            out[i] = powMod(psi, 2L * i + 1, q);
        }
        return out;
    }

    /**
     * 教科书 NTT：â[i] = Σ_j a[j]·ψ^((2i+1)·j) == "多项式 a 在根 r_i 上的取值"，仅此而已。
     * 两层 for 循环：外层是 256 个求值点，内层是 Horner 意义上的逐项累加。
     * <pre>
     *   â[i] = a(r_i) = Σ_{j=0}^{255} a[j]·r_i^j = Σ_j a[j]·ψ^((2i+1)·j)   （把 X ← r_i 代入多项式）
     *   "NTT 就是把多项式乘法变成逐点乘法"：两个多项式在 256 个点上取值都相等 ⇔ 它们相等（次数 &lt; 256），
     *   所以 a·b 在每个 r_i 上的值 = â[i]·b̂[i]，逐点乘 + 插值回去 == 原环里的乘法。
     * </pre>
     */
    private static int[] nttBook(int q, int psi, int[] a)
    {
        int[] rs = roots(q, psi);
        int[] out = new int[N];
        for (int i = 0; i < N; i++)
        {
            int[] pows = powers(q, rs[i], N);
            long acc = 0;
            for (int j = 0; j < N; j++)
            {
                acc += (long)a[j] * pows[j];
            }
            out[i] = mod(acc, q);
        }
        return out;
    }

    /**
     * 教科书逆 NTT：a[j] = 256^-1 · Σ_i â[i]·r_i^(-j)。
     * 它成立只因为 Σ_i r_i^m 在 256 | m 时等于 256、否则等于 0（等比级数）—— 正交性就是全部的证明。
     * <pre>
     *   正交性推导：r_i = ψ·ω^i（ω = ψ^2 是 256 次本原单位根），所以
     *     Σ_i r_i^m = ψ^m · Σ_i (ω^m)^i = ψ^m · (ω^(256m) − 1)/(ω^m − 1)：
     *     ω^m = 1（即 256 | m）时每格都是 1，和 = 256；否则分子为 0 而分母非 0，和 = 0。
     *   于是 Σ_i â[i]·r_i^(−j) = Σ_k a[k]·Σ_i r_i^(k−j) = 256·a[j] —— 只剩 j 那一项活着。
     *   256^−1 存在因为 gcd(256, q) = 1（q 是奇素数）；r_i^(−j) 用 r_i^(2N−j) 实现（r_i^(2N)=1，免求逆）
     * </pre>
     */
    private static int[] invNttBook(int q, int psi, int[] hats)
    {
        int[] rs = roots(q, psi);
        int nInv = invMod(N, q);
        int[] out = new int[N];
        for (int j = 0; j < N; j++)
        {
            long acc = 0;
            for (int i = 0; i < N; i++)
            {
                acc += (long)hats[i] * powMod(rs[i], 2L * N - j, q);
            }
            out[j] = mod((long)mod(acc, q) * nInv, q);
        }
        return out;
    }

    /**
     * 快速 NTT：同一个映射，只是把 O(n^2) 的求值矩阵分解成 8 级蝴蝶。
     *
     * <p>关键恒等式 â[i] = Σ_j (a[j]·ψ^j)·ω^(i·j)，其中 ω = ψ^2 是 256 次本原单位根。
     * 也就是"先把系数各自乘上 ψ^j（这正是 Dilithium 第一层蝴蝶做的事），再作一次普通 256 点 DFT"。
     * DFT 用标准的"位反转 + Cooley-Tukey 迭代蝴蝶"，twiddle 因子现场用 powMod 算，
     * 不需要 BC 那份硬编码的 zetas 表 —— 表只是把 powMod 缓存起来罢了。
     *
     * <p>蝴蝶天生就地更新：一个 pair 的两个输出只依赖这个 pair 的两个输入，
     * 所以直接读写同一个数组 b 即可，不需要函数式写法里"每级复制一份新数组"。
     *
     * <pre>
     *   b[i]    第 i 个蝴蝶槽：写入时 b[i] = a[j]·ψ^j，其中 j = reverse8(i)（i 的低 8 位按位反转，256 = 2^8）
     *   len     当前级的块长：2,4,8,...,256 —— 共 log2(256) = 8 级；每级 N/2 对 (u,v)
     *   w       旋转因子 (twiddle) = ω^((N/len)·low)：把"合并两个 len/2 子变换"的错位相位乘上
     *   u,v     一对输入 (u, v) → 一对输出 (u+v, u−v)："蝴蝶"名字就来自这两条交叉连线
     *   为什么对：n 点 DFT 拆成两个 n/2 点 DFT 的经典恒等式 F(a0,a1)(k) = a0+ω^k·a1、
     *   F(a0,a1)(k+n/2) = a0−ω^k·a1，逐层套用 8 次 = Cooley-Tukey；复杂度从 n^2 降到 (n/2)·log2(n) 次蝶
     * </pre>
     */
    private static int[] nttFast(int q, int psi, int[] a)
    {
        int omega = powMod(psi, 2, q);
        int[] psiPows = powers(q, psi, N);
        // 预_twiddle：b[i] = a[j]·ψ^j（j 是 i 的低 8 位反转），把数组按位反转重排（256 = 2^8）
        int[] b = new int[N];
        for (int i = 0; i < N; i++)
        {
            int j = Integer.reverse(i) >>> 24;
            b[i] = mod((long)a[j] * psiPows[j], q);
        }
        for (int len = 2; len <= N; len <<= 1)
        {
            for (int base = 0; base < N; base += len)
            {
                for (int low = 0; low < len / 2; low++)
                {
                    int w = powMod(omega, (long)(N / len) * low, q);
                    int u = b[base + low];
                    int v = mod((long)b[base + low + len / 2] * w, q);
                    b[base + low] = mod((long)u + v, q);
                    b[base + low + len / 2] = mod((long)u - v, q);
                }
            }
        }
        return b;
    }

    // ---------------------------------------------------------------- "填充模式"之一：分解 t = t1·2^d + t0

    /**
     * 2 的幂分解（ML-DSA 用它把 t 拆成公钥里的 t1 与私钥里的 t0）。
     * 返回 {a1, a0} —— 一个两元素数组，不需要 DecompositionResult 类。
     * <pre>
     *   half = 2^(d−1)                                  d = 13 时 half = 4096
     *   a0   = ((a + half − 1) mod 2^d) − (half − 1)    低 d bit 再"偏置"到对称区间 [−(half−1), half]
     *   a1   = (a − a0) >> d                            高 bit 商（右移 d 位 == 除 2^d，a−a0 天然是 2^d 的倍数）
     *   恒等式  a = a1·2^d + a0（mod q 下），a−a0 ≡ 0 (mod 2^d) 所以移位无损失
     * </pre>
     * <p>边界必须和参考实现一致：a0 的范围是 [-(2^(d-1)-1), 2^(d-1)]，即"上界含、下界不含"。
     * 之所以必须是这一边而不是对称的那一边，是因为 t0 随后要以 (2^(d-1) - a0) 的形式装进 13 bit
     * —— 另一个约定会溢出 1 bit（见 {@link #publicKeyIsJustTheHighBitsOfOnePolynomial()}）。
     */
    private static int[] power2Round(int q, int d, int a)
    {
        int half = 1 << (d - 1);
        int a0 = mod(a + (half - 1), 1 << d) - (half - 1);
        int a1 = (a - a0) >> d;
        return new int[]{ a1, a0 };
    }

    /**
     * γ2 分解（ML-DSA 签名里 z 与 r1 的那一步）。α = 2γ2，且 q-1 必须是 α 的整数倍 ——
     * 这解释了 q = 2^23-2^13+1 为什么被选中：q-1 = 2^13·3·11·31 有 44 与 16 这样的因子。
     * 返回 {a1, a0}，其中 a1 在商 M = (q-1)/α 上取模 —— 这个"绕回 0"就是 hint 存在的理由。
     * <pre>
     *   α (alpha)  = 2γ2：把 [0, q−1] 切成 M = (q−1)/α 段、每段宽 α 的"刻度"（44 档 α=(q−1)/44 → M=44；
     *              65/87 档 α=(q−1)/16 → M=16）
     *   a1         = ⌊(a + α/2)/α⌋ mod M   "四舍五入到最近段"的商；mod M 让最后一段与第 0 段在 q−1↔0 处接吻
     *   a0         = a − a1·α 的中心化代表元，|a0| ≤ γ2 + 1（绕回段附近会多出 1 的余量）
     *   恒等式      a ≡ a1·α + a0 (mod q)
     * </pre>
     * <p>"绕回"的麻烦：a 在 [0,q−1] 头部或尾部时，a1 一个跳到 0 一个跳到 M−1，两者其实只隔着
     * 一条模 q 的接缝。验签端重构的 w' 与签名端的 w 差一个小噪声，一旦落在接缝两侧，
     * 单靠 w1 就无法对齐 —— MakeHint 记下"有没有跨界"这 1 bit，UseHint 把它加回高位模 M 即可对齐。
     * 一条签名总共只允许 ω 个这样的位（80/55/75），这就是 hint 泄漏有 O(ω) bit（每系数 1 bit、
     * 且只说"跨没跨界"，不指出跨了多远）的根本原因。
     */
    private static int[] decompose(int q, int alpha, int a)
    {
        int m = (q - 1) / alpha;
        int a1 = mod((a + alpha / 2) / alpha, m);
        int a0 = center(a - (long)a1 * alpha, q);
        return new int[]{ a1, a0 };
    }

    /**
     * 加一个小噪声 e 后，有多少个探针点的 a1 改变了 —— hint 密度就是它。
     * 一个 for 循环，逐点比较 decompose 前后的高位。
     * <pre>
     *   pts[i]  探针点 a（铺满整个 [0,q) 才碰得到分界线）
     *   noise   加的噪声 e；只有"a 恰好落在某条分界线下方 e 宽的那段"才会把 a1 推过刻度
     *   结论     changed / len(pts) ≈ e/α：刻度越宽（α 大）或噪声越小，越不需要 hint —— ω 的物理意义
     * </pre>
     */
    private static long countCrossings(int alpha, int noise, int[] pts)
    {
        long changed = 0;
        for (int i = 0; i < pts.length; i++)
        {
            int before = decompose(Q_DSA, alpha, pts[i])[0];
            int after = decompose(Q_DSA, alpha, mod(pts[i] + noise, Q_DSA))[0];
            if (before != after)
            {
                changed++;
            }
        }
        return changed;
    }

    // ---------------------------------------------------------------- "填充模式"之二：压缩到 d 位

    /**
     * ML-KEM 的 compress：round(2^d·x/q)，即"把 q 个刻度量化成 2^d 个刻度"。
     * <pre>
     *   x  ∈ [0, q)   量化前的系数（q = 3329 个刻度）
     *   d  ∈ {4,5,10,11}  压缩到的位数；2^d 个输出刻度
     *   式  y = ⌊ (2^d·x + q/2) / q ⌋   —— "+q/2 再整除" 就是四舍五入；再 mod 2^d
     * </pre>
     * 末尾那个 mod 2^d 不是防御性代码：x = q-1 时结果正好等于 2^d，必须绕回 0 ——
     * 这与"量化误差在 Z_q 里中心化"是同一件事（见 kemCiphertextLengthIs... 里的误差断言）。
     */
    private static int compress(int q, int d, int x)
    {
        return (int)(((((long)x << d) + q / 2) / q) & ((1L << d) - 1));
    }

    /**
     * ML-KEM 的 decompress：round(q·y/2^d)，把 2^d 个刻度映回 q 个刻度的代表元。
     * <pre>
     *   式  x' = ⌊ (q·y + 2^(d−1)) / 2^d ⌋ = ⌊ q·y/2^d + 1/2 ⌋   （"(q·y + 半格) >> d" 同样是四舍五入）
     *   误差 |x' − x| ≤ ⌈q / 2^(d+1)⌉：一段量化宽度是 q/2^d，四舍五入最多差半个宽度
     *   这条误差就是 KEM 解密正确性预算：u/v 里每个量化项最多吃掉这么多，累加后仍要小于噪声容限
     * </pre>
     * 量化必然有误差，误差上界就是安全性证明里的噪声预算。
     */
    private static int decompress(int q, int d, int y)
    {
        return (int)(((long)q * y + (1L << (d - 1))) >> d);
    }

    // ---------------------------------------------------------------- "填充模式"之三：比特打包

    /**
     * 低位在前的比特打包：ML-DSA/ML-KEM 的所有"编码"都只是这件事。
     * {@code pack(bits, coeffs)} 得到的字节数必须与 BC 的公开常量逐字节相等。
     * <pre>
     *   bits      每个系数占的位数：t1=10、t0=13、η=4、z=18/20、ML-KEM 系数=12、w1=6 …
     *   全局比特序号 m = 8i + k（i 字节号，k 字节内位号，LSB 在前）
     *   out[i] 的第 k 位 = coeffs[m / bits] 的第 (m mod bits) 位   —— 系数之间"比特流式"紧挨，无字节对齐
     *   长度      coeffs.length·bits/8 字节；256 系数 ⇒ 每 8 位凑 1 字节的整数倍才允许（bits 都整除 8·32）
     * </pre>
     */
    private static byte[] pack(int bits, int[] coeffs)
    {
        int nBytes = coeffs.length * bits / 8;
        int[] out = new int[nBytes];
        for (int i = 0; i < nBytes; i++)
        {
            int sum = 0;
            for (int k = 0; k < 8; k++)
            {
                sum += ((coeffs[(8 * i + k) / bits] >>> ((8 * i + k) % bits)) & 1) << k;
            }
            out[i] = sum;
        }
        return bytesOf(out);
    }

    /** 逆操作：从字节流里按 bits 位一段地读出系数 —— out[i] = Σ_k bitAt(data, i·bits + k)·2^k。 */
    private static int[] unpack(int bits, int count, byte[] data)
    {
        int[] out = new int[count];
        for (int i = 0; i < count; i++)
        {
            int sum = 0;
            for (int k = 0; k < bits; k++)
            {
                sum += bitAt(data, i * bits + k) << k;
            }
            out[i] = sum;
        }
        return out;
    }

    // ---------------------------------------------------------------- "填充模式"之四：采样（拒绝式）

    /**
     * 中心二项式采样（ML-KEM 的密钥噪声）：2η 个随机 bit 分成两半，各数 1 的个数再相减。
     * 它是"噪声"的全部来源：系数落在 [-η, η]，因为它是 η 个 ±1 的和。
     * <pre>
     *   η (eta)     ML-KEM 密钥噪声参数 η1 = 3/2/2（按 512/768/1024），舍入噪声 η2 = 2
     *   out[i]      = #A − #B，#A = 第 i 组前 η 个 bit 的 1 数，#B = 后 η 个 bit 的 1 数
     *   第 i 组消耗  2η 个 bit，起始全局位号 = 2η·i（bitAt 逐位取，无需任何算术）
     *   分布         中心二项分布 (centered binomial distribution)：#A,#B ~ Bin(η, 1/2)，
     *                均值 0、方差 = 2·(η·1/4) = η/2；η 大时与离散高斯统计上几乎不可分 ——
     *                它是格密码"高斯采样"最便宜、且天然常数时间（无分支、无泄漏）的近亲
     *   count        = src.length·8/(2η)：给 64 字节/η=2 恰好得 256 个系数
     * </pre>
     */
    private static int[] cbd(int eta, byte[] src)
    {
        int count = src.length * 8 / (2 * eta);
        int[] out = new int[count];
        for (int i = 0; i < count; i++)
        {
            int sumA = 0;
            int sumB = 0;
            for (int j = 0; j < eta; j++)
            {
                sumA += bitAt(src, 2 * eta * i + j);
            }
            for (int j = 0; j < eta; j++)
            {
                sumB += bitAt(src, 2 * eta * i + eta + j);
            }
            out[i] = sumA - sumB;
        }
        return out;
    }

    /**
     * ML-DSA 的均匀采样 = 一条可见的拒绝循环：23-bit 窗口取一个候选，&ge; q 就丢掉，
     * while 循环直到凑够 need 个。教科书写作 while(count &lt; n)，这里就是一模一样的 while；
     * ML-DSA 的 η 采样、r1 采样全是这个形状，index 与 filled 都是普通局部变量。
     * <pre>
     *   循环条件   v = word23(seed, index) ；接受 iff v &lt; q（拒绝条件 v ≥ q）
     *   丢弃率     2^23 − q = 8191 个坏值 / 2^23 ≈ 0.098%，可忽略但必须在（否则分布偏向 [0,2^23) 非均匀）
     *   均匀性     每个 v &lt; q 被接受的概率都是 1（同一段比特窗口唯一决定它），所以拒绝不改变条件分布
     * </pre>
     */
    private static int[] rejectField(int need, byte[] seed)
    {
        int[] out = new int[need];
        int filled = 0;
        int index = 0;
        while (filled < need)
        {
            int v = word23(seed, index);
            index++;
            if (v < Q_DSA)
            {
                out[filled] = v;
                filled++;
            }
        }
        return out;
    }

    /**
     * 4-bit 版拒绝采样：16 个符号里 6 个要丢，丢弃率看得见 —— 用来演示"拒绝不改变均匀性"。
     * 接受域 {0..9}：每个符号的接受概率同为 1/16，条件分布就是 [0,10) 上的均匀分布；
     * 丢弃率 6/16 = 37.5%，所以 bucket 图应该十个桶都在 200±40 附近（命题七里断言）。
     */
    private static int[] rejectNibble(int need, byte[] seed)
    {
        int[] out = new int[need];
        int filled = 0;
        int index = 0;
        while (filled < need)
        {
            byte[] b = shakeBytes(seed, index + 1);
            int v = (b[index] >> (4 * (index & 1))) & 0xf;
            index++;
            if (v < 10)
            {
                out[filled] = v;
                filled++;
            }
        }
        return out;
    }

    /**
     * ML-DSA 的挑战多项式 c：恰好 tau 个非零位置（系数只有 ±1）。
     * "位置撞车就再抽一次"就是一个 while + 一个线性查找的局部循环；
     * 权重精确等于 tau，这就是 c 便宜的原因（见下面的稀疏乘法）。
     * <pre>
     *   slot 公式   slot = (24-bit 窗口 word23 同形状) >>> 9 &amp; 0xff：取 bit 9..16，均匀落在 [0, 256)
     *   拒绝        contains(used, slot) 撞车就丢 —— 这是"不放回抽样"的近亲：得到 τ 个互不相同的位置
     *   符号        真规范再抽 1 bit 定 ±1；本类 demo 用 slot 的奇偶当符号（只为演示稀疏乘法）
     *   τ (tau)     权重 = 非零系数个数 = 汉明重量 (hamming weight)。FIPS 204 真值 39/49/60；
     *               这里的 demo 借用 80（恰好是 ml-dsa-44 的 hint 上限 ω），性质断言与 τ 的具体值无关
     * </pre>
     */
    private static int[] sampleInBall(int tau, byte[] seed)
    {
        int[] used = new int[tau];
        int count = 0;
        int index = 0;
        while (count < tau)
        {
            byte[] b = shakeBytes(seed, 3 * index + 3);
            int o = 3 * index;
            int slot = (((b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16)) >>> 9) & 0xff;
            index++;
            if (!contains(used, slot))
            {
                used[count] = slot;
                count++;
            }
        }
        return used;
    }

    // ---------------------------------------------------------------- Montgomery 约减（裁判用的小过程）

    /**
     * Montgomery 约减：R = 2^32，redc(x) = (x - ((x·q^-1) mod R)·q) / R = x·R^-1 mod q。
     * 注意这里是<b>减</b>：教科书写作 -q^-1 mod R 然后加，BC 存的是 +q^-1 mod 2^32 = 58728449，
     * 所以必须减 —— 两种写法凑出的都是 R 的整数倍，结果同样落在 [0, q)。
     * <pre>
     *   R      = 2^32："便宜模数"，mod R 就是取低 32 位（&amp; 0xFFFFFFFFL），除 R 就是右移 32 位
     *   qInv   = q^−1 mod R，满足 m = x·qInv mod R 时 (x − m·q) ≡ 0 (mod R) —— 整除性是 m 的定义
     *   m      = (x·qInv) mod R：唯一能把 x 的"低 32 位"凑成 2^32 倍数的乘子
     *   redc   = (x − m·q)/R ≡ x·R^−1 (mod q)：商式 (x/R) 是精确整数除法，全程没有除 q
     *   用途   Montgomery 域约定：值先乘 R 存着（"待在 Montgomery 域"），最后 invNttToMont 一次性 redc 折回，
     *          中间每次乘法都省掉最贵的"除 q 取模"。Barrett 归约（预乘 ⌊2^k/q⌋ 近似倒数）是同类技巧的另一族。
     * </pre>
     */
    private static int redc(long x, long qInv)
    {
        // 只关心 mod 2^32，所以直接取低 32 位 —— long 的自然溢出在这里是免费的模运算
        long m = (x * qInv) & 0xFFFFFFFFL;
        return mod((x - m * Q_DSA) >> 32, Q_DSA);
    }

    // ---------------------------------------------------------------- 裁判：BC 的 ML-DSA

    /** 私钥 = 32 字节种子的确定性展开。这一步把"密钥对象"还原成"一串比特"。 */
    private static MLDSAPrivateKeyParameters dsaPriv(MLDSAParameters p, byte[] seed)
    {
        return new MLDSAPrivateKeyParameters(p, seed);
    }

    /** 让 BC 签一次：普通方法，消息和私钥都是真实参数。 */
    private static byte[] dsaSign(MLDSAPrivateKeyParameters priv, byte[] msg)
    {
        MLDSASigner s = new MLDSASigner();
        s.init(true, priv);
        s.update(msg, 0, msg.length);
        try
        {
            return s.generateSignature();
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e);
        }
    }

    /** 让 BC 验一次：返回 boolean，没有比这更直白的形状了。 */
    private static boolean dsaVerify(MLDSAPublicKeyParameters pub, byte[] msg, byte[] sig)
    {
        MLDSASigner s = new MLDSASigner();
        s.init(false, pub);
        s.update(msg, 0, msg.length);
        return s.verifySignature(sig);
    }

    /**
     * FIPS 204 表里的 η（s1/s2 的系数幅度，噪声幅度），按级别排 —— 一张常量表，不是三个子类。
     * 完整参数表（k, l, η, τ, γ1, γ2, ω, z 每项位数）：
     * <pre>
     *   ml-dsa-44   k=4, l=4, η=2, τ=39, γ1=2^17, γ2=(q−1)/88, ω=80,  z 每项 18 bit（576 字节/多项式）
     *   ml-dsa-65   k=6, l=5, η=4, τ=49, γ1=2^19, γ2=(q−1)/32, ω=55,  z 每项 20 bit（640 字节/多项式）
     *   ml-dsa-87   k=8, l=7, η=2, τ=60, γ1=2^19, γ2=(q−1)/32, ω=75,  z 每项 20 bit（640 字节/多项式）
     *   签名长度 = c~ 字节 + l·(位数·256/8) + (ω + k) 字节 —— 2420 / 3309 / 4627 全部由这一行算出来
     * </pre>
     */
    private static final int[] ETA = new int[]{ 2, 4, 2 };

    // ---------------------------------------------------------------- 测试

    /**
     * 命题一：R_q 里只有一个数组和一个负号。X^256 = -1 是环的全部额外规则。
     */
    @Test
    public void ringElementsAreCoefficientVectorsAndMultiplicationIsNegacyclic()
    {
        // X^256 = -1：从 1 出发乘 256 次 X，得到的不是 1 而是 -1（即 q-1 落在 0 号位）
        int[] x256 = monomial(0);
        for (int i = 0; i < N; i++)
        {
            x256 = mulByX(Q_DSA, x256);
        }
        Assert.assertEquals("X^256 的 0 号系数必须是 -1（也就是 q-1）", Q_DSA - 1, x256[0]);
        Assert.assertTrue("其余 255 个系数必须为 0", allZeroExcept(x256, 0));

        int[] a = randomPoly(Q_DSA, "ring".getBytes());
        int[] b = randomPoly(Q_DSA, "ring-b".getBytes());
        int[] c = randomPoly(Q_DSA, "ring-c".getBytes());

        // 环乘法的基本代数律：交换、结合、单位元、分配律
        Assert.assertTrue("环乘法必须交换", same(mulPoly(Q_DSA, a, b), mulPoly(Q_DSA, b, a)));
        Assert.assertTrue("环乘法必须结合",
            same(mulPoly(Q_DSA, mulPoly(Q_DSA, a, b), c), mulPoly(Q_DSA, a, mulPoly(Q_DSA, b, c))));
        Assert.assertTrue("1 是单位元", same(mulPoly(Q_DSA, a, monomial(0)), a));
        Assert.assertTrue("乘法对加法分配",
            same(mulPoly(Q_DSA, a, addPoly(Q_DSA, b, c)),
                addPoly(Q_DSA, mulPoly(Q_DSA, a, b), mulPoly(Q_DSA, a, c))));
        Assert.assertTrue("乘 X 就是左移一位（与卷积定义一致）",
            same(mulPoly(Q_DSA, monomial(1), a), mulByX(Q_DSA, a)));
        Assert.assertTrue("乘 0 得 0", allZero(mulPoly(Q_DSA, a, new int[N])));
        // 常数 7 的多项式 = 把 monomial(0) 整体乘 7
        Assert.assertTrue("数乘 = 用常数多项式乘（R_q 是 Z_q 上的代数）",
            same(scalePoly(Q_DSA, 7, a), mulPoly(Q_DSA, a, scalePoly(Q_DSA, 7, monomial(0)))));

        // 次数相加会"绕回来"，绕回来的那一项取负 —— 手动验证一个具体例子
        int[] xHi = mulPoly(Q_DSA, monomial(N - 1), monomial(N - 1));
        Assert.assertEquals("X^255 · X^255 = X^510 = X^254·X^256 = -X^254", Q_DSA - 1, xHi[N - 2]);
        Assert.assertTrue("其余系数必须为 0", allZeroExcept(xHi, N - 2));

        // Kyber 用同一个环，只是模数换成 3329
        int[] expectedKem = new int[N];
        expectedKem[N - 2] = Q_KEM - 1;
        Assert.assertTrue("ML-KEM 的环同样是 X^256 = -1",
            same(mulPoly(Q_KEM, monomial(N - 1), monomial(N - 1)), expectedKem));
        log.info("[PQC-环] q_dsa={} q_kem={} 维数 {}，绕回取负 -> negacyclic", Q_DSA, Q_KEM, N);
    }

    /**
     * 命题二：NTT 是换基，不是新数学。教科书求值、蝴蝶实现、逐点乘三者必须完全一致。
     */
    @Test
    public void nttIsAChangeOfBasisThatMakesConvolutionPointwise()
    {
        // ψ 必须满足 ψ^256 = -1（等价于 ψ 是 512 次本原单位根）。BC 源码里注释掉的 1753 正是它。
        Assert.assertEquals("1753^256 mod q 必须等于 -1", Q_DSA - 1, powMod(PSI_DSA, N, Q_DSA));
        Assert.assertEquals("于是 1753^512 = 1", 1, powMod(PSI_DSA, 2L * N, Q_DSA));

        // r_i = ψ^(2i+1) 是 X^256+1 的 256 个互不相同的根 —— "X^256+1 在 Z_q 上完全分裂"的构造性证明
        int[] roots = roots(Q_DSA, PSI_DSA);
        Assert.assertEquals("256 个根必须互不相同（否则插值不唯一，NTT 就不是双射）",
            N, countDistinct(roots));
        boolean everyRootNegates = true;
        for (int i = 0; i < roots.length; i++)
        {
            if (powMod(roots[i], N, Q_DSA) != Q_DSA - 1)
            {
                everyRootNegates = false;
                break;
            }
        }
        Assert.assertTrue("每个根都必须满足 r^256 = -1", everyRootNegates);

        // NTT(1) 必须等于"根自身的幂"检查：1 在每点取值 1
        Assert.assertTrue("常数 1 的象必须全是 1",
            allInRange(nttBook(Q_DSA, PSI_DSA, monomial(0)), 1, 2));
        // X 的象就是根表本身：这就是"NTT == 求值"最直接的证据
        Assert.assertTrue("X 的象必须正好是 256 个根", same(nttBook(Q_DSA, PSI_DSA, monomial(1)), roots));

        int[] p = randomPoly(Q_DSA, "ntt-a".getBytes());
        int[] q = randomPoly(Q_DSA, "ntt-b".getBytes());

        // 正逆变换互逆：这就是"换基"的意思 —— 双射，不丢信息
        Assert.assertTrue("逆变换必须完全还原系数：NTT^-1(NTT(p)) = p",
            same(invNttBook(Q_DSA, PSI_DSA, nttBook(Q_DSA, PSI_DSA, p)), p));
        // 蝴蝶版必须和教科书版逐系数相等：加速没有改变数学
        Assert.assertTrue("快速 NTT 必须与教科书 NTT 逐系数相等",
            same(nttFast(Q_DSA, PSI_DSA, p), nttBook(Q_DSA, PSI_DSA, p)));
        // 环里卷积的象 = 象的逐点乘 —— NTT 存在的全部理由
        Assert.assertTrue("NTT(p*q) 必须等于 NTT(p)·NTT(q)（逐点）",
            same(nttBook(Q_DSA, PSI_DSA, mulPoly(Q_DSA, p, q)),
                pointwiseMul(Q_DSA, nttBook(Q_DSA, PSI_DSA, p), nttBook(Q_DSA, PSI_DSA, q))));
        // 换基是线性的
        Assert.assertTrue("NTT 必须线性：NTT(p+q) = NTT(p)+NTT(q)",
            same(nttFast(Q_DSA, PSI_DSA, addPoly(Q_DSA, p, q)),
                addPoly(Q_DSA, nttFast(Q_DSA, PSI_DSA, p), nttFast(Q_DSA, PSI_DSA, q))));
        // 逆变换确实是逐点乘的另一半：解完方程还能乘回去
        Assert.assertTrue("用 NTT 算的乘法必须与学校公式算的环乘法一致",
            same(mulPoly(Q_DSA, p, q),
                invNttBook(Q_DSA, PSI_DSA,
                    pointwiseMul(Q_DSA, nttFast(Q_DSA, PSI_DSA, p), nttFast(Q_DSA, PSI_DSA, q)))));
        log.info("[PQC-NTT] ψ={}，{} 个一次因子；O(n^2) 求值与 O(n log n) 蝴蝶逐系数相同", PSI_DSA, N);
    }

    /**
     * 命题三：q 不是随便挑的。"有没有 512 次单位根"决定了 NTT 的形状，这就是两族算法的差别。
     */
    @Test
    public void moduliAreChosenForRootsOfUnity()
    {
        // 结构恒等式：q = 2^23 - 2^13 + 1（这个形状让模约减可以用移位而不是除法）
        Assert.assertEquals("Dilithium 的 q 就是 2^23-2^13+1", (1 << 23) - (1 << 13) + 1, Q_DSA);
        Assert.assertEquals("Kyber 的 q 就是 13*2^8+1", 13 * (1 << 8) + 1, Q_KEM);

        // Z_q^* 是 q-1 阶循环群 -> 512 次单位根存在 <=> 512 | (q-1)
        // 术语：循环群 (cyclic group) = 全体非零元素恰是某个生成元 g 的幂 g^0..g^(q−2)（素数域的经典结论）；
        // 于是"g^(m/k) 的阶 = m" ⟺ k | (q−1)（拉格朗日定理：元素的阶整除群的阶）—— 这就是"有 512 次
        // 单位根 ⟺ 512 | q−1"的全部理由；"本原单位根 (primitive root of unity)"= 阶恰好等于该次数的那个。
        Assert.assertEquals("512 必须整除 q_dsa - 1（否则 NTT 无法把 X^256+1 拆成一次因子）",
            0, (Q_DSA - 1) % (2 * N));
        Assert.assertNotEquals("512 不整除 q_kem - 1：这就是 Kyber 的 NTT 只做 8 级、最后要用 2x2 基例的原因",
            0, (Q_KEM - 1) % (2 * N));
        Assert.assertEquals("但 256 整除 q_kem - 1，所以 Kyber 有 256 阶子群，够它把环切成 128 个二次因子",
            0, (Q_KEM - 1) % N);

        // 2-adic 余量：Dilithium 的 q-1 含 2^13，8 级蝴蝶只用掉 2^8，还剩 2^5
        Assert.assertEquals("q_dsa - 1 里 2 的幂次是 13（NTT 长度最多能到 2^13 = 8192）",
            13, Long.numberOfTrailingZeros(Q_DSA - 1L));
        Assert.assertEquals("q_kem - 1 里 2 的幂次只有 8（正好够 256，一点余量都没有）",
            8, Long.numberOfTrailingZeros(Q_KEM - 1L));

        // 穷举证明"Kyber 域里一个 512 次单位根都没有"（全部 3328 个非零元素都试过，一个 for 循环）
        int kemRoots = 0;
        for (int x = 1; x <= Q_KEM - 1; x++)
        {
            if (powMod(x, N, Q_KEM) == Q_KEM - 1)
            {
                kemRoots++;
            }
        }
        Assert.assertEquals("X^256+1 在 Z_3329 里没有一次因子", 0, kemRoots);
        // 反过来在 Dilithium 域里，X^256+1 有 256 个一次因子（命题二已经用构造法证完：
        // r_i = ψ^(2i+1) 互不相同且都满足 r^256 = -1）。这里只把"为什么够用"的因子分解摆出来。
        Assert.assertEquals("q_dsa - 1 = 2^13 · 1023，而 1023 = 3·11·31（2 的部分有 13 级，远超 9 级）",
            1023, (Q_DSA - 1) >> 13);
        Assert.assertEquals("1023 确实是 3·11·31", 1023, 3 * 11 * 31);

        // Montgomery：BC 公开了 q^-1 mod 2^32 = 58728449，我们验一遍，再证明"乘 q 凑 2^32 倍"的约减是对的
        long qInv = BigInteger.valueOf(Q_DSA).modInverse(BigInteger.ONE.shiftLeft(32)).longValue();
        Assert.assertEquals("BC 的 DilithiumQinv 就是 q^-1 mod 2^32", MLDSAEngine.DilithiumQinv, qInv);

        //  Montgomery 约减见 redc()：注意这里是"减" —— BC 存的是 +q^-1，
        //  代价是结果多乘了一个 R^-1，所以 BC 才到处写 invNttToMont：
        //  值一直待在 Montgomery 域里，最后才一次约回。
        int rInv = BigInteger.valueOf(1L << 32).mod(BigInteger.valueOf(Q_DSA))
            .modInverse(BigInteger.valueOf(Q_DSA)).intValue();
        for (long x : new long[]{ 0, 1, 2, 7, 4096, 8380416L, 12345678L, 987654321L, 70331653613824L })
        {
            Assert.assertEquals("Montgomery 约减必须等于 x·R^-1 mod q（全程只有乘法和移位，没有除法）",
                mod((long)mod(x, Q_DSA) * rInv, Q_DSA), redc(x, qInv));
        }
        Assert.assertEquals("2^32 的模逆乘回去必须还原：R·R^-1 = 1 mod q", 1, mod((long)rInv * (1L << 32), Q_DSA));
        log.info("[PQC-模数] q_dsa-1 = 2^13·3·11·31（13 级单位根），q_kem-1 = 2^8·13（只有 8 级）");
    }

    /**
     * 命题四（"填充模式"之一）：t = t1·2^13 + t0 就是二进制切一刀；
     * 我们的 10/13 bit 打包必须和 BC 真实密钥字节逐字节相同。
     *
     * <p><b>符号表 —— 本节新出现的字母</b>
     * <pre>
     *   ξ        32 字节私钥种子；BC 的 MLDSAPrivateKeyParameters 只存它，s1/s2/t0/rho/tr 全部现场展开
     *   ρ (rho)  从 ξ 展开的种子之一，用来生成随机矩阵 A（均匀多项式由拒绝采样展开成 k·l 份）
     *   A        k×l 多项式矩阵；t = A∘s1 + s2 (mod q)，s1 是 l 个多项式组成的向量（"模块"就是这套矩阵）
     *   t1       公钥里的高位：t1 = (t + 2^12 − 1) >> 13，每系数 10 bit（0..1023），k 项共 k·320 字节
     *   t0       私钥里的低位：t0 = t − t1·2^13 ∈ [−4095, 4096]，编码成 (2^12 − t0) 恰好装 13 bit
     *   pk       公钥编码 = ρ(32字节) ‖ pack10(t1) 的 k 份 —— "32 + k·320" 没有别的名堂
     * </pre>
     *
     * <p><b>为什么只发 t1 还能签/验</b>：验签要重构 w' = A·z − c·t（相差 c·t0 这类小项）。
     * 用 t1·2^13 代替 t 引入的误差相对分解刻度 α = (q−1)/44 或 (q−1)/16 只是"小尾巴"，
     * 只有落在 α 的边界附近才会翻转 a1 —— 而那正是 hint 负责修补的少数系数。
     * 安全性侧：少发低 13 bit 让每个系数多出 2^13 种候选，配上短噪声 s2 后正是 Module-LWE
     * 样本的形状 —— 公钥字节发得出去，s1 仍算不出来。
     */
    @Test
    public void publicKeyIsJustTheHighBitsOfOnePolynomial()
    {
        MLDSAParameters p = MLDSAParameters.ml_dsa_65;
        byte[] seed = shakeBytes("t-is-high-bits", MLDSAEngine.SeedBytes);
        Assert.assertEquals("BC 的种子固定 32 字节", 32, seed.length);

        MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
        int k = MLDSAEngine.getInstance(p, ANY).getDilithiumK();
        int l = MLDSAEngine.getInstance(p, ANY).getDilithiumL();

        // 裁判 1：BC 公开的打包字节数 == 我们自己 pack() 出来的长度
        Assert.assertEquals("t1 每项 10 bit -> 每项 320 字节", 320, MLDSAEngine.DilithiumPolyT1PackedBytes);
        Assert.assertEquals("t0 每项 13 bit -> 每项 416 字节", 416, MLDSAEngine.DilithiumPolyT0PackedBytes);
        int[] t1Coeffs = new int[N];
        for (int i = 0; i < N; i++)
        {
            t1Coeffs[i] = (1 << T1_BITS) - 1 - i % 7;
        }
        Assert.assertEquals("我们的 10-bit 打包长度必须等于 BC 的 T1PackedBytes",
            MLDSAEngine.DilithiumPolyT1PackedBytes, pack(T1_BITS, t1Coeffs).length);

        // 裁判 2：拿 BC 真实密钥的 t1 字节，用我们的 unpack/pack 走一圈，必须逐字节还原
        byte[] t1Bytes = Arrays.copyOfRange(priv.getT1(), 0, MLDSAEngine.DilithiumPolyT1PackedBytes);
        int[] t1Real = unpack(T1_BITS, N, t1Bytes);
        Assert.assertTrue("t1 的系数必须落在 10 bit 内", allInRange(t1Real, 0, 1 << T1_BITS));
        Assert.assertArrayEquals("我们的 10-bit 打包必须逐字节复现 BC 的 t1 编码",
            t1Bytes, pack(T1_BITS, t1Real));

        // 裁判 3：t0 是 13 bit 的"偏置中心化"编码 —— BC 存的是 (2^12 - a0)，我们把这条规则也写出来
        byte[] t0Bytes = Arrays.copyOfRange(priv.getT0(), 0, MLDSAEngine.DilithiumPolyT0PackedBytes);
        int[] t0Stored = unpack(D_T, N, t0Bytes);
        int half = 1 << (D_T - 1);
        int[] t0Real = new int[N];
        for (int i = 0; i < N; i++)
        {
            t0Real[i] = half - t0Stored[i];
        }
        Assert.assertTrue("t0 必须装得进 13 bit（偏置后落在 [0, 2^13)）",
            allInRange(t0Stored, 0, 1 << D_T));
        Assert.assertTrue("t0 的系数必须是中心化的小值：" + t0Real[0],
            allInRange(t0Real, -(half - 1), half + 1));
        Assert.assertArrayEquals("我们的 13-bit 偏置打包必须逐字节复现 BC 的 t0 编码",
            t0Bytes, pack(D_T, t0Stored));

        // 分解恒等式：t1·2^13 + t0 == 原来的 t（在 Z_q 里），这就是公钥只发 t1 还能签名的原因
        int[] t = new int[N];
        for (int i = 0; i < N; i++)
        {
            t[i] = mod((long)t1Real[i] * (1 << D_T) + t0Real[i], Q_DSA);
        }
        for (int i : new int[]{ 0, 1, 127, 255 })
        {
            int[] back = power2Round(Q_DSA, D_T, t[i]);
            Assert.assertEquals("power2Round 必须还原 t1：" + i, t1Real[i], back[0]);
            Assert.assertEquals("power2Round 必须还原 t0：" + i, t0Real[i], back[1]);
        }
        // 全 256 个系数都验一遍：分解是可逆的（可逆性 = 只用公钥就能把 t1 换回 t）
        int[] rebuilt = new int[N];
        boolean t1IsHighBits = true;
        for (int i = 0; i < N; i++)
        {
            int[] back = power2Round(Q_DSA, D_T, t[i]);
            rebuilt[i] = mod((long)back[0] * (1 << D_T) + back[1], Q_DSA);
            if (back[0] != t1Real[i])
            {
                t1IsHighBits = false;
            }
        }
        Assert.assertTrue("power2Round 必须对整个多项式都可逆", same(t, rebuilt));
        Assert.assertTrue("t1 就是 t 的高位：t1 = (t + 2^12 - 1) >> 13", t1IsHighBits);

        // 公钥编码 = ρ(32) ‖ t1 的 k 份：长度不是魔法
        MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1());
        Assert.assertEquals("ML-DSA 公钥长度 = 32 + k·320", 32 + k * 320, pub.getEncoded().length);
        Assert.assertEquals("公钥字节就是 ρ ‖ pack(t1)",
            Calc.concat(priv.getRho(), priv.getT1()).length, pub.getEncoded().length);
        Assert.assertArrayEquals("我们的打包必须能重建整份 t1", t1Bytes,
            Arrays.copyOfRange(pub.getEncoded(), 32, 32 + MLDSAEngine.DilithiumPolyT1PackedBytes));
        log.info("[PQC-分解] {} k={} l={}：t1={} bit（{} 字节/项），t0={} bit 偏置（{} 字节/项），pk={} 字节",
            p.getName(), k, l, T1_BITS, MLDSAEngine.DilithiumPolyT1PackedBytes,
            D_T, MLDSAEngine.DilithiumPolyT0PackedBytes, pub.getEncoded().length);
    }

    /**
     * 命题五（"填充模式"之二）：γ2 分解与 hint —— 边界那一格就是 hint 存在的全部理由。
     *
     * <p><b>符号表 —— 本节公式里的字母</b>
     * <pre>
     *   m（循环变量）  = M = (q−1)/α：商/高位的个数。44 档 M=44（α=2γ2=(q−1)/44，γ2=(q−1)/88=95232）；
     *                  65/87 档 M=16（α=(q−1)/16，γ2=(q−1)/32）。44↔ml-dsa-44，16↔ml-dsa-65/87
     *   α (alpha)      刻度宽度；a = a1·α + a0 把 [0, q−1] 切成 M 段（每段宽 α），段号就是 a1
     *   probes         探针点集：[0, γ2]、[q−1−γ2, q−1]（绕回接缝两侧）+ 400 个步长遍历点
     *   e (noise)      故意加的小噪声（本测试取 α/16）；countCrossings 数"被 e 推过分界线"的点数
     *   期望 changed   = 20000 · e/α：分界线共 M 条、每条下方 e 宽的条带会把 a1 推高一格，占全域比例 e/α
     *   ω              真签名里 hint 非零位数的上限（80/55/75）—— 由 e 的分布尾部概率选出，保证重试率低
     * </pre>
     *
     * <p>与真实协议的对应：签名端 w = A·y 分解出 (r1, r0)（这里叫 a1/a0），验签端重构的 w' = w + 小误差；
     * 两者只在"绕回接缝"附近可能给出不同的 a1，MakeHint 记下这批系数（≤ ω 个），UseHint 只需
     * "高位加 hint 再 mod M"就把两边对齐 —— 每个 hint 只说"跨没跨界"这 1 bit，不泄漏跨界多少。
     */
    @Test
    public void gammaDecompositionHasExactlyOneBoundaryProblemAndThatIsWhereHintsLive()
    {
        // ml-dsa-44 用 γ2 = (q-1)/88（于是 α = 2γ2 = (q-1)/44，a1 有 44 个取值），
        // ml-dsa-65/87 用 γ2 = (q-1)/32（α = (q-1)/16，a1 有 16 个取值）—— 都能整除，因为 q-1 因子够多
        for (int m : new int[]{ 44, 16 })
        {
            int alpha = (Q_DSA - 1) / m;               // α = 2γ2
            int gamma2 = alpha / 2;
            Assert.assertEquals("q-1 必须是 α = 2γ2 的整数倍", 0, (Q_DSA - 1) % alpha);

            // 恒等式与界：在所有"有代表性"的点上验证（含 q-1 附近的那条绕回边界）
            int[] probes = new int[2 * (gamma2 + 3) + 400];
            int at = 0;
            for (int i = 0; i < gamma2 + 3; i++)
            {
                probes[at++] = i;
            }
            for (int i = Q_DSA - gamma2 - 3; i < Q_DSA; i++)
            {
                probes[at++] = i;
            }
            for (int i = 0; i < 400; i++)
            {
                probes[at++] = mod(1L + 3001177L * i, Q_DSA);
            }

            int wrapped = 0;
            for (int a : probes)
            {
                int[] d = decompose(Q_DSA, alpha, a);
                Assert.assertEquals("a = a1·α + a0 必须在 Z_q 里成立",
                    mod(a, Q_DSA), mod((long)d[0] * alpha + d[1], Q_DSA));
                Assert.assertTrue("|a0| 不能超过 γ2 加一：" + d[1], Math.abs(d[1]) <= gamma2 + 1);
                Assert.assertTrue("a1 必须在 [0, M) = [0," + m + ")", d[0] >= 0 && d[0] < m);
                if (a + gamma2 >= Q_DSA - 1)
                {
                    wrapped++;
                    Assert.assertEquals("绕回时 a1 必须变成 0（这正是需要 hint 的那一段）", 0, d[0]);
                }
            }
            Assert.assertTrue("必须真的探到绕回区间，否则这个测试什么都没验", wrapped > 0);

            // 加一个小噪声 e 后，只有"a 落在分界线下方 e 宽的那一段"才会改变 a1 ——
            // 段的宽度是 e/α 的比例，所以签名里只需要 ω 个提示位（稀疏性就在这里）。
            // 注意探针必须铺满整个域：只在 [0,2^15) 里取值永远碰不到分界线，changed 恒为 0。
            int[] spread = new int[20000];
            for (int i = 0; i < spread.length; i++)
            {
                spread[i] = mod(1L + 419L * i, Q_DSA);
            }
            int e = alpha / 16;
            long changed = countCrossings(alpha, e, spread);
            long expected = 20000L * e / alpha;                 // 理论上正好是 e/α 的比例
            Assert.assertTrue("hint 密度约等于 e/α（噪声越小提示越稀疏）：changed=" + changed + " expected~=" + expected,
                changed > expected / 2 && changed < expected * 3 / 2 + 1);
            // 单调性：噪声砍一半，需要提示的位置也几乎砍一半 —— 这就是 ω 的物理意义
            Assert.assertTrue("噪声减半，hint 数量也必须减半",
                countCrossings(alpha, e / 2, spread) < changed);
            log.info("[PQC-分解] α = {}（γ2 = {}，a1 ∈ [0,{})）：恒等式成立，绕回段唯一，e={} 时 hint 比例 {}/20000（理论 {}）",
                alpha, gamma2, m, e, changed, expected);
        }
    }

    /**
     * 命题六（"填充模式"之三）：ML-KEM 的 compress 就是把 q 个刻度量化成 2^d 个刻度，
     * 密文长度 = 32·(k·d_u + d_v)，一个比特都不多。
     *
     * <p><b>符号表 —— 本节公式里的字母</b>
     * <pre>
     *   k          ML-KEM 的模块维度（不是 FIPS 等级！）：512→2，768→3，1024→4；A 是 k×k，向量 s/e 长 k
     *   d_u, d_v   密文两段的压缩位数：(10,4)/(10,4)/(11,5)
     *   c1, c2     密文 = compress(u, d_u) 的 k 个多项式 ‖ compress(v, d_v) 的 1 个多项式
     *   32·(k·d_u + d_v)   推导：一个多项式 256 个系数 × d bit = 256d/8 = 32d 字节；u 有 k 份、v 有 1 份
     *   pk 长度    = 384·k + 32：t 的 k 个多项式按 12 bit（q &lt; 2^12）打包 + 种子 ρ 的 32 字节
     *   sk 长度    = 768k + 96：IND-CPA 私钥 s 的 k·384 字节 + 整份公钥 k·384+32 + 尾巴 H(pk)(32) ‖ z′(32)
     *   误差预算    ⌈q/2^(d_u+1)⌉：解密时 decompress∘compress 每系数的最大模偏差（在 Z_q 里中心化数）
     * </pre>
     */
    @Test
    public void kemCiphertextLengthIsJustTheSumOfCompressedCoefficients()
    {
        int[][] levels = new int[][]{
            // {k, d_u, d_v, 密文长度} —— FIPS 203 参数表的三列，第四列拿来和 BC 对
            new int[]{ 2, 10, 4, 768 },
            new int[]{ 3, 10, 4, 1088 },
            new int[]{ 4, 11, 5, 1568 },
        };
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024,
        };

        for (int i = 0; i < levels.length; i++)
        {
            int k = levels[i][0], du = levels[i][1], dv = levels[i][2], ct = levels[i][3];
            MLKEMEngine eng = MLKEMEngine.getInstance(params[i]);
            Assert.assertEquals("k 必须来自参数集", k, params[i].getK());
            Assert.assertEquals("BC 的密文长度必须等于 32·(k·d_u + d_v)", 32 * (k * du + dv), eng.getCipherTextBytes());
            Assert.assertEquals("密文长度是公开常识值（" + params[i].getName() + "）", ct, eng.getCipherTextBytes());
            Assert.assertEquals("MLKEMParameters 与引擎必须给同一个密文长度",
                eng.getCipherTextBytes(), params[i].getEncapsulationLength());
            Assert.assertEquals("公钥长度 = 12 bit 系数的 k 份 + 32 字节 ρ", 384 * k + 32, eng.getIndCpaPublicKeyBytes());
            Assert.assertEquals("每个多项式打包 384 字节 = 256 系数 × 12 bit / 8", 384, eng.getPolyVecBytes() / k);
            Assert.assertEquals("私钥 = IND-CPA 私钥 + 公钥 + 两个 32 字节尾巴（H(pk) 与 z）",
                eng.getIndCpaSecretKeyBytes() + eng.getIndCpaPublicKeyBytes() + 64, k * 768 + 96);

            // 量化误差：compress 再 decompress 的误差上界是 ceil(q / 2^(d+1)) —— 这就是 KEM 解密正确性的预算。
            // 误差必须在 Z_q 里"中心化"来量：x = q-1 会量化到 2^d 再绕回 0，看似差了整个 q，
            // 其实在模 q 的意义下差的是 -1 —— 这才是解密时真正的误差。
            int maxErr = (Q_KEM + (1 << (du + 1)) - 1) >> (du + 1);
            for (int x : new int[]{ 0, 1, Q_KEM / 3, Q_KEM / 2, Q_KEM - 2, Q_KEM - 1 })
            {
                int y = compress(Q_KEM, du, x);
                Assert.assertTrue("压缩结果必须能塞进 d 位：" + y, y >= 0 && y < (1 << du));
                Assert.assertTrue("量化误差必须在 ceil(q/2^(d+1)) = " + maxErr + " 内：" + x + " -> " + y,
                    Math.abs(center(decompress(Q_KEM, du, y) - (long)x, Q_KEM)) <= maxErr);
            }
            log.info("[PQC-压缩] {} d_u={} d_v={} 密文 {} 字节，量化误差预算 <= {}",
                params[i].getName(), du, dv, ct, maxErr);
        }

        // 12-bit 打包再和 BC 的真实公钥对：t 的每个系数都装得进 12 bit，且打包约定逐字节相同
        MLKEMParameters p = MLKEMParameters.ml_kem_768;
        MLKEMEngine eng = MLKEMEngine.getInstance(p);
        int[] coeffs = new int[N];
        for (int j = 0; j < N; j++)
        {
            coeffs[j] = (j * 13 + 7) % Q_KEM;
        }
        Assert.assertEquals("Kyber 系数打包 12 bit -> 384 字节", 384, pack(12, coeffs).length);
        Assert.assertTrue("12-bit 打包/解包必须互逆", same(coeffs, unpack(12, N, pack(12, coeffs))));

        byte[] d = shakeBytes("kem-d", MLKEMEngine.SymBytes);
        byte[] z = shakeBytes("kem-z", MLKEMEngine.SymBytes);
        byte[][] kp = eng.generateKemKeyPairInternal(d, z);
        byte[] tBytes = Arrays.copyOfRange(kp[0], 0, 384);     // 第一个多项式的真实编码
        int[] tReal = unpack(12, N, tBytes);
        Assert.assertTrue("公钥里的 t 系数必须落在 12 bit 内", allInRange(tReal, 0, 1 << 12));
        Assert.assertArrayEquals("我们的 12-bit 打包必须逐字节复现 BC 的 t 编码", tBytes, pack(12, tReal));
    }

    /**
     * 命题七（"填充模式"之四）：采样就是一个可见的拒绝循环 + 二项式差分；
     * 挑战多项式只有 τ 个非零系数，所以"乘 c"== τ 次移位加 —— 这是格签名便宜的那一半。
     *
     * <p>两条"便宜"的来源各占一半：<b>签名便宜</b>靠 c 稀疏（τ 项 ±1，乘法退化成 τ 次带符号循环移位）；
     * <b>采样便宜</b>靠全程只有两种原语 —— CBD（数 bit，无分支，天然抗侧信道）和 23-bit 窗口拒绝
     * （丢弃率 ~0.1%，条件分布仍是均匀的）。ML-DSA 全程不做高斯采样（GPV/Falcon 一系的核心技术）：
     * 均匀 y + 拒绝等价的"翻转到界内"就能让 z 的分布与私钥无关，工程上简单得多。
     */
    @Test
    public void samplingIsARejectionLoopAndABinomialDifferenceMadeVisible()
    {
        // ML-KEM 的中心二项式：η 个 ±1 相加，系数必落在 [-η, η]
        for (int eta : new int[]{ 2, 3 })
        {
            int[] noise = cbd(eta, shakeBytes("coins", N * 2 * eta / 8));
            Assert.assertEquals("必须正好得到 256 个系数", N, noise.length);
            Assert.assertTrue("系数必须落在 [-η, η]：" + Arrays.toString(Arrays.copyOf(noise, 6)),
                allAbsAtMost(noise, eta));
            long sum = 0;
            for (int i = 0; i < noise.length; i++)
            {
                sum += noise[i];
            }
            Assert.assertTrue("分布必须近似关于 0 对称", Math.abs((double)sum / noise.length) < 0.3);
        }

        // ML-DSA 的均匀采样：23-bit 窗口 + ">= q 就丢"，丢弃率小得可以忽略，但必须存在
        Assert.assertEquals("23-bit 窗口比 q 多出 8191 个值 —— 它们必须丢掉（约 0.1%）", 8191, (1 << 23) - Q_DSA);
        int[] kept = rejectField(2000, "field".getBytes());
        Assert.assertEquals("必须凑够 2000 个域元素", 2000, kept.length);
        Assert.assertTrue("所有样本都必须同时满足 < 2^23 与 < q", allInRange(kept, 0, Q_DSA));

        // 拒绝采样不改变均匀性：用 4 bit 抽 [0,10)，16 个符号里 6 个要丢，丢弃率看得见
        int[] drawn = rejectNibble(2000, "nib".getBytes());
        Assert.assertEquals("必须凑够 2000 个样本", 2000, drawn.length);
        long[] bucket = new long[10];
        for (int v : drawn)
        {
            bucket[v]++;
        }
        boolean bucketsEven = true;
        for (int i = 0; i < 10; i++)
        {
            if (Math.abs(bucket[i] - 200) >= 40)
            {
                bucketsEven = false;
            }
        }
        Assert.assertTrue("每个桶都应在期望 200 附近：" + Arrays.toString(bucket), bucketsEven);

        // ML-DSA 的挑战多项式：权重恰好 τ，位置互不相同。
        // 注意：这里 demo 取的"τ=80"不是 ml-dsa-44 的真挑战权重（FIPS 真值 τ=39/49/60），
        // 80 恰好是它的 hint 上限 ω；SampleInBall 的性质（权重精确、位置互异、落在 [0,256)）与权重值无关。
        int tau = 80;
        int[] slots = sampleInBall(tau, "ball".getBytes());
        Assert.assertEquals("权重必须精确等于 τ", tau, slots.length);
        Assert.assertEquals("位置必须互不相同", tau, countDistinct(slots));
        Assert.assertTrue("位置必须落在 [0,256)", allInRange(slots, 0, N));

        // c 只有 τ 个 ±1 系数，所以 c·a == τ 次"带符号的 negacyclic 移位"相加 —— 两条路必须同一条答案
        int[] a = randomPoly(Q_DSA, "sparse-a".getBytes());
        int[] cPoly = new int[N];
        for (int i = 0; i < N; i++)
        {
            cPoly[i] = contains(slots, i) ? (i % 2 == 0 ? 1 : Q_DSA - 1) : 0;
        }
        int[] viaShifts = new int[N];
        for (int s = 0; s < slots.length; s++)
        {
            int slot = slots[s];
            int[] moved = shifted(a, slot);
            viaShifts = slot % 2 == 0 ? addPoly(Q_DSA, viaShifts, moved)
                : subPoly(Q_DSA, viaShifts, moved);
        }
        Assert.assertTrue("稀疏乘法必须等于环乘法（这就是 τ 个移位加 = 一次环乘）",
            same(mulPoly(Q_DSA, a, cPoly), modPoly(viaShifts)));

        // 同一个 seed 的采样必须逐比特可重复：这就是"内部函数是确定性的"
        Assert.assertTrue("采样器是确定性的：同 seed 同结果",
            Arrays.equals(cbd(2, shakeBytes("same", 64)), cbd(2, shakeBytes("same", 64))));
        log.info("[PQC-采样] CBD(η=2,3) 支持 [-η,η]；23-bit 窗口丢弃 0.1%；SampleInBall 权重 τ={}", tau);
    }

    /**
     * 命题八：ML-DSA 的密钥生成与签名都只由种子决定（确定性过程）；6 种"算法模式"全部走通，
     * 并且和 JCE 互通。
     *
     * <p><b>确定性的含义</b>：私钥只是 ξ（32 字节），签名过程内部的随机掩码 y 由 XOF(κ‖计数器) 现场展开，
     * 连"拒绝后重抽"消耗的字节数都由 ξ 定死 —— 所以同一 (ξ, M) 两次签名逐字节相同（本测试断言）。
     * FIPS 204 另有 hedged/随机化模式（再喂 32 字节 rn 进去）：那时同一消息可出多张合法签名，
     * 但内部仍是"抽到 z 不越界、hint 数 ≤ ω 才停"的 while 重试环 —— "签名可能重试"是格签名的固有属性。
     * 密码学目标是 <b>EUF-CMA</b>（选择多组消息求签，仍伪造不出第三条有效签名）；本测试用"改一位必失败、
     * 换消息必失败"做最朴素的旁证。
     *
     * <p><b>mu-mode 与哈希结构</b>：算法真正吃的不是 M 而是 μ = SHAKE256(tr ‖ M, 64)，
     * tr = SHAKE256(pk, 64) 是公钥指纹（把签名"钉"在这把公钥上，防止跨公钥移植）。
     * 签名里的 c~ 是另一条哈希：c~ = SHAKE256(r ‖ M, 32/48/64)（r = 掩码 y 的承诺 w1 的压缩摘要），
     * c 再由 c~ 经 SampleInBall 展开 —— "Hash-then-sign" 的 PreHashed 变体只换 M 的进入方式，管线不变。
     */
    @Test
    public void mldsaIsAPureFunctionOfItsSeedAcrossEveryMode()
        throws Exception
    {
        Calc.useBc();
        byte[] msg = "post-quantum but still just hash-then-ring-math".getBytes();

        // ---- 裁判层：BC crypto 层（pure 模式，3 个安全级别）
        MLDSAParameters[] pure = new MLDSAParameters[]{
            MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87,
        };
        int[] sigLen = new int[]{ 2420, 3309, 4627 };

        for (int i = 0; i < pure.length; i++)
        {
            MLDSAParameters p = pure[i];
            byte[] seed = shakeBytes(new byte[]{ (byte)(i + 1) }, MLDSAEngine.SeedBytes);

            // 私钥 = 种子的展开；同一份种子给 BC 与"我们包出去的函数"，必须得到同一把钥匙
            // 展开链（全部是 XOF + 拒绝采样，没有任何"魔法密钥对象"）：
            //   ξ ─XOF→ ρ‖K‖tr ；ρ ─XOF→ 矩阵 A（k·l 个均匀多项式）；K ─XOF→ s1‖s2（η 折返采样）
            //   t = A∘s1 + s2 ─power2Round→ (t1, t0)；公钥只发 ρ‖t1，t0 与 s1/s2 留在 ξ 的展开里
            MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
            byte[][] direct = MLDSAEngine.getInstance(p, ANY).generateKeyPairInternal(seed);
            Assert.assertArrayEquals("rho 是种子的确定性展开", direct[0], priv.getRho());
            Assert.assertArrayEquals("tr 是种子的确定性展开", direct[2], priv.getTr());
            Assert.assertArrayEquals("s1 是种子的确定性展开", direct[3], priv.getS1());
            Assert.assertArrayEquals("t0 是种子的确定性展开", direct[5], priv.getT0());

            // 参数表里有两种"k"，很容易混：MLDSAParameters.getK() 是 FIPS 安全等级（2/3/5），
            // 引擎里的 dilithiumK 才是 A 矩阵的行数（4/6/8）—— 公钥长度用的是后者。
            int k = MLDSAEngine.getInstance(p, ANY).getDilithiumK();
            Assert.assertEquals("FIPS 等级与矩阵行数不是一回事", new int[]{ 2, 3, 5 }[i], p.getK());
            Assert.assertEquals("A 的行数必须来自参数集", new int[]{ 4, 6, 8 }[i], k);

            MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1());
            Assert.assertEquals("公钥长度 = 32 + k·320", 32 + k * T1_BITS * N / 8, pub.getEncoded().length);

            // 签名确定性：同一把钥匙、同一条消息，两次签名逐字节相同（FIPS 204 的 deterministic 模式）
            byte[] sig1 = dsaSign(priv, msg);
            byte[] sig2 = dsaSign(priv, msg);
            Assert.assertArrayEquals("ML-DSA 默认是确定性的：" + p.getName(), sig1, sig2);
            Assert.assertEquals("签名长度必须等于 FIPS 204 表值", sigLen[i], sig1.length);
            Assert.assertTrue("我们的验证器必须认它", dsaVerify(pub, msg, sig1));
            Assert.assertFalse("换消息必须失败", dsaVerify(pub, "other".getBytes(), sig1));
            byte[] bad = sig1.clone();
            bad[100] ^= 1;
            Assert.assertFalse("改一位必须失败", dsaVerify(pub, msg, bad));

            // mu-mode：ML-DSA 只吃 mu = SHAKE256(tr ‖ M)，先把 mu 算出来再签，结果必须一模一样
            // 符号：tr = SHAKE256(pk, 64) 是公钥指纹（把签名钉死在这把公钥上，防跨公钥移植）；μ 恒 64 字节 = CrhBytes；
            // "签 μ 与签 M 同结果"证明算法内部消息只以 μ 的形态进入 —— 预哈希模式换的仅是这一层入口
            MLDSASigner prep = new MLDSASigner();
            prep.init(true, priv);
            prep.update(msg, 0, msg.length);
            byte[] mu = prep.generateMu();
            Assert.assertEquals("mu 固定 64 字节", MLDSAEngine.CrhBytes, mu.length);
            MLDSASigner external = new MLDSASigner();
            external.init(true, priv);
            Assert.assertArrayEquals("签 mu 与签消息必须得到同一张签名（本质：算法只看 mu）",
                sig1, external.generateMuSignature(mu));
            MLDSASigner checkMu = new MLDSASigner();
            checkMu.init(false, pub);
            Assert.assertTrue("验签端同样可以只看 mu", checkMu.verifyMuSignature(mu, sig1));

            log.info("[PQC-ML-DSA] {} 等级={} k={} l={} η={}：pk={} sig={}，确定性 + mu-mode 一致",
                p.getName(), p.getK(), k, MLDSAEngine.getInstance(p, ANY).getDilithiumL(), ETA[i],
                pub.getEncoded().length, sig1.length);
        }

        // ---- 模式层：JCE 的 6 种注册名（3 个级别 × {pure, SHA-512 预哈希}）
        String[] names = new String[]{
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "ML-DSA-44-WITH-SHA512", "ML-DSA-65-WITH-SHA512", "ML-DSA-87-WITH-SHA512",
        };
        MLDSAParameterSpec[] specs = new MLDSAParameterSpec[]{
            MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87,
            MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_65_with_sha512,
            MLDSAParameterSpec.ml_dsa_87_with_sha512,
        };
        for (int i = 0; i < names.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
            kpg.initialize(specs[i]);
            KeyPair kp = kpg.generateKeyPair();

            Signature signer = Signature.getInstance(names[i], "BC");
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(names[i], "BC");
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            Assert.assertTrue(names[i] + "：JCE 必须自验通过", verifier.verify(sig));

            Signature tampered = Signature.getInstance(names[i], "BC");
            tampered.initVerify(kp.getPublic());
            tampered.update("different".getBytes());
            Assert.assertFalse(names[i] + "：换消息必须失败", tampered.verify(sig));

            if (!specs[i].getName().contains("SHA512"))
            {
                MLDSAParameters p = pure[i];
                // 跨层：JCE 的公钥（原始 rho||t1）喂给 crypto 层，必须认出 JCE 的签名
                MLDSAPublicKeyParameters raw =
                    new MLDSAPublicKeyParameters(p, ((MLDSAPublicKey)kp.getPublic()).getPublicData());
                Assert.assertTrue(names[i] + "：手写验证器必须认 JCE 的签名",
                    dsaVerify(raw, msg, sig));

                // 反向：我们只用 32 字节种子展开密钥，JCE 的 KeyFactory 必须接受这份原始编码
                byte[] seed = shakeBytes(names[i], MLDSAEngine.SeedBytes);
                MLDSAPrivateKeyParameters ours = dsaPriv(p, seed);
                PublicKey viaJce = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(
                    new MLDSAPublicKeySpec(specs[i], ours.getPublicKeyParameters().getEncoded()));
                Signature crossCheck = Signature.getInstance(names[i], "BC");
                crossCheck.initVerify(viaJce);
                crossCheck.update(msg);
                Assert.assertTrue(names[i] + "：JCE 必须认我们（从种子展开的）公钥签出的签名",
                    crossCheck.verify(dsaSign(ours, msg)));

                // 私钥只是 32 字节种子：JCE 的密钥类型也直接暴露这一点
                Assert.assertEquals("JCE 私钥必须能回到种子形态",
                    MLDSAEngine.SeedBytes, ((MLDSAPrivateKey)kp.getPrivate()).getSeed().length);
            }
            log.info("[PQC-模式] {} 签名 {} 字节，JCE 双向互通", names[i], sig.length);
        }
    }

    /**
     * 命题九：ML-KEM 是 KEM 不是加密 —— 密文不携带密钥，而是"约束"出同一个密钥；
     * 无效密文不会报错，它静默地导出一个假密钥（Fujisaki-Okamoto 的 implicit rejection），这正是 FO 变换的本质。
     *
     * <p><b>符号表 —— 本节公式里的字母/记号</b>
     * <pre>
     *   ξ=(d‖z′)   私钥种子：d 展开 IND-CPA 密钥对（s、t），z′ 是 32 字节"拒绝密钥"（别和签名侧的 t0 混）
     *   coin / m   封装熵（BC 参数名 randBytes；FIPS 203 里叫消息 m，32 字节）——"换硬币必换密钥"的根源
     *   (K, r)     G(coin ‖ H(pk)) 的前 64 字节：K = 共享密钥（取 32 字节），r = IND-CPA 加密内部硬币
     *              H = SHA3-256（公钥指纹），G = SHA3-512（一劈两半）—— 都是 32 字节体系里的"2× 长度"选择
     *   c=(c1‖c2)  IND-CPA 密文：u = Aᵀ∘r + e1 压 d_u 位、v = tᵀ∘r + e2 + 量化后的消息 压 d_v 位
     *   K̃          隐式拒绝值 = J(z′ ‖ c)，J = SHAKE256 截 32 字节：密文自检不通过时用"它"当密钥返回
     * </pre>
     *
     * <p><b>为什么"静默假密钥"恰好是 IND-CCA 的关键一步</b>：FO 变换给解密端加了一条自检
     * （re-encrypt(c) 得回原密文才认账）。若失败就<b>报错</b>，敌人把报错当判定器逐位试探（典型的
     * Manger/gap-选择密文攻击面）；若失败就<b>返回确定性的假密钥 K̃</b>，敌人拿到的仍是 32 字节随机样
     * 输出、没有任何"错/对"通道可区分 —— 判定器被拆掉，IND-CPA 内核就升格为 IND-CCA。
     * KEM 的应用层（TLS AEAD 密钥派生等）因此永远只见到"一把能用但不对的密钥"，而不是异常。
     * 另注意常见误解（本测试断言纠正过）：密钥不是嵌在密文里的明文，而是双方各自从
     * (coin, pk) 用同一条 G 现场重算出来的 —— 密文只是把 coin"藏"进格问题里的手段。
     */
    @Test
    public void mlkemEncapsulationIsPureAndRejectionIsSilent()
    {
        MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024,
        };

        for (int i = 0; i < params.length; i++)
        {
            MLKEMParameters p = params[i];
            MLKEMEngine eng = MLKEMEngine.getInstance(p);
            byte[] d = shakeBytes(("d" + p.getName()).getBytes(), MLKEMEngine.SymBytes);
            byte[] z = shakeBytes(("z" + p.getName()).getBytes(), MLKEMEngine.SymBytes);

            // keygen 只由 (d, z) 决定
            byte[][] kp1 = eng.generateKemKeyPairInternal(d, z);
            byte[][] kp2 = eng.generateKemKeyPairInternal(d, z);
            Assert.assertArrayEquals("同一对种子必须长出同一把钥匙：" + p.getName(), kp1[0], kp2[0]);
            Assert.assertArrayEquals("私钥种子就是 d||z（64 字节）", Calc.concat(d, z), kp1[5]);
            Assert.assertEquals("公钥 = t 打包 ‖ ρ", eng.getIndCpaPublicKeyBytes(), kp1[0].length + kp1[1].length);

            MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(p, Calc.concat(kp1[0], kp1[1]));
            // 64 字节种子 == 展开后的私钥：两种写法必须给出同一把钥匙
            MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(p, kp1[5]);
            Assert.assertArrayEquals("私钥的公钥部分必须等于公钥编码", pub.getEncoded(), priv.getPublicKey());
            Assert.assertEquals("私钥编码长度 = 768k + 96", p.getK() * 768 + 96, priv.getEncoded().length);
            Assert.assertEquals("会话密钥固定 32 字节", 32, p.getSessionKeySize() / 8);

            // 封装是随机硬币的确定过程：同硬币同密文同密钥
            byte[] coin = shakeBytes("coin", MLKEMEngine.SymBytes);
            byte[][] e1 = eng.kemEncrypt(pub, coin);
            byte[][] e2 = eng.kemEncrypt(pub, coin);
            Assert.assertArrayEquals("给定硬币后封装是确定性的", e1[0], e2[0]);
            Assert.assertArrayEquals("给定硬币后密文也是确定性的", e1[1], e2[1]);
            Assert.assertEquals("密文长度由参数集决定", eng.getCipherTextBytes(), e1[1].length);

            // 解封装与封装共享同一个密钥 —— 双方没有传输密钥，只是各自算出
            Assert.assertArrayEquals("decap(enc) 必须等于 enc 端的密钥", e1[0], eng.kemDecrypt(priv, e1[1]));
            Assert.assertArrayEquals("MLKEMExtractor 与引擎必须给同一个答案",
                e1[0], new MLKEMExtractor(priv).extractSecret(e1[1]));

            // 换硬币 -> 密文和密钥都完全不同。这里必须纠正一个常见误解：
            // ML-KEM 的密钥不是"嵌在密文里的明文"，而是 (K, r) = G(r ‖ H(pk)) ——
            // 封装自己现抛一枚硬币 r，所以换硬币必然换 K；解密端是从密文里恢复同一个 r 再重算 G。
            byte[] otherCoin = shakeBytes("other-coin", MLKEMEngine.SymBytes);
            byte[][] e3 = eng.kemEncrypt(pub, otherCoin);
            Assert.assertFalse("换硬币必须换密文", Arrays.equals(e1[1], e3[1]));
            Assert.assertFalse("换硬币也必须换密钥：K 由 G(r‖H(pk)) 现场导出，不是固定明文",
                Arrays.equals(e1[0], e3[0]));
            Assert.assertArrayEquals("但解封装必须能追回这次封装自己的那把 K", e3[0], eng.kemDecrypt(priv, e3[1]));

            // 走一遍"注入随机源"的公开 API：结果必须与固定硬币的同一条管线兼容
            SecretWithEncapsulation swe = new MLKEMGenerator(ANY).generateEncapsulated(pub);
            Assert.assertEquals("随机封装的密文长度不变", eng.getCipherTextBytes(), swe.getEncapsulation().length);
            Assert.assertArrayEquals("随机封装的密钥必须能被解出来",
                swe.getSecret(), new MLKEMExtractor(priv).extractSecret(swe.getEncapsulation()));

            // 隐式拒绝：改一个 bit（就地改克隆出来的密钥字节），不抛异常、不报错，只是导出另一个 32 字节"假密钥"
            byte[] tamperedCt = e1[1].clone();
            tamperedCt[40] ^= 0x01;
            byte[] rejected = eng.kemDecrypt(priv, tamperedCt);
            Assert.assertEquals("无效密文仍然返回 32 字节（没有任何错误通道）", 32, rejected.length);
            Assert.assertFalse("但它必须不是原来的密钥", Arrays.equals(e1[0], rejected));
            Assert.assertArrayEquals("隐式拒绝同样是确定性的：同输入必同输出", rejected, eng.kemDecrypt(priv, tamperedCt));
            log.info("[PQC-ML-KEM] {} pk={} ct={}，封装/解封装都是确定过程，拒绝是静默的",
                p.getName(), pub.getEncoded().length, eng.getCipherTextBytes());
        }

        // 裁判：BC 与 FIPS 203 的长度表必须一致（公钥 800/1184/1568，密文 768/1088/1568）
        Assert.assertEquals("ML-KEM-512 密文 768 字节", 768, MLKEMParameters.ml_kem_512.getEncapsulationLength());
        Assert.assertEquals("ML-KEM-768 密文 1088 字节", 1088, MLKEMParameters.ml_kem_768.getEncapsulationLength());
        Assert.assertEquals("ML-KEM-1024 密文 1568 字节", 1568, MLKEMParameters.ml_kem_1024.getEncapsulationLength());
        Assert.assertEquals("ML-KEM-512 公钥 800 字节", 800,
            MLKEMEngine.getInstance(MLKEMParameters.ml_kem_512).getIndCpaPublicKeyBytes());
        Assert.assertEquals("ML-KEM-768 公钥 1184 字节", 1184,
            MLKEMEngine.getInstance(MLKEMParameters.ml_kem_768).getIndCpaPublicKeyBytes());
        Assert.assertEquals("ML-KEM-1024 公钥 1568 字节", 1568,
            MLKEMEngine.getInstance(MLKEMParameters.ml_kem_1024).getIndCpaPublicKeyBytes());
    }

    /**
     * 综合题：ML-DSA 的签名流程就是一次环乘法 + 一次分解 + 一次打包，
     * 用普通静态方法把这些步骤逐个摆出来，再让 BC 裁判我们的所有猜想不至于跑偏。
     *
     * <p><b>符号表 —— 本节公式里的字母/记号</b>
     * <pre>
     *   ξ        种子 "mldsa-essence" 展开出 (ρ, κ, tr)；κ (kappa) 是抽 y 的 XOF 种子（本类用固定串代替）
     *   s1, s2   私钥短多项式向量（l 份 / k 份）；s1 系数 ∈ [−η, η]，η=2（ml-dsa-44），存储为 4 bit 偏置值 η−s1[i]
     *   y        掩码向量（l 份），系数均匀 ∈ (−γ1, γ1)；本类用 rejectField 仿制，真实协议 XOF(κ‖i) 逐份抽
     *   γ1, γ2   2^17 与 (q−1)/88（44 档）；α = 2γ2，刻度数 M = 44
     *   w = A∘y  环上矩阵-向量乘（本类拿 NTT(y·s1) 当演示替身，只考换基恒等式）；w1/w0 = decompose 的高/低位
     *   c~ → c   32 字节挑战摘要 → SampleInBall 展开的 τ=39 项 ±1 稀疏多项式（demo 权重借 80，见命题七）
     *   z        响应多项式 z = y + c∘s1 (mod q)，中心折回后按 18 bit/系数打包（576 字节/份 × l=4 份 = 2304）
     *   h        k 个多项式的 hint 拼段，共 ω + k = 80 + 4 = 84 字节；签名 2420 = 32 (c~) + 2304 (z) + 84 (h)
     *   β        = τ·η 的范数上界（44 档 39·2 = 78）：‖c∘s1‖∞ ≤ β —— 下面不等式的来源
     * </pre>
     *
     * <p><b>验签不等式为什么成立（‖z‖ 的上界从哪来）</b>：验签端重构
     * w' = A∘z − c∘t1·2^13，把 z = y + c∘s1 与 t = A∘s1 + s2 代入得
     * w' = A∘y + (c∘s2 − c∘t0 的 2^13 缩放与舍入小项) = w + 小误差 —— 所以只要 (1) z 的分解不引入额外
     * 误差、(2) w' 与 w 的 a1 一致（靠 h 修补边界），验签就通过。
     * (1) 的界是纯加法账：‖z‖∞ = ‖y + c∘s1‖∞ ≤ ‖y‖∞ + ‖c∘s1‖∞。
     * 第一项 &lt; γ1 由采样保证；第二项因为 c 只有 τ 个 ±1 单项式（汉明权重 τ），c∘s1 的每个系数是
     * "τ 个 s1 系数各带符号相加"，而 |s1[·]| ≤ η，所以 ≤ τ·η = β —— 这就是"z 的上界来自 s1 的长度
     * 与 c 的汉明权重"。于是签名端要求 z 折回中心后 ‖z‖∞ ≤ γ1 − β（留 β 的余量给负方向），
     * 打包位数 18 = bitlen(γ1) + 1（γ1 = 2^17 时平移后的 z 全范围不足 2^18）—— 界、位宽、重试条件是同一笔账的三个面。
     *
     * <p><b>为什么必须拒绝采样才能不泄漏私钥</b>：y 均匀，但 z = y + c∘s1 把分布整体"推"了 β 那么远，
     * z 的边缘分布带着 s1 的方向信息。ML-DSA 的处理是把 y 的采样域取成以 0 为中心的对称球，
     * 一旦 z 折回后出界（‖z‖∞ ≥ γ1 − β）或 hint 数超 ω，就整轮丢弃重抽 y ——
     * 被接受的 z 条件分布与"直接从中心均匀球里抽"统计上贴合，泄漏的互信息 ≤ 拒绝率的量级。
     * 对照：不做这层"翻折+拒绝"（比如把 y 抽在不对称区间），η 与 τ 再小也架不住多次签名对方程组解 s1。
     * hint 只泄漏 O(1) bit：每条 hint 一个"跨没跨 α 刻度边界"的判定位，共 ≤ ω=80 bit，
     * 相对 2420 字节签名 ≈ 3% 且与 s1/s2 的取值无关（它只依赖公开刻度与噪声落点）。
     */
    @Test
    public void signingIsOneRingMultiplyOneDecompositionAndOnePack()
    {
        MLDSAParameters p = MLDSAParameters.ml_dsa_44;
        MLDSAEngine eng = MLDSAEngine.getInstance(p, ANY);
        byte[] seed = shakeBytes("mldsa-essence", MLDSAEngine.SeedBytes);
        MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
        MLDSAPublicKeyParameters pub = priv.getPublicKeyParameters();
        Assert.assertArrayEquals("从私钥取出的公钥必须等于我们自己拼的", pub.getEncoded(),
            new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1()).getEncoded());

        // 步骤 0：s1 是"η 采样 + 4 bit（其实 3 bit）偏置打包"的产物 —— 用我们的 unpack 还原，幅度必须 <= η
        // 符号：η = 系数幅度（44 档 = 2）；stored ∈ [0, 2η] 只需 ⌈log2(2η+1)⌉ = 3 bit，标准仍按 4 bit/系数打包（128 字节/份）；
        // 真值 s1[i] = η − stored —— "偏置打包"就是用偏移量 η 把 [0,2η] 翻成 [−η, η]，中心化表示的又一次现身
        int eta = ETA[0];
        int etaBytes = eng.getDilithiumPolyEtaPackedBytes();
        int etaBits = etaBytes * 8 / N;
        int[] s1Stored = unpack(etaBits, N, Arrays.copyOf(priv.getS1(), etaBytes));
        int[] s1 = new int[N];
        for (int i = 0; i < N; i++)
        {
            s1[i] = eta - s1Stored[i];
        }
        Assert.assertTrue("s1 的系数必须落在 [-η, η] = [-" + eta + "," + eta + "]，这才是格问题的困难性来源",
            allAbsAtMost(s1, eta));
        Assert.assertArrayEquals("我们的 η 打包必须逐字节复现 BC 的 s1 编码",
            Arrays.copyOf(priv.getS1(), etaBytes), pack(etaBits, s1Stored));

        // 步骤 1：y 是一个"幅度 < γ1"的多项式 —— 这里用 23-bit 窗口的拒绝采样自己抽一个（while 循环直到凑满 256 个）
        // 符号：γ1 = 2^17（44 档）；真实协议是 y_i ← XOF(κ‖(256+i)) 以 21/22-bit 窗口拒绝后折成 (−γ1, γ1)，
        // 本类用 rejectField 同形状仿制：y = (γ1−1) − (v mod (γ1−1)) ∈ [1, γ1−1]，结论不变 —— 幅度 < γ1
        int gamma1 = 1 << 17;
        int[] yRaw = rejectField(N, "y-sample".getBytes());
        int[] y = new int[N];
        for (int i = 0; i < N; i++)
        {
            y[i] = mod((long)(gamma1 - 1) - yRaw[i] % (long)(gamma1 - 1), Q_DSA);
        }
        Assert.assertEquals("多项式就是 256 个系数", N, y.length);

        // 步骤 2：NTT 域里做一次逐点乘（真实协议是 A∘y，这里用我们自己的环验证换基恒等式）
        int[] wy = nttFast(Q_DSA, PSI_DSA, mulPoly(Q_DSA, y, s1));
        Assert.assertTrue("换基恒等式：NTT(y*s1) = NTT(y)·NTT(s1)",
            same(wy, pointwiseMul(Q_DSA, nttFast(Q_DSA, PSI_DSA, y), nttFast(Q_DSA, PSI_DSA, s1))));

        // 步骤 3：分解出 w1 并打包 —— γ2 分解（ml-dsa-44 用 γ2 = (q-1)/88，所以 w1 ∈ [0,44) 只要 6 bit）
        // 符号：w1 = HighBits(w) = decompose 的段号 a1；真实协议里它被压缩成 r（Compress(r1, 2γ2→4 bit/系数)），
        // 与消息一起进 c~ = H(r ‖ M) —— "承诺"就是这个被哈希进去的高位摘要
        int gamma2 = (Q_DSA - 1) / 88;
        int[] w1 = new int[N];
        for (int i = 0; i < N; i++)
        {
            w1[i] = decompose(Q_DSA, 2 * gamma2, wy[i])[0];
        }
        Assert.assertTrue("w1 必须在 [0, 44) 内，因此 6 bit 就够存", allInRange(w1, 0, 44));
        Assert.assertEquals("6-bit 打包：256·6/8 = 192 字节", 192, pack(6, w1).length);
        Assert.assertTrue("6-bit 打包/解包互逆", same(w1, unpack(6, N, pack(6, w1))));

        // 步骤 4：z = y + c·s1 的形状检查 —— c 是 τ-稀疏的，所以这一步是 τ 次移位加（见命题七）
        //
        // ┌─ 为什么签名侧必须"拒绝采样 + 重试"（本类最该讲清的一条推导）────────────────────────
        // │ z 的定义：z = y + c·s1  （环 R_q 里的加法/乘法；c·s1 就是那 τ 次带符号移位加）
        // │   y    —— 一次性掩码：每签一枚就重抽，系数在 [0, γ1−1] 上均匀（中心化后 ‖y‖∞ ≤ γ1−1）
        // │   c    —— 挑战多项式：恰好 τ 个非零系数、每个是 ±1，故 ‖c‖∞ = 1、‖c‖₁ = τ
        // │   s1   —— 私钥短多项式：‖s1‖∞ ≤ η（FIPS 204 表里 η = 2/4/2）
        // │
        // │ 范数上界的推导（卷积的"1-范数 × ∞-范数"不等式，负卷积同样成立）：
        // │   ‖c·s1‖∞ ≤ ‖c‖₁·‖s1‖∞ = τ·η =：β   —— 记 β 为"挑战把私钥放大"的最大幅度
        // │   于是若无限制：‖z‖∞ = ‖y + c·s1‖∞ ≤ (γ1−1) + β，即 z 的取值范围被 c·s1 整个平移了 β 格
        // │   ml-dsa-44 代数字：γ1 = 2^17 = 131072，τ=39, η=2 → β = 78（65/87 档 γ1=2^19、β 更大）
        // │
        // │ 关键恒等式（FIPS 204 真正的验签/界检查用的是 ∞-范数，不是 ⟨z,z⟩）：
        // │   接受 ⟺ ‖z‖∞ ≤ γ1 − β
        // │   注意 ‖z‖∞ = maxᵢ|z[i]|（本类 allAbsAtMost() 查的就是它）；
        // │   而 ⟨z,z⟩ = Σ z[i]² 开根号得到的是 L2 范数 ‖z‖，那是 Falcon/GPV 里"高斯采样"要控的量，
        // │   ML-DSA 用"均匀 y + ∞-范数拒绝"绕开了高斯采样，所以这里的界写的是 γ1 − β 而不是 √⟨z,z⟩
        // │
        // │ 为什么这条界 = "必须拒绝"的原因（分布与私钥无关）：
        // │   z 是 y 平移 c·s1 的结果；直接交出 z，就等于把"掩码分布"挪了一个依赖 s1 的量，
        // │   敌人可从 z 的统计偏移反推私钥。只有当 ‖z‖∞ 落在 γ1 − β 内才保留——
        // │   这条界把 y 的两端尾巴（离零超过 γ1−β 的那些）统一切掉，切完之后
        // │   留下的 z 分布对每个 s1 都（几乎）一模一样 → z 不泄露任何私钥信息。
        // │   代价就是"抽到的 y 让 z 越界就得丢掉、重抽 y 再试"——签名是概率性的、可能要重试若干轮。
        // │   同一轮里还要顺带检查 w0/r0 的界与 hint 位数 ≤ ω（λ），超限同样整枚重来。
        // │   hint 的 MakeHint/UseHint 与这条界配套：先固定"要交出的高位 w1"，再让 z 的分布只依赖 w1、
        // │   不依赖私钥 —— 这正是"让签名分布与 s 无关"这同一个目标的两面。
        // └──────────────────────────────────────────────────────────────────────────────────
        // 签名 2420 字节的精确拆分（ml-dsa-44）：32 (c~ 挑战摘要) + 4·576 (z：l=4 份 × 18 bit/系数) + 84 (h 段 = ω + k = 80 + 4)。
        // 下一条断言消息里写的 "c~(80)" 中的 80 其实是 hint 上限 ω 的数值（c~ 只有 32 字节；真正的挑战权重 τ=39），别读成"c~ 占 80 字节"。
        byte[] msg = "one multiply, one round, one pack".getBytes();
        byte[] sig = dsaSign(priv, msg);
        Assert.assertTrue("完整签名必须能被我们的手写验证器接受", dsaVerify(pub, msg, sig));
        Assert.assertEquals("ML-DSA-44 的签名长度 = c~(80) + z + hints", 2420, sig.length);
        log.info("[PQC-本质] 一次环乘 + 一次 γ2 分解 + 一次打包 = 一张 {} 字节的后量子签名（γ1={}, γ2={}）",
            sig.length, gamma1, gamma2);
    }

    /**
     * 对照表：把"模式"这件事显式列成一张表 —— 没有 switch，没有子类。
     * ML-DSA 六种模式 + ML-KEM 三种模式，全部只是不同的参数常量喂给同一条管线。
     *
     * <p>名字里的数字：44/65/87（ML-DSA）与 512/768/1024（ML-KEM）是 NIST 安全强度等级 1/3/5 的编号，
     * ≈ 与 AES-128/192/256 的暴力同级；Grover 只把搜索强度减半，所以等级 1 用 256-bit 哈希而不是 128-bit。
     * 本节断言的每个长度都是 FIPS 203/204 官方参数表值：pk 1312/1952/2592 = 32 + k·320，
     * sig 2420/3309/4627 = c~ + l·z份 + (ω+k)，ct 768/1088/1568 = 32·(k·d_u + d_v)。
     * NIST 标准随文发布的固定 seed → 期望字节串叫 KAT（known-answer test）：实现逐字节复现官方表，
     * 才算"和参考实现等价"；本类用"长度 + 结构恒等式 + BC 裁判"覆盖同一张表的骨架。
     */
    @Test
    public void parameterSetsAreATableNotAClassHierarchy()
    {
        Calc.useBc();
        List<MLDSAParameters> dsa = Arrays.asList(
            MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87,
            MLDSAParameters.ml_dsa_44_with_sha512, MLDSAParameters.ml_dsa_65_with_sha512,
            MLDSAParameters.ml_dsa_87_with_sha512);
        List<MLKEMParameters> kem = Arrays.asList(
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024);

        // 同一份代码路径 + 不同常量 = 不同模式：这里连一个 if 都不需要
        Assert.assertEquals("pure 模式不预哈希", Boolean.FALSE, Boolean.valueOf(dsa.get(0).isPreHash()));
        Assert.assertEquals("后 3 个是 SHA-512 预哈希模式", Boolean.TRUE, Boolean.valueOf(dsa.get(3).isPreHash()));
        Assert.assertEquals("同级别的 pure / 预哈希共用 k",
            dsa.get(0).getK(), dsa.get(3).getK());

        byte[] seed = shakeBytes("table", MLDSAEngine.SeedBytes);
        List<byte[]> pks = new ArrayList<byte[]>();
        List<Integer> matrixK = new ArrayList<Integer>();
        List<Integer> fipsK = new ArrayList<Integer>();
        List<Integer> sigLengths = new ArrayList<Integer>();
        // 注意两个 "k"：MLDSAParameters.getK() 存的是 FIPS 安全等级（2/3/5），矩阵行数在引擎里（4/6/8）
        for (int i = 0; i < dsa.size(); i++)
        {
            MLDSAParameters x = dsa.get(i);
            if (!x.isPreHash())
            {
                pks.add(dsaPriv(x, seed).getPublicKeyParameters().getEncoded());
                matrixK.add(MLDSAEngine.getInstance(x, ANY).getDilithiumK());
                fipsK.add(x.getK());
                // 同一条管线：种子 + 级别常量 -> 签名；三种级别的签名长度就是那张表
                sigLengths.add(dsaSign(dsaPriv(x, seed), "same code path".getBytes()).length);
            }
        }
        Assert.assertEquals("A 的行数随级别增长：4 -> 6 -> 8", Arrays.asList(4, 6, 8), matrixK);
        Assert.assertEquals("而参数对象里的 k 是 FIPS 等级：2 -> 3 -> 5", Arrays.asList(2, 3, 5), fipsK);
        Assert.assertTrue("公钥必须越来越长",
            pks.get(0).length < pks.get(1).length && pks.get(1).length < pks.get(2).length);
        Assert.assertEquals("签名长度表 = FIPS 204 Table", Arrays.asList(2420, 3309, 4627), sigLengths);

        // ML-KEM 的"模式"只改变 k 与 du/dv，管线一行没动
        List<Integer> kemK = new ArrayList<Integer>();
        List<Integer> sessionKeys = new ArrayList<Integer>();
        List<Integer> ctLengths = new ArrayList<Integer>();
        for (int i = 0; i < kem.size(); i++)
        {
            MLKEMParameters x = kem.get(i);
            kemK.add(x.getK());
            sessionKeys.add(x.getSessionKeySize() / 8);
            ctLengths.add(x.getEncapsulationLength());
        }
        Assert.assertEquals(Arrays.asList(2, 3, 4), kemK);
        Assert.assertEquals("会话密钥永远是 SHA3-256 的 32 字节", Arrays.asList(32, 32, 32), sessionKeys);
        Assert.assertEquals("密文长度表", Arrays.asList(768, 1088, 1568), ctLengths);

        // ML-DSA 的密钥生成也只是同一条管线，注入的随机源不同而已
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(ANY, MLDSAParameters.ml_dsa_87));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        byte[] challenge = "k=8 l=7".getBytes();
        Assert.assertTrue("最大级别同样可验", dsaVerify((MLDSAPublicKeyParameters)pair.getPublic(), challenge,
            dsaSign((MLDSAPrivateKeyParameters)pair.getPrivate(), challenge)));
        Assert.assertEquals("ML-DSA-87 公钥 = 32 + 8*320", 2592,
            ((MLDSAPublicKeyParameters)pair.getPublic()).getEncoded().length);
        log.info("[PQC-模式表] ML-DSA {} 种 + ML-KEM {} 种，全部是同一条管线上的一张表", dsa.size(), kem.size());
    }
}
