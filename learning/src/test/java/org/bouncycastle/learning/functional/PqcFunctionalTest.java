package org.bouncycastle.learning.functional;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

import static org.bouncycastle.learning.functional.Fp.fold;
import static org.bouncycastle.learning.functional.Fp.foldRange;

/**
 * 后量子密码（PQC）的本质计算 —— 纯函数版，覆盖 ML-DSA(FIPS 204) 与 ML-KEM(FIPS 203)。
 *
 * <p>格密码之所以难懂，是因为教科书先给你 Matrix、Polynomial、NTTDomain、Key 四类对象，
 * 于是"多项式环上的乘法"看起来像一门代数课。本类把它压回三条事实：
 * <ol>
 *   <li><b>元素就是数组</b>：R_q = Z_q[X]/(X^256+1) 的一个元素 == {@code int[256]}，
 *       "X^256 = -1" 这一条规则就是乘法里那个负号，除此之外没有任何魔法。</li>
 *   <li><b>NTT 只是换基</b>：它是"在 256 个根上求值"这个线性映射，把卷积变成逐点乘。
 *       本类用教科书定义（O(n^2) 求值）和蝴蝶版（O(n log n)）各写一遍，然后断言两者逐系数相等 ——
 *       快速算法没有引入任何新数学。</li>
 *   <li><b>安全性全部来自"分解 + 压缩 + 拒绝采样 + 打包"</b>：这四件事就是格密码里的"填充模式"。
 *       它们同样是与环乘法正交的纯函数：t = t1·2^13 + t0、compress(x) = round(2^d·x/q)、
 *       rejection = 在随机流上 filter-and-take、pack = 低位在前的比特流。</li>
 * </ol>
 *
 * <p>"算法模式"在这里的可数对应物：ML-DSA 的三个安全级别 × {pure, SHA-512 预哈希} 共 6 种，
 * ML-KEM 的三个级别；以及 ML-DSA 的 mu-mode（先算 mu = SHAKE256(tr‖M) 再签，结果必须与直接签完全相同）。
 *
 * <p>面向对象如何被消掉：多项式没有类，只有 {@code int[]}；构造器变成柯里化函数
 * {@code q -> psi -> a -> ntt(a)}；"随机数生成器"是一个 {@code Function<Integer, byte[]>}；
 * "采样器"用递归表达 while-重试；折叠用 {@link Fp#fold} / {@link Fp#foldRange}。
 * BC 与 JCE 只当裁判：环运算、NTT、分解、打包全部我们自己写，字节数与密钥材料拿去和 BC 对。
 *
 * <p>两个必须记对的数字：Dilithium 的 q = <b>8380417</b> = 2^23 - 2^13 + 1（不是 8380427），
 * Kyber 的 q = <b>3329</b> = 13·2^8 + 1。为什么是这两个数，见 {@link #moduliAreChosenForRootsOfUnity()}；
 * 密文长度 768/1088/1568 的由来见 {@link #kemCiphertextLengthIsJustTheSumOfCompressedCoefficients()}。
 */
@Slf4j
public class PqcFunctionalTest
{
    /** 环 R_q 的维数：所有多项式都是 256 个系数。 */
    private static final int N = 256;

    /** ML-DSA 的模数（BC 把它作为 public 常量暴露，我们直接引用它当裁判）。 */
    private static final int Q_DSA = MLDSAEngine.DilithiumQ;

    /** ML-KEM 的模数。 */
    private static final int Q_KEM = 3329;

    /** BC 源码里被注释掉的 DilithiumRootOfUnity —— 本类现场证明它确实是 512 次单位根。 */
    private static final int PSI_DSA = 1753;

    /** ML-DSA 公私钥分离 t 时用的比特数（BC public 常量 DilithiumD）。 */
    private static final int D_T = MLDSAEngine.DilithiumD;

    /**
     * t1 的位宽 = bitlen(q-1) - d = 23 - 13 = <b>10</b> -> 256·10/8 = 320 字节。
     * 注意不是 "32 - d"：t1 的取值范围由 q 决定，不是由 int 决定。
     */
    private static final int T1_BITS = (64 - Long.numberOfLeadingZeros(Q_DSA - 1L)) - D_T;

    private static final SecureRandom ANY = new SecureRandom();

    // ---------------------------------------------------------------- 边界：整数取模 / 中心化 / 幂

    /** 非负取模：数学上的 Z_q 元素代表元必须落在 [0,q)。 */
    private static int mod(long x, int q)
    {
        long r = x % q;
        return (int)(r < 0 ? r + q : r);
    }

    /** 中心化代表元：把 [0,q) 折到 (-q/2, q/2]，这就是"负系数"的唯一来源。 */
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
     * 平方-乘模幂：和 RsaFunctionalTest 里的 powMod 是同一个 fold，只是这次工作在 32-bit 域。
     * 求单位根、求 256 的模逆、验证 Montgomery 约减都要用它。
     */
    private static int powMod(int base, long exp, int q)
    {
        final int bits = Math.max(1, 64 - Long.numberOfLeadingZeros(exp));
        return foldRange(0, bits, new int[]{ 1, mod(base, q) }, (st, i) -> new int[]{
            (int)mod((long)st[0] * ((exp & (1L << i)) != 0 ? st[1] : 1), q),
            (int)mod((long)st[1] * st[1], q) })[0];
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

    /** 从"字节流函数"里取第 index 个 23-bit 字（低位在前）—— ML-DSA 均匀采样的窗口。 */
    private static int word23(Function<Integer, byte[]> stream, int index)
    {
        final byte[] b = stream.apply(3 * index + 3);
        final int o = 3 * index;
        return ((b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16)) & 0x7fffff;
    }

    // ---------------------------------------------------------------- 环 R_q：元素是 int[256]

    /** 加法：逐系数模 q。没有 Polynomial.plus()，只有一条 map。 */
    static final Function<Integer, BiFunction<int[], int[], int[]>> ADD = q -> (a, b) ->
        IntStream.range(0, N).map(i -> mod((long)a[i] + b[i], q)).toArray();

    /** 减法：逐系数模 q。 */
    static final Function<Integer, BiFunction<int[], int[], int[]>> SUB = q -> (a, b) ->
        IntStream.range(0, N).map(i -> mod((long)a[i] - b[i], q)).toArray();

    /** 乘常数：R_q 是 Z_q 的模，所以"数乘"也是逐点的。 */
    static final Function<Integer, Function<Integer, UnaryOperator<int[]>>> SCALE = q -> c -> a ->
        IntStream.range(0, N).map(i -> mod((long)c * a[i], q)).toArray();

    /** 逐点乘（NTT 域里的乘法）。 */
    static final Function<Integer, BiFunction<int[], int[], int[]>> POINTWISE = q -> (a, b) ->
        IntStream.range(0, N).map(i -> mod((long)a[i] * b[i], q)).toArray();

    /**
     * 环乘法 = 卷积 + "绕回来的那一项取负"。
     * X^256 + 1 = 0 写成 X^256 = -1，所以指数越界时多乘一个 -1 —— 这就是"negacyclic"的全部含义。
     */
    static final Function<Integer, BiFunction<int[], int[], int[]>> MUL = q -> (a, b) ->
        IntStream.range(0, N).map(i -> mod(foldRange(0, N, 0L, (acc, j) ->
            acc + ((i - j) >= 0 ? 1L : -1L) * (long)a[j] * b[mod(i - j, N)]), q)).toArray();

    /** 单项式 X^k：只在第 k 个位置是 1。用它来"证明" X^256 = -1。 */
    static final Function<Integer, int[]> MONOMIAL = k ->
        IntStream.range(0, N).map(i -> i == mod(k, N) ? 1 : 0).toArray();

    /** 乘 X：整个系数数组左移一位，绕出去的那一项变号 —— 分组密码里的"移位寄存器"同款。 */
    static final Function<Integer, UnaryOperator<int[]>> MUL_BY_X = q -> a ->
        IntStream.range(0, N).map(i -> i == 0 ? mod(-a[N - 1], q) : a[i - 1]).toArray();

    /** X^k · a：把 MUL_BY_X 折叠 k 次 —— 稀疏多项式乘法的全部成本就是"移位 + 加"。 */
    private static int[] shifted(int[] a, int k)
    {
        return foldRange(0, k, a, (acc, i) -> MUL_BY_X.apply(Q_DSA).apply(acc));
    }

    /** 随机环元素（裁判用的输入，随机源仍然是注入的函数）。 */
    private static int[] randomPoly(int q, Function<Integer, byte[]> random)
    {
        final byte[] raw = random.apply(N * 4);
        return IntStream.range(0, N).map(i ->
            mod(((raw[4 * i] & 0xffL) << 24) | ((raw[4 * i + 1] & 0xffL) << 16)
                | ((raw[4 * i + 2] & 0xffL) << 8) | (raw[4 * i + 3] & 0xffL), q)).toArray();
    }

    /** 数组版相等断言的助手（int[] 没有 equals）。 */
    private static boolean same(int[] a, int[] b)
    {
        return a.length == b.length && IntStream.range(0, a.length).allMatch(i -> a[i] == b[i]);
    }

    // ---------------------------------------------------------------- NTT：换基，不是新数学

    /** base^0 .. base^(count-1)，纯 map。 */
    static final Function<Integer, Function<Integer, Function<Integer, int[]>>> POWERS = q -> base -> count ->
        IntStream.range(0, count).map(i -> powMod(base, i, q)).toArray();

    /** X^256+1 的 256 个根：r_i = ψ^(2i+1)。ψ^256 = -1 保证每个 r_i 都满足 r_i^256 = -1。 */
    static final Function<Integer, Function<Integer, int[]>> ROOTS = q -> psi ->
        IntStream.range(0, N).map(i -> powMod(psi, 2L * i + 1, q)).toArray();

    /**
     * 教科书 NTT：â[i] = Σ_j a[j]·ψ^((2i+1)·j) == "多项式 a 在根 r_i 上的取值"，仅此而已。
     */
    static final Function<Integer, Function<Integer, UnaryOperator<int[]>>> NTT_BOOK = q -> psi -> a ->
    {
        final int[] roots = ROOTS.apply(q).apply(psi);
        return IntStream.range(0, N).map(i ->
        {
            final int[] powers = POWERS.apply(q).apply(roots[i]).apply(N);
            return mod(foldRange(0, N, 0L, (acc, j) -> acc + (long)a[j] * powers[j]), q);
        }).toArray();
    };

    /**
     * 教科书逆 NTT：a[j] = 256^-1 · Σ_i â[i]·r_i^(-j)。
     * 它成立只因为 Σ_i r_i^m 在 256 | m 时等于 256、否则等于 0（等比级数）—— 正交性就是全部的证明。
     */
    static final Function<Integer, Function<Integer, UnaryOperator<int[]>>> INV_NTT_BOOK = q -> psi -> hats ->
    {
        final int[] roots = ROOTS.apply(q).apply(psi);
        final int nInv = invMod(N, q);
        return IntStream.range(0, N).map(j -> mod((long)mod(foldRange(0, N, 0L, (acc, i) ->
            acc + (long)hats[i] * powMod(roots[i], 2L * N - j, q)), q) * nInv, q)).toArray();
    };

    /**
     * 快速 NTT：同一个映射，只是把 O(n^2) 的求值矩阵分解成 8 级蝴蝶。
     *
     * <p>关键恒等式 â[i] = Σ_j (a[j]·ψ^j)·ω^(i·j)，其中 ω = ψ^2 是 256 次本原单位根。
     * 也就是"先把系数各自乘上 ψ^j（这正是 Dilithium 第一层蝴蝶做的事），再作一次普通 256 点 DFT"。
     * DFT 用标准的"位反转 + Cooley-Tukey 迭代蝴蝶"，twiddle 因子现场用 powMod 算，
     * 不需要 BC 那份硬编码的 zetas 表 —— 表只是把 powMod 缓存起来罢了。
     */
    /**
     * 快速 NTT：同一个映射，只是把 O(n^2) 的求值矩阵分解成 8 级蝴蝶。
     *
     * <p>关键恒等式 â[i] = Σ_j (a[j]·ψ^j)·ω^(i·j)，其中 ω = ψ^2 是 256 次本原单位根。
     * 也就是"先把系数各自乘上 ψ^j（这正是 Dilithium 第一层蝴蝶做的事），再作一次普通 256 点 DFT"。
     * DFT 用标准的"位反转 + Cooley-Tukey 迭代蝴蝶"，twiddle 因子现场用 powMod 算，
     * 不需要 BC 那份硬编码的 zetas 表 —— 表只是把 powMod 缓存起来罢了。
     */
    static final Function<Integer, Function<Integer, UnaryOperator<int[]>>> NTT_FAST = q -> psi -> a ->
    {
        final int omega = powMod(psi, 2, q);
        final int[] psiPows = POWERS.apply(q).apply(psi).apply(N);
        // 预_twiddle：b[j] = a[j]·ψ^j，然后把数组按位反转重排（256 = 2^8，所以反转低 8 位）
        final int[] b = IntStream.range(0, N).map(i ->
        {
            final int j = Integer.reverse(i) >>> 24;
            return mod((long)a[j] * psiPows[j], q);
        }).toArray();
        final List<Integer> lens = IntStream.range(1, 9).map(i -> 1 << i).boxed().collect(Collectors.toList());
        return fold(lens, b, (arr, len) -> IntStream.range(0, N).map(i ->
        {
            final int base = (i / len) * len;
            final int j = i % len;
            final int low = j < len / 2 ? j : j - len / 2;
            final int w = powMod(omega, (long)(N / len) * low, q);
            final int u = arr[base + low];
            final int v = mod((long)arr[base + low + len / 2] * w, q);
            return mod(j < len / 2 ? (long)u + v : (long)u - v, q);
        }).toArray());
    };

    // ---------------------------------------------------------------- "填充模式"之一：分解 t = t1·2^d + t0

    /**
     * 2 的幂分解（ML-DSA 用它把 t 拆成公钥里的 t1 与私钥里的 t0）。
     * 返回 {a1, a0} —— 一个两元素数组，不需要 DecompositionResult 类。
     *
     * <p>边界必须和参考实现一致：a0 的范围是 [-(2^(d-1)-1), 2^(d-1)]，即"上界含、下界不含"。
     * 之所以必须是这一边而不是对称的那一边，是因为 t0 随后要以 (2^(d-1) - a0) 的形式装进 13 bit
     * —— 另一个约定会溢出 1 bit（见 {@link #publicKeyIsJustTheHighBitsOfOnePolynomial()}）。
     */
    static final Function<Integer, Function<Integer, Function<Integer, int[]>>> POWER2_ROUND = q -> d -> a ->
    {
        final int half = 1 << (d - 1);
        final int a0 = mod(a + (half - 1), 1 << d) - (half - 1);
        final int a1 = (a - a0) >> d;
        return new int[]{ a1, a0 };
    };

    /**
     * γ2 分解（ML-DSA 签名里 z 与 r1 的那一步）。α = 2γ2，且 q-1 必须是 α 的整数倍 ——
     * 这解释了 q = 2^23-2^13+1 为什么被选中：q-1 = 2^13·3·11·31 有 44 与 16 这样的因子。
     * 返回 {a1, a0}，其中 a1 在商 M = (q-1)/α 上取模 —— 这个"绕回 0"就是 hint 存在的理由。
     */
    static final Function<Integer, Function<Integer, Function<Integer, int[]>>> DECOMPOSE = q -> alpha -> a ->
    {
        final int m = (q - 1) / alpha;
        final int a1 = mod((a + alpha / 2) / alpha, m);
        final int a0 = center(a - (long)a1 * alpha, q);
        return new int[]{ a1, a0 };
    };

    // ---------------------------------------------------------------- "填充模式"之二：压缩到 d 位

    /**
     * ML-KEM 的 compress：round(2^d·x/q)，即"把 q 个刻度量化成 2^d 个刻度"。
     * 末尾那个 mod 2^d 不是防御性代码：x = q-1 时结果正好等于 2^d，必须绕回 0 ——
     * 这与"量化误差在 Z_q 里中心化"是同一件事（见 kemCiphertextLengthIs... 里的误差断言）。
     */
    static final Function<Integer, Function<Integer, Function<Integer, Integer>>> COMPRESS = q -> d -> x ->
        (int)(((((long)x << d) + q / 2) / q) & ((1L << d) - 1));

    /** ML-KEM 的 decompress：round(q·y/2^d)，量化必然有误差，误差上界就是安全性证明里的噪声预算。 */
    static final Function<Integer, Function<Integer, Function<Integer, Integer>>> DECOMPRESS = q -> d -> y ->
        (int)(((long)q * y + (1L << (d - 1))) >> d);

    // ---------------------------------------------------------------- "填充模式"之三：比特打包

    /**
     * 低位在前的比特打包：ML-DSA/ML-KEM 的所有"编码"都只是这件事。
     * {@code PACK.apply(bits).apply(coeffs)} 得到的字节数必须与 BC 的公开常量逐字节相等。
     */
    static final Function<Integer, Function<int[], byte[]>> PACK = bits -> coeffs ->
    {
        final int nBytes = coeffs.length * bits / 8;
        return bytesOf(IntStream.range(0, nBytes).map(i ->
            IntStream.range(0, 8).map(k ->
                ((coeffs[(8 * i + k) / bits] >>> ((8 * i + k) % bits)) & 1) << k).sum()).toArray());
    };

    /** 逆操作：从字节流里按 bits 位一段地读出系数。 */
    static final Function<Integer, Function<Integer, Function<byte[], int[]>>> UNPACK = bits -> count -> data ->
        IntStream.range(0, count).map(i ->
            IntStream.range(0, bits).map(k -> bitAt(data, i * bits + k) << k).sum()).toArray();

    // ---------------------------------------------------------------- "填充模式"之四：采样（拒绝式）

    /**
     * 中心二项式采样（ML-KEM 的密钥噪声）：2η 个随机 bit 分成两半，各数 1 的个数再相减。
     * 它是"噪声"的全部来源：系数落在 [-η, η]，因为它是 η 个 ±1 的和。
     */
    static final Function<Integer, Function<byte[], int[]>> CBD = eta -> src ->
        IntStream.range(0, src.length * 8 / (2 * eta)).map(i ->
            IntStream.range(0, eta).map(j -> bitAt(src, 2 * eta * i + j)).sum()
                - IntStream.range(0, eta).map(j -> bitAt(src, 2 * eta * i + eta + j)).sum()).toArray();

    /**
     * 拒绝采样 = 在一条随机流上 filter-then-take。教科书写作 while(count &lt; n)，
     * 函数式写法是递归：状态只有"还要几个"和"读到第几个候选"。
     * ML-DSA 的 η 采样、r1 采样、SampleInBall 全是这个形状，没有任何循环变量。
     */
    private static List<Integer> reject(int need, int index, Function<Integer, Integer> draw, Predicate<Integer> accept)
    {
        if (need <= 0)
        {
            return Collections.emptyList();
        }
        final int v = draw.apply(index);
        if (!accept.test(v))
        {
            return reject(need, index + 1, draw, accept);
        }
        List<Integer> tail = reject(need - 1, index + 1, draw, accept);
        List<Integer> out = new ArrayList<Integer>(tail.size() + 1);
        out.add(v);
        out.addAll(tail);
        return out;
    }

    /**
     * ML-DSA 的挑战多项式 c：恰好 τ 个非零位置（系数只有 ±1）。
     * "位置撞车就再抽一次"同样是递归；权重精确等于 τ，这就是 c 便宜的原因（见下面的稀疏乘法）。
     */
    private static List<Integer> inBall(int need, int index, Function<Integer, Integer> slotOf, List<Integer> used)
    {
        if (need <= 0)
        {
            return used;
        }
        final int slot = slotOf.apply(index);
        if (used.contains(slot))
        {
            return inBall(need, index + 1, slotOf, used);
        }
        List<Integer> out = new ArrayList<Integer>(used);
        out.add(slot);
        return inBall(need - 1, index + 1, slotOf, out);
    }

    // ---------------------------------------------------------------- 随机源：一个纯函数

    /**
     * 把"随机数生成器"降回它的真面目：XOF 是 {@code seed -> n -> bytes} 的纯函数（SHAKE256 展开）。
     * 给定同一个 seed，所有采样、所有密钥导出都逐字节可重复 —— 这就是 BC 内部
     * "Internal functions are deterministic. No randomness is sampled inside them" 注释的意思。
     */
    static final Function<byte[], Function<Integer, byte[]>> XOF = seed -> n ->
    {
        SHAKEDigest d = new SHAKEDigest(256);
        d.update(seed, 0, seed.length);
        byte[] out = new byte[n];
        d.doOutput(out, 0, n);
        return out;
    };

    // ---------------------------------------------------------------- 裁判：BC 的 ML-DSA

    /** 私钥 = 32 字节种子的确定性展开。这一步把"密钥对象"还原成"一串比特"。 */
    private static MLDSAPrivateKeyParameters dsaPriv(final MLDSAParameters p, final byte[] seed)
    {
        return new MLDSAPrivateKeyParameters(p, seed);
    }

    private static Function<byte[], byte[]> dsaSigner(final MLDSAPrivateKeyParameters priv)
    {
        return msg ->
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
        };
    }

    private static BiFunction<byte[], byte[], Boolean> dsaVerifier(final MLDSAPublicKeyParameters pub)
    {
        return (msg, sig) ->
        {
            MLDSASigner s = new MLDSASigner();
            s.init(false, pub);
            s.update(msg, 0, msg.length);
            return s.verifySignature(sig);
        };
    }

    /** FIPS 204 表里的 η（噪声幅度），按级别排 —— 一张常量表，不是三个子类。 */
    private static final int[] ETA = new int[]{ 2, 4, 2 };

    // ---------------------------------------------------------------- 测试

    /**
     * 命题一：R_q 里只有一个数组和一个负号。X^256 = -1 是环的全部额外规则。
     */
    @Test
    public void ringElementsAreCoefficientVectorsAndMultiplicationIsNegacyclic()
    {
        // X^256 = -1：从 1 出发乘 256 次 X，得到的不是 1 而是 -1（即 q-1 落在 0 号位）
        final int[] x256 = foldRange(0, N, MONOMIAL.apply(0), (acc, i) -> MUL_BY_X.apply(Q_DSA).apply(acc));
        Assert.assertEquals("X^256 的 0 号系数必须是 -1（也就是 q-1）", Q_DSA - 1, x256[0]);
        Assert.assertTrue("其余 255 个系数必须为 0", IntStream.range(1, N).allMatch(i -> x256[i] == 0));

        final Function<Integer, byte[]> rnd = XOF.apply("ring".getBytes());
        final int[] a = randomPoly(Q_DSA, rnd);
        final int[] b = randomPoly(Q_DSA, XOF.apply("ring-b".getBytes()));
        final int[] c = randomPoly(Q_DSA, XOF.apply("ring-c".getBytes()));
        final BiFunction<int[], int[], int[]> mul = MUL.apply(Q_DSA);
        final BiFunction<int[], int[], int[]> add = ADD.apply(Q_DSA);

        // 环乘法的基本代数律：交换、结合、单位元、分配律
        Assert.assertTrue("环乘法必须交换", same(mul.apply(a, b), mul.apply(b, a)));
        Assert.assertTrue("环乘法必须结合", same(mul.apply(mul.apply(a, b), c), mul.apply(a, mul.apply(b, c))));
        Assert.assertTrue("1 是单位元", same(mul.apply(a, MONOMIAL.apply(0)), a));
        Assert.assertTrue("乘法对加法分配",
            same(mul.apply(a, add.apply(b, c)), add.apply(mul.apply(a, b), mul.apply(a, c))));
        Assert.assertTrue("乘 X 就是左移一位（与卷积定义一致）",
            same(mul.apply(MONOMIAL.apply(1), a), MUL_BY_X.apply(Q_DSA).apply(a)));
        Assert.assertTrue("乘 0 得 0", IntStream.of(mul.apply(a, new int[N])).allMatch(v -> v == 0));
        Assert.assertTrue("数乘 = 用常数多项式乘（R_q 是 Z_q 上的代数）",
            same(SCALE.apply(Q_DSA).apply(7).apply(a), mul.apply(a, IntStream.concat(
                IntStream.of(7), IntStream.range(1, N).map(i -> 0)).toArray())));

        // 次数相加会"绕回来"，绕回来的那一项取负 —— 手动验证一个具体例子
        final int[] xHi = mul.apply(MONOMIAL.apply(N - 1), MONOMIAL.apply(N - 1));
        Assert.assertEquals("X^255 · X^255 = X^510 = X^254·X^256 = -X^254", Q_DSA - 1, xHi[N - 2]);
        Assert.assertTrue("其余系数必须为 0", IntStream.range(0, N).filter(i -> i != N - 2)
            .allMatch(i -> xHi[i] == 0));

        // Kyber 用同一个环，只是模数换成 3329
        final BiFunction<int[], int[], int[]> mulKem = MUL.apply(Q_KEM);
        Assert.assertTrue("ML-KEM 的环同样是 X^256 = -1",
            same(mulKem.apply(MONOMIAL.apply(N - 1), MONOMIAL.apply(N - 1)),
                IntStream.range(0, N).map(i -> i == N - 2 ? Q_KEM - 1 : 0).toArray()));
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
        final int[] roots = ROOTS.apply(Q_DSA).apply(PSI_DSA);
        Assert.assertEquals("256 个根必须互不相同（否则插值不唯一，NTT 就不是双射）",
            N, IntStream.of(roots).distinct().count());
        Assert.assertTrue("每个根都必须满足 r^256 = -1",
            IntStream.of(roots).allMatch(r -> powMod(r, N, Q_DSA) == Q_DSA - 1));

        final UnaryOperator<int[]> nttBook = NTT_BOOK.apply(Q_DSA).apply(PSI_DSA);
        final UnaryOperator<int[]> nttFast = NTT_FAST.apply(Q_DSA).apply(PSI_DSA);
        final UnaryOperator<int[]> invBook = INV_NTT_BOOK.apply(Q_DSA).apply(PSI_DSA);
        final BiFunction<int[], int[], int[]> mul = MUL.apply(Q_DSA);
        final BiFunction<int[], int[], int[]> pw = POINTWISE.apply(Q_DSA);

        // NTT(1) 必须等于"根自身的幂"检查：1 在每点取值 1
        Assert.assertTrue("常数 1 的象必须全是 1",
            IntStream.of(nttBook.apply(MONOMIAL.apply(0))).allMatch(v -> v == 1));
        // X 的象就是根表本身：这就是"NTT == 求值"最直接的证据
        Assert.assertTrue("X 的象必须正好是 256 个根", same(nttBook.apply(MONOMIAL.apply(1)), roots));

        final int[] p = randomPoly(Q_DSA, XOF.apply("ntt-a".getBytes()));
        final int[] q = randomPoly(Q_DSA, XOF.apply("ntt-b".getBytes()));

        // 正逆变换互逆：这就是"换基"的意思 —— 双射，不丢信息
        Assert.assertTrue("逆变换必须完全还原系数：NTT^-1(NTT(p)) = p", same(invBook.apply(nttBook.apply(p)), p));
        // 蝴蝶版必须和教科书版逐系数相等：加速没有改变数学
        Assert.assertTrue("快速 NTT 必须与教科书 NTT 逐系数相等", same(nttFast.apply(p), nttBook.apply(p)));
        // 环里卷积的象 = 象的逐点乘 —— NTT 存在的全部理由
        Assert.assertTrue("NTT(p*q) 必须等于 NTT(p)·NTT(q)（逐点）",
            same(nttBook.apply(mul.apply(p, q)), pw.apply(nttBook.apply(p), nttBook.apply(q))));
        // 换基是线性的
        Assert.assertTrue("NTT 必须线性：NTT(p+q) = NTT(p)+NTT(q)",
            same(nttFast.apply(ADD.apply(Q_DSA).apply(p, q)),
                ADD.apply(Q_DSA).apply(nttFast.apply(p), nttFast.apply(q))));
        // 逆变换确实是逐点乘的另一半：解完方程还能乘回去
        Assert.assertTrue("用 NTT 算的乘法必须与学校公式算的环乘法一致",
            same(mul.apply(p, q), INV_NTT_BOOK.apply(Q_DSA).apply(PSI_DSA)
                .apply(pw.apply(nttFast.apply(p), nttFast.apply(q)))));
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

        // 穷举证明"Kyber 域里一个 512 次单位根都没有"（全部 3328 个非零元素都试过）
        Assert.assertEquals("X^256+1 在 Z_3329 里没有一次因子",
            0, IntStream.rangeClosed(1, Q_KEM - 1).filter(x -> powMod(x, N, Q_KEM) == Q_KEM - 1).count());
        // 反过来在 Dilithium 域里，X^256+1 有 256 个一次因子（命题二已经用构造法证完：
        // r_i = ψ^(2i+1) 互不相同且都满足 r^256 = -1）。这里只把"为什么够用"的因子分解摆出来。
        Assert.assertEquals("q_dsa - 1 = 2^13 · 1023，而 1023 = 3·11·31（2 的部分有 13 级，远超 9 级）",
            1023, (Q_DSA - 1) >> 13);
        Assert.assertEquals("1023 确实是 3·11·31", 1023, 3 * 11 * 31);

        // Montgomery：BC 公开了 q^-1 mod 2^32 = 58728449，我们验一遍，再证明"乘 q 凑 2^32 倍"的约减是对的
        final long qInv = BigInteger.valueOf(Q_DSA).modInverse(BigInteger.ONE.shiftLeft(32)).longValue();
        Assert.assertEquals("BC 的 DilithiumQinv 就是 q^-1 mod 2^32", MLDSAEngine.DilithiumQinv, qInv);

        //  Montgomery 约减：R = 2^32，redc(x) = (x - ((x·q^-1) mod R)·q)/R = x·R^-1 mod q
        //  注意这里是"减"：教科书写作 -N^-1 mod R 然后加，BC 存的是 +q^-1，所以必须减 ——
        //  两种写法凑出的都是 R 的整数倍。代价是结果多乘了一个 R^-1，
        //  所以 BC 才到处写 invNttToMont：值一直待在 Montgomery 域里，最后才一次约回。
        final Function<Long, Integer> redc = x ->
        {
            // 只关心 mod 2^32，所以直接取低 32 位 —— long 的自然溢出在这里是免费的模运算
            final long m = (x * qInv) & 0xFFFFFFFFL;
            return (int)mod((x - m * Q_DSA) >> 32, Q_DSA);
        };
        final int rInv = BigInteger.valueOf(1L << 32).mod(BigInteger.valueOf(Q_DSA))
            .modInverse(BigInteger.valueOf(Q_DSA)).intValue();
        for (long x : new long[]{ 0, 1, 2, 7, 4096, 8380416L, 12345678L, 987654321L, 70331653613824L })
        {
            Assert.assertEquals("Montgomery 约减必须等于 x·R^-1 mod q（全程只有乘法和移位，没有除法）",
                mod((long)mod(x, Q_DSA) * rInv, Q_DSA), (int)redc.apply(x));
        }
        Assert.assertEquals("2^32 的模逆乘回去必须还原：R·R^-1 = 1 mod q", 1, mod((long)rInv * (1L << 32), Q_DSA));
        log.info("[PQC-模数] q_dsa-1 = 2^13·3·11·31（13 级单位根），q_kem-1 = 2^8·13（只有 8 级）");
    }

    /**
     * 命题四（"填充模式"之一）：t = t1·2^13 + t0 就是二进制切一刀；
     * 我们的 10/13 bit 打包必须和 BC 真实密钥字节逐字节相同。
     */
    @Test
    public void publicKeyIsJustTheHighBitsOfOnePolynomial()
    {
        final MLDSAParameters p = MLDSAParameters.ml_dsa_65;
        final byte[] seed = XOF.apply("t-is-high-bits".getBytes()).apply(MLDSAEngine.SeedBytes);
        Assert.assertEquals("BC 的种子固定 32 字节", 32, seed.length);

        final MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
        final int k = MLDSAEngine.getInstance(p, ANY).getDilithiumK();
        final int l = MLDSAEngine.getInstance(p, ANY).getDilithiumL();

        // 裁判 1：BC 公开的打包字节数 == 我们自己 PACK 出来的长度
        Assert.assertEquals("t1 每项 10 bit -> 每项 320 字节", 320, MLDSAEngine.DilithiumPolyT1PackedBytes);
        Assert.assertEquals("t0 每项 13 bit -> 每项 416 字节", 416, MLDSAEngine.DilithiumPolyT0PackedBytes);
        final int[] t1Coeffs = IntStream.range(0, N).map(i -> (1 << T1_BITS) - 1 - i % 7).toArray();
        Assert.assertEquals("我们的 10-bit 打包长度必须等于 BC 的 T1PackedBytes",
            MLDSAEngine.DilithiumPolyT1PackedBytes, PACK.apply(T1_BITS).apply(t1Coeffs).length);

        // 裁判 2：拿 BC 真实密钥的 t1 字节，用我们的 UNPACK/PACK 走一圈，必须逐字节还原
        final byte[] t1Bytes = Arrays.copyOfRange(priv.getT1(), 0, MLDSAEngine.DilithiumPolyT1PackedBytes);
        final int[] t1Real = UNPACK.apply(T1_BITS).apply(N).apply(t1Bytes);
        Assert.assertTrue("t1 的系数必须落在 10 bit 内",
            IntStream.of(t1Real).allMatch(v -> v >= 0 && v < (1 << T1_BITS)));
        Assert.assertArrayEquals("我们的 10-bit 打包必须逐字节复现 BC 的 t1 编码",
            t1Bytes, PACK.apply(T1_BITS).apply(t1Real));

        // 裁判 3：t0 是 13 bit 的"偏置中心化"编码 —— BC 存的是 (2^12 - a0)，我们把这条规则也写出来
        final byte[] t0Bytes = Arrays.copyOfRange(priv.getT0(), 0, MLDSAEngine.DilithiumPolyT0PackedBytes);
        final int[] t0Stored = UNPACK.apply(D_T).apply(N).apply(t0Bytes);
        final int half = 1 << (D_T - 1);
        final int[] t0Real = IntStream.of(t0Stored).map(v -> half - v).toArray();
        Assert.assertTrue("t0 必须装得进 13 bit（偏置后落在 [0, 2^13)）",
            IntStream.of(t0Stored).allMatch(v -> v >= 0 && v < (1 << D_T)));
        Assert.assertTrue("t0 的系数必须是中心化的小值：" + t0Real[0],
            IntStream.of(t0Real).allMatch(v -> v >= -(half - 1) && v <= half));
        Assert.assertArrayEquals("我们的 13-bit 偏置打包必须逐字节复现 BC 的 t0 编码",
            t0Bytes, PACK.apply(D_T).apply(t0Stored));

        // 分解恒等式：t1·2^13 + t0 == 原来的 t（在 Z_q 里），这就是公钥只发 t1 还能签名的原因
        final int[] t = IntStream.range(0, N)
            .map(i -> mod((long)t1Real[i] * (1 << D_T) + t0Real[i], Q_DSA)).toArray();
        for (int i : new int[]{ 0, 1, 127, 255 })
        {
            final int[] back = POWER2_ROUND.apply(Q_DSA).apply(D_T).apply(t[i]);
            Assert.assertEquals("power2Round 必须还原 t1：" + i, t1Real[i], back[0]);
            Assert.assertEquals("power2Round 必须还原 t0：" + i, t0Real[i], back[1]);
        }
        // 全 256 个系数都验一遍：分解是可逆的（可逆性 = 只用公钥就能把 t1 换回 t）
        Assert.assertTrue("power2Round 必须对整个多项式都可逆", same(t,
            IntStream.range(0, N).map(i ->
            {
                final int[] back = POWER2_ROUND.apply(Q_DSA).apply(D_T).apply(t[i]);
                return mod((long)back[0] * (1 << D_T) + back[1], Q_DSA);
            }).toArray()));
        Assert.assertTrue("t1 就是 t 的高位：t1 = (t + 2^12 - 1) >> 13",
            IntStream.range(0, N).allMatch(i -> POWER2_ROUND.apply(Q_DSA).apply(D_T).apply(t[i])[0] == t1Real[i]));

        // 公钥编码 = ρ(32) ‖ t1 的 k 份：长度不是魔法
        final MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1());
        Assert.assertEquals("ML-DSA 公钥长度 = 32 + k·320", 32 + k * 320, pub.getEncoded().length);
        Assert.assertEquals("公钥字节就是 ρ ‖ pack(t1)",
            Fp.concat(priv.getRho(), priv.getT1()).length, pub.getEncoded().length);
        Assert.assertArrayEquals("我们的打包必须能重建整份 t1", t1Bytes,
            Arrays.copyOfRange(pub.getEncoded(), 32, 32 + MLDSAEngine.DilithiumPolyT1PackedBytes));
        log.info("[PQC-分解] {} k={} l={}：t1={} bit（{} 字节/项），t0={} bit 偏置（{} 字节/项），pk={} 字节",
            p.getName(), k, l, T1_BITS, MLDSAEngine.DilithiumPolyT1PackedBytes,
            D_T, MLDSAEngine.DilithiumPolyT0PackedBytes, pub.getEncoded().length);
    }

    /**
     * 命题五（"填充模式"之二）：γ2 分解与 hint —— 边界那一格就是 hint 存在的全部理由。
     */
    @Test
    public void gammaDecompositionHasExactlyOneBoundaryProblemAndThatIsWhereHintsLive()
    {
        // ml-dsa-44 用 γ2 = (q-1)/88（于是 α = 2γ2 = (q-1)/44，a1 有 44 个取值），
        // ml-dsa-65/87 用 γ2 = (q-1)/32（α = (q-1)/16，a1 有 16 个取值）—— 都能整除，因为 q-1 因子够多
        for (int m : new int[]{ 44, 16 })
        {
            final int alpha = (Q_DSA - 1) / m;               // α = 2γ2
            final int gamma2 = alpha / 2;
            Assert.assertEquals("q-1 必须是 α = 2γ2 的整数倍", 0, (Q_DSA - 1) % alpha);
            final Function<Integer, int[]> dec = DECOMPOSE.apply(Q_DSA).apply(alpha);

            // 恒等式与界：在所有"有代表性"的点上验证（含 q-1 附近的那条绕回边界）
            final int[] probes = IntStream.concat(
                IntStream.concat(IntStream.range(0, gamma2 + 3), IntStream.range(Q_DSA - gamma2 - 3, Q_DSA)),
                IntStream.range(0, 400).map(i -> mod(1L + 3001177L * i, Q_DSA))).toArray();

            int wrapped = 0;
            for (int a : probes)
            {
                final int[] d = dec.apply(a);
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
            final int[] spread = IntStream.range(0, 20000).map(i -> mod(1L + 419L * i, Q_DSA)).toArray();
            final BiFunction<Integer, int[], Long> crossings = (noise, pts) -> IntStream.range(0, pts.length)
                .filter(i -> dec.apply(mod(pts[i] + noise, Q_DSA))[0] != dec.apply(pts[i])[0]).count();
            final int e = alpha / 16;
            final long changed = crossings.apply(e, spread);
            final long expected = 20000L * e / alpha;                 // 理论上正好是 e/α 的比例
            Assert.assertTrue("hint 密度约等于 e/α（噪声越小提示越稀疏）：changed=" + changed + " expected~=" + expected,
                changed > expected / 2 && changed < expected * 3 / 2 + 1);
            // 单调性：噪声砍一半，需要提示的位置也几乎砍一半 —— 这就是 ω 的物理意义
            Assert.assertTrue("噪声减半，hint 数量也必须减半",
                crossings.apply(e / 2, spread) < changed);
            log.info("[PQC-分解] α = {}（γ2 = {}，a1 ∈ [0,{})）：恒等式成立，绕回段唯一，e={} 时 hint 比例 {}/20000（理论 {}）",
                alpha, gamma2, m, e, changed, expected);
        }
    }

    /**
     * 命题六（"填充模式"之三）：ML-KEM 的 compress 就是把 q 个刻度量化成 2^d 个刻度，
     * 密文长度 = 32·(k·d_u + d_v)，一个比特都不多。
     */
    @Test
    public void kemCiphertextLengthIsJustTheSumOfCompressedCoefficients()
    {
        final int[][] levels = new int[][]{
            // {k, d_u, d_v, 密文长度} —— FIPS 203 参数表的三列，第四列拿来和 BC 对
            new int[]{ 2, 10, 4, 768 },
            new int[]{ 3, 10, 4, 1088 },
            new int[]{ 4, 11, 5, 1568 },
        };
        final MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024,
        };

        for (int i = 0; i < levels.length; i++)
        {
            final int k = levels[i][0], du = levels[i][1], dv = levels[i][2], ct = levels[i][3];
            final MLKEMEngine eng = MLKEMEngine.getInstance(params[i]);
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
            final int maxErr = (Q_KEM + (1 << (du + 1)) - 1) >> (du + 1);
            final Function<Integer, Integer> comp = COMPRESS.apply(Q_KEM).apply(du);
            final Function<Integer, Integer> decp = DECOMPRESS.apply(Q_KEM).apply(du);
            for (int x : new int[]{ 0, 1, Q_KEM / 3, Q_KEM / 2, Q_KEM - 2, Q_KEM - 1 })
            {
                final int y = comp.apply(x);
                Assert.assertTrue("压缩结果必须能塞进 d 位：" + y, y >= 0 && y < (1 << du));
                Assert.assertTrue("量化误差必须在 ceil(q/2^(d+1)) = " + maxErr + " 内：" + x + " -> " + y,
                    Math.abs(center(decp.apply(y) - (long)x, Q_KEM)) <= maxErr);
            }
            log.info("[PQC-压缩] {} d_u={} d_v={} 密文 {} 字节，量化误差预算 <= {}",
                params[i].getName(), du, dv, ct, maxErr);
        }

        // 12-bit 打包再和 BC 的真实公钥对：t 的每个系数都装得进 12 bit，且打包约定逐字节相同
        final MLKEMParameters p = MLKEMParameters.ml_kem_768;
        final MLKEMEngine eng = MLKEMEngine.getInstance(p);
        final int[] coeffs = IntStream.range(0, N).map(j -> (j * 13 + 7) % Q_KEM).toArray();
        Assert.assertEquals("Kyber 系数打包 12 bit -> 384 字节", 384, PACK.apply(12).apply(coeffs).length);
        Assert.assertTrue("12-bit 打包/解包必须互逆",
            same(coeffs, UNPACK.apply(12).apply(N).apply(PACK.apply(12).apply(coeffs))));

        final byte[] d = XOF.apply("kem-d".getBytes()).apply(MLKEMEngine.SymBytes);
        final byte[] z = XOF.apply("kem-z".getBytes()).apply(MLKEMEngine.SymBytes);
        final byte[][] kp = eng.generateKemKeyPairInternal(d, z);
        final byte[] tBytes = Arrays.copyOfRange(kp[0], 0, 384);     // 第一个多项式的真实编码
        final int[] tReal = UNPACK.apply(12).apply(N).apply(tBytes);
        Assert.assertTrue("公钥里的 t 系数必须落在 12 bit 内",
            IntStream.of(tReal).allMatch(v -> v >= 0 && v < (1 << 12)));
        Assert.assertArrayEquals("我们的 12-bit 打包必须逐字节复现 BC 的 t 编码", tBytes, PACK.apply(12).apply(tReal));
    }

    /**
     * 命题七（"填充模式"之四）：采样就是一个可见的拒绝循环 + 二项式差分；
     * 挑战多项式只有 τ 个非零系数，所以"乘 c"== τ 次移位加 —— 这是格签名便宜的那一半。
     */
    @Test
    public void samplingIsARejectionLoopAndABinomialDifferenceMadeVisible()
    {
        final Function<Integer, byte[]> coins = XOF.apply("coins".getBytes());

        // ML-KEM 的中心二项式：η 个 ±1 相加，系数必落在 [-η, η]
        for (int eta : new int[]{ 2, 3 })
        {
            final int[] noise = CBD.apply(eta).apply(coins.apply(N * 2 * eta / 8));
            Assert.assertEquals("必须正好得到 256 个系数", N, noise.length);
            Assert.assertTrue("系数必须落在 [-η, η]：" + Arrays.toString(Arrays.copyOf(noise, 6)),
                IntStream.of(noise).allMatch(v -> Math.abs(v) <= eta));
            Assert.assertTrue("分布必须近似关于 0 对称", Math.abs(IntStream.of(noise).average().getAsDouble()) < 0.3);
        }

        // ML-DSA 的均匀采样：23-bit 窗口 + ">= q 就丢"，丢弃率小得可以忽略，但必须存在
        final Function<Integer, byte[]> field = XOF.apply("field".getBytes());
        Assert.assertEquals("23-bit 窗口比 q 多出 8191 个值 —— 它们必须丢掉（约 0.1%）", 8191, (1 << 23) - Q_DSA);
        final List<Integer> kept = reject(2000, 0, idx -> word23(field, idx), v -> v < Q_DSA);
        Assert.assertEquals("必须凑够 2000 个域元素", 2000, kept.size());
        Assert.assertTrue("所有样本都必须同时满足 < 2^23 与 < q",
            kept.stream().allMatch(v -> v >= 0 && v < Q_DSA));

        // 拒绝采样不改变均匀性：用 4 bit 抽 [0,10)，16 个符号里 6 个要丢，丢弃率看得见
        final Function<Integer, byte[]> nibbles = XOF.apply("nib".getBytes());
        final List<Integer> drawn = reject(2000, 0, idx ->
        {
            final byte[] b = nibbles.apply(idx + 1);
            return (b[idx] >> (4 * (idx & 1))) & 0xf;
        }, v -> v < 10);
        Assert.assertEquals("必须凑够 2000 个样本", 2000, drawn.size());
        final long[] bucket = new long[10];
        for (int v : drawn)
        {
            bucket[v]++;
        }
        Assert.assertTrue("每个桶都应在期望 200 附近：" + Arrays.toString(bucket),
            IntStream.range(0, 10).allMatch(i -> Math.abs(bucket[i] - 200) < 40));

        // ML-DSA 的挑战多项式：权重恰好 τ，位置互不相同
        final int tau = 80;
        final Function<Integer, byte[]> ballStream = XOF.apply("ball".getBytes());
        final List<Integer> slots = inBall(tau, 0, idx ->
        {
            final byte[] b = ballStream.apply(3 * idx + 3);
            final int o = 3 * idx;
            return (((b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16)) >>> 9) & 0xff;
        }, new ArrayList<Integer>());
        Assert.assertEquals("权重必须精确等于 τ", tau, slots.size());
        Assert.assertEquals("位置必须互不相同", tau, slots.stream().distinct().count());
        Assert.assertTrue("位置必须落在 [0,256)", slots.stream().allMatch(v -> v >= 0 && v < N));

        // c 只有 τ 个 ±1 系数，所以 c·a == τ 次"带符号的 negacyclic 移位"相加 —— 两条路必须同一条答案
        final int[] a = randomPoly(Q_DSA, XOF.apply("sparse-a".getBytes()));
        final int[] cPoly = IntStream.range(0, N).map(i ->
            slots.contains(i) ? (i % 2 == 0 ? 1 : Q_DSA - 1) : 0).toArray();
        final int[] viaShifts = fold(slots, new int[N], (acc, slot) ->
        {
            final int[] shifted = shifted(a, slot);
            return slot % 2 == 0 ? ADD.apply(Q_DSA).apply(acc, shifted)
                : SUB.apply(Q_DSA).apply(acc, shifted);
        });
        Assert.assertTrue("稀疏乘法必须等于环乘法（这就是 τ 个移位加 = 一次环乘）",
            same(MUL.apply(Q_DSA).apply(a, cPoly), modPoly(viaShifts)));

        // 同一个 seed 的采样必须逐比特可重复：这就是"内部函数是确定性的"
        Assert.assertTrue("采样器是纯函数：同 seed 同结果",
            Arrays.equals(CBD.apply(2).apply(XOF.apply("same".getBytes()).apply(64)),
                CBD.apply(2).apply(XOF.apply("same".getBytes()).apply(64))));
        log.info("[PQC-采样] CBD(η=2,3) 支持 [-η,η]；23-bit 窗口丢弃 0.1%；SampleInBall 权重 τ={}", tau);
    }

    private static int[] modPoly(int[] v)
    {
        return IntStream.of(v).map(x -> mod(x, Q_DSA)).toArray();
    }

    /**
     * 命题八：ML-DSA 的密钥生成与签名都是种子的纯函数；6 种"算法模式"全部走通，
     * 并且和 JCE 互通。
     */
    @Test
    public void mldsaIsAPureFunctionOfItsSeedAcrossEveryMode()
        throws Exception
    {
        Fp.useBc();
        final byte[] msg = "post-quantum but still just hash-then-ring-math".getBytes();

        // ---- 裁判层：BC crypto 层（pure 模式，3 个安全级别）
        final MLDSAParameters[] pure = new MLDSAParameters[]{
            MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87,
        };
        final int[] sigLen = new int[]{ 2420, 3309, 4627 };

        for (int i = 0; i < pure.length; i++)
        {
            final MLDSAParameters p = pure[i];
            final byte[] seed = XOF.apply(new byte[]{ (byte)(i + 1) }).apply(MLDSAEngine.SeedBytes);

            // 私钥 = 种子的展开；同一份种子给 BC 与"我们包出去的函数"，必须得到同一把钥匙
            final MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
            final byte[][] direct = MLDSAEngine.getInstance(p, ANY).generateKeyPairInternal(seed);
            Assert.assertArrayEquals("rho 是种子的确定性展开", direct[0], priv.getRho());
            Assert.assertArrayEquals("tr 是种子的确定性展开", direct[2], priv.getTr());
            Assert.assertArrayEquals("s1 是种子的确定性展开", direct[3], priv.getS1());
            Assert.assertArrayEquals("t0 是种子的确定性展开", direct[5], priv.getT0());

            // 参数表里有两种"k"，很容易混：MLDSAParameters.getK() 是 FIPS 安全等级（2/3/5），
            // 引擎里的 dilithiumK 才是 A 矩阵的行数（4/6/8）—— 公钥长度用的是后者。
            final int k = MLDSAEngine.getInstance(p, ANY).getDilithiumK();
            Assert.assertEquals("FIPS 等级与矩阵行数不是一回事", new int[]{ 2, 3, 5 }[i], p.getK());
            Assert.assertEquals("A 的行数必须来自参数集", new int[]{ 4, 6, 8 }[i], k);

            final MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1());
            Assert.assertEquals("公钥长度 = 32 + k·320", 32 + k * T1_BITS * N / 8, pub.getEncoded().length);

            // 签名确定性：同一把钥匙、同一条消息，两次签名逐字节相同（FIPS 204 的 deterministic 模式）
            final byte[] sig1 = dsaSigner(priv).apply(msg);
            final byte[] sig2 = dsaSigner(priv).apply(msg);
            Assert.assertArrayEquals("ML-DSA 默认是确定性的：" + p.getName(), sig1, sig2);
            Assert.assertEquals("签名长度必须等于 FIPS 204 表值", sigLen[i], sig1.length);
            Assert.assertTrue("我们的验证器必须认它", dsaVerifier(pub).apply(msg, sig1));
            Assert.assertFalse("换消息必须失败", dsaVerifier(pub).apply("other".getBytes(), sig1));
            final byte[] bad = sig1.clone();
            bad[100] ^= 1;
            Assert.assertFalse("改一位必须失败", dsaVerifier(pub).apply(msg, bad));

            // mu-mode：ML-DSA 只吃 mu = SHAKE256(tr ‖ M)，先把 mu 算出来再签，结果必须一模一样
            final MLDSASigner prep = new MLDSASigner();
            prep.init(true, priv);
            prep.update(msg, 0, msg.length);
            final byte[] mu = prep.generateMu();
            Assert.assertEquals("mu 固定 64 字节", MLDSAEngine.CrhBytes, mu.length);
            final MLDSASigner external = new MLDSASigner();
            external.init(true, priv);
            Assert.assertArrayEquals("签 mu 与签消息必须得到同一张签名（本质：算法只看 mu）",
                sig1, external.generateMuSignature(mu));
            final MLDSASigner checkMu = new MLDSASigner();
            checkMu.init(false, pub);
            Assert.assertTrue("验签端同样可以只看 mu", checkMu.verifyMuSignature(mu, sig1));

            log.info("[PQC-ML-DSA] {} 等级={} k={} l={} η={}：pk={} sig={}，确定性 + mu-mode 一致",
                p.getName(), p.getK(), k, MLDSAEngine.getInstance(p, ANY).getDilithiumL(), ETA[i],
                pub.getEncoded().length, sig1.length);
        }

        // ---- 模式层：JCE 的 6 种注册名（3 个级别 × {pure, SHA-512 预哈希}）
        final String[] names = new String[]{
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "ML-DSA-44-WITH-SHA512", "ML-DSA-65-WITH-SHA512", "ML-DSA-87-WITH-SHA512",
        };
        final MLDSAParameterSpec[] specs = new MLDSAParameterSpec[]{
            MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87,
            MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_65_with_sha512,
            MLDSAParameterSpec.ml_dsa_87_with_sha512,
        };
        for (int i = 0; i < names.length; i++)
        {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
            kpg.initialize(specs[i]);
            final KeyPair kp = kpg.generateKeyPair();

            final Signature signer = Signature.getInstance(names[i], "BC");
            signer.initSign(kp.getPrivate());
            signer.update(msg);
            final byte[] sig = signer.sign();

            final Signature verifier = Signature.getInstance(names[i], "BC");
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);
            Assert.assertTrue(names[i] + "：JCE 必须自验通过", verifier.verify(sig));

            final Signature tampered = Signature.getInstance(names[i], "BC");
            tampered.initVerify(kp.getPublic());
            tampered.update("different".getBytes());
            Assert.assertFalse(names[i] + "：换消息必须失败", tampered.verify(sig));

            if (!specs[i].getName().contains("SHA512"))
            {
                final MLDSAParameters p = pure[i];
                // 跨层：JCE 的公钥（原始 rho||t1）喂给 crypto 层，必须认出 JCE 的签名
                final MLDSAPublicKeyParameters raw =
                    new MLDSAPublicKeyParameters(p, ((MLDSAPublicKey)kp.getPublic()).getPublicData());
                Assert.assertTrue(names[i] + "：纯函数层的验证器必须认 JCE 的签名",
                    dsaVerifier(raw).apply(msg, sig));

                // 反向：我们只用 32 字节种子展开密钥，JCE 的 KeyFactory 必须接受这份原始编码
                final byte[] seed = XOF.apply(names[i].getBytes()).apply(MLDSAEngine.SeedBytes);
                final MLDSAPrivateKeyParameters ours = dsaPriv(p, seed);
                final PublicKey viaJce = KeyFactory.getInstance("ML-DSA", "BC").generatePublic(
                    new MLDSAPublicKeySpec(specs[i], ours.getPublicKeyParameters().getEncoded()));
                final Signature crossCheck = Signature.getInstance(names[i], "BC");
                crossCheck.initVerify(viaJce);
                crossCheck.update(msg);
                Assert.assertTrue(names[i] + "：JCE 必须认我们（从种子展开的）公钥签出的签名",
                    crossCheck.verify(dsaSigner(ours).apply(msg)));

                // 私钥只是 32 字节种子：JCE 的密钥类型也直接暴露这一点
                Assert.assertEquals("JCE 私钥必须能回到种子形态",
                    MLDSAEngine.SeedBytes, ((MLDSAPrivateKey)kp.getPrivate()).getSeed().length);
            }
            log.info("[PQC-模式] {} 签名 {} 字节，JCE 双向互通", names[i], sig.length);
        }
    }

    /**
     * 命题九：ML-KEM 是 KEM 不是加密 —— 密文不携带密钥，而是"约束"出同一个密钥；
     * 无效密文不会报错，它静默地导出一个假密钥（implicit rejection），这正是 FO 变换的本质。
     */
    @Test
    public void mlkemEncapsulationIsPureAndRejectionIsSilent()
    {
        final MLKEMParameters[] params = new MLKEMParameters[]{
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024,
        };

        for (final MLKEMParameters p : params)
        {
            final MLKEMEngine eng = MLKEMEngine.getInstance(p);
            final byte[] d = XOF.apply(("d" + p.getName()).getBytes()).apply(MLKEMEngine.SymBytes);
            final byte[] z = XOF.apply(("z" + p.getName()).getBytes()).apply(MLKEMEngine.SymBytes);

            // keygen 是 (d, z) 的纯函数
            final byte[][] kp1 = eng.generateKemKeyPairInternal(d, z);
            final byte[][] kp2 = eng.generateKemKeyPairInternal(d, z);
            Assert.assertArrayEquals("同一对种子必须长出同一把钥匙：" + p.getName(), kp1[0], kp2[0]);
            Assert.assertArrayEquals("私钥种子就是 d||z（64 字节）", Fp.concat(d, z), kp1[5]);
            Assert.assertEquals("公钥 = t 打包 ‖ ρ", eng.getIndCpaPublicKeyBytes(), kp1[0].length + kp1[1].length);

            final MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(p, Fp.concat(kp1[0], kp1[1]));
            // 64 字节种子 == 展开后的私钥：两种写法必须给出同一把钥匙
            final MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(p, kp1[5]);
            Assert.assertArrayEquals("私钥的公钥部分必须等于公钥编码", pub.getEncoded(), priv.getPublicKey());
            Assert.assertEquals("私钥编码长度 = 768k + 96", p.getK() * 768 + 96, priv.getEncoded().length);
            Assert.assertEquals("会话密钥固定 32 字节", 32, p.getSessionKeySize() / 8);

            // 封装是随机硬币的纯函数：同硬币同密文同密钥
            final byte[] coin = XOF.apply("coin".getBytes()).apply(MLKEMEngine.SymBytes);
            final byte[][] e1 = eng.kemEncrypt(pub, coin);
            final byte[][] e2 = eng.kemEncrypt(pub, coin);
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
            final byte[] otherCoin = XOF.apply("other-coin".getBytes()).apply(MLKEMEngine.SymBytes);
            final byte[][] e3 = eng.kemEncrypt(pub, otherCoin);
            Assert.assertFalse("换硬币必须换密文", Arrays.equals(e1[1], e3[1]));
            Assert.assertFalse("换硬币也必须换密钥：K 由 G(r‖H(pk)) 现场导出，不是固定明文",
                Arrays.equals(e1[0], e3[0]));
            Assert.assertArrayEquals("但解封装必须能追回这次封装自己的那把 K", e3[0], eng.kemDecrypt(priv, e3[1]));

            // 走一遍"注入随机源"的公开 API：结果必须与固定硬币的同一条管线兼容
            final SecretWithEncapsulation swe = new MLKEMGenerator(ANY).generateEncapsulated(pub);
            Assert.assertEquals("随机封装的密文长度不变", eng.getCipherTextBytes(), swe.getEncapsulation().length);
            Assert.assertArrayEquals("随机封装的密钥必须能被解出来",
                swe.getSecret(), new MLKEMExtractor(priv).extractSecret(swe.getEncapsulation()));

            // 隐式拒绝：改一个 bit，不抛异常、不报错，只是导出另一个 32 字节"假密钥"
            final byte[] tamperedCt = Fp.replace(e1[1], 40, (byte)(e1[1][40] ^ 0x01));
            final byte[] rejected = eng.kemDecrypt(priv, tamperedCt);
            Assert.assertEquals("无效密文仍然返回 32 字节（没有任何错误通道）", 32, rejected.length);
            Assert.assertFalse("但它必须不是原来的密钥", Arrays.equals(e1[0], rejected));
            Assert.assertArrayEquals("隐式拒绝同样是确定性的纯函数", rejected, eng.kemDecrypt(priv, tamperedCt));
            log.info("[PQC-ML-KEM] {} pk={} ct={}，封装/解封装都是纯函数，拒绝是静默的",
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
     * 用纯函数把这些步骤逐个摆出来，再让 BC 裁判我们的所有猜想不至于跑偏。
     */
    @Test
    public void signingIsOneRingMultiplyOneDecompositionAndOnePack()
    {
        final MLDSAParameters p = MLDSAParameters.ml_dsa_44;
        final MLDSAEngine eng = MLDSAEngine.getInstance(p, ANY);
        final byte[] seed = XOF.apply("mldsa-essence".getBytes()).apply(MLDSAEngine.SeedBytes);
        final MLDSAPrivateKeyParameters priv = dsaPriv(p, seed);
        final MLDSAPublicKeyParameters pub = priv.getPublicKeyParameters();
        Assert.assertArrayEquals("从私钥取出的公钥必须等于我们自己拼的", pub.getEncoded(),
            new MLDSAPublicKeyParameters(p, priv.getRho(), priv.getT1()).getEncoded());

        // 步骤 0：s1 是"η 采样 + 4 bit（其实 3 bit）偏置打包"的产物 —— 用我们的 UNPACK 还原，幅度必须 <= η
        final int eta = ETA[0];
        final int etaBytes = eng.getDilithiumPolyEtaPackedBytes();
        final int etaBits = etaBytes * 8 / N;
        final int[] s1Stored = UNPACK.apply(etaBits).apply(N).apply(Arrays.copyOf(priv.getS1(), etaBytes));
        final int[] s1 = IntStream.of(s1Stored).map(v -> eta - v).toArray();
        Assert.assertTrue("s1 的系数必须落在 [-η, η] = [-" + eta + "," + eta + "]，这才是格问题的困难性来源",
            IntStream.of(s1).allMatch(v -> Math.abs(v) <= eta));
        Assert.assertArrayEquals("我们的 η 打包必须逐字节复现 BC 的 s1 编码",
            Arrays.copyOf(priv.getS1(), etaBytes), PACK.apply(etaBits).apply(s1Stored));

        // 步骤 1：y 是一个"幅度 < γ1"的多项式 —— 这里用 23-bit 窗口的拒绝采样自己抽一个
        final Function<Integer, byte[]> coins = XOF.apply("y-sample".getBytes());
        final int gamma1 = 1 << 17;
        final int[] yRaw = reject(N, 0, idx -> word23(coins, idx), v -> v < Q_DSA).stream()
            .mapToInt(Integer::intValue).toArray();
        final int[] y = IntStream.range(0, N).map(i ->
            mod((long)(gamma1 - 1) - yRaw[i] % (long)(gamma1 - 1), Q_DSA)).toArray();
        Assert.assertEquals("多项式就是 256 个系数", N, y.length);

        // 步骤 2：NTT 域里做一次逐点乘（真实协议是 A∘y，这里用我们自己的环验证换基恒等式）
        final UnaryOperator<int[]> ntt = NTT_FAST.apply(Q_DSA).apply(PSI_DSA);
        final int[] wy = ntt.apply(MUL.apply(Q_DSA).apply(y, s1));
        Assert.assertTrue("换基恒等式：NTT(y*s1) = NTT(y)·NTT(s1)",
            same(wy, POINTWISE.apply(Q_DSA).apply(ntt.apply(y), ntt.apply(s1))));

        // 步骤 3：分解出 w1 并打包 —— γ2 分解（ml-dsa-44 用 γ2 = (q-1)/88，所以 w1 ∈ [0,44) 只要 6 bit）
        final int gamma2 = (Q_DSA - 1) / 88;
        final int[] w1 = IntStream.of(wy).map(v -> DECOMPOSE.apply(Q_DSA).apply(2 * gamma2).apply(v)[0]).toArray();
        Assert.assertTrue("w1 必须在 [0, 44) 内，因此 6 bit 就够存",
            IntStream.of(w1).allMatch(v -> v >= 0 && v < 44));
        Assert.assertEquals("6-bit 打包：256·6/8 = 192 字节", 192, PACK.apply(6).apply(w1).length);
        Assert.assertTrue("6-bit 打包/解包互逆", same(w1, UNPACK.apply(6).apply(N).apply(PACK.apply(6).apply(w1))));

        // 步骤 4：z = y + c·s1 的形状检查 —— c 是 τ-稀疏的，所以这一步是 τ 次移位加（见命题七）
        final byte[] msg = "one multiply, one round, one pack".getBytes();
        final byte[] sig = dsaSigner(priv).apply(msg);
        Assert.assertTrue("完整签名必须能被纯函数验证器接受", dsaVerifier(pub).apply(msg, sig));
        Assert.assertEquals("ML-DSA-44 的签名长度 = c~(80) + z + hints", 2420, sig.length);
        log.info("[PQC-本质] 一次环乘 + 一次 γ2 分解 + 一次打包 = 一张 {} 字节的后量子签名（γ1={}, γ2={}）",
            sig.length, gamma1, gamma2);
    }

    /**
     * 对照表：把"模式"这件事显式列成一张函数表 —— 没有 switch，没有子类。
     * ML-DSA 六种模式 + ML-KEM 三种模式，全部只是不同的参数常量喂给同一条管线。
     */
    @Test
    public void parameterSetsAreATableNotAClassHierarchy()
    {
        Fp.useBc();
        final List<MLDSAParameters> dsa = Arrays.asList(
            MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65, MLDSAParameters.ml_dsa_87,
            MLDSAParameters.ml_dsa_44_with_sha512, MLDSAParameters.ml_dsa_65_with_sha512,
            MLDSAParameters.ml_dsa_87_with_sha512);
        final List<MLKEMParameters> kem = Arrays.asList(
            MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768, MLKEMParameters.ml_kem_1024);

        // 同一份代码路径 + 不同常量 = 不同模式：这里连一个 if 都不需要
        final Function<MLDSAParameters, Boolean> preHash = MLDSAParameters::isPreHash;
        Assert.assertEquals("pure 模式不预哈希", Boolean.FALSE, preHash.apply(dsa.get(0)));
        Assert.assertEquals("后 3 个是 SHA-512 预哈希模式", Boolean.TRUE, preHash.apply(dsa.get(3)));
        Assert.assertEquals("同级别的 pure / 预哈希共用 k",
            dsa.get(0).getK(), dsa.get(3).getK());

        final byte[] seed = XOF.apply("table".getBytes()).apply(MLDSAEngine.SeedBytes);
        final List<byte[]> pks = dsa.stream().filter(x -> !x.isPreHash())
            .map(x -> dsaPriv(x, seed).getPublicKeyParameters().getEncoded()).collect(Collectors.toList());
        // 注意两个 "k"：MLDSAParameters.getK() 存的是 FIPS 安全等级（2/3/5），矩阵行数在引擎里（4/6/8）
        Assert.assertEquals("A 的行数随级别增长：4 -> 6 -> 8", Arrays.asList(4, 6, 8),
            dsa.stream().filter(x -> !x.isPreHash())
                .map(x -> MLDSAEngine.getInstance(x, ANY).getDilithiumK()).collect(Collectors.toList()));
        Assert.assertEquals("而参数对象里的 k 是 FIPS 等级：2 -> 3 -> 5", Arrays.asList(2, 3, 5),
            dsa.stream().filter(x -> !x.isPreHash()).map(MLDSAParameters::getK).collect(Collectors.toList()));
        Assert.assertTrue("公钥必须越来越长",
            pks.get(0).length < pks.get(1).length && pks.get(1).length < pks.get(2).length);
        // 同一条管线：种子 + 级别常量 -> 签名；三种级别的签名长度就是那张表
        final List<Integer> sigLengths = dsa.stream().filter(x -> !x.isPreHash()).map(x ->
            dsaSigner(dsaPriv(x, seed)).apply("same code path".getBytes()).length)
            .collect(Collectors.toList());
        Assert.assertEquals("签名长度表 = FIPS 204 Table", Arrays.asList(2420, 3309, 4627), sigLengths);

        // ML-KEM 的"模式"只改变 k 与 du/dv，管线一行没动
        Assert.assertEquals(Arrays.asList(2, 3, 4), kem.stream().map(MLKEMParameters::getK).collect(Collectors.toList()));
        Assert.assertEquals("会话密钥永远是 SHA3-256 的 32 字节", Arrays.asList(32, 32, 32),
            kem.stream().map(x -> x.getSessionKeySize() / 8).collect(Collectors.toList()));
        Assert.assertEquals("密文长度表", Arrays.asList(768, 1088, 1568),
            kem.stream().map(MLKEMParameters::getEncapsulationLength).collect(Collectors.toList()));

        // ML-DSA 的密钥生成也只是同一条管线，注入的随机源不同而已
        final MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(ANY, MLDSAParameters.ml_dsa_87));
        final AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        final byte[] challenge = "k=8 l=7".getBytes();
        Assert.assertTrue("最大级别同样可验", dsaVerifier((MLDSAPublicKeyParameters)pair.getPublic())
            .apply(challenge, dsaSigner((MLDSAPrivateKeyParameters)pair.getPrivate()).apply(challenge)));
        Assert.assertEquals("ML-DSA-87 公钥 = 32 + 8*320", 2592,
            ((MLDSAPublicKeyParameters)pair.getPublic()).getEncoded().length);
        log.info("[PQC-模式表] ML-DSA {} 种 + ML-KEM {} 种，全部是同一条管线上的一张表", dsa.size(), kem.size());
    }
}
