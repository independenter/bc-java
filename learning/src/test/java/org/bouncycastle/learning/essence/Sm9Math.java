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
 * <p>算术一律用 {@link BigInteger} 明文模 p，不做 Montgomery 变换 —— 慢一点，但每一步都能
 * 直接和纸上的公式对照；这也让"常数是否抄对"这类错误一眼可见（有测试专门核对）。
 */
final class Sm9Math
{
    private Sm9Math()
    {
    }

    // ---------------------------------------------------------------- 域与曲线常数（GB/T 32915.5 的 256-bit 参数）

    /** p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d。 */
    static final BigInteger P = new BigInteger("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d", 16);

    /** n = b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25（G₁、G₂ 的公共阶）。 */
    static final BigInteger N = new BigInteger("b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25", 16);

    /** G₁ 的生成元 P1 = (x, y) ∈ E(Fp)，E: y² = x³ + 5。 */
    static final BigInteger[] P1 = new BigInteger[]{
        new BigInteger("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", 16),
        new BigInteger("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", 16) };

    /**
     * G₂ 的生成元 P2 ∈ E'(Fp2)，直接写成引擎内部用的射影三元组 {X, Y, Z}：
     * 每个分量都是 Fp2（两个 Fp 系数），Z = (1,0) 表示这就是仿射点。
     */
    static final BigInteger[][] P2 = new BigInteger[][]{
        new BigInteger[]{
            new BigInteger("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", 16),
            new BigInteger("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", 16) },
        new BigInteger[]{
            new BigInteger("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", 16),
            new BigInteger("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", 16) },
        new BigInteger[]{ BigInteger.ONE, BigInteger.ZERO } };

    /** G₁ 仿射点的"无穷远" = 空数组；G₂ 射影点的"无穷远" = Z 为 Fp2 的 0。 */
    static final BigInteger[] INFINITY_1 = new BigInteger[0];

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    /** Frobenius 映射要用的 6 个 Fp 常数（GB/T 32915.1 附录里给的就是这几个数）。 */
    static final BigInteger BETA = new BigInteger("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011", 16);
    static final BigInteger ALPHA1 = new BigInteger("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b", 16);
    static final BigInteger ALPHA2 = new BigInteger("f300000002a3a6f2780272354f8b78f4d5fc11967be65334", 16);
    static final BigInteger ALPHA3 = BETA;                                       // 与 beta 相同，不是巧合：α³ = β
    static final BigInteger ALPHA4 = new BigInteger("f300000002a3a6f2780272354f8b78f4d5fc11967be65333", 16);
    static final BigInteger ALPHA5 = new BigInteger("2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686", 16);

    /** ate 配对主线循环：|6u+2| 的带符号三进制，'1' = +Q，'2' = −Q，'0' = 只倍点。 */
    static final String ABITS = "00100000000000000000000000000000000000010000101100020200101000020";

    /** 最终幂难算部分用的两个指数（GB/T 32915.1 里的 a₂、a₃）。 */
    static final BigInteger FINAL_A2 = new BigInteger("d8000000019062ed0000b98b0cb27659", 16);
    static final BigInteger FINAL_A3 = new BigInteger("2400000000215d941", 16);
    private static final BigInteger FINAL_NINE = BigInteger.valueOf(9);

    // ---------------------------------------------------------------- Fp：一个 BigInteger 就是一个域元素

    static BigInteger fpAdd(BigInteger a, BigInteger b)
    {
        return a.add(b).mod(P);
    }

    static BigInteger fpSub(BigInteger a, BigInteger b)
    {
        return a.subtract(b).mod(P);
    }

    static BigInteger fpNeg(BigInteger a)
    {
        return a.negate().mod(P);
    }

    static BigInteger fpDbl(BigInteger a)
    {
        return a.shiftLeft(1).mod(P);
    }

    static BigInteger fpMul(BigInteger a, BigInteger b)
    {
        return a.multiply(b).mod(P);
    }

    static BigInteger fpSqr(BigInteger a)
    {
        return a.multiply(a).mod(P);
    }

    /** 域里唯一的"贵"运算：模逆，就是扩展欧几里得。 */
    static BigInteger fpInv(BigInteger a)
    {
        return a.modInverse(P);
    }

    // ---------------------------------------------------------------- Fp2 = Fp[u]/(u²+2)，元素 = (a₀, a₁)

    static BigInteger[] fp2Of(BigInteger a0, BigInteger a1)
    {
        return new BigInteger[]{ a0.mod(P), a1.mod(P) };
    }

    static BigInteger[] fp2Add(BigInteger[] a, BigInteger[] b)
    {
        return new BigInteger[]{ fpAdd(a[0], b[0]), fpAdd(a[1], b[1]) };
    }

    static BigInteger[] fp2Sub(BigInteger[] a, BigInteger[] b)
    {
        return new BigInteger[]{ fpSub(a[0], b[0]), fpSub(a[1], b[1]) };
    }

    static BigInteger[] fp2Neg(BigInteger[] a)
    {
        return new BigInteger[]{ fpNeg(a[0]), fpNeg(a[1]) };
    }

    static BigInteger[] fp2Dbl(BigInteger[] a)
    {
        return new BigInteger[]{ fpDbl(a[0]), fpDbl(a[1]) };
    }

    static BigInteger[] fp2Tri(BigInteger[] a)
    {
        return new BigInteger[]{ a[0].multiply(THREE).mod(P), a[1].multiply(THREE).mod(P) };
    }

    /**
     * u² = −2 是整条塔的根：(a₀+a₁u)(b₀+b₁u) = (a₀b₀ − 2a₁b₁) + (a₀b₁ + a₁b₀)u。
     * 后面 Fp4、Fp12 的乘法都是把这一条套上去，没有新东西。
     */
    static BigInteger[] fp2Mul(BigInteger[] a, BigInteger[] b)
    {
        BigInteger t0 = fpMul(a[0], b[0]);
        BigInteger t1 = fpMul(a[1], b[1]);
        return new BigInteger[]{
            fpSub(t0, fpMul(TWO, t1)),
            fpSub(fpMul(fpAdd(a[0], a[1]), fpAdd(b[0], b[1])), fpAdd(t0, t1)) };
    }

    static BigInteger[] fp2Sqr(BigInteger[] a)
    {
        return fp2Mul(a, a);
    }

    /** 乘 u：(a₀+a₁u)·u = −2a₁ + a₀u。 */
    static BigInteger[] fp2MulU(BigInteger[] a)
    {
        return new BigInteger[]{ fpNeg(fpMul(TWO, a[1])), a[0] };
    }

    /** 乘 Fp 里的标量（Frobenius 的 α、β 都是以这个方式进来的）。 */
    static BigInteger[] fp2MulFp(BigInteger[] a, BigInteger c)
    {
        return new BigInteger[]{ fpMul(a[0], c), fpMul(a[1], c) };
    }

    /** 共轭 = Fp2 上的 p 次 Frobenius：a₀ + a₁u -> a₀ − a₁u。 */
    static BigInteger[] fp2Conj(BigInteger[] a)
    {
        return new BigInteger[]{ a[0], fpNeg(a[1]) };
    }

    /** 范数 N(a) = a₀² + 2a₁²（因为 u² = −2），逆 = 共轭 / 范数。 */
    static BigInteger[] fp2Inv(BigInteger[] a)
    {
        BigInteger norm = fpAdd(fpSqr(a[0]), fpMul(TWO, fpSqr(a[1])));
        BigInteger inv = fpInv(norm);
        return new BigInteger[]{ fpMul(a[0], inv), fpMul(fpNeg(a[1]), inv) };
    }

    static boolean fp2IsZero(BigInteger[] a)
    {
        return a[0].signum() == 0 && a[1].signum() == 0;
    }

    // ---------------------------------------------------------------- Fp4 = Fp2[v]/(v²−u)，元素 = 4 个 Fp 系数

    static BigInteger[] fp4Of(BigInteger[] c0, BigInteger[] c1)
    {
        BigInteger[] out = new BigInteger[4];
        out[0] = c0[0];
        out[1] = c0[1];
        out[2] = c1[0];
        out[3] = c1[1];
        return out;
    }

    /** 取 Fp4 元素的两个 Fp2 半边：v⁰ 部分与 v¹ 部分。 */
    static BigInteger[] fp4Half(BigInteger[] a, int which)
    {
        return new BigInteger[]{ a[2 * which], a[2 * which + 1] };
    }

    static BigInteger[] fp4Add(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpAdd(a[i], b[i]);
        }
        return out;
    }

    static BigInteger[] fp4Sub(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpSub(a[i], b[i]);
        }
        return out;
    }

    static BigInteger[] fp4Neg(BigInteger[] a)
    {
        BigInteger[] out = new BigInteger[4];
        for (int i = 0; i < 4; i++)
        {
            out[i] = fpNeg(a[i]);
        }
        return out;
    }

    /** (a₀+a₁v)(b₀+b₁v) = (a₀b₀ + u·a₁b₁) + (a₀b₁ + a₁b₀)v，因为 v² = u。 */
    static BigInteger[] fp4Mul(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] a0 = fp4Half(a, 0);
        BigInteger[] a1 = fp4Half(a, 1);
        BigInteger[] b0 = fp4Half(b, 0);
        BigInteger[] b1 = fp4Half(b, 1);
        return fp4Of(fp2Add(fp2Mul(a0, b0), fp2MulU(fp2Mul(a1, b1))),
            fp2Add(fp2Mul(a0, b1), fp2Mul(a1, b0)));
    }

    static BigInteger[] fp4Sqr(BigInteger[] a)
    {
        return fp4Mul(a, a);
    }

    /** 乘 v：(x₀ + x₁v)·v = u·x₁ + x₀·v。 */
    static BigInteger[] fp4MulV(BigInteger[] x)
    {
        return fp4Of(fp2MulU(fp4Half(x, 1)), fp4Half(x, 0));
    }

    /** 乘 Fp 里的标量：Fp4 的每一半各自乘同一个数（Frobenius 的 α 就落在 Fp 里）。 */
    static BigInteger[] fp4MulFp(BigInteger[] a, BigInteger c)
    {
        return fp4Of(fp2MulFp(fp4Half(a, 0), c), fp2MulFp(fp4Half(a, 1), c));
    }

    /** Fp4 的共轭 = 翻 v 的符号；范数 = a₀² − u·a₁²。 */
    static BigInteger[] fp4Conj(BigInteger[] a)
    {
        return fp4Of(fp4Half(a, 0), fp2Neg(fp4Half(a, 1)));
    }

    static BigInteger[] fp4Inv(BigInteger[] a)
    {
        BigInteger[] a0 = fp4Half(a, 0);
        BigInteger[] a1 = fp4Half(a, 1);
        BigInteger[] norm = fp2Sub(fp2Sqr(a0), fp2MulU(fp2Sqr(a1)));
        BigInteger[] inv = fp2Inv(norm);
        return fp4Of(fp2Mul(inv, a0), fp2Mul(inv, fp2Neg(a1)));
    }

    // ---------------------------------------------------------------- Fp12 = Fp4[w]/(w³−v)，元素 = 12 个 Fp 系数

    static BigInteger[] fp12One()
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
    static BigInteger[] fp12Group(BigInteger[] a, int which)
    {
        BigInteger[] out = new BigInteger[4];
        System.arraycopy(a, 4 * which, out, 0, 4);
        return out;
    }

    static BigInteger[] fp12Of(BigInteger[] g0, BigInteger[] g1, BigInteger[] g2)
    {
        BigInteger[] out = new BigInteger[12];
        System.arraycopy(g0, 0, out, 0, 4);
        System.arraycopy(g1, 0, out, 4, 4);
        System.arraycopy(g2, 0, out, 8, 4);
        return out;
    }

    static BigInteger[] fp12Add(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = fpAdd(a[i], b[i]);
        }
        return out;
    }

    static BigInteger[] fp12Sub(BigInteger[] a, BigInteger[] b)
    {
        BigInteger[] out = new BigInteger[12];
        for (int i = 0; i < 12; i++)
        {
            out[i] = fpSub(a[i], b[i]);
        }
        return out;
    }

    static boolean fp12Equals(BigInteger[] a, BigInteger[] b)
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
    static BigInteger[] fp12Mul(BigInteger[] a, BigInteger[] b)
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

    static BigInteger[] fp12Sqr(BigInteger[] a)
    {
        return fp12Mul(a, a);
    }

    /**
     * Fp12 求逆用三次扩张的"三次共轭"公式（ξ = v）：
     * <pre>
     *   c₀ = a₀² − v·a₁a₂,  c₁ = v·a₂² − a₀a₁,  c₂ = a₁² − a₀a₂
     *   N  = a₀c₀ + v(a₁c₂ + a₂c₁)  ∈ Fp4,   a⁻¹ = N⁻¹·(c₀ + c₁w + c₂w²)
     * </pre>
     */
    static BigInteger[] fp12Inv(BigInteger[] a)
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

    /** 逐位扫描的 for 循环：先平方，再按位乘 —— 和 SM2 里那个 mul 一模一样的结构。 */
    static BigInteger[] fp12Pow(BigInteger[] base, BigInteger e)
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
    static BigInteger[] fp12FromLine(BigInteger[][] lw)
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
    static byte[] fp12ToBytes(BigInteger[] a)
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
    static BigInteger[] fp12FromBytes(byte[] buf)
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
    static BigInteger[] fp12Frobenius(BigInteger[] x)
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
    static BigInteger[] fp12Frobenius2(BigInteger[] x)
    {
        BigInteger[] a = fp4Conj(fp12Group(x, 0));
        BigInteger[] b = fp4MulFp(fp4Conj(fp12Group(x, 1)), ALPHA2);
        BigInteger[] c = fp4MulFp(fp4Conj(fp12Group(x, 2)), ALPHA4);
        return fp12Of(a, b, c);
    }

    /** x^{p³}：每组共轭后按 β 的规则带符号地错一层。 */
    static BigInteger[] fp12Frobenius3(BigInteger[] x)
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
    static BigInteger[] fp12Frobenius6(BigInteger[] x)
    {
        BigInteger[] a = fp4Conj(fp12Group(x, 0));
        BigInteger[] b = fp4Neg(fp4Conj(fp12Group(x, 1)));
        BigInteger[] c = fp4Conj(fp12Group(x, 2));
        return fp12Of(a, b, c);
    }

    // ---------------------------------------------------------------- G₁ = E(Fp): y² = x³ + 5（仿射，点 = BigInteger[2]）

    static boolean pointIsOnCurve(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return true;
        }
        BigInteger lhs = fpSqr(pt[1]);
        BigInteger rhs = fpAdd(fpMul(fpSqr(pt[0]), pt[0]), FIVE);
        return lhs.equals(rhs);
    }

    static BigInteger[] pointNeg(BigInteger[] pt)
    {
        return pt.length == 0 ? pt : new BigInteger[]{ pt[0], fpNeg(pt[1]) };
    }

    /** 弦的斜率 λ = (y₂−y₁)/(x₂−x₁)；a = 0 所以加法公式里没有曲线参数。 */
    static BigInteger[] pointAdd(BigInteger[] p, BigInteger[] q)
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

    /** 切线的斜率 λ = 3x²/(2y)（a = 0，导数只剩 3x²）。 */
    static BigInteger[] pointDouble(BigInteger[] p)
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

    /** 标量乘 = 从最高位往下的 double-and-add for 循环。 */
    static BigInteger[] pointMul(BigInteger k, BigInteger[] point)
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

    /** Fp2 里的 1 与 0，以及 E'(Fp2) 的 b' = 5u。 */
    static BigInteger[] fp2One()
    {
        return new BigInteger[]{ BigInteger.ONE, BigInteger.ZERO };
    }

    static BigInteger[] fp2FiveU()
    {
        return new BigInteger[]{ BigInteger.ZERO, BigInteger.valueOf(5) };
    }

    /** G₂ 的无穷远点：Z = 0。用同一个表示，配对和密钥运算才不会走两条路。 */
    static BigInteger[][] twistInfinity()
    {
        return new BigInteger[][]{ fp2One(), fp2One(), new BigInteger[]{ BigInteger.ZERO, BigInteger.ZERO } };
    }

    /** 仿射 (x, y) ∈ Fp2² 变成射影 {X, Y, Z=(1,0)} —— 配对内部要的是射影坐标。 */
    static BigInteger[][] twistFromAffine(BigInteger[] x, BigInteger[] y)
    {
        return new BigInteger[][]{ x, y, fp2One() };
    }

    static BigInteger[][] twistNeg(BigInteger[][] pt)
    {
        return new BigInteger[][]{ pt[0], fp2Neg(pt[1]), pt[2] };
    }

    static boolean twistIsOnCurve(BigInteger[][] pt)
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
    static BigInteger[][] twistAffineAdd(BigInteger[][] p, BigInteger[][] q)
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
    static BigInteger[][] twistAffineDouble(BigInteger[][] p)
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

    static BigInteger[][] twistMul(BigInteger k, BigInteger[][] point)
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

    /** π₁(Q)：共轭再让 Z 乘 α₁（GB/T 32915.1 里那个未声明倍的 Frobenius 组合）。 */
    static BigInteger[][] twistPi1(BigInteger[][] q)
    {
        return new BigInteger[][]{ fp2Conj(q[0]), fp2Conj(q[1]), fp2MulFp(fp2Conj(q[2]), ALPHA1) };
    }

    /** −π₂(Q)：只翻 y 的符号，Z 乘 α₂。 */
    static BigInteger[][] twistNegPi2(BigInteger[][] q)
    {
        return new BigInteger[][]{ q[0], fp2Neg(q[1]), fp2MulFp(q[2], ALPHA2) };
    }

    // ---------------------------------------------------------------- 配对的两条主线：切线 / 割线（照 GB/T 32915 的压缩公式）

    /**
     * 切线评估 + 倍点，一次算完（省一半中间量，这是所有实用实现的写法）。
     * 出参：{@code rOut} = 2·pt，{@code lwOut} = 切线在仿射点 q ∈ G₁ 处的取值（3 个 Fp2 系数）。
     * 逐行对应 GmSSL 的 sm9_z256_eval_g_tangent，只把 mont 换成了明文。
     */
    static void evalGTangent(BigInteger[][] rOut, BigInteger[][] lwOut, BigInteger[][] pt, BigInteger[] q)
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
     */
    static void evalGLine(BigInteger[][] rOut, BigInteger[][] lwOut, BigInteger[][] acc,
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
     */
    static BigInteger[] pairing(BigInteger[][] qTwist, BigInteger[] pAffine)
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
     */
    static BigInteger[] finalExponent(BigInteger[] f)
    {
        BigInteger[] t0 = fp12Mul(fp12Frobenius6(f), fp12Inv(f));
        t0 = fp12Mul(t0, fp12Frobenius2(t0));
        return finalExponentHardPart(t0);
    }

    /** 难算部分的加法链（GmSSL 的 sm9_z256_final_exponent_hard_part，逐步对应）。 */
    static BigInteger[] finalExponentHardPart(BigInteger[] f)
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
    static boolean twistIsInfinity(BigInteger[][] pt)
    {
        return fp2IsZero(pt[2]);
    }

    /** 射影 -> 仿射（同除 Z），只用于结果核对；配对内部一直保持射影。 */
    static BigInteger[][] twistToAffine(BigInteger[][] pt)
    {
        BigInteger[] zInv = fp2Inv(pt[2]);
        return twistFromAffine(fp2Mul(pt[0], fp2Sqr(zInv)), fp2Mul(fp2Mul(pt[1], zInv), fp2Sqr(zInv)));
    }

    // ---------------------------------------------------------------- 模 n 的标量运算与"哈希 -> [1,n-1]"

    static BigInteger modnAdd(BigInteger a, BigInteger b)
    {
        return a.add(b).mod(N);
    }

    static BigInteger modnSub(BigInteger a, BigInteger b)
    {
        return a.subtract(b).mod(N);
    }

    static BigInteger modnMul(BigInteger a, BigInteger b)
    {
        return a.multiply(b).mod(N);
    }

    static BigInteger modnInv(BigInteger a)
    {
        return a.modInverse(N);
    }

    /**
     * GB/T 32915 的"把哈希当成 [1, n−1] 里的数"：取摘要的前 40 字节（320 bit）当整数，
     * <b>对 n−1 取模再加 1</b>。加 1 这一步不是装饰 —— 它保证 k、h 永远不等于 0，
     * 而 0 会让 r = e(P,Q)⁰ 变成单位元，签名立刻退化成公开可伪造。
     */
    static BigInteger modnFromHash(byte[] ha)
    {
        BigInteger z = Calc.toBigInt(java.util.Arrays.copyOfRange(ha, 0, 40));
        return z.mod(N.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    /** H1(ID, hid) = 模 n 归约(SM3(0x01‖ID‖hid‖00000001) ‖ SM3(0x01‖ID‖hid‖00000002))。 */
    static BigInteger hash1(byte[] id, int hid)
    {
        byte[] ha = Calc.concat(
            Sm3EssenceTest.sm3(Calc.concat(new byte[]{ 0x01 }, id, new byte[]{ (byte)hid }, new byte[]{ 0, 0, 0, 1 })),
            Sm3EssenceTest.sm3(Calc.concat(new byte[]{ 0x01 }, id, new byte[]{ (byte)hid }, new byte[]{ 0, 0, 0, 2 })));
        return modnFromHash(ha);
    }

    /** H2(M, w) = 同一个套路，前缀换成 0x02，把 384 字节的 w 接在消息后面。 */
    static BigInteger hash2(byte[] message, byte[] w)
    {
        byte[] head = Calc.concat(new byte[]{ 0x02 }, message, w);
        byte[] ha = Calc.concat(
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 1 })),
            Sm3EssenceTest.sm3(Calc.concat(head, new byte[]{ 0, 0, 0, 2 })));
        return modnFromHash(ha);
    }

    /** SM3 计数器 KDF：T = SM3(Z‖1) ‖ SM3(Z‖2) ‖ …，一个 while 循环填够 klen 字节。 */
    static byte[] kdfSm3(byte[] z, int klen)
    {
        byte[] out = new byte[klen];
        int off = 0;
        int counter = 1;
        while (off < klen)
        {
            byte[] block = Sm3EssenceTest.sm3(Calc.concat(z, Calc.toBytes(BigInteger.valueOf(counter), 4)));
            int take = Math.min(klen - off, block.length);
            System.arraycopy(block, 0, out, off, take);
            off += take;
            counter++;
        }
        return out;
    }

    /** HMAC-SM3（分组 64 字节）：加密侧的 C3 完整性标签用它。 */
    static byte[] hmacSm3(byte[] key, byte[] msg)
    {
        byte[] k = key.length > 64 ? Sm3EssenceTest.sm3(key) : key;
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        System.arraycopy(k, 0, ipad, 0, k.length);
        System.arraycopy(k, 0, opad, 0, k.length);
        for (int i = 0; i < 64; i++)
        {
            ipad[i] ^= 0x36;
            opad[i] ^= 0x5c;
        }
        return Sm3EssenceTest.sm3(Calc.concat(opad, Sm3EssenceTest.sm3(Calc.concat(ipad, msg))));
    }

    // ---------------------------------------------------------------- 点的字节化（和 GmSSL 的 DER/八位组表示一致）

    /** G₁ 点 -> 0x04 ‖ x(32) ‖ y(32)；无穷远点用 0x00 打头，避免歧义。 */
    static byte[] pointToOctets(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return new byte[]{ 0x00 };
        }
        return Calc.concat(new byte[]{ 0x04 }, Calc.toBytes(pt[0], 32), Calc.toBytes(pt[1], 32));
    }

    static BigInteger[] pointFromOctets(byte[] octets)
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
    static byte[] twistToOctets(BigInteger[][] pt)
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

    static BigInteger[][] twistFromOctets(byte[] octets)
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

    /** 三个用途的 hid 字节：签名 0x01、密钥交换 0x02、加密 0x03。 */
    static final int HID_SIGN = 0x01;
    static final int HID_EXCH = 0x02;
    static final int HID_ENC = 0x03;

    /** 主密钥的随机数：与 GmSSL 的 sm9_z256_rand_range 同构 —— 采 32 字节大端，>= n 就重采。 */
    static BigInteger randScalar(java.util.Random rnd)
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
    static BigInteger[][] signMasterPublicKey(BigInteger ks)
    {
        return twistMul(ks, P2);
    }

    /**
     * 私钥提取 ds = ks·(ks + H1(ID,0x01))⁻¹ · P1 ∈ G₁。
     * 分母是"主私钥 + 标识哈希"，这就是基于标识密码的特征：标识本身进了标量。
     */
    static BigInteger[] signPrivateKeyExtract(BigInteger ks, byte[] id)
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
     */
    static byte[] sign(byte[] message, byte[] id, BigInteger ks, BigInteger r)
    {
        BigInteger[] g = pairing(signMasterPublicKey(ks), P1);
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
        return Calc.concat(Calc.toBytes(h, 32), pointToOctets(pointMul(l, signPrivateKeyExtract(ks, id))));
    }

    /**
     * 验签（B1~B5）：验签方只要 Ppubs，不需要主私钥。
     * <pre>
     *   P' = H1(ID,0x01)·P2 + Ppubs;   u = e(S, P');   t = g^h;   w = u·t;   核对 H2(M‖w) == h
     *   代入 S = l·ds、ds = ks/(ks+h1)·P1 可得 u = g^l，于是 w = g^{l+h} = g^r —— 与签名侧同一个 w。
     * </pre>
     */
    static boolean verify(byte[] message, byte[] signature, byte[] id, BigInteger[][] ppubs)
    {
        BigInteger h = Calc.toBigInt(ArraysRange(signature, 0, 32));
        BigInteger[] S = pointFromOctets(ArraysRange(signature, 32, 97));
        BigInteger[] g = pairing(ppubs, P1);
        BigInteger[] t = fp12Pow(g, h);
        BigInteger[][] pp = twistAffineAdd(twistMul(hash1(id, HID_SIGN), P2), ppubs);
        byte[] wbuf = fp12ToBytes(fp12Mul(pairing(pp, S), t));
        return h.equals(hash2(message, wbuf));
    }

    /** 加密主公钥 Ppube = ke·P1 ∈ G₁。 */
    static BigInteger[] encMasterPublicKey(BigInteger ke)
    {
        return pointMul(ke, P1);
    }

    /**
     * 私钥提取 de = ke·(ke + H1(ID,hid))⁻¹ · P2 ∈ G₂。加密用 hid = 0x03，密钥交换用 0x02，
     * 同一个主密钥给两个用途导出<b>两把不同的私钥</b> —— 这就是 hid 存在的全部理由。
     */
    static BigInteger[][] privateKeyExtract(BigInteger ke, byte[] id, int hid)
    {
        BigInteger t = modnAdd(hash1(id, hid), ke);
        return twistMul(modnMul(ke, modnInv(t)), P2);
    }

    /** KEM 里的 Q_B = H1(ID,0x03)·P1 + Ppube —— 标识直接拼进公钥点，所以没有证书。 */
    static BigInteger[] kemQ(BigInteger ke, byte[] id)
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
    static byte[] kemEncrypt(BigInteger ke, byte[] id, int klen, BigInteger r)
    {
        byte[] c1 = pointToOctets(pointMul(r, kemQ(ke, id)));
        byte[] wbuf = fp12ToBytes(fp12Pow(pairing(P2, encMasterPublicKey(ke)), r));
        byte[] k = kdfSm3(Calc.concat(ArraysRange(c1, 1, 65), wbuf, id), klen);
        return Calc.concat(c1, k);
    }

    /**
     * KEM 解密（B1~B4）：w = e(C1, de)，其余与加密侧逐字节相同。
     * B1 的"先检查 C1 在 G₁ 上"不是可选的 —— 塞一个不在曲线上的点进来，配对会算出
     * 一个跟真密钥无关的 w，攻击者就能靠"解密成功与否"的信号做错误预言攻击。
     */
    static byte[] kemDecrypt(BigInteger ke, byte[] id, int klen, byte[] c1)
    {
        BigInteger[] point = pointFromOctets(c1);
        if (!pointIsOnCurve(point))
        {
            throw new IllegalArgumentException("C1 不在 G₁ 上：拒绝（GB/T 32915.3 的 B1 步）");
        }
        byte[] wbuf = fp12ToBytes(pairing(privateKeyExtract(ke, id, HID_ENC), point));
        return kdfSm3(Calc.concat(ArraysRange(c1, 1, 65), wbuf, id), klen);
    }

    /**
     * 完整 IBBE（GmSSL 的 sm9_do_encrypt）：K 一次取 <b>明文长度 + 32</b> 字节，
     * 前 len 字节当异或掩码，后 32 字节当 HMAC-SM3 的密钥 —— 没有分组密码，只有一次异或。
     * 返回 C1(65) ‖ C3(32) ‖ C2。
     */
    static byte[] encrypt(BigInteger ke, byte[] id, byte[] message, BigInteger r)
    {
        byte[] full = kemEncrypt(ke, id, message.length + 32, r);
        byte[] c1 = ArraysRange(full, 0, 65);
        byte[] kbuf = ArraysRange(full, 65, full.length);
        byte[] c2 = Calc.xor(ArraysRange(kbuf, 0, message.length), message);
        byte[] c3 = hmacSm3(ArraysRange(kbuf, message.length, message.length + 32), c2);
        return Calc.concat(c1, c3, c2);
    }

    /** 解密：先用 de 还原同一个 K，核 C3，再异或回来。 */
    static byte[] decrypt(BigInteger ke, byte[] id, byte[] c1, byte[] c2, byte[] c3)
    {
        byte[] kbuf = kemDecrypt(ke, id, c2.length + 32, c1);
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
     * 出参：{@code gOut[0..2]} 各 384 字节，{@code rOut[0]} = RA(64)、{@code rOut[1]} = RB(64)。
     */
    static void exchComputeG(boolean isInitiator, BigInteger ke, byte[] ownId,
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
    static byte[] exchSessionKey(boolean isInitiator, BigInteger ke, byte[] ownId, byte[] peerId,
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
    static byte[] exchConfirmTag(byte[] g1, byte[] g2, byte[] g3,
        byte[] ra, byte[] rb, byte[] idA, byte[] idB, int prefix)
    {
        byte[] hash = Sm3EssenceTest.sm3(Calc.concat(g2, g3, idA, idB, ra, rb));
        return Sm3EssenceTest.sm3(Calc.concat(new byte[]{ (byte) prefix }, g1, hash));
    }

    /** 交换里 A 的临时点 RA = rA·(H1(ID_B,0x02)·P1 + Ppube)：Q 用的是<b>对方</b>的标识。 */
    static BigInteger[] exchEphemeral(BigInteger ke, byte[] peerId, BigInteger r)
    {
        return pointMul(r, pointAdd(pointMul(hash1(peerId, HID_EXCH), P1), encMasterPublicKey(ke)));
    }
}
