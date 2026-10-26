package org.bouncycastle.learning.trace;

import java.math.BigInteger;
import java.security.SecureRandom;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * 追踪框架的演示测试 —— 展示如何使用 @TraceExecution 注解和 Tracer。
 */
@Slf4j
public class TracerDemoTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    private static final X9ECParameters CURVE_PARAMS = GMNamedCurves.getByName("sm2p256v1");
    private static final BigInteger P = CURVE_PARAMS.getCurve().getField().getCharacteristic();
    private static final BigInteger N = CURVE_PARAMS.getN();
    private static final BigInteger GX = CURVE_PARAMS.getG().getAffineXCoord().toBigInteger();
    private static final BigInteger GY = CURVE_PARAMS.getG().getAffineYCoord().toBigInteger();

    /**
     * 演示：追踪椭圆曲线点加运算。
     */
    @TraceExecution("EC 点加追踪演示")
    @Test
    public void traceEcAdd()
    {
        log.info("=== EC 点加追踪演示 ===");

        // 生成两个随机点
        BigInteger k1 = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger k2 = new BigInteger(256, new SecureRandom()).mod(N);
        BigInteger[] pt1 = ecMul(k1, GX, GY, P);
        BigInteger[] pt2 = ecMul(k2, GX, GY, P);

        log.info("pt1 = ({}, {})", pt1[0].toString(16).substring(0, 16),
            pt1[1].toString(16).substring(0, 16));
        log.info("pt2 = ({}, {})", pt2[0].toString(16).substring(0, 16),
            pt2[1].toString(16).substring(0, 16));

        // 执行点加（会被追踪）
        BigInteger[] result = ecAdd(pt1, pt2);

        log.info("result = ({}, {})", result[0].toString(16).substring(0, 16),
            result[1].toString(16).substring(0, 16));

        Assert.assertNotNull(result);
        Assert.assertEquals(2, result.length);
    }

    /**
     * 演示：追踪标量乘法。
     */
    @TraceExecution("EC 标量乘追踪演示")
    @Test
    public void traceEcMul()
    {
        log.info("=== EC 标量乘追踪演示 ===");

        BigInteger k = new BigInteger(256, new SecureRandom()).mod(N);
        log.info("k = {}", k.toString(16).substring(0, 16));

        // 执行标量乘（会被追踪）
        BigInteger[] result = ecMul(k, GX, GY, P);

        log.info("result = ({}, {})", result[0].toString(16).substring(0, 16),
            result[1].toString(16).substring(0, 16));

        Assert.assertNotNull(result);
        Assert.assertEquals(2, result.length);
    }

    // =====================================================================
    // 带追踪的椭圆曲线运算
    // =====================================================================

    private static BigInteger[] ecAdd(BigInteger[] pt1, BigInteger[] pt2)
    {
        long startNanos = System.nanoTime();

        if (pt1.length == 0)
        {
            return pt2;
        }
        if (pt2.length == 0)
        {
            return pt1;
        }

        BigInteger x1 = pt1[0], y1 = pt1[1];
        BigInteger x2 = pt2[0], y2 = pt2[1];

        if (x1.equals(x2) && y1.equals(y2))
        {
            BigInteger[] result = ecDouble(pt1);
            long duration = System.nanoTime() - startNanos;
            Tracer.trace("ecAdd (double)", new Object[]{"pt", pt1}, result, duration);
            return result;
        }

        if (x1.equals(x2))
        {
            BigInteger[] result = new BigInteger[0];
            long duration = System.nanoTime() - startNanos;
            Tracer.trace("ecAdd (infinity)", new Object[]{"pt1", pt1, "pt2", pt2}, result, duration);
            return result;
        }

        // λ = (y₂ - y₁) / (x₂ - x₁) mod p
        BigInteger lam = y2.subtract(y1).mod(P)
            .multiply(x2.subtract(x1).modInverse(P)).mod(P);

        // x₃ = λ² - x₁ - x₂ mod p
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(P);

        // y₃ = λ(x₁ - x₃) - y₁ mod p
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(P);

        BigInteger[] result = new BigInteger[]{x3, y3};
        long duration = System.nanoTime() - startNanos;

        // 记录追踪
        Tracer.trace("ecAdd", new Object[]{
            "pt1", pt1,
            "pt2", pt2,
            "lambda", lam
        }, result, duration);

        return result;
    }

    private static BigInteger[] ecDouble(BigInteger[] pt)
    {
        if (pt.length == 0)
        {
            return pt;
        }

        BigInteger x = pt[0], y = pt[1];
        if (y.signum() == 0)
        {
            return new BigInteger[0];
        }

        BigInteger a = P.subtract(BigInteger.valueOf(3));
        BigInteger num = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a).mod(P);
        BigInteger den = y.multiply(BigInteger.valueOf(2)).mod(P);
        BigInteger lam = num.multiply(den.modInverse(P)).mod(P);
        BigInteger x3 = lam.multiply(lam).subtract(x.multiply(BigInteger.valueOf(2))).mod(P);
        BigInteger y3 = lam.multiply(x.subtract(x3)).subtract(y).mod(P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] ecMul(BigInteger k, BigInteger gx, BigInteger gy, BigInteger mod)
    {
        long startNanos = System.nanoTime();

        BigInteger[] result = new BigInteger[0];
        BigInteger[] base = {gx, gy};
        BigInteger exp = k;
        int step = 0;

        while (exp.signum() > 0)
        {
            if (exp.testBit(0))
            {
                result = ecAdd(result, base);
                step++;

                // 每 4 步记录一次（避免追踪数据过多）
                if (Tracer.isEnabled() && step % 4 == 0)
                {
                    Tracer.trace("ecMul.step", new Object[]{
                        "bit", k.bitLength() - exp.bitLength(),
                        "intermediate", result
                    }, null, "default");
                }
            }
            base = ecDouble(base);
            exp = exp.shiftRight(1);
        }

        long duration = System.nanoTime() - startNanos;
        Tracer.trace("ecMul", new Object[]{
            "k", k,
            "base", new BigInteger[]{gx, gy},
            "steps", step
        }, result, duration);

        return result;
    }
}
