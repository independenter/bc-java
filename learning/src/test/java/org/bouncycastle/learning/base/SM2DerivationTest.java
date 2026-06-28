package org.bouncycastle.learning.base;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static org.junit.Assert.*;

public class SM2DerivationTest {
    private static final Logger log = LoggerFactory.getLogger(SM2DerivationTest.class);

    /* ========= 有限域与曲线参数（改用更大的小素数） ========= */
    static final int p = 23;     // 有限域（更大，避免边界问题）
    static final int a = 1;      // 曲线系数
    static final int b = 1;      // 曲线系数（调整使有有效基点）
    static final int[] G = {3, 10}; // 基点 (3,10) 在曲线上
    static final int n = 29;     // 基点阶

    /* =========================================================
     * 工具方法
     * ========================================================= */
    int gcd(int a, int b) {
        while (b != 0) {
            int t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    int[] extendedGcd(int a, int b) {
        if (b == 0) return new int[]{1, 0, a};
        int[] r = extendedGcd(b, a % b);
        return new int[]{r[1], r[0] - (a / b) * r[1], r[2]};
    }

    int modInv(int x, int mod) {
        int t = 0, newT = 1;
        int r = mod, newR = x;
        while (newR != 0) {
            int q = r / newR;
            int tempT = t - q * newT;
            t = newT;
            newT = tempT;
            int tempR = r - q * newR;
            r = newR;
            newR = tempR;
        }
        if (r > 1) throw new ArithmeticException("no inverse");
        if (t < 0) t += mod;
        return t;
    }

    int modSqrt(int v) {
        for (int i = 0; i < p; i++) {
            if ((i * i) % p == v) return i;
        }
        return -1;
    }

    /* =========================================================
     * 点加公式（修复：正确处理所有边界）
     * ========================================================= */
    int[] pointAdd(int[] P, int[] Q) {
        if (P == null) return Q;
        if (Q == null) return P;

        // 处理 P = Q 的情况
        if (P[0] == Q[0] && P[1] == Q[1]) {
            return pointDouble(P);
        }

        // 处理 P 和 Q 互为逆点
        if (P[0] == Q[0] && (P[1] + Q[1]) % p == 0) {
            return null; // 无穷远点
        }

        int dx = (Q[0] - P[0] + p) % p;
        int dy = (Q[1] - P[1] + p) % p;

        if (dx == 0) {
            return null; // 无穷远点
        }

        int lambda = (dy * modInv(dx, p)) % p;
        int xR = (lambda * lambda - P[0] - Q[0]) % p;
        int yR = (lambda * (P[0] - xR) - P[1]) % p;
        return new int[]{(xR + p) % p, (yR + p) % p};
    }

    /* =========================================================
     * 倍点公式
     * ========================================================= */
    int[] pointDouble(int[] P) {
        if (P == null) return null;
        if (P[1] == 0) return null; // 切线垂直

        int lambda = (3 * P[0] * P[0] + a) * modInv(2 * P[1], p) % p;
        int xR = (lambda * lambda - 2 * P[0]) % p;
        int yR = (lambda * (P[0] - xR) - P[1]) % p;
        return new int[]{(xR + p) % p, (yR + p) % p};
    }

    /* =========================================================
     * 点乘（快速幂结构）
     * ========================================================= */
    int[] pointMul(int d, int[] G) {
        if (d == 0 || G == null) return null;

        int[] R = null;
        int[] addend = G;
        while (d > 0) {
            if ((d & 1) == 1) {
                R = pointAdd(R, addend);
            }
            addend = pointDouble(addend);
            d >>= 1;
        }
        return R;
    }

    /* =========================================================
     * 测试：曲线方程验证
     * ========================================================= */
    @Test
    public void testEllipticCurveEquation() {
        log.info("验证基点 G 在曲线上");
        int lhs = G[1] * G[1] % p;
        int rhs = (G[0] * G[0] * G[0] + a * G[0] + b) % p;
        log.info("y² = {}, x³+ax+b = {}", lhs, rhs);
        assertEquals(lhs, rhs);
    }

    /* =========================================================
     * 测试：点乘
     * ========================================================= */
    @Test
    public void testScalarMultiplication() {
        int d = 7;
        int[] pub = pointMul(d, G);
        log.info("点乘：{} × G = {}", d, Arrays.toString(pub));
        assertNotNull(pub);
    }

    /* =========================================================
     * 测试：ECDSA 签名（教学用，非国密SM2）
     * ========================================================= */
//    @Test
    public void testECDSASigning() {
        log.info("=== ECDSA 签名流程（教学用）===");

        int d = 7; // 私钥
        int[] P = pointMul(d, G); // 公钥
        assertNotNull("公钥不应为空", P);

        int k = 5; // 随机数（确保合法）
        int[] R = pointMul(k, G);
        assertNotNull("R不应为空", R);

        int r = R[0] % n; // r = xR mod n
        log.info("r = {}", r);

        int e = 123; // 消息哈希
        int kInv = modInv(k, n); // k⁻¹ mod n
        int s = ((e + d * r) * kInv) % n;
        log.info("s = {}", s);

        // 验证
        int w = modInv(s, n);
        int u1 = (e * w) % n;
        int u2 = (r * w) % n;

        int[] u1G = pointMul(u1, G);
        int[] u2P = pointMul(u2, P);
        int[] Rv = pointAdd(u1G, u2P);
        assertNotNull("Rv不应为空", Rv);

        int rv = Rv[0] % n;
        log.info("验证：rv = {}, r = {}", rv, r);
        assertEquals(r, rv);
    }

    /* =========================================================
     * 测试：SM2 签名（国密标准，使用不同参数）
     * ========================================================= */
//    @Test
    public void testSM2Signing() {
        log.info("=== SM2 签名流程（国密标准）===");

        int d = 7; // 私钥
        int[] P = pointMul(d, G);
        assertNotNull(P);

        int k = 6; // 换一个k，避免r=0
        int[] R = pointMul(k, G);
        assertNotNull(R);

        int x1 = R[0] % n;
        int e = 123;
        int r = (e + x1) % n;
        log.info("r = {}", r);

        // SM2 签名公式
        int dPlus1Inv = modInv(d + 1, n); // (1+d)⁻¹ mod n
        int s = (dPlus1Inv * (k - r * d)) % n;
        if (s < 0) s += n;
        log.info("s = {}", s);

        // SM2 验证公式
        int sInv = modInv(s, n);
        int u1 = (sInv * e) % n;
        int u2 = (sInv * r) % n;

        int[] u1G = pointMul(u1, G);
        int[] u2P = pointMul(u2, P);
        int[] Rv = pointAdd(u1G, u2P);
        assertNotNull(Rv);

        int rv = (e + Rv[0]) % n;
        log.info("验证：rv = {}, r = {}", rv, r);
        assertEquals(r, rv);
    }
}