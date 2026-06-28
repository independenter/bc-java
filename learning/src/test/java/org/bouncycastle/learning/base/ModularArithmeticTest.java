package org.bouncycastle.learning.base;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

@Slf4j
public class ModularArithmeticTest {

    static int modAdd(int a, int b, int mod) {
        return (a + b) % mod;
    }

    static int modMul(int a, int b, int mod) {
        return (a * b) % mod;
    }

    static int modPow(int base, int exp, int mod) {
        int result = 1;
        base %= mod;
        while (exp > 0) {
            // ① 当前位是否是 1？
            if ((exp & 1) == 1) {
                result = (result * base) % mod;
            }
            // ② 底数平方（对应“平方链”）
            base = (base * base) % mod;
            // ③ 右移一位（处理下一位）
            exp >>= 1;
        }
        return result;
    }

    @Test
    public void test() {
        int mod = 17;

        System.out.println("模加: " + modAdd(10, 7, mod));
        System.out.println("模乘: " + modMul(6, 5, mod));
        System.out.println("模幂: " + modPow(3, 13, mod)); // 3^13 mod 17 = 6
    }

    /**
     * 模幂运算推断：
     * 1. 幂运算的计算过程：
     * 3^5 mod 17
     * = 3 × 3 × 3 × 3 × 3 mod 17
     * = 243 mod 17
     * = 6
     * 2. 原理
     * 幂运算的计算过程，可以理解为将一个数重复乘 itself 的 n 次，然后对 mod 取模。
     * 可以利用指数的二进制表示，把"大幂运算"拆成"多次平方+少量乘法". -- 快速幂
     * 3. 例子: 3^13 mod 17
     * 3.1 13 = 1101
     *        = 8 + 4 + 1
     *        = 2^3 + 2^2 + 2^0
     *        = 2^0 + 2^2 + 2^3
     * 3.2 拆平方链
     *     3^1 mod 17 = 3
     *     3^2 mod 17 = 3^1 * 3^1 mod 17 = 3 * 3 mod 17 = 9 mod 17 = 9
     *     3^4 mod 17 = 3^2 * 3^2 mod 17 = 9 * 9 mod 17 = 81 mod 17 = 13
     *     3^8 mod 17 = 3^4 * 3^4 mod 17 = 13 * 13 mod 17 = 169 mod 17 = 16
     * 3.4 按二进制拼接
     *    3^13 mod 17 = 3^8 * 3^4 * 3^1 mod 17
     *                = 16 * 13 * 3 mod 17
     *                = 624 mod 17
     *                = 12
     *     时间复杂度：O(log n) = log₂(13) ≈ 4 次平方 + 几次乘法
     *
     * 数学定理: (a × b) mod m = [(a mod m) × (b mod m)] mod m
      */
    @Test
    public void test1() {
        int mod = 17;
        int base = 3;
        int exp = 5;
        int result1 = Math.powExact(base, exp) % mod; // 注意 base ^ exp 在程序里面不是幂运算,是异或
        log.info("result1: {}", result1);

        int exp1 = 0b0101;
        int result = 1;
        base %= mod; // 3 mod 17 = 3
        if ((exp1 & 1) == 1) { // 0b0101 & 1 = 1
            // 计算第一位余数
            result = (result * base) % mod; // 3 mod 17 = 3
            // 计算下一轮平方链
            base = (base * base) % mod; // 9 mod 17 = 9
            exp1 >>= 1;
        }
        if ((exp1 & 1) == 0) { // 0b010 & 1 = 0
            // 继续计算下一轮平方链
            base = (base * base) % mod; // 81 mod 17 = 13
            exp1 >>= 1;
        }
        if ((exp1 & 1) == 1) { // 0b01 & 1 = 1
            // 继续计算第三位余数
            result = (result * base) % mod; // 39 mod 17 = 5
            // 继续计算下一轮平方链
            base = (base * base) % mod; // 169 mod 17 = 16
            exp1 >>= 1;
        }
        if ((exp1 & 1) == 0) { // 0b0 & 1 = 0
            // 继续计算下一轮平方链
            base = (base * base) % mod; // 256 mod 17 = 16
            exp1 >>= 1;
        }
        log.info("result2: {}", result);
    }
}