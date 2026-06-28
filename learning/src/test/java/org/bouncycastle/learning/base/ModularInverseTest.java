package org.bouncycastle.learning.base;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * 模逆是模的倒数
 * 若 a · a⁻¹ ≡ 1 (mod m), 则称 a⁻¹为 a在模 m下的模逆。
 * 前提条件:  gcd(a, m) = 1（a 和 m 互素）, gcd代表最大公约数.
 */
@Slf4j
public class ModularInverseTest {

    // 扩展欧几里得
    static int modInverse(int a, int mod) {
        int t = 0, newT = 1;
        int r = mod, newR = a;

        while (newR != 0) {
            int q = r / newR;
            int tempT = t - q * newT;
            t = newT;
            newT = tempT;

            int tempR = r - q * newR;
            r = newR;
            newR = tempR;
        }

        if (r > 1) {
            throw new ArithmeticException("逆元不存在");
        }
        if (t < 0) {
            t += mod;
        }
        return t;
    }

    static boolean hasInverse(int a, int m) {
        return gcd(a, m) == 1;
    }

    static int gcd(int a, int b) {
        while (b != 0) {
            int t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    @Test
    public void testModularInverse() {
        // 情况1：互素，有逆元
        int a = 3;
        int m = 17;

        // 用扩展欧几里得算法计算逆元
        int inverse = modInverse(a, m);

        log.info("{} 在模 {} 下的逆元是: {}", a, m, inverse);

        // 验证：a * inverse ≡ 1 (mod m)
        int verification = (a * inverse) % m;
        log.info("验证: {} × {} mod {} = {}", a, inverse, m, verification);
        assertEquals(1, verification);

        // 情况2：不互素，无逆元
        int a2 = 2;
        int m2 = 6;

        try {
            int inverse2 = modInverse(a2, m2);
            log.info("{} 在模 {} 下的逆元是: {}", a2, m2, inverse2);
            fail("预期抛出异常，但没有抛出");
        } catch (ArithmeticException e) {
            log.info("{} 在模 {} 下无逆元: {}", a2, m2, e.getMessage());
            assertTrue(e.getMessage().contains("逆元不存在"));
        }
    }

    /**
     * 模逆运算推断：
     * 1. 模逆的定义：
     *    若 a·x ≡ 1 (mod m)，则称 x 为 a 在模 m 下的逆元。
     *    即：a 乘以 x 除以 m 的余数为 1。
     *
     * 2. 原理：
     *    利用扩展欧几里得算法求解方程：a·x + m·y = 1
     *    当 gcd(a, m) = 1 时，方程有整数解 (x, y)。
     *    两边对 m 取模，消去 y，得到：a·x ≡ 1 (mod m)
     *
     * 3. 扩展欧几里得算法详解：
     *    算法维护两组变量 (r, s, t) 和 (r', s', t')，分别表示：
     *    - r: 当前余数（从大到小递减）
     *    - s: 当前余数对应的 a 的系数
     *    - t: 当前余数对应的 m 的系数
     *
     *    初始状态：
     *    r₁ = m, s₁ = 1, t₁ = 0  → 表示：m = 1·m + 0·a
     *    r₂ = a, s₂ = 0, t₂ = 1  → 表示：a = 0·m + 1·a
     *
     *    迭代过程：
     *    用 r₁ 除以 r₂，得到商 q 和余数 r₃
     *    r₃ = r₁ - q·r₂
     *    s₃ = s₁ - q·s₂
     *    t₃ = t₁ - q·t₂
     *
     *    然后更新：
     *    (r₁, s₁, t₁) = (r₂, s₂, t₂)
     *    (r₂, s₂, t₂) = (r₃, s₃, t₃)
     *
     *    重复直到 r₂ = 0，此时 r₁ = gcd(a, m)，且 s₁·m + t₁·a = gcd(a, m)
     *
     * 4. 例子：求 3⁻¹ mod 17
     *    4.1 用扩展欧几里得算法求解 3·x + 17·y = 1
     *        初始状态：
     *          r₁ = 17, s₁ = 1, t₁ = 0  → 17 = 1·17 + 0·3
     *          r₂ = 3,  s₂ = 0, t₂ = 1  → 3  = 0·17 + 1·3
     *
     *        第一轮：17 ÷ 3 = 5 余 2
     *          r₃ = 2 = 17 - 5×3
     *          s₃ = 1 - 5×0 = 1
     *          t₃ = 0 - 5×1 = -5
     *          更新后：
     *          r₁ = 3,  s₁ = 0, t₁ = 1
     *          r₂ = 2,  s₂ = 1, t₂ = -5
     *
     *        第二轮：3 ÷ 2 = 1 余 1
     *          r₃ = 1 = 3 - 1×2
     *          s₃ = 0 - 1×1 = -1
     *          t₃ = 1 - 1×(-5) = 6
     *          更新后：
     *          r₁ = 2,  s₁ = 1, t₁ = -5
     *          r₂ = 1,  s₂ = -1, t₂ = 6
     *
     *        第三轮：2 ÷ 1 = 2 余 0，结束
     *        最终：r₁ = 1, s₁ = -1, t₁ = 6
     *        即：(-1)·17 + 6·3 = 1
     *
     *    4.2 验证：3 × 6 + 17 × (-1) = 18 - 17 = 1 ✓
     *    4.3 取正数：(-1 + 17) mod 17 = 16
     *        但 t₁ = 6 已经是正数，所以 3⁻¹ mod 17 = 6
     *
     * 5. 不互素的情况（无解）：
     *    求 2⁻¹ mod 6
     *    gcd(2, 6) = 2 ≠ 1，逆元不存在。
     *    验证：2 × 1 = 2 mod 6 = 2
     *         2 × 2 = 4 mod 6 = 4
     *         2 × 3 = 6 mod 6 = 0
     *         2 × 4 = 8 mod 6 = 2
     *         2 × 5 = 10 mod 6 = 4
     *    永远得不到 1，所以无解。
     *
     * 6. 数学定理：
     *    a 在模 m 下有逆元的充要条件是 gcd(a, m) = 1。
     */
    @Test
    public void testModularInverseDerivation() {
        int a = 3;  // 要求逆的数
        int m = 17; // 模数

        log.info("=== 模逆推导过程 ===");
        log.info("目标：找到 x 使得 {}·x ≡ 1 (mod {})", a, m);
        log.info("即求解方程：{}·x + {}·y = 1", a, m);

        // 步骤1：验证互素
        int gcd = gcd(a, m);
        log.info("步骤1：验证 gcd({}, {}) = {}", a, m, gcd);
        if (gcd != 1) {
            log.info("由于 gcd ≠ 1，逆元不存在");
            return;
        }

        // 步骤2：扩展欧几里得算法
        log.info("步骤2：扩展欧几里得算法求解 {}·x + {}·y = 1", a, m);
        log.info("初始状态：");
        log.info("  r₁ = {}, s₁ = 1, t₁ = 0  → {} = 1·{} + 0·{}", m, m, m, a);
        log.info("  r₂ = {}, s₂ = 0, t₂ = 1  → {} = 0·{} + 1·{}", a, a, m, a);

        /**
         * extendedGcd(3, 17)
         * → extendedGcd(17, 3)
         *    → extendedGcd(3, 2)
         *       → extendedGcd(2, 1)
         *          → extendedGcd(1, 0) 返回 [1, 0, 1]
         */
        int[] result = extendedGcd(a, m);
        int x = result[0];  // a 的系数（即逆元）
        int y = result[1];  // m 的系数
        int g = result[2];  // 最大公约数

        log.info("最终状态：");
        log.info("  r = {}, s = {}, t = {}", g, y, x);
        log.info("验证：{}·({}) + {}·({}) = {}", a, x, m, y, a * x + m * y);

        // 步骤3：调整为正值
        if (x < 0) {
            int originalX = x;
            x += m;
            log.info("步骤3：调整 x 为正值，x = {} + {} = {}", originalX, m, x);
        }

        // 步骤4：验证
        int check = (a * x) % m;
        log.info("步骤4：验证 {} × {} mod {} = {}", a, x, m, check);

        if (check == 1) {
            log.info("✅ 验证成功，{}⁻¹ mod {} = {}", a, m, x);
        } else {
            log.info("❌ 验证失败");
        }

        assertEquals(1, check);
    }

    /**
     * 扩展欧几里得算法（返回数组形式：[x, y, gcd]）
     */
    private int[] extendedGcd(int a, int b) {
        if (b == 0) {
            return new int[]{1, 0, a};
        }

        int[] result = extendedGcd(b, a % b);
        int x1 = result[0];
        int y1 = result[1];
        int gcd = result[2];

        int x = y1;
        int y = x1 - (a / b) * y1;

        return new int[]{x, y, gcd};
    }



}