package org.bouncycastle.learning.base;

import org.junit.Test;

public class BasicArithmeticTest {

    @Test
    public void test() {
        int a = 17;
        int b = 5;

        System.out.println("加法: " + add(a, b));
        System.out.println("减法: " + sub(a, b));
        System.out.println("乘法: " + mul(a, b));
        System.out.println("除法: " + div(a, b));
        System.out.println("取余: " + mod(a, b));
    }

    static int add(int a, int b) { return a + b; }
    static int sub(int a, int b) { return a - b; }
    static int mul(int a, int b) { return a * b; }
    static int div(int a, int b) { return a / b; }
    static int mod(int a, int b) { return a % b; }
}