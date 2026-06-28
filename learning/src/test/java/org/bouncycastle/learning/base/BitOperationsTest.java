package org.bouncycastle.learning.base;

import org.junit.Test;

public class BitOperationsTest {

    @Test
    public void test() {
        int a = 0b1100; // 12
        int b = 0b1010; // 10

        System.out.println("AND  : " + (a & b));   // 1000 = 8
        System.out.println("OR   : " + (a | b));   // 1110 = 14
        System.out.println("XOR  : " + (a ^ b));   // 0110 = 6
        System.out.println("NOT  : " + (~a & 0xF)); // 0011 = 3
        System.out.println("左移 : " + (a << 1));  // 11000 = 24
        System.out.println("右移 : " + (a >> 1));  // 0110 = 6
    }
}