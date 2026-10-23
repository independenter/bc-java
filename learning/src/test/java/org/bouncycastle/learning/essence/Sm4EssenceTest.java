package org.bouncycastle.learning.essence;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.TBCPadding;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Assert;
import org.junit.Test;

import static org.bouncycastle.learning.essence.Calc.rotl;
import static org.bouncycastle.learning.essence.Calc.u32;

/**
 * SM4（GB/T 32907-2016）的本质计算 —— 面向过程版，覆盖全部分组模式与填充模式。
 *
 * <p>本类要说明的"本质"只有三件事：
 * <ol>
 *   <li>SM4 = 32 轮扩散网络：状态是 {@code long[4]}，轮函数是一个普通静态方法（输入状态、输出新状态），
 *       加密就是用一个 for 循环把轮函数迭代 32 次；</li>
 *   <li>模式（ECB/CBC/CTR/OFB/CFB/GCM）与算法无关，它们只是把"单块加密方法"串成"整条消息"的普通静态方法：
 *       无非是用 for 循环把上一块密文、计数器或密钥流这些局部变量接起来；</li>
 *   <li>填充（PKCS#7、ISO 10126-2、ISO 7816-4、ANSI X9.23、ZeroByte、TBC、NoPadding）是独立的
 *       {@code byte[] -> byte[]} 普通静态方法，与模式互不干涉，所以"模式 × 填充"可以自由搭配。</li>
 * </ol>
 * 计算全程不用 Cipher/Engine 对象，BC 只当"第三方裁判"。
 *
 * <p>风格说明：按用户要求改成<b>面向过程</b> —— 没有 {@code Function}/{@code UnaryOperator}/{@code Predicate}，
 * 没有 lambda，没有 {@code IntStream}，只有普通静态方法、真实参数、{@code for}/{@code while} 和局部变量。
 */
@Slf4j
public class Sm4EssenceTest
{
    private static final int BS = 16;
    private static final BigInteger M32_BIG = BigInteger.valueOf(Calc.M32);

    /** S 盒：SM4 唯一的非线性来源 —— 一张 byte -> byte 的查表，不是对象。 */
    private static final byte[] S_BOX =
    {
        (byte)0xd6, (byte)0x90, (byte)0xe9, (byte)0xfe, (byte)0xcc, (byte)0xe1, (byte)0x3d, (byte)0xb7, (byte)0x16, (byte)0xb6, (byte)0x14, (byte)0xc2, (byte)0x28, (byte)0xfb, (byte)0x2c, (byte)0x05,
        (byte)0x2b, (byte)0x67, (byte)0x9a, (byte)0x76, (byte)0x2a, (byte)0xbe, (byte)0x04, (byte)0xc3, (byte)0xaa, (byte)0x44, (byte)0x13, (byte)0x26, (byte)0x49, (byte)0x86, (byte)0x06, (byte)0x99,
        (byte)0x9c, (byte)0x42, (byte)0x50, (byte)0xf4, (byte)0x91, (byte)0xef, (byte)0x98, (byte)0x7a, (byte)0x33, (byte)0x54, (byte)0x0b, (byte)0x43, (byte)0xed, (byte)0xcf, (byte)0xac, (byte)0x62,
        (byte)0xe4, (byte)0xb3, (byte)0x1c, (byte)0xa9, (byte)0xc9, (byte)0x08, (byte)0xe8, (byte)0x95, (byte)0x80, (byte)0xdf, (byte)0x94, (byte)0xfa, (byte)0x75, (byte)0x8f, (byte)0x3f, (byte)0xa6,
        (byte)0x47, (byte)0x07, (byte)0xa7, (byte)0xfc, (byte)0xf3, (byte)0x73, (byte)0x17, (byte)0xba, (byte)0x83, (byte)0x59, (byte)0x3c, (byte)0x19, (byte)0xe6, (byte)0x85, (byte)0x4f, (byte)0xa8,
        (byte)0x68, (byte)0x6b, (byte)0x81, (byte)0xb2, (byte)0x71, (byte)0x64, (byte)0xda, (byte)0x8b, (byte)0xf8, (byte)0xeb, (byte)0x0f, (byte)0x4b, (byte)0x70, (byte)0x56, (byte)0x9d, (byte)0x35,
        (byte)0x1e, (byte)0x24, (byte)0x0e, (byte)0x5e, (byte)0x63, (byte)0x58, (byte)0xd1, (byte)0xa2, (byte)0x25, (byte)0x22, (byte)0x7c, (byte)0x3b, (byte)0x01, (byte)0x21, (byte)0x78, (byte)0x87,
        (byte)0xd4, (byte)0x00, (byte)0x46, (byte)0x57, (byte)0x9f, (byte)0xd3, (byte)0x27, (byte)0x52, (byte)0x4c, (byte)0x36, (byte)0x02, (byte)0xe7, (byte)0xa0, (byte)0xc4, (byte)0xc8, (byte)0x9e,
        (byte)0xea, (byte)0xbf, (byte)0x8a, (byte)0xd2, (byte)0x40, (byte)0xc7, (byte)0x38, (byte)0xb5, (byte)0xa3, (byte)0xf7, (byte)0xf2, (byte)0xce, (byte)0xf9, (byte)0x61, (byte)0x15, (byte)0xa1,
        (byte)0xe0, (byte)0xae, (byte)0x5d, (byte)0xa4, (byte)0x9b, (byte)0x34, (byte)0x1a, (byte)0x55, (byte)0xad, (byte)0x93, (byte)0x32, (byte)0x30, (byte)0xf5, (byte)0x8c, (byte)0xb1, (byte)0xe3,
        (byte)0x1d, (byte)0xf6, (byte)0xe2, (byte)0x2e, (byte)0x82, (byte)0x66, (byte)0xca, (byte)0x60, (byte)0xc0, (byte)0x29, (byte)0x23, (byte)0xab, (byte)0x0d, (byte)0x53, (byte)0x4e, (byte)0x6f,
        (byte)0xd5, (byte)0xdb, (byte)0x37, (byte)0x45, (byte)0xde, (byte)0xfd, (byte)0x8e, (byte)0x2f, (byte)0x03, (byte)0xff, (byte)0x6a, (byte)0x72, (byte)0x6d, (byte)0x6c, (byte)0x5b, (byte)0x51,
        (byte)0x8d, (byte)0x1b, (byte)0xaf, (byte)0x92, (byte)0xbb, (byte)0xdd, (byte)0xbc, (byte)0x7f, (byte)0x11, (byte)0xd9, (byte)0x5c, (byte)0x41, (byte)0x1f, (byte)0x10, (byte)0x5a, (byte)0xd8,
        (byte)0x0a, (byte)0xc1, (byte)0x31, (byte)0x88, (byte)0xa5, (byte)0xcd, (byte)0x7b, (byte)0xbd, (byte)0x2d, (byte)0x74, (byte)0xd0, (byte)0x12, (byte)0xb8, (byte)0xe5, (byte)0xb4, (byte)0xb0,
        (byte)0x89, (byte)0x69, (byte)0x97, (byte)0x4a, (byte)0x0c, (byte)0x96, (byte)0x77, (byte)0x7e, (byte)0x65, (byte)0xb9, (byte)0xf1, (byte)0x09, (byte)0xc5, (byte)0x6e, (byte)0xc6, (byte)0x84,
        (byte)0x18, (byte)0xf0, (byte)0x7d, (byte)0xec, (byte)0x3a, (byte)0xdc, (byte)0x4d, (byte)0x20, (byte)0x79, (byte)0xee, (byte)0x5f, (byte)0x3e, (byte)0xd7, (byte)0xcb, (byte)0x39, (byte)0x48
    };

    /** FK：把主密钥"搅匀"成密钥扩展的起点。 */
    private static final long[] FK = { 0xa3b1bac6L, 0x56aa3350L, 0x677d9197L, 0xb27022dcL };

    // ---------------------------------------------------------------- 核心：普通静态方法轮函数

    /** τ：4 次 S 盒查表 —— SM4 唯一的非线性变换，一个普通静态方法。 */
    private static long tau(long a)
    {
        long v = u32(a);
        return u32(((S_BOX[(int)((v >>> 24) & 0xff)] & 0xffL) << 24)
            | ((S_BOX[(int)((v >>> 16) & 0xff)] & 0xffL) << 16)
            | ((S_BOX[(int)((v >>> 8) & 0xff)] & 0xffL) << 8)
            | (S_BOX[(int)(v & 0xff)] & 0xffL));
    }

    /** L：加密轮的线性扩散（4 次循环移位 + 异或）。 */
    private static long linearL(long b)
    {
        return u32(b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24));
    }

    /** L'：密钥扩展专用的弱扩散 —— 说明"轮函数"与"扩展函数"的差别只在 L。 */
    private static long linearLPrime(long b)
    {
        return u32(b ^ rotl(b, 13) ^ rotl(b, 23));
    }

    /** T(x) = L(τ(x))：先做非线性替换 τ，再做线性扩散 L，这就是加密轮函数的全部本质。 */
    private static long compositeT(long b)
    {
        return linearL(tau(b));
    }

    /** T'(x) = L'(τ(x))：密钥扩展用的版本，只是把 L 换成弱扩散 L'。 */
    private static long compositeTPrime(long b)
    {
        return linearLPrime(tau(b));
    }

    /** CK_i 的第 j 个字节 = (4i + j) * 7 mod 256 —— 用一个 for 循环按公式拼出，而不是查表。 */
    private static long ck(int i)
    {
        long acc = 0L;
        for (int j = 0; j < 4; j++)
        {
            acc = u32((acc << 8) | (long)(((4 * i + j) * 7) & 0xff));
        }
        return acc;
    }

    /** 密钥扩展：K_0..3 = MK ⊕ FK，然后一条 for 循环按递推式算出 rk[0..31]，全程就地写一个局部数组。 */
    private static long[] expandKey(byte[] key)
    {
        long[] mk = Calc.words32(key);
        long[] k = new long[36];
        for (int i = 0; i < 4; i++)
        {
            k[i] = u32(mk[i] ^ FK[i]);
        }
        for (int j = 4; j < 36; j++)
        {
            k[j] = u32(k[j - 4] ^ compositeTPrime(u32(k[j - 3] ^ k[j - 2] ^ k[j - 1] ^ ck(j - 4))));
        }
        long[] rk = new long[32];
        for (int j = 0; j < 32; j++)
        {
            rk[j] = u32(k[j + 4]);
        }
        return rk;
    }

    /**
     * 轮密钥表：加密用正序 rk[0..31]，解密用反序 rk[31..0]。
     * 解密 = 同一张网络 + 轮密钥反序，这就是"SM4 加解密结构相同"的本质。
     */
    private static long[] keySchedule(byte[] key, boolean forEncryption)
    {
        long[] rk = expandKey(key);
        if (forEncryption)
        {
            return rk;
        }
        long[] reversed = new long[32];
        for (int i = 0; i < 32; i++)
        {
            reversed[i] = rk[31 - i];
        }
        return reversed;
    }

    /**
     * 单块函数：{@code byte[16] -> byte[16]}。传入轮密钥表，32 轮扩散就是一个 for 循环，
     * 状态就地滚动在局部数组 x 上。
     */
    private static byte[] sm4Block(long[] roundKeys, byte[] block)
    {
        long[] x = Calc.words32(block);
        for (int i = 0; i < 32; i++)
        {
            long t = u32(x[0] ^ compositeT(u32(x[1] ^ x[2] ^ x[3] ^ roundKeys[i])));
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = t;
        }
        return Calc.bytes32(new long[]{ x[3], x[2], x[1], x[0] });
    }

    /** 迭代：用一个 for 循环把单块加密重复 times 次（用循环而不是递归，避免深栈）。 */
    private static byte[] iterate(int times, long[] roundKeys, byte[] data)
    {
        byte[] acc = data;
        for (int i = 0; i < times; i++)
        {
            acc = sm4Block(roundKeys, acc);
        }
        return acc;
    }

    // ---------------------------------------------------------------- 模式：把单块方法串成消息方法的普通静态方法

    /** ECB：逐块独立加密（for 循环遍历每个 16 字节块）。一句话讲完，也一句话讲完它为什么不安全。 */
    private static byte[] ecb(long[] roundKeys, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        byte[] out = new byte[0];
        for (int i = 0; i < blocks.size(); i++)
        {
            out = Calc.concat(out, sm4Block(roundKeys, blocks.get(i)));
        }
        return out;
    }

    /** CBC：链式 for 循环 —— 局部变量 prev 记住"上一块密文"，每轮先异或再加密。 */
    private static byte[] cbcEncrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < blocks.size(); i++)
        {
            byte[] c = sm4Block(roundKeys, Calc.xor(blocks.get(i), prev));
            out = Calc.concat(out, c);
            prev = c;
        }
        return out;
    }

    private static byte[] cbcDecrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < blocks.size(); i++)
        {
            byte[] c = blocks.get(i);
            byte[] p = Calc.xor(sm4Block(roundKeys, c), prev);
            out = Calc.concat(out, p);
            prev = c;
        }
        return out;
    }

    /** CTR：计数器 -> 密钥流 -> 异或。加密与解密是同一个方法（对称性）。 */
    private static byte[] ctr(long[] roundKeys, byte[] counterBlock, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        BigInteger base = Calc.toBigInt(counterBlock);
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            byte[] keystream = sm4Block(roundKeys, Calc.toBytes(base.add(BigInteger.valueOf(i)), BS));
            out = Calc.concat(out, Calc.xor(parts.get(i), keystream));
        }
        return out;
    }

    /** OFB：密钥流只依赖 IV，与明文无关 —— 局部变量 s 记住"上一块密钥流"。 */
    private static byte[] ofb(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        byte[] s = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            s = sm4Block(roundKeys, s);
            out = Calc.concat(out, Calc.xor(parts.get(i), s));
        }
        return out;
    }

    /** CFB：输出反馈，但局部变量 prev 换成"上一块密文" —— 与 OFB 的唯一区别就在这里。 */
    private static byte[] cfbEncrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            byte[] c = Calc.xor(sm4Block(roundKeys, prev), parts.get(i));
            out = Calc.concat(out, c);
            prev = Arrays.copyOf(c, BS);
        }
        return out;
    }

    private static byte[] cfbDecrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            byte[] c = parts.get(i);
            byte[] p = Calc.xor(sm4Block(roundKeys, prev), c);
            out = Calc.concat(out, p);
            prev = Arrays.copyOf(c, BS);
        }
        return out;
    }

    // ---------------------------------------------------------------- GCM：CTR 之后再接 GHASH

    /** GF(2^128) 乘法：128 次 for 循环里做"条件异或 + 右移 + 约减 R=0xe1…"，GHASH 唯一的数学内容。 */
    private static byte[] galoisMultiply(byte[] x, byte[] y)
    {
        byte[] r = Calc.concat(new byte[]{ (byte)0xe1 }, Calc.repeatedByte(0, 15));
        byte[] z = new byte[BS];
        byte[] v = y;
        for (int i = 0; i < 128; i++)
        {
            if (((x[i / 8] >>> (7 - (i % 8))) & 1) == 1)
            {
                z = Calc.xor(z, v);
            }
            boolean lsb = (v[15] & 1) != 0;
            byte[] shifted = new byte[BS];
            shifted[0] = (byte)((v[0] & 0xff) >>> 1);
            for (int b = 1; b < BS; b++)
            {
                shifted[b] = (byte)(((v[b] & 0xff) >>> 1) | ((v[b - 1] & 1) << 7));
            }
            v = lsb ? Calc.xor(shifted, r) : shifted;
        }
        return z;
    }

    /** 补零到 16 的整数倍（GHASH 的分块前置）。 */
    private static byte[] padTo16(byte[] b)
    {
        return b.length % BS == 0 ? b
            : Calc.concat(b, Calc.repeatedByte(0, BS - b.length % BS));
    }

    /** GHASH = 一个 for 循环：每读一块就 acc ⊕ block 再乘 H，走完 (AAD‖0-pad, C‖0-pad, 长度块)。 */
    private static byte[] gHash(byte[] h, byte[] aad, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(padTo16(aad), BS);
        blocks.addAll(Calc.chunks(padTo16(data), BS));
        blocks.add(Calc.concat(
            Calc.toBytes(BigInteger.valueOf(8L * aad.length), 8),
            Calc.toBytes(BigInteger.valueOf(8L * data.length), 8)));
        byte[] acc = new byte[BS];
        for (int i = 0; i < blocks.size(); i++)
        {
            acc = galoisMultiply(Calc.xor(acc, blocks.get(i)), h);
        }
        return acc;
    }

    /** GCM 的计数器只加最后 32 位（inc32），这是它与普通 CTR 的唯一不同。 */
    private static byte[] inc32(byte[] b)
    {
        return Calc.concat(Arrays.copyOf(b, 12), Calc.toBytes(
            Calc.toBigInt(Arrays.copyOfRange(b, 12, 16)).add(BigInteger.ONE).and(M32_BIG), 4));
    }

    /** GCM 加密：{@code 明文 -> 密文‖tag}，nonce/aad/tagBits 都作为普通参数传入。 */
    private static byte[] gcmEncrypt(long[] roundKeys, byte[] nonce, byte[] aad, int tagBits, byte[] data)
    {
        byte[] h = sm4Block(roundKeys, new byte[BS]);
        byte[] j0 = nonce.length == 12
            ? Calc.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash(h, nonce, new byte[0]);
        byte[] ct = ctr(roundKeys, inc32(j0), data);
        byte[] tag = Calc.xor(gHash(h, aad, ct), sm4Block(roundKeys, j0));
        return Calc.concat(ct, Arrays.copyOf(tag, tagBits / 8));
    }

    /** GCM 解密：按定义重算 tag 并比较，不一致即"被篡改"；随后用同一个 CTR 还原明文。 */
    private static byte[] gcmDecrypt(long[] roundKeys, byte[] nonce, byte[] aad, int tagBits, byte[] ctAndTag)
    {
        byte[] h = sm4Block(roundKeys, new byte[BS]);
        byte[] j0 = nonce.length == 12
            ? Calc.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash(h, nonce, new byte[0]);
        int tagLen = tagBits / 8;
        byte[] ct = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - tagLen);
        byte[] givenTag = Arrays.copyOfRange(ctAndTag, ctAndTag.length - tagLen, ctAndTag.length);
        byte[] expected = Calc.xor(gHash(h, aad, ct), sm4Block(roundKeys, j0));
        Assert.assertArrayEquals("GCM tag 校验失败：数据被篡改",
            givenTag, Arrays.copyOf(expected, tagLen));
        return ctr(roundKeys, inc32(j0), ct);
    }

    // ---------------------------------------------------------------- 填充：与模式正交的普通静态方法

    /**
     * PKCS#7：补 n 个值为 n 的字节（n = 需要补的长度，已对齐时补一整块）。
     * JCE 里 PKCS5Padding 对 16 字节块就是它的别名。
     */
    private static byte[] pkcs7Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        return Calc.concat(data, Calc.repeatedByte(n, n));
    }

    private static byte[] pkcs7Unpad(byte[] padded)
    {
        int n = padded[padded.length - 1] & 0xff;
        Assert.assertTrue("PKCS#7 填充长度非法", n >= 1 && n <= padded.length);
        for (int i = padded.length - n; i < padded.length; i++)
        {
            Assert.assertEquals("PKCS#7 的每个填充字节都必须等于 n", (byte)n, padded[i]);
        }
        return Arrays.copyOf(padded, padded.length - n);
    }

    /** ISO 7816-4：先打一个 0x80 标记，其余补 0。 */
    private static byte[] iso7816d4Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        return Calc.concat(data, new byte[]{ (byte)0x80 }, Calc.repeatedByte(0, n - 1));
    }

    private static byte[] iso7816d4Unpad(byte[] padded)
    {
        int i = padded.length - 1;
        while (i >= 0 && padded[i] == 0)
        {
            i--;
        }
        Assert.assertEquals("ISO 7816-4 的填充必须以 0x80 收尾", (byte)0x80, padded[i]);
        return Arrays.copyOf(padded, i);
    }

    /** ANSI X9.23：中间补 0，最后一字节是长度。 */
    private static byte[] ansiX923Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        return Calc.concat(data, Calc.repeatedByte(0, n - 1), new byte[]{ (byte)n });
    }

    private static byte[] ansiX923Unpad(byte[] padded)
    {
        return Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ISO 10126-2：中间补随机字节 —— 结构与 X9.23 相同，只是内容不可预测。 */
    private static byte[] iso10126d2Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        byte[] random = new byte[n - 1];
        new java.security.SecureRandom().nextBytes(random);
        return Calc.concat(data, random, new byte[]{ (byte)n });
    }

    private static byte[] iso10126d2Unpad(byte[] padded)
    {
        return Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ZeroByte：全补 0（对齐时 BC 仍补一整块），因此不可逆 —— 尾部真实 0 会被吃掉。 */
    private static byte[] zeroBytePad(int bs, byte[] data)
    {
        return Calc.concat(data, Calc.repeatedByte(0, bs - data.length % bs));
    }

    private static byte[] zeroByteUnpad(byte[] padded)
    {
        int i = padded.length;
        while (i > 0 && padded[i - 1] == 0)
        {
            i--;
        }
        return Arrays.copyOf(padded, i);
    }

    /** TBC：用"最后一个明文字节的奇偶性的反面"填满整块（奇 -> 0x00，偶 -> 0xFF）。 */
    private static byte[] tbcPad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        int last = data.length == 0 ? 0 : data[data.length - 1] & 0xff;
        return Calc.concat(data, Calc.repeatedByte((last & 1) == 0 ? 0xff : 0x00, n));
    }

    /** NoPadding：本质只是一个对齐判断 —— 数据长度必须是块长的整数倍。 */
    private static boolean isBlockAligned(int bs, byte[] data)
    {
        return data.length % bs == 0;
    }

    // ---------------------------------------------------------------- 测试

    /** 标准向量 + 密钥扩展 + S 盒双射性 + 与 BC SM4Engine 对照。 */
    @Test
    public void sm4CoreIsAThirtyTwoStepLoop()
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] pt = Calc.unhex("0123456789abcdeffedcba9876543210");

        long[] rk = expandKey(key);
        log.info("[SM4-本质] rk[0]=0x{} rk[1]=0x{} rk[31]=0x{}",
            String.format("%08x", rk[0]), String.format("%08x", rk[1]), String.format("%08x", rk[31]));
        Assert.assertEquals(0xf12186f9L, rk[0]);

        byte[] ct = sm4Block(rk, pt);
        log.info("[SM4-本质] GB/T 32907 单块加密 = {}", Calc.hex(ct));
        Assert.assertEquals("681edf34d206965e86b3e94f536e4246", Calc.hex(ct));
        Assert.assertArrayEquals("解密必须是加密的逆", pt, sm4Block(keySchedule(key, false), ct));

        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        byte[] ref = new byte[BS];
        engine.processBlock(pt, 0, ref, 0);
        Assert.assertArrayEquals("与 BC SM4Engine 不一致", ref, ct);

        // S 盒是否 256 元双射：用一个布尔表数一遍互不相同的像
        boolean[] seen = new boolean[256];
        int distinct = 0;
        for (int i = 0; i < 256; i++)
        {
            int v = S_BOX[i] & 0xff;
            if (!seen[v])
            {
                seen[v] = true;
                distinct++;
            }
        }
        Assert.assertEquals("S 盒必须是 256 元双射（否则不可逆）", 256, distinct);
    }

    /** GB/T 32907 的 100 万次迭代测试：单块加密的自调用迭代。 */
    @Test
    public void oneMillionIterationsIsSelfComposition()
    {
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] data = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] result = iterate(1_000_000, expandKey(key), data);
        log.info("[SM4-本质] 迭代 100 万次 = {}", Calc.hex(result));
        Assert.assertEquals("595298c7c6fd271f0402f804c33d3f66", Calc.hex(result));
    }

    /** ECB / CBC：手工循环的输出必须与 BC 的 JCE 流水线逐字节相同。 */
    @Test
    public void blockModesAreCombinatorsOverTheBlockFunction()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = Calc.concat(Calc.repeatedByte(0xaa, BS), Calc.repeatedByte(0xbb, BS), Calc.repeatedByte(0xcc, BS));   // 3 个整块
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        long[] encKeys = expandKey(key);
        long[] decKeys = keySchedule(key, false);

        // ECB 的本质缺陷：把"相同的明文块对"塞进去，密文块也必然相同
        byte[] repetitive = Calc.concat(Calc.repeatedByte(0x41, BS), Calc.repeatedByte(0x41, BS));
        byte[] ecbLeaky = ecb(encKeys, repetitive);
        Assert.assertTrue("ECB：相同明文块 -> 相同密文块（模式没有链，这就是它不安全的原因）",
            Arrays.equals(Arrays.copyOfRange(ecbLeaky, 0, BS), Arrays.copyOfRange(ecbLeaky, BS, 2 * BS)));

        byte[] ecbOurs = ecb(encKeys, pt);
        Cipher c = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks);
        Assert.assertArrayEquals("ECB 与 BC 不一致", c.doFinal(pt), ecbOurs);
        log.info("[SM4-模式] ECB={}", Calc.hex(ecbOurs));

        byte[] cbcOurs = cbcEncrypt(encKeys, iv, pt);
        c = Cipher.getInstance("SM4/CBC/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        byte[] cbcRef = c.doFinal(pt);
        log.info("[SM4-模式] CBC={}", Calc.hex(cbcOurs));
        Assert.assertArrayEquals("CBC 与 BC 不一致", cbcRef, cbcOurs);
        Assert.assertArrayEquals("CBC 解密必须还原明文", pt, cbcDecrypt(decKeys, iv, cbcOurs));
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("BC 的 CBC 解密 == 我们的 cbcDecrypt", pt, c.doFinal(cbcRef));

        // CBC 的"链"性：IV 是链条的第一环，加密侧改一个 bit 会传播到每一块密文
        byte[] iv2 = iv.clone();
        iv2[0] ^= 1;
        byte[] cbcOurs2 = cbcEncrypt(encKeys, iv2, pt);
        Assert.assertFalse("改 IV 必须改变密文", Arrays.equals(cbcOurs, cbcOurs2));
        Assert.assertFalse("加密方向的差异会沿链接传播，后续块也全变",
            Arrays.equals(Arrays.copyOfRange(cbcOurs, BS, 2 * BS), Arrays.copyOfRange(cbcOurs2, BS, 2 * BS)));

        // 解密方向：CBC 对 IV 的依赖只是"第一块上的一个可控异或差分"，其余块与 IV 无关
        // （这正是 CBC 没有完整性的原因 —— 攻击者可以精确翻转明文的任意比特）
        byte[] wrongIv = cbcDecrypt(decKeys, iv2, cbcOurs);
        Assert.assertArrayEquals("用错 IV 只让第一块按 (IV ^ IV') 翻转",
            Calc.xor(Arrays.copyOfRange(pt, 0, BS), Calc.xor(iv, iv2)), Arrays.copyOfRange(wrongIv, 0, BS));
        Assert.assertArrayEquals("其余明文块完全不受 IV 影响",
            Arrays.copyOfRange(pt, BS, pt.length), Arrays.copyOfRange(wrongIv, BS, wrongIv.length));
    }

    /** CTR / OFB / CFB：三种"块方法 -> 流方法"的写法，区别只在反馈来源。 */
    @Test
    public void streamLikeModesDifferOnlyInFeedbackSource()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = "0123456789abcdef-1234-5678".getBytes("UTF-8");   // 24 字节：最后一块不完整
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        long[] encKeys = expandKey(key);

        byte[] ctrOurs = ctr(encKeys, iv, pt);
        Cipher c = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CTR 与 BC 不一致", c.doFinal(pt), ctrOurs);
        Assert.assertArrayEquals("CTR 的解密就是再加密一次（对称性）", pt, ctr(encKeys, iv, ctrOurs));

        byte[] ofbOurs = ofb(encKeys, iv, pt);
        c = Cipher.getInstance("SM4/OFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("OFB 与 BC 不一致", c.doFinal(pt), ofbOurs);
        Assert.assertArrayEquals("OFB 解密 == 加密（密钥流与明文无关）", pt, ofb(encKeys, iv, ofbOurs));

        byte[] cfbOurs = cfbEncrypt(encKeys, iv, pt);
        c = Cipher.getInstance("SM4/CFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CFB 与 BC 不一致", c.doFinal(pt), cfbOurs);
        Assert.assertArrayEquals("CFB 解密用密文做反馈", pt, cfbDecrypt(encKeys, iv, cfbOurs));

        Assert.assertNotEquals("OFB 与 CFB 只差在反馈来源，密文必须不同", Calc.hex(ofbOurs), Calc.hex(cfbOurs));
        log.info("[SM4-模式] CTR={} OFB={} CFB={}", Calc.hex(ctrOurs), Calc.hex(ofbOurs), Calc.hex(cfbOurs));
    }

    /** GCM：CTR 之后再接 GHASH，并验证认证性（改一字节必须失败）。 */
    @Test
    public void gcmIsCtrComposedWithGHashOverGf128()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] nonce = Calc.unhex("cafebabefacedbaddecaf888");      // 96-bit：GCM 的原生最优长度
        byte[] aad = "authenticated-but-not-encrypted".getBytes("UTF-8");
        byte[] pt = "GCM gives confidentiality AND integrity at once".getBytes("UTF-8");
        long[] encKeys = expandKey(key);

        // GF(2^128) 的基本代数性质：GHASH 的线性性就建立在这上面
        byte[] unit = new byte[BS];
        unit[0] = (byte)0x80;                                      // GCM 位序里最高位代表 x^0，即乘法单位元
        byte[] x = Calc.unhex("66108cfd83f1946ecbf7099108f4533c");
        Assert.assertArrayEquals("x * 1 = x", x, galoisMultiply(x, unit));
        Assert.assertArrayEquals("0 * x = 0", new byte[BS], galoisMultiply(new byte[BS], x));
        byte[] y = Calc.unhex("f69f24f171d2f8f7e3a6566f70e0be09");
        Assert.assertArrayEquals("GF(2^128) 乘法可交换", galoisMultiply(x, y), galoisMultiply(y, x));
        Assert.assertArrayEquals("x*x ⊕ x*x = 0（特征为 2 的域：加法即异或）",
            new byte[BS], Calc.xor(galoisMultiply(x, x), galoisMultiply(x, x)));
        log.info("[SM4-GCM] mul(x,y) = {}", Calc.hex(galoisMultiply(x, y)));

        byte[] ours = gcmEncrypt(encKeys, nonce, aad, 128, pt);
        Cipher c = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        byte[] ref = c.doFinal(pt);
        log.info("[SM4-GCM] 我们的 ct‖tag = {}", Calc.hex(ours));
        log.info("[SM4-GCM] BC   的 ct‖tag = {}", Calc.hex(ref));
        Assert.assertArrayEquals("GCM 与 BC 不一致", ref, ours);
        Assert.assertArrayEquals(pt, gcmDecrypt(encKeys, nonce, aad, 128, ours));

        byte[] tampered = ours.clone();
        tampered[0] ^= 1;
        try
        {
            gcmDecrypt(encKeys, nonce, aad, 128, tampered);
            Assert.fail("被篡改的数据必须导致 tag 校验失败");
        }
        catch (AssertionError expected)
        {
            log.info("[SM4-GCM] 篡改 1 个 bit -> tag 校验失败（这就是认证性）");
        }

        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        try
        {
            c.doFinal(tampered);
            Assert.fail("BC 也应拒绝被篡改的 GCM 密文");
        }
        catch (javax.crypto.AEADBadTagException ok)
        {
            log.info("[SM4-GCM] BC 抛出 AEADBadTagException，与我们的实现行为一致");
        }

        // AAD 也参与认证：改 AAD 必须导致 tag 不同
        byte[] tagWithOtherAad = gcmEncrypt(encKeys, nonce, "different-aad".getBytes("UTF-8"), 128, pt);
        Assert.assertNotEquals("AAD 不加密但被认证",
            Calc.hex(Arrays.copyOfRange(ours, ours.length - 16, ours.length)),
            Calc.hex(Arrays.copyOfRange(tagWithOtherAad, tagWithOtherAad.length - 16, tagWithOtherAad.length)));
    }

    /** 全部填充模式：普通静态方法实现 + BC padding 原语对照 + JCE 端到端对照。 */
    @Test
    public void paddingsAreOrthogonalFunctionsIndependentOfMode()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        long[] encKeys = expandKey(key);
        long[] decKeys = keySchedule(key, false);

        for (int len : new int[]{ 0, 1, 15, 16, 17, 31 })
        {
            byte[] pt = Calc.repeatedByte('x', len);

            // ---- PKCS#7（JCE 的 PKCS5Padding 是它的别名）
            byte[] p7 = pkcs7Pad(BS, pt);
            Assert.assertEquals(len + (BS - len % BS), p7.length);
            byte[] ct7 = cbcEncrypt(encKeys, iv, p7);
            assertMatchesJce("SM4/CBC/PKCS7Padding", ks, iv, pt, ct7);
            assertMatchesJce("SM4/CBC/PKCS5Padding", ks, iv, pt, ct7);
            Assert.assertArrayEquals("PKCS#7 去填充应还原明文", pt,
                pkcs7Unpad(cbcDecrypt(decKeys, iv, ct7)));

            // ---- ISO 7816-4
            byte[] p8 = iso7816d4Pad(BS, pt);
            Assert.assertEquals("ISO 7816-4 也必须补到整块", 0, p8.length % BS);
            byte[] ct8 = cbcEncrypt(encKeys, iv, p8);
            assertMatchesJce("SM4/CBC/ISO7816-4PADDING", ks, iv, pt, ct8);
            Assert.assertArrayEquals(pt, iso7816d4Unpad(cbcDecrypt(decKeys, iv, ct8)));

            // ---- ANSI X9.23：填充体是随机字节，无法逐字节对照，只做互操作校验
            byte[] p9 = ansiX923Pad(BS, pt);
            byte[] ct9 = cbcEncrypt(encKeys, iv, p9);
            assertJceDecrypts("SM4/CBC/X9.23PADDING", ks, iv, ct9, pt);
            Assert.assertArrayEquals(pt, ansiX923Unpad(cbcDecrypt(decKeys, iv, ct9)));

            // ---- ZeroByte：有损填充（尾部真实 0 会被当作填充）
            byte[] p0 = zeroBytePad(BS, pt);
            byte[] ct0 = cbcEncrypt(encKeys, iv, p0);
            assertMatchesJce("SM4/CBC/ZeroBytePadding", ks, iv, pt, ct0);
            boolean lossless = Arrays.equals(pt, zeroByteUnpad(cbcDecrypt(decKeys, iv, ct0)));
            log.info("[SM4-填充] len={} ZeroByte 可逆性={}", len, lossless);

            // ---- ISO 10126-2：随机填充，只能验证结构与去填充结果
            byte[] pi = iso10126d2Pad(BS, pt);
            Assert.assertEquals(pt.length + (pi[pi.length - 1] & 0xff), pi.length);
            Assert.assertArrayEquals("ISO 10126-2 去填充", pt, iso10126d2Unpad(pi));

            // ---- NoPadding：只是一个对齐判断
            Assert.assertEquals(len % BS == 0, isBlockAligned(BS, pt));
        }

        // 与 BC 的填充原语逐字节对照（addPadding 从 offset 开始写，返回写入的填充字节数）
        assertBcPaddingAgree(new PKCS7Padding(), pkcs7Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ISO7816d4Padding(), iso7816d4Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new X923Padding(), ansiX923Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ZeroBytePadding(), zeroBytePad(BS, new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ISO10126d2Padding(), iso10126d2Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new TBCPadding(), tbcPad(BS, new byte[]{ 1, 2, 3 }), 3);
        log.info("[SM4-填充] 7 种填充全部与 BC 一致：PKCS#7/PKCS#5、ISO 7816-4、X9.23、ISO 10126-2、ZeroByte、TBC、NoPadding");
    }

    // ---------------------------------------------------------------- 裁判辅助

    /** 我们的"填充 + CBC 手工实现"必须等于 BC 的"模式+填充流水线"输出。 */
    private static void assertMatchesJce(String transformation, SecretKeySpec ks, byte[] iv,
                                        byte[] plain, byte[] ours)
        throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals(transformation + " 与 BC 不一致", c.doFinal(plain), ours);
    }

    /** X9.23 的填充体由随机数填充（JCE 会给 padding 传 SecureRandom），密文不可逐字节对照，只能验互操作。 */
    private static void assertJceDecrypts(String transformation, SecretKeySpec ks, byte[] iv,
                                          byte[] ours, byte[] expectedPlain)
        throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, "BC");
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals(transformation + "：BC 必须能解出我们手写生成的密文", expectedPlain, c.doFinal(ours));
    }

    private static void assertBcPaddingAgree(BlockCipherPadding bcPad, byte[] oursPadded, int dataLen)
        throws Exception
    {
        // BC 的 X9.23 不 init 时用 0 填充；ISO 10126-2 不 init 直接 NPE —— 它的填充体本来就是随机的
        if (bcPad instanceof ISO10126d2Padding)
        {
            bcPad.init(new java.security.SecureRandom());
        }
        byte[] buf = new byte[BS];
        System.arraycopy(oursPadded, 0, buf, 0, dataLen);
        int written = bcPad.addPadding(buf, dataLen);
        Assert.assertEquals("填充字节数必须一致", oursPadded.length - dataLen, written);
        byte[] bcTail = Arrays.copyOfRange(buf, dataLen, BS);
        byte[] ourTail = Arrays.copyOfRange(oursPadded, dataLen, oursPadded.length);
        // ISO 10126-2 / TBC 的填充内容含随机或固定 0x80/0x00，这里只对照最后一字节（长度字段）
        Assert.assertEquals(bcPad.getClass().getSimpleName() + " 的最后一字节必须一致",
            bcTail[bcTail.length - 1], ourTail[ourTail.length - 1]);
        if (!(bcPad instanceof ISO10126d2Padding))
        {
            Assert.assertArrayEquals(bcPad.getClass().getSimpleName() + " 填充字节必须逐位一致", bcTail, ourTail);
        }
        log.info("[SM4-填充] {} pad={}", bcPad.getClass().getSimpleName(), Calc.hex(ourTail));
    }
}
