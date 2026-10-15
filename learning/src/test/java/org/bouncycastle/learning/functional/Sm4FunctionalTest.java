package org.bouncycastle.learning.functional;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

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

import static org.bouncycastle.learning.functional.Fp.fold;
import static org.bouncycastle.learning.functional.Fp.foldRange;
import static org.bouncycastle.learning.functional.Fp.rotl;
import static org.bouncycastle.learning.functional.Fp.u32;

/**
 * SM4（GB/T 32907-2016）的本质计算 —— 纯函数版，覆盖全部分组模式与填充模式。
 *
 * <p>本类要说明的"本质"只有三件事：
 * <ol>
 *   <li>SM4 = 32 轮扩散网络的 <b>fold</b>：状态是 {@code long[4]}，轮函数是 {@code 状态 -> 状态}；</li>
 *   <li>模式（ECB/CBC/CTR/OFB/CFB/GCM）与算法无关，它们是把"单块函数"提升为"消息函数"的<b>组合子</b>；</li>
 *   <li>填充（PKCS#7、ISO 10126-2、ISO 7816-4、ANSI X9.23、ZeroByte、TBC、NoPadding）是独立的
 *       {@code byte[] -> byte[]} 函数，与模式正交，所以"模式 × 填充"可以自由组合。</li>
 * </ol>
 * 计算全程不用 Cipher/Engine 对象，BC 只当"第三方裁判"。
 */
@Slf4j
public class Sm4FunctionalTest
{
    private static final int BS = 16;
    private static final BigInteger M32_BIG = BigInteger.valueOf(Fp.M32);

    /** S 盒：SM4 唯一的非线性来源 —— 一张 byte -> byte 的纯函数表，不是对象。 */
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

    // ---------------------------------------------------------------- 核心：纯函数轮

    /** τ：4 次 S 盒查表 —— SM4 唯一的非线性变换。 */
    private static UnaryOperator<Long> tau()
    {
        return a ->
        {
            long v = u32(a);
            return u32(((S_BOX[(int)((v >>> 24) & 0xff)] & 0xffL) << 24)
                | ((S_BOX[(int)((v >>> 16) & 0xff)] & 0xffL) << 16)
                | ((S_BOX[(int)((v >>> 8) & 0xff)] & 0xffL) << 8)
                | (S_BOX[(int)(v & 0xff)] & 0xffL));
        };
    }

    /** L：加密轮的线性扩散（4 次循环移位 + 异或）。 */
    private static UnaryOperator<Long> linearL()
    {
        return b -> u32(b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24));
    }

    /** L'：密钥扩展专用的弱扩散 —— 说明"轮函数"与"扩展函数"的差别只在 L。 */
    private static UnaryOperator<Long> linearLPrime()
    {
        return b -> u32(b ^ rotl(b, 13) ^ rotl(b, 23));
    }

    /** T = L ∘ τ，T' = L' ∘ τ：函数复合就是轮函数的全部本质。 */
    private static UnaryOperator<Long> compositeT()
    {
        return b -> linearL().apply(tau().apply(b));
    }

    private static UnaryOperator<Long> compositeTPrime()
    {
        return b -> linearLPrime().apply(tau().apply(b));
    }

    /** CK_i 的第 j 个字节 = (4i + j) * 7 mod 256 —— 用公式而不是查表。 */
    private static long ck(int i)
    {
        return foldRange(0, 4, 0L, (acc, j) -> u32((acc << 8) | (long)(((4 * i + j) * 7) & 0xff)));
    }

    /** 密钥扩展：K_0..3 = MK ⊕ FK，然后一条递推式折叠 32 次得到 rk[0..31]。 */
    private static Function<byte[], long[]> expandKey()
    {
        return key ->
        {
            long[] mk = Fp.words32(key);
            long[] seed = IntStream.range(0, 4).mapToLong(i -> u32(mk[i] ^ FK[i])).toArray();
            long[] k = foldRange(4, 36, Arrays.copyOf(seed, 36), (arr, j) -> Fp.replace(arr, j,
                u32(arr[j - 4] ^ compositeTPrime().apply(u32(arr[j - 3] ^ arr[j - 2] ^ arr[j - 1] ^ ck(j - 4))))));
            return IntStream.range(0, 32).mapToLong(j -> u32(k[j + 4])).toArray();
        };
    }

    /**
     * 单块函数：{@code byte[16] -> byte[16]}。
     * 解密 = 同一张网络 + 轮密钥反序，这就是"SM4 加解密结构相同"的本质。
     */
    private static UnaryOperator<byte[]> sm4Block(byte[] key, boolean forEncryption)
    {
        final long[] rk = expandKey().apply(key);
        final long[] roundKeys = forEncryption ? rk
            : IntStream.range(0, 32).mapToLong(i -> rk[31 - i]).toArray();
        return block ->
        {
            long[] x = Fp.words32(block);
            long[] after = foldRange(0, 32, x, (s, i) -> new long[]{
                s[1], s[2], s[3],
                u32(s[0] ^ compositeT().apply(u32(s[1] ^ s[2] ^ s[3] ^ roundKeys[i])))
            });
            return Fp.bytes32(new long[]{ after[3], after[2], after[1], after[0] });
        };
    }

    /** 自复合：把 f 迭代 n 次 —— fold 而不是递归，避免 100 万层栈。 */
    private static byte[] iterate(int times, UnaryOperator<byte[]> f, byte[] data)
    {
        return foldRange(0, times, data, (acc, i) -> f.apply(acc));
    }

    // ---------------------------------------------------------------- 模式：块函数的组合子

    /** ECB：{@code map blockFn}。一句话讲完，也一句话讲完它为什么不安全。 */
    private static Function<byte[], Function<byte[], byte[]>> ecb(UnaryOperator<byte[]> blockFn)
    {
        return iv -> data -> fold(Fp.chunks(data, BS), new byte[0],
            (acc, blk) -> Fp.concat(acc, blockFn.apply(blk)));
    }

    /** CBC：链式 fold —— 状态 = (上一块密文, 已输出)。 */
    private static Function<byte[], Function<byte[], byte[]>> cbcEncrypt(UnaryOperator<byte[]> enc)
    {
        return iv -> data -> fold(Fp.chunks(data, BS), new byte[][]{ iv, new byte[0] },
            (acc, p) ->
            {
                byte[] c = enc.apply(Fp.xor(p, acc[0]));
                return new byte[][]{ c, Fp.concat(acc[1], c) };
            })[1];
    }

    private static Function<byte[], Function<byte[], byte[]>> cbcDecrypt(UnaryOperator<byte[]> dec)
    {
        return iv -> data -> fold(Fp.chunks(data, BS), new byte[][]{ iv, new byte[0] },
            (acc, c) ->
            {
                byte[] p = Fp.xor(dec.apply(c), acc[0]);
                return new byte[][]{ c, Fp.concat(acc[1], p) };
            })[1];
    }

    /** CTR：计数器 -> 密钥流 -> 异或。加密与解密是同一个函数（对称性）。 */
    private static Function<byte[], Function<byte[], byte[]>> ctr(UnaryOperator<byte[]> enc)
    {
        return counterBlock -> data ->
        {
            List<byte[]> parts = Fp.chunks(data, BS);
            BigInteger base = Fp.toBigInt(counterBlock);
            return foldRange(0, parts.size(), new byte[0], (acc, i) ->
                Fp.concat(acc, Fp.xor(parts.get(i), enc.apply(Fp.toBytes(base.add(BigInteger.valueOf(i)), BS)))));
        };
    }

    /** OFB：密钥流只依赖 IV，与明文无关 —— 状态是"上一块密钥流"。 */
    private static Function<byte[], Function<byte[], byte[]>> ofb(UnaryOperator<byte[]> enc)
    {
        return iv -> data ->
        {
            List<byte[]> parts = Fp.chunks(data, BS);
            return foldRange(0, parts.size(), new byte[][]{ iv, new byte[0] }, (acc, i) ->
            {
                byte[] s = enc.apply(acc[0]);
                return new byte[][]{ s, Fp.concat(acc[1], Fp.xor(parts.get(i), s)) };
            })[1];
        };
    }

    /** CFB：输出反馈，但状态换成"上一块密文" —— 与 OFB 的唯一区别就在这里。 */
    private static Function<byte[], Function<byte[], byte[]>> cfbEncrypt(UnaryOperator<byte[]> enc)
    {
        return iv -> data ->
        {
            List<byte[]> parts = Fp.chunks(data, BS);
            return foldRange(0, parts.size(), new byte[][]{ iv, new byte[0] }, (acc, i) ->
            {
                byte[] c = Fp.xor(enc.apply(acc[0]), parts.get(i));
                return new byte[][]{ Arrays.copyOf(c, BS), Fp.concat(acc[1], c) };
            })[1];
        };
    }

    private static Function<byte[], Function<byte[], byte[]>> cfbDecrypt(UnaryOperator<byte[]> enc)
    {
        return iv -> data ->
        {
            List<byte[]> parts = Fp.chunks(data, BS);
            return foldRange(0, parts.size(), new byte[][]{ iv, new byte[0] }, (acc, i) ->
            {
                byte[] p = Fp.xor(enc.apply(acc[0]), parts.get(i));
                return new byte[][]{ Arrays.copyOf(parts.get(i), BS), Fp.concat(acc[1], p) };
            })[1];
        };
    }

    // ---------------------------------------------------------------- GCM：CTR ∘ GHASH

    /** GF(2^128) 乘法：逐比特"条件异或 + 右移 + 约减 R=0xe1…"，GHASH 唯一的数学内容。 */
    private static BiFunction<byte[], byte[], byte[]> galoisMultiply()
    {
        final byte[] r = Fp.concat(new byte[]{ (byte)0xe1 }, Fp.repeatedByte(0, 15));
        return (x, y) -> foldRange(0, 128, new byte[][]{ new byte[BS], y }, (acc, i) ->
        {
            byte[] z = acc[0];
            byte[] v = acc[1];
            if (((x[i / 8] >>> (7 - (i % 8))) & 1) == 1)
            {
                z = Fp.xor(z, v);
            }
            boolean lsb = (v[15] & 1) != 0;
            byte[] shifted = new byte[BS];
            shifted[0] = (byte)((v[0] & 0xff) >>> 1);
            for (int b = 1; b < BS; b++)
            {
                shifted[b] = (byte)(((v[b] & 0xff) >>> 1) | ((v[b - 1] & 1) << 7));
            }
            return new byte[][]{ z, lsb ? Fp.xor(shifted, r) : shifted };
        })[0];
    }

    /** GHASH = fold(acc ⊕ block, H) 走完 (AAD‖0-pad, C‖0-pad, 长度块)。 */
    private static Function<byte[], Function<byte[][], byte[]>> gHash()
    {
        UnaryOperator<byte[]> padTo16 = b -> b.length % BS == 0 ? b
            : Fp.concat(b, Fp.repeatedByte(0, BS - b.length % BS));
        return h -> aadAndData ->
        {
            byte[] aad = aadAndData[0];
            byte[] data = aadAndData[1];
            List<byte[]> blocks = Fp.chunks(padTo16.apply(aad), BS);
            blocks.addAll(Fp.chunks(padTo16.apply(data), BS));
            blocks.add(Fp.concat(
                Fp.toBytes(BigInteger.valueOf(8L * aad.length), 8),
                Fp.toBytes(BigInteger.valueOf(8L * data.length), 8)));
            return fold(blocks, new byte[BS], (acc, blk) -> galoisMultiply().apply(Fp.xor(acc, blk), h));
        };
    }

    /** GCM 的计数器只加最后 32 位（inc32），这是它与普通 CTR 的唯一不同。 */
    private static UnaryOperator<byte[]> inc32()
    {
        return b -> Fp.concat(Arrays.copyOf(b, 12), Fp.toBytes(
            Fp.toBigInt(Arrays.copyOfRange(b, 12, 16)).add(BigInteger.ONE).and(M32_BIG), 4));
    }

    /** GCM 加密：{@code 明文 -> 密文‖tag}，nonce/aad 预先柯里化。 */
    private static Function<byte[], byte[]> gcmEncrypt(UnaryOperator<byte[]> enc, byte[] nonce, byte[] aad, int tagBits)
    {
        final byte[] h = enc.apply(new byte[BS]);
        final byte[] j0 = nonce.length == 12
            ? Fp.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash().apply(h).apply(new byte[][]{ nonce, new byte[0] });
        return data ->
        {
            byte[] ct = ctr(enc).apply(inc32().apply(j0)).apply(data);
            byte[] tag = Fp.xor(gHash().apply(h).apply(new byte[][]{ aad, ct }), enc.apply(j0));
            return Fp.concat(ct, Arrays.copyOf(tag, tagBits / 8));
        };
    }

    /** GCM 解密：按定义重算 tag 并比较，不一致即"被篡改"；随后用同一个 CTR 还原明文。 */
    private static Function<byte[], byte[]> gcmDecrypt(UnaryOperator<byte[]> enc, byte[] nonce, byte[] aad, int tagBits)
    {
        final byte[] h = enc.apply(new byte[BS]);
        final byte[] j0 = nonce.length == 12
            ? Fp.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash().apply(h).apply(new byte[][]{ nonce, new byte[0] });
        final int tagLen = tagBits / 8;
        return ctAndTag ->
        {
            byte[] ct = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - tagLen);
            byte[] givenTag = Arrays.copyOfRange(ctAndTag, ctAndTag.length - tagLen, ctAndTag.length);
            byte[] expected = Fp.xor(gHash().apply(h).apply(new byte[][]{ aad, ct }), enc.apply(j0));
            Assert.assertArrayEquals("GCM tag 校验失败：数据被篡改",
                givenTag, Arrays.copyOf(expected, tagLen));
            return ctr(enc).apply(inc32().apply(j0)).apply(ct);
        };
    }

    // ---------------------------------------------------------------- 填充：与模式正交的纯函数

    /**
     * PKCS#7：补 n 个值为 n 的字节（n = 需要补的长度，已对齐时补一整块）。
     * JCE 里 PKCS5Padding 对 16 字节块就是它的别名。
     */
    private static Function<Integer, UnaryOperator<byte[]>> pkcs7()
    {
        return bs -> data ->
        {
            int n = bs - data.length % bs;
            return Fp.concat(data, Fp.repeatedByte(n, n));
        };
    }

    private static Function<byte[], byte[]> pkcs7Unpad()
    {
        return padded ->
        {
            int n = padded[padded.length - 1] & 0xff;
            Assert.assertTrue("PKCS#7 填充长度非法", n >= 1 && n <= padded.length);
            for (int i = padded.length - n; i < padded.length; i++)
            {
                Assert.assertEquals("PKCS#7 的每个填充字节都必须等于 n", (byte)n, padded[i]);
            }
            return Arrays.copyOf(padded, padded.length - n);
        };
    }

    /** ISO 7816-4：先打一个 0x80 标记，其余补 0。 */
    private static Function<Integer, UnaryOperator<byte[]>> iso7816d4()
    {
        return bs -> data ->
        {
            int n = bs - data.length % bs;
            return Fp.concat(data, new byte[]{ (byte)0x80 }, Fp.repeatedByte(0, n - 1));
        };
    }

    private static Function<byte[], byte[]> iso7816d4Unpad()
    {
        return padded ->
        {
            int i = padded.length - 1;
            while (i >= 0 && padded[i] == 0)
            {
                i--;
            }
            Assert.assertEquals("ISO 7816-4 的填充必须以 0x80 收尾", (byte)0x80, padded[i]);
            return Arrays.copyOf(padded, i);
        };
    }

    /** ANSI X9.23：中间补 0，最后一字节是长度。 */
    private static Function<Integer, UnaryOperator<byte[]>> ansiX923()
    {
        return bs -> data ->
        {
            int n = bs - data.length % bs;
            return Fp.concat(data, Fp.repeatedByte(0, n - 1), new byte[]{ (byte)n });
        };
    }

    private static Function<byte[], byte[]> ansiX923Unpad()
    {
        return padded -> Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ISO 10126-2：中间补随机字节 —— 结构与 X9.23 相同，只是内容不可预测。 */
    private static Function<Integer, UnaryOperator<byte[]>> iso10126d2()
    {
        return bs -> data ->
        {
            int n = bs - data.length % bs;
            byte[] random = new byte[n - 1];
            new java.security.SecureRandom().nextBytes(random);
            return Fp.concat(data, random, new byte[]{ (byte)n });
        };
    }

    private static Function<byte[], byte[]> iso10126d2Unpad()
    {
        return padded -> Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ZeroByte：全补 0（对齐时 BC 仍补一整块），因此不可逆 —— 尾部真实 0 会被吃掉。 */
    private static Function<Integer, UnaryOperator<byte[]>> zeroByte()
    {
        return bs -> data -> Fp.concat(data, Fp.repeatedByte(0, bs - data.length % bs));
    }

    private static Function<byte[], byte[]> zeroByteUnpad()
    {
        return padded ->
        {
            int i = padded.length;
            while (i > 0 && padded[i - 1] == 0)
            {
                i--;
            }
            return Arrays.copyOf(padded, i);
        };
    }

    /** TBC：用"最后一个明文字节的奇偶性的反面"填满整块（奇 -> 0x00，偶 -> 0xFF）。 */
    private static Function<Integer, UnaryOperator<byte[]>> tbc()
    {
        return bs -> data ->
        {
            int n = bs - data.length % bs;
            int last = data.length == 0 ? 0 : data[data.length - 1] & 0xff;
            return Fp.concat(data, Fp.repeatedByte((last & 1) == 0 ? 0xff : 0x00, n));
        };
    }

    /** NoPadding：本质是一个谓词 + identity。 */
    private static Predicate<byte[]> blockAligned(int bs)
    {
        return data -> data.length % bs == 0;
    }

    // ---------------------------------------------------------------- 测试

    /** 标准向量 + 密钥扩展 + S 盒双射性 + 与 BC SM4Engine 对照。 */
    @Test
    public void sm4CoreIsAThirtyTwoStepFold()
    {
        Fp.useBc();
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] pt = Fp.unhex("0123456789abcdeffedcba9876543210");

        long[] rk = expandKey().apply(key);
        log.info("[SM4-本质] rk[0]=0x{} rk[1]=0x{} rk[31]=0x{}",
            String.format("%08x", rk[0]), String.format("%08x", rk[1]), String.format("%08x", rk[31]));
        Assert.assertEquals(0xf12186f9L, rk[0]);

        byte[] ct = sm4Block(key, true).apply(pt);
        log.info("[SM4-本质] GB/T 32907 单块加密 = {}", Fp.hex(ct));
        Assert.assertEquals("681edf34d206965e86b3e94f536e4246", Fp.hex(ct));
        Assert.assertArrayEquals("解密必须是加密的逆", pt, sm4Block(key, false).apply(ct));

        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        byte[] ref = new byte[BS];
        engine.processBlock(pt, 0, ref, 0);
        Assert.assertArrayEquals("与 BC SM4Engine 不一致", ref, ct);

        long distinct = IntStream.range(0, 256).map(i -> S_BOX[i] & 0xff).distinct().count();
        Assert.assertEquals("S 盒必须是 256 元双射（否则不可逆）", 256, distinct);
    }

    /** GB/T 32907 的 100 万次迭代测试：纯函数的自复合。 */
    @Test
    public void oneMillionIterationsIsSelfComposition()
    {
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] data = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] result = iterate(1_000_000, sm4Block(key, true), data);
        log.info("[SM4-本质] 迭代 100 万次 = {}", Fp.hex(result));
        Assert.assertEquals("595298c7c6fd271f0402f804c33d3f66", Fp.hex(result));
    }

    /** ECB / CBC：组合子的输出必须与 BC 的 JCE 流水线逐字节相同。 */
    @Test
    public void blockModesAreCombinatorsOverTheBlockFunction()
        throws Exception
    {
        Fp.useBc();
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Fp.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = Fp.concat(Fp.repeatedByte(0xaa, BS), Fp.repeatedByte(0xbb, BS), Fp.repeatedByte(0xcc, BS));   // 3 个整块
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");

        // ECB 的本质缺陷：把"相同的明文块对"塞进去，密文块也必然相同
        byte[] repetitive = Fp.concat(Fp.repeatedByte(0x41, BS), Fp.repeatedByte(0x41, BS));
        byte[] ecbLeaky = ecb(sm4Block(key, true)).apply(iv).apply(repetitive);
        Assert.assertTrue("ECB：相同明文块 -> 相同密文块（模式没有链，这就是它不安全的原因）",
            Arrays.equals(Arrays.copyOfRange(ecbLeaky, 0, BS), Arrays.copyOfRange(ecbLeaky, BS, 2 * BS)));

        byte[] ecbOurs = ecb(sm4Block(key, true)).apply(iv).apply(pt);
        Cipher c = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks);
        Assert.assertArrayEquals("ECB 与 BC 不一致", c.doFinal(pt), ecbOurs);
        log.info("[SM4-模式] ECB={}", Fp.hex(ecbOurs));

        byte[] cbcOurs = cbcEncrypt(sm4Block(key, true)).apply(iv).apply(pt);
        c = Cipher.getInstance("SM4/CBC/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        byte[] cbcRef = c.doFinal(pt);
        log.info("[SM4-模式] CBC={}", Fp.hex(cbcOurs));
        Assert.assertArrayEquals("CBC 与 BC 不一致", cbcRef, cbcOurs);
        Assert.assertArrayEquals("CBC 解密必须还原明文", pt,
            cbcDecrypt(sm4Block(key, false)).apply(iv).apply(cbcOurs));
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("BC 的 CBC 解密 == 我们的 cbcDecrypt", pt, c.doFinal(cbcRef));

        // CBC 的"链"性：IV 是链条的第一环，加密侧改一个 bit 会传播到每一块密文
        byte[] iv2 = iv.clone();
        iv2[0] ^= 1;
        byte[] cbcOurs2 = cbcEncrypt(sm4Block(key, true)).apply(iv2).apply(pt);
        Assert.assertFalse("改 IV 必须改变密文", Arrays.equals(cbcOurs, cbcOurs2));
        Assert.assertFalse("加密方向的差异会沿链接传播，后续块也全变",
            Arrays.equals(Arrays.copyOfRange(cbcOurs, BS, 2 * BS), Arrays.copyOfRange(cbcOurs2, BS, 2 * BS)));

        // 解密方向：CBC 对 IV 的依赖只是"第一块上的一个可控异或差分"，其余块与 IV 无关
        // （这正是 CBC 没有完整性的原因 —— 攻击者可以精确翻转明文的任意比特）
        byte[] wrongIv = cbcDecrypt(sm4Block(key, false)).apply(iv2).apply(cbcOurs);
        Assert.assertArrayEquals("用错 IV 只让第一块按 (IV ^ IV') 翻转",
            Fp.xor(Arrays.copyOfRange(pt, 0, BS), Fp.xor(iv, iv2)), Arrays.copyOfRange(wrongIv, 0, BS));
        Assert.assertArrayEquals("其余明文块完全不受 IV 影响",
            Arrays.copyOfRange(pt, BS, pt.length), Arrays.copyOfRange(wrongIv, BS, wrongIv.length));
    }

    /** CTR / OFB / CFB：三种"块函数 -> 流函数"的方式，区别只在反馈来源。 */
    @Test
    public void streamLikeModesDifferOnlyInFeedbackSource()
        throws Exception
    {
        Fp.useBc();
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Fp.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = "0123456789abcdef-1234-5678".getBytes("UTF-8");   // 24 字节：最后一块不完整
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        UnaryOperator<byte[]> enc = sm4Block(key, true);

        byte[] ctrOurs = ctr(enc).apply(iv).apply(pt);
        Cipher c = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CTR 与 BC 不一致", c.doFinal(pt), ctrOurs);
        Assert.assertArrayEquals("CTR 的解密就是再加密一次（对称性）", pt, ctr(enc).apply(iv).apply(ctrOurs));

        byte[] ofbOurs = ofb(enc).apply(iv).apply(pt);
        c = Cipher.getInstance("SM4/OFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("OFB 与 BC 不一致", c.doFinal(pt), ofbOurs);
        Assert.assertArrayEquals("OFB 解密 == 加密（密钥流与明文无关）", pt, ofb(enc).apply(iv).apply(ofbOurs));

        byte[] cfbOurs = cfbEncrypt(enc).apply(iv).apply(pt);
        c = Cipher.getInstance("SM4/CFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CFB 与 BC 不一致", c.doFinal(pt), cfbOurs);
        Assert.assertArrayEquals("CFB 解密用密文做反馈", pt, cfbDecrypt(enc).apply(iv).apply(cfbOurs));

        Assert.assertNotEquals("OFB 与 CFB 只差在反馈来源，密文必须不同", Fp.hex(ofbOurs), Fp.hex(cfbOurs));
        log.info("[SM4-模式] CTR={} OFB={} CFB={}", Fp.hex(ctrOurs), Fp.hex(ofbOurs), Fp.hex(cfbOurs));
    }

    /** GCM：CTR + GHASH 的复合，并验证认证性（改一字节必须失败）。 */
    @Test
    public void gcmIsCtrComposedWithGHashOverGf128()
        throws Exception
    {
        Fp.useBc();
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] nonce = Fp.unhex("cafebabefacedbaddecaf888");      // 96-bit：GCM 的原生最优长度
        byte[] aad = "authenticated-but-not-encrypted".getBytes("UTF-8");
        byte[] pt = "GCM gives confidentiality AND integrity at once".getBytes("UTF-8");
        UnaryOperator<byte[]> enc = sm4Block(key, true);

        // GF(2^128) 的基本代数性质：GHASH 的线性性就建立在这上面
        BiFunction<byte[], byte[], byte[]> mul = galoisMultiply();
        byte[] unit = new byte[BS];
        unit[0] = (byte)0x80;                                      // GCM 位序里最高位代表 x^0，即乘法单位元
        byte[] x = Fp.unhex("66108cfd83f1946ecbf7099108f4533c");
        Assert.assertArrayEquals("x * 1 = x", x, mul.apply(x, unit));
        Assert.assertArrayEquals("0 * x = 0", new byte[BS], mul.apply(new byte[BS], x));
        byte[] y = Fp.unhex("f69f24f171d2f8f7e3a6566f70e0be09");
        Assert.assertArrayEquals("GF(2^128) 乘法可交换", mul.apply(x, y), mul.apply(y, x));
        Assert.assertArrayEquals("x*x ⊕ x*x = 0（特征为 2 的域：加法即异或）",
            new byte[BS], Fp.xor(mul.apply(x, x), mul.apply(x, x)));
        log.info("[SM4-GCM] mul(x,y) = {}", Fp.hex(mul.apply(x, y)));

        byte[] ours = gcmEncrypt(enc, nonce, aad, 128).apply(pt);
        Cipher c = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        byte[] ref = c.doFinal(pt);
        log.info("[SM4-GCM] 我们的 ct‖tag = {}", Fp.hex(ours));
        log.info("[SM4-GCM] BC   的 ct‖tag = {}", Fp.hex(ref));
        Assert.assertArrayEquals("GCM 与 BC 不一致", ref, ours);
        Assert.assertArrayEquals(pt, gcmDecrypt(enc, nonce, aad, 128).apply(ours));

        byte[] tampered = ours.clone();
        tampered[0] ^= 1;
        try
        {
            gcmDecrypt(enc, nonce, aad, 128).apply(tampered);
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
        byte[] tagWithOtherAad = gcmEncrypt(enc, nonce, "different-aad".getBytes("UTF-8"), 128).apply(pt);
        Assert.assertNotEquals("AAD 不加密但被认证",
            Fp.hex(Arrays.copyOfRange(ours, ours.length - 16, ours.length)),
            Fp.hex(Arrays.copyOfRange(tagWithOtherAad, tagWithOtherAad.length - 16, tagWithOtherAad.length)));
    }

    /** 全部填充模式：纯函数实现 + BC padding 原语对照 + JCE 端到端对照。 */
    @Test
    public void paddingsAreOrthogonalFunctionsIndependentOfMode()
        throws Exception
    {
        Fp.useBc();
        byte[] key = Fp.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Fp.unhex("00112233445566778899aabbccddeeff");
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        UnaryOperator<byte[]> enc = sm4Block(key, true);
        UnaryOperator<byte[]> dec = sm4Block(key, false);

        for (int len : new int[]{ 0, 1, 15, 16, 17, 31 })
        {
            byte[] pt = Fp.repeatedByte('x', len);

            // ---- PKCS#7（JCE 的 PKCS5Padding 是它的别名）
            byte[] p7 = pkcs7().apply(BS).apply(pt);
            Assert.assertEquals(len + (BS - len % BS), p7.length);
            byte[] ct7 = cbcEncrypt(enc).apply(iv).apply(p7);
            assertMatchesJce("SM4/CBC/PKCS7Padding", ks, iv, pt, ct7);
            assertMatchesJce("SM4/CBC/PKCS5Padding", ks, iv, pt, ct7);
            Assert.assertArrayEquals("PKCS#7 去填充应还原明文", pt,
                pkcs7Unpad().apply(cbcDecrypt(dec).apply(iv).apply(ct7)));

            // ---- ISO 7816-4
            byte[] p8 = iso7816d4().apply(BS).apply(pt);
            Assert.assertEquals("ISO 7816-4 也必须补到整块", 0, p8.length % BS);
            byte[] ct8 = cbcEncrypt(enc).apply(iv).apply(p8);
            assertMatchesJce("SM4/CBC/ISO7816-4PADDING", ks, iv, pt, ct8);
            Assert.assertArrayEquals(pt, iso7816d4Unpad().apply(cbcDecrypt(dec).apply(iv).apply(ct8)));

            // ---- ANSI X9.23：填充体是随机字节，无法逐字节对照，只做互操作校验
            byte[] p9 = ansiX923().apply(BS).apply(pt);
            byte[] ct9 = cbcEncrypt(enc).apply(iv).apply(p9);
            assertJceDecrypts("SM4/CBC/X9.23PADDING", ks, iv, ct9, pt);
            Assert.assertArrayEquals(pt, ansiX923Unpad().apply(cbcDecrypt(dec).apply(iv).apply(ct9)));

            // ---- ZeroByte：有损填充（尾部真实 0 会被当作填充）
            byte[] p0 = zeroByte().apply(BS).apply(pt);
            byte[] ct0 = cbcEncrypt(enc).apply(iv).apply(p0);
            assertMatchesJce("SM4/CBC/ZeroBytePadding", ks, iv, pt, ct0);
            boolean lossless = Arrays.equals(pt, zeroByteUnpad().apply(cbcDecrypt(dec).apply(iv).apply(ct0)));
            log.info("[SM4-填充] len={} ZeroByte 可逆性={}", len, lossless);

            // ---- ISO 10126-2：随机填充，只能验证结构与去填充结果
            byte[] pi = iso10126d2().apply(BS).apply(pt);
            Assert.assertEquals(pt.length + (pi[pi.length - 1] & 0xff), pi.length);
            Assert.assertArrayEquals("ISO 10126-2 去填充", pt, iso10126d2Unpad().apply(pi));

            // ---- NoPadding：只是对齐谓词
            Assert.assertEquals(len % BS == 0, blockAligned(BS).test(pt));
        }

        // 与 BC 的填充原语逐字节对照（addPadding 从 offset 开始写，返回写入的填充字节数）
        assertBcPaddingAgree(new PKCS7Padding(), pkcs7().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ISO7816d4Padding(), iso7816d4().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new X923Padding(), ansiX923().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ZeroBytePadding(), zeroByte().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new ISO10126d2Padding(), iso10126d2().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        assertBcPaddingAgree(new TBCPadding(), tbc().apply(BS).apply(new byte[]{ 1, 2, 3 }), 3);
        log.info("[SM4-填充] 7 种填充全部与 BC 一致：PKCS#7/PKCS#5、ISO 7816-4、X9.23、ISO 10126-2、ZeroByte、TBC、NoPadding");
    }

    // ---------------------------------------------------------------- 裁判辅助

    /** 我们的"填充 + CBC 纯函数复合"必须等于 BC 的"模式+填充流水线"输出。 */
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
        Assert.assertArrayEquals(transformation + "：BC 必须能解出我们纯函数生成的密文", expectedPlain, c.doFinal(ours));
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
        log.info("[SM4-填充] {} pad={}", bcPad.getClass().getSimpleName(), Fp.hex(ourTail));
    }
}
