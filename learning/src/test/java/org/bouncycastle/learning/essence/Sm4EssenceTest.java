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
import org.bouncycastle.learning.trace.TraceExecution;
import org.bouncycastle.learning.trace.TraceExecutionRule;
import org.bouncycastle.learning.trace.Tracer;
import org.junit.Assert;
import org.junit.Rule;
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
 *
 * <p><b>分组密码 (block cipher) 的基本设定 —— 先搞清楚"我们在算什么"</b>
 * <pre>
 *   分组/块 (block)   明文被切成定长小段，一次只加工一段。SM4 的段长固定 128 bit = 16 字节（本文件的 BS = 16）
 *   字 (word)         段内再切成 4 个 32-bit 字，记作 X₀ X₁ X₂ X₃；大端约定下 X₀ 是最高 32 位 = block[0..3]
 *   明文 P / 密文 C    P (plaintext) 是要保密的原文，C (ciphertext) 是加密的结果；带下标 i 就是"第 i 块"
 *   密钥 (key)        SM4 主密钥也是 128 bit = 4 个字 MK₀..MK₃。密钥与分组同宽不是巧合：
 *                     它保证"密钥的每一分都能作用到整个状态上"，不会出现某半个密钥从头到尾没被用过
 *   轮 (round)        单轮 SM4 只是"查表 + 循环移位异或 + 窗口往前挪一格"的小网络，单轮几乎没有安全性；
 *                     32 轮串联才把安全性攒够 —— "轮数"就是"把一点点扩散叠很多遍"的那个遍数
 *   混淆 (confusion)  让"密文与密钥的关系"变成非线性、看不出代数结构（猜密钥时得不到线性反馈）—— 全 SM4 只有 S 盒 τ 这一处
 *   扩散 (diffusion)  让 1 个输入比特的改动在若干轮后摊到全部 128 个输出比特上 —— 靠 L 的"循环移位后再异或"
 *   雪崩效应 (avalanche) 混淆+扩散做足之后<b>可观察</b>的现象：改 1 bit，输出约有半数 bit 翻转。
 *                     它只是一个经验检验指标（好密码的必要条件），不是安全性证明
 *   流密码 (stream cipher) 把块加密器当"密钥流发生器"，明文逐字节与密钥流异或；不要求长度对齐，所以不需要填充
 * </pre>
 *
 * <p><b>符号表 —— 本文件每条公式里出现的字母/记号</b>
 * <pre>
 *   X₀..X₃        当前分组拆成的 4 个 32-bit 字（大端）；X₀ 是最高 32 位
 *   Xᵢ / i        下标 i 既当"轮序号"（0..31）也当"字序号"；轮递推里本轮新长出的字写作 X_{i+4}
 *   rkᵢ           第 i 轮 (0..31) 的轮密钥 (round key)，32-bit。它是从主密钥派生的中间产物，<b>不是</b>用户密钥本身；
 *                 加密用正序 rk₀..rk₃₁，解密用同一张表倒过来读 rk₃₁..rk₀
 *   MK = (MK₀..MK₃) 用户主密钥 key[0..15] 按大端拆成的 4 个字（Calc.words32(key)）
 *   FK = (FK₀..FK₃) GB/T 32907 给定的 4 个固定常数，官方名叫"系统参数"；密钥扩展的第一步先与它异或
 *   CK₀..CK₃₁     轮常数 (round constant)：CKᵢ 的第 j 个字节 = ((4i + j) · 7) mod 256（本文件按公式现算，见 ck 方法）
 *   Kᵢ            密钥扩展序列：Kᵢ = MKᵢ ⊕ FKᵢ（i 为 0..3）作种子，之后按递推生成；rkᵢ = K_{i+4}
 *   τ             非线性替换层 (S-box layer)：把 32-bit 字的 4 个字节各查一次 S 盒
 *   L             线性扩散函数（加密轮用）：L(B) = B ⊕ (B≪2) ⊕ (B≪10) ⊕ (B≪18) ⊕ (B≪24)
 *   L′            密钥扩展用的弱扩散：L′(B) = B ⊕ (B≪13) ⊕ (B≪23)
 *   T / T′        合成置换 (composite permutation)：T = L∘τ 即 T(x)=L(τ(x))；T′ = L′∘τ。∘ 是"复合/串联"
 *   ⊕             逐比特异或 (XOR)，不是加法
 *   ≪n / rotl     32-bit 循环左移 n 位：整体左移，溢出的高 n 位绕回低 n 位（Calc.rotl）
 *   mod 2³²       只保留低 32 位（代码里的 u32(x)，等价于 &amp; 0xFFFFFFFF）
 *   Pᵢ / Cᵢ       第 i 块明文 / 第 i 块密文（16 字节），工作模式部分全用这两个记号
 *   E_K(·)/D_K(·) 在密钥 K 下做"一次单块加密/单块解密"，本文件即 sm4Block(roundKeys, block)
 *   ksⱼ           第 j 块的密钥流字节块 (keystream) = E_K(计数器值 或 反馈状态)，CTR/OFB/CFB 的核心量
 *   IV            初始化向量 (initial vector)：链条的第一环，16 字节。要随机且不可预测；它不必保密，
 *                 但同一密钥下重复使用同一 IV 会立刻暴露重复结构（ECB 式的病又回来了）
 *   nonce         "只用一次的号码" (number used once)，GCM 专用的 IV；同一密钥下重用 nonce 会彻底摧毁安全性
 *   H             GHASH 的哈希子密钥 = E_K(0¹²⁸)，也就是"把全零块加密一次"
 *   J₀            GCM 的初始计数器块：nonce 为 96 bit 时 J₀ = nonce‖00000001，否则 J₀ = GHASH(nonce)
 *   Tag / tag     GCM 的认证标签 (authentication tag) = GHASH(…) ⊕ E_K(J₀)，截取前 tagBits/8 字节
 *   ‖             字节串拼接 (concat)，例如 ct‖tag；千万别读成异或
 *   GF(2¹²⁸)      128 次二元扩域：元素是 128-bit 位串（看成系数只取 0/1 的多项式），加法就是异或（故 a⊕a=0，称"特征 2"）
 *   R = 0xe1…     GF(2¹²⁸) 的约减常数，对应 GCM 位序下的不可约多项式 x¹²⁸ + x⁷ + x² + x + 1
 *   大端序 (big-endian)  最高位字节放在最小地址（网络字节序）；Calc.words32 / Calc.bytes32 用的就是这个约定
 *   KAT           known-answer test（已知答案测试）：标准里官方给出的 (密钥, 明文) → 密文 样例，
 *                 我们手写实现必须逐字节命中；对不上就说明某处的位序、移位量或下标算错了
 *   AEAD          认证加密 (Authenticated Encryption with Associated Data)：一次同时给机密性 + 完整性，GCM 是一族 AEAD
 *   AAD           只认证、不加密的附加数据 (additional authenticated data)，本文件变量名 aad
 * </pre>
 *
 * <p><b>阅读顺序建议</b>：先看常量表（S_BOX / FK / ck）→ 再看四个纯函数 τ / L / T / T′ →
 * 然后 expandKey（密钥侧）与 sm4Block（数据侧，二者共用同一套 T）→ 最后模式与填充，
 * 它们只是把 sm4Block 这个"单块方法"用 for 循环接起来，符号全是 Pᵢ/Cᵢ/IV/ksⱼ。
 */
@Slf4j
public class Sm4EssenceTest
{
    @Rule
    public TraceExecutionRule traceRule = new TraceExecutionRule();

    /** BS：块长 (block size) = 16 字节 = 128 bit —— SM4 唯一的"分组大小"，所有模式与填充都以它为模数。 */
    private static final int BS = 16;
    /** M32_BIG = 2³²−1 的大数形态（BigInteger 版的 u32）：GCM 的 inc32 加完 1 后要"只留低 32 位"。 */
    private static final BigInteger M32_BIG = BigInteger.valueOf(Calc.M32);

    /** S 盒：SM4 唯一的非线性来源 —— 一张 byte -> byte 的查表，不是对象。
     * <pre>
     *   长什么样  256 个表项：下标是 1 个字节（0..255），值也是 1 个字节。第 0 格是 0xd6，第 255 格是 0x48
     *   本质      它是一个<b>置换 (permutation)</b>：256 个输入各对应唯一输出，且 256 个像互不相同
     *             （下面有一个测试专门用布尔表数一遍），所以查表可逆、解密时不丢信息
     *   记号      就是公式里的 τ（见 {@link #tau}）：一个 32-bit 字的 4 个字节各自进表里换一次
     *   为什么是非线性  表里没有任何代数结构可用，导致 τ(a ⊕ b) ≠ τ(a) ⊕ τ(b)；
     *             攻击者输入差分时，输出差分被彻底打散 —— 这就是"混淆 (confusion)"，
     *             全 SM4 只有这一处非线性，其余全是移位和异或（纯线性），所以 S 盒一坏整个算法就塌
     *   国标来源  GB/T 32907 附录直接给的固定表，与算法结构一起构成"公开设计"（柯克霍夫原则：安全只依赖密钥）
     * </pre>
     */
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

    /** FK：把主密钥"搅匀"成密钥扩展的起点。
     * <pre>
     *   记号  FK = (FK₀, FK₁, FK₂, FK₃)，4 个 32-bit 固定常数（就是下面那四个 0xa3b1bac6… 的十六进制数），
     *         GB/T 32907 直接给定，官方名称叫"系统参数 (system parameter)"，不是随便挑的也不是算出来的
     *   用法  Kᵢ = MKᵢ ⊕ FKᵢ（i = 0..3）—— 主密钥 MK 先与 FK 逐位异或，才作为递推的种子（见 expandKey）
     *   目的1 让"主密钥本身恰好带某种规律"（全 0、重复 4 次、连续递增…）这类弱结构不会原封不动滚进 32 轮
     *   目的2 让 K₀..K₃ 不等于 MK：即使攻击者拿到若干轮密钥，也不会直接读到用户密钥的那 128 bit
     * </pre>
     */
    private static final long[] FK = { 0xa3b1bac6L, 0x56aa3350L, 0x677d9197L, 0xb27022dcL };

    // ---------------------------------------------------------------- 核心：普通静态方法轮函数

    /** τ：4 次 S 盒查表 —— SM4 唯一的非线性变换，一个普通静态方法。
     * <pre>
     *   公式  τ(A) = S[a₀] ‖ S[a₁] ‖ S[a₂] ‖ S[a₃]
     *   符号  A 是输入的 32-bit 字；a₀ 是 A 的最高字节（取法 A >>> 24），a₁ = (A >>> 16) &amp; 0xff，
     *         a₂ = (A >>> 8) &amp; 0xff，a₃ = A &amp; 0xff —— 下标 0..3 按大端"从高位往低位"数；
     *         S[·] 就是 S_BOX 这张 256 项的替换表；‖ 是把 4 个字节重新拼回一个 32-bit 字（代码里用移位 + 或）
     *   关键  只在同一个字<b>内部</b>逐字节替换，字节与字节之间毫不相干 ——
     *         所以 τ 只负责"混淆 (confusion)"，不负责"扩散 (diffusion)"；扩散是 L 的活
     *   Java 细节  byte 是有符号的，所以查表前后都要 &amp; 0xffL 把它当 0..255 的无符号值用
     * </pre>
     */
    private static long tau(long a)
    {
        long v = u32(a);
        // 从高位到低位依次抽出 a₀,a₁,a₂,a₃ 各查一次表，再按原位置拼回去（大端顺序不变）
        return u32(((S_BOX[(int)((v >>> 24) & 0xff)] & 0xffL) << 24)
            | ((S_BOX[(int)((v >>> 16) & 0xff)] & 0xffL) << 16)
            | ((S_BOX[(int)((v >>> 8) & 0xff)] & 0xffL) << 8)
            | (S_BOX[(int)(v & 0xff)] & 0xffL));
    }

    /** L：加密轮的线性扩散（4 次循环移位 + 异或）。
     * <pre>
     *   公式  L(B) = B ⊕ (B≪2) ⊕ (B≪10) ⊕ (B≪18) ⊕ (B≪24)
     *   符号  B 是 τ 的输出字（32-bit）；"≪n" 表示循环左移 n 位（Calc.rotl）：整体左移，
     *         溢出的高 n 位绕回低 n 位，不丢位；⊕ 是逐比特异或
     *   逐项解释  B≪2 / B≪10 / B≪18 / B≪24 是同一个字的 4 份"错位副本"；
     *             把 5 份（含原地的 B）异或起来，B 的每个比特就被复制进了 5 个互不相同的位置
     *   为什么移位量是 2,10,18,24  前三个刚好相差 8（跨一个字节槽），24 再把另一半位错开，
     *             使 5 份副本落在互相对不齐的位置上、同一个输出位能收集到来自不同输入位的贡献；
     *             这组数是国标给定的设计选择（同时照顾软件实现），不是我们凑出来的
     *   与"扩散"的关系  一次 L 就把 1 bit 的差分散布到整个 32-bit 字；再配合轮间的 4 字移位寄存器
     *             （每轮只有 1 个新字进窗口），32 轮后任意 1 bit 的改动都能影响到整块 128 bit —— 这就是雪崩效应
     *   为什么留一个"原地的 B"  这 5 项异或成一个<b>线性</b>映射，且国标这组移位量让它恰好是双射（可逆）；
     *             有原地那份，B 的信息不会被丢掉 —— 不过本文件的解密并不显式求 L⁻¹，而是靠"轮密钥逆序"整轮退回
     * </pre>
     */
    private static long linearL(long b)
    {
        return u32(b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24));
    }

    /** L'：密钥扩展专用的弱扩散 —— 说明"轮函数"与"扩展函数"的差别只在 L。
     * <pre>
     *   公式  L′(B) = B ⊕ (B≪13) ⊕ (B≪23)
     *   符号  与 L 完全同一个记号：B 是 32-bit 字，≪n 是循环左移，⊕ 是异或；只是移位量换成 13 与 23，项数从 5 变 3
     *   为什么可以"弱"一点  L′ 作用在密钥扩展里，产出的是轮密钥而不是密文；轮密钥的安全性是靠
     *             "它被 32 轮的 T 反复使用"来保证的，不必自己扛差分攻击 —— 于是用更便宜的扩散换速度
     *   一句话  加密轮与扩展轮的<b>全部</b>差别只有这一个线性函数，τ 是共用的
     * </pre>
     */
    private static long linearLPrime(long b)
    {
        return u32(b ^ rotl(b, 13) ^ rotl(b, 23));
    }

    /** T(x) = L(τ(x))：先做非线性替换 τ，再做线性扩散 L，这就是加密轮函数的全部本质。
     * <pre>
     *   记号  T 叫"合成置换 (composite permutation)"，写作 T = L∘τ；∘ 是函数复合，读作"先 τ 后 L"
     *   顺序不能反  τ 先把差分打乱（混淆），L 再把打乱的结果摊到整个字（扩散）；
     *             若先扩散再混淆，差分特征可以成块穿过 L 而不被破坏，密码强度会大幅下降
     *   在轮里怎么用  X_{i+4} = Xᵢ ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rkᵢ)（见 sm4Block）
     * </pre>
     */
    private static long compositeT(long b)
    {
        return linearL(tau(b));
    }

    /** T'(x) = L'(τ(x))：密钥扩展用的版本，只是把 L 换成弱扩散 L'。
     * <pre>
     *   记号  T′ = L′∘τ；输入 x 是"三个字异或上轮常数 CKᵢ 之后的那个 32-bit 字"
     *   用途  只出现在密钥扩展递推 K_{i+4} = Kᵢ ⊕ T′(K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CKᵢ) 里
     * </pre>
     */
    private static long compositeTPrime(long b)
    {
        return linearLPrime(tau(b));
    }

    /** CK_i 的第 j 个字节 = (4i + j) * 7 mod 256 —— 用一个 for 循环按公式拼出，而不是查表。
     * <pre>
     *   公式  CKᵢ 的第 j 个字节 = ((4i + j) · 7) mod 256，其中 i = 0..31 是轮常数序号，j = 0..3 是字内字节序号
     *   符号  4i + j 把"第 i 号的第 j 字节"排成一条全局序号 0..127（CK 一共有 32 个字 × 4 字节 = 128 个字节）；
     *         "· 7" 是普通整数乘法，mod 256 就是只留这一字节能装下的低 8 位（等价于 &amp; 0xff）
     *   为什么用 7  7 与 256 互质（在 mod 256 下有乘法逆元），所以 0..127 这 128 个互不相同的序号乘 7 再 mod 256
     *         得到的像也两两不相同 —— 一串看着没规律、却能一行公式复现的常数
     *   作用  CKᵢ 是"轮常数 (round constant)"：它让 32 次递推各不相同，挡住"每轮只差一个固定量"
     *         导致的滑行攻击 (slide attack) 与不动点/周期过短的问题
     *   结论  国标附录里那张 CK 表就是这条公式的展开结果，所以"按公式现算"与"查表"逐字节相同（测试里可验证）
     *   代码  acc = (acc 左移 8 位) | 本字节（这里是<b>普通左移</b>，低位补 0，不是循环左移 rotl）——
     *         一个 for 循环把 4 个字节从高位往低位拼成一个 32-bit 字，正是大端约定
     * </pre>
     */
    private static long ck(int i)
    {
        long acc = 0L;
        for (int j = 0; j < 4; j++)
        {
            acc = u32((acc << 8) | (long)(((4 * i + j) * 7) & 0xff));
        }
        return acc;
    }

    /** 密钥扩展：K_0..3 = MK ⊕ FK，然后一条 for 循环按递推式算出 rk[0..31]，全程就地写一个局部数组。
     * <pre>
     *   输入  key = 128-bit 用户主密钥；MK = Calc.words32(key) = (MK₀, MK₁, MK₂, MK₃)，4 个大端 32-bit 字
     *   种子  Kᵢ = MKᵢ ⊕ FKᵢ                        （i = 0..3，FK 见上面的常量表）
     *   递推  K_{i+4} = Kᵢ ⊕ T′( K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CKᵢ )   （i = 0..27，共 28 步）
     *   输出  rkᵢ = K_{i+4}                         （i = 0..31）
     *   符号  T′ = L′∘τ 是密钥扩展用的合成置换（弱扩散那一版）；CKᵢ 是第 i 个轮常数；⊕ 是异或；
     *         i 是"轮序号"，与数据面 sm4Block 里的 i 是同一个含义、同一套写法
     *   读法  数组 k 的长度是 36 = 4 个种子 + 32 个产物，所以"第 j 个元素"与"第 j−4 轮"差一个固定偏移：
     *         代码里循环变量 j 从 4 数到 35，它对应的公式下标是 i = j − 4；k[j-4]..k[j-1] 就是 Kᵢ..K_{i+3}
     *   本质  一条"非线性反馈移位寄存器"：4 个字的窗口，每步把窗口里 3 个字与本轮常数搅一次再喂回窗口；
     *         数据面（sm4Block）用的是结构完全一样的另一条递推，只是把 T′ 换成 T、把 CKᵢ 换成 rkᵢ
     * </pre>
     */
    private static long[] expandKey(byte[] key)
    {
        long[] mk = Calc.words32(key);
        // k[0..3] 是种子 Kᵢ = MKᵢ ⊕ FKᵢ；k[4..35] 依次放 rk₀..rk₃₁
        long[] k = new long[36];
        for (int i = 0; i < 4; i++)
        {
            k[i] = u32(mk[i] ^ FK[i]);
        }
        // j = i + 4：这一行写的就是递推式 K_{i+4} = Kᵢ ⊕ T′(K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CKᵢ)
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
     * <pre>
     *   加密轮密钥序列  rk₀, rk₁, rk₂, …, rk₃₁（expandKey 数组的正序读法）
     *   解密轮密钥序列  rk₃₁, rk₃₀, rk₂₉, …, rk₀（同一张表倒过来读，代码里 reversed[i] = rk[31 − i]）
     *   为什么只倒顺序就够（推导）：一轮写的是 X_{i+4} = Xᵢ ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rkᵢ)。
     *     把它移项：Xᵢ = X_{i+4} ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rkᵢ) —— 因为 ⊕ 自己就是自己的逆
     *     （a ⊕ b ⊕ b = a），式子形状一模一样；而从解密方向看，X_{i+1}、X_{i+2}、X_{i+3} 都比 Xᵢ 先算出来，
     *     所以"逆着跑同一张网络"时 T 的输入永远是已知的。整张网络唯一带方向的量就是每轮喂进去的 rkᵢ，
     *     把它的顺序倒过来，就得到逆变换 —— 因此本文件不需要写 τ⁻¹（查逆表）也不需要写 L⁻¹（解线性方程组）。
     *   工程意义  加密器与解密器共用同一份代码/同一套硬件电路，只是密钥排布不同，这是很多分组密码的通用做法
     * </pre>
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
     * <pre>
     *   轮函数（国标原式）  X_{i+4} = Xᵢ ⊕ T( X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rkᵢ )，i = 0..31
     *   符号逐个说明：
     *     X₀..X₃    进轮的 4 个 32-bit 字 = Calc.words32(block)，大端：X₀ = block[0..3]（最高 32 位）
     *     i          轮序号 0..31；rkᵢ = roundKeys[i] 是第 i 轮密钥（expandKey 的产物，32-bit）
     *     ⊕          逐比特异或：X_{i+1}、X_{i+2}、X_{i+3} 三个字先异或成"一个"字，再与 rkᵢ 异或，
     *                合起来就是 T 的那唯一一个 32-bit 输入
     *     T          合成置换 T = L∘τ：先 4 次 S 盒查表（混淆），再 4 次循环左移异或（扩散）
     *     X_{i+4}    本轮新长出来的那个字，就是代码里的局部变量 t
     *   滑动窗口  算出 X_{i+4} 后把窗口整体前进一格（x[0]=x[1]; x[1]=x[2]; x[2]=x[3]; x[3]=t）。
     *           所谓 32 个字 X₄..X₃₅ 从来不需要真的存下来，只有这 4 格寄存器在滚 —— 这就是"迭代密码"的结构
     *   为什么用 for 不用递归  轮数是固定 32，循环变量 i 就是"第几轮"，深度恒定、栈不会爆
     *   最后为什么要反序 return (X₃,X₂,X₁,X₀)  国标叫"反序置换 R (reverse permutation)"：
     *           它只是把 4 个字倒过来输出，不承担安全性；有了它，"解密 = 同一张网络 + 轮密钥逆序"才严丝合缝
     *   混淆/扩散在这一轮里各出现在哪  异或 rkᵢ 与 τ 提供混淆；τ 之后的 L 与 4 字窗口共同提供扩散
     * </pre>
     */
    private static byte[] sm4Block(long[] roundKeys, byte[] block)
    {
        long[] x = Calc.words32(block);
        for (int i = 0; i < 32; i++)
        {
            // t 就是公式里的 X_{i+4}；括号里那三个字的异或再异或 rkᵢ，正是 T 的输入
            long t = u32(x[0] ^ compositeT(u32(x[1] ^ x[2] ^ x[3] ^ roundKeys[i])));
            // 窗口往前滑一格：本轮的 X_{i+1}..X_{i+3} 变成下一轮的 Xᵢ..X_{i+2}，新字 t 落在最后一格
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = t;
        }
        // 反序输出 R：国标要求把 4 个字倒过来再拼成 16 字节（Calc.bytes32 按大端展开）
        return Calc.bytes32(new long[]{ x[3], x[2], x[1], x[0] });
    }

    /** 迭代：用一个 for 循环把单块加密重复 times 次（用循环而不是递归，避免深栈）。
     * <pre>
     *   记号  iterate(times, rk, X) = E_rk 自复合 times 次，即 E∘E∘…∘E(X)（times 个 E）；acc 是滚动结果
     *   用途  GB/T 32907 的"100 万次迭代"KAT 就是这里的 times = 1_000_000，标准给定官方答案
     *   注意  这是<b>同一个置换的反复自复合</b>，跟 CBC 那种"链式模式"无关（模式在下面的方法里）
     * </pre>
     */
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

    /** ECB：逐块独立加密（for 循环遍历每个 16 字节块）。一句话讲完，也一句话讲完它为什么不安全。
     * <pre>
     *   公式  Cᵢ = E_K(Pᵢ)，i = 0..n−1 —— 没有链、没有 IV，块与块之间互不影响
     *   符号  Pᵢ 第 i 块明文（16 字节），Cᵢ 第 i 块密文，E_K(·) 就是一次 sm4Block，n = 块数
     *   缺陷1 相同明文块 ⇒ 相同密文块（Pᵢ = Pⱼ 则 Cᵢ = Cⱼ）：明文的重复结构被原样抄进密文，
     *         连"哪两块一样"这种信息都漏出去（下面的测试现场复现）
     *   缺陷2 对完整性毫无保护：攻击者可以整块地删除、调换、复制密文块，接收方察觉不到
     *   缺陷3 同一条消息在两个位置重复出现，密文也重复 —— 因为式子里除了 Pᵢ 别的东西都没有
     *   填充  ECB 一样要求长度是 16 的整数倍（式子里根本没有"短块"的位置），
     *         所以它必须配填充，或用密文窃取 CTS (ciphertext stealing) 借前一密文块的空位塞尾块
     * </pre>
     */
    private static byte[] ecb(long[] roundKeys, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        byte[] out = new byte[0];
        // 每块只依赖它自己：这一行完全没用到"上一块"的任何东西，所以每块的密文内容与前后块无关 —— 这就是"没有链"
        for (int i = 0; i < blocks.size(); i++)
        {
            out = Calc.concat(out, sm4Block(roundKeys, blocks.get(i)));
        }
        return out;
    }

    /** CBC：链式 for 循环 —— 局部变量 prev 记住"上一块密文"，每轮先异或再加密。
     * <pre>
     *   公式  C₀ = E_K(P₀ ⊕ IV)；Cᵢ = E_K(Pᵢ ⊕ C_{i−1})，i 从 1 到 n−1（统一写法：令 C_{−1} = IV）
     *   符号  IV = 初始化向量 (initial vector)，链条的第一环，16 字节随机数，要随机且不可预测但不必保密；
     *         Pᵢ/Cᵢ = 第 i 块明文/密文；E_K(·) = sm4Block(roundKeys, ·)；⊕ = 逐比特异或；
     *         局部变量 prev 就是公式里的 C_{i−1}（第一圈它是 IV）
     *   为什么比 ECB 安全  每块的输入都被"上一块密文"搅过一遍，于是 Pᵢ = Pⱼ 也不再给出 Cᵢ = Cⱼ ——
     *         块加密器自带的扩散被<b>跨过了块边界</b>继续延伸；同一明文重复出现两次，密文看起来完全不同
     *   必须填充  式子要求 Pᵢ 是完整 16 字节（异或是按字节做的，短一块就没法对齐），
     *             所以 CBC 一定要配填充（本文件的 PKCS#7 等都是给它配的）；
     *             不想加长度就用密文窃取 CTS (ciphertext stealing)：借前一个密文块腾出的空位把尾块塞进去，
     *             代价是至少要有两块密文、实现更绕
     *   串行代价  加密<b>不能</b>并行：第 i 块要等第 i−1 块的 C 出来才能算（式子里有 C_{i−1}）；
     *             解密反而可以并行，见 {@link #cbcDecrypt}
     * </pre>
     */
    private static byte[] cbcEncrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        // prev 就是公式里的 C_{i−1}（上一块密文）；第一圈它是 IV，等价于约定 C_{−1} = IV
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < blocks.size(); i++)
        {
            // 先异或上一块密文（或 IV），再整体过一次单块加密器：Cᵢ = E_K(Pᵢ ⊕ C_{i−1})
            byte[] c = sm4Block(roundKeys, Calc.xor(blocks.get(i), prev));
            out = Calc.concat(out, c);
            prev = c;
        }
        return out;
    }

    /**
     * CBC 解密：逆着链条，把密文块过一次"逆置换"再异或回上一块密文。
     * <pre>
     *   公式  P₀ = D_K(C₀) ⊕ IV；Pᵢ = D_K(Cᵢ) ⊕ C_{i−1}（同样令 C_{−1} = IV）
     *   符号  D_K(·) 就是"用逆序轮密钥跑同一个 sm4Block"（见 keySchedule(key, false)）；
     *         注意式子里直接用的是<b>密文</b> C_{i−1}，它不需要先被解开 —— 异或那一头本来就是明文侧的
     *   推论 1（解密可并行）  每个 Pᵢ 只依赖已经收到的 Cᵢ 与 C_{i−1}，块与块之间没有"等待"关系，
     *             所以解密能同时开工（加密不能，这是 CBC 最有名的不对称）
     *   推论 2（错误传播）  密文里坏 1 bit：对应明文块的那 1 bit 错，且<b>下一块</b>整块被带坏
     *             （因为它异或的 prev 是错的）；再往后又自动恢复正常
     *   推论 3（没有完整性）  改 IV 只污染 P₀，改 Cᵢ 只污染 Pᵢ/P_{i+1} —— 攻击者能<b>精确翻转</b>明文的指定位
     *             而接收方无从发现；这正是"CBC 只提供机密性、不提供认证"的原因，要认证得靠 GCM 这类 AEAD
     * </pre>
     */
    private static byte[] cbcDecrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> blocks = Calc.chunks(data, BS);
        // prev 仍是"上一块密文 C_{i−1}"，第一圈取 IV：Pᵢ = D_K(Cᵢ) ⊕ C_{i−1}
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < blocks.size(); i++)
        {
            byte[] c = blocks.get(i);
            // 先做单块解密 D_K(Cᵢ)（逆序轮密钥跑同一张网络），再异或上一块密文，异或两次即还原
            byte[] p = Calc.xor(sm4Block(roundKeys, c), prev);
            out = Calc.concat(out, p);
            prev = c;
        }
        return out;
    }

    /** CTR：计数器 -> 密钥流 -> 异或。加密与解密是同一个方法（对称性）。
     * <pre>
     *   公式  ksᵢ = E_K(ctr₀ + i)；Cᵢ = Pᵢ ⊕ ksᵢ；解密 Pᵢ = Cᵢ ⊕ ksᵢ —— 两行长得一样，所以是<b>同一个方法</b>
     *   符号  ctr₀ = 初始计数器块，本文件把传入的 counterBlock（模式测试里就是 IV）按<b>大端</b>读成
     *         128-bit 整数 base（Calc.toBigInt）；i 是块序号 0..n−1；"+" 是 128-bit 大整数加法；
     *         ksᵢ 是第 i 块的 16 字节密钥流 (keystream)，代码里的局部变量 keystream；
     *         Calc.toBytes(…, BS) 再把计数器值按大端写回 16 字节
     *   本质  块加密器被当成"密钥流发生器 (keystream generator)"用：它加密的是计数器而不是明文，
     *         于是得到一个与明文无关的伪随机字节流，明文只管逐字节异或上去 —— 这就把分组密码变成了<b>流密码</b>
     *   为什么不需要填充  最后一块不足 16 字节时（Calc.chunks 允许尾块短），只取密钥流的前几个字节异或，
     *         多余部分丢掉即可；密文长度 = 明文长度，一个字节都不多
     *   优点  可并行（密钥流只依赖计数器，不依赖前一块的输出）；密文长度不膨胀；错误只坏对应位
     *   风险  同一密钥下计数器值绝不能重复：ctr₀ 重用 ⇒ ksᵢ 完全相同 ⇒
     *         两段密文异或 = 两段明文异或（一次"只有未知数没有密钥"的题），常见字符结构立刻可读
     * </pre>
     */
    private static byte[] ctr(long[] roundKeys, byte[] counterBlock, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        // ctr₀：把 16 字节计数器初值按大端读成一个 128-bit 无符号整数
        BigInteger base = Calc.toBigInt(counterBlock);
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            // ksᵢ = E_K(ctr₀ + i)：加密"计数器值"而不是明文，产出的块就是这一位置的密钥流
            byte[] keystream = sm4Block(roundKeys, Calc.toBytes(base.add(BigInteger.valueOf(i)), BS));
            // Cᵢ = Pᵢ ⊕ ksᵢ（解密方向就是 Pᵢ = Cᵢ ⊕ ksᵢ，同一行代码）
            out = Calc.concat(out, Calc.xor(parts.get(i), keystream));
        }
        return out;
    }

    /** OFB：密钥流只依赖 IV，与明文无关 —— 局部变量 s 记住"上一块密钥流"。
     * <pre>
     *   公式  s₀ = IV；sᵢ = E_K(s_{i−1})；Cᵢ = Pᵢ ⊕ sᵢ（第一块的密钥流是 s₁ = E_K(IV)）
     *   符号  sᵢ 是第 i 块的 16 字节密钥流 (keystream)，代码里就地滚动在局部变量 s 上；
     *         反馈进加密器的是<b>加密器自己的输出</b> —— 这就是 OFB 的名字来源：Output Feedback（输出反馈）
     *   关键点  密钥流里<b>没有出现 P 也没有出现 C</b>：只要 IV 定了，整条密钥流就完全定了，
     *             可以离线预生成；因此加解密共用同一段代码，与 CTR 一样是"自反"的
     *   错误传播  信道把密文某 1 bit 打翻，只有明文那 1 bit 错，密钥流不受污染（因为反馈不经过密文）；
     *             代价是密钥流是固定周期轨道，一旦 IV 重用就与 CTR 重用计数器同样致命
     *   尾块  与 CTR 一样按流取用，不足一块只截密钥流的前几字节 ⇒ <b>不需要填充</b>
     * </pre>
     */
    private static byte[] ofb(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        // s 是"上一块密钥流"，起点是 IV（即 s₀）
        byte[] s = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            // sᵢ = E_K(s_{i−1})：加密器吃自己的输出，与明文/密文无关
            s = sm4Block(roundKeys, s);
            // Cᵢ = Pᵢ ⊕ sᵢ；解密方向同式
            out = Calc.concat(out, Calc.xor(parts.get(i), s));
        }
        return out;
    }

    /** CFB：输出反馈，但局部变量 prev 换成"上一块密文" —— 与 OFB 的唯一区别就在这里。
     * <pre>
     *   公式  Cᵢ = Pᵢ ⊕ E_K(C_{i−1})，约定 C_{−1} = IV
     *   符号  prev 就是"喂回加密器的那 16 字节反馈块"，这里取的是<b>密文</b>（OFB 取的是加密器输出），
     *         名字 CFB = Cipher Feedback（密文反馈）；Arrays.copyOf(c, BS) 只是把 c 归整成 16 字节（尾块短时右侧补 0）
     *   与 OFB 的唯一区别  反馈来源：OFB 反馈"加密器输出 sᵢ"，密钥流与明文无关；CFB 反馈"密文 Cᵢ"，
     *         密钥流被明文带着走 —— 所以两者的密文必然不同（本文件有断言现场对照）
     *   名词对照  OFB = Output Feedback（输出反馈），CFB = Cipher Feedback（密文反馈）；
     *         本方法首句里"输出反馈"指的是"加密器输出被反馈出去"这个共同动作，
     *         真正区分两者的是<b>反馈回去的内容</b>（sᵢ 还是 Cᵢ），别把名字读混
     *   错误传播  密文坏 1 bit：当前明文块只坏那 1 bit，但<b>下一块</b>的密钥流整个错掉（因为它异或的
     *         反馈块是错的），下一块明文全坏，之后再恢复 —— 这是 OFB 没有的扩散性破坏
     *   尾块  与 OFB/CTR 一样按流使用，<b>不需要填充</b>（BC 的 CFB 段长默认等于整块，本文件就是这个配置）
     * </pre>
     */
    private static byte[] cfbEncrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        // prev 是公式里的反馈块 C_{i−1}，第一圈取 IV
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            // Cᵢ = Pᵢ ⊕ E_K(C_{i−1})：加密器的输入是上一块密文，不是计数器、也不是自己的输出
            byte[] c = Calc.xor(sm4Block(roundKeys, prev), parts.get(i));
            out = Calc.concat(out, c);
            prev = Arrays.copyOf(c, BS);
        }
        return out;
    }

    /**
     * CFB 解密：与加密共用密钥流来源 —— 反馈仍然取自<b>密文</b>。
     * <pre>
     *   公式  Pᵢ = Cᵢ ⊕ E_K(C_{i−1})，约定 C_{−1} = IV
     *   为什么解密不需要"逆置换" D_K  异或两头同时消掉密钥流：
     *             Cᵢ ⊕ E_K(C_{i−1}) = (Pᵢ ⊕ E_K(C_{i−1})) ⊕ E_K(C_{i−1}) = Pᵢ；
     *       而密钥流的输入是密文本身（已经收到了），所以整个循环里根本不用解 SM4，只用加密器
     *   并行性  密钥流 E_K(C_{i−1}) 只依赖<b>已收到的密文</b>，所以密文一到就能先算密钥流，
     *             不必等前一块的明文还原出来（这点优于 CBC 的加密方向）
     * </pre>
     */
    private static byte[] cfbDecrypt(long[] roundKeys, byte[] iv, byte[] data)
    {
        List<byte[]> parts = Calc.chunks(data, BS);
        // 这里的 parts 是密文块 Cᵢ；prev 依旧是"上一块密文"，起点为 IV
        byte[] prev = iv;
        byte[] out = new byte[0];
        for (int i = 0; i < parts.size(); i++)
        {
            byte[] c = parts.get(i);
            // Pᵢ = Cᵢ ⊕ E_K(C_{i−1})：与 cfbEncrypt 用的是同一个密钥流，只是异或对象换成了密文
            byte[] p = Calc.xor(sm4Block(roundKeys, prev), c);
            out = Calc.concat(out, p);
            prev = Arrays.copyOf(c, BS);
        }
        return out;
    }

    // ---------------------------------------------------------------- GCM：CTR 之后再接 GHASH

    /** GF(2^128) 乘法：128 次 for 循环里做"条件异或 + 右移 + 约减 R=0xe1…"，GHASH 唯一的数学内容。
     * <pre>
     *   记号  x、y 是两个 128-bit 块（16 字节），被当成二元扩域 GF(2¹²⁸) 里的元素：
     *         一个块 = 一个系数只取 0/1 的 127 次多项式，"1 的位"就是"这一项存在"
     *   GCM 位序（最容易搞错的地方）  byte[0] 的<b>最高位</b>代表 x⁰ 的系数，byte[15] 的最低位代表 x¹²⁷ ——
     *         是"反射/最高位在前"的位序，跟普通大端整数的直觉相反。
     *         所以只有一个字节的 0x80（byte[0] 最高位为 1）代表的多项式就是"1"，即<b>乘法单位元</b>；
     *         下面代码用 (x[i / 8] >>> (7 − i % 8)) &amp; 1 取"第 i 个系数"，就是这个位序的直接翻译
     *   算法（俄罗斯农民乘法 / 逐位累加）  z ← 0；对 i = 0..127 每轮做两件事：
     *         ① 若 x 的第 i 个系数为 1，则 z ← z ⊕ v（把 v 的当前值加进累加器；域里加法=异或）
     *         ② v ← v 右移 1 位；若移出的那一位（v[15] 的最低位，代表 x¹²⁷ 项）是 1，
     *            再异或约减常数 R —— 这就是"多项式乘法超过 x¹²⁷ 后要按模约回去"
     *   R     = 0xe1 ‖ 0¹²⁰（1 字节 + 15 个 0 字节），是 GCM 位序下不可约多项式
     *           x¹²⁸ + x⁷ + x² + x + 1 的 128-bit 表示；0xe1 = 1110 0001b 正好把这 5 项摆进低 8 位
     *   域的性质（测试逐条验证）  加法就是 ⊕，因此 a ⊕ a = 0（称"特征为 2"，减法与加法完全一样）；
     *           乘法可交换、可结合，0 乘任何数是 0，0x80 那个块是乘法单位元 1
     *   为什么 GHASH 只用到它  GHASH 就是在 H 上对密文/AAD 多项式<b>求值</b>，只用加法和乘法，
     *           所以它是<b>线性</b>的 —— 这也解释了为什么 nonce 重用后能像解线性方程组一样把 H 求出来
     * </pre>
     */
    private static byte[] galoisMultiply(byte[] x, byte[] y)
    {
        // R = 0xe1 ‖ 0¹²⁰：约减常数（见上面注释），只在"移出位是 1"时异或进 v
        byte[] r = Calc.concat(new byte[]{ (byte)0xe1 }, Calc.repeatedByte(0, 15));
        byte[] z = new byte[BS];
        byte[] v = y;
        for (int i = 0; i < 128; i++)
        {
            // ① x 的第 i 个系数（byte 序号 i/8，字节内从最高位数起第 i%8 位）为 1 就把 v 累加进 z
            if (((x[i / 8] >>> (7 - (i % 8))) & 1) == 1)
            {
                z = Calc.xor(z, v);
            }
            boolean lsb = (v[15] & 1) != 0;
            // ② 整块右移 1 位：本字节右移一位，再借上前一字节的最低位补到高位（跨字节的"进位链"）
            byte[] shifted = new byte[BS];
            shifted[0] = (byte)((v[0] & 0xff) >>> 1);
            for (int b = 1; b < BS; b++)
            {
                shifted[b] = (byte)(((v[b] & 0xff) >>> 1) | ((v[b - 1] & 1) << 7));
            }
            // 移出的那 1 位代表 x¹²⁸ 项，需要按模约减：异或 R；否则就只是普通右移
            v = lsb ? Calc.xor(shifted, r) : shifted;
        }
        return z;
    }

    /** 补零到 16 的整数倍（GHASH 的分块前置）。
     * <pre>
     *   公式  pad(Y) = Y ‖ 0^k，其中 k = (16 − |Y| mod 16) mod 16，保证补完 |pad(Y)| mod 16 = 0；已对齐时 k = 0
     *   符号  |Y| 是 Y 的字节数；‖ 是拼接；0^k 是 k 个 0x00 字节。这里补的 0 是"GHASH 内部的分块要求"，
     *         与分组密码的填充 (padding) 是<b>两回事</b>：它不改变对外看到的密文长度，也不需要被解出去
     * </pre>
     */
    private static byte[] padTo16(byte[] b)
    {
        return b.length % BS == 0 ? b
            : Calc.concat(b, Calc.repeatedByte(0, BS - b.length % BS));
    }

    /** GHASH = 一个 for 循环：每读一块就 acc ⊕ block 再乘 H，走完 (AAD‖0-pad, C‖0-pad, 长度块)。
     * <pre>
     *   标准写法（多项式求值形式）  Y = Σⱼ Xⱼ · H^{n−j+1}，其中 X₁..X_{n−1} 是输入数据块，Xₙ 是最后的长度块
     *   本文件的等价写法（Horner 秦九韶展开）  acc = 0；对每一块 acc ← (acc ⊕ Xⱼ) 乘 H ——
     *         一行 for 循环就把求值和乘幂全做了，不需要真的去算 H 的各次幂
     *   符号  H = E_K(0¹²⁸) 哈希子密钥（全零块加密一次，见 gcmEncrypt 里第一行）；
     *         Xⱼ 第 j 个 128-bit 输入块；acc 累加器，初值是全 0 块；⊕ 是异或；"乘"就是 galoisMultiply；
     *         块序列 = pad(AAD) 的块 ‖ pad(C) 的块 ‖ 长度块
     *   长度块  len(AAD) 的比特数（64-bit 大端）‖ len(C) 的比特数（64-bit 大端）—— 代码里写 8 · 字节数，
     *         因为 GHASH 要的是"位长度"而不是"字节长度"
     *   为什么必须有长度块  GHASH 是线性函数：没有长度信息时，攻击者可以做"块拼接/截断"式伪造
     *         （多加几个零块或多砍几块，值仍然对得上）。把长度钉进最后一个块，就堵住了这类改写
     *   ‖ 拼接、⊕ 异或，两个符号在同一个式子里同时出现，别读混
     * </pre>
     */
    private static byte[] gHash(byte[] h, byte[] aad, byte[] data)
    {
        // 输入块序列的前两段：先 AAD（补零对齐），再数据（补零对齐）
        List<byte[]> blocks = Calc.chunks(padTo16(aad), BS);
        blocks.addAll(Calc.chunks(padTo16(data), BS));
        // 第三段：长度块 = AAD 比特数（64-bit 大端）‖ 数据比特数（64-bit 大端）；代码里 8 × 字节数 = 位数
        blocks.add(Calc.concat(
            Calc.toBytes(BigInteger.valueOf(8L * aad.length), 8),
            Calc.toBytes(BigInteger.valueOf(8L * data.length), 8)));
        byte[] acc = new byte[BS];
        // acc 是多项式求值的累加器，初值取域里的 0（全 0 块）
        for (int i = 0; i < blocks.size(); i++)
        {
            // Horner 一步：acc ← (acc ⊕ Xⱼ) · H
            acc = galoisMultiply(Calc.xor(acc, blocks.get(i)), h);
        }
        return acc;
    }

    /** GCM 的计数器只加最后 32 位（inc32），这是它与普通 CTR 的唯一不同。
     * <pre>
     *   公式  b' = b[0..11] ‖ ((大端整数 b[12..15] + 1) mod 2³²)
     *   符号  b 是 16 字节的计数器块；前 12 字节（96 bit）原样保留，只有后 4 字节（32 bit）参与 +1；
     *         M32_BIG = 2³²−1 的 BigInteger 形态，与它做一次按位 and 就等于"只留低 32 位"（即 mod 2³² 回绕）
     *   为什么要"只加 32 位"  GCM 把 128-bit 计数器块规定成"nonce(96 bit) ‖ 计数器(32 bit)"，
     *         于是一把消息最多用 2³² 个块，且计数器溢出不会串改 nonce 那半段；
     *         普通 CTR（上面的 ctr 方法）则是整个 128 bit 一起 +1，这是两者唯一的结构差别
     * </pre>
     */
    private static byte[] inc32(byte[] b)
    {
        return Calc.concat(Arrays.copyOf(b, 12), Calc.toBytes(
            Calc.toBigInt(Arrays.copyOfRange(b, 12, 16)).add(BigInteger.ONE).and(M32_BIG), 4));
    }

    /** GCM 加密：{@code 明文 -> 密文‖tag}，nonce/aad/tagBits 都作为普通参数传入。
     * <pre>
     *   流程（逐步对应下面 4 行代码）
     *     H   ← E_K(0¹²⁸)                                        哈希子密钥：把全零块加密一次
     *     J₀  ← nonce ‖ 00000001（nonce 恰为 96 bit 时的原生路径）
     *         或 GHASH(H, nonce, 空)（其它长度：先压成 128 bit）
     *     C   ← P ⊕ 密钥流，密钥流第 i 块 = E_K(inc32 逐次作用在 J₀ 上的计数器)   机密性由这半段给出（就是 {@link #ctr}）
     *     Tag ← GHASH(H, AAD, C) ⊕ E_K(J₀)，再取前 tagBits/8 字节   完整性/认证由这半段给出
     *   符号  nonce = "只用一次的号码" (number used once)，GCM 的 IV；96 bit（12 字节）是原生最优长度，
     *         因为省掉一次 GHASH；aad = 只认证不加密的附加数据；tagBits = 标签比特数（常用 128）；
     *         J₀ 是初始计数器块（注意 ctr 用的是 inc32(J₀)，J₀ 本身只留给算 tag 用）；
     *         ‖ 拼接、⊕ 异或；0¹²⁸ 表示 128 个 0 bit
     *   AEAD  认证加密 (Authenticated Encryption with Associated Data)：一次同时给"别人读不懂"(机密性) 和
     *         "别人改不了、改了一定被发现"(完整性/认证)。AAD 不进密文、只进 GHASH，适合放协议头、长度、
     *         密钥 ID 这类"必须原样但不必保密"的字段
     *   nonce 重用为何致命  同一密钥下 nonce 一重复，J₀ 与整条密钥流都一模一样：
     *         ① 两段密文相减（异或）直接得到两段明文相减 —— CTR 的老毛病；
     *         ② 更糟的是 tag 等式里唯一的未知数 H 变成可解（GHASH 对 H 是线性的），
     *            解出 H 之后攻击者能为<b>任意</b>伪造密文算出正确 tag。这是 GCM 最常见的实战事故
     *   为什么不需要填充  CTR 部分是流密码；GHASH 的补零是内部要求，对外长度不变 —— 密文长度 = 明文长度 + tag 长度
     * </pre>
     */
    private static byte[] gcmEncrypt(long[] roundKeys, byte[] nonce, byte[] aad, int tagBits, byte[] data)
    {
        // H = E_K(0¹²⁸)：GHASH 用的哈希子密钥，它由密钥决定、对每条消息都相同
        byte[] h = sm4Block(roundKeys, new byte[BS]);
        // J₀：96-bit nonce 走"nonce ‖ 00000001"这条捷径（末 4 字节正好是计数器初值 1）；
        //      其它长度必须先 GHASH 一次，把它压成 128 bit
        byte[] j0 = nonce.length == 12
            ? Calc.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash(h, nonce, new byte[0]);
        // 机密性：从 inc32(J₀) 开始的 CTR，密钥流永远不碰 J₀ 那一块（它被留给算 tag）
        byte[] ct = ctr(roundKeys, inc32(j0), data);
        // 认证：tag = GHASH(H, AAD, C) ⊕ E_K(J₀)，最后按 tagBits 截断（128 bit 就取满 16 字节）
        byte[] tag = Calc.xor(gHash(h, aad, ct), sm4Block(roundKeys, j0));
        return Calc.concat(ct, Arrays.copyOf(tag, tagBits / 8));
    }

    /** GCM 解密：按定义重算 tag 并比较，不一致即"被篡改"；随后用同一个 CTR 还原明文。
     * <pre>
     *   流程  重算 H、J₀（与加密侧一模一样，全都不需要 nonce 之外的额外信息）；
     *         把收到的 ct‖tag 按 tagLen = tagBits/8 切成两段；
     *         用收到的 ct 与 aad 重新算一遍 expected = GHASH(H, AAD, ct) ⊕ E_K(J₀)；
     *         逐字节比较（本文件用 assertArrayEquals）；通过了才跑 CTR 出明文
     *   符号  tagLen = tagBits / 8 是标签字节数；givenTag 是"对方声称的 tag"；expected 是"我们重算的 tag"
     *   为什么"先验 tag 再交明文"  认证加密的语义就是：未经认证的明文<b>绝不能</b>交给调用者处理 ——
     *         否则攻击者可以在受害者校验之前先消费被篡改的数据（解密 oracle / 提前反应攻击）
     *   认证性从哪来  tag 里混进了 GHASH(H, AAD, C)，而 GHASH 对 C 与 AAD 都线性、又钉了长度块；
     *         改 1 bit 的 C 或换任何 AAD，expected 都会整个变掉，撞上 tag 的概率约 2^(−tagBits)
     *   对照 BC  BC 抛 AEADBadTagException，我们的实现抛 AssertionError —— 行为等价，只是裁判不同
     * </pre>
     */
    private static byte[] gcmDecrypt(long[] roundKeys, byte[] nonce, byte[] aad, int tagBits, byte[] ctAndTag)
    {
        // 与加密侧完全相同的两步：H = E_K(0¹²⁸)，J₀ = nonce‖00000001 或 GHASH(nonce)
        byte[] h = sm4Block(roundKeys, new byte[BS]);
        byte[] j0 = nonce.length == 12
            ? Calc.concat(nonce, new byte[]{ 0, 0, 0, 1 })
            : gHash(h, nonce, new byte[0]);
        // tagLen = tagBits / 8：标签占的字节数（128 bit 就是 16 字节）
        int tagLen = tagBits / 8;
        // 收到的尾巴是 tag，头上是密文 ct —— GCM 的对外格式固定为 ct ‖ tag（‖ 是拼接）
        byte[] ct = Arrays.copyOfRange(ctAndTag, 0, ctAndTag.length - tagLen);
        byte[] givenTag = Arrays.copyOfRange(ctAndTag, ctAndTag.length - tagLen, ctAndTag.length);
        // expected = GHASH(H, AAD, ct) ⊕ E_K(J₀)：完全按定义重算一遍，不看对方给的 tag
        byte[] expected = Calc.xor(gHash(h, aad, ct), sm4Block(roundKeys, j0));
        Assert.assertArrayEquals("GCM tag 校验失败：数据被篡改",
            givenTag, Arrays.copyOf(expected, tagLen));
        return ctr(roundKeys, inc32(j0), ct);
    }

    // ---------------------------------------------------------------- 填充：与模式正交的普通静态方法

    /**
     * PKCS#7：补 n 个值为 n 的字节（n = 需要补的长度，已对齐时补一整块）。
     * JCE 里 PKCS5Padding 对 16 字节块就是它的别名。
     * <pre>
     *   公式  n = bs − (|data| mod bs)，然后尾部追加 n 个字节，每个字节的<b>值</b>都写成 n
     *   符号  bs = 块长（SM4 是 16）；|data| = data.length 是明文字节数；n 就是"还差几字节才对齐"
     *   n 的取值范围  |data| mod bs 落在 0..bs−1，bs 减它必落在 1..bs —— 所以 n 永远不为 0
     *   为什么最多补 16 字节（一整块）  已经对齐时差值是 0，但公式仍给出 n = bs = 16，即补满一整块（值全 0x10）。
     *         这样才同时满足两件事：① 任何长度补完都是整块；② 去填充结果唯一（否则"对齐不补"会让接收方
     *         分不清"末尾本来就有 16 个数据字节"还是"其实带了 16 字节填充"）
     *   为什么可逆  只读最后一个字节 m，就知道要砍掉末尾 m 个；再校验这 m 个是否都等于 m（见 pkcs7Unpad）
     *   别名关系  PKCS#5 原文只定义在 8 字节块上，把块长换成 16 后行为与 PKCS#7 完全一致，
     *             所以 JCE 里 "SM4/CBC/PKCS5Padding" 与 "PKCS7Padding" 给出同一份密文（测试里两条都断言了）
     * </pre>
     */
    private static byte[] pkcs7Pad(int bs, byte[] data)
    {
        // n = 还差几字节才对齐（1..bs），它同时是"填充的个数"和"每个填充字节的值"
        int n = bs - data.length % bs;
        return Calc.concat(data, Calc.repeatedByte(n, n));
    }

    private static byte[] pkcs7Unpad(byte[] padded)
    {
        // 末尾那个字节的值就是"填充了几个字节"（这就是 PKCS#7 的定义）；0xff 掩码把有符号 byte 读成 0..255
        int n = padded[padded.length - 1] & 0xff;
        // 合法性检查 1：n 至少 1、至多不超过整段长度（否则说明数据被截断或填充是伪造的）
        Assert.assertTrue("PKCS#7 填充长度非法", n >= 1 && n <= padded.length);
        // 合法性检查 2：末尾 n 个字节必须全部等于 n —— 漏掉这条就可能被畸形填充（padding oracle 一类）利用
        for (int i = padded.length - n; i < padded.length; i++)
        {
            Assert.assertEquals("PKCS#7 的每个填充字节都必须等于 n", (byte)n, padded[i]);
        }
        // 还原：把末尾 n 个字节整段丢掉，剩下的就是原始明文（长度可以是 0，对应"空明文补一整块"）
        return Arrays.copyOf(padded, padded.length - n);
    }

    /** ISO 7816-4：先打一个 0x80 标记，其余补 0。
     * <pre>
     *   公式  尾部追加 1 个 0x80，再追加 (n − 1) 个 0x00，其中 n = bs − (|data| mod bs)（与 PKCS#7 同一个 n）
     *   符号  0x80 = 二进制 1000 0000，是"数据与填充的分界标记"；n 为 1 时只补这一个 0x80，没有后面的 0
     *   为什么选 0x80  去填充时从尾往前跳过所有 0，撞到第一个 1 就停 —— 0x80 是唯一"只有最高位为 1"的字节，
     *             所以这条规则能一眼定位分界，不必像 PKCS#7 那样依赖长度字段
     *   局限  明文本身末尾有 0x80 或 0x00 时同样会有歧义（跟 ZeroByte 一样不是完全无损的），
     *             所以它常见于芯片卡/APDU 这类"明文内容由协议保证不以这些字节收尾"的场合
     *   出处  ISO/IEC 7816-4（智能卡命令与响应格式）里定义的 padding，也叫 "pad = 80 00* "
     * </pre>
     */
    private static byte[] iso7816d4Pad(int bs, byte[] data)
    {
        // n 是"总共要补几字节"，其中第 1 字节留给 0x80，剩下 n−1 字节是 0x00
        int n = bs - data.length % bs;
        return Calc.concat(data, new byte[]{ (byte)0x80 }, Calc.repeatedByte(0, n - 1));
    }

    private static byte[] iso7816d4Unpad(byte[] padded)
    {
        // 从最后一个字节起往前跳过所有 0x00（i 逐格后退），停在第一个非 0 字节上
        int i = padded.length - 1;
        while (i >= 0 && padded[i] == 0)
        {
            i--;
        }
        // 停下来的那格必须是分界标记 0x80，否则这份数据的填充不合规
        Assert.assertEquals("ISO 7816-4 的填充必须以 0x80 收尾", (byte)0x80, padded[i]);
        // 明文就是 0x80 之前的全部字节（0x80 本身也丢掉）
        return Arrays.copyOf(padded, i);
    }

    /** ANSI X9.23：中间补 0，最后一字节是长度。
     * <pre>
     *   公式  尾部追加 (n − 1) 个 0x00，最后 1 个字节写 n 本身；n = bs − (|data| mod bs)
     *   符号  末字节就是"长度字段 (length field)"，取值 1..bs；n=1 时没有中间的 0，只有一个 0x01
     *   与 PKCS#7 的区别  只有末字节携带长度，中间全是 0（PKCS#7 是 n 个字节全写 n）。
     *             冗余度更低，但校验也更弱：无法像 PKCS#7 那样"逐个字节都核对一遍 n"
     *   与 ISO 10126-2 的关系  结构完全一样，只是本族的填充体规定为 0，而 10126-2 规定为随机字节
     *   出处  ANSI X9.23（金融报文加密标准）
     * </pre>
     */
    private static byte[] ansiX923Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        return Calc.concat(data, Calc.repeatedByte(0, n - 1), new byte[]{ (byte)n });
    }

    private static byte[] ansiX923Unpad(byte[] padded)
    {
        // 末字节 = 填充个数 n，直接从尾部砍掉 n 字节（0x00 那一段不用管，长度已经写在 n 里了）
        return Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ISO 10126-2：中间补随机字节 —— 结构与 X9.23 相同，只是内容不可预测。
     * <pre>
     *   公式  尾部追加 (n − 1) 个<b>随机</b>字节，最后 1 个字节写 n；n 的定义与前面完全相同
     *   符号  random 是长度 n−1 的随机字节数组，由 SecureRandom（密码学安全随机数发生器）填充；
     *             末字节 (byte)n 是唯一的确定性信息
     *   为什么用随机而不是 0  填充体不携带任何"可预测的模式"，减少给旁路/统计分析留下的抓手
     *   代价  填充体不可复现 ⇒ 同一明文两次加密的密文不同，没法与第三方实现<b>逐字节</b>对照，
     *             只能验"末字节的长度字段"和"解出来的明文"（本文件的测试就是这么做的）
     *   出处  ISO/IEC 10126-2（该标准已被撤回，但工程上仍常见）
     * </pre>
     */
    private static byte[] iso10126d2Pad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        // 中间的 n−1 字节由随机数填满，只有最后一格留给长度字段 n
        byte[] random = new byte[n - 1];
        new java.security.SecureRandom().nextBytes(random);
        return Calc.concat(data, random, new byte[]{ (byte)n });
    }

    private static byte[] iso10126d2Unpad(byte[] padded)
    {
        // 与 X9.23 的去填充完全一样：读末字节 n，砍掉尾部 n 字节（中间是什么随机值都不影响）
        return Arrays.copyOf(padded, padded.length - (padded[padded.length - 1] & 0xff));
    }

    /** ZeroByte：全补 0（对齐时 BC 仍补一整块），因此不可逆 —— 尾部真实 0 会被吃掉。
     * <pre>
     *   公式  尾部追加 (bs − |data| mod bs) 个 0x00；已对齐时 BC 的实现仍补整整 bs 个 0（保证块数一定增加）
     *   有损的原因  填充与"明文本身末尾的 0"长得一模一样，去填充时无法区分，只能一律砍掉 ——
     *             于是明文尾部真实的 0x00 会被当成填充吃掉（这就是"不可逆 / 有损填充"）
     *   什么时候能用  明文保证不以 0 结尾时（文本、ASN.1 之类），或者长度另外在协议里显式给出时
     *   对照  这也是下面的测试只把可逆性<b>打印</b>成一个 lossless 变量、而不断言它一定成立的原因
     * </pre>
     */
    private static byte[] zeroBytePad(int bs, byte[] data)
    {
        return Calc.concat(data, Calc.repeatedByte(0, bs - data.length % bs));
    }

    private static byte[] zeroByteUnpad(byte[] padded)
    {
        // 从尾往前把<b>所有</b> 0 都当作填充丢掉 —— 这个"无法区分"正是上面说的有损性的直接来源
        int i = padded.length;
        while (i > 0 && padded[i - 1] == 0)
        {
            i--;
        }
        return Arrays.copyOf(padded, i);
    }

    /** TBC：用"最后一个明文字节的奇偶性的反面"填满整块（奇 -> 0x00，偶 -> 0xFF）。
     * <pre>
     *   公式  填充字节 f = ((末字节的最低位 = 0) ? 0xFF : 0x00)，共补 n 个 f；n = bs − (|data| mod bs)
     *   符号  TBC = Trailing Bit Complement，"补一个与最后一位相反的位"：只看 data 最后一个字节的
     *             最低位（奇偶性），偶（最低位 0）就整块填 0xFF，奇（最低位 1）就整块填 0x00；
     *             空明文时按"没有末字节"处理，取 last = 0（于是填 0xFF）
     *   为什么这样设计  填充体由"末位取反"唯一决定 ⇒ 只要知道明文末字节就能重算出该填什么，
     *             而且 0xFF/0x00 这两种极端模式在块尾一眼可辨；去填充从尾部往前数"与末字节相同"的字节即是填充
     *             （BC 的 TBCPadding.padCount 正是这么数的，它没有长度字段）
     *   出处  常见于 3GPP/EMV 一类的旧规范；本文件只实现 pad（对照时只比最后一字节）
     * </pre>
     */
    private static byte[] tbcPad(int bs, byte[] data)
    {
        int n = bs - data.length % bs;
        // last = 最后一个明文字节（0..255 无符号读法）；空串时约定为 0
        int last = data.length == 0 ? 0 : data[data.length - 1] & 0xff;
        // (last & 1) 取末位判奇偶：偶 -> 填 0xFF，奇 -> 填 0x00
        return Calc.concat(data, Calc.repeatedByte((last & 1) == 0 ? 0xff : 0x00, n));
    }

    /** NoPadding：本质只是一个对齐判断 —— 数据长度必须是块长的整数倍。
     * <pre>
     *   公式  要求 |data| mod bs == 0；不满足时没有任何"可去掉的痕迹"，只能报错或丢尾
     *   符号  bs 块长（16），|data| 数据字节数；"NoPadding" 的意思不是"补 0 个字节"，而是"根本不补"
     *   适用  长度天然对齐的数据（密钥、分组、计数器），以及 CTR/OFB/CFB/GCM 这些流式用法——
     *             它们压根不要求对齐，所以标准名字才叫 "SM4/CTR/NoPadding" 且完全正常
     * </pre>
     */
    private static boolean isBlockAligned(int bs, byte[] data)
    {
        return data.length % bs == 0;
    }

    // ---------------------------------------------------------------- 测试

    /** 标准向量 + 密钥扩展 + S 盒双射性 + 与 BC SM4Engine 对照。
     * <pre>
     *   什么是 KAT（known-answer test，已知答案测试）  标准文本里官方给定的一组
     *         (密钥, 明文) → (轮密钥, 密文) 答案；我们的手写实现必须<b>逐字节</b>命中它。
     *         命不中不要紧，关键是能立刻告诉你是哪一段错了（扩展 / 轮函数 / 字节序）
     *   本方法用到的官方 KAT（全部来自 GB/T 32907-2016 附录，不是我们自己造的）：
     *     key = pt = 0123456789abcdeffedcba9876543210        128-bit 主密钥 = 128-bit 明文（大端）
     *     rk[0] = 0xf12186f9                                 密钥扩展给出的第一个轮密钥（断言只钉它）
     *     rk[1]、rk[31]                                      只打印出来供肉眼与标准文本核对，不设断言
     *     ct    = 681edf34d206965e86b3e94f536e4246           单块加密的官方密文
     *   为什么要先单独断言 rk[0]  密钥扩展错了后面全错；把"扩展"与"轮函数"两处分开卡住，
     *         一旦失败能马上分辨是 T′/CK/FK 那条链出错，还是 T/L/轮递推那条链出错
     *   断言层次  ①对标准文本（KAT）②对第三方实现（BC 的 SM4Engine）③对自身的代数性质
     *         （解密必须是加密的逆、S 盒必须是 256 元双射）—— 三层互相独立，任何一层单独坏都能被发现
     *   "双射 (bijection)"的意思  256 个输入映到 256 个<b>互不相同</b>的输出，一一对应；
     *         不满足就不可逆，分组密码也就无法解密
     * </pre>
     */
    @TraceExecution(value = "SM4 三十二轮迭代核心", algorithm = "SM4", flow = "SM4-CORE")
    @Test
    public void sm4CoreIsAThirtyTwoStepLoop()
    {
        Calc.useBc();
        // 官方 KAT 的两个输入：128-bit 密钥与 128-bit 明文取成同一个串，纯粹是标准图省事
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] pt = Calc.unhex("0123456789abcdeffedcba9876543210");

        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "key", Calc.hex(key), "plaintext", Calc.hex(pt)
        }, null, "start");

        long[] rk = expandKey(key);
        Tracer.trace("keyExpand", new Object[]{
            "MK", Calc.hex(key), "FK", Calc.hex(FK)
        }, Calc.hex(rk), "keyExpand");
        long[] initX = Calc.words32(pt);
        Tracer.trace("initReg", new Object[]{
            "plaintext", Calc.hex(pt), "X0..X3", Calc.hex(initX)
        }, Calc.hex(initX), "initReg");
        log.info("[SM4-本质] rk[0]=0x{} rk[1]=0x{} rk[31]=0x{}",
            String.format("%08x", rk[0]), String.format("%08x", rk[1]), String.format("%08x", rk[31]));
        // GB/T 32907 给的第一个轮密钥：先把密钥扩展钉死，再谈轮函数
        Assert.assertEquals(0xf12186f9L, rk[0]);

        byte[] ct = sm4Block(rk, pt);
        if (Tracer.isEnabled())
        {
            // 只为追踪重放 32 轮：输入、轮密钥与 sm4Block 完全相同，事件里是真实中间值
            long[] traceX = Calc.words32(pt);
            for (int round = 0; round < 32; round++)
            {
                long[] before = new long[]{ traceX[0], traceX[1], traceX[2], traceX[3] };
                long tInput = u32(traceX[1] ^ traceX[2] ^ traceX[3] ^ rk[round]);
                long tauOut = tau(tInput);
                long linearOut = linearL(tauOut);
                long t = u32(traceX[0] ^ linearOut);
                traceX[0] = traceX[1];
                traceX[1] = traceX[2];
                traceX[2] = traceX[3];
                traceX[3] = t;
                Tracer.traceLoop("round", new Object[]{
                    "round", round, "rk", String.format("0x%08x", rk[round]),
                    "stateBefore", Calc.hex(before)
                }, Calc.hex(traceX), "roundLoop", round + 1, 32, "roundLoop");
                // τ 与 L 每 4 轮采样一次，32 轮的事件总数保持在预算内
                if ((round & 3) == 0)
                {
                    Tracer.trace("tau", new Object[]{
                        "round", round, "T_input", String.format("0x%08x", tInput)
                    }, String.format("0x%08x", tauOut), "sBox");
                    Tracer.trace("linearL", new Object[]{
                        "round", round, "tau", String.format("0x%08x", tauOut)
                    }, String.format("0x%08x", linearOut), "linear");
                }
            }
            Tracer.trace("reverse", new Object[]{
                "X32", String.format("0x%08x", traceX[3]),
                "X33", String.format("0x%08x", traceX[2]),
                "X34", String.format("0x%08x", traceX[1]),
                "X35", String.format("0x%08x", traceX[0])
            }, Calc.hex(ct), "reverse");
        }
        log.info("[SM4-本质] GB/T 32907 单块加密 = {}", Calc.hex(ct));
        // GB/T 32907 官方 KAT 的密文（十六进制字符串就是那 16 字节的大端表示）
        Assert.assertEquals("681edf34d206965e86b3e94f536e4246", Calc.hex(ct));
        // 自洽性检查：解密用的只是"逆序的同一张轮密钥表"（见 keySchedule 的推导）
        Assert.assertArrayEquals("解密必须是加密的逆", pt, sm4Block(keySchedule(key, false), ct));

        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        byte[] ref = new byte[BS];
        engine.processBlock(pt, 0, ref, 0);
        Assert.assertArrayEquals("与 BC SM4Engine 不一致", ref, ct);

        // S 盒是否 256 元双射：用一个布尔表数一遍互不相同的像
        // seen[v] 记录"值 v 有没有出现过"；distinct 统计不同的像的个数。
        // 256 个原像只能有 256 个不同的像才谈得上一一对应（双射，bijection）——少一个就意味着有两格撞车、不可逆
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
        Tracer.trace("end", new Object[]{
            "ciphertext", Calc.hex(ct), "kat", "681edf34d206965e86b3e94f536e4246",
            "sBoxDistinct", distinct
        }, true, "end");
    }

    /** GB/T 32907 的 100 万次迭代测试：单块加密的自调用迭代。
     * <pre>
     *   官方 KAT（GB/T 32907-2016 附录，known-answer test）：
     *     key = pt = 0123456789abcdeffedcba9876543210（大端 16 字节）
     *     E_rk 自复合 10⁶ 次的结果必须是 595298c7c6fd271f0402f804c33d3f66
     *   记号  iterate(1_000_000, rk, X) = E_rk ∘ E_rk ∘ … ∘ E_rk (X)，共 10⁶ 个 E；
     *         每一次的<b>输出</b>就是下一对的<b>输入</b>（密钥 rk 全程不变，轮密钥表只扩展一次）
     *   它在测什么  反复自复合是"扩散是否彻底"的极端体检：单轮只把 1 个新字塞进 4 格窗口，
     *         10⁶ 次后任何残留的固定结构（线性关系、轨道周期过短、某些字节从不变化）都会露馅
     *   注意  这是"同一个置换的自复合"，<b>不是</b> CBC 那种链式模式；与工作模式无关，只验核心算法
     *   为什么值得等这一百万次  它是标准自带的、不用第三方裁判就能核对的最强单点检查之一
     * </pre>
     */
    @TraceExecution(value = "SM4 一百万次自复合", algorithm = "SM4", flow = "SM4-CORE")
    @Test
    public void oneMillionIterationsIsSelfComposition()
    {
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] data = Calc.unhex("0123456789abcdeffedcba9876543210");
        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "iterations", 1_000_000, "key", Calc.hex(key), "data", Calc.hex(data)
        }, null, "start");
        // 轮密钥表在循环外面算一次即可：迭代的是置换 E，而不是每次都重做密钥扩展
        byte[] result = iterate(1_000_000, expandKey(key), data);
        if (Tracer.isEnabled())
        {
            // 只重放前两次与末次的值；100 万次循环本身绝不逐次 trace
            long[] traceKeys = expandKey(key);
            Tracer.trace("keyExpand", new Object[]{
                "MK", Calc.hex(key), "FK", Calc.hex(FK)
            }, Calc.hex(traceKeys), "keyExpand");
            long[] traceX = Calc.words32(data);
            Tracer.trace("initReg", new Object[]{
                "data", Calc.hex(data), "X0..X3", Calc.hex(traceX)
            }, Calc.hex(traceX), "initReg");
            byte[] first = sm4Block(traceKeys, data);
            byte[] second = sm4Block(traceKeys, first);
            Tracer.traceLoop("iterate", new Object[]{
                "iteration", 1, "input", Calc.hex(data)
            }, Calc.hex(first), "roundLoop", 1, 1_000_000, "roundLoop");
            Tracer.traceLoop("iterate", new Object[]{
                "iteration", 2, "input", Calc.hex(first)
            }, Calc.hex(second), "roundLoop", 2, 1_000_000, "roundLoop");
            Tracer.traceLoop("iterate", new Object[]{
                "iteration", 1_000_000, "input", "第 999999 次迭代的输出"
            }, Calc.hex(result), "roundLoop", 1_000_000, 1_000_000, "roundLoop");
            Tracer.traceLoop("iterate.summary", new Object[]{
                "iterations", 1_000_000, "rk0", String.format("0x%08x", traceKeys[0])
            }, Calc.hex(result), "roundLoop", 1_000_000, 1_000_000, "roundLoop");
            Tracer.trace("reverse", new Object[]{
                "result", Calc.hex(result)
            }, Calc.hex(result), "reverse");
        }
        log.info("[SM4-本质] 迭代 100 万次 = {}", Calc.hex(result));
        // GB/T 32907 官方 KAT 的 10⁶ 次迭代答案
        Assert.assertEquals("595298c7c6fd271f0402f804c33d3f66", Calc.hex(result));
        Tracer.trace("end", new Object[]{
            "ciphertext", Calc.hex(result), "iterations", 1_000_000,
            "kat", "595298c7c6fd271f0402f804c33d3f66"
        }, true, "end");
    }

    /** ECB / CBC：手工循环的输出必须与 BC 的 JCE 流水线逐字节相同。
     * <pre>
     *   记号（沿用类头的符号表）  Pᵢ/Cᵢ = 第 i 块明文/密文（各 16 字节）；IV = 初始化向量；
     *         E_K/D_K = 一次单块加密/单块解密（这里就是 sm4Block 配正序/逆序轮密钥表）；⊕ = 异或
     *   本方法里用到的三条公式：
     *         ECB 加密   Cᵢ = E_K(Pᵢ)                       —— 没有链，没有 IV
     *         CBC 加密   Cᵢ = E_K(Pᵢ ⊕ C_{i−1})，C_{−1} = IV
     *         CBC 解密   Pᵢ = D_K(Cᵢ) ⊕ C_{i−1}
     *   数据准备   pt 由三块 0xaa/0xbb/0xcc 组成（3 个整块，长度天然对齐，所以配 NoPadding）；
     *         repetitive 是"两个一模一样的块"，专门用来现场演示 ECB 的泄露
     *   裁判层次   BC 的 JCE 流水线（SM4/ECB/NoPadding、SM4/CBC/NoPadding）是第三方裁判，
     *         逐字节相同才算手写实现与标准实现一致；这属于"互操作对照"，与 KAT 互为补充
     *   最后四段断言在证什么   ①改 IV 会让密文全变（IV 是链条第一环）；
     *         ②加密方向的差异<b>沿链扩散</b>到后续每一块（这就是 CBC 的扩散跨越块边界）；
     *         ③解密方向改 IV 只污染第一块，且污染量精确等于 (IV ⊕ IV′)；
     *         ④其余明文块不受 IV 影响 —— ③④合起来说明"CBC 可被精确翻转比特、没有完整性"
     * </pre>
     */
    @TraceExecution(value = "SM4 ECB/CBC 分组模式", algorithm = "SM4", flow = "SM4-MODES")
    @Test
    public void blockModesAreCombinatorsOverTheBlockFunction()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        // iv 是 CBC 链条的第一环，相当于公式里的 C_{−1}；这里取一个 16 字节的十六进制串充当随机 IV
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = Calc.concat(Calc.repeatedByte(0xaa, BS), Calc.repeatedByte(0xbb, BS), Calc.repeatedByte(0xcc, BS));   // 3 个整块
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        // 加密轮密钥表：rk₀..rk₃₁ 正序
        long[] encKeys = expandKey(key);
        // 解密轮密钥表：同一张表倒过来读，rk₃₁..rk₀
        long[] decKeys = keySchedule(key, false);

        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "modes", "ECB/CBC", "key", Calc.hex(key)
        }, null, "start");
        Tracer.trace("pad", new Object[]{
            "blockSize", BS, "plainBytes", pt.length, "blocks", pt.length / BS, "padding", "NoPadding"
        }, pt.length / BS, "pad");
        Tracer.trace("iv", new Object[]{
            "iv", Calc.hex(iv), "role", "CBC 的 C_{-1}"
        }, Calc.hex(iv), "iv");

        // ECB 的本质缺陷：把"相同的明文块对"塞进去，密文块也必然相同
        byte[] repetitive = Calc.concat(Calc.repeatedByte(0x41, BS), Calc.repeatedByte(0x41, BS));
        byte[] ecbLeaky = ecb(encKeys, repetitive);
        Assert.assertTrue("ECB：相同明文块 -> 相同密文块（模式没有链，这就是它不安全的原因）",
            Arrays.equals(Arrays.copyOfRange(ecbLeaky, 0, BS), Arrays.copyOfRange(ecbLeaky, BS, 2 * BS)));

        if (Tracer.isEnabled())
        {
            List<byte[]> leakyPlain = Calc.chunks(repetitive, BS);
            List<byte[]> leakyCipher = Calc.chunks(ecbLeaky, BS);
            for (int bi = 0; bi < leakyPlain.size(); bi++)
            {
                Tracer.traceLoop("block", new Object[]{
                    "mode", "ECB", "block", bi, "plain", Calc.hex(leakyPlain.get(bi)),
                    "demo", "相同的明文块对"
                }, Calc.hex(leakyCipher.get(bi)), "blockLoop", bi + 1, leakyPlain.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "mode", "ECB", "block", bi, "plain", Calc.hex(leakyPlain.get(bi))
                }, Calc.hex(leakyCipher.get(bi)), "encBlock");
            }
        }

        byte[] ecbOurs = ecb(encKeys, pt);
        if (Tracer.isEnabled())
        {
            List<byte[]> ecbPlain = Calc.chunks(pt, BS);
            List<byte[]> ecbCipher = Calc.chunks(ecbOurs, BS);
            for (int bi = 0; bi < ecbPlain.size(); bi++)
            {
                Tracer.traceLoop("block", new Object[]{
                    "mode", "ECB", "block", bi, "plain", Calc.hex(ecbPlain.get(bi))
                }, Calc.hex(ecbCipher.get(bi)), "blockLoop", bi + 1, ecbPlain.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "mode", "ECB", "block", bi, "plain", Calc.hex(ecbPlain.get(bi))
                }, Calc.hex(ecbCipher.get(bi)), "encBlock");
            }
        }
        Cipher c = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks);
        Assert.assertArrayEquals("ECB 与 BC 不一致", c.doFinal(pt), ecbOurs);
        log.info("[SM4-模式] ECB={}", Calc.hex(ecbOurs));

        byte[] cbcOurs = cbcEncrypt(encKeys, iv, pt);
        if (Tracer.isEnabled())
        {
            List<byte[]> cbcPlain = Calc.chunks(pt, BS);
            List<byte[]> cbcCipher = Calc.chunks(cbcOurs, BS);
            byte[] tracePrev = iv;
            for (int bi = 0; bi < cbcPlain.size(); bi++)
            {
                byte[] traceInput = Calc.xor(cbcPlain.get(bi), tracePrev);
                byte[] traceCipher = cbcCipher.get(bi);
                Tracer.traceLoop("block", new Object[]{
                    "mode", "CBC", "block", bi,
                    "plain", Calc.hex(cbcPlain.get(bi)), "C_{i-1}", Calc.hex(tracePrev)
                }, Calc.hex(traceCipher), "blockLoop", bi + 1, cbcPlain.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "mode", "CBC", "block", bi, "input", Calc.hex(traceInput)
                }, Calc.hex(traceCipher), "encBlock");
                Tracer.trace("xor", new Object[]{
                    "plain", Calc.hex(cbcPlain.get(bi)), "C_{i-1}", Calc.hex(tracePrev)
                }, Calc.hex(traceInput), "xor");
                Tracer.trace("feedback", new Object[]{
                    "C_{i-1}", Calc.hex(tracePrev), "C_i", Calc.hex(traceCipher)
                }, Calc.hex(traceCipher), "feedback");
                tracePrev = traceCipher;
            }
        }
        c = Cipher.getInstance("SM4/CBC/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        byte[] cbcRef = c.doFinal(pt);
        log.info("[SM4-模式] CBC={}", Calc.hex(cbcOurs));
        Tracer.trace("final", new Object[]{
            "ecb", Calc.hex(ecbOurs), "cbc", Calc.hex(cbcOurs), "bytes", cbcOurs.length
        }, cbcOurs.length, "final");
        Assert.assertArrayEquals("CBC 与 BC 不一致", cbcRef, cbcOurs);
        Assert.assertArrayEquals("CBC 解密必须还原明文", pt, cbcDecrypt(decKeys, iv, cbcOurs));
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("BC 的 CBC 解密 == 我们的 cbcDecrypt", pt, c.doFinal(cbcRef));

        // CBC 的"链"性：IV 是链条的第一环，加密侧改一个 bit 会传播到每一块密文
        byte[] iv2 = iv.clone();
        // iv2 与 iv 只差 1 个 bit（这里异或的是 iv2[0] 的最低位），是"C_{−1} 被改动"的最小实验
        iv2[0] ^= 1;
        byte[] cbcOurs2 = cbcEncrypt(encKeys, iv2, pt);
        Assert.assertFalse("改 IV 必须改变密文", Arrays.equals(cbcOurs, cbcOurs2));
        // 断言的是"第 2 块密文（下标 BS..2BS−1）在两种 IV 下不同"：
        // 因为 P₁ 异或的是 C₀，而 C₀ 已经因 IV 变了 —— 差异沿着 C_{i−1} 一路传到最后一块
        Assert.assertFalse("加密方向的差异会沿链接传播，后续块也全变",
            Arrays.equals(Arrays.copyOfRange(cbcOurs, BS, 2 * BS), Arrays.copyOfRange(cbcOurs2, BS, 2 * BS)));

        // 解密方向：CBC 对 IV 的依赖只是"第一块上的一个可控异或差分"，其余块与 IV 无关
        // （这正是 CBC 没有完整性的原因 —— 攻击者可以精确翻转明文的任意比特）
        byte[] wrongIv = cbcDecrypt(decKeys, iv2, cbcOurs);
        // 期望值写成 P₀ ⊕ (IV ⊕ iv2)：把公式 P₀ = D_K(C₀) ⊕ IV 里的 IV 换成 iv2，
        // 与正确明文相差的正好是那个"可控差分" (IV ⊕ iv2) —— 攻击者改几个 bit 就精确改几个 bit
        Assert.assertArrayEquals("用错 IV 只让第一块按 (IV ^ IV') 翻转",
            Calc.xor(Arrays.copyOfRange(pt, 0, BS), Calc.xor(iv, iv2)), Arrays.copyOfRange(wrongIv, 0, BS));
        // 第二块起用的是 C_{i−1}（真实的密文），跟 IV 一个字都没沾上 —— 所以完全不受影响
        Assert.assertArrayEquals("其余明文块完全不受 IV 影响",
            Arrays.copyOfRange(pt, BS, pt.length), Arrays.copyOfRange(wrongIv, BS, wrongIv.length));
        Tracer.traceDecision("compare.ecb", new Object[]{
            "ours", Calc.hex(ecbOurs)
        }, true, "compare", "ECB 输出与 BC SM4/ECB/NoPadding 逐字节一致");
        Tracer.traceDecision("compare.cbc", new Object[]{
            "ours", Calc.hex(cbcOurs), "bc", Calc.hex(cbcRef)
        }, Arrays.equals(cbcRef, cbcOurs), "compare", "CBC 输出与 BC SM4/CBC/NoPadding 逐字节一致");
        Tracer.traceDecision("compare.roundtrip", new Object[]{
            "plaintext", Calc.hex(pt)
        }, Arrays.equals(pt, cbcDecrypt(decKeys, iv, cbcOurs)), "compare", "CBC 解密还原明文");
        Tracer.traceDecision("compare.ivDiffusion", new Object[]{
            "iv", Calc.hex(iv), "iv2", Calc.hex(iv2)
        }, !Arrays.equals(cbcOurs, cbcOurs2), "compare", "改 IV 后全部密文块改变");
        Tracer.trace("end", new Object[]{
            "ecb", Calc.hex(ecbOurs), "cbc", Calc.hex(cbcOurs), "verified", true
        }, true, "end");
    }

    /** CTR / OFB / CFB：三种"块方法 -> 流方法"的写法，区别只在反馈来源。
     * <pre>
     *   三条公式（ks 是密钥流块，16 字节；下标 i 是块序号）
     *     CTR   ksᵢ = E_K(ctr₀ + i)，Cᵢ = Pᵢ ⊕ ksᵢ          反馈来源 = <b>计数器</b>（与 P、C 都无关）
     *     OFB   ksᵢ = E_K(ks_{i−1})，Cᵢ = Pᵢ ⊕ ksᵢ（ks₀ 由 IV 起）  反馈来源 = <b>加密器自己的输出</b>
     *     CFB   ksᵢ = E_K(C_{i−1})，Cᵢ = Pᵢ ⊕ ksᵢ（C_{−1} = IV）    反馈来源 = <b>密文</b>
     *   三行右边只差"喂回加密器的是什么"，这就是方法名的意思：模式只是反馈来源的差别，
     *         底层的 sm4Block / ⊕ / 分组长度一个都没动
     *   共同点  三者都是"块方法 → 流方法"，明文逐字节与密钥流异或 ⇒ 都不需要填充、密文长度 = 明文长度、
     *         加密方向都能并行预计算（CTR/OFB 完全不依赖前一块的输出）
     *   错误传播差别  CTR/OFB：密文坏 1 bit 只坏明文那 1 bit；
     *         CFB：当前块坏那 1 bit，下一块因反馈被污染而整块错，之后再恢复
     *   数据准备  pt 故意取 24 字节（16 + 8），最后一块不完整 —— 就是在验证"无填充也能与 BC 逐字节一致"；
     *         这里的 iv 在 CTR 里被当作<b>计数器初值 ctr₀</b>，在 OFB/CFB 里才是真正意义上的 IV
     *   自反性  CTR 与 OFB 的"解密 = 再跑一遍同一个方法"（两个 assertArrayEquals 就断言这件事）；
     *         CFB 的解密要单独写，因为它的反馈必须取<b>密文</b>而不是明文
     *   对照裁判  BC 的 SM4/CTR|OFB|CFB/NoPadding 三条流水线；最后一行断言 OFB 与 CFB 密文必然不同，
     *         把"只差反馈来源"这件事钉成可观察的事实
     * </pre>
     */
    @TraceExecution(value = "SM4 CTR/OFB/CFB 流式模式", algorithm = "SM4", flow = "SM4-MODES")
    @Test
    public void streamLikeModesDifferOnlyInFeedbackSource()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        // 同一个 16 字节串在三种模式里身份不同：CTR 里它是计数器初值 ctr₀，OFB/CFB 里它是链条第一环 IV
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        byte[] pt = "0123456789abcdef-1234-5678".getBytes("UTF-8");   // 24 字节：最后一块不完整
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        // 流式模式的三种用法都只调"加密方向的轮密钥表"（加密器只被用来产生密钥流，从不需要逆序表）
        long[] encKeys = expandKey(key);

        List<byte[]> tracePlainParts = Calc.chunks(pt, BS);
        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "modes", "CTR/OFB/CFB", "key", Calc.hex(key)
        }, null, "start");
        Tracer.trace("pad", new Object[]{
            "plainBytes", pt.length, "blockSize", BS, "blocks", tracePlainParts.size(), "padding", "NoPadding"
        }, tracePlainParts.size(), "pad");
        Tracer.trace("iv", new Object[]{
            "iv", Calc.hex(iv), "roles", "CTR 的 ctr₀；OFB/CFB 的 IV"
        }, Calc.hex(iv), "iv");

        byte[] ctrOurs = ctr(encKeys, iv, pt);
        if (Tracer.isEnabled())
        {
            List<byte[]> ctrCipherParts = Calc.chunks(ctrOurs, BS);
            BigInteger ctrBase = Calc.toBigInt(iv);
            for (int bi = 0; bi < tracePlainParts.size(); bi++)
            {
                byte[] counterBlock = Calc.toBytes(ctrBase.add(BigInteger.valueOf(bi)), BS);
                byte[] keystream = sm4Block(encKeys, counterBlock);
                byte[] cipherBlock = ctrCipherParts.get(bi);
                byte[] nextCounter = Calc.toBytes(ctrBase.add(BigInteger.valueOf(bi + 1)), BS);
                Tracer.traceLoop("block", new Object[]{
                    "mode", "CTR", "block", bi, "counter", Calc.hex(counterBlock)
                }, Calc.hex(cipherBlock), "blockLoop", bi + 1, tracePlainParts.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "counter", Calc.hex(counterBlock)
                }, Calc.hex(keystream), "encBlock");
                Tracer.trace("xor", new Object[]{
                    "plain", Calc.hex(tracePlainParts.get(bi)), "keystream", Calc.hex(keystream)
                }, Calc.hex(cipherBlock), "xor");
                Tracer.trace("feedback", new Object[]{
                    "nextCounter", Calc.hex(nextCounter)
                }, Calc.hex(nextCounter), "feedback");
            }
        }
        Cipher c = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CTR 与 BC 不一致", c.doFinal(pt), ctrOurs);
        Assert.assertArrayEquals("CTR 的解密就是再加密一次（对称性）", pt, ctr(encKeys, iv, ctrOurs));

        byte[] ofbOurs = ofb(encKeys, iv, pt);
        if (Tracer.isEnabled())
        {
            List<byte[]> ofbCipherParts = Calc.chunks(ofbOurs, BS);
            byte[] ofbState = iv;
            for (int bi = 0; bi < tracePlainParts.size(); bi++)
            {
                byte[] prevState = ofbState;
                ofbState = sm4Block(encKeys, ofbState);
                byte[] cipherBlock = ofbCipherParts.get(bi);
                Tracer.traceLoop("block", new Object[]{
                    "mode", "OFB", "block", bi, "s_{i-1}", Calc.hex(prevState)
                }, Calc.hex(cipherBlock), "blockLoop", bi + 1, tracePlainParts.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "s_{i-1}", Calc.hex(prevState)
                }, Calc.hex(ofbState), "encBlock");
                Tracer.trace("xor", new Object[]{
                    "plain", Calc.hex(tracePlainParts.get(bi)), "keystream", Calc.hex(ofbState)
                }, Calc.hex(cipherBlock), "xor");
                Tracer.trace("feedback", new Object[]{
                    "s_i", Calc.hex(ofbState)
                }, Calc.hex(ofbState), "feedback");
            }
        }
        c = Cipher.getInstance("SM4/OFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("OFB 与 BC 不一致", c.doFinal(pt), ofbOurs);
        Assert.assertArrayEquals("OFB 解密 == 加密（密钥流与明文无关）", pt, ofb(encKeys, iv, ofbOurs));

        byte[] cfbOurs = cfbEncrypt(encKeys, iv, pt);
        if (Tracer.isEnabled())
        {
            List<byte[]> cfbCipherParts = Calc.chunks(cfbOurs, BS);
            byte[] cfbPrev = iv;
            for (int bi = 0; bi < tracePlainParts.size(); bi++)
            {
                byte[] keystream = sm4Block(encKeys, cfbPrev);
                byte[] cipherBlock = cfbCipherParts.get(bi);
                byte[] nextPrev = Arrays.copyOf(cipherBlock, BS);
                Tracer.traceLoop("block", new Object[]{
                    "mode", "CFB", "block", bi, "C_{i-1}", Calc.hex(cfbPrev)
                }, Calc.hex(cipherBlock), "blockLoop", bi + 1, tracePlainParts.size(), "blockLoop");
                Tracer.trace("E_K", new Object[]{
                    "C_{i-1}", Calc.hex(cfbPrev)
                }, Calc.hex(keystream), "encBlock");
                Tracer.trace("xor", new Object[]{
                    "plain", Calc.hex(tracePlainParts.get(bi)), "keystream", Calc.hex(keystream)
                }, Calc.hex(cipherBlock), "xor");
                Tracer.trace("feedback", new Object[]{
                    "C_i", Calc.hex(nextPrev)
                }, Calc.hex(nextPrev), "feedback");
                cfbPrev = nextPrev;
            }
        }
        c = Cipher.getInstance("SM4/CFB/NoPadding", "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals("CFB 与 BC 不一致", c.doFinal(pt), cfbOurs);
        Assert.assertArrayEquals("CFB 解密用密文做反馈", pt, cfbDecrypt(encKeys, iv, cfbOurs));

        Assert.assertNotEquals("OFB 与 CFB 只差在反馈来源，密文必须不同", Calc.hex(ofbOurs), Calc.hex(cfbOurs));
        log.info("[SM4-模式] CTR={} OFB={} CFB={}", Calc.hex(ctrOurs), Calc.hex(ofbOurs), Calc.hex(cfbOurs));
        Tracer.trace("final", new Object[]{
            "ctr", Calc.hex(ctrOurs), "ofb", Calc.hex(ofbOurs), "cfb", Calc.hex(cfbOurs)
        }, pt.length, "final");
        Tracer.traceDecision("compare.ctr", new Object[]{
            "ours", Calc.hex(ctrOurs)
        }, true, "compare", "CTR 与 BC SM4/CTR/NoPadding 一致");
        Tracer.traceDecision("compare.ofb", new Object[]{
            "ours", Calc.hex(ofbOurs)
        }, true, "compare", "OFB 与 BC SM4/OFB/NoPadding 一致");
        Tracer.traceDecision("compare.cfb", new Object[]{
            "ours", Calc.hex(cfbOurs)
        }, true, "compare", "CFB 与 BC SM4/CFB/NoPadding 一致");
        Tracer.traceDecision("compare.feedback", new Object[]{
            "ofb", Calc.hex(ofbOurs), "cfb", Calc.hex(cfbOurs)
        }, !Calc.hex(ofbOurs).equals(Calc.hex(cfbOurs)), "compare", "仅反馈来源不同 -> 密文不同");
        Tracer.trace("end", new Object[]{
            "ctr", Calc.hex(ctrOurs), "ofb", Calc.hex(ofbOurs), "cfb", Calc.hex(cfbOurs), "verified", true
        }, true, "end");
    }

    /** GCM：CTR 之后再接 GHASH，并验证认证性（改一字节必须失败）。
     * <pre>
     *   记号  nonce = 一次性随机数（GCM 的 IV），这里取 96 bit = 12 字节；
     *         aad = 只认证不加密的附加数据 (additional authenticated data)；
     *         tag = 认证标签，本测试取 128 bit（tagBits = 128，故 16 字节）；
     *         H = E_K(0¹²⁸) 哈希子密钥；J₀ = nonce‖00000001 初始计数器块；‖ = 拼接；⊕ = 异或
     *   这个测试分三层：
     *         ① 先验 GF(2¹²⁸) 的<b>代数性质</b>：单位元、零元、乘法可交换、a ⊕ a = 0（特征 2）——
     *            GHASH 的线性性完全建立在这四条上，域算错则 tag 一定错；
     *         ② 再拿我们的 ct‖tag 与 BC 的 SM4/GCM 输出<b>逐字节</b>对照（第三方裁判 + 互操作）；
     *         ③ 最后验<b>认证性</b>：改 1 bit 密文、或换 AAD，tag 都必须对不上
     *   unit[0] = 0x80 为什么是"1"  GCM 的位序把 byte[0] 的<b>最高位</b>当作 x⁰ 的系数（反射位序），
     *         所以单字节 0x80 代表的多项式恰好就是常数 1，即乘法单位元；别按大端整数理解成 128
     *   为什么 nonce 用 96 bit  GCM 的原生最优长度：此时 J₀ = nonce‖00000001，省掉一次 GHASH；
     *         其它长度要先 GHASH 压成 128 bit（gcmEncrypt 里那条三元分支就是这两条路径）
     *   为什么要"改 AAD 也必须让 tag 变"  AAD 不进密文、只进 GHASH 的块序列与长度块 ——
     *         这正是 AEAD 的语义：认证"消息的头"，但头仍然以明文形式传输
     *   AEADBadTagException  JCE 对"tag 校验失败"的标准异常；我们的实现抛 AssertionError（裁判不同，行为等价）
     *   nonce 重用的危害（本文件反复强调）  同一密钥下 nonce 一重复 ⇒ J₀ 与密钥流完全相同 ⇒
     *         两段密文异或即两段明文异或；更糟的是 GHASH 对 H 是线性的，tag 等式里的 H 变得可解，
     *         拿到 H 就能为任意伪造密文造出正确 tag —— GCM 的实战事故绝大多数都是这一条
     * </pre>
     */
    @TraceExecution(value = "SM4-GCM 认证加密", algorithm = "SM4", flow = "SM4-GCM")
    @Test
    public void gcmIsCtrComposedWithGHashOverGf128()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] nonce = Calc.unhex("cafebabefacedbaddecaf888");      // 96-bit：GCM 的原生最优长度
        byte[] aad = "authenticated-but-not-encrypted".getBytes("UTF-8");
        byte[] pt = "GCM gives confidentiality AND integrity at once".getBytes("UTF-8");
        // GCM 只需要加密方向的轮密钥表：CTR 与 GHASH 都只调 E_K，从不调 D_K
        long[] encKeys = expandKey(key);
        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "mode", "GCM", "nonce", Calc.hex(nonce),
            "aad", Calc.hex(aad), "plainBytes", pt.length
        }, null, "start");

        // GF(2^128) 的基本代数性质：GHASH 的线性性就建立在这上面
        byte[] unit = new byte[BS];
        unit[0] = (byte)0x80;                                      // GCM 位序里最高位代表 x^0，即乘法单位元
        byte[] x = Calc.unhex("66108cfd83f1946ecbf7099108f4533c");
        // x · 1 = x：单位元律
        Assert.assertArrayEquals("x * 1 = x", x, galoisMultiply(x, unit));
        // 0 · x = 0：零元律（全 0 块在域里就是加法单位元也是乘法零元）
        Assert.assertArrayEquals("0 * x = 0", new byte[BS], galoisMultiply(new byte[BS], x));
        byte[] y = Calc.unhex("f69f24f171d2f8f7e3a6566f70e0be09");
        // 交换律：x·y = y·x（这两个十六进制串只是任意取的两个 128-bit 块，用来做性质检验）
        Assert.assertArrayEquals("GF(2^128) 乘法可交换", galoisMultiply(x, y), galoisMultiply(y, x));
        // 特征 2：加法就是异或，所以同一个元素加自己两次等于 0 —— 这是"改一位 tag 全变"能成立的根子
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
        // GCM 的对外格式就是 ct ‖ tag（‖ 是拼接），密文长度 = 明文长度 + tagBits/8 字节
        Assert.assertArrayEquals("GCM 与 BC 不一致", ref, ours);
        if (Tracer.isEnabled())
        {
            // 按定义重放 CTR / GHASH / tag 半段，事件里都是与 gcmEncrypt 相同的真实中间值
            byte[] traceH = sm4Block(encKeys, new byte[BS]);
            byte[] traceJ0 = Calc.concat(nonce, new byte[]{ 0, 0, 0, 1 });
            byte[] traceCt = ctr(encKeys, inc32(traceJ0), pt);
            byte[] traceS = gHash(traceH, aad, traceCt);
            byte[] traceMask = sm4Block(encKeys, traceJ0);
            byte[] traceTag = Calc.xor(traceS, traceMask);
            Tracer.trace("ctr", new Object[]{
                "nonce", Calc.hex(nonce), "J0", Calc.hex(traceJ0), "plainBytes", pt.length
            }, Calc.hex(traceCt), "ctr");
            Tracer.trace("ghash", new Object[]{
                "H", Calc.hex(traceH), "aad", Calc.hex(aad), "ct", Calc.hex(traceCt)
            }, Calc.hex(traceS), "ghash");
            Tracer.trace("tag", new Object[]{
                "S", Calc.hex(traceS), "E_K(J0)", Calc.hex(traceMask), "tagBits", 128
            }, Calc.hex(Arrays.copyOf(traceTag, 16)), "tag");
        }
        Assert.assertArrayEquals(pt, gcmDecrypt(encKeys, nonce, aad, 128, ours));
        Tracer.traceDecision("verify.tag", new Object[]{
            "ct", Calc.hex(Arrays.copyOf(ours, pt.length)),
            "tag", Calc.hex(Arrays.copyOfRange(ours, ours.length - 16, ours.length))
        }, true, "verify", "重算 tag == 收到的 tag");

        byte[] tampered = ours.clone();
        // 只翻 ct 的 1 个 bit：因为 tag 是 GHASH(H, AAD, C) ⊕ E_K(J₀)，C 变一点，重算的 tag 就面目全非
        tampered[0] ^= 1;
        try
        {
            gcmDecrypt(encKeys, nonce, aad, 128, tampered);
            Assert.fail("被篡改的数据必须导致 tag 校验失败");
        }
        catch (AssertionError expected)
        {
            log.info("[SM4-GCM] 篡改 1 个 bit -> tag 校验失败（这就是认证性）");
            Tracer.traceDecision("verify.tamper", new Object[]{
                "tamperedByte0", tampered[0]
            }, false, "verify", "篡改 1 bit 后 tag 校验通过");
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
            Tracer.traceDecision("verify.tamper.bc", new Object[]{
                "tamperedByte0", tampered[0]
            }, false, "verify", "BC 接受被篡改的密文");
        }

        // AAD 也参与认证：改 AAD 必须导致 tag 不同
        // 密钥、nonce、明文全部不动，只换 aad —— 密文那半段（CTR）完全相同，只有 tag 会变
        byte[] tagWithOtherAad = gcmEncrypt(encKeys, nonce, "different-aad".getBytes("UTF-8"), 128, pt);
        // 取两段结果的末尾 16 字节（= tagBits/8 = 128/8）互相比较：这就是 ct‖tag 里的 tag 那一段
        Assert.assertNotEquals("AAD 不加密但被认证",
            Calc.hex(Arrays.copyOfRange(ours, ours.length - 16, ours.length)),
            Calc.hex(Arrays.copyOfRange(tagWithOtherAad, tagWithOtherAad.length - 16, tagWithOtherAad.length)));
        Tracer.traceDecision("verify.aad", new Object[]{
            "tag", Calc.hex(Arrays.copyOfRange(ours, ours.length - 16, ours.length)),
            "tagWithOtherAad", Calc.hex(Arrays.copyOfRange(tagWithOtherAad, tagWithOtherAad.length - 16, tagWithOtherAad.length))
        }, true, "verify", "换 AAD 后 tag 不同");
        Tracer.trace("end", new Object[]{
            "ct||tag", Calc.hex(ours), "verified", true
        }, true, "end");
    }

    /** 全部填充模式：普通静态方法实现 + BC padding 原语对照 + JCE 端到端对照。
     * <pre>
     *   统一记号  len = 明文字节数 |data|；bs = 16；n = bs − (len mod bs) 是要补的字节数（取值 1..bs）
     *   七种填充的"结构"一览（右边是尾部补上的 n 个字节长什么样）：
     *     PKCS#7        n 个字节，每个都写 n            —— 冗余度最高，校验最强，可逆
     *     ISO 7816-4    0x80 后跟 (n−1) 个 0x00          —— 靠"第一个 1 位"标出分界，可逆（除非明文尾撞车）
     *     ANSI X9.23    (n−1) 个 0x00 后跟 n             —— 末字节是长度字段，可逆
     *     ISO 10126-2   (n−1) 个随机字节后跟 n           —— 结构与 X9.23 相同，内容不可预测，可逆
     *     ZeroByte      n 个 0x00                        —— <b>有损</b>：明文尾部真实的 0 会被当填充吃掉
     *     TBC           n 个 0xFF 或 n 个 0x00（按末字节奇偶） —— 填充体可重算，按模式尾部计数去填充
     *     NoPadding     不补，只要求 len mod bs == 0      —— 一个对齐判断而已
     *   为什么"与模式正交"  填充只作用在明文字节串上（把长度凑成整块），它不知道也不关心后面接哪种模式；
     *         反过来 ECB/CBC 需要它，CTR/OFB/GCM 按流工作压根不需要它 —— 两个自由度互不干涉，所以能自由搭配
     *   len 取 0,1,15,16,17,31 的用意  覆盖全部填充边界：空串(n=16)、n=15、恰好对齐(n=16 一整块)、
     *         超 1 字节(n=15)、差 1 字节到两块(n=1)
     *   这里的 CBC 只是"载体"  断言的是"我们的填充 + 我们的 CBC" 合起来等于 JCE 的 "SM4/CBC/某Padding"，
     *         一次锁住两个自由度；BC 的 BlockCipherPadding 原语则单独对照"填充这一小段字节本身"
     *   为什么 X9.23/ISO 10126-2 只验互操作  填充体含随机（或实现自选的 0），密文每次不同，无法逐字节比对，
     *         只能验"BC 能解出我们的密文并还原明文"与"长度字段一致"
     * </pre>
     */
    @TraceExecution(value = "SM4 七种填充的正交性", algorithm = "SM4", flow = "SM4-PAD")
    @Test
    public void paddingsAreOrthogonalFunctionsIndependentOfMode()
        throws Exception
    {
        Calc.useBc();
        byte[] key = Calc.unhex("0123456789abcdeffedcba9876543210");
        byte[] iv = Calc.unhex("00112233445566778899aabbccddeeff");
        SecretKeySpec ks = new SecretKeySpec(key, "SM4");
        // 加密表 rk₀..rk₃₁ 与解密表 rk₃₁..rk₀：CBC 解密要的是逆序那张
        long[] encKeys = expandKey(key);
        long[] decKeys = keySchedule(key, false);
        Tracer.trace("start", new Object[]{
            "algorithm", "SM4", "paddings", "PKCS#7/ISO7816-4/X9.23/ISO10126-2/ZeroByte/TBC/NoPadding",
            "lengths", "0,1,15,16,17,31", "key", Calc.hex(key)
        }, null, "start");

        // 六个长度各跑一遍全部填充，专门扫边界：0 / 1 / 15 / 16 / 17 / 31
        for (int len : new int[]{ 0, 1, 15, 16, 17, 31 })
        {
            byte[] pt = Calc.repeatedByte('x', len);

            // ---- PKCS#7（JCE 的 PKCS5Padding 是它的别名）
            byte[] p7 = pkcs7Pad(BS, pt);
            Tracer.trace("pad", new Object[]{
                "scheme", "PKCS#7", "len", len, "n", BS - len % BS, "plain", Calc.hex(pt)
            }, Calc.hex(p7), "pad");
            // 长度检查：补完一定是 len + n 个字节，且 n = BS − len % BS（对齐时 n = 16，多补一整块）
            Assert.assertEquals(len + (BS - len % BS), p7.length);
            byte[] ct7 = cbcEncrypt(encKeys, iv, p7);
            Tracer.trace("encrypt", new Object[]{
                "scheme", "PKCS#7", "len", len, "padded", Calc.hex(p7)
            }, Calc.hex(ct7), "encrypt");
            assertMatchesJce("SM4/CBC/PKCS7Padding", ks, iv, pt, ct7);
            assertMatchesJce("SM4/CBC/PKCS5Padding", ks, iv, pt, ct7);
            byte[] traceDec7 = cbcDecrypt(decKeys, iv, ct7);
            byte[] traceUnpadded7 = pkcs7Unpad(traceDec7);
            Tracer.trace("decrypt", new Object[]{
                "scheme", "PKCS#7", "len", len, "ciphertext", Calc.hex(ct7)
            }, Calc.hex(traceDec7), "decrypt");
            Tracer.trace("unpad", new Object[]{
                "scheme", "PKCS#7", "len", len, "padded", Calc.hex(traceDec7)
            }, Calc.hex(traceUnpadded7), "unpad");
            Tracer.traceDecision("compare", new Object[]{
                "scheme", "PKCS#7", "len", len, "recovered", Calc.hex(traceUnpadded7)
            }, Arrays.equals(pt, traceUnpadded7), "compare", "去填充后恢复原始明文");
            Assert.assertArrayEquals("PKCS#7 去填充应还原明文", pt,
                pkcs7Unpad(cbcDecrypt(decKeys, iv, ct7)));

            // ---- ISO 7816-4
            byte[] p8 = iso7816d4Pad(BS, pt);
            Tracer.trace("pad", new Object[]{
                "scheme", "ISO7816-4", "len", len, "n", BS - len % BS, "plain", Calc.hex(pt)
            }, Calc.hex(p8), "pad");
            // 这里断言的是"补完一定整块"（|p8| mod 16 = 0），与 PKCS#7 的"len + n"是同一件事的两种写法
            Assert.assertEquals("ISO 7816-4 也必须补到整块", 0, p8.length % BS);
            byte[] ct8 = cbcEncrypt(encKeys, iv, p8);
            Tracer.trace("encrypt", new Object[]{
                "scheme", "ISO7816-4", "len", len, "padded", Calc.hex(p8)
            }, Calc.hex(ct8), "encrypt");
            assertMatchesJce("SM4/CBC/ISO7816-4PADDING", ks, iv, pt, ct8);
            byte[] traceDec8 = cbcDecrypt(decKeys, iv, ct8);
            byte[] traceUnpadded8 = iso7816d4Unpad(traceDec8);
            Tracer.trace("decrypt", new Object[]{
                "scheme", "ISO7816-4", "len", len, "ciphertext", Calc.hex(ct8)
            }, Calc.hex(traceDec8), "decrypt");
            Tracer.trace("unpad", new Object[]{
                "scheme", "ISO7816-4", "len", len, "padded", Calc.hex(traceDec8)
            }, Calc.hex(traceUnpadded8), "unpad");
            Tracer.traceDecision("compare", new Object[]{
                "scheme", "ISO7816-4", "len", len, "recovered", Calc.hex(traceUnpadded8)
            }, Arrays.equals(pt, traceUnpadded8), "compare", "去填充后恢复原始明文");
            Assert.assertArrayEquals(pt, iso7816d4Unpad(cbcDecrypt(decKeys, iv, ct8)));

            // ---- ANSI X9.23：填充体是随机字节，无法逐字节对照，只做互操作校验
            // （补充：我们手写的 ansiX923Pad 把中间填成 0x00，而 JCE 的 X9.23 实现会向 padding 传
            //   SecureRandom 把中间填成随机数 —— 两种都合规，所以只能验"BC 能解出我们的密文"）
            byte[] p9 = ansiX923Pad(BS, pt);
            Tracer.trace("pad", new Object[]{
                "scheme", "ANSI X9.23", "len", len, "n", BS - len % BS, "plain", Calc.hex(pt)
            }, Calc.hex(p9), "pad");
            byte[] ct9 = cbcEncrypt(encKeys, iv, p9);
            Tracer.trace("encrypt", new Object[]{
                "scheme", "ANSI X9.23", "len", len, "padded", Calc.hex(p9)
            }, Calc.hex(ct9), "encrypt");
            assertJceDecrypts("SM4/CBC/X9.23PADDING", ks, iv, ct9, pt);
            byte[] traceDec9 = cbcDecrypt(decKeys, iv, ct9);
            byte[] traceUnpadded9 = ansiX923Unpad(traceDec9);
            Tracer.trace("decrypt", new Object[]{
                "scheme", "ANSI X9.23", "len", len, "ciphertext", Calc.hex(ct9)
            }, Calc.hex(traceDec9), "decrypt");
            Tracer.trace("unpad", new Object[]{
                "scheme", "ANSI X9.23", "len", len, "padded", Calc.hex(traceDec9)
            }, Calc.hex(traceUnpadded9), "unpad");
            Tracer.traceDecision("compare", new Object[]{
                "scheme", "ANSI X9.23", "len", len, "recovered", Calc.hex(traceUnpadded9)
            }, Arrays.equals(pt, traceUnpadded9), "compare", "去填充后恢复原始明文");
            Assert.assertArrayEquals(pt, ansiX923Unpad(cbcDecrypt(decKeys, iv, ct9)));

            // ---- ZeroByte：有损填充（尾部真实 0 会被当作填充）
            byte[] p0 = zeroBytePad(BS, pt);
            Tracer.trace("pad", new Object[]{
                "scheme", "ZeroByte", "len", len, "n", BS - len % BS, "plain", Calc.hex(pt)
            }, Calc.hex(p0), "pad");
            byte[] ct0 = cbcEncrypt(encKeys, iv, p0);
            Tracer.trace("encrypt", new Object[]{
                "scheme", "ZeroByte", "len", len, "padded", Calc.hex(p0)
            }, Calc.hex(ct0), "encrypt");
            assertMatchesJce("SM4/CBC/ZeroBytePadding", ks, iv, pt, ct0);
            // lossless 记录"这次是否恰好无损"：pt 全填 'x'（非 0），所以这些长度上恰好都可逆；
            // 换成尾部带 0x00 的明文就会丢字节 —— 因此只打印、不断言（断言会把有损性误当成性质）
            boolean lossless = Arrays.equals(pt, zeroByteUnpad(cbcDecrypt(decKeys, iv, ct0)));
            byte[] traceDec0 = cbcDecrypt(decKeys, iv, ct0);
            byte[] traceUnpadded0 = zeroByteUnpad(traceDec0);
            Tracer.trace("decrypt", new Object[]{
                "scheme", "ZeroByte", "len", len, "ciphertext", Calc.hex(ct0)
            }, Calc.hex(traceDec0), "decrypt");
            Tracer.trace("unpad", new Object[]{
                "scheme", "ZeroByte", "len", len, "padded", Calc.hex(traceDec0)
            }, Calc.hex(traceUnpadded0), "unpad");
            Tracer.traceDecision("compare", new Object[]{
                "scheme", "ZeroByte", "len", len, "lossless", lossless
            }, lossless, "compare", "ZeroByte 去填充后恢复原始明文（可能是有损的）");
            log.info("[SM4-填充] len={} ZeroByte 可逆性={}", len, lossless);

            // ---- ISO 10126-2：随机填充，只能验证结构与去填充结果
            byte[] pi = iso10126d2Pad(BS, pt);
            Tracer.trace("pad", new Object[]{
                "scheme", "ISO 10126-2", "len", len, "n", BS - len % BS, "plain", Calc.hex(pt)
            }, Calc.hex(pi), "pad");
            // 长度自洽：末字节的值就是补的字节数 n，所以 |pi| 必等于 |pt| + n（这一条与随机体无关，可以断言）
            Assert.assertEquals(pt.length + (pi[pi.length - 1] & 0xff), pi.length);
            byte[] traceUnpaddedI = iso10126d2Unpad(pi);
            Tracer.trace("unpad", new Object[]{
                "scheme", "ISO 10126-2", "len", len, "padded", Calc.hex(pi)
            }, Calc.hex(traceUnpaddedI), "unpad");
            Tracer.traceDecision("compare", new Object[]{
                "scheme", "ISO 10126-2", "len", len, "recovered", Calc.hex(traceUnpaddedI)
            }, Arrays.equals(pt, traceUnpaddedI), "compare", "去填充后恢复原始明文");
            Assert.assertArrayEquals("ISO 10126-2 去填充", pt, iso10126d2Unpad(pi));

            // ---- NoPadding：只是一个对齐判断
            boolean aligned = isBlockAligned(BS, pt);
            Tracer.trace("pad.align", new Object[]{
                "scheme", "NoPadding", "len", len
            }, aligned, "pad");
            // 期望值 "len mod 16 == 0" 与 isBlockAligned 的返回值必须一致（16 与 0 是对齐的两个长度）
            Assert.assertEquals(len % BS == 0, isBlockAligned(BS, pt));
            Tracer.traceDecision("compare.align", new Object[]{
                "scheme", "NoPadding", "len", len, "expected", len % BS == 0
            }, len % BS == 0, "compare", "对齐判断与 len mod 16 一致");
        }

        // 与 BC 的填充原语逐字节对照（addPadding 从 offset 开始写，返回写入的填充字节数）
        // 这里统一用 3 字节的明文 {1,2,3}：n = 16 − 3 = 13，能一眼看出各族的"尾部结构"差别
        assertBcPaddingAgree(new PKCS7Padding(), pkcs7Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "PKCS#7", "data", "010203"
        }, true, "compare", "与 BC PKCS7Padding 原语逐字节一致");
        assertBcPaddingAgree(new ISO7816d4Padding(), iso7816d4Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "ISO7816-4", "data", "010203"
        }, true, "compare", "与 BC ISO7816d4Padding 原语逐字节一致");
        assertBcPaddingAgree(new X923Padding(), ansiX923Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "ANSI X9.23", "data", "010203"
        }, true, "compare", "与 BC X923Padding 原语逐字节一致");
        assertBcPaddingAgree(new ZeroBytePadding(), zeroBytePad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "ZeroByte", "data", "010203"
        }, true, "compare", "与 BC ZeroBytePadding 原语逐字节一致");
        assertBcPaddingAgree(new ISO10126d2Padding(), iso10126d2Pad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "ISO 10126-2", "data", "010203"
        }, true, "compare", "与 BC ISO10126d2Padding 的尾字节与长度字段一致");
        Tracer.trace("pad", new Object[]{
            "scheme", "TBC", "data", "010203", "lastByte", 3
        }, Calc.hex(tbcPad(BS, new byte[]{ 1, 2, 3 })), "pad");
        assertBcPaddingAgree(new TBCPadding(), tbcPad(BS, new byte[]{ 1, 2, 3 }), 3);
        Tracer.traceDecision("compare.bc", new Object[]{
            "scheme", "TBC", "data", "010203"
        }, true, "compare", "与 BC TBCPadding 原语逐字节一致");
        log.info("[SM4-填充] 7 种填充全部与 BC 一致：PKCS#7/PKCS#5、ISO 7816-4、X9.23、ISO 10126-2、ZeroByte、TBC、NoPadding");
        Tracer.trace("end", new Object[]{
            "schemes", 7, "lengths", 6, "verified", true
        }, true, "end");
    }

    // ---------------------------------------------------------------- 裁判辅助

    /** 我们的"填充 + CBC 手工实现"必须等于 BC 的"模式+填充流水线"输出。
     * <pre>
     *   参数  transformation 是 JCE 的三段式算法名 "算法/模式/填充"（如 SM4/CBC/PKCS7Padding）；
     *         ks 是密钥（SecretKeySpec，只是把 key 字节包一层给 JCE 用）；iv 是初始化向量；
     *         plain 是<b>未填充</b>的原始明文；ours 是我们自己"先 pad 再手写 CBC"得到的密文
     *   含义  让 BC 完成同样的"填充 + CBC"，两边逐字节相同 ⇒ 我们的两个手写函数拼起来与流水线等价
     *   为什么只给可确定性复现的填充用  填充体含随机数时（X9.23/ISO 10126-2）密文每次都不同，
     *         这条逐字节断言就没意义了，得改用 {@link #assertJceDecrypts}
     * </pre>
     */
    private static void assertMatchesJce(String transformation, SecretKeySpec ks, byte[] iv,
                                        byte[] plain, byte[] ours)
        throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, "BC");
        c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals(transformation + " 与 BC 不一致", c.doFinal(plain), ours);
    }

    /** X9.23 的填充体由随机数填充（JCE 会给 padding 传 SecureRandom），密文不可逐字节对照，只能验互操作。
     * <pre>
     *   "互操作 (interop)"的意思  不比密文长什么样，只问一句：BC 用同一密钥/IV 解开<b>我们</b>生成的密文，
     *         得到的明文是否等于原始明文（expectedPlain）。等于就说明我们的填充与它的解填充规则兼容
     *   为什么这样也够  随机填充体的正确性无法用相等断言表达，但"能被对方解出"是更强的实际要求
     * </pre>
     */
    private static void assertJceDecrypts(String transformation, SecretKeySpec ks, byte[] iv,
                                          byte[] ours, byte[] expectedPlain)
        throws Exception
    {
        Cipher c = Cipher.getInstance(transformation, "BC");
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(iv));
        Assert.assertArrayEquals(transformation + "：BC 必须能解出我们手写生成的密文", expectedPlain, c.doFinal(ours));
    }

    /** 把 BC 的 BlockCipherPadding 原语当裁判，对照我们手写填充的"尾部那几字节"。
     * <pre>
     *   接口约定  addPadding(buf, offset) 从 buf 的第 offset 格起把整块补齐（补到 bs 的整数倍），
     *         返回"写入了几个填充字节"；本文件用的 buf 长度就是一个块（BS = 16）
     *   参数  bcPad 是 BC 的填充原语对象；oursPadded 是我们 pad 出来的完整结果；
     *         dataLen 是原始数据字节数（本文件全部传 3，即明文 {1,2,3}，于是 n = 16 − 3 = 13）
     *   对照的三件事  ①写入的填充<b>个数</b>（oursPadded.length − dataLen 与返回值 written）；
     *         ②尾字节（对 X9.23 / ISO 10126-2 就是长度字段 n）；
     *         ③除 ISO 10126-2 之外，整段填充字节逐个相同
     *   为什么 ISO 10126-2 只比尾字节  它的填充体是 SecureRandom 生成的随机数，两侧不可能相同；
     *         而 TBC 的填充体是 0xFF/0x00 的固定模式，可以逐字节比 —— 所以它走"逐位一致"那条分支
     * </pre>
     */
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
