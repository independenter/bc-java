package org.bouncycastle.learning.trace;

/**
 * 循环节点的子流程形态 —— 决定循环框内画哪些步骤。
 *
 * <ul>
 *   <li>{@link #BIT}   逐位扫描：取第 j 位 → bit=1? → double+add / double only（SM2 标量乘）</li>
 *   <li>{@link #ROUND} 轮数循环：第 j 轮 → 执行轮函数（SM3 压缩 / SM4 32 轮）</li>
 *   <li>{@link #BLOCK} 分块/逐项循环：第 j 块 → 处理该块（SM3 分块 / RSA 分块）</li>
 *   <li>{@link #STEP}  通用循环：第 j 步 → 执行循环体</li>
 * </ul>
 */
public enum FlowLoopKind
{
    BIT, ROUND, BLOCK, STEP
}
