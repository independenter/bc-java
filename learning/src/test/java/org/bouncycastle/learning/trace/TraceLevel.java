package org.bouncycastle.learning.trace;

/**
 * 追踪级别。
 */
public enum TraceLevel
{
    /**
     * 粗略：只追踪顶层方法调用。
     */
    COARSE,

    /**
     * 详细：追踪所有数学运算（默认）。
     */
    DETAILED,

    /**
     * 完整：追踪每一步（包括模运算等底层操作）。
     */
    FULL
}
