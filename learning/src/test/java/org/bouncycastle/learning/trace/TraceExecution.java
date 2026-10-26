package org.bouncycastle.learning.trace;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记需要追踪执行的测试方法。
 *
 * <p>使用方式：
 * <pre>
 * &#64;TraceExecution
 * &#64;Test
 * public void sm2Sign() {
 *     // 测试代码
 * }
 * </pre>
 *
 * <p>测试运行时会自动：
 * <ol>
 *   <li>启用 Tracer</li>
 *   <li>记录所有 trace 调用</li>
 *   <li>生成 HTML 可视化文件到 build/traces/ 目录</li>
 * </ol>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface TraceExecution
{
    /**
     * 追踪描述（可选）。
     */
    String value() default "";

    /**
     * 追踪级别。
     */
    TraceLevel level() default TraceLevel.DETAILED;

    /**
     * 输出文件名（不含路径，会自动放到 build/traces/ 下）。
     * 如果为空，则使用 "类名_方法名.html"。
     */
    String outputFileName() default "";

    /**
     * 算法名称（用于路由到对应的流程图定义）。
     * 支持：SM2, SM3, SM4, RSA, SM9, PQC, THRESHOLD, MULTISIG, INTERACTIVE
     */
    String algorithm() default "SM2";

    /**
     * 主题流程图 key（见 {@code Flows}），为空时用 algorithm 的默认流程图。
     * 同一个算法下的不同测试主题（如 RSA 的密钥生成 / 填充 / 分块）可用不同流程图。
     */
    String flow() default "";
}
