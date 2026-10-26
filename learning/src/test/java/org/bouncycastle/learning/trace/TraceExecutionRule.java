package org.bouncycastle.learning.trace;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * JUnit 4 规则 —— 自动启用/禁用追踪，生成 HTML 可视化。
 *
 * <p>使用方式：
 * <pre>
 * public class Sm2EssenceTest {
 *     &#64;Rule
 *     public TraceExecutionRule traceRule = new TraceExecutionRule();
 *
 *     &#64;TraceExecution
 *     &#64;Test
 *     public void sm2Sign() {
 *         // 测试代码
 *     }
 * }
 * </pre>
 */
public class TraceExecutionRule extends TestWatcher
{
    @Override
    protected void starting(Description description)
    {
        TraceExecution annotation = description.getAnnotation(TraceExecution.class);
        if (annotation != null)
        {
            Tracer.enable(annotation.algorithm(), annotation.flow(), annotation.value());
        }
    }

    @Override
    protected void finished(Description description)
    {
        TraceExecution annotation = description.getAnnotation(TraceExecution.class);
        if (annotation != null && Tracer.isEnabled())
        {
            try
            {
                String fileName = annotation.outputFileName();
                if (fileName.isEmpty())
                {
                    fileName = description.getTestClass().getSimpleName() + "_" +
                        description.getMethodName() + ".html";
                }

                String outputPath = "build/traces/" + fileName;
                Tracer.generateHtml(outputPath);
            }
            finally
            {
                Tracer.disable();
            }
        }
    }

    @Override
    protected void failed(Throwable e, Description description)
    {
        // 测试失败时也生成追踪（用于调试）
        finished(description);
    }
}
