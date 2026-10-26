package org.bouncycastle.learning.trace;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 追踪器 —— 记录算法执行的每一步，支持生成 HTML 可视化。
 *
 * <p>使用方式：
 * <pre>
 * // 1. 启用追踪
 * Tracer.enable();
 *
 * // 2. 在关键运算处记录（带分组）
 * Tracer.trace("ecAdd",
 *     new Object[]{"pt1", pt1, "pt2", pt2},
 *     result,
 *     "mul_kG"  // 业务逻辑分组
 * );
 *
 * // 3. 记录循环步骤（带迭代信息）
 * Tracer.traceLoop("doublePoint", inputs, output, "mul_kG", 128, 256);
 *
 * // 4. 记录判断步骤
 * Tracer.traceDecision("checkR", inputs, r.signum() == 0, "checkR", "r == 0");
 *
 * // 5. 生成 HTML
 * Tracer.generateHtml("sm2_trace.html");
 *
 * // 6. 禁用追踪
 * Tracer.disable();
 * </pre>
 *
 * <p>线程安全：使用 ThreadLocal，每个线程有独立的追踪上下文。
 */
public class Tracer
{
    private static final ThreadLocal<TraceContext> CONTEXT = new ThreadLocal<>();
    private static final ThreadLocal<java.util.Deque<String>> LOOP_STACK = new ThreadLocal<>();

    public static void enable()
    {
        enable("SM2");
    }

    public static void enable(String algorithm)
    {
        enable(algorithm, "");
    }

    public static void enable(String algorithm, String flowKey)
    {
        enable(algorithm, flowKey, "");
    }

    /**
     * 启用追踪，并记录本次追踪的用途标题（通常是测试方法的 @TraceExecution.value()）。
     */
    public static void enable(String algorithm, String flowKey, String title)
    {
        CONTEXT.set(new TraceContext(algorithm, flowKey, title));
    }

    public static void disable()
    {
        CONTEXT.remove();
        LOOP_STACK.remove();
    }

    public static boolean isEnabled()
    {
        return CONTEXT.get() != null;
    }

    /**
     * 进入循环上下文：循环体内的 trace 会通过 currentGroup() 关联到该循环。
     *
     * @param loopName 循环名（如 "mul_kG"），null 则不压栈
     */
    public static void pushLoop(String loopName)
    {
        if (loopName == null)
        {
            return;
        }
        java.util.Deque<String> stack = LOOP_STACK.get();
        if (stack == null)
        {
            stack = new java.util.ArrayDeque<>();
            LOOP_STACK.set(stack);
        }
        stack.push(loopName);
    }

    public static void popLoop()
    {
        java.util.Deque<String> stack = LOOP_STACK.get();
        if (stack != null && !stack.isEmpty())
        {
            stack.pop();
        }
    }

    /**
     * 若在循环内则返回 "loopName:defaultGroup"，否则返回 defaultGroup。
     * 用于把循环内的子运算（doublePoint/add）归属到循环节点而不是主流程图的其他节点。
     */
    public static String currentGroup(String defaultGroup)
    {
        java.util.Deque<String> stack = LOOP_STACK.get();
        if (stack != null && !stack.isEmpty())
        {
            return stack.peek() + ":" + defaultGroup;
        }
        return defaultGroup;
    }

    /**
     * 记录一步运算（带分组）。
     *
     * @param operation 运算名称（如 "ecAdd"、"modInverse"）
     * @param inputs    输入参数，格式：{"name1", value1, "name2", value2, ...}
     * @param output    输出结果
     * @param group     业务逻辑分组（如 "mul_kG"、"computeR"）
     */
    public static void trace(String operation, Object[] inputs, Object output, String group)
    {
        trace(operation, inputs, output, group, (Map<String, Object>)null);
    }

    /**
     * 记录一步运算（带分组和元数据）。
     *
     * @param operation 运算名称
     * @param inputs    输入参数
     * @param output    输出结果
     * @param group     业务逻辑分组
     * @param metadata  额外信息（如循环迭代次数、判断结果等）
     */
    public static void trace(String operation, Object[] inputs, Object output, String group,
        Map<String, Object> metadata)
    {
        if (!isEnabled())
        {
            return;
        }

        TraceContext ctx = CONTEXT.get();
        Map<String, Object> inputMap = parseInputs(inputs);
        long startNanos = System.nanoTime();
        int stepNumber = ctx.getEvents().size() + 1;
        long durationNanos = System.nanoTime() - startNanos;

        TraceEvent event = new TraceEvent(stepNumber, operation, inputMap, output,
            startNanos, durationNanos, group, metadata);
        ctx.addEvent(event);
    }

    /**
     * 记录一步运算（带耗时测量）。
     */
    public static void trace(String operation, Object[] inputs, Object output, long durationNanos)
    {
        trace(operation, inputs, output, "default", (Map<String, Object>)null, durationNanos);
    }

    /**
     * 记录一步运算（带分组和耗时）。
     */
    public static void trace(String operation, Object[] inputs, Object output, String group,
        long durationNanos)
    {
        trace(operation, inputs, output, group, (Map<String, Object>)null, durationNanos);
    }

    /**
     * 记录一步运算（带分组、元数据和耗时）。
     */
    public static void trace(String operation, Object[] inputs, Object output, String group,
        Map<String, Object> metadata, long durationNanos)
    {
        if (!isEnabled())
        {
            return;
        }

        TraceContext ctx = CONTEXT.get();
        Map<String, Object> inputMap = parseInputs(inputs);
        int stepNumber = ctx.getEvents().size() + 1;

        TraceEvent event = new TraceEvent(stepNumber, operation, inputMap, output,
            System.nanoTime(), durationNanos, group, metadata);
        ctx.addEvent(event);
    }

    /**
     * 记录循环中的步骤。
     *
     * @param operation 运算名称
     * @param inputs    输入参数
     * @param output    输出结果
     * @param group     业务逻辑分组
     * @param iteration 当前迭代次数（从 1 开始）
     * @param total     总迭代次数
     */
    public static void traceLoop(String operation, Object[] inputs, Object output, String group,
        int iteration, int total)
    {
        traceLoop(operation, inputs, output, group, iteration, total, null);
    }

    /**
     * 记录循环迭代（带循环名称）。
     *
     * @param operation 运算名称
     * @param inputs    输入参数
     * @param output    输出结果
     * @param group     业务逻辑分组
     * @param iteration 当前迭代次数
     * @param total     总迭代次数
     * @param loopName  循环名称（用于流程图节点定位，如 "mul_kG"）
     */
    public static void traceLoop(String operation, Object[] inputs, Object output, String group,
        int iteration, int total, String loopName)
    {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("loopIteration", iteration);
        metadata.put("loopTotal", total);
        if (loopName != null)
        {
            metadata.put("loopName", loopName);
        }
        trace(operation, inputs, output, group, metadata);
    }

    /**
     * 记录判断步骤。
     *
     * @param operation 运算名称
     * @param inputs    输入参数
     * @param result    判断结果（true/false）
     * @param group     业务逻辑分组
     * @param condition 判断条件描述（如 "r == 0"）
     */
    public static void traceDecision(String operation, Object[] inputs, boolean result,
        String group, String condition)
    {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("decisionResult", result);
        metadata.put("condition", condition);
        trace(operation, inputs, result, group, metadata);
    }

    /**
     * 生成 HTML 可视化文件。
     */
    public static void generateHtml(String filename)
    {
        if (!isEnabled())
        {
            throw new IllegalStateException("Tracer is not enabled");
        }

        TraceContext ctx = CONTEXT.get();
        String html = HtmlGenerator.generate(ctx);

        try
        {
            java.nio.file.Path path = java.nio.file.Paths.get(filename);
            java.nio.file.Files.createDirectories(path.getParent() == null ?
                java.nio.file.Paths.get(".") : path.getParent());
            java.nio.file.Files.write(path, html.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            System.out.println("Trace HTML generated: " + path.toAbsolutePath());
        }
        catch (Exception e)
        {
            throw new RuntimeException("Failed to generate trace HTML", e);
        }
    }

    /**
     * 获取当前追踪上下文的事件列表。
     */
    public static List<TraceEvent> getEvents()
    {
        if (!isEnabled())
        {
            return new ArrayList<>();
        }
        return new ArrayList<>(CONTEXT.get().getEvents());
    }

    /**
     * 获取当前追踪上下文的事件数量。
     */
    public static int getEventCount()
    {
        if (!isEnabled())
        {
            return 0;
        }
        return CONTEXT.get().getEvents().size();
    }

    /**
     * 清空当前追踪上下文。
     */
    public static void clear()
    {
        if (isEnabled())
        {
            CONTEXT.get().clear();
        }
    }

    private static Map<String, Object> parseInputs(Object[] inputs)
    {
        Map<String, Object> inputMap = new LinkedHashMap<>();
        if (inputs == null)
        {
            return inputMap;
        }
        for (int i = 0; i < inputs.length; i += 2)
        {
            String name = (String) inputs[i];
            Object value = inputs[i + 1];
            inputMap.put(name, value);
        }
        return inputMap;
    }

    /**
     * 追踪上下文 —— 存储一个测试方法的所有追踪事件。
     */
    static class TraceContext
    {
        private final String algorithm;
        private final String flowKey;
        private final String title;
        private final List<TraceEvent> events = new ArrayList<>();

        TraceContext(String algorithm, String flowKey, String title)
        {
            this.algorithm = algorithm;
            this.flowKey = flowKey == null ? "" : flowKey;
            this.title = title == null ? "" : title;
        }

        public String getAlgorithm()
        {
            return algorithm;
        }

        public String getFlowKey()
        {
            return flowKey;
        }

        public String getTitle()
        {
            return title;
        }

        public void addEvent(TraceEvent event)
        {
            events.add(event);
        }

        public List<TraceEvent> getEvents()
        {
            return events;
        }

        public void clear()
        {
            events.clear();
        }
    }
}
