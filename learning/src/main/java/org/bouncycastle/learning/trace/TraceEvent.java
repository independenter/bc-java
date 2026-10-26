package org.bouncycastle.learning.trace;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 追踪事件 —— 记录一次运算的输入、输出、时间信息和业务逻辑分组。
 *
 * <p>每个 TraceEvent 代表算法执行过程中的一步，例如：
 * <ul>
 *   <li>ecAdd(pt1, pt2) → result（group: "mul_kG"）</li>
 *   <li>modInverse(a, p) → result（group: "computeS"）</li>
 *   <li>sm3.compress(block, V) → newV（group: "computeZA"）</li>
 * </ul>
 *
 * <p>group 字段用于将步骤归类到业务逻辑块（如"标量乘循环"、"计算 r"、"判断 r==0"），
 * 便于在可视化时着色和分组显示。metadata 存储额外信息（如循环迭代次数、判断结果等）。
 */
public class TraceEvent
{
    private final int stepNumber;
    private final String operation;
    private final Map<String, Object> inputs;
    private final Object output;
    private final long timestampNanos;
    private final long durationNanos;
    private final String group;
    private final Map<String, Object> metadata;

    public TraceEvent(int stepNumber, String operation, Map<String, Object> inputs,
        Object output, long timestampNanos, long durationNanos)
    {
        this(stepNumber, operation, inputs, output, timestampNanos, durationNanos, null, null);
    }

    public TraceEvent(int stepNumber, String operation, Map<String, Object> inputs,
        Object output, long timestampNanos, long durationNanos, String group,
        Map<String, Object> metadata)
    {
        this.stepNumber = stepNumber;
        this.operation = operation;
        this.inputs = new LinkedHashMap<>(inputs);
        this.output = output;
        this.timestampNanos = timestampNanos;
        this.durationNanos = durationNanos;
        this.group = group != null ? group : "default";
        this.metadata = metadata != null ? new LinkedHashMap<>(metadata) : new LinkedHashMap<>();
    }

    public int getStepNumber()
    {
        return stepNumber;
    }

    public String getOperation()
    {
        return operation;
    }

    public Map<String, Object> getInputs()
    {
        return inputs;
    }

    public Object getOutput()
    {
        return output;
    }

    public long getTimestampNanos()
    {
        return timestampNanos;
    }

    public long getDurationNanos()
    {
        return durationNanos;
    }

    public double getDurationMillis()
    {
        return durationNanos / 1_000_000.0;
    }

    public String getGroup()
    {
        return group;
    }

    public Map<String, Object> getMetadata()
    {
        return metadata;
    }
}
