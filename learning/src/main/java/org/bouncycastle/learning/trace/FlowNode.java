package org.bouncycastle.learning.trace;

import java.util.ArrayList;
import java.util.List;

/**
 * 流程节点 —— 流程图中的一个节点。
 */
public class FlowNode
{
    private final String id;
    private final String label;
    private final FlowNodeType type;
    private final String group;
    private final String description;
    private final List<FlowEdge> edges;
    private final List<FlowNode> children;
    
    // 循环相关
    private int loopTotal;
    private int loopCurrent;
    
    // 判断相关
    private String condition;
    private Boolean decisionResult;

    // 循环子流程相关
    private FlowLoopKind loopKind = FlowLoopKind.BIT;
    private String loopSymbol = "";
    private String loopStepLabel = "";

    public FlowNode(String id, String label, FlowNodeType type, String group)
    {
        this(id, label, type, group, "");
    }

    public FlowNode(String id, String label, FlowNodeType type, String group, String description)
    {
        this.id = id;
        this.label = label;
        this.type = type;
        this.group = group;
        this.description = description;
        this.edges = new ArrayList<>();
        this.children = new ArrayList<>();
    }

    public String getId()
    {
        return id;
    }

    public String getLabel()
    {
        return label;
    }

    public FlowNodeType getType()
    {
        return type;
    }

    public String getGroup()
    {
        return group;
    }

    public String getDescription()
    {
        return description;
    }

    public List<FlowEdge> getEdges()
    {
        return edges;
    }

    public List<FlowNode> getChildren()
    {
        return children;
    }

    public void addEdge(FlowEdge edge)
    {
        edges.add(edge);
    }

    public void addChild(FlowNode child)
    {
        children.add(child);
    }

    public int getLoopTotal()
    {
        return loopTotal;
    }

    public void setLoopTotal(int loopTotal)
    {
        this.loopTotal = loopTotal;
    }

    public int getLoopCurrent()
    {
        return loopCurrent;
    }

    public void setLoopCurrent(int loopCurrent)
    {
        this.loopCurrent = loopCurrent;
    }

    public String getCondition()
    {
        return condition;
    }

    public void setCondition(String condition)
    {
        this.condition = condition;
    }

    public Boolean getDecisionResult()
    {
        return decisionResult;
    }

    public void setDecisionResult(Boolean decisionResult)
    {
        this.decisionResult = decisionResult;
    }

    public FlowLoopKind getLoopKind()
    {
        return loopKind;
    }

    public String getLoopSymbol()
    {
        return loopSymbol;
    }

    public String getLoopStepLabel()
    {
        return loopStepLabel;
    }

    /**
     * 把节点标记为循环并指定子流程形态。
     *
     * @param kind      子流程形态（逐位 / 轮数 / 分块 / 通用）
     * @param symbol    逐位循环扫描的变量名（如 k、s、t、e），非逐位循环可为空
     * @param stepLabel 循环体步骤的文字（如 "执行轮函数"、"压缩一块"），为空时按形态给默认值
     */
    public FlowNode asLoop(FlowLoopKind kind, String symbol, String stepLabel)
    {
        this.loopKind = kind == null ? FlowLoopKind.STEP : kind;
        this.loopSymbol = symbol == null ? "" : symbol;
        this.loopStepLabel = stepLabel == null ? "" : stepLabel;
        return this;
    }
}
