package org.bouncycastle.learning.trace;

/**
 * 流程边 —— 连接两个流程节点的边。
 */
public class FlowEdge
{
    private final String fromId;
    private final String toId;
    private final String label;
    private final boolean isBranch;  // 是否是判断分支（yes/no）

    public FlowEdge(String fromId, String toId)
    {
        this(fromId, toId, "", false);
    }

    public FlowEdge(String fromId, String toId, String label)
    {
        this(fromId, toId, label, !label.isEmpty());
    }

    public FlowEdge(String fromId, String toId, String label, boolean isBranch)
    {
        this.fromId = fromId;
        this.toId = toId;
        this.label = label;
        this.isBranch = isBranch;
    }

    public String getFromId()
    {
        return fromId;
    }

    public String getToId()
    {
        return toId;
    }

    public String getLabel()
    {
        return label;
    }

    public boolean isBranch()
    {
        return isBranch;
    }
}
