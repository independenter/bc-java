package org.bouncycastle.learning.trace;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 流程定义 —— 定义一个完整的流程图谱结构。
 *
 * <p>用于描述算法的业务逻辑流程，包括操作、判断、循环等节点，
 * 以及它们之间的连接关系。在 HTML 可视化中渲染为流程图，
 * 并与执行步骤联动高亮。
 */
public class FlowDefinition
{
    private final String name;
    private final Map<String, FlowNode> nodes;
    private final List<FlowEdge> edges;
    private String startNodeId;

    public FlowDefinition(String name)
    {
        this.name = name;
        this.nodes = new LinkedHashMap<>();
        this.edges = new ArrayList<>();
    }

    public String getName()
    {
        return name;
    }

    public Map<String, FlowNode> getNodes()
    {
        return nodes;
    }

    public List<FlowEdge> getEdges()
    {
        return edges;
    }

    public String getStartNodeId()
    {
        return startNodeId;
    }

    public void setStartNodeId(String startNodeId)
    {
        this.startNodeId = startNodeId;
    }

    /**
     * 添加一个流程节点。
     */
    public FlowNode addNode(String id, String label, FlowNodeType type, String group)
    {
        return addNode(id, label, type, group, "");
    }

    /**
     * 添加一个流程节点（带描述）。
     */
    public FlowNode addNode(String id, String label, FlowNodeType type, String group,
        String description)
    {
        FlowNode node = new FlowNode(id, label, type, group, description);
        nodes.put(id, node);
        return node;
    }

    /**
     * 添加一条边。
     */
    public void addEdge(String fromId, String toId)
    {
        addEdge(fromId, toId, "");
    }

    /**
     * 添加一条带标签的边。
     *
     * <p>同一对 (from,to) 只保留一条：先由顺序链建立的无标签边，会被后续带标签的调用
     * 升级为有标签边，避免流程图上叠画两条重复箭头。
     */
    public void addEdge(String fromId, String toId, String label)
    {
        for (int i = 0; i < edges.size(); i++)
        {
            FlowEdge existing = edges.get(i);
            if (existing.getFromId().equals(fromId) && existing.getToId().equals(toId))
            {
                if (!label.isEmpty() && existing.getLabel().isEmpty())
                {
                    FlowEdge upgraded = new FlowEdge(fromId, toId, label);
                    edges.set(i, upgraded);
                    FlowNode source = nodes.get(fromId);
                    if (source != null)
                    {
                        List<FlowEdge> sourceEdges = source.getEdges();
                        for (int j = 0; j < sourceEdges.size(); j++)
                        {
                            if (sourceEdges.get(j) == existing)
                            {
                                sourceEdges.set(j, upgraded);
                            }
                        }
                    }
                }
                return;
            }
        }

        FlowEdge edge = new FlowEdge(fromId, toId, label);
        edges.add(edge);

        // 同时添加到源节点的边列表中
        FlowNode fromNode = nodes.get(fromId);
        if (fromNode != null)
        {
            fromNode.addEdge(edge);
        }
    }

    /**
     * 根据 group 查找节点。
     */
    public FlowNode findNodeByGroup(String group)
    {
        for (FlowNode node : nodes.values())
        {
            if (node.getGroup().equals(group))
            {
                return node;
            }
        }
        return null;
    }

    /**
     * 获取指定 group 的所有节点。
     */
    public List<FlowNode> getNodesByGroup(String group)
    {
        List<FlowNode> result = new ArrayList<>();
        for (FlowNode node : nodes.values())
        {
            if (node.getGroup().equals(group))
            {
                result.add(node);
            }
        }
        return result;
    }

    /**
     * 获取所有唯一的 group 名称。
     */
    public List<String> getAllGroups()
    {
        List<String> groups = new ArrayList<>();
        for (FlowNode node : nodes.values())
        {
            String group = node.getGroup();
            if (!groups.contains(group))
            {
                groups.add(group);
            }
        }
        return groups;
    }
}
