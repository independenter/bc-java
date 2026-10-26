package org.bouncycastle.learning.trace;

/**
 * 流程节点类型。
 */
public enum FlowNodeType
{
    /** 普通操作（矩形框） */
    OPERATION,
    
    /** 判断/决策（菱形框） */
    DECISION,
    
    /** 循环（双线框，显示迭代次数） */
    LOOP,
    
    /** 分组容器（粗线框，包含子节点） */
    GROUP,
    
    /** 开始/结束（圆角矩形） */
    TERMINAL
}
