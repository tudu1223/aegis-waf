package com.aegis.core.sql.ast;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * SQL 抽象语法树节点。
 *
 * <p>这是整个检测引擎的中心数据结构：
 * <ul>
 *   <li><b>结构指纹</b>由归一化后的节点树序列化得出</li>
 *   <li><b>结构差分</b>通过比较两棵树的路径签名集合得出</li>
 *   <li><b>前端可视化</b>直接消费本结构导出的 JSON</li>
 * </ul>
 *
 * <p>节点区分两类信息：
 * <ul>
 *   <li>{@code type} 与 {@code children} —— 决定语义结构，参与指纹计算</li>
 *   <li>{@code value} —— 具体取值，字面量归一化时被抹除</li>
 * </ul>
 */
public final class AstNode {

    private final NodeType type;

    /** 节点值：列名、表名、函数名、运算符或字面量内容。归一化后字面量的值变为 "?"。 */
    private String value;

    private final List<AstNode> children = new ArrayList<>();

    /** 是否源自 MySQL 可执行内联注释，高风险信号。 */
    private boolean fromInlineComment;

    /** 在源 SQL 中的位置，用于前端高亮定位。 */
    private int sourcePosition = -1;

    /** 结构差分标记：normal / injected / removed。仅用于可视化，不参与指纹。 */
    private String diffStatus = "normal";

    /** 差分语义分类，如 OR_INJECTION、TAUTOLOGY。 */
    private String diffKind;

    public AstNode(NodeType type) {
        this(type, null);
    }

    public AstNode(NodeType type, String value) {
        this.type = Objects.requireNonNull(type, "节点类型不能为空");
        this.value = value;
    }

    // ==================== 结构操作 ====================

    public AstNode addChild(AstNode child) {
        if (child != null) {
            children.add(child);
        }
        return this;
    }

    public AstNode addChildren(List<AstNode> nodes) {
        if (nodes != null) {
            for (AstNode n : nodes) {
                addChild(n);
            }
        }
        return this;
    }

    public List<AstNode> getChildren() {
        return Collections.unmodifiableList(children);
    }

    /** 供归一化阶段替换子节点使用。 */
    public List<AstNode> mutableChildren() {
        return children;
    }

    public NodeType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean isFromInlineComment() {
        return fromInlineComment;
    }

    public void setFromInlineComment(boolean fromInlineComment) {
        this.fromInlineComment = fromInlineComment;
    }

    public int getSourcePosition() {
        return sourcePosition;
    }

    public void setSourcePosition(int sourcePosition) {
        this.sourcePosition = sourcePosition;
    }

    public String getDiffStatus() {
        return diffStatus;
    }

    public void setDiffStatus(String diffStatus) {
        this.diffStatus = diffStatus;
    }

    public String getDiffKind() {
        return diffKind;
    }

    public void setDiffKind(String diffKind) {
        this.diffKind = diffKind;
    }

    // ==================== 遍历工具 ====================

    /** 深度优先遍历整棵树（含自身）。 */
    public void traverse(java.util.function.Consumer<AstNode> visitor) {
        visitor.accept(this);
        for (AstNode child : children) {
            child.traverse(visitor);
        }
    }

    /** 收集树中所有指定类型的节点。 */
    public List<AstNode> findAll(NodeType target) {
        List<AstNode> result = new ArrayList<>();
        traverse(n -> {
            if (n.type == target) {
                result.add(n);
            }
        });
        return result;
    }

    /** 判断树中是否存在指定类型的节点。 */
    public boolean contains(NodeType target) {
        if (this.type == target) {
            return true;
        }
        for (AstNode child : children) {
            if (child.contains(target)) {
                return true;
            }
        }
        return false;
    }

    /** 统计树的节点总数，用于复杂度评估。 */
    public int size() {
        int n = 1;
        for (AstNode child : children) {
            n += child.size();
        }
        return n;
    }

    /** 树的最大深度。 */
    public int depth() {
        int max = 0;
        for (AstNode child : children) {
            max = Math.max(max, child.depth());
        }
        return max + 1;
    }

    /** 深拷贝，用于在不影响原树的前提下做归一化或差分标记。 */
    public AstNode deepCopy() {
        AstNode copy = new AstNode(type, value);
        copy.fromInlineComment = this.fromInlineComment;
        copy.sourcePosition = this.sourcePosition;
        copy.diffStatus = this.diffStatus;
        copy.diffKind = this.diffKind;
        for (AstNode child : children) {
            copy.addChild(child.deepCopy());
        }
        return copy;
    }

    /** 面向人类阅读的标签，用于前端节点展示。 */
    public String label() {
        if (value == null || value.isEmpty()) {
            return switch (type) {
                case SELECT_STATEMENT -> "SELECT";
                case INSERT_STATEMENT -> "INSERT";
                case UPDATE_STATEMENT -> "UPDATE";
                case DELETE_STATEMENT -> "DELETE";
                case WHERE_CLAUSE -> "WHERE";
                case FROM_CLAUSE -> "FROM";
                case AND_EXPRESSION -> "AND";
                case OR_EXPRESSION -> "OR";
                case NOT_EXPRESSION -> "NOT";
                case SET_OPERATION -> "UNION";
                case SUBQUERY -> "子查询";
                case SELECT_LIST -> "投影列";
                case ORDER_BY_CLAUSE -> "ORDER BY";
                case GROUP_BY_CLAUSE -> "GROUP BY";
                case LIMIT_CLAUSE -> "LIMIT";
                case WILDCARD -> "*";
                case STATEMENT_LIST -> "语句序列";
                default -> type.name();
            };
        }
        return value;
    }

    @Override
    public String toString() {
        return type + (value != null ? "(" + value + ")" : "");
    }
}
