package com.aegis.core.sql.fingerprint;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * [SEC-SQLI-03] AST 字面量归一化器 —— 结构指纹算法的核心
 *
 * <p><b>安全原理：</b>
 * 一条 SQL 的语义结构由其语法树的<b>形状</b>决定，与树中具体的常量取值无关。
 * 例如下面两条语句结构完全相同，仅参数不同：
 * <pre>
 *   SELECT * FROM notes WHERE id = 42
 *   SELECT * FROM notes WHERE id = 1337
 * </pre>
 * 而注入载荷会引入新的语法节点，使结构发生实质变化：
 * <pre>
 *   SELECT * FROM notes WHERE id = 42 OR 1 = 1   ← WHERE 子树多出 OR 节点
 * </pre>
 *
 * <p>因此，将所有<b>字面量</b>替换为统一占位符后，同一业务接口的合法 SQL
 * 必然收敛为极少数几个固定结构，而任何注入都会打破这种收敛。这正是结构指纹
 * 能够免疫编码混淆的根本原因：攻击者可以任意改变参数的文本形态，但只要他
 * 想改变查询逻辑（这正是注入的目的），就必须引入新的语法节点。
 *
 * <p><b>两条关键的工程决策：</b>
 * <ol>
 *   <li><b>IN 列表长度无关化</b>：{@code IN (1,2)} 与 {@code IN (1,2,3)} 属于同一
 *       业务语义，若不做长度归一会导致基线因参数个数不同而爆炸式增长。</li>
 *   <li><b>函数名必须保留</b>：SLEEP、BENCHMARK、LOAD_FILE、EXTRACTVALUE 等是
 *       时间盲注与带外注入的核心标志。若将函数名一并归一化，最危险的一类攻击
 *       将完全漏报。</li>
 * </ol>
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入（STRIDE: Tampering, DREAD 9.0）
 */
public final class AstNormalizer {

    /** 归一化占位符。所有字面量统一替换为此符号。 */
    public static final String PLACEHOLDER = "?";

    /**
     * 语义敏感的字面量：这些值参与逻辑判断，归一化会丢失语义信息。
     * NULL 与布尔值保留原样。
     */
    private static final Set<String> SEMANTIC_LITERALS = Set.of("NULL", "TRUE", "FALSE");

    private AstNormalizer() {
    }

    /**
     * 对语法树执行字面量归一化。
     *
     * <p>该方法不修改入参，返回归一化后的新树。
     *
     * @param root 原始语法树
     * @return 归一化后的语法树，字面量已替换为占位符
     */
    public static AstNode normalize(AstNode root) {
        if (root == null) {
            return new AstNode(NodeType.UNKNOWN);
        }
        AstNode copy = root.deepCopy();
        normalizeInPlace(copy);
        return copy;
    }

    private static void normalizeInPlace(AstNode node) {
        switch (node.getType()) {
            case LITERAL -> normalizeLiteral(node);
            case IN_EXPRESSION -> {
                // [关键] IN 列表长度无关化：先归一化子节点，再折叠重复的占位符项，
                // 避免 IN (1,2) 与 IN (1,2,3) 产生不同指纹导致基线爆炸
                for (AstNode child : node.mutableChildren()) {
                    normalizeInPlace(child);
                }
                collapseInList(node);
                return;
            }
            case LIMIT_CLAUSE -> {
                // LIMIT 的具体数值不影响结构语义
                for (AstNode child : node.mutableChildren()) {
                    if (child.getType() == NodeType.LITERAL) {
                        child.setValue(PLACEHOLDER);
                    }
                }
                return;
            }
            case FUNCTION_CALL -> {
                // [关键] 函数名保留不变（危险函数是核心风险信号），仅归一化其参数
                for (AstNode child : node.mutableChildren()) {
                    normalizeInPlace(child);
                }
                return;
            }
            default -> {
                // 表名、列名、运算符等结构性节点保持原样
            }
        }

        for (AstNode child : node.mutableChildren()) {
            normalizeInPlace(child);
        }
    }

    /**
     * 归一化单个字面量节点。
     *
     * <p>NULL/TRUE/FALSE 参与逻辑语义，保留原值；其余一律替换为占位符。
     */
    private static void normalizeLiteral(AstNode node) {
        String v = node.getValue();
        if (v == null) {
            node.setValue(PLACEHOLDER);
            return;
        }
        String upper = v.toUpperCase();
        if (SEMANTIC_LITERALS.contains(upper)) {
            node.setValue(upper);
        } else {
            node.setValue(PLACEHOLDER);
        }
    }

    /**
     * 折叠 IN 列表中连续的占位符项，使列表长度不影响指纹。
     *
     * <p>{@code col IN (?, ?, ?)} → {@code col IN (?)}
     * 首个子节点是被判定的列表达式，需保留；其后的值列表折叠为单个占位符。
     */
    private static void collapseInList(AstNode inNode) {
        List<AstNode> children = inNode.mutableChildren();
        if (children.size() <= 2) {
            return;
        }
        // 子查询形式的 IN 不做折叠，其结构本身有语义
        boolean hasSubquery = children.stream()
                .anyMatch(c -> c.getType() == NodeType.SUBQUERY);
        if (hasSubquery) {
            return;
        }

        AstNode target = children.get(0);
        List<AstNode> values = new ArrayList<>(children.subList(1, children.size()));
        boolean allPlaceholders = values.stream()
                .allMatch(v -> (v.getType() == NodeType.LITERAL
                        || v.getType() == NodeType.PLACEHOLDER)
                        && PLACEHOLDER.equals(v.getValue()));

        if (allPlaceholders) {
            children.clear();
            children.add(target);
            AstNode single = new AstNode(NodeType.LITERAL, PLACEHOLDER);
            children.add(single);
        }
    }
}
