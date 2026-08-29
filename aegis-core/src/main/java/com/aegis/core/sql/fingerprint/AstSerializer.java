package com.aegis.core.sql.fingerprint;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;

import java.util.ArrayList;
import java.util.List;

/**
 * [SEC-SQLI-04] AST 规范化序列化器
 *
 * <p><b>安全原理：</b>
 * 同一语义的 SQL 存在多种等价书写形式——大小写不同、空白不同、可选关键字
 * （AS、INNER）省略与否、冗余括号等。若直接对 SQL 文本做哈希，同一结构会
 * 产生多个不同指纹，导致基线无法收敛、误报激增。
 *
 * <p>本序列化器对归一化后的语法树做深度优先遍历，按固定规则输出<b>规范形式</b>：
 * 关键字统一大写、标识符统一小写、单空格分隔、结构显式化。由此保证
 * "结构相同 ⟺ 序列化结果相同 ⟺ 指纹相同"。
 *
 * <p><b>交换律处理：</b>AND/OR 的同级操作数满足交换律，{@code a=? AND b=?} 与
 * {@code b=? AND a=?} 在语义上等价。本实现对同级布尔操作数按序列化文本排序后
 * 再连接，使二者收敛为同一指纹，进一步降低基线数量与误报率。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入、T-12 检测绕过
 */
public final class AstSerializer {

    private AstSerializer() {
    }

    /**
     * 将语法树序列化为规范字符串。
     *
     * @param node 归一化后的语法树
     * @return 规范化序列化结果，作为指纹计算的输入
     */
    public static String serialize(AstNode node) {
        StringBuilder sb = new StringBuilder();
        write(node, sb);
        return sb.toString().trim().replaceAll("\\s+", " ");
    }

    private static void write(AstNode node, StringBuilder sb) {
        if (node == null) {
            return;
        }
        switch (node.getType()) {
            case STATEMENT_LIST -> writeJoined(node.getChildren(), " ; ", sb);

            case SET_OPERATION -> {
                List<AstNode> ch = node.getChildren();
                if (!ch.isEmpty()) {
                    write(ch.get(0), sb);
                }
                sb.append(' ').append(upper(node.getValue())).append(' ');
                if (ch.size() > 1) {
                    write(ch.get(1), sb);
                }
            }

            case SELECT_STATEMENT -> writeSelect(node, sb);

            case INSERT_STATEMENT -> {
                sb.append("INSERT INTO ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case UPDATE_STATEMENT -> {
                sb.append("UPDATE ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case DELETE_STATEMENT -> {
                sb.append("DELETE FROM ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case DDL_STATEMENT -> {
                sb.append(upper(node.getValue())).append(' ');
                writeJoined(node.getChildren(), " ", sb);
            }

            case SELECT_LIST -> writeJoined(node.getChildren(), ", ", sb);

            case SELECT_ITEM -> writeJoined(node.getChildren(), " ", sb);

            case FROM_CLAUSE -> {
                sb.append("FROM ");
                writeJoined(node.getChildren(), ", ", sb);
            }

            case JOIN_CLAUSE -> {
                sb.append(' ').append(upper(node.getValue())).append(' ');
                writeJoined(node.getChildren(), " ON ", sb);
            }

            case WHERE_CLAUSE -> {
                sb.append(" WHERE ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case GROUP_BY_CLAUSE -> {
                sb.append(" GROUP BY ");
                writeJoined(node.getChildren(), ", ", sb);
            }

            case HAVING_CLAUSE -> {
                sb.append(" HAVING ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case ORDER_BY_CLAUSE -> {
                sb.append(" ORDER BY ");
                writeJoined(node.getChildren(), ", ", sb);
            }

            case LIMIT_CLAUSE -> {
                sb.append(" LIMIT ");
                writeJoined(node.getChildren(), ", ", sb);
            }

            case SET_CLAUSE -> {
                sb.append(" SET ");
                writeJoined(node.getChildren(), ", ", sb);
            }

            case VALUES_CLAUSE -> {
                sb.append(" VALUES (");
                writeJoined(node.getChildren(), ", ", sb);
                sb.append(')');
            }

            // AND/OR 满足交换律，对同级操作数排序以消除书写顺序差异
            case AND_EXPRESSION -> writeCommutative(node, "AND", sb);
            case OR_EXPRESSION -> writeCommutative(node, "OR", sb);

            case NOT_EXPRESSION -> {
                sb.append("NOT ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case COMPARISON -> {
                List<AstNode> ch = node.getChildren();
                if (!ch.isEmpty()) {
                    write(ch.get(0), sb);
                }
                sb.append(' ').append(normalizeOperator(node.getValue())).append(' ');
                if (ch.size() > 1) {
                    write(ch.get(1), sb);
                }
            }

            case ARITHMETIC -> {
                List<AstNode> ch = node.getChildren();
                if (ch.size() == 1) {
                    // 一元运算
                    sb.append(node.getValue() == null ? "" : node.getValue().replace("u", ""));
                    write(ch.get(0), sb);
                } else {
                    if (!ch.isEmpty()) {
                        write(ch.get(0), sb);
                    }
                    sb.append(' ').append(node.getValue()).append(' ');
                    if (ch.size() > 1) {
                        write(ch.get(1), sb);
                    }
                }
            }

            case IN_EXPRESSION -> {
                List<AstNode> ch = node.getChildren();
                if (!ch.isEmpty()) {
                    write(ch.get(0), sb);
                }
                sb.append(' ').append(upper(node.getValue())).append(" (");
                if (ch.size() > 1) {
                    writeJoined(ch.subList(1, ch.size()), ", ", sb);
                }
                sb.append(')');
            }

            case LIKE_EXPRESSION, BETWEEN_EXPRESSION -> {
                List<AstNode> ch = node.getChildren();
                if (!ch.isEmpty()) {
                    write(ch.get(0), sb);
                }
                sb.append(' ').append(upper(node.getValue())).append(' ');
                if (ch.size() > 1) {
                    writeJoined(ch.subList(1, ch.size()), " AND ", sb);
                }
            }

            case IS_NULL_EXPRESSION -> {
                writeJoined(node.getChildren(), " ", sb);
                sb.append(' ').append(upper(node.getValue()));
            }

            case EXISTS_EXPRESSION -> {
                sb.append("EXISTS ");
                writeJoined(node.getChildren(), " ", sb);
            }

            case CASE_EXPRESSION -> {
                sb.append("CASE ");
                writeJoined(node.getChildren(), " ", sb);
                sb.append(" END");
            }

            // [关键] 函数名保留并统一大写，是危险函数检测的依据
            case FUNCTION_CALL -> {
                sb.append(upper(node.getValue())).append('(');
                writeJoined(node.getChildren(), ", ", sb);
                sb.append(')');
            }

            case SUBQUERY -> {
                sb.append('(');
                writeJoined(node.getChildren(), " ", sb);
                sb.append(')');
            }

            // 标识符统一小写，消除大小写混淆
            case COLUMN_REF, TABLE_REF -> sb.append(lower(node.getValue()));

            case LITERAL -> sb.append(node.getValue() == null ? "?" : node.getValue());

            case PLACEHOLDER -> sb.append('?');

            case WILDCARD -> sb.append('*');

            case UNKNOWN -> sb.append("<?>");

            default -> writeJoined(node.getChildren(), " ", sb);
        }
    }

    private static void writeSelect(AstNode node, StringBuilder sb) {
        sb.append("SELECT ");
        for (AstNode child : node.getChildren()) {
            write(child, sb);
            if (child.getType() == NodeType.SELECT_LIST) {
                sb.append(' ');
            }
        }
    }

    /**
     * 序列化满足交换律的布尔表达式。
     *
     * <p>先分别序列化各操作数，再按文本排序后连接，使
     * {@code a=? AND b=?} 与 {@code b=? AND a=?} 收敛为同一形式。
     */
    private static void writeCommutative(AstNode node, String op, StringBuilder sb) {
        List<String> parts = new ArrayList<>();
        for (AstNode child : node.getChildren()) {
            StringBuilder part = new StringBuilder();
            write(child, part);
            parts.add(part.toString().trim());
        }
        parts.sort(String::compareTo);
        sb.append('(');
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) {
                sb.append(' ').append(op).append(' ');
            }
            sb.append(parts.get(i));
        }
        sb.append(')');
    }

    private static void writeJoined(List<AstNode> nodes, String sep, StringBuilder sb) {
        for (int i = 0; i < nodes.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            write(nodes.get(i), sb);
        }
    }

    /** 比较运算符规范化：{@code <>} 与 {@code !=} 语义相同，统一为 {@code <>}。 */
    private static String normalizeOperator(String op) {
        if (op == null) {
            return "=";
        }
        return "!=".equals(op) ? "<>" : op;
    }

    private static String upper(String s) {
        return s == null ? "" : s.toUpperCase();
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase();
    }
}
