package com.aegis.core.sql.visual;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;
import com.aegis.core.sql.diff.DiffResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AST 可视化导出器。
 *
 * <p>将语法树与结构差分结果转换为前端图可视化组件可直接消费的树形数据。
 * 这是"攻防对抗可视化"的数据契约：被标记为 {@code injected} 的节点
 * 在大屏上渲染为高亮的注入子树，是整个系统最具冲击力的展示环节。
 *
 * <p>输出为纯 Java 数据结构（Map/List），由上层用 Jackson 序列化为 JSON，
 * 使本模块保持对具体 JSON 库的零依赖。
 */
public final class AstVisualExporter {

    private AstVisualExporter() {
    }

    /**
     * 导出带差分标记的可视化树。
     *
     * @param baseline 基线语法树，可为 null
     * @param actual   实际语法树
     * @param diff     结构差分结果
     * @return 可序列化为 JSON 的树形结构
     */
    public static Map<String, Object> export(AstNode baseline, AstNode actual, DiffResult diff) {
        if (actual == null) {
            return Map.of(
                    "tree", Map.of(),
                    "similarity", 0.0,
                    "annotations", List.of()
            );
        }

        AstNode marked = actual.deepCopy();
        markInjectedNodes(baseline, marked, diff);

        List<Map<String, Object>> annotations = new ArrayList<>();
        for (DiffResult.DiffAnnotation a : diff.annotations()) {
            annotations.add(Map.of(
                    "kind", a.kind().name(),
                    "kindName", a.kind().getDisplayName(),
                    "path", a.path(),
                    "snippet", a.snippet(),
                    "detail", a.detail(),
                    "critical", a.kind().isCritical()
            ));
        }

        return Map.of(
                "tree", toNodeMap(marked, "n"),
                "similarity", diff.similarity(),
                "matched", diff.matched(),
                "hasBaseline", diff.hasBaseline(),
                "annotations", annotations,
                "nodeCount", marked.size(),
                "depth", marked.depth()
        );
    }

    /** 仅导出结构树，不含差分标记，用于基线展示。 */
    public static Map<String, Object> exportPlain(AstNode ast) {
        if (ast == null) {
            return Map.of();
        }
        return toNodeMap(ast, "n");
    }

    /**
     * 标记注入节点。
     *
     * <p>依据差分标注的语义分类，定位实际树中对应的节点并打上
     * {@code injected} 状态，供前端高亮渲染。
     */
    private static void markInjectedNodes(AstNode baseline, AstNode actual, DiffResult diff) {
        if (diff.matched() || diff.annotations().isEmpty()) {
            return;
        }

        Set<String> kinds = new java.util.HashSet<>();
        for (DiffResult.DiffAnnotation a : diff.annotations()) {
            kinds.add(a.kind().name());
        }

        int baselineOrCount = baseline == null ? 0
                : baseline.findAll(NodeType.OR_EXPRESSION).size();
        int baselineSubqueryCount = baseline == null ? 0
                : baseline.findAll(NodeType.SUBQUERY).size();

        // OR 注入：标记超出基线数量的 OR 节点及其子树
        if (kinds.contains("OR_INJECTION")) {
            List<AstNode> ors = actual.findAll(NodeType.OR_EXPRESSION);
            for (int i = baselineOrCount; i < ors.size(); i++) {
                markSubtree(ors.get(i), "OR_INJECTION");
            }
        }

        // UNION 注入：标记集合运算节点
        if (kinds.contains("UNION_INJECTION")) {
            for (AstNode setOp : actual.findAll(NodeType.SET_OPERATION)) {
                setOp.setDiffStatus("injected");
                setOp.setDiffKind("UNION_INJECTION");
                // 右侧子树为注入的查询，整体标记
                List<AstNode> children = setOp.getChildren();
                if (children.size() > 1) {
                    markSubtree(children.get(1), "UNION_INJECTION");
                }
            }
        }

        // 堆叠查询：标记第一条之后的所有语句
        if (kinds.contains("STACKED_QUERY") && actual.getType() == NodeType.STATEMENT_LIST) {
            List<AstNode> stmts = actual.getChildren();
            for (int i = 1; i < stmts.size(); i++) {
                markSubtree(stmts.get(i), "STACKED_QUERY");
            }
        }

        // 恒真式：标记构成恒真的比较节点
        if (kinds.contains("TAUTOLOGY")) {
            for (AstNode cmp : actual.findAll(NodeType.COMPARISON)) {
                if (isTautology(cmp)) {
                    markSubtree(cmp, "TAUTOLOGY");
                }
            }
        }

        // 危险函数：标记函数调用节点
        if (kinds.contains("DANGEROUS_FUNCTION")) {
            for (AstNode func : actual.findAll(NodeType.FUNCTION_CALL)) {
                String name = func.getValue() == null ? "" : func.getValue().toUpperCase();
                if (com.aegis.core.sql.diff.AstDiffer.dangerousFunctions().contains(name)) {
                    markSubtree(func, "DANGEROUS_FUNCTION");
                }
            }
        }

        // 系统表访问
        if (kinds.contains("SYSTEM_TABLE_ACCESS")) {
            for (AstNode table : actual.findAll(NodeType.TABLE_REF)) {
                String name = table.getValue() == null ? "" : table.getValue().toLowerCase();
                for (String sys : com.aegis.core.sql.diff.AstDiffer.systemTables()) {
                    if (name.equals(sys) || name.startsWith(sys + ".")) {
                        table.setDiffStatus("injected");
                        table.setDiffKind("SYSTEM_TABLE_ACCESS");
                        break;
                    }
                }
            }
        }

        // 子查询注入
        if (kinds.contains("SUBQUERY_INJECTION")) {
            List<AstNode> subs = actual.findAll(NodeType.SUBQUERY);
            for (int i = baselineSubqueryCount; i < subs.size(); i++) {
                markSubtree(subs.get(i), "SUBQUERY_INJECTION");
            }
        }

        // 内联注释混淆：标记所有源自可执行注释的节点
        if (kinds.contains("INLINE_COMMENT_EVASION")) {
            actual.traverse(n -> {
                if (n.isFromInlineComment()) {
                    n.setDiffStatus("injected");
                    if (n.getDiffKind() == null) {
                        n.setDiffKind("INLINE_COMMENT_EVASION");
                    }
                }
            });
        }
    }

    /** 将整棵子树标记为注入状态。 */
    private static void markSubtree(AstNode root, String kind) {
        root.traverse(n -> {
            n.setDiffStatus("injected");
            if (n.getDiffKind() == null) {
                n.setDiffKind(kind);
            }
        });
    }

    private static boolean isTautology(AstNode cmp) {
        List<AstNode> children = cmp.getChildren();
        if (children.size() != 2) {
            return false;
        }
        String op = cmp.getValue();
        if (!"=".equals(op) && !"<=>".equals(op)) {
            return false;
        }
        AstNode left = children.get(0);
        AstNode right = children.get(1);
        boolean bothPlaceholders = isPlaceholder(left) && isPlaceholder(right);
        if (bothPlaceholders) {
            return true;
        }
        if (left.getType() == NodeType.COLUMN_REF && right.getType() == NodeType.COLUMN_REF) {
            return left.getValue() != null && left.getValue().equalsIgnoreCase(right.getValue());
        }
        return false;
    }

    private static boolean isPlaceholder(AstNode node) {
        return (node.getType() == NodeType.LITERAL || node.getType() == NodeType.PLACEHOLDER)
                && "?".equals(node.getValue());
    }

    /** 递归转换为前端消费的 Map 结构。 */
    private static Map<String, Object> toNodeMap(AstNode node, String idPrefix) {
        Map<String, Object> map = new java.util.LinkedHashMap<>();
        map.put("id", idPrefix);
        map.put("label", node.label());
        map.put("type", node.getType().name());
        map.put("status", node.getDiffStatus());
        if (node.getDiffKind() != null) {
            map.put("kind", node.getDiffKind());
        }
        if (node.isFromInlineComment()) {
            map.put("inlineComment", true);
        }
        if (node.getSourcePosition() >= 0) {
            map.put("pos", node.getSourcePosition());
        }

        List<AstNode> children = node.getChildren();
        if (!children.isEmpty()) {
            List<Map<String, Object>> childMaps = new ArrayList<>(children.size());
            for (int i = 0; i < children.size(); i++) {
                childMaps.add(toNodeMap(children.get(i), idPrefix + "-" + i));
            }
            map.put("children", childMaps);
        }
        return map;
    }
}
