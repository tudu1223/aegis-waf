package com.aegis.core.sql.diff;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * [SEC-SQLI-06] AST 结构差分定位器
 *
 * <p><b>安全原理：</b>
 * 指纹比对只能回答"结构变了没有"，无法回答"变在哪里"。结构差分进一步定位到
 * <b>具体是哪个语法节点被注入</b>，这既是安全取证的依据，也是攻防可视化中
 * 红色高亮子树的数据来源。
 *
 * <p><b>算法选型：</b>
 * 未采用完整的树编辑距离算法（Zhang-Shasha，复杂度 O(n²·d²) 过重，
 * 在网关热路径上不可接受），而是采用<b>路径签名多集差分</b>：
 * 为每个节点生成"从根到该节点的类型路径 + 节点自身特征"作为签名，
 * 两棵树的签名多集之差即为新增与缺失的结构，复杂度为 O(n)。
 *
 * <p>差分结果再经语义分类，映射为具有安全含义的攻击手法标注
 * （恒真式、UNION 注入、堆叠查询等）。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入（DREAD 9.0）
 */
public final class AstDiffer {

    /**
     * 危险函数名单。
     *
     * <p>这些函数是时间盲注、带外注入与文件读写的核心标志，
     * 出现在用户可控的查询中即构成确定性攻击信号。
     */
    private static final Set<String> DANGEROUS_FUNCTIONS = Set.of(
            // 时间盲注
            "SLEEP", "BENCHMARK", "WAITFOR", "PG_SLEEP", "DBMS_PIPE.RECEIVE_MESSAGE",
            // 带外注入与报错注入
            "EXTRACTVALUE", "UPDATEXML", "EXP", "FLOOR", "RAND", "NAME_CONST",
            // 文件读写
            "LOAD_FILE", "OUTFILE", "DUMPFILE", "LOAD DATA",
            // 信息收集
            "VERSION", "DATABASE", "USER", "CURRENT_USER", "SYSTEM_USER",
            "SESSION_USER", "SCHEMA", "CONNECTION_ID",
            // 编码绕过常用
            "CHAR", "CONCAT_WS", "UNHEX", "HEX", "ASCII", "ORD"
    );

    /** 数据库元数据表，访问它们属于典型的注入信息收集行为。 */
    private static final Set<String> SYSTEM_TABLES = Set.of(
            "information_schema", "mysql.user", "mysql.db", "pg_catalog",
            "pg_shadow", "pg_user", "sys.databases", "sysobjects", "syscolumns",
            "all_tables", "user_tables", "dba_users"
    );

    private AstDiffer() {
    }

    /**
     * 计算实际语法树相对基线语法树的结构差分。
     *
     * @param baseline 基线语法树（归一化后），可为 null 表示无基线
     * @param actual   实际语法树（归一化后）
     * @return 差分结果，含相似度与语义标注
     */
    public static DiffResult diff(AstNode baseline, AstNode actual) {
        if (actual == null) {
            return DiffResult.ofNoBaseline();
        }

        // 无基线时仅做绝对结构风险分析（冷启动场景）
        if (baseline == null) {
            List<DiffResult.DiffAnnotation> annotations = analyzeAbsoluteRisks(actual);
            return new DiffResult(false, 0.0, annotations, List.of(), List.of(), false);
        }

        Map<String, Integer> baseSigs = collectSignatures(baseline);
        Map<String, Integer> actualSigs = collectSignatures(actual);

        List<String> added = multisetDifference(actualSigs, baseSigs);
        List<String> removed = multisetDifference(baseSigs, actualSigs);

        double similarity = jaccardSimilarity(baseSigs, actualSigs);

        if (added.isEmpty() && removed.isEmpty()) {
            return DiffResult.ofMatched();
        }

        List<DiffResult.DiffAnnotation> annotations =
                classify(baseline, actual, added, removed);

        return new DiffResult(false, similarity, annotations, added, removed, true);
    }

    // ==================== 路径签名 ====================

    /**
     * 收集树中所有节点的路径签名多集。
     *
     * <p>签名格式：{@code 父路径/节点类型[:特征值]}。
     * 对于结构决定性节点（函数名、表名、运算符），特征值参与签名，
     * 使 {@code SLEEP(?)} 与 {@code LENGTH(?)} 被视为不同结构。
     */
    private static Map<String, Integer> collectSignatures(AstNode root) {
        Map<String, Integer> signatures = new HashMap<>();
        collect(root, "", signatures);
        return signatures;
    }

    private static void collect(AstNode node, String parentPath, Map<String, Integer> out) {
        String sig = parentPath + "/" + signatureOf(node);
        out.merge(sig, 1, Integer::sum);
        for (AstNode child : node.getChildren()) {
            collect(child, sig, out);
        }
    }

    /** 生成单个节点的签名片段。 */
    private static String signatureOf(AstNode node) {
        String base = node.getType().name();
        return switch (node.getType()) {
            // 这些节点的取值决定语义，必须纳入签名
            case FUNCTION_CALL, TABLE_REF, COLUMN_REF, COMPARISON,
                 ARITHMETIC, SET_OPERATION, IN_EXPRESSION, LIKE_EXPRESSION,
                 IS_NULL_EXPRESSION ->
                    base + ":" + (node.getValue() == null ? "" : node.getValue().toUpperCase());
            // 字面量已归一化，取值不参与签名
            default -> base;
        };
    }

    /** 多集差：返回在 a 中出现次数多于 b 的签名（按超出的次数重复列出）。 */
    private static List<String> multisetDifference(Map<String, Integer> a,
                                                   Map<String, Integer> b) {
        List<String> result = new ArrayList<>();
        for (Map.Entry<String, Integer> e : a.entrySet()) {
            int diff = e.getValue() - b.getOrDefault(e.getKey(), 0);
            for (int i = 0; i < diff; i++) {
                result.add(e.getKey());
            }
        }
        return result;
    }

    /** Jaccard 相似度：交集大小 / 并集大小，用于量化结构偏离程度。 */
    private static double jaccardSimilarity(Map<String, Integer> a, Map<String, Integer> b) {
        Set<String> union = new HashSet<>(a.keySet());
        union.addAll(b.keySet());
        if (union.isEmpty()) {
            return 1.0;
        }
        int intersection = 0;
        for (String key : a.keySet()) {
            if (b.containsKey(key)) {
                intersection += Math.min(a.get(key), b.get(key));
            }
        }
        int total = 0;
        for (String key : union) {
            total += Math.max(a.getOrDefault(key, 0), b.getOrDefault(key, 0));
        }
        return total == 0 ? 1.0 : (double) intersection / total;
    }

    // ==================== 语义分类 ====================

    /**
     * 将结构差分映射为具有安全语义的攻击手法标注。
     */
    private static List<DiffResult.DiffAnnotation> classify(
            AstNode baseline, AstNode actual,
            List<String> added, List<String> removed) {

        List<DiffResult.DiffAnnotation> annotations = new ArrayList<>();
        Set<DiffKind> seen = new HashSet<>();

        // ---- 基于新增结构的判定 ----

        // 堆叠查询：出现多语句结构
        if (actual.getType() == NodeType.STATEMENT_LIST
                && baseline.getType() != NodeType.STATEMENT_LIST) {
            addOnce(annotations, seen, DiffKind.STACKED_QUERY,
                    "STATEMENT_LIST", "检出 " + actual.getChildren().size() + " 条语句");
        }

        // UNION 注入：出现基线之外的集合运算
        boolean baselineHasSetOp = baseline.contains(NodeType.SET_OPERATION);
        if (actual.contains(NodeType.SET_OPERATION) && !baselineHasSetOp) {
            List<AstNode> setOps = actual.findAll(NodeType.SET_OPERATION);
            String op = setOps.isEmpty() ? "UNION" : setOps.get(0).getValue();
            addOnce(annotations, seen, DiffKind.UNION_INJECTION, "SET_OPERATION", op);
        }

        // OR 注入：OR 节点数量超出基线
        int baselineOrCount = baseline.findAll(NodeType.OR_EXPRESSION).size();
        List<AstNode> actualOrs = actual.findAll(NodeType.OR_EXPRESSION);
        if (actualOrs.size() > baselineOrCount) {
            addOnce(annotations, seen, DiffKind.OR_INJECTION,
                    "OR_EXPRESSION", "新增 " + (actualOrs.size() - baselineOrCount) + " 处 OR 运算");
        }

        // 恒真式：新增的比较表达式两侧结构相同
        for (AstNode cmp : actual.findAll(NodeType.COMPARISON)) {
            if (isTautology(cmp) && !containsEquivalent(baseline, cmp)) {
                addOnce(annotations, seen, DiffKind.TAUTOLOGY,
                        "COMPARISON", describeComparison(cmp));
            }
        }

        // 危险函数：调用了基线中不存在的高危函数
        Set<String> baselineFunctions = new HashSet<>();
        for (AstNode f : baseline.findAll(NodeType.FUNCTION_CALL)) {
            if (f.getValue() != null) {
                baselineFunctions.add(f.getValue().toUpperCase());
            }
        }
        for (AstNode f : actual.findAll(NodeType.FUNCTION_CALL)) {
            String name = f.getValue() == null ? "" : f.getValue().toUpperCase();
            if (DANGEROUS_FUNCTIONS.contains(name) && !baselineFunctions.contains(name)) {
                addOnce(annotations, seen, DiffKind.DANGEROUS_FUNCTION,
                        "FUNCTION_CALL:" + name, name + "()");
            }
        }

        // 系统表访问
        for (AstNode t : actual.findAll(NodeType.TABLE_REF)) {
            String table = t.getValue() == null ? "" : t.getValue().toLowerCase();
            if (isSystemTable(table) && !containsTable(baseline, table)) {
                addOnce(annotations, seen, DiffKind.SYSTEM_TABLE_ACCESS,
                        "TABLE_REF:" + table, table);
            }
        }

        // 内联注释混淆：树中存在源自 MySQL 可执行注释的节点
        final boolean[] inlineFound = {false};
        actual.traverse(n -> {
            if (n.isFromInlineComment()) {
                inlineFound[0] = true;
            }
        });
        if (inlineFound[0]) {
            addOnce(annotations, seen, DiffKind.INLINE_COMMENT_EVASION,
                    "INLINE_COMMENT", "载荷使用了 MySQL 可执行注释");
        }

        // 子查询注入
        int baselineSubqueries = baseline.findAll(NodeType.SUBQUERY).size();
        int actualSubqueries = actual.findAll(NodeType.SUBQUERY).size();
        if (actualSubqueries > baselineSubqueries) {
            addOnce(annotations, seen, DiffKind.SUBQUERY_INJECTION,
                    "SUBQUERY", "新增 " + (actualSubqueries - baselineSubqueries) + " 处子查询");
        }

        // 投影列扩展
        int baseCols = countSelectItems(baseline);
        int actualCols = countSelectItems(actual);
        if (actualCols > baseCols) {
            addOnce(annotations, seen, DiffKind.COLUMN_EXPANSION,
                    "SELECT_LIST", "投影列由 " + baseCols + " 增至 " + actualCols);
        }

        // ---- 基于缺失结构的判定 ----

        // 条件剥离：基线有 WHERE 条件而实际缺失，或条件节点显著减少
        boolean baselineHasWhere = baseline.contains(NodeType.WHERE_CLAUSE);
        boolean actualHasWhere = actual.contains(NodeType.WHERE_CLAUSE);
        int baselineConditions = baseline.findAll(NodeType.COMPARISON).size()
                + baseline.findAll(NodeType.AND_EXPRESSION).size();
        int actualConditions = actual.findAll(NodeType.COMPARISON).size()
                + actual.findAll(NodeType.AND_EXPRESSION).size();

        if ((baselineHasWhere && !actualHasWhere)
                || (baselineConditions > actualConditions && !removed.isEmpty())) {
            addOnce(annotations, seen, DiffKind.CONDITION_REMOVED,
                    "WHERE_CLAUSE", "查询条件数量由 " + baselineConditions
                            + " 减至 " + actualConditions);
        }

        // 兜底：存在结构差异但未命中任何具体分类
        if (annotations.isEmpty()) {
            if (!added.isEmpty()) {
                addOnce(annotations, seen, DiffKind.STRUCTURE_ADDED,
                        added.get(0), "新增 " + added.size() + " 个结构节点");
            } else if (!removed.isEmpty()) {
                addOnce(annotations, seen, DiffKind.STRUCTURE_REMOVED,
                        removed.get(0), "缺失 " + removed.size() + " 个结构节点");
            }
        }

        return annotations;
    }

    /**
     * 无基线场景下的绝对结构风险分析。
     *
     * <p>系统冷启动或遇到新接口时基线为空，此时无法做差分比对，
     * 转而识别那些<b>无论何种业务场景都不应出现</b>的结构特征。
     */
    private static List<DiffResult.DiffAnnotation> analyzeAbsoluteRisks(AstNode actual) {
        List<DiffResult.DiffAnnotation> annotations = new ArrayList<>();
        Set<DiffKind> seen = new HashSet<>();

        if (actual.getType() == NodeType.STATEMENT_LIST) {
            addOnce(annotations, seen, DiffKind.STACKED_QUERY,
                    "STATEMENT_LIST", "检出 " + actual.getChildren().size() + " 条语句");
        }

        for (AstNode cmp : actual.findAll(NodeType.COMPARISON)) {
            if (isTautology(cmp)) {
                addOnce(annotations, seen, DiffKind.TAUTOLOGY,
                        "COMPARISON", describeComparison(cmp));
            }
        }

        for (AstNode f : actual.findAll(NodeType.FUNCTION_CALL)) {
            String name = f.getValue() == null ? "" : f.getValue().toUpperCase();
            if (DANGEROUS_FUNCTIONS.contains(name)) {
                addOnce(annotations, seen, DiffKind.DANGEROUS_FUNCTION,
                        "FUNCTION_CALL:" + name, name + "()");
            }
        }

        for (AstNode t : actual.findAll(NodeType.TABLE_REF)) {
            String table = t.getValue() == null ? "" : t.getValue().toLowerCase();
            if (isSystemTable(table)) {
                addOnce(annotations, seen, DiffKind.SYSTEM_TABLE_ACCESS,
                        "TABLE_REF:" + table, table);
            }
        }

        final boolean[] inlineFound = {false};
        actual.traverse(n -> {
            if (n.isFromInlineComment()) {
                inlineFound[0] = true;
            }
        });
        if (inlineFound[0]) {
            addOnce(annotations, seen, DiffKind.INLINE_COMMENT_EVASION,
                    "INLINE_COMMENT", "载荷使用了 MySQL 可执行注释");
        }

        return annotations;
    }

    // ==================== 判定工具 ====================

    /**
     * 判断比较表达式是否构成恒真式。
     *
     * <p>归一化后 {@code '1'='1'} 变为 {@code ? = ?}，两侧均为占位符且运算符为等号，
     * 即为典型的恒真式注入特征。同时识别 {@code 1=1} 形式的列自比较。
     */
    private static boolean isTautology(AstNode comparison) {
        List<AstNode> children = comparison.getChildren();
        if (children.size() != 2) {
            return false;
        }
        String op = comparison.getValue();
        if (!"=".equals(op) && !"<=>".equals(op)) {
            return false;
        }
        AstNode left = children.get(0);
        AstNode right = children.get(1);

        // 两侧均为归一化字面量：'1'='1' 归一化后成为 ? = ?
        boolean bothLiterals = isNormalizedLiteral(left) && isNormalizedLiteral(right);
        if (bothLiterals) {
            return true;
        }

        // 两侧为同一列的自比较：id = id
        if (left.getType() == NodeType.COLUMN_REF && right.getType() == NodeType.COLUMN_REF) {
            return left.getValue() != null && left.getValue().equalsIgnoreCase(right.getValue());
        }
        return false;
    }

    private static boolean isNormalizedLiteral(AstNode node) {
        return (node.getType() == NodeType.LITERAL || node.getType() == NodeType.PLACEHOLDER)
                && "?".equals(node.getValue());
    }

    private static String describeComparison(AstNode cmp) {
        List<AstNode> ch = cmp.getChildren();
        if (ch.size() != 2) {
            return cmp.getValue();
        }
        return ch.get(0).label() + " " + cmp.getValue() + " " + ch.get(1).label();
    }

    /** 判断基线中是否存在结构等价的比较表达式，避免把正常条件误判为恒真式。 */
    private static boolean containsEquivalent(AstNode baseline, AstNode target) {
        for (AstNode cmp : baseline.findAll(NodeType.COMPARISON)) {
            if (isTautology(cmp) && sameShape(cmp, target)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameShape(AstNode a, AstNode b) {
        if (a.getType() != b.getType()) {
            return false;
        }
        if (a.getChildren().size() != b.getChildren().size()) {
            return false;
        }
        for (int i = 0; i < a.getChildren().size(); i++) {
            if (!sameShape(a.getChildren().get(i), b.getChildren().get(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSystemTable(String table) {
        if (table == null || table.isEmpty()) {
            return false;
        }
        String lower = table.toLowerCase();
        for (String sys : SYSTEM_TABLES) {
            if (lower.equals(sys) || lower.startsWith(sys + ".")) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsTable(AstNode root, String table) {
        for (AstNode t : root.findAll(NodeType.TABLE_REF)) {
            if (t.getValue() != null && t.getValue().equalsIgnoreCase(table)) {
                return true;
            }
        }
        return false;
    }

    private static int countSelectItems(AstNode root) {
        int count = 0;
        for (AstNode list : root.findAll(NodeType.SELECT_LIST)) {
            count += list.getChildren().size();
        }
        return count;
    }

    private static void addOnce(List<DiffResult.DiffAnnotation> list, Set<DiffKind> seen,
                                DiffKind kind, String path, String snippet) {
        if (seen.add(kind)) {
            list.add(DiffResult.DiffAnnotation.of(kind, path, snippet));
        }
    }

    /** 暴露危险函数名单，供风险特征检测器复用。 */
    public static Set<String> dangerousFunctions() {
        return DANGEROUS_FUNCTIONS;
    }

    /** 暴露系统表名单，供风险特征检测器复用。 */
    public static Set<String> systemTables() {
        return SYSTEM_TABLES;
    }
}
