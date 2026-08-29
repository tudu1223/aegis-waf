package com.aegis.core.sql.risk;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;
import com.aegis.core.sql.diff.AstDiffer;
import com.aegis.core.sql.fingerprint.SqlFingerprintEngine.ParseResult;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * [SEC-SQLI-07] SQL 风险特征检测器
 *
 * <p><b>安全原理与设计动机：</b>
 * 基线学习需要时间。系统刚部署、或遇到从未见过的新接口时，基线为空。
 * 此时若采取"无基线一律拦截"会阻断正常业务，若"无基线一律放行"则防护形同虚设。
 * 本检测器提供一套<b>不依赖基线</b>的绝对判定规则，保证系统开箱即用。
 *
 * <p><b>与传统 WAF 规则集的本质区别：</b>
 * 这里的"特征"作用于<b>已经解析完成的语法树结构</b>，而非原始文本的正则匹配。
 * 例如判定恒真式，不是去匹配字符串 {@code "1=1"}（可被 {@code "2>1"}、
 * {@code "'a'='a'"} 等无穷变形绕过），而是检查语法树中比较表达式的
 * 两个操作数在归一化后是否结构等价——这覆盖了所有恒真式的写法。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入、T-12 检测绕过
 */
public final class RiskFeatureDetector {

    /** 正常业务查询中布尔运算符的合理上限，超出即视为异常。 */
    private static final int NORMAL_LOGIC_OPERATOR_LIMIT = 6;

    private RiskFeatureDetector() {
    }

    /**
     * 对解析结果执行风险特征检测。
     *
     * @param parseResult    SQL 解析结果
     * @param encodingDepth  载荷归一化时的解码深度
     * @param originalSql    原始 SQL 文本，用于注释截断等词法层判定
     * @return 命中的风险特征集合
     */
    public static DetectionOutcome detect(ParseResult parseResult,
                                          int encodingDepth,
                                          String originalSql) {
        Set<RiskFeature> features = EnumSet.noneOf(RiskFeature.class);
        List<String> evidence = new ArrayList<>();

        // 解析失败本身是可疑信号——畸形载荷常导致解析异常，
        // 但绝不能因此放行（解析失败不能成为绕过手段）
        if (!parseResult.parsed()) {
            features.add(RiskFeature.PARSE_FAILURE);
            evidence.add("语法解析异常: " + parseResult.parseError());
        }

        AstNode ast = parseResult.normalizedAst();
        if (ast != null) {
            detectStructuralFeatures(ast, features, evidence);
        }

        // 词法层特征：注释截断需要原始文本才能判定
        detectLexicalFeatures(originalSql, features, evidence);

        // 编码层特征
        if (encodingDepth >= 3) {
            features.add(RiskFeature.EXCESSIVE_ENCODING);
            evidence.add("载荷经过 " + encodingDepth + " 重编码");
        }

        int score = features.stream().mapToInt(RiskFeature::getWeight).sum();
        return new DetectionOutcome(features, evidence, Math.min(score, 100));
    }

    /** 基于语法树结构的特征判定。 */
    private static void detectStructuralFeatures(AstNode ast,
                                                 Set<RiskFeature> features,
                                                 List<String> evidence) {

        // R-03 堆叠查询：解析出多条语句
        if (ast.getType() == NodeType.STATEMENT_LIST) {
            features.add(RiskFeature.STACKED_QUERY);
            evidence.add("解析出 " + ast.getChildren().size() + " 条独立语句");
        }

        // R-02 UNION 联合查询
        List<AstNode> setOps = ast.findAll(NodeType.SET_OPERATION);
        if (!setOps.isEmpty()) {
            features.add(RiskFeature.UNION_QUERY);
            evidence.add("检出集合运算: " + setOps.get(0).getValue());
        }

        // R-01 恒真式
        for (AstNode cmp : ast.findAll(NodeType.COMPARISON)) {
            if (isTautology(cmp)) {
                features.add(RiskFeature.TAUTOLOGY);
                evidence.add("恒真表达式: " + describeComparison(cmp));
                break;
            }
        }

        // R-05 / R-06 / R-12 危险函数分类判定
        for (AstNode func : ast.findAll(NodeType.FUNCTION_CALL)) {
            String name = func.getValue() == null ? "" : func.getValue().toUpperCase();
            if (isTimeBlindFunction(name)) {
                features.add(RiskFeature.TIME_BLIND_FUNCTION);
                evidence.add("时间盲注函数: " + name + "()");
            } else if (isOutOfBandFunction(name)) {
                features.add(RiskFeature.OUT_OF_BAND_FUNCTION);
                evidence.add("带外/文件函数: " + name + "()");
            } else if (isVersionProbeFunction(name)) {
                features.add(RiskFeature.VERSION_PROBE);
                evidence.add("指纹探测函数: " + name + "()");
            } else if (isEncodingFunction(name)) {
                features.add(RiskFeature.ENCODING_EVASION);
                evidence.add("编码构造函数: " + name + "()");
            }
        }

        // R-07 系统表访问
        for (AstNode table : ast.findAll(NodeType.TABLE_REF)) {
            String name = table.getValue() == null ? "" : table.getValue().toLowerCase();
            if (isSystemTable(name)) {
                features.add(RiskFeature.SYSTEM_TABLE);
                evidence.add("系统表访问: " + name);
                break;
            }
        }

        // R-12 系统变量探测：@@version 等以列引用形式出现
        for (AstNode col : ast.findAll(NodeType.COLUMN_REF)) {
            String name = col.getValue() == null ? "" : col.getValue().toLowerCase();
            if (name.startsWith("@@")) {
                features.add(RiskFeature.VERSION_PROBE);
                evidence.add("系统变量探测: " + name);
                break;
            }
        }

        // R-08 布尔盲注：条件中嵌套子查询
        for (AstNode cmp : ast.findAll(NodeType.COMPARISON)) {
            if (cmp.contains(NodeType.SUBQUERY)) {
                features.add(RiskFeature.BOOLEAN_BLIND);
                evidence.add("条件中嵌套子查询，疑似盲注推断");
                break;
            }
        }

        // R-09 十六进制字面量绕过
        for (AstNode lit : ast.findAll(NodeType.LITERAL)) {
            String v = lit.getValue();
            if (v != null && v.length() > 6
                    && (v.startsWith("0x") || v.startsWith("0X"))) {
                features.add(RiskFeature.ENCODING_EVASION);
                evidence.add("十六进制字面量: " + truncate(v));
                break;
            }
        }

        // R-11 逻辑运算符异常增多
        int logicOps = ast.findAll(NodeType.OR_EXPRESSION).size()
                + ast.findAll(NodeType.AND_EXPRESSION).size();
        if (logicOps > NORMAL_LOGIC_OPERATOR_LIMIT) {
            features.add(RiskFeature.EXCESSIVE_LOGIC_OPERATORS);
            evidence.add("布尔运算符数量达 " + logicOps + " 个");
        }

        // R-13 内联注释混淆
        final boolean[] inline = {false};
        ast.traverse(n -> {
            if (n.isFromInlineComment()) {
                inline[0] = true;
            }
        });
        if (inline[0]) {
            features.add(RiskFeature.INLINE_COMMENT);
            evidence.add("载荷使用 MySQL 可执行注释隐藏关键字");
        }

        // R-15 DDL 操作出现在数据查询接口
        if (ast.contains(NodeType.DDL_STATEMENT)) {
            features.add(RiskFeature.DDL_OPERATION);
            List<AstNode> ddls = ast.findAll(NodeType.DDL_STATEMENT);
            evidence.add("结构变更语句: " + ddls.get(0).getValue());
        }
    }

    /**
     * 词法层特征判定。
     *
     * <p>注释截断需要检查原始文本：语句尾部出现注释符且其后仍有内容，
     * 说明攻击者试图注释掉原有的查询条件。
     */
    private static void detectLexicalFeatures(String sql,
                                              Set<RiskFeature> features,
                                              List<String> evidence) {
        if (sql == null || sql.isEmpty()) {
            return;
        }
        int idx = indexOfCommentStart(sql);
        if (idx >= 0) {
            String tail = sql.substring(idx).trim();
            // 注释后仍有实质内容，且注释不在语句最开头，判定为截断攻击
            if (tail.length() > 2 && idx > 0) {
                features.add(RiskFeature.COMMENT_TRUNCATION);
                evidence.add("注释截断: " + truncate(tail));
            }
        }
    }

    /** 查找有效的注释起始位置，跳过字符串字面量内部的伪注释。 */
    private static int indexOfCommentStart(String sql) {
        boolean inString = false;
        char quote = 0;
        for (int i = 0; i < sql.length(); i++) {
            char c = sql.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == quote) {
                    inString = false;
                }
                continue;
            }
            if (c == '\'' || c == '"') {
                inString = true;
                quote = c;
                continue;
            }
            if (c == '-' && i + 1 < sql.length() && sql.charAt(i + 1) == '-') {
                return i;
            }
            if (c == '#') {
                return i;
            }
        }
        return -1;
    }

    // ==================== 判定辅助 ====================

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
        boolean bothPlaceholders = isNormalizedLiteral(left) && isNormalizedLiteral(right);
        if (bothPlaceholders) {
            return true;
        }
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
            return String.valueOf(cmp.getValue());
        }
        return ch.get(0).label() + " " + cmp.getValue() + " " + ch.get(1).label();
    }

    private static boolean isTimeBlindFunction(String name) {
        return switch (name) {
            case "SLEEP", "BENCHMARK", "WAITFOR", "PG_SLEEP",
                 "DBMS_PIPE.RECEIVE_MESSAGE" -> true;
            default -> false;
        };
    }

    private static boolean isOutOfBandFunction(String name) {
        return switch (name) {
            case "LOAD_FILE", "OUTFILE", "DUMPFILE", "EXTRACTVALUE",
                 "UPDATEXML", "NAME_CONST" -> true;
            default -> false;
        };
    }

    private static boolean isVersionProbeFunction(String name) {
        return switch (name) {
            case "VERSION", "DATABASE", "USER", "CURRENT_USER", "SYSTEM_USER",
                 "SESSION_USER", "SCHEMA", "CONNECTION_ID" -> true;
            default -> false;
        };
    }

    private static boolean isEncodingFunction(String name) {
        return switch (name) {
            case "CHAR", "UNHEX", "HEX", "ASCII", "ORD", "CONCAT_WS" -> true;
            default -> false;
        };
    }

    private static boolean isSystemTable(String table) {
        if (table == null || table.isEmpty()) {
            return false;
        }
        String lower = table.toLowerCase();
        for (String sys : AstDiffer.systemTables()) {
            if (lower.equals(sys) || lower.startsWith(sys + ".")) {
                return true;
            }
        }
        return false;
    }

    private static String truncate(String s) {
        return s.length() <= 60 ? s : s.substring(0, 60) + "...";
    }

    /**
     * 风险特征检测结果。
     *
     * @param features 命中的特征集合
     * @param evidence 每条特征对应的证据描述
     * @param score    特征累计风险分（上限 100）
     */
    public record DetectionOutcome(
            Set<RiskFeature> features,
            List<String> evidence,
            int score
    ) {
        public boolean isEmpty() {
            return features.isEmpty();
        }

        /** 是否命中确定性攻击特征（权重 ≥ 40 的特征）。 */
        public boolean hasCriticalFeature() {
            return features.stream().anyMatch(f -> f.getWeight() >= 40);
        }

        public List<String> featureCodes() {
            return features.stream().map(RiskFeature::getCode).sorted().toList();
        }
    }
}
