package com.aegis.core.engine;

import com.aegis.core.model.Severity;
import com.aegis.core.model.ThreatType;
import com.aegis.core.model.Verdict;
import com.aegis.core.normalize.NormalizeResult;
import com.aegis.core.normalize.PayloadNormalizer;
import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.diff.AstDiffer;
import com.aegis.core.sql.diff.DiffResult;
import com.aegis.core.sql.fingerprint.SqlFingerprintEngine;
import com.aegis.core.sql.fingerprint.SqlFingerprintEngine.ParseResult;
import com.aegis.core.sql.risk.RiskFeatureDetector;
import com.aegis.core.sql.visual.AstVisualExporter;
import com.aegis.core.xss.HtmlSanitizer;
import com.aegis.core.xss.SanitizeResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * [SEC-ENGINE-01] AEGIS 检测引擎门面
 *
 * <p>统一封装全部检测能力，是网关层与 RASP 层唯一需要交互的入口。
 *
 * <p><b>综合风险评分模型：</b>
 * <pre>
 *   风险分 = 结构偏离贡献 + 差分标注贡献 + 风险特征贡献 + 编码可疑度
 *
 *   其中：
 *     结构偏离贡献 = (1 - Jaccard相似度) × 50     （仅在有基线时计算）
 *     差分标注贡献 = Σ 各变异类型权重
 *     风险特征贡献 = Σ 各命中特征权重
 *     编码可疑度   = 归一化阶段的异常标记权重
 * </pre>
 *
 * <p><b>基线优先原则：</b>指纹命中基线时直接放行，不再计算风险分。
 * 这是降低误报的关键——正常业务查询即使包含某些"可疑"特征
 * （如业务本身就需要 OR 条件），只要结构与基线一致就是安全的。
 *
 * <p><b>失效安全设计：</b>检测过程中的任何异常均降级为放行并记录引擎异常事件，
 * 保证检测引擎故障不会阻断正常业务（可用性优先）。
 */
public final class DetectionEngine {

    /** 判定为攻击并拦截的风险分阈值。 */
    public static final int BLOCK_THRESHOLD = 70;

    /** 判定为可疑并记录的风险分阈值。 */
    public static final int ALERT_THRESHOLD = 50;

    /** 结构相似度容差：高于此值且无严重标注时视为等价结构，降低误报。 */
    private static final double SIMILARITY_TOLERANCE = 0.95;

    private final SqlFingerprintEngine fingerprintEngine;
    private final HtmlSanitizer htmlSanitizer;

    public DetectionEngine() {
        this.fingerprintEngine = new SqlFingerprintEngine();
        this.htmlSanitizer = new HtmlSanitizer();
    }

    /**
     * SQL 语义检测 —— RASP 层的核心方法。
     *
     * <p>这是本系统技术含量最高的路径：输入是 RASP 探针捕获的
     * <b>拼接完成的真实 SQL</b>，而非 HTTP 参数。因此这里的判定是
     * 确定性的结构比对，而非启发式猜测。
     *
     * @param sql              真实执行的 SQL
     * @param endpoint         接口标识
     * @param baselineSqls     该接口已确认的基线 SQL 列表，可为空
     * @param encodingDepth    来源参数的编码深度，无则传 0
     * @return 检测结果
     */
    public SqlDetectionResult detectSql(String sql, String endpoint,
                                        List<String> baselineSqls, int encodingDepth) {
        long start = System.nanoTime();
        try {
            ParseResult actual = fingerprintEngine.analyze(sql, endpoint);

            // 基线比对：命中即放行（基线优先原则）
            ParseResult matchedBaseline = null;
            AstNode baselineAst = null;
            String baselineFingerprint = "";
            if (baselineSqls != null && !baselineSqls.isEmpty()) {
                for (String baselineSql : baselineSqls) {
                    ParseResult candidate = fingerprintEngine.analyze(baselineSql, endpoint);
                    if (candidate.fingerprint().equals(actual.fingerprint())) {
                        matchedBaseline = candidate;
                        break;
                    }
                    if (baselineAst == null) {
                        baselineAst = candidate.normalizedAst();
                        baselineFingerprint = candidate.fingerprint();
                    }
                }
            }

            if (matchedBaseline != null) {
                // 结构与基线完全一致，确定性放行
                return new SqlDetectionResult(
                        false, Verdict.PASS, Severity.INFO, 0,
                        actual, DiffResult.ofMatched(), List.of(), List.of(),
                        matchedBaseline.fingerprint(), actual.fingerprint(),
                        Map.of(), costMicros(start));
            }

            // 结构差分定位
            DiffResult diff = AstDiffer.diff(baselineAst, actual.normalizedAst());

            // 风险特征检测（冷启动兜底 + 风险加权）
            RiskFeatureDetector.DetectionOutcome sqlRiskOutcome =
                    RiskFeatureDetector.detect(actual, encodingDepth, sql);

            int score = computeRiskScore(diff, sqlRiskOutcome, encodingDepth);
            Severity severity = Severity.fromScore(score);

            // 相似度容差：结构高度相似且无严重标注时视为等价，避免误报
            if (diff.hasBaseline() && diff.similarity() >= SIMILARITY_TOLERANCE
                    && !diff.hasCriticalAnnotation() && !sqlRiskOutcome.hasCriticalFeature()) {
                return new SqlDetectionResult(
                        false, Verdict.PASS, Severity.INFO, score,
                        actual, diff, List.of(), List.of(),
                        baselineFingerprint, actual.fingerprint(),
                        Map.of(), costMicros(start));
            }

            boolean threat = score >= ALERT_THRESHOLD;
            Verdict verdict = score >= BLOCK_THRESHOLD ? Verdict.BLOCK
                    : (threat ? Verdict.MONITOR : Verdict.PASS);

            List<String> evidence = new ArrayList<>(sqlRiskOutcome.evidence());
            for (DiffResult.DiffAnnotation a : diff.annotations()) {
                evidence.add(a.kind().getDisplayName() + ": " + a.detail());
            }

            Map<String, Object> visual = AstVisualExporter.export(
                    baselineAst, actual.normalizedAst(), diff);

            return new SqlDetectionResult(
                    threat, verdict, severity, score,
                    actual, diff, sqlRiskOutcome.featureCodes(), evidence,
                    baselineFingerprint, actual.fingerprint(),
                    visual, costMicros(start));

        } catch (RuntimeException e) {
            // 失效安全：引擎异常时放行并记录，绝不因检测故障阻断业务
            return SqlDetectionResult.engineError(e.getMessage(), costMicros(start));
        }
    }

    /**
     * HTTP 参数的启发式预判 —— 网关层方法。
     *
     * <p>网关只能看到参数文本，无法确知它是否会被拼接进 SQL，
     * 因此这里是<b>启发式判定</b>，存在误报可能。确定性判定由 RASP 层完成。
     * 这正是双层架构的设计动机。
     */
    public ParamDetectionResult detectParameter(String paramName, String value) {
        long start = System.nanoTime();
        try {
            if (value == null || value.isBlank()) {
                return ParamDetectionResult.safe(costMicros(start));
            }

            NormalizeResult normalized = PayloadNormalizer.normalize(value);
            List<String> evidence = new ArrayList<>();
            int score = normalized.riskContribution();
            ThreatType type = null;

            // SQL 注入意图判定：见 detectSqlInjectionIntent 的算法说明
            InjectionProbe probe = detectSqlInjectionIntent(normalized.normalized(),
                    normalized.decodeDepth());
            if (probe.injectionIntent()) {
                score += probe.score();
                evidence.addAll(probe.evidence());
                type = ThreatType.SQL_INJECTION;
            }

            // XSS 判定
            SanitizeResult xss = htmlSanitizer.sanitize(value);
            if (xss.hasThreat()) {
                int xssScore = xss.riskScore();
                if (xssScore > score) {
                    type = ThreatType.XSS;
                }
                score = Math.max(score, xssScore);
                for (SanitizeResult.Removal r : xss.removals()) {
                    evidence.add(r.type().getDisplayName() + ": " + r.detail());
                }
            }

            // 路径穿越判定
            if (com.aegis.core.path.PathTraversalDetector.looksLikeTraversal(value)) {
                int pathScore = 75;
                // 按分值择优确定威胁类型，而非以判定顺序先到先得。
                // 否则含 /etc/passwd 的命令注入载荷会因路径检测先执行
                // 而被误分类为"路径穿越"，掩盖其真实的攻击性质。
                if (pathScore > score || type == null) {
                    type = ThreatType.PATH_TRAVERSAL;
                }
                score = Math.max(score, pathScore);
                evidence.add("参数包含路径上跳语义或指向敏感系统文件");
            }

            // 命令注入判定
            // 该判定要求同时出现 shell 元字符与敏感命令，证据强度高于
            // 单纯的敏感路径匹配，因此赋予更高的分值以在分类中胜出
            if (com.aegis.core.cmd.CommandInjectionDetector.looksLikeCommandInjection(value)) {
                int cmdScore = 85;
                if (cmdScore >= score || type == null) {
                    type = ThreatType.COMMAND_INJECTION;
                }
                score = Math.max(score, cmdScore);
                evidence.add("参数同时包含 shell 元字符与敏感命令");
            }

            score = Math.min(score, 100);
            boolean threat = score >= ALERT_THRESHOLD;
            Verdict verdict = score >= BLOCK_THRESHOLD ? Verdict.BLOCK
                    : (threat ? Verdict.MONITOR : Verdict.PASS);

            return new ParamDetectionResult(threat, verdict, Severity.fromScore(score),
                    score, type == null ? ThreatType.SQL_INJECTION : type,
                    paramName, value, normalized.normalized(),
                    evidence, costMicros(start));

        } catch (RuntimeException e) {
            return ParamDetectionResult.safe(costMicros(start));
        }
    }

    /**
     * [SEC-GW-01] 参数级 SQL 注入意图判定 —— 双探针结构差分法
     *
     * <p><b>问题背景：</b>
     * 网关层拿到的只是参数文本，不知道它会被拼接到 SQL 的什么位置。
     * 朴素做法是把参数值裸拼进一条模板 SQL 再解析，但这会产生严重误报：
     * 普通文本 {@code "hello world"} 拼成 {@code "WHERE x = hello world"} 后
     * 无法解析为单一表达式，被误判为堆叠查询。
     *
     * <p><b>本方法的解法：</b>
     * 模拟真实的字符串拼接场景，将参数值作为<b>字符串字面量</b>注入探针模板：
     * <pre>
     *   基准模板：SELECT * FROM t WHERE x = '&lt;安全占位&gt;'
     *   实际探针：SELECT * FROM t WHERE x = '&lt;参数值&gt;'
     * </pre>
     * 若参数是普通文本，它始终被包裹在引号内，探针结构与基准<b>完全一致</b>；
     * 只有当参数含有能够<b>闭合引号并逃逸出字面量上下文</b>的内容时
     * （这正是 SQL 注入的本质），探针才会产生额外的语法结构。
     *
     * <p>随后对基准与探针做结构差分，仅当出现确定性攻击标志
     * （恒真式、UNION、堆叠、危险函数等）时才判定为注入意图。
     * 由此实现"对正常文本零误报，对逃逸载荷高检出"。
     *
     * <p>同时使用数值上下文探针，覆盖 {@code WHERE id = 1 OR 1=1} 这类
     * 无需闭合引号的数值型注入。
     *
     * @param normalizedValue 已归一化的参数值
     * @param encodingDepth   编码深度
     * @return 注入意图判定结果
     */
    private InjectionProbe detectSqlInjectionIntent(String normalizedValue, int encodingDepth) {
        List<String> evidence = new ArrayList<>();
        int maxScore = 0;
        boolean intent = false;

        // ---- 探针一：字符串上下文（主判据）----
        // 模拟 WHERE col = '<value>' 的拼接场景。
        // 普通文本被完整包裹在引号内，不产生额外结构；
        // 只有能闭合引号并逃逸的载荷才会改变语法结构。
        String stringProbe = "SELECT * FROM t WHERE c = '" + normalizedValue + "'";
        InjectionProbe stringResult = evaluateProbe(stringProbe, normalizedValue,
                encodingDepth, true);
        if (stringResult.injectionIntent()) {
            intent = true;
            maxScore = Math.max(maxScore, stringResult.score());
            evidence.addAll(stringResult.evidence());
        }

        // ---- 探针二：数值上下文（仅对数值型参数启用）----
        // 模拟 WHERE id = <value> 的拼接场景，覆盖 "1 OR 1=1" 这类
        // 无需闭合引号的数值型注入。
        //
        // [关键] 仅当参数以数字开头时才启用此探针。原因是：将任意文本
        // 裸拼进 SQL 会因无法解析而产生虚假的"堆叠查询"特征
        // （如 "hello world" 会被切分为两条语句），造成严重误报。
        // 数值型参数天然不含空格分隔的自由文本，可安全使用此探针。
        if (looksNumericPrefixed(normalizedValue)) {
            String numericProbe = "SELECT * FROM t WHERE c = " + normalizedValue;
            InjectionProbe numericResult = evaluateProbe(numericProbe, normalizedValue,
                    encodingDepth, false);
            if (numericResult.injectionIntent()) {
                intent = true;
                maxScore = Math.max(maxScore, numericResult.score());
                for (String e : numericResult.evidence()) {
                    if (!evidence.contains(e)) {
                        evidence.add(e);
                    }
                }
            }
        }

        return new InjectionProbe(intent, maxScore, evidence);
    }

    /**
     * 判断参数值是否为数值型（以数字开头且不含自由文本空格）。
     *
     * <p>用于决定是否启用数值上下文探针，避免自由文本触发解析噪声。
     */
    private boolean looksNumericPrefixed(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        char first = value.charAt(0);
        if (!Character.isDigit(first) && first != '-' && first != '+') {
            return false;
        }
        // 数值型参数后若跟随大量自由文本单词，说明并非真正的数值上下文
        String[] words = value.trim().split("\\s+");
        if (words.length <= 1) {
            return true;
        }
        // 允许 "1 OR 1=1" 这类注入载荷（含 SQL 关键字），
        // 排除 "1 个苹果和 2 个梨" 这类自然语言
        String upper = value.toUpperCase();
        return upper.contains("OR") || upper.contains("AND") || upper.contains("UNION")
                || upper.contains("SELECT") || value.contains("=") || value.contains(";")
                || value.contains("--") || value.contains("/*");
    }

    /**
     * 评估单个探针：解析后仅采纳确定性攻击特征。
     *
     * <p>关键在于<b>排除解析噪声</b>：普通文本拼接可能导致解析器产生
     * UNKNOWN 节点或语句切分，这些不能作为攻击判据。只有恒真式、
     * UNION、危险函数等无法由正常文本偶然产生的结构才被采纳。
     *
     * @param trustStacked 是否采纳"堆叠查询"特征。仅字符串上下文探针可信任——
     *                     该探针中普通文本被引号包裹不会产生语句切分，
     *                     一旦出现堆叠即说明发生了引号逃逸。
     */
    private InjectionProbe evaluateProbe(String probeSql, String rawValue,
                                         int encodingDepth, boolean trustStacked) {
        ParseResult result = fingerprintEngine.analyze(probeSql, "gw-probe");
        RiskFeatureDetector.DetectionOutcome outcome =
                RiskFeatureDetector.detect(result, encodingDepth, probeSql);

        List<String> evidence = new ArrayList<>();
        int score = 0;
        boolean deterministicHit = false;

        for (var feature : outcome.features()) {
            // 仅采纳确定性攻击特征。解析失败、逻辑运算符增多等
            // 可能由正常文本触发的特征在网关层不作为判据，
            // 交由 RASP 层用真实 SQL 做确定性判定。
            switch (feature) {
                case TAUTOLOGY, UNION_QUERY,
                     TIME_BLIND_FUNCTION, OUT_OF_BAND_FUNCTION,
                     SYSTEM_TABLE, DDL_OPERATION, INLINE_COMMENT -> {
                    score += feature.getWeight();
                    deterministicHit = true;
                    evidence.add(feature.getDisplayName() + ": " + feature.getDescription());
                }
                case STACKED_QUERY -> {
                    if (trustStacked) {
                        score += feature.getWeight();
                        deterministicHit = true;
                        evidence.add(feature.getDisplayName() + ": " + feature.getDescription());
                    }
                }
                case COMMENT_TRUNCATION -> {
                    // 注释截断需谨慎：正常文本可能包含 -- 或 #
                    // 仅当同时存在引号闭合迹象时才采纳
                    if (rawValue.contains("'") || rawValue.contains("\"")) {
                        score += feature.getWeight();
                        evidence.add(feature.getDisplayName() + ": " + feature.getDescription());
                    }
                }
                default -> {
                    // 其余特征不在网关层作为独立判据
                }
            }
        }

        // [关键] 命中任一确定性攻击特征即判定为注入意图。
        // 这些特征（恒真式、UNION、危险函数等）无法由正常业务参数
        // 在探针中偶然产生，因此单项命中即足以定性，
        // 无需依赖多项累加达到阈值——后者会导致单一手法的攻击被漏报。
        if (deterministicHit) {
            score = Math.max(score, BLOCK_THRESHOLD);
        }

        return new InjectionProbe(deterministicHit || score >= ALERT_THRESHOLD,
                Math.min(score, 100), evidence);
    }

    /**
     * 参数注入意图探测结果。
     *
     * @param injectionIntent 是否存在注入意图
     * @param score           风险评分
     * @param evidence        判定依据
     */
    private record InjectionProbe(boolean injectionIntent, int score, List<String> evidence) {
    }

    /** HTML 内容净化，供靶场安全实现调用。 */
    public SanitizeResult sanitizeHtml(String input) {
        return htmlSanitizer.sanitize(input);
    }

    /** 计算 SQL 的结构指纹，供基线学习使用。 */
    public String fingerprint(String sql, String endpoint) {
        return fingerprintEngine.fingerprint(sql, endpoint);
    }

    /** 解析 SQL 并导出可视化树，供基线管理页展示。 */
    public Map<String, Object> exportAst(String sql, String endpoint) {
        ParseResult result = fingerprintEngine.analyze(sql, endpoint);
        return AstVisualExporter.exportPlain(result.normalizedAst());
    }

    public void invalidateCache() {
        fingerprintEngine.invalidateAll();
    }

    /**
     * 综合风险评分。
     *
     * <p>三个来源加权求和：结构偏离、差分标注、风险特征。
     */
    private int computeRiskScore(DiffResult diff,
                                 RiskFeatureDetector.DetectionOutcome risk,
                                 int encodingDepth) {
        int score = 0;

        // 结构偏离贡献：相似度越低，偏离越大
        if (diff.hasBaseline()) {
            score += (int) ((1.0 - diff.similarity()) * 50);
        }

        // 差分标注贡献
        score += diff.annotationScore();

        // 风险特征贡献
        score += risk.score();

        // 编码可疑度
        score += encodingDepth * 5;

        return Math.min(score, 100);
    }

    private long costMicros(long startNanos) {
        return (System.nanoTime() - startNanos) / 1000;
    }

    /**
     * SQL 检测结果。
     */
    public record SqlDetectionResult(
            boolean threat,
            Verdict verdict,
            Severity severity,
            int riskScore,
            ParseResult parseResult,
            DiffResult diff,
            List<String> riskFeatures,
            List<String> evidence,
            String baselineFingerprint,
            String actualFingerprint,
            Map<String, Object> visualTree,
            long costMicros
    ) {
        static SqlDetectionResult engineError(String message, long cost) {
            return new SqlDetectionResult(false, Verdict.PASS, Severity.INFO, 0,
                    null, DiffResult.ofNoBaseline(), List.of(),
                    List.of("检测引擎异常，已按失效安全策略放行: " + message),
                    "", "", Map.of(), cost);
        }

        public boolean shouldBlock() {
            return verdict == Verdict.BLOCK;
        }
    }

    /**
     * HTTP 参数检测结果。
     */
    public record ParamDetectionResult(
            boolean threat,
            Verdict verdict,
            Severity severity,
            int riskScore,
            ThreatType threatType,
            String paramName,
            String rawValue,
            String normalizedValue,
            List<String> evidence,
            long costMicros
    ) {
        static ParamDetectionResult safe(long cost) {
            return new ParamDetectionResult(false, Verdict.PASS, Severity.INFO, 0,
                    ThreatType.SQL_INJECTION, "", "", "", List.of(), cost);
        }

        public boolean shouldBlock() {
            return verdict == Verdict.BLOCK;
        }
    }
}
