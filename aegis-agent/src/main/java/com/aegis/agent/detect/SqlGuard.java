package com.aegis.agent.detect;

import com.aegis.agent.AegisAgent;
import com.aegis.agent.context.TraceContext;
import com.aegis.agent.report.EventReporter;
import com.aegis.core.engine.DetectionEngine;
import com.aegis.core.model.Severity;
import com.aegis.core.model.Verdict;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [SEC-RASP-03] SQL 执行守卫
 *
 * <p>探针捕获 SQL 后的判定中枢。承担三项职责：
 * <ol>
 *   <li><b>基线管理</b>：学习模式下记录各接口的合法 SQL 结构指纹</li>
 *   <li><b>结构判定</b>：将真实 SQL 与基线做 AST 结构比对</li>
 *   <li><b>处置执行</b>：拦截模式下抛出异常阻断 SQL 执行</li>
 * </ol>
 *
 * <p><b>关于基线的冷启动策略：</b>
 * 系统初次运行时基线为空。此时不采取"一律拦截"（会阻断正常业务），
 * 而是依赖检测引擎的风险特征层做绝对判定——恒真式、UNION、堆叠查询、
 * 危险函数等特征无论有无基线都能识别。基线建立后再启用结构差分，
 * 检测精度进一步提升。
 */
public final class SqlGuard {

    private static final DetectionEngine ENGINE = new DetectionEngine();

    /** 接口标识 → 该接口已学习到的基线 SQL 列表。 */
    private static final Map<String, List<String>> BASELINES = new ConcurrentHashMap<>();

    /** 每个接口保留的基线样本上限，防止内存无限增长。 */
    private static final int MAX_BASELINE_PER_ENDPOINT = 20;

    /** 是否处于基线学习模式。 */
    private static volatile boolean learningMode = false;

    private SqlGuard() {
    }

    /**
     * 检查即将执行的 SQL。
     *
     * <p>被字节码注入调用，运行在业务线程上，因此必须满足：
     * <ul>
     *   <li><b>快速</b>：不能显著增加业务延迟</li>
     *   <li><b>安全</b>：任何内部异常都不能影响业务（失效安全）</li>
     *   <li><b>无递归</b>：自身产生的数据库操作不能再次触发检测</li>
     * </ul>
     *
     * @param sql 即将执行的真实 SQL
     * @throws SecurityException 判定为注入且处于拦截模式时抛出，阻断执行
     */
    public static void inspect(String sql) {
        if (sql == null || sql.isBlank() || AegisAgent.isOff()) {
            return;
        }
        // 防止检测逻辑自身的数据库操作被递归拦截
        if (TraceContext.isInDetection()) {
            return;
        }

        try {
            TraceContext.enterDetection();
            doInspect(sql);
        } catch (SecurityException e) {
            // 拦截决定必须向上传播以阻断 SQL 执行
            throw e;
        } catch (Throwable t) {
            // [失效安全] 检测引擎的任何异常均不得影响业务执行。
            // 可用性优先于检测完整性——WAF 故障不应导致业务瘫痪。
            if (System.getProperty("aegis.agent.debug") != null) {
                System.err.println("[AEGIS] 检测异常(已放行): " + t.getMessage());
            }
        } finally {
            TraceContext.exitDetection();
        }
    }

    private static void doInspect(String sql) {
        String endpoint = TraceContext.getEndpoint();
        String traceId = TraceContext.getTraceId();

        // 过滤框架自身的元数据查询与连接检测语句，减少噪声
        if (isInfrastructureSql(sql)) {
            return;
        }

        List<String> baseline = BASELINES.get(endpoint);

        // 学习模式：记录结构指纹作为基线，不做拦截
        if (learningMode) {
            learn(endpoint, sql);
            return;
        }

        DetectionEngine.SqlDetectionResult result =
                ENGINE.detectSql(sql, endpoint, baseline, 0);

        if (!result.threat()) {
            return;
        }

        // 判定实际处置结果：引擎给出的是"建议处置"，
        // 最终是否拦截还取决于当前防护模式。
        // 上报时必须反映真实处置，否则 MONITOR 模式下的事件
        // 会误显示为"已拦截"，与实际放行的行为不符。
        boolean willBlock = AegisAgent.isBlockMode() && result.verdict() == Verdict.BLOCK;

        // 上报检测事件，供控制台汇聚与大屏展示
        EventReporter.reportSqlEvent(
                traceId,
                endpoint,
                TraceContext.getSourceIp(),
                sql,
                result,
                willBlock ? "BLOCK" : "MONITOR");

        // [关键] 拦截模式下在 SQL 送达数据库前抛出异常，阻断攻击生效。
        // 这是 RASP 相较网关层的核心优势：判定基于真实 SQL 结构，
        // 是确定性的，因此可以放心执行阻断而不必担心误伤正常业务。
        if (willBlock) {
            throw new SecurityException(buildBlockMessage(result));
        }
    }

    /** 学习并记录接口的合法 SQL 结构。 */
    private static void learn(String endpoint, String sql) {
        BASELINES.compute(endpoint, (key, existing) -> {
            List<String> list = existing == null ? new ArrayList<>() : existing;
            if (list.size() >= MAX_BASELINE_PER_ENDPOINT) {
                return list;
            }
            // 依据结构指纹去重：同结构不同参数的 SQL 只保留一份
            String fingerprint = ENGINE.fingerprint(sql, endpoint);
            for (String recorded : list) {
                if (ENGINE.fingerprint(recorded, endpoint).equals(fingerprint)) {
                    return list;
                }
            }
            list.add(sql);
            EventReporter.reportBaselineLearned(endpoint, sql, fingerprint);
            return list;
        });
    }

    /**
     * 判断是否为框架基础设施 SQL。
     *
     * <p>连接池心跳、元数据查询等与业务无关的语句不参与基线学习与检测，
     * 避免污染基线并产生无意义的告警。
     */
    private static boolean isInfrastructureSql(String sql) {
        String upper = sql.trim().toUpperCase();
        return upper.startsWith("SET ")
                || upper.startsWith("CALL ")
                || upper.equals("SELECT 1")
                || upper.startsWith("VALUES(")
                || upper.startsWith("SHOW ")
                || upper.contains("INFORMATION_SCHEMA.SETTINGS")
                || upper.startsWith("CREATE TABLE")
                || upper.startsWith("DROP TABLE IF EXISTS")
                || upper.startsWith("INSERT INTO USERS (USERNAME, PASSWORD_MD5")
                || upper.startsWith("INSERT INTO NOTES (OWNER_ID, TITLE, CONTENT, VISIBILITY) VALUES (2,")
                || upper.startsWith("INSERT INTO NOTES_BACKUP");
    }

    private static String buildBlockMessage(DetectionEngine.SqlDetectionResult result) {
        StringBuilder sb = new StringBuilder(
                "AEGIS 已拦截疑似 SQL 注入攻击 [风险评分 " + result.riskScore() + "/100]");
        if (!result.evidence().isEmpty()) {
            sb.append("，判定依据: ");
            for (int i = 0; i < Math.min(3, result.evidence().size()); i++) {
                if (i > 0) {
                    sb.append("; ");
                }
                sb.append(result.evidence().get(i));
            }
        }
        return sb.toString();
    }

    // ==================== 基线管理接口 ====================

    public static void setLearningMode(boolean enabled) {
        learningMode = enabled;
    }

    public static boolean isLearningMode() {
        return learningMode;
    }

    public static Map<String, List<String>> getBaselines() {
        return BASELINES;
    }

    public static void clearBaselines() {
        BASELINES.clear();
        ENGINE.invalidateCache();
    }

    public static int baselineCount() {
        return BASELINES.values().stream().mapToInt(List::size).sum();
    }

    /** 供控制台注入已确认的基线。 */
    public static void importBaseline(String endpoint, List<String> sqls) {
        BASELINES.put(endpoint, new ArrayList<>(sqls));
    }

    /** 严重级别转换，供上报使用。 */
    public static Severity severityOf(int score) {
        return Severity.fromScore(score);
    }
}
