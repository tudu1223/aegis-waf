package com.aegis.core.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 检测事件。
 *
 * <p>这是贯穿网关层与 RASP 层的统一事件模型，也是控制台存储、
 * 大屏展示与安全取证的核心数据载体。
 *
 * <p><b>TraceID 的关键作用：</b>同一次 HTTP 请求在网关层与 RASP 层
 * 产生的事件共享同一 TraceID，由此可还原完整的攻击证据链：
 * HTTP 请求 → 被污染的参数 → 生成的真实 SQL → AST 结构变异 → 处置结果。
 * 这是"网关 + RASP 双层联动"架构的价值所在。
 */
public record DetectionEvent(
        String eventId,
        String traceId,
        Instant timestamp,
        Layer layer,
        ThreatType threatType,
        Severity severity,
        Verdict verdict,
        String sourceIp,
        String method,
        String uri,
        String endpoint,
        String paramName,
        String rawPayload,
        String normalizedPayload,
        String rawSql,
        String baselineFingerprint,
        String actualFingerprint,
        double similarity,
        String diffJson,
        List<String> riskFeatures,
        List<String> evidence,
        int riskScore,
        long detectionCostMicros,
        Map<String, String> extra
) {

    /** 事件产生的层次。 */
    public enum Layer {
        /** 网关层：基于 HTTP 参数的启发式预判 */
        GATEWAY("网关层"),
        /** RASP 层：基于真实 SQL 的确定性判定 */
        RASP("探针层");

        private final String displayName;

        Layer(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /** 是否为需要在报告中给出修复证明的高危事件（CVSS ≥ 7.0 等价）。 */
    public boolean requiresRemediation() {
        return severity.isHighRisk();
    }

    /** 构建器，字段较多时避免冗长的构造调用。 */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String eventId = java.util.UUID.randomUUID().toString();
        private String traceId = "";
        private Instant timestamp = Instant.now();
        private Layer layer = Layer.GATEWAY;
        private ThreatType threatType = ThreatType.SQL_INJECTION;
        private Severity severity = Severity.INFO;
        private Verdict verdict = Verdict.PASS;
        private String sourceIp = "";
        private String method = "";
        private String uri = "";
        private String endpoint = "";
        private String paramName = "";
        private String rawPayload = "";
        private String normalizedPayload = "";
        private String rawSql = "";
        private String baselineFingerprint = "";
        private String actualFingerprint = "";
        private double similarity = 0;
        private String diffJson = "";
        private List<String> riskFeatures = List.of();
        private List<String> evidence = List.of();
        private int riskScore = 0;
        private long detectionCostMicros = 0;
        private Map<String, String> extra = Map.of();

        public Builder eventId(String v) { this.eventId = v; return this; }
        public Builder traceId(String v) { this.traceId = v; return this; }
        public Builder timestamp(Instant v) { this.timestamp = v; return this; }
        public Builder layer(Layer v) { this.layer = v; return this; }
        public Builder threatType(ThreatType v) { this.threatType = v; return this; }
        public Builder severity(Severity v) { this.severity = v; return this; }
        public Builder verdict(Verdict v) { this.verdict = v; return this; }
        public Builder sourceIp(String v) { this.sourceIp = v; return this; }
        public Builder method(String v) { this.method = v; return this; }
        public Builder uri(String v) { this.uri = v; return this; }
        public Builder endpoint(String v) { this.endpoint = v; return this; }
        public Builder paramName(String v) { this.paramName = v; return this; }
        public Builder rawPayload(String v) { this.rawPayload = v; return this; }
        public Builder normalizedPayload(String v) { this.normalizedPayload = v; return this; }
        public Builder rawSql(String v) { this.rawSql = v; return this; }
        public Builder baselineFingerprint(String v) { this.baselineFingerprint = v; return this; }
        public Builder actualFingerprint(String v) { this.actualFingerprint = v; return this; }
        public Builder similarity(double v) { this.similarity = v; return this; }
        public Builder diffJson(String v) { this.diffJson = v; return this; }
        public Builder riskFeatures(List<String> v) { this.riskFeatures = v; return this; }
        public Builder evidence(List<String> v) { this.evidence = v; return this; }
        public Builder riskScore(int v) { this.riskScore = v; return this; }
        public Builder detectionCostMicros(long v) { this.detectionCostMicros = v; return this; }
        public Builder extra(Map<String, String> v) { this.extra = v; return this; }

        public DetectionEvent build() {
            return new DetectionEvent(eventId, traceId, timestamp, layer, threatType,
                    severity, verdict, sourceIp, method, uri, endpoint, paramName,
                    rawPayload, normalizedPayload, rawSql, baselineFingerprint,
                    actualFingerprint, similarity, diffJson, riskFeatures, evidence,
                    riskScore, detectionCostMicros, extra);
        }
    }
}
