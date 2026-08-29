package com.aegis.console.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 检测事件持久化实体。
 *
 * <p><b>哈希链设计：</b>每条记录保存前一条记录的哈希值，形成链式结构。
 * 任何对历史记录的篡改都会导致后续所有记录的哈希校验失败，
 * 由此提供审计日志的<b>不可否认性</b>（对应威胁 T-09）。
 */
@Entity
@Table(name = "t_detection_event", indexes = {
        @Index(name = "idx_trace", columnList = "traceId"),
        @Index(name = "idx_created", columnList = "createdAt"),
        @Index(name = "idx_threat", columnList = "threatType"),
        @Index(name = "idx_severity", columnList = "severity"),
        @Index(name = "idx_source_ip", columnList = "sourceIp")
})
public class DetectionEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 36, unique = true)
    private String eventId;

    /** 贯穿网关层与探针层的追踪标识，用于还原完整攻击证据链。 */
    @Column(length = 36)
    private String traceId;

    private Instant createdAt;

    /** 事件产生层次：GATEWAY 或 RASP。 */
    @Column(length = 16)
    private String layer;

    @Column(length = 32)
    private String threatType;

    @Column(length = 16)
    private String severity;

    @Column(length = 16)
    private String verdict;

    @Column(length = 45)
    private String sourceIp;

    @Column(length = 10)
    private String method;

    @Column(length = 512)
    private String uri;

    @Column(length = 256)
    private String endpoint;

    @Column(length = 128)
    private String paramName;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String rawPayload;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String normalizedPayload;

    /** RASP 层捕获的真实 SQL，是确定性判定的依据。 */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String rawSql;

    @Column(length = 64)
    private String baselineFingerprint;

    @Column(length = 64)
    private String actualFingerprint;

    /** AST 结构相似度（Jaccard 系数）。 */
    private Double similarity;

    /** 结构差分结果与可视化树，JSON 格式，供前端渲染。 */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String diffJson;

    @Column(length = 512)
    private String riskFeatures;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String evidence;

    private Integer riskScore;

    private Long detectionCostMicros;

    /** 前一条记录的哈希，构成哈希链。 */
    @Column(length = 64)
    private String prevHash;

    /** 本条记录的哈希。 */
    @Column(length = 64)
    private String hash;

    // ==================== Getter / Setter ====================

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEventId() { return eventId; }
    public void setEventId(String eventId) { this.eventId = eventId; }

    public String getTraceId() { return traceId; }
    public void setTraceId(String traceId) { this.traceId = traceId; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public String getLayer() { return layer; }
    public void setLayer(String layer) { this.layer = layer; }

    public String getThreatType() { return threatType; }
    public void setThreatType(String threatType) { this.threatType = threatType; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getUri() { return uri; }
    public void setUri(String uri) { this.uri = uri; }

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

    public String getParamName() { return paramName; }
    public void setParamName(String paramName) { this.paramName = paramName; }

    public String getRawPayload() { return rawPayload; }
    public void setRawPayload(String rawPayload) { this.rawPayload = rawPayload; }

    public String getNormalizedPayload() { return normalizedPayload; }
    public void setNormalizedPayload(String v) { this.normalizedPayload = v; }

    public String getRawSql() { return rawSql; }
    public void setRawSql(String rawSql) { this.rawSql = rawSql; }

    public String getBaselineFingerprint() { return baselineFingerprint; }
    public void setBaselineFingerprint(String v) { this.baselineFingerprint = v; }

    public String getActualFingerprint() { return actualFingerprint; }
    public void setActualFingerprint(String v) { this.actualFingerprint = v; }

    public Double getSimilarity() { return similarity; }
    public void setSimilarity(Double similarity) { this.similarity = similarity; }

    public String getDiffJson() { return diffJson; }
    public void setDiffJson(String diffJson) { this.diffJson = diffJson; }

    public String getRiskFeatures() { return riskFeatures; }
    public void setRiskFeatures(String riskFeatures) { this.riskFeatures = riskFeatures; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public Integer getRiskScore() { return riskScore; }
    public void setRiskScore(Integer riskScore) { this.riskScore = riskScore; }

    public Long getDetectionCostMicros() { return detectionCostMicros; }
    public void setDetectionCostMicros(Long v) { this.detectionCostMicros = v; }

    public String getPrevHash() { return prevHash; }
    public void setPrevHash(String prevHash) { this.prevHash = prevHash; }

    public String getHash() { return hash; }
    public void setHash(String hash) { this.hash = hash; }
}
