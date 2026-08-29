package com.aegis.console.entity;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * SQL 基线实体。
 *
 * <p>存储各业务接口的合法 SQL 结构指纹。基线是结构差分检测的参照系：
 * 只有当实际执行的 SQL 指纹与基线全部失配时，才进入差分定位与风险评分流程。
 */
@Entity
@Table(name = "t_sql_baseline", indexes = {
        @Index(name = "idx_endpoint", columnList = "endpoint"),
        @Index(name = "idx_fingerprint", columnList = "fingerprint")
})
public class SqlBaselineEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 接口标识，形如 {@code GET:/api/notes/search}。 */
    @Column(length = 256)
    private String endpoint;

    /** 结构指纹，与 endpoint 绑定计算。 */
    @Column(length = 64)
    private String fingerprint;

    /** 归一化后的 SQL 模板，用于人工审核。 */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String normalizedSql;

    /** 原始样本 SQL。 */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String sampleSql;

    /** AST 结构 JSON，供前端可视化展示。 */
    @Lob
    @Column(columnDefinition = "CLOB")
    private String astJson;

    private Long hitCount;

    /** 状态：LEARNING（学习中）/ CONFIRMED（已确认）/ DISABLED（已禁用）。 */
    @Column(length = 16)
    private String status;

    private Instant firstSeen;
    private Instant lastSeen;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

    public String getNormalizedSql() { return normalizedSql; }
    public void setNormalizedSql(String normalizedSql) { this.normalizedSql = normalizedSql; }

    public String getSampleSql() { return sampleSql; }
    public void setSampleSql(String sampleSql) { this.sampleSql = sampleSql; }

    public String getAstJson() { return astJson; }
    public void setAstJson(String astJson) { this.astJson = astJson; }

    public Long getHitCount() { return hitCount; }
    public void setHitCount(Long hitCount) { this.hitCount = hitCount; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Instant getFirstSeen() { return firstSeen; }
    public void setFirstSeen(Instant firstSeen) { this.firstSeen = firstSeen; }

    public Instant getLastSeen() { return lastSeen; }
    public void setLastSeen(Instant lastSeen) { this.lastSeen = lastSeen; }
}
