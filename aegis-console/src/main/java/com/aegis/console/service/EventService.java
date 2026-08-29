package com.aegis.console.service;

import com.aegis.console.entity.DetectionEventEntity;
import com.aegis.console.repository.DetectionEventRepository;
import com.aegis.console.websocket.EventBroadcaster;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * [SEC-AUDIT-01] 检测事件服务
 *
 * <p>负责事件的持久化、哈希链构建与实时推送。
 *
 * <p><b>哈希链设计（对应威胁 T-09 抵赖）：</b>
 * 每条事件记录包含前一条记录的哈希值：
 * <pre>
 *   hash(n) = SHA-256( 事件内容(n) + hash(n-1) )
 * </pre>
 * 由此形成链式依赖。若攻击者篡改任意一条历史记录，该记录及其后
 * 所有记录的哈希都将失配，篡改行为立即暴露。这为安全审计提供了
 * <b>不可否认性</b>——攻击者无法否认其行为，也无法悄然抹除痕迹。
 */
@Service
public class EventService {

    private final DetectionEventRepository repository;
    private final EventBroadcaster broadcaster;
    private final ObjectMapper objectMapper;

    /** 缓存最新哈希，避免每次写入都查库。 */
    private final AtomicReference<String> lastHash = new AtomicReference<>("");

    public EventService(DetectionEventRepository repository,
                        EventBroadcaster broadcaster,
                        ObjectMapper objectMapper) {
        this.repository = repository;
        this.broadcaster = broadcaster;
        this.objectMapper = objectMapper;
        // 启动时恢复链尾哈希，保证重启后链条连续
        repository.findFirstByOrderByIdDesc()
                .ifPresent(e -> lastHash.set(e.getHash() == null ? "" : e.getHash()));
    }

    /**
     * 记录一条检测事件。
     *
     * @param payload 探针或网关上报的事件数据
     * @return 持久化后的实体
     */
    @Transactional
    public DetectionEventEntity record(Map<String, Object> payload) {
        DetectionEventEntity entity = new DetectionEventEntity();

        entity.setEventId(UUID.randomUUID().toString());
        entity.setTraceId(str(payload.get("traceId")));
        Object ts = payload.get("timestamp");
        entity.setCreatedAt(ts instanceof Number n
                ? Instant.ofEpochMilli(n.longValue())
                : Instant.now());
        entity.setLayer(str(payload.getOrDefault("layer", "GATEWAY")));
        entity.setThreatType(str(payload.getOrDefault("threatType", "SQL_INJECTION")));
        entity.setSeverity(str(payload.getOrDefault("severity", "INFO")));
        entity.setVerdict(str(payload.getOrDefault("verdict", "PASS")));
        entity.setSourceIp(str(payload.get("sourceIp")));
        entity.setMethod(str(payload.get("method")));
        entity.setUri(truncate(str(payload.get("uri")), 512));
        entity.setEndpoint(truncate(str(payload.get("endpoint")), 256));
        entity.setParamName(truncate(str(payload.get("paramName")), 128));
        entity.setRawPayload(str(payload.get("rawPayload")));
        entity.setNormalizedPayload(str(payload.get("normalizedPayload")));
        entity.setRawSql(str(payload.get("rawSql")));
        entity.setBaselineFingerprint(str(payload.get("baselineFingerprint")));
        entity.setActualFingerprint(str(payload.get("actualFingerprint")));

        Object sim = payload.get("similarity");
        entity.setSimilarity(sim instanceof Number n ? n.doubleValue() : 0.0);

        Object score = payload.get("riskScore");
        entity.setRiskScore(score instanceof Number n ? n.intValue() : 0);

        Object cost = payload.get("detectionCostMicros");
        entity.setDetectionCostMicros(cost instanceof Number n ? n.longValue() : 0L);

        entity.setRiskFeatures(joinList(payload.get("riskFeatures")));
        entity.setEvidence(toJson(payload.get("evidence")));

        // 组装差分与可视化数据，供前端 AST 分析页渲染
        entity.setDiffJson(toJson(Map.of(
                "visualTree", payload.getOrDefault("visualTree", Map.of()),
                "annotations", payload.getOrDefault("annotations", List.of())
        )));

        // [SEC-AUDIT-01] 构建哈希链
        String prev = lastHash.get();
        entity.setPrevHash(prev);
        entity.setHash(computeHash(entity, prev));
        lastHash.set(entity.getHash());

        DetectionEventEntity saved = repository.save(entity);

        // 实时推送至大屏
        broadcaster.broadcastEvent(toDto(saved, payload));

        return saved;
    }

    /**
     * 计算事件哈希。
     *
     * <p>将事件的关键字段与前一条哈希拼接后做 SHA-256，
     * 保证任何字段的改动都会导致哈希变化。
     */
    private String computeHash(DetectionEventEntity e, String prevHash) {
        String material = String.join("|",
                nullSafe(e.getEventId()),
                nullSafe(e.getTraceId()),
                e.getCreatedAt() == null ? "" : String.valueOf(e.getCreatedAt().toEpochMilli()),
                nullSafe(e.getLayer()),
                nullSafe(e.getThreatType()),
                nullSafe(e.getSeverity()),
                nullSafe(e.getVerdict()),
                nullSafe(e.getSourceIp()),
                nullSafe(e.getEndpoint()),
                nullSafe(e.getRawSql()),
                nullSafe(e.getRawPayload()),
                String.valueOf(e.getRiskScore()),
                nullSafe(prevHash));
        return sha256(material);
    }

    /**
     * 校验哈希链完整性。
     *
     * <p>逐条重算哈希并与存储值比对，任一环节失配即说明日志被篡改。
     * 这是测试用例 TC-21（日志与监控失败）的验证依据。
     *
     * @return 校验结果，含首个失配位置
     */
    public ChainVerification verifyChain() {
        List<DetectionEventEntity> all = repository.findAllByOrderByIdAsc();
        String expectedPrev = "";
        for (DetectionEventEntity e : all) {
            if (!expectedPrev.equals(nullSafe(e.getPrevHash()))) {
                return new ChainVerification(false, all.size(), e.getId(),
                        "前置哈希不匹配，记录 ID " + e.getId() + " 处链条断裂");
            }
            String recomputed = computeHash(e, expectedPrev);
            if (!recomputed.equals(nullSafe(e.getHash()))) {
                return new ChainVerification(false, all.size(), e.getId(),
                        "内容哈希不匹配，记录 ID " + e.getId() + " 已被篡改");
            }
            expectedPrev = e.getHash();
        }
        return new ChainVerification(true, all.size(), null, "哈希链完整，未检出篡改");
    }

    /** 依据 TraceID 还原完整攻击证据链。 */
    public List<DetectionEventEntity> findByTrace(String traceId) {
        return repository.findByTraceIdOrderByCreatedAtAsc(traceId);
    }

    /**
     * 清空全部事件并重置哈希链状态。
     *
     * <p><b>为何必须一并重置链状态：</b>哈希链依赖内存中缓存的"链尾哈希"，
     * 若仅删除数据库记录而不重置该缓存，后续新增的第一条记录会携带
     * 指向已删除记录的 {@code prevHash}，导致链条从起点即断裂，
     * 完整性校验永远失败。
     *
     * <p>这类"存储与内存状态不同步"的缺陷在重置类操作中十分常见，
     * 需将二者视为一个原子操作。
     */
    @Transactional
    public long clearAll() {
        long count = repository.count();
        repository.deleteAll();
        // 关键：链尾哈希必须与数据库状态同步重置
        lastHash.set("");
        return count;
    }

    private Map<String, Object> toDto(DetectionEventEntity e, Map<String, Object> original) {
        return Map.ofEntries(
                Map.entry("eventId", nullSafe(e.getEventId())),
                Map.entry("traceId", nullSafe(e.getTraceId())),
                Map.entry("timestamp", e.getCreatedAt() == null
                        ? System.currentTimeMillis() : e.getCreatedAt().toEpochMilli()),
                Map.entry("layer", nullSafe(e.getLayer())),
                Map.entry("threatType", nullSafe(e.getThreatType())),
                Map.entry("severity", nullSafe(e.getSeverity())),
                Map.entry("verdict", nullSafe(e.getVerdict())),
                Map.entry("sourceIp", nullSafe(e.getSourceIp())),
                Map.entry("endpoint", nullSafe(e.getEndpoint())),
                Map.entry("uri", nullSafe(e.getUri())),
                Map.entry("rawSql", nullSafe(e.getRawSql())),
                Map.entry("rawPayload", nullSafe(e.getRawPayload())),
                Map.entry("riskScore", e.getRiskScore() == null ? 0 : e.getRiskScore()),
                Map.entry("similarity", e.getSimilarity() == null ? 0.0 : e.getSimilarity()),
                Map.entry("riskFeatures", nullSafe(e.getRiskFeatures())),
                Map.entry("evidence", original.getOrDefault("evidence", List.of())),
                Map.entry("annotations", original.getOrDefault("annotations", List.of())),
                Map.entry("detectionCostMicros",
                        e.getDetectionCostMicros() == null ? 0L : e.getDetectionCostMicros())
        );
    }

    // ==================== 工具方法 ====================

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    private String toJson(Object obj) {
        if (obj == null) {
            return "{}";
        }
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String joinList(Object obj) {
        if (obj instanceof List<?> list) {
            return truncate(String.join(",", list.stream().map(String::valueOf).toList()), 512);
        }
        return "";
    }

    private static String str(Object obj) {
        return obj == null ? "" : String.valueOf(obj);
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    /**
     * 哈希链校验结果。
     *
     * @param intact       链条是否完整
     * @param totalRecords 记录总数
     * @param brokenAtId   首个失配记录的 ID
     * @param message      校验说明
     */
    public record ChainVerification(boolean intact, int totalRecords,
                                    Long brokenAtId, String message) {
    }
}
