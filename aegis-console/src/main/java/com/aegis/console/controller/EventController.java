package com.aegis.console.controller;

import com.aegis.console.entity.DetectionEventEntity;
import com.aegis.console.repository.DetectionEventRepository;
import com.aegis.console.service.EventService;
import com.aegis.console.service.StatisticsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 检测事件查询接口。
 */
@RestController
@RequestMapping("/api/events")
@CrossOrigin(originPatterns = "*")
public class EventController {

    private final DetectionEventRepository repository;
    private final EventService eventService;
    private final StatisticsService statisticsService;
    private final ObjectMapper objectMapper;

    public EventController(DetectionEventRepository repository,
                           EventService eventService,
                           StatisticsService statisticsService,
                           ObjectMapper objectMapper) {
        this.repository = repository;
        this.eventService = eventService;
        this.statisticsService = statisticsService;
        this.objectMapper = objectMapper;
    }

    /** 分页查询检测事件，支持多维过滤。 */
    @GetMapping
    public ResponseEntity<Map<String, Object>> list(
            @RequestParam(required = false) String threatType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String layer,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        Page<DetectionEventEntity> result = repository.search(
                emptyToNull(threatType), emptyToNull(severity),
                emptyToNull(sourceIp), emptyToNull(layer),
                from == null ? null : Instant.ofEpochMilli(from),
                to == null ? null : Instant.ofEpochMilli(to),
                PageRequest.of(Math.max(0, page), Math.min(200, size)));

        List<Map<String, Object>> items = new ArrayList<>();
        result.getContent().forEach(e -> items.add(toSummary(e)));

        return ResponseEntity.ok(Map.of(
                "success", true,
                "total", result.getTotalElements(),
                "page", result.getNumber(),
                "size", result.getSize(),
                "totalPages", result.getTotalPages(),
                "data", items
        ));
    }

    /** 事件详情，含 AST 差分可视化数据。 */
    @GetMapping("/{eventId}")
    public ResponseEntity<Map<String, Object>> detail(@PathVariable String eventId) {
        return repository.findByEventId(eventId)
                .map(e -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", toDetail(e))))
                .orElseGet(() -> ResponseEntity.status(404).body(Map.of(
                        "success", false, "message", "事件不存在")));
    }

    /**
     * 按 TraceID 还原完整攻击证据链。
     *
     * <p>这是"网关 + RASP 双层联动"架构的价值体现：
     * 同一 TraceID 下可能同时存在网关层的参数检测事件与
     * 探针层的 SQL 结构检测事件，二者串联形成完整证据链。
     */
    @GetMapping("/trace/{traceId}")
    public ResponseEntity<Map<String, Object>> trace(@PathVariable String traceId) {
        List<DetectionEventEntity> events = eventService.findByTrace(traceId);
        List<Map<String, Object>> chain = new ArrayList<>();
        events.forEach(e -> chain.add(toDetail(e)));
        return ResponseEntity.ok(Map.of(
                "success", true,
                "traceId", traceId,
                "count", chain.size(),
                "chain", chain
        ));
    }

    /**
     * 校验审计日志哈希链完整性。
     *
     * <p>对应测试用例 TC-21，验证日志的不可否认性。
     */
    @GetMapping("/verify-chain")
    public ResponseEntity<Map<String, Object>> verifyChain() {
        EventService.ChainVerification result = eventService.verifyChain();
        return ResponseEntity.ok(Map.of(
                "success", true,
                "intact", result.intact(),
                "totalRecords", result.totalRecords(),
                "brokenAtId", result.brokenAtId() == null ? "" : result.brokenAtId(),
                "message", result.message()
        ));
    }

    /**
     * 清空全部事件，便于重复演示。
     *
     * <p>委托给服务层执行，以保证数据库记录与内存中的哈希链状态
     * 同步重置——二者必须视为一个原子操作。
     */
    @DeleteMapping("/all")
    public ResponseEntity<Map<String, Object>> clear() {
        long count = eventService.clearAll();
        return ResponseEntity.ok(Map.of(
                "success", true,
                "deleted", count,
                "message", "已清空 " + count + " 条事件记录，哈希链已重置"
        ));
    }

    private Map<String, Object> toSummary(DetectionEventEntity e) {
        Map<String, Object> map = new HashMap<>();
        map.put("eventId", e.getEventId());
        map.put("traceId", e.getTraceId());
        map.put("timestamp", e.getCreatedAt() == null ? 0 : e.getCreatedAt().toEpochMilli());
        map.put("layer", e.getLayer());
        map.put("threatType", e.getThreatType());
        map.put("severity", e.getSeverity());
        map.put("verdict", e.getVerdict());
        map.put("sourceIp", e.getSourceIp());
        map.put("endpoint", e.getEndpoint());
        map.put("uri", e.getUri());
        map.put("riskScore", e.getRiskScore());
        map.put("similarity", e.getSimilarity());
        map.put("riskFeatures", e.getRiskFeatures());
        map.put("detectionCostMicros", e.getDetectionCostMicros());
        return map;
    }

    private Map<String, Object> toDetail(DetectionEventEntity e) {
        Map<String, Object> map = toSummary(e);
        map.put("rawSql", e.getRawSql());
        map.put("rawPayload", e.getRawPayload());
        map.put("normalizedPayload", e.getNormalizedPayload());
        map.put("paramName", e.getParamName());
        map.put("baselineFingerprint", e.getBaselineFingerprint());
        map.put("actualFingerprint", e.getActualFingerprint());
        map.put("prevHash", e.getPrevHash());
        map.put("hash", e.getHash());
        map.put("evidence", parseJson(e.getEvidence()));
        map.put("diff", parseJson(e.getDiffJson()));
        return map;
    }

    private Object parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String emptyToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
