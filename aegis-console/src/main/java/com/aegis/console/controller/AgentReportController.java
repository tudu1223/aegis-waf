package com.aegis.console.controller;

import com.aegis.console.service.BaselineService;
import com.aegis.console.service.EventService;
import com.aegis.console.service.StatisticsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 探针与网关的内部上报接口。
 *
 * <p>使用共享密钥认证，防止外部伪造检测事件污染审计日志。
 */
@RestController
@RequestMapping("/internal/agent")
public class AgentReportController {

    /**
     * 探针共享密钥。
     *
     * <p>生产环境应通过配置注入并定期轮换；此处为演示靶场，使用固定值。
     * 该密钥仅用于区分"内部组件"与"外部请求"，防止攻击者伪造安全事件
     * 以掩盖真实攻击或制造噪声。
     */
    private static final String AGENT_KEY = "aegis-internal-agent-key";

    private final EventService eventService;
    private final BaselineService baselineService;
    private final StatisticsService statisticsService;

    public AgentReportController(EventService eventService,
                                 BaselineService baselineService,
                                 StatisticsService statisticsService) {
        this.eventService = eventService;
        this.baselineService = baselineService;
        this.statisticsService = statisticsService;
    }

    /**
     * 接收批量上报的检测事件。
     *
     * @param key  共享密钥请求头
     * @param body 形如 {@code {"events":[...]}} 的批量数据
     */
    @PostMapping("/report")
    public ResponseEntity<Map<String, Object>> report(
            @RequestHeader(value = "X-Aegis-Agent-Key", required = false) String key,
            @RequestBody Map<String, Object> body) {

        if (!AGENT_KEY.equals(key)) {
            return ResponseEntity.status(401).body(Map.of(
                    "success", false, "message", "探针密钥无效"));
        }

        Object eventsObj = body.get("events");
        if (!(eventsObj instanceof List<?> events)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "message", "缺少 events 字段"));
        }

        int recorded = 0;
        int baselines = 0;
        for (Object item : events) {
            if (!(item instanceof Map<?, ?> raw)) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> event = (Map<String, Object>) raw;

            // 基线学习事件与检测事件走不同的处理路径
            if ("BASELINE_LEARNED".equals(event.get("type"))) {
                baselineService.recordLearned(
                        String.valueOf(event.get("endpoint")),
                        String.valueOf(event.get("sql")),
                        String.valueOf(event.get("fingerprint")));
                baselines++;
            } else {
                eventService.record(event);
                recorded++;
            }
        }

        return ResponseEntity.ok(Map.of(
                "success", true,
                "recorded", recorded,
                "baselines", baselines
        ));
    }

    /** 网关上报请求计数，用于大屏的总请求量指标。 */
    @PostMapping("/metrics")
    public ResponseEntity<Map<String, Object>> metrics(
            @RequestHeader(value = "X-Aegis-Agent-Key", required = false) String key,
            @RequestBody Map<String, Object> body) {

        if (!AGENT_KEY.equals(key)) {
            return ResponseEntity.status(401).body(Map.of("success", false));
        }
        Object requests = body.get("requests");
        if (requests instanceof Number n) {
            statisticsService.incrementRequests(n.longValue());
        }
        return ResponseEntity.ok(Map.of("success", true));
    }
}
