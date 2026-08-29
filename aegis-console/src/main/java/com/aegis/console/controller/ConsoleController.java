package com.aegis.console.controller;

import com.aegis.console.service.BaselineService;
import com.aegis.console.service.PolicyService;
import com.aegis.console.service.StatisticsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 统计、策略与基线管理接口。
 */
@RestController
@CrossOrigin(originPatterns = "*")
public class ConsoleController {

    private final StatisticsService statisticsService;
    private final PolicyService policyService;
    private final BaselineService baselineService;

    public ConsoleController(StatisticsService statisticsService,
                             PolicyService policyService,
                             BaselineService baselineService) {
        this.statisticsService = statisticsService;
        this.policyService = policyService;
        this.baselineService = baselineService;
    }

    // ==================== 统计 ====================

    /** 大屏总览指标。 */
    @GetMapping("/api/stats/overview")
    public ResponseEntity<Map<String, Object>> overview() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", statisticsService.overview()
        ));
    }

    /** 威胁类型分布。 */
    @GetMapping("/api/stats/threat-distribution")
    public ResponseEntity<Map<String, Object>> threatDistribution() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", statisticsService.threatDistribution()
        ));
    }

    /** 攻击源排行。 */
    @GetMapping("/api/stats/top-attackers")
    public ResponseEntity<Map<String, Object>> topAttackers(
            @RequestParam(defaultValue = "10") int limit) {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", statisticsService.topAttackers(limit)
        ));
    }

    /** 受攻击接口排行。 */
    @GetMapping("/api/stats/top-endpoints")
    public ResponseEntity<Map<String, Object>> topEndpoints(
            @RequestParam(defaultValue = "10") int limit) {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", statisticsService.topEndpoints(limit)
        ));
    }

    /** 时序趋势。 */
    @GetMapping("/api/stats/timeline")
    public ResponseEntity<Map<String, Object>> timeline(
            @RequestParam(defaultValue = "30") int minutes,
            @RequestParam(defaultValue = "30") int buckets) {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", statisticsService.timeline(minutes, Math.min(120, buckets))
        ));
    }

    // ==================== 策略 ====================

    /** 查询当前防护策略。 */
    @GetMapping("/api/policy")
    public ResponseEntity<Map<String, Object>> getPolicy() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", policyService.snapshot()
        ));
    }

    /**
     * 切换防护策略。
     *
     * <p>演示流程的核心开关：OFF 展示漏洞危害，
     * MONITOR 展示检测能力，BLOCK 展示完整防护。
     */
    @PutMapping("/api/policy")
    public ResponseEntity<Map<String, Object>> updatePolicy(
            @RequestBody Map<String, Object> body) {
        try {
            if (body.containsKey("mode")) {
                policyService.setMode(String.valueOf(body.get("mode")));
            }
            if (body.containsKey("learningMode")) {
                policyService.setLearningMode(
                        Boolean.parseBoolean(String.valueOf(body.get("learningMode"))));
            }
            if (body.containsKey("blockThreshold")) {
                policyService.setBlockThreshold(
                        Integer.parseInt(String.valueOf(body.get("blockThreshold"))));
            }
            if (body.containsKey("rateLimitCapacity")) {
                policyService.setRateLimitCapacity(
                        Integer.parseInt(String.valueOf(body.get("rateLimitCapacity"))));
            }
            if (body.containsKey("rateLimitRefillPerSecond")) {
                policyService.setRateLimitRefillPerSecond(
                        Double.parseDouble(String.valueOf(body.get("rateLimitRefillPerSecond"))));
            }
            if (body.containsKey("slidingWindowThreshold")) {
                policyService.setSlidingWindowThreshold(
                        Long.parseLong(String.valueOf(body.get("slidingWindowThreshold"))));
            }
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "data", policyService.snapshot()
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "message", e.getMessage()));
        }
    }

    // ==================== 基线 ====================

    /** 基线列表。 */
    @GetMapping("/api/baselines")
    public ResponseEntity<Map<String, Object>> baselines(
            @RequestParam(required = false) String endpoint) {
        List<Map<String, Object>> data = baselineService.list(endpoint);
        return ResponseEntity.ok(Map.of(
                "success", true,
                "count", data.size(),
                "data", data
        ));
    }

    /** 手工添加基线。 */
    @PostMapping("/api/baselines")
    public ResponseEntity<Map<String, Object>> addBaseline(
            @RequestBody Map<String, String> body) {
        String endpoint = body.getOrDefault("endpoint", "");
        String sql = body.getOrDefault("sql", "");
        if (endpoint.isBlank() || sql.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "message", "endpoint 与 sql 均不能为空"));
        }
        var entity = baselineService.add(endpoint, sql);
        return ResponseEntity.ok(Map.of(
                "success", true,
                "id", entity.getId(),
                "fingerprint", entity.getFingerprint()
        ));
    }

    /** 确认基线。 */
    @PostMapping("/api/baselines/{id}/confirm")
    public ResponseEntity<Map<String, Object>> confirmBaseline(@PathVariable Long id) {
        boolean ok = baselineService.confirm(id);
        return ResponseEntity.ok(Map.of("success", ok));
    }

    /** 禁用基线。 */
    @PostMapping("/api/baselines/{id}/disable")
    public ResponseEntity<Map<String, Object>> disableBaseline(@PathVariable Long id) {
        boolean ok = baselineService.disable(id);
        return ResponseEntity.ok(Map.of("success", ok));
    }

    /** 删除基线。 */
    @DeleteMapping("/api/baselines/{id}")
    public ResponseEntity<Map<String, Object>> deleteBaseline(@PathVariable Long id) {
        baselineService.delete(id);
        return ResponseEntity.ok(Map.of("success", true));
    }

    /** 清空基线。 */
    @DeleteMapping("/api/baselines")
    public ResponseEntity<Map<String, Object>> clearBaselines() {
        baselineService.clear();
        return ResponseEntity.ok(Map.of("success", true));
    }

    /** 导出已确认的基线，供网关与探针加载。 */
    @GetMapping("/api/baselines/export")
    public ResponseEntity<Map<String, Object>> exportBaselines() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "data", baselineService.exportConfirmed()
        ));
    }

    /** 服务健康检查。 */
    @GetMapping("/api/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "service", "aegis-console",
                "status", "UP",
                "policy", policyService.snapshot()
        ));
    }
}
