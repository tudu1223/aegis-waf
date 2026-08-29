package com.aegis.gateway.controller;

import com.aegis.core.limit.IpReputationManager;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 网关管理接口。
 *
 * <p>路径前缀 {@code /aegis/} 在检测过滤器中被跳过，
 * 保证管理接口自身不会被防护逻辑拦截。
 */
@RestController
@RequestMapping("/aegis")
@CrossOrigin(originPatterns = "*")
public class GatewayAdminController {

    private final IpReputationManager reputationManager;

    public GatewayAdminController(IpReputationManager reputationManager) {
        this.reputationManager = reputationManager;
    }

    /** 查询 IP 信誉排行，用于大屏展示攻击源画像。 */
    @GetMapping("/reputation")
    public ResponseEntity<Map<String, Object>> reputation(
            @RequestParam(defaultValue = "20") int limit) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (IpReputationManager.Reputation rep : reputationManager.topOffenders(limit)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ip", rep.ip());
            item.put("score", Math.round(rep.score() * 10) / 10.0);
            item.put("eventCount", rep.eventCount());
            item.put("blocked", rep.isCurrentlyBlocked());
            item.put("blockedUntil", rep.blockedUntil() == null
                    ? null : rep.blockedUntil().toEpochMilli());
            items.add(item);
        }
        return ResponseEntity.ok(Map.of(
                "success", true,
                "blockedCount", reputationManager.blockedCount(),
                "trackedCount", reputationManager.trackedCount(),
                "data", items
        ));
    }

    /**
     * 解除指定 IP 的封禁。
     *
     * <p><b>使用场景：</b>连续演练会使演示者自身的 IP 累积风险分并被封禁，
     * 导致后续攻击全部以"IP 已封禁"为由拦下，无法展示各类攻击的
     * 具体检测能力。此接口用于在演练间隙重置信誉状态。
     */
    @PostMapping("/reputation/unblock")
    public ResponseEntity<Map<String, Object>> unblock(@RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false, "message", "缺少 ip 参数"));
        }
        reputationManager.unblock(ip);
        return ResponseEntity.ok(Map.of("success", true, "ip", ip));
    }

    /** 清空全部 IP 信誉记录。 */
    @PostMapping("/reputation/reset")
    public ResponseEntity<Map<String, Object>> reset() {
        long before = reputationManager.trackedCount();
        reputationManager.clear();
        return ResponseEntity.ok(Map.of(
                "success", true,
                "cleared", before,
                "message", "已重置 " + before + " 条 IP 信誉记录"
        ));
    }

    /** 网关健康检查。 */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "success", true,
                "service", "aegis-gateway",
                "status", "UP",
                "blockedIps", reputationManager.blockedCount(),
                "timestamp", Instant.now().toEpochMilli()
        ));
    }
}
