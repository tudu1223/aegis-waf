package com.aegis.console.service;

import com.aegis.console.websocket.EventBroadcaster;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 防护策略管理。
 *
 * <p>控制全局防护模式，是演示流程的核心开关：
 * <ul>
 *   <li><b>OFF</b> —— 关闭防护，用于演示漏洞的真实危害</li>
 *   <li><b>MONITOR</b> —— 仅记录不拦截，用于观察检测能力而不影响业务</li>
 *   <li><b>BLOCK</b> —— 检出即拦截，完整防护</li>
 * </ul>
 *
 * <p>三态设计对应设计文档的"三轮测试法"，使同一套系统能够
 * 依次展示"漏洞存在 → 能够检出 → 成功拦截"的完整链条。
 */
@Service
public class PolicyService {

    /** 当前防护模式。 */
    private final AtomicReference<String> mode = new AtomicReference<>("BLOCK");

    /** 基线学习模式开关。 */
    private final AtomicReference<Boolean> learningMode = new AtomicReference<>(false);

    /** 令牌桶容量。 */
    private volatile int rateLimitCapacity = 100;

    /** 令牌填充速率（个/秒）。 */
    private volatile double rateLimitRefillPerSecond = 20;

    /** 滑动窗口阈值（次/分钟）。 */
    private volatile long slidingWindowThreshold = 600;

    /** 判定拦截的风险分阈值。 */
    private volatile int blockThreshold = 70;

    private final EventBroadcaster broadcaster;

    public PolicyService(EventBroadcaster broadcaster) {
        this.broadcaster = broadcaster;
    }

    public String getMode() {
        return mode.get();
    }

    /** 切换防护模式并广播变更。 */
    public void setMode(String newMode) {
        String normalized = newMode == null ? "BLOCK" : newMode.toUpperCase();
        if (!normalized.equals("OFF") && !normalized.equals("MONITOR")
                && !normalized.equals("BLOCK")) {
            throw new IllegalArgumentException("防护模式仅支持 OFF / MONITOR / BLOCK");
        }
        mode.set(normalized);
        broadcaster.broadcastPolicy(snapshot());
    }

    public boolean isLearningMode() {
        return Boolean.TRUE.equals(learningMode.get());
    }

    public void setLearningMode(boolean enabled) {
        learningMode.set(enabled);
        broadcaster.broadcastPolicy(snapshot());
    }

    public boolean isBlockMode() {
        return "BLOCK".equals(mode.get());
    }

    public boolean isOff() {
        return "OFF".equals(mode.get());
    }

    public int getRateLimitCapacity() {
        return rateLimitCapacity;
    }

    public void setRateLimitCapacity(int v) {
        this.rateLimitCapacity = Math.max(1, v);
    }

    public double getRateLimitRefillPerSecond() {
        return rateLimitRefillPerSecond;
    }

    public void setRateLimitRefillPerSecond(double v) {
        this.rateLimitRefillPerSecond = Math.max(0.1, v);
    }

    public long getSlidingWindowThreshold() {
        return slidingWindowThreshold;
    }

    public void setSlidingWindowThreshold(long v) {
        this.slidingWindowThreshold = Math.max(1, v);
    }

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public void setBlockThreshold(int v) {
        this.blockThreshold = Math.min(100, Math.max(1, v));
    }

    /** 当前策略快照，供前端展示与网关同步。 */
    public Map<String, Object> snapshot() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("mode", getMode());
        map.put("learningMode", isLearningMode());
        map.put("rateLimitCapacity", rateLimitCapacity);
        map.put("rateLimitRefillPerSecond", rateLimitRefillPerSecond);
        map.put("slidingWindowThreshold", slidingWindowThreshold);
        map.put("blockThreshold", blockThreshold);
        return map;
    }
}
