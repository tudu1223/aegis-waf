package com.aegis.gateway.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 网关策略服务。
 *
 * <p>从控制台同步防护策略，使大屏上的模式切换能够实时生效于网关。
 * 这是演示流程"关闭防护 → 开启防护"一键切换的实现基础。
 */
@Service
public class GatewayPolicy {

    /** 请求属性名：追踪标识。 */
    public static final String ATTR_TRACE_ID = "aegis.traceId";

    /** 请求属性名：接口标识。 */
    public static final String ATTR_ENDPOINT = "aegis.endpoint";

    /** 请求属性名：检测起始时间。 */
    public static final String ATTR_START_NANOS = "aegis.startNanos";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Value("${aegis.gateway.console:http://localhost:8080}")
    private String consoleUrl;

    private final AtomicReference<String> mode = new AtomicReference<>("BLOCK");
    private final AtomicReference<Integer> blockThreshold = new AtomicReference<>(70);
    private final AtomicReference<Integer> rateLimitCapacity = new AtomicReference<>(100);
    private final AtomicReference<Double> rateLimitRefill = new AtomicReference<>(20.0);
    private final AtomicReference<Long> slidingThreshold = new AtomicReference<>(600L);

    /** 累计处理的请求数，定期上报控制台用于大屏展示。 */
    private final AtomicLong requestCounter = new AtomicLong(0);

    public String getMode() {
        return mode.get();
    }

    public boolean isBlockMode() {
        return "BLOCK".equalsIgnoreCase(mode.get());
    }

    public boolean isOff() {
        return "OFF".equalsIgnoreCase(mode.get());
    }

    public int getBlockThreshold() {
        return blockThreshold.get();
    }

    public int getRateLimitCapacity() {
        return rateLimitCapacity.get();
    }

    public double getRateLimitRefill() {
        return rateLimitRefill.get();
    }

    public long getSlidingThreshold() {
        return slidingThreshold.get();
    }

    public void countRequest() {
        requestCounter.incrementAndGet();
    }

    public String getConsoleUrl() {
        return consoleUrl;
    }

    /**
     * 定期从控制台拉取最新策略。
     *
     * <p>采用轮询而非推送，是因为网关可能有多个实例，
     * 拉取模式无需控制台维护实例列表，部署更简单可靠。
     */
    @Scheduled(fixedDelay = 2000)
    public void syncPolicy() {
        try {
            URI uri = URI.create(consoleUrl + "/api/policy");
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(1500);
            conn.setRequestMethod("GET");

            if (conn.getResponseCode() != 200) {
                conn.disconnect();
                return;
            }
            try (var in = conn.getInputStream()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> response = MAPPER.readValue(in, Map.class);
                Object dataObj = response.get("data");
                if (dataObj instanceof Map<?, ?> raw) {
                    applyPolicy(raw);
                }
            }
            conn.disconnect();
        } catch (Exception e) {
            // 控制台不可达时保持当前策略，网关继续独立运行（可用性优先）
        }
    }

    private void applyPolicy(Map<?, ?> data) {
        Object m = data.get("mode");
        if (m != null) {
            mode.set(String.valueOf(m));
        }
        Object bt = data.get("blockThreshold");
        if (bt instanceof Number n) {
            blockThreshold.set(n.intValue());
        }
        Object rc = data.get("rateLimitCapacity");
        if (rc instanceof Number n) {
            rateLimitCapacity.set(n.intValue());
        }
        Object rr = data.get("rateLimitRefillPerSecond");
        if (rr instanceof Number n) {
            rateLimitRefill.set(n.doubleValue());
        }
        Object st = data.get("slidingWindowThreshold");
        if (st instanceof Number n) {
            slidingThreshold.set(n.longValue());
        }
    }

    /** 定期上报请求计数，供大屏展示总流量。 */
    @Scheduled(fixedDelay = 3000)
    public void reportMetrics() {
        long count = requestCounter.getAndSet(0);
        if (count == 0) {
            return;
        }
        try {
            URI uri = URI.create(consoleUrl + "/internal/agent/metrics");
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(1500);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("X-Aegis-Agent-Key", "aegis-internal-agent-key");
            try (var os = conn.getOutputStream()) {
                os.write(MAPPER.writeValueAsBytes(Map.of("requests", count)));
            }
            conn.getResponseCode();
            conn.disconnect();
        } catch (Exception e) {
            // 上报失败不影响转发主流程
        }
    }
}
