package com.aegis.gateway.report;

import com.aegis.core.engine.DetectionEngine;
import com.aegis.core.model.Severity;
import com.aegis.gateway.service.GatewayPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * 网关检测事件上报器。
 *
 * <p>与探针的上报器同理，采用异步批量模式，
 * 保证上报操作不阻塞请求转发的主链路。
 */
@Component
public class GatewayEventReporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int BATCH_SIZE = 50;
    private static final long FLUSH_INTERVAL_MILLIS = 200;

    private final BlockingQueue<Map<String, Object>> queue = new ArrayBlockingQueue<>(2000);
    private final GatewayPolicy policy;
    private volatile boolean running = false;
    private Thread worker;

    public GatewayEventReporter(GatewayPolicy policy) {
        this.policy = policy;
    }

    @PostConstruct
    public void start() {
        running = true;
        worker = new Thread(this::flushLoop, "aegis-gateway-reporter");
        worker.setDaemon(true);
        worker.start();
    }

    @PreDestroy
    public void stop() {
        running = false;
        if (worker != null) {
            worker.interrupt();
        }
    }

    /** 上报参数检测事件。 */
    public void reportParamEvent(String traceId, String endpoint, String sourceIp,
                                 String method, String uri, String paramName,
                                 String rawValue,
                                 DetectionEngine.ParamDetectionResult result,
                                 boolean blocked) {
        Map<String, Object> event = new HashMap<>();
        event.put("traceId", traceId);
        event.put("layer", "GATEWAY");
        event.put("threatType", result.threatType().name());
        event.put("severity", result.severity().name());
        event.put("verdict", blocked ? "BLOCK" : "MONITOR");
        event.put("endpoint", endpoint);
        event.put("sourceIp", sourceIp);
        event.put("method", method);
        event.put("uri", uri);
        event.put("paramName", paramName);
        event.put("rawPayload", truncate(rawValue, 2000));
        event.put("normalizedPayload", truncate(result.normalizedValue(), 2000));
        event.put("riskScore", result.riskScore());
        event.put("evidence", result.evidence());
        event.put("detectionCostMicros", result.costMicros());
        event.put("timestamp", System.currentTimeMillis());
        queue.offer(event);
    }

    /** 上报限流事件。 */
    public void reportRateLimit(String traceId, String endpoint, String sourceIp, String uri) {
        Map<String, Object> event = new HashMap<>();
        event.put("traceId", traceId);
        event.put("layer", "GATEWAY");
        event.put("threatType", "RATE_ABUSE");
        event.put("severity", Severity.MEDIUM.name());
        event.put("verdict", "BLOCK");
        event.put("endpoint", endpoint);
        event.put("sourceIp", sourceIp);
        event.put("uri", uri);
        event.put("riskScore", 60);
        event.put("evidence", List.of("请求速率超出限制，触发限流保护"));
        event.put("timestamp", System.currentTimeMillis());
        queue.offer(event);
    }

    private void flushLoop() {
        List<Map<String, Object>> batch = new ArrayList<>(BATCH_SIZE);
        while (running) {
            try {
                Map<String, Object> first = queue.poll(FLUSH_INTERVAL_MILLIS,
                        TimeUnit.MILLISECONDS);
                if (first == null) {
                    continue;
                }
                batch.clear();
                batch.add(first);
                queue.drainTo(batch, BATCH_SIZE - 1);
                send(batch);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // 上报失败静默重试，不影响转发主流程
            }
        }
    }

    private void send(List<Map<String, Object>> batch) throws Exception {
        String json = MAPPER.writeValueAsString(Map.of("events", batch));
        URI uri = URI.create(policy.getConsoleUrl() + "/internal/agent/report");
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setRequestProperty("X-Aegis-Agent-Key", "aegis-internal-agent-key");
        try (var os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
        conn.getResponseCode();
        conn.disconnect();
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
