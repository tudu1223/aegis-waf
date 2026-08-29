package com.aegis.agent.report;

import com.aegis.core.cmd.CommandInjectionDetector;
import com.aegis.core.engine.DetectionEngine;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.OutputStream;
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
 * [SEC-RASP-07] 检测事件异步上报器
 *
 * <p><b>设计约束：</b>探针运行在业务线程上，上报操作<b>绝不能阻塞业务</b>。
 * 因此采用"内存队列 + 后台批量提交"模式：
 * <ul>
 *   <li>业务线程仅将事件放入有界队列，耗时为 O(1)</li>
 *   <li>队列满时<b>丢弃新事件</b>而非阻塞——宁可丢失监控数据，
 *       也不能拖慢业务响应（可用性优先）</li>
 *   <li>后台守护线程定时批量提交，减少网络往返</li>
 * </ul>
 */
public final class EventReporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 有界队列，容量上限防止内存溢出。 */
    private static final BlockingQueue<Map<String, Object>> QUEUE =
            new ArrayBlockingQueue<>(2000);

    /** 单批最大上报数量。 */
    private static final int BATCH_SIZE = 50;

    /** 批量提交间隔（毫秒）。 */
    private static final long FLUSH_INTERVAL_MILLIS = 200;

    private static volatile String consoleUrl = "http://localhost:8080";
    private static volatile boolean running = false;

    private EventReporter() {
    }

    /** 初始化上报器并启动后台提交线程。 */
    public static synchronized void initialize(String url) {
        if (running) {
            return;
        }
        consoleUrl = url;
        running = true;

        Thread worker = new Thread(EventReporter::flushLoop, "aegis-event-reporter");
        // 守护线程：不阻止 JVM 退出
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * 上报 SQL 注入检测事件。
     *
     * @param actualVerdict 实际处置结果。引擎给出的是"建议处置"，
     *                      而最终是否拦截取决于当前防护模式，
     *                      此处上报的必须是真实发生的处置。
     */
    public static void reportSqlEvent(String traceId, String endpoint, String sourceIp,
                                      String sql,
                                      DetectionEngine.SqlDetectionResult result,
                                      String actualVerdict) {
        Map<String, Object> event = new HashMap<>();
        event.put("traceId", traceId);
        event.put("layer", "RASP");
        event.put("threatType", "SQL_INJECTION");
        event.put("severity", result.severity().name());
        event.put("verdict", actualVerdict);
        event.put("endpoint", endpoint);
        event.put("sourceIp", sourceIp);
        event.put("rawSql", truncate(sql, 4000));
        event.put("riskScore", result.riskScore());
        event.put("similarity", result.diff().similarity());
        event.put("baselineFingerprint", result.baselineFingerprint());
        event.put("actualFingerprint", result.actualFingerprint());
        event.put("riskFeatures", result.riskFeatures());
        event.put("evidence", result.evidence());
        event.put("detectionCostMicros", result.costMicros());
        event.put("timestamp", System.currentTimeMillis());

        // AST 可视化树：大屏渲染红色注入子树的数据来源
        if (result.visualTree() != null && !result.visualTree().isEmpty()) {
            event.put("visualTree", result.visualTree());
        }

        List<Map<String, String>> annotations = new ArrayList<>();
        result.diff().annotations().forEach(a -> {
            Map<String, String> item = new HashMap<>();
            item.put("kind", a.kind().name());
            item.put("kindName", a.kind().getDisplayName());
            item.put("path", a.path());
            item.put("snippet", a.snippet());
            item.put("detail", a.detail());
            annotations.add(item);
        });
        event.put("annotations", annotations);

        enqueue(event);
    }

    /** 上报命令注入检测事件。 */
    public static void reportCommandEvent(String traceId, String endpoint, String sourceIp,
                                          CommandInjectionDetector.Result result) {
        Map<String, Object> event = new HashMap<>();
        event.put("traceId", traceId);
        event.put("layer", "RASP");
        event.put("threatType", "COMMAND_INJECTION");
        event.put("severity", result.score() >= 90 ? "CRITICAL" : "HIGH");
        event.put("verdict", "BLOCK");
        event.put("endpoint", endpoint);
        event.put("sourceIp", sourceIp);
        event.put("rawPayload", truncate(result.fullCommand(), 1000));
        event.put("riskScore", result.score());
        event.put("evidence", result.evidence());
        event.put("timestamp", System.currentTimeMillis());
        enqueue(event);
    }

    /** 上报基线学习事件。 */
    public static void reportBaselineLearned(String endpoint, String sql, String fingerprint) {
        Map<String, Object> event = new HashMap<>();
        event.put("type", "BASELINE_LEARNED");
        event.put("endpoint", endpoint);
        event.put("sql", truncate(sql, 2000));
        event.put("fingerprint", fingerprint);
        event.put("timestamp", System.currentTimeMillis());
        enqueue(event);
    }

    /**
     * 将事件放入队列。
     *
     * <p>使用非阻塞的 {@code offer}：队列满时直接丢弃，
     * 保证业务线程永不因监控而阻塞。
     */
    private static void enqueue(Map<String, Object> event) {
        QUEUE.offer(event);
    }

    /** 后台批量提交循环。 */
    private static void flushLoop() {
        List<Map<String, Object>> batch = new ArrayList<>(BATCH_SIZE);
        while (running) {
            try {
                // 阻塞等待首个事件，避免空转消耗 CPU
                Map<String, Object> first = QUEUE.poll(FLUSH_INTERVAL_MILLIS,
                        TimeUnit.MILLISECONDS);
                if (first == null) {
                    continue;
                }
                batch.clear();
                batch.add(first);
                QUEUE.drainTo(batch, BATCH_SIZE - 1);
                send(batch);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Throwable t) {
                // 上报失败不影响业务，静默重试下一批
                if (System.getProperty("aegis.agent.debug") != null) {
                    System.err.println("[AEGIS] 事件上报失败: " + t.getMessage());
                }
            }
        }
    }

    private static void send(List<Map<String, Object>> batch) throws Exception {
        String json = MAPPER.writeValueAsString(Map.of("events", batch));
        URI uri = URI.create(consoleUrl + "/internal/agent/report");
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(2000);
        conn.setReadTimeout(2000);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        // 共享密钥认证，防止外部伪造探针事件
        conn.setRequestProperty("X-Aegis-Agent-Key", "aegis-internal-agent-key");

        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
        conn.getResponseCode();
        conn.disconnect();
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    public static void shutdown() {
        running = false;
    }

    public static int pendingCount() {
        return QUEUE.size();
    }
}
