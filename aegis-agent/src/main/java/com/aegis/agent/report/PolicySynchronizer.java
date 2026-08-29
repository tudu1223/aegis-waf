package com.aegis.agent.report;

import com.aegis.agent.AegisAgent;
import com.aegis.agent.detect.SqlGuard;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Map;

/**
 * 探针策略同步器。
 *
 * <p><b>设计动机：</b>探针的防护模式若在启动时固定，则控制台上的
 * 模式切换只能影响网关层，探针层仍按旧策略运行。这会导致演示时
 * "已关闭防护"但请求仍被探针拦截的矛盾状态。
 *
 * <p>本同步器定期从控制台拉取最新策略并应用到探针，使
 * OFF / MONITOR / BLOCK 三种模式在网关与探针两层保持一致，
 * 保证"三轮测试法"的演示流程能够正确呈现。
 *
 * <p>采用守护线程轮询而非长连接，避免探针对宿主应用引入额外的
 * 网络组件依赖。
 */
public final class PolicySynchronizer {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 策略同步间隔（毫秒）。 */
    private static final long SYNC_INTERVAL_MILLIS = 2000;

    private static volatile boolean running = false;

    private PolicySynchronizer() {
    }

    /** 启动后台同步线程。 */
    public static synchronized void start(String consoleUrl) {
        if (running) {
            return;
        }
        running = true;
        Thread worker = new Thread(() -> syncLoop(consoleUrl), "aegis-policy-sync");
        worker.setDaemon(true);
        worker.start();
    }

    private static void syncLoop(String consoleUrl) {
        while (running) {
            try {
                Thread.sleep(SYNC_INTERVAL_MILLIS);
                fetchAndApply(consoleUrl);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Throwable t) {
                // 控制台不可达时保持当前策略，探针继续独立工作
            }
        }
    }

    private static void fetchAndApply(String consoleUrl) throws Exception {
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
            if (dataObj instanceof Map<?, ?> data) {
                Object mode = data.get("mode");
                if (mode != null) {
                    AegisAgent.setMode(String.valueOf(mode));
                }
                Object learning = data.get("learningMode");
                if (learning != null) {
                    SqlGuard.setLearningMode(
                            Boolean.parseBoolean(String.valueOf(learning)));
                }
            }
        }
        conn.disconnect();
    }

    public static void stop() {
        running = false;
    }
}
