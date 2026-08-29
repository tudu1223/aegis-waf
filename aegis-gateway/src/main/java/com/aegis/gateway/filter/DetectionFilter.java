package com.aegis.gateway.filter;

import com.aegis.core.engine.DetectionEngine;
import com.aegis.core.limit.IpReputationManager;
import com.aegis.core.limit.SlidingWindowCounter;
import com.aegis.core.limit.TokenBucket;
import com.aegis.core.model.Severity;
import com.aegis.core.model.ThreatType;
import com.aegis.gateway.proxy.ReverseProxyServlet;
import com.aegis.gateway.report.GatewayEventReporter;
import com.aegis.gateway.service.GatewayPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [SEC-GW-02] 网关安全检测过滤器
 *
 * <p>网关层的防护主链路，依次执行四道关卡：
 * <ol>
 *   <li><b>追踪标识生成</b> —— 为本次请求分配 TraceID，供 RASP 层关联</li>
 *   <li><b>IP 信誉校验</b> —— 已封禁的来源直接拒绝</li>
 *   <li><b>速率限制</b> —— 令牌桶控制突发、滑动窗口控制持续总量</li>
 *   <li><b>参数语义检测</b> —— 对全部参数做攻击载荷判定</li>
 * </ol>
 *
 * <p><b>网关层判定的性质：</b>此处只能看到 HTTP 参数文本，
 * 无法确知它是否会被拼接进 SQL，因此判定具有<b>启发式</b>性质。
 * 确定性判定由 RASP 层基于真实 SQL 完成。这种分工使网关能够
 * 快速拦截明显的攻击，同时把模糊场景交给更精确的下游判定。
 */
@Component
@Order(1)
public class DetectionFilter implements Filter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 无需检测的静态资源与健康检查路径。 */
    private static final List<String> SKIP_PREFIXES = List.of(
            "/actuator", "/favicon.ico", "/h2-console", "/aegis/"
    );

    private final DetectionEngine engine;
    private final IpReputationManager reputationManager;
    private final GatewayPolicy policy;
    private final GatewayEventReporter reporter;

    /** 每个 IP 独立的令牌桶。 */
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    /** 每个 IP 独立的滑动窗口计数器。 */
    private final Map<String, SlidingWindowCounter> windows = new ConcurrentHashMap<>();

    public DetectionFilter(DetectionEngine engine,
                           IpReputationManager reputationManager,
                           GatewayPolicy policy,
                           GatewayEventReporter reporter) {
        this.engine = engine;
        this.reputationManager = reputationManager;
        this.policy = policy;
        this.reporter = reporter;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String uri = request.getRequestURI();
        if (shouldSkip(uri)) {
            chain.doFilter(req, res);
            return;
        }

        // 缓存请求体，使其可被检测与转发两次消费
        CachedBodyRequestWrapper wrapped = new CachedBodyRequestWrapper(request);

        // ---- 关卡零：生成追踪标识 ----
        String traceId = UUID.randomUUID().toString();
        String endpoint = request.getMethod() + ":" + uri;
        wrapped.setAttribute(GatewayPolicy.ATTR_TRACE_ID, traceId);
        wrapped.setAttribute(GatewayPolicy.ATTR_ENDPOINT, endpoint);
        wrapped.setAttribute(GatewayPolicy.ATTR_START_NANOS, System.nanoTime());
        response.setHeader("X-Aegis-Trace", traceId);

        policy.countRequest();

        // 防护关闭时直接放行，用于演示漏洞的真实危害
        if (policy.isOff()) {
            chain.doFilter(wrapped, res);
            return;
        }

        String clientIp = ReverseProxyServlet.clientIp(request);

        // ---- 关卡一：IP 信誉校验 ----
        if (reputationManager.isBlocked(clientIp)) {
            reject(response, 403, "来源 IP 因持续攻击行为已被临时封禁", traceId);
            return;
        }

        // ---- 关卡二：速率限制 ----
        if (!checkRateLimit(clientIp)) {
            reputationManager.record(clientIp, Severity.MEDIUM);
            reporter.reportRateLimit(traceId, endpoint, clientIp, uri);
            reject(response, 429, "请求速率超出限制，请稍后重试", traceId);
            return;
        }

        // ---- 关卡三：参数语义检测 ----
        DetectionOutcome outcome = inspectParameters(wrapped, traceId, endpoint, clientIp);
        if (outcome.blocked()) {
            reject(response, 403, outcome.message(), traceId);
            return;
        }

        chain.doFilter(wrapped, res);
    }

    /**
     * 令牌桶与滑动窗口双重限流。
     *
     * <p>二者取"与"关系：令牌桶控制瞬时突发，滑动窗口控制持续总量，
     * 任一超限即拒绝。这样既能容忍正常业务的短时峰值，
     * 又能有效抑制持续的暴力破解与 CC 攻击。
     */
    private boolean checkRateLimit(String clientIp) {
        TokenBucket bucket = buckets.computeIfAbsent(clientIp,
                k -> new TokenBucket(policy.getRateLimitCapacity(),
                        policy.getRateLimitRefill()));
        SlidingWindowCounter window = windows.computeIfAbsent(clientIp,
                k -> new SlidingWindowCounter(60_000, 12, policy.getSlidingThreshold()));

        boolean bucketOk = bucket.tryAcquire();
        boolean windowOk = window.tryAcquire();
        return bucketOk && windowOk;
    }

    /**
     * 检测请求中的全部参数。
     *
     * <p>覆盖 Query 参数、表单参数、JSON 请求体与部分请求头，
     * 确保攻击载荷无论从哪个位置传入都能被检出。
     */
    private DetectionOutcome inspectParameters(CachedBodyRequestWrapper request,
                                               String traceId, String endpoint,
                                               String clientIp) {
        Map<String, String> parameters = collectParameters(request);
        if (parameters.isEmpty()) {
            return DetectionOutcome.pass();
        }

        int maxScore = 0;
        String worstParam = null;
        String worstValue = null;
        ThreatType worstType = null;
        List<String> allEvidence = new ArrayList<>();
        DetectionEngine.ParamDetectionResult worstResult = null;

        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            DetectionEngine.ParamDetectionResult result =
                    engine.detectParameter(entry.getKey(), entry.getValue());
            if (result.riskScore() > maxScore) {
                maxScore = result.riskScore();
                worstParam = entry.getKey();
                worstValue = entry.getValue();
                worstType = result.threatType();
                worstResult = result;
            }
            if (result.threat()) {
                allEvidence.addAll(result.evidence());
            }
        }

        if (worstResult == null || !worstResult.threat()) {
            return DetectionOutcome.pass();
        }

        boolean shouldBlock = policy.isBlockMode()
                && maxScore >= policy.getBlockThreshold();

        // 上报事件并更新 IP 信誉
        Severity severity = Severity.fromScore(maxScore);
        reputationManager.record(clientIp, severity);
        reporter.reportParamEvent(traceId, endpoint, clientIp, request.getMethod(),
                request.getRequestURI(), worstParam, worstValue,
                worstResult, shouldBlock);

        if (shouldBlock) {
            String detail = allEvidence.isEmpty() ? "参数中检出攻击载荷"
                    : allEvidence.get(0);
            return DetectionOutcome.block(
                    "检出 " + worstType.getDisplayName() + " 攻击载荷（参数 "
                            + worstParam + "，风险评分 " + maxScore + "）：" + detail);
        }
        return DetectionOutcome.pass();
    }

    /** 汇集请求中所有可能承载攻击载荷的位置。 */
    private Map<String, String> collectParameters(CachedBodyRequestWrapper request) {
        Map<String, String> result = new HashMap<>();

        // Query 与表单参数
        request.getParameterMap().forEach((name, values) -> {
            if (values != null && values.length > 0) {
                result.put(name, values[0]);
            }
        });

        // JSON 请求体：递归提取全部字符串值
        String contentType = request.getContentType();
        if (contentType != null && contentType.toLowerCase().contains("json")) {
            String body = request.getBodyAsString();
            if (!body.isBlank()) {
                extractJsonValues(body, result);
            }
        }

        // 部分请求头也可能承载载荷（如通过 Referer 注入）
        String referer = request.getHeader("Referer");
        if (referer != null && !referer.isBlank()) {
            result.put("__header.Referer", referer);
        }
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && userAgent.length() > 200) {
            // 异常长的 UA 值得检查
            result.put("__header.User-Agent", userAgent);
        }

        return result;
    }

    private void extractJsonValues(String body, Map<String, String> out) {
        try {
            JsonNode root = MAPPER.readTree(body);
            walkJson("", root, out);
        } catch (Exception e) {
            // 非法 JSON：整体作为一个参数检测，避免绕过
            out.put("__body", body);
        }
    }

    private void walkJson(String prefix, JsonNode node, Map<String, String> out) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                walkJson(key, entry.getValue(), out);
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                walkJson(prefix + "[" + i + "]", node.get(i), out);
            }
        } else if (node.isTextual()) {
            out.put(prefix.isEmpty() ? "__value" : prefix, node.asText());
        }
    }

    private boolean shouldSkip(String uri) {
        for (String prefix : SKIP_PREFIXES) {
            if (uri.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private void reject(HttpServletResponse response, int status, String message,
                        String traceId) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json; charset=utf-8");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("X-Aegis-Blocked", "1");
        String json = MAPPER.writeValueAsString(Map.of(
                "success", false,
                "blocked", true,
                "traceId", traceId,
                "message", message,
                "by", "AEGIS Gateway"
        ));
        response.getWriter().write(json);
        response.getWriter().flush();
    }

    /** 检测结论。 */
    private record DetectionOutcome(boolean blocked, String message) {
        static DetectionOutcome pass() {
            return new DetectionOutcome(false, "");
        }

        static DetectionOutcome block(String message) {
            return new DetectionOutcome(true, message);
        }
    }
}
