package com.aegis.gateway.proxy;

import com.aegis.gateway.service.GatewayPolicy;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.Set;

/**
 * 反向代理 Servlet。
 *
 * <p>将通过安全检测的请求转发至后端业务系统，并回传响应。
 *
 * <p><b>关键职责 —— 注入追踪标识：</b>
 * 转发时写入 {@code X-Aegis-Trace} 与 {@code X-Aegis-Endpoint} 请求头，
 * 使部署在业务应用内的 RASP 探针能够将其捕获的 SQL 执行事件
 * 关联回本次 HTTP 请求。没有这一步，两层检测就是割裂的，
 * 无法回答"这条注入 SQL 源自哪个请求的哪个参数"。
 */
@Component
public class ReverseProxyServlet extends HttpServlet {

    /** 逐跳请求头，依据 HTTP 规范不应转发。 */
    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
    );

    @Value("${aegis.gateway.upstream:http://localhost:8090}")
    private String upstream;

    private final GatewayPolicy policy;

    public ReverseProxyServlet(GatewayPolicy policy) {
        this.policy = policy;
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String targetUrl = buildTargetUrl(request);
        HttpURLConnection conn = null;
        try {
            URI uri = URI.create(targetUrl);
            conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod(request.getMethod());
            conn.setConnectTimeout(10_000);
            conn.setReadTimeout(30_000);
            conn.setInstanceFollowRedirects(false);
            conn.setDoInput(true);

            copyRequestHeaders(request, conn);
            injectTraceHeaders(request, conn);
            copyRequestBody(request, conn);

            int status = conn.getResponseCode();
            response.setStatus(status);
            copyResponseHeaders(conn, response);
            copyResponseBody(conn, response, status);

        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            response.setContentType("application/json; charset=utf-8");
            response.getWriter().write(
                    "{\"success\":false,\"message\":\"后端服务不可达: "
                            + escapeJson(e.getMessage()) + "\"}");
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String buildTargetUrl(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder(upstream);
        sb.append(request.getRequestURI());
        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) {
            sb.append('?').append(query);
        }
        return sb.toString();
    }

    private void copyRequestHeaders(HttpServletRequest request, HttpURLConnection conn) {
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                continue;
            }
            conn.setRequestProperty(name, request.getHeader(name));
        }
    }

    /**
     * [关键] 注入追踪标识，实现网关层与 RASP 层的联动。
     *
     * <p>同时透传客户端真实 IP，使探针上报的事件包含正确的攻击来源。
     */
    private void injectTraceHeaders(HttpServletRequest request, HttpURLConnection conn) {
        Object traceId = request.getAttribute(GatewayPolicy.ATTR_TRACE_ID);
        if (traceId != null) {
            conn.setRequestProperty("X-Aegis-Trace", String.valueOf(traceId));
        }
        Object endpoint = request.getAttribute(GatewayPolicy.ATTR_ENDPOINT);
        if (endpoint != null) {
            conn.setRequestProperty("X-Aegis-Endpoint", String.valueOf(endpoint));
        }
        conn.setRequestProperty("X-Forwarded-For", clientIp(request));
        conn.setRequestProperty("X-Forwarded-Proto", request.getScheme());
    }

    private void copyRequestBody(HttpServletRequest request, HttpURLConnection conn)
            throws IOException {
        String method = request.getMethod();
        if (!"POST".equals(method) && !"PUT".equals(method) && !"PATCH".equals(method)) {
            return;
        }
        conn.setDoOutput(true);
        // 请求体已被 CachedBodyRequestWrapper 缓存，此处可安全重复读取
        byte[] body = request.getInputStream().readAllBytes();
        conn.setRequestProperty("Content-Length", String.valueOf(body.length));
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
    }

    private void copyResponseHeaders(HttpURLConnection conn, HttpServletResponse response) {
        conn.getHeaderFields().forEach((name, values) -> {
            if (name == null || HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                return;
            }
            for (String value : values) {
                response.addHeader(name, value);
            }
        });
        // 标记响应经由 AEGIS 网关，便于测试脚本识别
        response.setHeader("X-Aegis-Gateway", "1");
    }

    private void copyResponseBody(HttpURLConnection conn, HttpServletResponse response,
                                  int status) throws IOException {
        try (InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream()) {
            if (in == null) {
                return;
            }
            in.transferTo(response.getOutputStream());
            response.getOutputStream().flush();
        }
    }

    /** 提取客户端真实 IP，优先使用代理链首个地址。 */
    public static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ");
    }
}
