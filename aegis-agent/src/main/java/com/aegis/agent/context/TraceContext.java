package com.aegis.agent.context;

/**
 * 追踪上下文。
 *
 * <p><b>作用：</b>在应用线程上传递 TraceID，使 RASP 探针捕获的 SQL 执行事件
 * 能够与网关层的 HTTP 请求事件关联起来。这是"网关 + RASP 双层联动"架构
 * 能够还原完整攻击证据链的技术基础：
 *
 * <pre>
 *   HTTP 请求(网关,TraceID=X) → 业务处理 → SQL 执行(探针,TraceID=X)
 *                                    ↓
 *              大屏依据 TraceID 关联展示：参数 → 真实SQL → AST变异 → 处置
 * </pre>
 *
 * <p>使用 {@link InheritableThreadLocal} 使异步子线程也能继承追踪标识。
 */
public final class TraceContext {

    /** 网关注入的追踪标识请求头名称。 */
    public static final String TRACE_HEADER = "X-Aegis-Trace";

    /** 网关注入的接口标识请求头名称。 */
    public static final String ENDPOINT_HEADER = "X-Aegis-Endpoint";

    private static final InheritableThreadLocal<String> TRACE_ID = new InheritableThreadLocal<>();
    private static final InheritableThreadLocal<String> ENDPOINT = new InheritableThreadLocal<>();
    private static final InheritableThreadLocal<String> SOURCE_IP = new InheritableThreadLocal<>();

    /** 探针内部标记：避免检测逻辑自身触发的数据库操作被递归拦截。 */
    private static final ThreadLocal<Boolean> IN_DETECTION =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private TraceContext() {
    }

    public static void setTraceId(String traceId) {
        TRACE_ID.set(traceId);
    }

    public static String getTraceId() {
        String id = TRACE_ID.get();
        return id == null ? "" : id;
    }

    public static void setEndpoint(String endpoint) {
        ENDPOINT.set(endpoint);
    }

    public static String getEndpoint() {
        String ep = ENDPOINT.get();
        return ep == null ? "UNKNOWN" : ep;
    }

    public static void setSourceIp(String ip) {
        SOURCE_IP.set(ip);
    }

    public static String getSourceIp() {
        String ip = SOURCE_IP.get();
        return ip == null ? "" : ip;
    }

    /**
     * 标记当前线程正在执行检测逻辑。
     *
     * <p>防止探针在上报事件或查询基线时触发的数据库操作被自身再次拦截，
     * 造成无限递归。
     */
    public static void enterDetection() {
        IN_DETECTION.set(Boolean.TRUE);
    }

    public static void exitDetection() {
        IN_DETECTION.set(Boolean.FALSE);
    }

    public static boolean isInDetection() {
        return Boolean.TRUE.equals(IN_DETECTION.get());
    }

    /** 请求结束时清理，防止线程池复用导致的上下文串扰。 */
    public static void clear() {
        TRACE_ID.remove();
        ENDPOINT.remove();
        SOURCE_IP.remove();
    }
}
