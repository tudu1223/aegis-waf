package com.aegis.agent.transform;

import com.aegis.agent.context.TraceContext;
import net.bytebuddy.asm.Advice;

/**
 * [SEC-RASP-04] HTTP 追踪拦截器
 *
 * <p><b>双层联动的关键环节。</b>
 *
 * <p>网关在转发请求时会注入 {@code X-Aegis-Trace} 与 {@code X-Aegis-Endpoint}
 * 请求头。本拦截器在 Servlet 过滤器链的入口读取这两个头并写入线程上下文，
 * 使后续在同一线程上执行的 SQL 检测事件能够关联回源 HTTP 请求。
 *
 * <p>没有这一步，探针捕获的 SQL 就是"孤立的"，无法回答
 * "这条注入语句是由哪个请求的哪个参数造成的"——
 * 而这正是安全取证最需要的信息。
 */
public final class HttpTraceInterceptor {

    private HttpTraceInterceptor() {
    }

    /** 请求进入时提取追踪标识。 */
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.Argument(0) Object request) {
        TraceExtractor.extract(request);
    }

    /** 请求结束时清理上下文，防止线程池复用导致串扰。 */
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void onExit() {
        TraceExtractor.clear();
    }

    /**
     * 追踪信息提取器。
     *
     * <p>使用反射访问 Servlet API，避免探针模块对 Servlet 容器产生编译期依赖——
     * 探针需要能挂载到任意 Java 应用上，不应绑定特定的 Web 框架。
     */
    public static final class TraceExtractor {

        private TraceExtractor() {
        }

        public static void extract(Object request) {
            if (request == null) {
                return;
            }
            try {
                Class<?> clazz = request.getClass();
                java.lang.reflect.Method getHeader =
                        findMethod(clazz, "getHeader", String.class);
                if (getHeader == null) {
                    return;
                }
                getHeader.setAccessible(true);

                Object traceId = getHeader.invoke(request, TraceContext.TRACE_HEADER);
                if (traceId != null) {
                    TraceContext.setTraceId(String.valueOf(traceId));
                }

                Object endpoint = getHeader.invoke(request, TraceContext.ENDPOINT_HEADER);
                if (endpoint != null) {
                    TraceContext.setEndpoint(String.valueOf(endpoint));
                } else {
                    // 未经网关的直连请求：自行构造接口标识，
                    // 保证直连场景下探针仍能正常工作
                    buildEndpointFromRequest(request, clazz);
                }

                extractSourceIp(request, clazz, getHeader);
            } catch (Throwable ignored) {
                // 提取失败不影响业务，检测降级为无接口上下文
            }
        }

        private static void buildEndpointFromRequest(Object request, Class<?> clazz)
                throws Exception {
            java.lang.reflect.Method getMethod = findMethod(clazz, "getMethod");
            java.lang.reflect.Method getRequestUri = findMethod(clazz, "getRequestURI");
            if (getMethod != null && getRequestUri != null) {
                getMethod.setAccessible(true);
                getRequestUri.setAccessible(true);
                Object m = getMethod.invoke(request);
                Object uri = getRequestUri.invoke(request);
                TraceContext.setEndpoint(m + ":" + uri);
            }
        }

        private static void extractSourceIp(Object request, Class<?> clazz,
                                            java.lang.reflect.Method getHeader) throws Exception {
            Object forwarded = getHeader.invoke(request, "X-Forwarded-For");
            if (forwarded != null && !String.valueOf(forwarded).isBlank()) {
                String ip = String.valueOf(forwarded).split(",")[0].trim();
                TraceContext.setSourceIp(ip);
                return;
            }
            java.lang.reflect.Method getRemoteAddr = findMethod(clazz, "getRemoteAddr");
            if (getRemoteAddr != null) {
                getRemoteAddr.setAccessible(true);
                Object addr = getRemoteAddr.invoke(request);
                if (addr != null) {
                    TraceContext.setSourceIp(String.valueOf(addr));
                }
            }
        }

        /** 沿类继承链查找方法，兼容各类 Request 包装器。 */
        private static java.lang.reflect.Method findMethod(Class<?> clazz, String name,
                                                           Class<?>... paramTypes) {
            Class<?> current = clazz;
            while (current != null && current != Object.class) {
                try {
                    return current.getMethod(name, paramTypes);
                } catch (NoSuchMethodException e) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        public static void clear() {
            TraceContext.clear();
        }
    }
}
