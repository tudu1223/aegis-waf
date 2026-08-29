package com.aegis.agent;

import com.aegis.agent.report.EventReporter;
import com.aegis.agent.transform.HttpTraceInterceptor;
import com.aegis.agent.transform.JdbcInterceptor;
import com.aegis.agent.transform.ProcessInterceptor;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.util.HashMap;
import java.util.Map;

/**
 * [SEC-RASP-01] AEGIS RASP 探针入口
 *
 * <p><b>架构价值 —— 为何需要 RASP 层：</b>
 * 网关层只能看到 HTTP 参数，它对"这个参数是否会造成注入"永远只能<b>猜测</b>——
 * 这正是传统 WAF 误报与漏报并存的根源。而 RASP 探针工作在应用进程内部，
 * 通过字节码注入钩取 JDBC 执行点，拿到的是<b>已经拼接完成、即将送入数据库的
 * 真实 SQL</b>。此时进行 AST 结构比对是<b>确定性判定</b>，不存在"像不像"的问题，
 * 只有"结构变没变"。
 *
 * <p>两层通过 TraceID 关联，可还原完整的攻击证据链：
 * HTTP 请求 → 被污染的参数 → 生成的真实 SQL → AST 结构变异 → 处置结果。
 *
 * <p><b>工作原理：</b>
 * 通过 JVM 的 {@code -javaagent} 机制在类加载时改写字节码，
 * 在目标方法前后插入检测逻辑。被钩取的关键点：
 * <ul>
 *   <li>{@code java.sql.Statement#execute*} —— 捕获真实 SQL</li>
 *   <li>{@code java.sql.Connection#prepareStatement} —— 捕获预编译模板</li>
 *   <li>{@code ProcessBuilder#start} —— 捕获命令执行</li>
 *   <li>{@code HttpServlet#service} —— 提取网关注入的 TraceID</li>
 * </ul>
 *
 * <p><b>启动方式：</b>
 * <pre>
 *   java -javaagent:aegis-agent.jar=console=http://localhost:8080,mode=BLOCK \
 *        -jar vuln-target.jar
 * </pre>
 */
public final class AegisAgent {

    /** 控制台地址，探针将检测事件上报至此。 */
    private static String consoleUrl = "http://localhost:8080";

    /** 防护模式：OFF / MONITOR / BLOCK。 */
    private static volatile String mode = "MONITOR";

    private AegisAgent() {
    }

    /**
     * JVM 启动时的探针入口。
     *
     * @param agentArgs       形如 {@code console=http://host:port,mode=BLOCK} 的参数
     * @param instrumentation JVM 提供的字节码改写接口
     */
    public static void premain(String agentArgs, Instrumentation instrumentation) {
        Map<String, String> args = parseArgs(agentArgs);
        consoleUrl = args.getOrDefault("console", consoleUrl);
        mode = args.getOrDefault("mode", mode);

        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║  AEGIS RASP 探针已激活                                ║");
        System.out.println("║  控制台: " + pad(consoleUrl, 44) + "║");
        System.out.println("║  防护模式: " + pad(mode, 42) + "║");
        System.out.println("╚══════════════════════════════════════════════════════╝");

        EventReporter.initialize(consoleUrl);
        // 启动策略同步，使控制台上的模式切换能够实时作用于探针层，
        // 保证网关与探针两层的防护模式始终一致
        com.aegis.agent.report.PolicySynchronizer.start(consoleUrl);

        installJdbcHooks(instrumentation);
        installProcessHooks(instrumentation);
        installHttpHooks(instrumentation);
    }

    /** 支持运行时动态挂载（attach 方式），便于演示。 */
    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        premain(agentArgs, instrumentation);
    }

    /**
     * 安装 JDBC 钩子 —— 探针的核心。
     *
     * <p>拦截 {@code Statement} 及其子接口的 execute 系列方法，
     * 在 SQL 真正送达数据库<b>之前</b>完成结构判定。
     * 若判定为注入且处于拦截模式，抛出异常阻断执行——
     * 这是在攻击生效前的最后一道防线。
     */
    private static void installJdbcHooks(Instrumentation instrumentation) {
        new AgentBuilder.Default()
                // JDBC 接口位于 java.sql 包，属于引导类加载器加载的核心类，
                // 需要显式忽略默认的类加载器过滤规则
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy.")
                        .or(ElementMatchers.nameStartsWith("com.aegis.agent."))
                        .or(ElementMatchers.nameStartsWith("org.slf4j.")))
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .with(new LoggingListener())
                .type(ElementMatchers.isSubTypeOf(java.sql.Statement.class)
                        .and(ElementMatchers.not(ElementMatchers.isInterface())))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                        builder.visit(net.bytebuddy.asm.Advice
                                .to(JdbcInterceptor.class)
                                .on(ElementMatchers.nameStartsWith("execute")
                                        .and(ElementMatchers.takesArgument(0, String.class)))))
                .installOn(instrumentation);
    }

    /** 安装命令执行钩子，用于命令注入检测（TC-11）。 */
    private static void installProcessHooks(Instrumentation instrumentation) {
        new AgentBuilder.Default()
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy.")
                        .or(ElementMatchers.nameStartsWith("com.aegis.agent.")))
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .type(ElementMatchers.named("java.lang.ProcessBuilder"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                        builder.visit(net.bytebuddy.asm.Advice
                                .to(ProcessInterceptor.class)
                                .on(ElementMatchers.named("start")
                                        .and(ElementMatchers.takesNoArguments()))))
                .installOn(instrumentation);
    }

    /**
     * 安装 HTTP 钩子，提取网关注入的 TraceID。
     *
     * <p>这是双层联动的关键：网关在转发请求时写入 {@code X-Aegis-Trace} 头，
     * 探针在此处读取并存入线程上下文，使后续的 SQL 事件能够关联到源请求。
     */
    private static void installHttpHooks(Instrumentation instrumentation) {
        new AgentBuilder.Default()
                .ignore(ElementMatchers.nameStartsWith("net.bytebuddy.")
                        .or(ElementMatchers.nameStartsWith("com.aegis.agent.")))
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .type(ElementMatchers.named("org.apache.catalina.core.ApplicationFilterChain"))
                .transform((builder, typeDescription, classLoader, module, protectionDomain) ->
                        builder.visit(net.bytebuddy.asm.Advice
                                .to(HttpTraceInterceptor.class)
                                .on(ElementMatchers.named("doFilter"))))
                .installOn(instrumentation);
    }

    public static String getMode() {
        return mode;
    }

    public static void setMode(String newMode) {
        mode = newMode;
    }

    public static String getConsoleUrl() {
        return consoleUrl;
    }

    /** 是否处于拦截模式。 */
    public static boolean isBlockMode() {
        return "BLOCK".equalsIgnoreCase(mode);
    }

    /** 是否完全关闭防护。 */
    public static boolean isOff() {
        return "OFF".equalsIgnoreCase(mode);
    }

    private static Map<String, String> parseArgs(String agentArgs) {
        Map<String, String> map = new HashMap<>();
        if (agentArgs == null || agentArgs.isBlank()) {
            return map;
        }
        for (String pair : agentArgs.split(",")) {
            int idx = pair.indexOf('=');
            if (idx > 0) {
                map.put(pair.substring(0, idx).trim(), pair.substring(idx + 1).trim());
            }
        }
        return map;
    }

    private static String pad(String s, int width) {
        if (s.length() >= width) {
            return s.substring(0, width);
        }
        return s + " ".repeat(width - s.length());
    }

    /** 字节码改写日志监听器，用于诊断探针是否成功挂载。 */
    private static class LoggingListener extends AgentBuilder.Listener.Adapter {
        @Override
        public void onError(String typeName, ClassLoader classLoader, JavaModule module,
                            boolean loaded, Throwable throwable) {
            // 单个类改写失败不应影响应用启动，仅记录
            if (System.getProperty("aegis.agent.debug") != null) {
                System.err.println("[AEGIS] 类改写失败: " + typeName
                        + " 原因: " + throwable.getMessage());
            }
        }

        @Override
        public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader,
                                     JavaModule module, boolean loaded,
                                     net.bytebuddy.dynamic.DynamicType dynamicType) {
            if (System.getProperty("aegis.agent.debug") != null) {
                System.out.println("[AEGIS] 已挂载探针: " + typeDescription.getName());
            }
        }
    }
}
