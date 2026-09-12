package com.aegis.agent.detect;

import com.aegis.agent.AegisAgent;
import com.aegis.agent.context.TraceContext;
import com.aegis.agent.report.EventReporter;
import com.aegis.core.cmd.CommandInjectionDetector;

import java.util.ArrayList;
import java.util.List;

/**
 * [SEC-RASP-06] 命令执行守卫
 *
 * <p>在系统命令真正执行前判定是否存在注入。对应 TC-11（CVSS 9.8）。
 *
 * <p><b>RASP 层检测命令注入的优势：</b>
 * 网关层只能猜测参数是否会流入命令执行；而本守卫拿到的是
 * <b>即将传给操作系统的完整命令与参数数组</b>，
 * 可以准确判断是否存在 shell 元字符逃逸或敏感命令调用。
 */
public final class CommandGuard {

    /** 反射桥接用的入口缓存：内联进 ProcessBuilder 的 Advice 无状态，
     *  经 Class.forName 定位本类后调用此方法，缓存由本类静态字段持有。 */
    private static volatile java.lang.reflect.Method selfMethod;

    private CommandGuard() {
    }

    /**
     * 反射桥接入口。
     *
     * <p>{@code ProcessBuilder} 由引导类加载器加载，内联进其 {@code start()}
     * 的检测代码无法直接引用本类（系统类加载器），因此经反射调用。
     * 本方法缓存自身的 Method 对象，将反射查找开销降为一次。
     *
     * @param command 命令及参数列表
     */
    public static void bridgeInspect(List<String> command) {
        try {
            java.lang.reflect.Method m = selfMethod;
            if (m == null) {
                m = CommandGuard.class.getDeclaredMethod("inspect", List.class);
                selfMethod = m;
            }
            m.invoke(null, command);
        } catch (Throwable t) {
            Throwable cause = t.getCause() != null ? t.getCause() : t;
            if (cause instanceof SecurityException) {
                throw (SecurityException) cause;
            }
            // 桥接异常：失败安全，放行
        }
    }

    /**
     * 检查即将执行的系统命令。
     *
     * @param command 命令及参数列表
     * @throws SecurityException 判定为注入且处于拦截模式时抛出
     */
    public static void inspect(List<String> command) {
        if (command == null || command.isEmpty() || AegisAgent.isOff()) {
            return;
        }
        if (TraceContext.isInDetection()) {
            return;
        }

        try {
            TraceContext.enterDetection();

            String executable = command.get(0);
            List<String> arguments = command.size() > 1
                    ? new ArrayList<>(command.subList(1, command.size()))
                    : List.of();

            // 判断是否为 shell 解析型调用：
            // sh -c "..." 或 cmd /c "..." 形式会将参数交由 shell 解释，
            // 这是命令注入得以成立的前提条件
            boolean shellParsed = isShellInvocation(executable, arguments);

            CommandInjectionDetector.Result result =
                    CommandInjectionDetector.detect(executable, arguments, shellParsed);

            if (!result.injection()) {
                return;
            }

            EventReporter.reportCommandEvent(
                    TraceContext.getTraceId(),
                    TraceContext.getEndpoint(),
                    TraceContext.getSourceIp(),
                    result);

            if (AegisAgent.isBlockMode()) {
                throw new SecurityException(
                        "AEGIS 已拦截疑似命令注入 [风险评分 " + result.score() + "/100]: "
                                + String.join("; ", result.evidence()));
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            // 失效安全：检测异常不影响业务
            if (System.getProperty("aegis.agent.debug") != null) {
                System.err.println("[AEGIS] 命令检测异常(已放行): " + t.getMessage());
            }
        } finally {
            TraceContext.exitDetection();
        }
    }

    /**
     * 判断调用是否会经过 shell 解析。
     *
     * <p>{@code sh -c "cmd"} 与 {@code cmd /c "cmd"} 形式中，
     * 后续参数会被 shell 重新解释，元字符具有特殊语义，
     * 这是命令注入的必要条件。直接执行程序则不存在此风险。
     */
    private static boolean isShellInvocation(String executable, List<String> arguments) {
        if (executable == null) {
            return false;
        }
        String exe = executable.toLowerCase().replace('\\', '/');
        // 提取程序名，忽略路径前缀
        int lastSlash = exe.lastIndexOf('/');
        if (lastSlash >= 0) {
            exe = exe.substring(lastSlash + 1);
        }

        boolean isShell = exe.equals("sh") || exe.equals("bash") || exe.equals("zsh")
                || exe.equals("dash") || exe.equals("ksh")
                || exe.equals("cmd") || exe.equals("cmd.exe")
                || exe.equals("powershell") || exe.equals("powershell.exe");

        if (!isShell) {
            return false;
        }
        // 带 -c 或 /c 参数才表示"执行给定的命令字符串"
        for (String arg : arguments) {
            if ("-c".equalsIgnoreCase(arg) || "/c".equalsIgnoreCase(arg)) {
                return true;
            }
        }
        return false;
    }
}
