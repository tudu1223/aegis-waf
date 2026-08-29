package com.aegis.agent.transform;

import com.aegis.agent.detect.CommandGuard;
import net.bytebuddy.asm.Advice;

import java.util.List;

/**
 * [SEC-RASP-05] 命令执行拦截器
 *
 * <p>钩取 {@code ProcessBuilder.start()}，在系统命令真正执行前完成检测。
 * 对应测试用例 TC-11（命令注入，CVSS 9.8）。
 *
 * <p><b>为何钩 ProcessBuilder 而非 Runtime.exec：</b>
 * {@code Runtime.exec} 的所有重载最终都委托给 {@code ProcessBuilder.start()}，
 * 因此在此处设钩可以覆盖两类调用方式，避免遗漏。
 */
public final class ProcessInterceptor {

    private ProcessInterceptor() {
    }

    /**
     * 在进程启动前检测命令内容。
     *
     * <p>与 {@link JdbcInterceptor} 同理，此处不使用 {@code suppress}，
     * 否则拦截攻击时抛出的 {@link SecurityException} 会被吞掉导致阻断失效。
     *
     * @param command 命令及其参数列表，从 ProcessBuilder 的 command 字段读取
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.FieldValue("command") List<String> command) {
        CommandGuard.inspect(command);
    }
}
