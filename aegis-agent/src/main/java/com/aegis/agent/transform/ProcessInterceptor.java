package com.aegis.agent.transform;

import net.bytebuddy.asm.Advice;

import java.util.List;

/**
 * [SEC-RASP-05] 命令执行拦截器
 *
 * <p>钩取 {@code ProcessBuilder#start()}，在系统命令真正执行前完成检测。
 * 对应测试用例 TC-11（命令注入，CVSS 9.8）。
 *
 * <p><b>为何钩 ProcessBuilder 而非 Runtime.exec：</b>
 * {@code Runtime.exec} 的所有重载最终都委托给 {@code ProcessBuilder.start()}，
 * 因此在此处设钩可以覆盖两类调用方式，避免遗漏。
 *
 * <p><b>为何使用反射桥接而非直接调用 CommandGuard：</b>
 * {@code ProcessBuilder} 由<b>引导类加载器</b>加载，本 Advice 的方法体会被
 * <b>内联</b>进 {@code ProcessBuilder.start()}，其中对 {@code CommandGuard}
 * 的直接引用将沿引导类加载器解析——而 agent jar 挂在系统类加载器上，
 * 直接引用会抛 {@code NoClassDefFoundError}，使命令执行整体失败。
 *
 * <p>反射桥接经 {@code ClassLoader.getSystemClassLoader()} 定位守卫类：
 * 内联代码只依赖 JDK 核心类型（Class/Method），可被引导类加载器解析；
 * 同时命中系统类加载器中的唯一实例，保持守卫状态（模式开关、事件上报）
 * 单副本。反射开销仅在命令执行这条低频路径上产生，对业务吞吐无实质影响。
 *
 * <p>失败安全：桥接异常不中断业务命令执行；但拦截决定
 * （守卫抛出的 {@link SecurityException}）必须解包重新抛出，
 * 否则阻断会失效——探针看得见攻击却拦不住。
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
     * <p>注意：内联进 JDK 核心类的代码不应持有静态可变字段
     * （retransformation 语义不明且有安全审查风险），因此这里
     * 每次都经 {@code Class.forName} 取类、由守卫自身的静态字段
     * 缓存 Method——内联体保持无状态。
     *
     * @param command 命令及其参数列表，从 ProcessBuilder 的 command 字段读取
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.FieldValue("command") List<String> command) {
        try {
            Class.forName("com.aegis.agent.detect.CommandGuard", true,
                            ClassLoader.getSystemClassLoader())
                    .getMethod("bridgeInspect", List.class)
                    .invoke(null, command);
        } catch (Throwable t) {
            if (t instanceof SecurityException) {
                throw (SecurityException) t;
            }
            Throwable cause = t.getCause();
            if (cause instanceof SecurityException) {
                throw (SecurityException) cause;
            }
            // 其余桥接异常：失败安全，放行命令执行
        }
    }
}
