package com.aegis.agent.transform;

import com.aegis.agent.detect.SqlGuard;
import net.bytebuddy.asm.Advice;

/**
 * [SEC-RASP-02] JDBC 执行拦截器 —— 探针的核心
 *
 * <p><b>这是整个系统的技术制高点。</b>
 *
 * <p>本拦截器通过字节码注入插入到 {@code Statement.execute*} 方法的入口，
 * 因此它拿到的 SQL 是<b>已经完成全部拼接、即将送入数据库的最终语句</b>。
 * 在这个位置做 AST 结构比对具有网关层无法企及的优势：
 *
 * <table border="1">
 *   <tr><th></th><th>网关层</th><th>RASP 层（本拦截器）</th></tr>
 *   <tr><td>可见对象</td><td>HTTP 参数文本</td><td>真实 SQL 语句</td></tr>
 *   <tr><td>判定性质</td><td>启发式猜测</td><td>确定性结构比对</td></tr>
 *   <tr><td>误报可能</td><td>存在</td><td>极低</td></tr>
 * </table>
 *
 * <p><b>拦截时机的意义：</b>若判定为注入且处于 BLOCK 模式，
 * 本拦截器抛出 {@link SecurityException} 阻断方法执行——
 * SQL 在真正到达数据库<b>之前</b>被拦下，攻击不会产生任何实际效果。
 *
 * <p><b>实现约束：</b>Advice 类的方法体会被<b>内联</b>到目标方法中，
 * 因此不能引用非静态字段、不能使用 lambda，所有逻辑须委托给独立的静态方法。
 */
public final class JdbcInterceptor {

    private JdbcInterceptor() {
    }

    /**
     * 在 SQL 执行前进行检测。
     *
     * <p>方法体将被内联到 {@code Statement.execute(String)} 等方法的开头。
     *
     * <p><b>[关键] 此处不能使用 {@code suppress = Throwable.class}：</b>
     * 该选项会吞掉 Advice 中抛出的<b>所有</b>异常，包括拦截攻击时
     * 主动抛出的 {@link SecurityException}，导致阻断失效——
     * 探针能检出攻击却无法阻止它。
     *
     * <p>失效安全由 {@link SqlGuard#inspect} 内部保证：
     * 它捕获并忽略检测过程中的意外异常，仅让拦截决定向上传播。
     *
     * @param sql 即将执行的 SQL，由被拦截方法的第一个参数提供
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(0) String sql) {
        // 委托给独立类处理，避免在内联代码中引入复杂逻辑
        SqlGuard.inspect(sql);
    }
}
