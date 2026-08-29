package com.aegis.core.engine;

import com.aegis.core.model.Verdict;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 检测引擎端到端集成测试。
 *
 * <p>覆盖设计文档 04 中 TC-01 至 TC-11 的攻击载荷，验证引擎
 * 在"有基线"与"无基线（冷启动）"两种场景下均能正确判定。
 */
class DetectionEngineTest {

    private final DetectionEngine engine = new DetectionEngine();
    private static final String LOGIN_EP = "POST:/api/auth/login";
    private static final String SEARCH_EP = "GET:/api/notes/search";

    /** 登录接口的合法基线 SQL。 */
    private static final List<String> LOGIN_BASELINE = List.of(
            "SELECT id, username, role FROM users WHERE username = 'alice' AND password = 'hash'"
    );

    /** 搜索接口的合法基线 SQL。 */
    private static final List<String> SEARCH_BASELINE = List.of(
            "SELECT id, title, content FROM notes WHERE title LIKE '%keyword%' AND owner_id = 1"
    );

    // ==================== 基线命中：不得误报 ====================

    @Test
    @DisplayName("合法查询命中基线必须放行，且风险分为零")
    void legitimateQueryPasses() {
        String sql = "SELECT id, username, role FROM users "
                + "WHERE username = 'bob' AND password = 'anotherhash'";
        var result = engine.detectSql(sql, LOGIN_EP, LOGIN_BASELINE, 0);

        assertFalse(result.threat(), "合法查询不应判定为威胁");
        assertEquals(Verdict.PASS, result.verdict());
        assertEquals(0, result.riskScore(), "基线命中时风险分应为零");
        assertTrue(result.diff().matched(), "结构应与基线完全一致");
    }

    @Test
    @DisplayName("参数值变化不应影响基线命中")
    void differentParametersStillMatchBaseline() {
        String sql = "SELECT id, title, content FROM notes "
                + "WHERE title LIKE '%完全不同的搜索词%' AND owner_id = 99999";
        var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);
        assertFalse(result.threat(), "仅参数不同的查询必须放行");
    }

    // ==================== TC-01 恒真式绕过认证 ====================

    @Test
    @DisplayName("TC-01 恒真式绕过必须被拦截")
    void tc01_tautologyBypass() {
        String sql = "SELECT id, username, role FROM users "
                + "WHERE username = 'admin' OR '1'='1' AND password = 'x'";
        var result = engine.detectSql(sql, LOGIN_EP, LOGIN_BASELINE, 0);

        assertTrue(result.threat(), "恒真式注入必须被检出");
        assertEquals(Verdict.BLOCK, result.verdict(), "风险分应达到拦截阈值");
        assertTrue(result.riskScore() >= 70, "实际风险分: " + result.riskScore());
        assertFalse(result.evidence().isEmpty(), "必须产出取证依据");
    }

    // ==================== TC-02 UNION 联合查询 ====================

    @Test
    @DisplayName("TC-02 UNION 联合查询脱库必须被拦截")
    void tc02_unionInjection() {
        String sql = "SELECT id, title, content FROM notes WHERE title LIKE '%x%' "
                + "UNION SELECT username, password, email FROM users";
        var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);

        assertTrue(result.threat());
        assertEquals(Verdict.BLOCK, result.verdict());
        assertTrue(result.riskFeatures().contains("R-02"), "应命中 UNION 查询特征");
    }

    // ==================== TC-03 注释截断 ====================

    @Test
    @DisplayName("TC-03 注释截断剥离条件必须被检出")
    void tc03_commentTruncation() {
        String sql = "SELECT id, title, content FROM notes WHERE title LIKE '%x%' -- ' AND owner_id = 1";
        var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);
        assertTrue(result.threat(), "条件被注释剥离必须被检出");
    }

    // ==================== TC-04 内联注释混淆（核心创新验证）====================

    @Test
    @DisplayName("TC-04 内联注释混淆的 UNION 必须被拦截")
    void tc04_inlineCommentEvasion() {
        String sql = "SELECT id, title, content FROM notes WHERE title LIKE '%x%' "
                + "/*!50000UNION*/ SELECT username, password, email FROM users";
        var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);

        assertTrue(result.threat(), "内联注释中的 UNION 必须被还原并检出");
        assertEquals(Verdict.BLOCK, result.verdict());
    }

    @Test
    @DisplayName("TC-04 三种混淆变形应全部拦截，证明优于正则方案")
    void tc04_allObfuscationVariantsBlocked() {
        String[] variants = {
                "SELECT id, title, content FROM notes WHERE title LIKE '%x%' UNION SELECT username, password, email FROM users",
                "SELECT id, title, content FROM notes WHERE title LIKE '%x%' /*!50000UNION*/ SELECT username, password, email FROM users",
                "SELECT id, title, content FROM notes WHERE title LIKE '%x%' uNiOn SeLeCt username, password, email FROM users",
                "SELECT id, title, content FROM notes WHERE title LIKE '%x%' UNION/**/SELECT username, password, email FROM users"
        };
        for (String sql : variants) {
            var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);
            assertEquals(Verdict.BLOCK, result.verdict(),
                    "变形载荷未被拦截: " + sql);
        }
    }

    // ==================== TC-05 时间盲注 ====================

    @Test
    @DisplayName("TC-05 时间盲注函数必须被拦截，且无基线时也生效")
    void tc05_timeBlindInjection() {
        String sql = "SELECT id FROM notes WHERE id = 1 AND SLEEP(5)";
        // 无基线场景，验证冷启动兜底能力
        var result = engine.detectSql(sql, "GET:/api/unknown", List.of(), 0);

        assertTrue(result.threat(), "冷启动无基线时仍须检出危险函数");
        assertEquals(Verdict.BLOCK, result.verdict());
        assertTrue(result.riskFeatures().contains("R-05"), "应命中时间盲注特征");
    }

    // ==================== TC-06 堆叠查询 ====================

    @Test
    @DisplayName("TC-06 堆叠查询必须被拦截")
    void tc06_stackedQuery() {
        String sql = "SELECT id FROM notes WHERE id = 1; DROP TABLE users";
        var result = engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);

        assertTrue(result.threat());
        assertEquals(Verdict.BLOCK, result.verdict());
        assertTrue(result.riskFeatures().contains("R-03"), "应命中堆叠查询特征");
    }

    // ==================== 系统表访问与信息收集 ====================

    @Test
    @DisplayName("information_schema 访问必须被检出")
    void systemTableAccessDetected() {
        String sql = "SELECT table_name FROM information_schema.tables";
        var result = engine.detectSql(sql, "GET:/api/unknown", List.of(), 0);
        assertTrue(result.threat(), "系统表访问属于注入信息收集，必须检出");
        assertTrue(result.riskFeatures().contains("R-07"));
    }

    // ==================== 网关层参数检测 ====================

    @Test
    @DisplayName("网关层应检出参数中的 SQL 注入意图")
    void gatewayDetectsSqlInjectionIntent() {
        var result = engine.detectParameter("id", "1' OR '1'='1");
        assertTrue(result.threat(), "网关层应识别注入意图");
        assertTrue(result.riskScore() >= 50);
    }

    @Test
    @DisplayName("TC-07 多重 URL 编码绕过必须被还原并检出")
    void tc07_multipleUrlEncoding() {
        // %2527 为双重编码的单引号
        var result = engine.detectParameter("id", "1%2527%2520OR%2520%25271%2527%253D%25271");
        assertTrue(result.riskScore() > 0, "多重编码本身即为风险信号");
    }

    @Test
    @DisplayName("TC-08 网关层应检出 XSS 载荷")
    void tc08_gatewayDetectsXss() {
        var result = engine.detectParameter("content", "<img src=x onerror=alert(1)>");
        assertTrue(result.threat(), "XSS 载荷必须被检出");
        assertEquals(Verdict.BLOCK, result.verdict());
    }

    @Test
    @DisplayName("TC-14 网关层应检出路径穿越")
    void tc14_gatewayDetectsPathTraversal() {
        var result = engine.detectParameter("file", "../../../../etc/passwd");
        assertTrue(result.threat(), "路径穿越必须被检出");
        assertEquals(Verdict.BLOCK, result.verdict());
    }

    @Test
    @DisplayName("TC-11 网关层应检出命令注入")
    void tc11_gatewayDetectsCommandInjection() {
        var result = engine.detectParameter("host", "127.0.0.1; cat /etc/passwd");
        assertTrue(result.threat(), "命令注入必须被检出");
        assertEquals(Verdict.BLOCK, result.verdict());
    }

    @Test
    @DisplayName("正常参数值不得误报")
    void normalParametersNotFlagged() {
        String[] normalValues = {
                "hello world",
                "张三的读书笔记",
                "user@example.com",
                "2026-08-29",
                "价格 199.99 元",
                "这是一段包含 and 与 or 的正常中文描述",
                "C:\\Users\\Documents\\report.pdf"
        };
        for (String value : normalValues) {
            var result = engine.detectParameter("q", value);
            assertFalse(result.threat(),
                    "正常值被误报为攻击: " + value + " (score=" + result.riskScore() + ")");
        }
    }

    // ==================== 可视化数据契约 ====================

    @Test
    @DisplayName("检出攻击时必须产出可视化树数据")
    void visualTreeProducedOnThreat() {
        String sql = "SELECT id, username, role FROM users "
                + "WHERE username = 'admin' OR '1'='1' AND password = 'x'";
        var result = engine.detectSql(sql, LOGIN_EP, LOGIN_BASELINE, 0);

        assertNotNull(result.visualTree());
        assertFalse(result.visualTree().isEmpty(), "必须产出前端可消费的可视化树");
        assertTrue(result.visualTree().containsKey("tree"));
        assertTrue(result.visualTree().containsKey("annotations"));
    }

    // ==================== 健壮性 ====================

    @Test
    @DisplayName("异常输入不得导致引擎崩溃")
    void engineRobustness() {
        assertDoesNotThrow(() -> engine.detectSql(null, LOGIN_EP, LOGIN_BASELINE, 0));
        assertDoesNotThrow(() -> engine.detectSql("", LOGIN_EP, LOGIN_BASELINE, 0));
        assertDoesNotThrow(() -> engine.detectSql("!!!@#$%^&*()", LOGIN_EP, LOGIN_BASELINE, 0));
        assertDoesNotThrow(() -> engine.detectParameter(null, null));
        assertDoesNotThrow(() -> engine.detectSql("SELECT " + "(".repeat(200), LOGIN_EP, List.of(), 0));
    }

    @Test
    @DisplayName("检测耗时应满足性能要求")
    void detectionPerformance() {
        String sql = "SELECT id, title, content FROM notes WHERE title LIKE '%x%' AND owner_id = 1";
        // 预热
        for (int i = 0; i < 100; i++) {
            engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);
        }
        long start = System.nanoTime();
        int iterations = 1000;
        for (int i = 0; i < iterations; i++) {
            engine.detectSql(sql, SEARCH_EP, SEARCH_BASELINE, 0);
        }
        long avgMicros = (System.nanoTime() - start) / iterations / 1000;
        assertTrue(avgMicros < 5000,
                "平均检测耗时 " + avgMicros + "μs，应低于 5000μs(5ms)");
    }
}
