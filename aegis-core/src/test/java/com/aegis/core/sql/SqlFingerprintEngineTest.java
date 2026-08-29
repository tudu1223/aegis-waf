package com.aegis.core.sql;

import com.aegis.core.sql.fingerprint.SqlFingerprintEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SQL 结构指纹引擎核心性质验证。
 *
 * <p>本测试类验证指纹算法的三条核心性质，它们构成整个检测方案的理论基础：
 * <ol>
 *   <li><b>参数无关性</b>：同结构不同参数 → 指纹相同</li>
 *   <li><b>形态无关性</b>：文本混淆不改变结构 → 指纹相同</li>
 *   <li><b>结构敏感性</b>：注入引入新结构 → 指纹必然改变</li>
 * </ol>
 */
class SqlFingerprintEngineTest {

    private final SqlFingerprintEngine engine = new SqlFingerprintEngine();
    private static final String EP = "GET:/api/notes/detail";

    private String fp(String sql) {
        return engine.fingerprint(sql, EP);
    }

    // ==================== 性质一：参数无关性 ====================

    @Test
    @DisplayName("同一结构不同参数取值应产生相同指纹")
    void sameStructureDifferentLiterals() {
        String a = "SELECT id, title FROM notes WHERE owner = 'alice' AND id = 42";
        String b = "SELECT id, title FROM notes WHERE owner = 'bob' AND id = 1337";
        assertEquals(fp(a), fp(b), "仅字面量不同的语句必须收敛为同一指纹");
    }

    @Test
    @DisplayName("IN 列表长度不同应产生相同指纹，避免基线爆炸")
    void inListLengthIrrelevant() {
        String a = "SELECT * FROM notes WHERE id IN (1, 2)";
        String b = "SELECT * FROM notes WHERE id IN (1, 2, 3, 4, 5)";
        assertEquals(fp(a), fp(b), "IN 列表长度不应影响结构指纹");
    }

    @Test
    @DisplayName("LIMIT 数值不同应产生相同指纹")
    void limitValueIrrelevant() {
        assertEquals(fp("SELECT * FROM notes LIMIT 10"),
                fp("SELECT * FROM notes LIMIT 500"));
    }

    // ==================== 性质二：形态无关性（抗混淆）====================

    @Test
    @DisplayName("大小写混淆不应改变指纹")
    void caseInsensitive() {
        String a = "SELECT * FROM notes WHERE id = 1";
        String b = "sElEcT * FrOm NOTES wHeRe ID = 1";
        assertEquals(fp(a), fp(b), "大小写混淆必须被消解");
    }

    @Test
    @DisplayName("空白与换行差异不应改变指纹")
    void whitespaceInsensitive() {
        String a = "SELECT * FROM notes WHERE id = 1";
        String b = "SELECT\t*\n\nFROM   notes\r\nWHERE     id=1";
        assertEquals(fp(a), fp(b));
    }

    @Test
    @DisplayName("注释拆分关键字不应改变指纹")
    void commentSplittingNeutralized() {
        String a = "SELECT * FROM notes WHERE id = 1";
        String b = "SELECT/**/*/**/FROM/**/notes/**/WHERE/**/id/**/=/**/1";
        assertEquals(fp(a), fp(b), "注释拆分必须在词法阶段被消解");
    }

    @Test
    @DisplayName("AND/OR 操作数交换顺序不应改变指纹")
    void commutativeOperandsConverge() {
        String a = "SELECT * FROM notes WHERE owner = 'a' AND id = 1";
        String b = "SELECT * FROM notes WHERE id = 1 AND owner = 'a'";
        assertEquals(fp(a), fp(b), "满足交换律的操作数应排序后收敛");
    }

    // ==================== 性质三：结构敏感性（检出注入）====================

    @Test
    @DisplayName("OR 恒真式注入必须改变指纹")
    void orTautologyChangesFingerprint() {
        String legit = "SELECT * FROM users WHERE username = 'admin' AND password = 'x'";
        String inject = "SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'x'";
        assertNotEquals(fp(legit), fp(inject), "OR 注入必须导致指纹失配");
    }

    @Test
    @DisplayName("UNION 联合查询注入必须改变指纹")
    void unionInjectionChangesFingerprint() {
        String legit = "SELECT title FROM notes WHERE id = 1";
        String inject = "SELECT title FROM notes WHERE id = 1 UNION SELECT password FROM users";
        assertNotEquals(fp(legit), fp(inject));
    }

    @Test
    @DisplayName("注释截断剥离条件必须改变指纹")
    void commentTruncationChangesFingerprint() {
        String legit = "SELECT * FROM notes WHERE id = 1 AND owner = 'alice'";
        String inject = "SELECT * FROM notes WHERE id = 1 -- AND owner = 'alice'";
        assertNotEquals(fp(legit), fp(inject), "条件被注释剥离必须被检出");
    }

    @Test
    @DisplayName("堆叠查询必须改变指纹")
    void stackedQueryChangesFingerprint() {
        String legit = "SELECT * FROM notes WHERE id = 1";
        String inject = "SELECT * FROM notes WHERE id = 1; DROP TABLE users";
        assertNotEquals(fp(legit), fp(inject));
    }

    // ==================== 核心创新验证：内联注释混淆 ====================

    @Test
    @DisplayName("MySQL 内联注释混淆的 UNION 必须被还原并检出")
    void mysqlInlineCommentUnionDetected() {
        String legit = "SELECT title FROM notes WHERE id = 1";
        // /*!50000UNION*/ 会被 MySQL 真实执行，若整体丢弃将导致严重漏报
        String inject = "SELECT title FROM notes WHERE id = 1/*!50000UNION*/SELECT password FROM users";
        assertNotEquals(fp(legit), fp(inject),
                "内联注释中的 UNION 必须被还原为可执行结构并检出");
    }

    @Test
    @DisplayName("三种混淆变形的 UNION 注入应收敛为同一指纹")
    void obfuscationVariantsConverge() {
        String v1 = "SELECT a FROM t WHERE id = 1 UNION SELECT p FROM u";
        String v2 = "SELECT a FROM t WHERE id = 1 UNI/**/ON SELECT p FROM u";
        String v3 = "SELECT a FROM t WHERE id = 1 uNiOn SeLeCt p FROM u";
        assertEquals(fp(v1), fp(v2), "注释拆分变形应与原型收敛");
        assertEquals(fp(v1), fp(v3), "大小写变形应与原型收敛");
    }

    // ==================== 健壮性：容错解析 ====================

    @Test
    @DisplayName("语法非法的注入载荷也必须能被解析并产出指纹")
    void malformedSqlStillProducesFingerprint() {
        String malformed = "SELECT * FROM users WHERE name = 'admin' OR '1'='1' --'";
        String result = fp(malformed);
        assertNotNull(result);
        assertEquals(32, result.length(), "任何输入都必须产出定长指纹");
    }

    @Test
    @DisplayName("空输入与 null 不应抛出异常")
    void nullAndEmptyInputSafe() {
        assertDoesNotThrow(() -> engine.analyze(null, EP));
        assertDoesNotThrow(() -> engine.analyze("", EP));
        assertDoesNotThrow(() -> engine.analyze("   ", EP));
    }

    @Test
    @DisplayName("指纹必须绑定接口标识，防止跨接口复用绕过")
    void fingerprintBoundToEndpoint() {
        String sql = "SELECT * FROM notes WHERE id = 1";
        String fpA = engine.fingerprint(sql, "GET:/api/a");
        String fpB = engine.fingerprint(sql, "GET:/api/b");
        assertNotEquals(fpA, fpB, "相同 SQL 在不同接口下必须产生不同指纹");
    }
}
