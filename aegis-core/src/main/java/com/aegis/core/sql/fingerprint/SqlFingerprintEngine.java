package com.aegis.core.sql.fingerprint;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.parser.SqlParser;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

/**
 * [SEC-SQLI-05] SQL 结构指纹引擎
 *
 * <p><b>安全原理：</b>
 * 将一条 SQL 依次经过"词法分析 → 语法分析 → 字面量归一化 → 规范化序列化 → 哈希"
 * 的流水线，得到一个仅反映其<b>语义结构</b>的定长指纹。
 *
 * <p>该指纹具有以下性质：
 * <ul>
 *   <li><b>参数无关</b>：同一模板不同参数取值 → 指纹相同</li>
 *   <li><b>形态无关</b>：大小写、空白、注释拆分、内联注释 → 指纹相同</li>
 *   <li><b>结构敏感</b>：任何语法结构的改变 → 指纹必然不同</li>
 * </ul>
 *
 * <p>由此，对每个业务接口学习其合法 SQL 的指纹集合作为基线后，
 * 注入攻击必然因结构改变而指纹失配，被确定性地检出——
 * 这与依赖特征库的正则匹配有本质区别。
 *
 * <p><b>指纹绑定接口标识的理由：</b>
 * 若指纹全局共享，攻击者可将接口 A 的合法结构用于接口 B 从而绕过检测。
 * 指纹计算为 {@code SHA-256(endpoint + "|" + canonical)}，保证基线是接口级隔离的。
 *
 * <p><b>性能设计：</b>内置 LRU 缓存，重复 SQL 直接返回缓存指纹，
 * 使高频重复查询的检测开销降至可忽略水平。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入（DREAD 9.0）、T-12 检测绕过（DREAD 8.0）
 */
public final class SqlFingerprintEngine {

    /** 指纹长度（十六进制字符数）。取 SHA-256 前 16 字节，碰撞概率可忽略。 */
    private static final int FINGERPRINT_HEX_LENGTH = 32;

    /** SQL 长度上限，防御超长载荷导致的解析资源耗尽（可用性防护）。 */
    private static final int MAX_SQL_LENGTH = 64 * 1024;

    private final Cache<String, ParseResult> cache;

    public SqlFingerprintEngine() {
        this(10_000);
    }

    public SqlFingerprintEngine(int cacheSize) {
        this.cache = Caffeine.newBuilder()
                .maximumSize(cacheSize)
                .expireAfterAccess(Duration.ofMinutes(30))
                .build();
    }

    /**
     * 解析 SQL 并计算结构指纹。
     *
     * @param sql      待分析的 SQL（RASP 探针捕获的真实语句）
     * @param endpoint 接口标识，形如 {@code GET:/api/notes/search}
     * @return 解析结果，含原始树、归一化树、规范形式与指纹
     */
    public ParseResult analyze(String sql, String endpoint) {
        if (sql == null || sql.isBlank()) {
            return ParseResult.empty(endpoint);
        }
        String trimmed = sql.length() > MAX_SQL_LENGTH
                ? sql.substring(0, MAX_SQL_LENGTH)
                : sql;

        String cacheKey = endpoint + "\u0000" + trimmed;
        ParseResult cached = cache.getIfPresent(cacheKey);
        if (cached != null) {
            return cached;
        }

        ParseResult result;
        try {
            AstNode ast = new SqlParser(trimmed).parse();
            AstNode normalized = AstNormalizer.normalize(ast);
            String canonical = AstSerializer.serialize(normalized);
            String fingerprint = hash(endpoint + "|" + canonical);
            result = new ParseResult(trimmed, endpoint, ast, normalized,
                    canonical, fingerprint, true, null);
        } catch (RuntimeException e) {
            // 解析异常降级：仍然产出可用结果，交由风险特征层判定。
            // 解析失败本身不能成为绕过手段，因此绝不放行。
            result = new ParseResult(trimmed, endpoint, null, null,
                    trimmed, hash(endpoint + "|" + trimmed), false, e.getMessage());
        }

        cache.put(cacheKey, result);
        return result;
    }

    /** 仅计算指纹，用于基线快速比对。 */
    public String fingerprint(String sql, String endpoint) {
        return analyze(sql, endpoint).fingerprint();
    }

    /** 清空缓存，用于基线变更后强制重新计算。 */
    public void invalidateAll() {
        cache.invalidateAll();
    }

    public long cacheSize() {
        return cache.estimatedSize();
    }

    /** 计算 SHA-256 并取前 16 字节的十六进制表示。 */
    private static String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(bytes);
            return hex.substring(0, FINGERPRINT_HEX_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JDK 强制要求支持的算法，此分支实际不可达
            throw new IllegalStateException("运行环境不支持 SHA-256 算法", e);
        }
    }

    /**
     * SQL 解析与指纹计算结果。
     *
     * @param sql          原始 SQL
     * @param endpoint     接口标识
     * @param ast          原始语法树（解析失败时为 null）
     * @param normalizedAst 归一化后的语法树（解析失败时为 null）
     * @param canonical    规范化序列化结果
     * @param fingerprint  结构指纹
     * @param parsed       是否成功解析
     * @param parseError   解析错误信息
     */
    public record ParseResult(
            String sql,
            String endpoint,
            AstNode ast,
            AstNode normalizedAst,
            String canonical,
            String fingerprint,
            boolean parsed,
            String parseError
    ) {
        static ParseResult empty(String endpoint) {
            return new ParseResult("", endpoint, null, null, "", "", false, "空语句");
        }
    }
}
