package com.aegis.core.cmd;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 命令注入检测器测试。
 *
 * <p>重点验证<b>误报控制</b>：SQL 注入载荷、正常业务文本
 * 不得被误判为命令注入。这类跨类型误判会导致安全事件的
 * 分类失真，影响告警的可用性。
 */
class CommandInjectionDetectorTest {

    // ==================== 应当检出的真实命令注入 ====================

    @Test
    @DisplayName("分号分隔追加命令应被检出")
    void detectSemicolonInjection() {
        assertTrue(CommandInjectionDetector.looksLikeCommandInjection(
                "127.0.0.1; cat /etc/passwd"));
    }

    @Test
    @DisplayName("管道符追加命令应被检出")
    void detectPipeInjection() {
        assertTrue(CommandInjectionDetector.looksLikeCommandInjection(
                "127.0.0.1 | whoami"));
    }

    @Test
    @DisplayName("逻辑与追加命令应被检出")
    void detectAndInjection() {
        assertTrue(CommandInjectionDetector.looksLikeCommandInjection(
                "127.0.0.1 && id"));
    }

    @Test
    @DisplayName("反引号命令替换应被检出")
    void detectBacktickInjection() {
        assertTrue(CommandInjectionDetector.looksLikeCommandInjection(
                "127.0.0.1`whoami`"));
    }

    @Test
    @DisplayName("绝对路径形式的命令调用应被检出")
    void detectAbsolutePathCommand() {
        assertTrue(CommandInjectionDetector.looksLikeCommandInjection(
                "test; /bin/sh -c 'x'"));
    }

    // ==================== 误报控制：不得误判 ====================

    @Test
    @DisplayName("SQL 注入载荷不得被误判为命令注入")
    void sqlPayloadNotMisclassified() {
        String[] sqlPayloads = {
                "x%' UNION SELECT id, id, username, CAST(password_md5 AS VARCHAR), "
                        + "role, created_at FROM users --",
                "x%'/*!50000UNION*/SELECT id, role FROM users --",
                "admin' OR '1'='1' --",
                "1'; DROP TABLE users; --"
        };
        for (String payload : sqlPayloads) {
            assertFalse(CommandInjectionDetector.looksLikeCommandInjection(payload),
                    "SQL 载荷被误判为命令注入: " + payload);
        }
    }

    @Test
    @DisplayName("正常业务文本不得被误判")
    void normalTextNotMisclassified() {
        String[] normalValues = {
                "张三 & 李四的会议纪要",
                "价格区间 100|200",
                "查询条件: name=test; status=active",
                "user@example.com",
                "C:\\Users\\Documents\\report.pdf",
                "函数说明 (含参数 id, name)"
        };
        for (String value : normalValues) {
            assertFalse(CommandInjectionDetector.looksLikeCommandInjection(value),
                    "正常文本被误判为命令注入: " + value);
        }
    }

    @Test
    @DisplayName("仅含元字符而无敏感命令不应告警")
    void metacharAloneNotEnough() {
        assertFalse(CommandInjectionDetector.looksLikeCommandInjection(
                "value1; value2"));
        assertFalse(CommandInjectionDetector.looksLikeCommandInjection(
                "a | b | c"));
    }

    @Test
    @DisplayName("敏感命令作为普通单词的一部分不应告警")
    void commandAsSubstringNotFlagged() {
        // identifier 含 id，但不是命令调用
        assertFalse(CommandInjectionDetector.looksLikeCommandInjection(
                "field; identifier_column"));
    }

    // ==================== RASP 层的完整检测 ====================

    @Test
    @DisplayName("shell 解析型调用应被判定为高危")
    void shellParsedInvocationIsHighRisk() {
        CommandInjectionDetector.Result result = CommandInjectionDetector.detect(
                "sh", List.of("-c", "ping -c 1 127.0.0.1; cat /etc/passwd"), true);
        assertTrue(result.injection());
        assertTrue(result.score() >= 50);
        assertFalse(result.evidence().isEmpty());
    }

    @Test
    @DisplayName("参数数组化的正常调用不应告警")
    void safeArrayInvocationNotFlagged() {
        CommandInjectionDetector.Result result = CommandInjectionDetector.detect(
                "ping", List.of("-c", "1", "example.com"), false);
        assertFalse(result.injection());
    }

    @Test
    @DisplayName("空输入应安全处理")
    void handleNullAndEmpty() {
        assertDoesNotThrow(() ->
                CommandInjectionDetector.looksLikeCommandInjection(null));
        assertFalse(CommandInjectionDetector.looksLikeCommandInjection(""));
        assertDoesNotThrow(() -> CommandInjectionDetector.detect(null, null, false));
    }
}
