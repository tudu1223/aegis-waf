package com.aegis.core.xss;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * XSS 语义净化器绕过测试集。
 *
 * <p>对应设计文档 02 第 7.4 节的 12 项必过测试。
 * 其中最后一项"正常富文本完整保留"极为重要：净化器不能采取
 * 一刀切全删的策略，必须证明正常业务内容不受影响，否则功能性不达标。
 */
class HtmlSanitizerTest {

    private final HtmlSanitizer sanitizer = new HtmlSanitizer();

    private String clean(String input) {
        return sanitizer.sanitize(input).cleanHtml().toLowerCase();
    }

    private boolean detected(String input) {
        return sanitizer.sanitize(input).hasThreat();
    }

    @Test
    @DisplayName("01 script 标签必须被整体移除")
    void removeScriptTag() {
        String result = clean("<script>alert(1)</script>");
        assertFalse(result.contains("<script"), "script 标签必须移除");
        assertFalse(result.contains("alert"), "script 内容必须一并移除");
        assertTrue(detected("<script>alert(1)</script>"));
    }

    @Test
    @DisplayName("02 img 标签的 onerror 事件属性必须被移除")
    void removeOnErrorAttribute() {
        String result = clean("<img src=x onerror=alert(document.cookie)>");
        assertFalse(result.contains("onerror"), "事件属性必须移除");
        assertTrue(result.contains("<img"), "img 标签本身应保留");
    }

    @Test
    @DisplayName("03 svg 命名空间绕过必须被拦截")
    void removeSvgOnload() {
        String result = clean("<svg/onload=alert(1)>");
        assertFalse(result.contains("svg"), "svg 标签必须移除");
        assertFalse(result.contains("onload"));
        assertTrue(detected("<svg/onload=alert(1)>"));
    }

    @Test
    @DisplayName("04 javascript 伪协议必须被移除")
    void removeJavascriptProtocol() {
        String result = clean("<a href=\"javascript:alert(1)\">click</a>");
        assertFalse(result.contains("javascript:"), "伪协议必须移除");
        assertTrue(detected("<a href=\"javascript:alert(1)\">click</a>"));
    }

    @Test
    @DisplayName("05 HTML 实体编码的伪协议必须被识别")
    void removeEntityEncodedProtocol() {
        String payload = "<a href=\"java&#115;cript:alert(1)\">click</a>";
        String result = clean(payload);
        assertFalse(result.contains("javascript:"), "解码后应识别为伪协议");
        assertTrue(detected(payload), "实体编码绕过必须被检出");
    }

    @Test
    @DisplayName("06 制表符分隔的伪协议必须被识别")
    void removeTabSeparatedProtocol() {
        String payload = "<a href=\"java\tscript:alert(1)\">click</a>";
        assertTrue(detected(payload), "空白字符分隔的伪协议必须被检出");
        assertFalse(clean(payload).contains("script:"));
    }

    @Test
    @DisplayName("07 大小写混淆不应绕过检测")
    void caseInsensitiveDetection() {
        String result = clean("<IMG SRC=x ONERROR=alert(1)>");
        assertFalse(result.contains("onerror"), "大小写混淆必须被消解");
    }

    @Test
    @DisplayName("08 iframe srcdoc 必须被拦截")
    void removeIframeSrcdoc() {
        String payload = "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"></iframe>";
        String result = clean(payload);
        assertFalse(result.contains("<iframe"), "iframe 必须移除");
        assertTrue(detected(payload));
    }

    @Test
    @DisplayName("09 body onload 必须被拦截")
    void removeBodyOnload() {
        String result = clean("<body onload=alert(1)>content</body>");
        assertFalse(result.contains("onload"), "事件属性必须移除");
    }

    @Test
    @DisplayName("10 style 属性中的 javascript 必须被移除")
    void removeStyleAttribute() {
        String payload = "<div style=\"background:url(javascript:alert(1))\">x</div>";
        String result = clean(payload);
        assertFalse(result.contains("style="), "style 属性必须移除");
        assertTrue(detected(payload));
    }

    @Test
    @DisplayName("11 math 命名空间混淆必须被拦截")
    void removeMathNamespace() {
        String payload = "<math><mtext><script>alert(1)</script></mtext></math>";
        String result = clean(payload);
        assertFalse(result.contains("<script"), "嵌套在 math 中的脚本必须移除");
        assertTrue(detected(payload));
    }

    @Test
    @DisplayName("12 正常富文本必须完整保留，不得误伤")
    void preserveLegitimateContent() {
        String input = "<p>这是一段<strong>加粗</strong>与<em>斜体</em>的正常内容</p>"
                + "<ul><li>列表项一</li><li>列表项二</li></ul>"
                + "<a href=\"https://example.com\" title=\"链接\">安全链接</a>"
                + "<img src=\"https://example.com/a.png\" alt=\"图片\">";
        SanitizeResult result = sanitizer.sanitize(input);
        String output = result.cleanHtml();

        assertTrue(output.contains("<strong>"), "加粗标签应保留");
        assertTrue(output.contains("<em>"), "斜体标签应保留");
        assertTrue(output.contains("<li>"), "列表标签应保留");
        assertTrue(output.contains("https://example.com"), "正常链接应保留");
        assertTrue(output.contains("这是一段"), "文本内容应完整保留");
        assertFalse(result.hasThreat(), "正常富文本不应触发威胁告警");
    }

    // ==================== 补充边界测试 ====================

    @Test
    @DisplayName("data 协议必须被拦截")
    void removeDataProtocol() {
        String payload = "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">x</a>";
        assertTrue(detected(payload), "data 协议可承载 HTML 文档，必须拦截");
    }

    @Test
    @DisplayName("相对路径链接应正常保留")
    void preserveRelativeUrl() {
        String result = clean("<a href=\"/notes/123\">笔记</a>");
        assertTrue(result.contains("/notes/123"), "相对路径不应被误删");
    }

    @Test
    @DisplayName("空输入与 null 应安全处理")
    void handleNullAndEmpty() {
        assertDoesNotThrow(() -> sanitizer.sanitize(null));
        assertDoesNotThrow(() -> sanitizer.sanitize(""));
        assertEquals("", sanitizer.sanitize(null).cleanHtml());
    }

    @Test
    @DisplayName("净化结果必须记录攻击证据用于取证")
    void recordRemovalEvidence() {
        SanitizeResult result = sanitizer.sanitize("<img src=x onerror=alert(1)>");
        assertFalse(result.removals().isEmpty(), "必须记录被移除的内容作为证据");
        assertTrue(result.riskScore() > 0, "检出攻击时风险分应大于零");
    }
}
