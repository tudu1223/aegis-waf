package com.aegis.core.xss;

import com.aegis.core.normalize.PayloadNormalizer;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Entities;
import org.jsoup.nodes.Node;
import org.jsoup.select.NodeFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * [SEC-XSS-01] 基于 DOM 解析的 HTML 语义净化器
 *
 * <p><b>安全原理：</b>
 * 用正则过滤 XSS 是经典的反面教材。过滤 {@code <script>} 可以用
 * {@code <img onerror>} 绕过，过滤 {@code onerror} 可以用 {@code <svg onload>} 绕过，
 * 过滤所有已知标签仍可被 {@code javascript:} 伪协议、HTML 实体编码、
 * 大小写混淆、属性换行分隔等手法穿透。黑名单永远追不上新的绕过手法。
 *
 * <p>本实现的做法是：<b>把 HTML 当作 HTML 来解析</b>。先按 HTML 规范构建 DOM 树，
 * 再对每个节点依据"标签 → 属性 → 协议"三级<b>白名单</b>逐层裁决。
 * 白名单机制的根本优势在于：即使出现未知的新型绕过手法，只要它依赖白名单
 * 之外的标签或属性，就自动失效——防护能力不依赖于对攻击手法的穷举。
 *
 * <p><b>关键实现细节：</b>协议判定前必须先剥离空白与控制字符并做多重解码，
 * 否则 {@code "java\tscript:alert(1)"}、{@code "java&#115;cript:"} 等变形可绕过。
 *
 * <p><b>威胁对应：</b>T-02 存储型/反射型 XSS（STRIDE: Tampering, DREAD 8.0）
 */
public final class HtmlSanitizer {

    /**
     * 一级白名单：允许的 HTML 标签。
     *
     * <p>刻意排除 script、iframe、object、embed、svg、math、form、style、
     * link、meta、base 等具备脚本执行或资源加载能力的标签。
     */
    private static final Set<String> ALLOWED_TAGS = Set.of(
            "p", "br", "hr", "strong", "b", "em", "i", "u", "s", "del", "ins",
            "h1", "h2", "h3", "h4", "h5", "h6",
            "ul", "ol", "li", "dl", "dt", "dd",
            "blockquote", "pre", "code", "kbd", "samp", "var",
            "a", "img",
            "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption",
            "span", "div", "section", "article", "figure", "figcaption",
            "sub", "sup", "small", "mark", "abbr", "cite", "q"
    );

    /**
     * 二级白名单：按标签细分的允许属性。
     *
     * <p>所有 {@code on*} 事件属性与 {@code style} 属性一律不在白名单内。
     */
    private static final Map<String, Set<String>> ALLOWED_ATTRIBUTES = Map.of(
            "a", Set.of("href", "title", "target", "rel"),
            "img", Set.of("src", "alt", "title", "width", "height"),
            "td", Set.of("colspan", "rowspan", "align"),
            "th", Set.of("colspan", "rowspan", "align", "scope"),
            "table", Set.of("border", "cellpadding", "cellspacing"),
            "blockquote", Set.of("cite"),
            "q", Set.of("cite"),
            "abbr", Set.of("title")
    );

    /** 所有标签均允许的通用属性。 */
    private static final Set<String> GLOBAL_ATTRIBUTES = Set.of("class", "id", "title", "dir", "lang");

    /**
     * 三级白名单：URL 属性允许的协议。
     *
     * <p>刻意排除 javascript:、data:、vbscript:、file:、about: 等可执行协议。
     */
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of(
            "http", "https", "mailto", "tel", "ftp"
    );

    /** 需要做协议校验的属性。 */
    private static final Set<String> URL_ATTRIBUTES = Set.of(
            "href", "src", "cite", "action", "formaction", "background", "poster"
    );

    /** 明确禁止的危险协议，用于生成精确的攻击证据。 */
    private static final Set<String> DANGEROUS_PROTOCOLS = Set.of(
            "javascript", "vbscript", "data", "file", "about", "blob", "jar"
    );

    /** 输入长度上限，防御超大载荷导致的解析资源耗尽。 */
    private static final int MAX_INPUT_LENGTH = 512 * 1024;

    /**
     * 对 HTML 内容执行语义净化。
     *
     * @param input 用户提交的原始 HTML
     * @return 净化结果，含安全 HTML 与被移除内容的证据清单
     */
    public SanitizeResult sanitize(String input) {
        if (input == null || input.isEmpty()) {
            return SanitizeResult.clean("");
        }
        String source = input.length() > MAX_INPUT_LENGTH
                ? input.substring(0, MAX_INPUT_LENGTH)
                : input;

        List<SanitizeResult.Removal> removals = new ArrayList<>();

        // [关键] 先做多重解码检测：若解码后出现新的危险特征，说明使用了编码混淆。
        // 注意：解码结果仅用于"检测"，净化仍在原始内容的 DOM 上进行，
        // 避免因解码引入本不存在的标签结构。
        String decoded = PayloadNormalizer.normalize(source).normalized();
        if (!decoded.equals(source) && containsSuspiciousPattern(decoded)
                && !containsSuspiciousPattern(source)) {
            removals.add(new SanitizeResult.Removal(
                    SanitizeResult.RemovalType.ENCODED_PAYLOAD,
                    "encoded",
                    "载荷经过编码混淆，解码后检出危险特征"));
        }

        // 按 HTML 规范解析为 DOM 树
        Document document = Jsoup.parseBodyFragment(source);
        document.outputSettings()
                .escapeMode(Entities.EscapeMode.base)
                .prettyPrint(false);

        Element body = document.body();
        filterNode(body, removals);

        String clean = body.html();
        return new SanitizeResult(clean, removals, !removals.isEmpty());
    }

    /**
     * 递归遍历 DOM 树并执行三级白名单裁决。
     *
     * <p>使用后序方式收集待删除节点，避免遍历过程中修改集合导致的并发问题。
     */
    private void filterNode(Element root, List<SanitizeResult.Removal> removals) {
        List<Element> toUnwrap = new ArrayList<>();
        List<Element> toRemove = new ArrayList<>();

        root.filter((NodeFilter) (node, depth) -> {
            if (node instanceof Element element && node != root) {
                String tag = element.tagName().toLowerCase(Locale.ROOT);

                // ---- 一级：标签白名单 ----
                if (!ALLOWED_TAGS.contains(tag)) {
                    if (isScriptCapableTag(tag)) {
                        // 具备脚本执行能力的标签：连同内容整体移除
                        toRemove.add(element);
                        removals.add(new SanitizeResult.Removal(
                                SanitizeResult.RemovalType.DISALLOWED_TAG,
                                tag,
                                "移除危险标签 <" + tag + ">：" + truncate(element.outerHtml())));
                        return NodeFilter.FilterResult.SKIP_ENTIRELY;
                    }
                    // 普通未知标签：仅剥离标签本身，保留其文本内容（避免误伤正常内容）
                    toUnwrap.add(element);
                    removals.add(new SanitizeResult.Removal(
                            SanitizeResult.RemovalType.DISALLOWED_TAG,
                            tag,
                            "剥离非白名单标签 <" + tag + ">"));
                    return NodeFilter.FilterResult.CONTINUE;
                }

                // ---- 二级与三级：属性与协议白名单 ----
                filterAttributes(element, tag, removals);
            }
            return NodeFilter.FilterResult.CONTINUE;
        });

        for (Element e : toRemove) {
            e.remove();
        }
        for (Element e : toUnwrap) {
            e.unwrap();
        }
    }

    /** 属性级裁决：事件属性、style、非白名单属性与危险协议。 */
    private void filterAttributes(Element element, String tag,
                                  List<SanitizeResult.Removal> removals) {
        Attributes attributes = element.attributes();
        List<String> keysToRemove = new ArrayList<>();

        for (Attribute attr : attributes) {
            String key = attr.getKey().toLowerCase(Locale.ROOT);
            String value = attr.getValue();

            // [关键] 所有 on* 事件处理属性一律禁止。
            // 这是 <img src=x onerror=alert(1)> 类攻击的核心载体。
            if (key.startsWith("on")) {
                keysToRemove.add(attr.getKey());
                removals.add(new SanitizeResult.Removal(
                        SanitizeResult.RemovalType.EVENT_ATTRIBUTE,
                        key,
                        "移除事件属性 " + key + "=\"" + truncate(value) + "\""));
                continue;
            }

            // style 属性可承载 expression()、url(javascript:) 等攻击，一律禁止
            if ("style".equals(key)) {
                keysToRemove.add(attr.getKey());
                removals.add(new SanitizeResult.Removal(
                        SanitizeResult.RemovalType.STYLE_ATTRIBUTE,
                        key,
                        "移除样式属性：" + truncate(value)));
                continue;
            }

            // srcdoc 可嵌入完整 HTML 文档，等价于脚本执行
            if ("srcdoc".equals(key) || "formaction".equals(key)) {
                keysToRemove.add(attr.getKey());
                removals.add(new SanitizeResult.Removal(
                        SanitizeResult.RemovalType.DISALLOWED_ATTRIBUTE,
                        key,
                        "移除高危属性 " + key));
                continue;
            }

            // URL 类属性：三级协议白名单校验
            if (URL_ATTRIBUTES.contains(key)) {
                String protocol = extractProtocol(value);
                if (protocol != null && !ALLOWED_PROTOCOLS.contains(protocol)) {
                    keysToRemove.add(attr.getKey());
                    SanitizeResult.RemovalType type =
                            DANGEROUS_PROTOCOLS.contains(protocol)
                                    ? SanitizeResult.RemovalType.DANGEROUS_PROTOCOL
                                    : SanitizeResult.RemovalType.DISALLOWED_ATTRIBUTE;
                    removals.add(new SanitizeResult.Removal(
                            type, key,
                            "移除危险协议 " + protocol + ": " + truncate(value)));
                    continue;
                }
            }

            // 二级：属性白名单
            Set<String> allowed = ALLOWED_ATTRIBUTES.getOrDefault(tag, Set.of());
            if (!allowed.contains(key) && !GLOBAL_ATTRIBUTES.contains(key)
                    && !key.startsWith("data-")) {
                keysToRemove.add(attr.getKey());
                removals.add(new SanitizeResult.Removal(
                        SanitizeResult.RemovalType.DISALLOWED_ATTRIBUTE,
                        key,
                        "移除非白名单属性 " + key));
            }
        }

        for (String key : keysToRemove) {
            attributes.remove(key);
        }
    }

    /**
     * [关键安全逻辑] 提取并规范化 URL 协议。
     *
     * <p>判定前必须移除所有空白与控制字符并执行多重解码，否则以下变形均可绕过：
     * <ul>
     *   <li>{@code "java\tscript:alert(1)"} —— 制表符分隔</li>
     *   <li>{@code "  javascript:alert(1)"} —— 前导空白</li>
     *   <li>{@code "java&#115;cript:alert(1)"} —— HTML 实体编码</li>
     *   <li>{@code "JaVaScRiPt:alert(1)"} —— 大小写混淆</li>
     * </ul>
     *
     * @return 小写协议名；无协议（相对路径）时返回 null
     */
    private String extractProtocol(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        // 剥离空白与控制字符 + 多重解码 + 转小写
        String normalized = PayloadNormalizer.normalizeForUrl(url);
        if (normalized.isEmpty()) {
            return null;
        }
        int colonIndex = normalized.indexOf(':');
        if (colonIndex <= 0) {
            return null; // 相对路径或锚点，无协议
        }
        // 冒号前若出现 / ? # 说明冒号属于路径部分而非协议分隔符
        String beforeColon = normalized.substring(0, colonIndex);
        if (beforeColon.indexOf('/') >= 0 || beforeColon.indexOf('?') >= 0
                || beforeColon.indexOf('#') >= 0) {
            return null;
        }
        return beforeColon;
    }

    /** 判断标签是否具备脚本执行或外部资源加载能力，此类标签需连同内容整体移除。 */
    private boolean isScriptCapableTag(String tag) {
        return switch (tag) {
            case "script", "iframe", "object", "embed", "applet", "frame", "frameset",
                 "svg", "math", "form", "style", "link", "meta", "base",
                 "noscript", "template", "portal" -> true;
            default -> false;
        };
    }

    /** 快速判断内容是否含有可疑的 XSS 特征，用于编码混淆检测。 */
    private boolean containsSuspiciousPattern(String content) {
        String lower = content.toLowerCase(Locale.ROOT);
        return lower.contains("<script") || lower.contains("javascript:")
                || lower.contains("onerror") || lower.contains("onload")
                || lower.contains("<iframe") || lower.contains("<svg")
                || lower.contains("vbscript:") || lower.contains("data:text/html");
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        String flat = s.replaceAll("\\s+", " ").trim();
        return flat.length() <= 80 ? flat : flat.substring(0, 80) + "...";
    }

    /**
     * 仅检测不净化，用于网关层的快速判定。
     *
     * @return 是否检出 XSS 攻击载荷
     */
    public boolean containsXss(String input) {
        return sanitize(input).hasThreat();
    }
}
