package com.aegis.core.normalize;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * [SEC-NORM-01] 载荷多重归一化器
 *
 * <p><b>安全原理：</b>
 * 攻击者普遍使用编码手段隐藏攻击载荷。若不做归一化，任何检测逻辑都可被简单的
 * URL 编码绕过。本归一化器将各种编码形态还原为统一的规范形式，是所有后续
 * 检测的前置条件。
 *
 * <p>处理的混淆手法包括：URL 单/多重编码、HTML 实体编码（十进制与十六进制）、
 * Unicode 转义、全角字符、空字节截断、控制字符插入、注释拆分、多余空白。
 *
 * <p><b>循环解码至不动点：</b>
 * 单次解码不足以应对多重编码（如 {@code %2527} 需两轮才能还原为 {@code '}）。
 * 本实现循环解码直到内容不再变化，同时设置轮数上限防御<b>解码炸弹</b>——
 * 攻击者可构造极深的嵌套编码耗尽 CPU，这本身是一种拒绝服务攻击。
 *
 * <p><b>过度编码即信号：</b>正常业务请求几乎不会出现三重以上编码，
 * 因此解码深度本身被作��风险评分的输入。
 *
 * <p><b>威胁对应：</b>T-12 检测绕过（DREAD 8.0）、T-06 拒绝服务（DREAD 7.0）
 */
public final class PayloadNormalizer {

    /** 解码轮数上限，防御解码炸弹导致的资源耗尽。 */
    private static final int MAX_DECODE_DEPTH = 5;

    /** 载荷长度上限，超长部分截断以控制处理开销。 */
    private static final int MAX_LENGTH = 32 * 1024;

    /** 触发"过度编码"标记的深度阈值。 */
    private static final int EXCESSIVE_DEPTH = 3;

    private static final Pattern HTML_ENTITY_NAMED =
            Pattern.compile("&([a-zA-Z][a-zA-Z0-9]{1,10});");
    private static final Pattern HTML_ENTITY_DECIMAL =
            Pattern.compile("&#(\\d{1,7});?");
    private static final Pattern HTML_ENTITY_HEX =
            Pattern.compile("&#[xX]([0-9a-fA-F]{1,6});?");
    private static final Pattern UNICODE_ESCAPE =
            Pattern.compile("\\\\[uU]\\+?([0-9a-fA-F]{4})");
    private static final Pattern HEX_ESCAPE =
            Pattern.compile("\\\\x([0-9a-fA-F]{2})");
    private static final Pattern INLINE_COMMENT =
            Pattern.compile("/\\*!\\d*(.*?)\\*/", Pattern.DOTALL);
    private static final Pattern BLOCK_COMMENT =
            Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
    private static final Pattern MULTI_WHITESPACE =
            Pattern.compile("\\s+");

    private PayloadNormalizer() {
    }

    /**
     * 对载荷执行多重归一化。
     *
     * @param raw 原始载荷
     * @return 归一化结果，含解码深度与异常标记
     */
    public static NormalizeResult normalize(String raw) {
        Set<String> flags = new LinkedHashSet<>();
        if (raw == null || raw.isEmpty()) {
            return NormalizeResult.of(raw == null ? "" : raw, "", 0, flags);
        }

        String s = raw.length() > MAX_LENGTH ? raw.substring(0, MAX_LENGTH) : raw;
        String original = s;

        // ---- 阶段一：循环解码至不动点 ----
        int depth = 0;
        while (depth < MAX_DECODE_DEPTH) {
            String previous = s;
            s = urlDecode(s);
            s = htmlEntityDecode(s);
            s = unicodeUnescape(s);
            if (s.equals(previous)) {
                break;
            }
            depth++;
        }
        if (depth >= MAX_DECODE_DEPTH) {
            // 达到上限仍未收敛，极可能是刻意构造的解码炸弹
            flags.add(NormalizeResult.FLAG_DECODE_LIMIT);
        }
        if (depth >= EXCESSIVE_DEPTH) {
            flags.add(NormalizeResult.FLAG_EXCESSIVE_ENCODING);
        }

        // ---- 阶段二：字符层面的异常检测与清理 ----
        if (s.indexOf('\0') >= 0 || s.contains("%00")) {
            flags.add(NormalizeResult.FLAG_NULL_BYTE);
            s = s.replace("\0", "");
        }
        if (containsControlChar(s)) {
            flags.add(NormalizeResult.FLAG_CONTROL_CHAR);
        }
        if (containsFullwidth(s)) {
            flags.add(NormalizeResult.FLAG_FULLWIDTH);
        }

        // Unicode 兼容等价规范化：全角字符转半角，消除全角绕过
        s = Normalizer.normalize(s, Normalizer.Form.NFKC);

        // ---- 阶段三：注释处理 ----
        if (s.contains("/*") || s.contains("--") || s.contains("#")) {
            flags.add(NormalizeResult.FLAG_COMMENT);
        }
        // MySQL 可执行内联注释：保留内容（会被真实执行），仅去除包裹符号
        s = INLINE_COMMENT.matcher(s).replaceAll("$1");
        // 普通块注释：替换为空格，使被拆分的关键字重新相邻
        s = BLOCK_COMMENT.matcher(s).replaceAll(" ");

        // ---- 阶段四：空白规范化 ----
        // 控制字符（\t \n \r \f \v）统一转为空格，防止用换行绕过关键字匹配
        s = s.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", " ");
        s = MULTI_WHITESPACE.matcher(s).replaceAll(" ").trim();

        return NormalizeResult.of(original, s, depth, flags);
    }

    /**
     * URL 解码。
     *
     * <p>使用宽容策略：遇到非法的百分号编码时保留原字符而非抛异常，
     * 保证畸形载荷同样能被分析——解析失败不能成为绕过手段。
     */
    private static String urlDecode(String s) {
        if (s.indexOf('%') < 0 && s.indexOf('+') < 0) {
            return s;
        }
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // 非法编码序列：逐字符手工解码，跳过无法解析的部分
            return lenientUrlDecode(s);
        }
    }

    private static String lenientUrlDecode(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                String hex = s.substring(i + 1, i + 3);
                try {
                    sb.append((char) Integer.parseInt(hex, 16));
                    i += 2;
                } catch (NumberFormatException ignored) {
                    sb.append(c);
                }
            } else if (c == '+') {
                sb.append(' ');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** HTML 实体解码，覆盖具名实体、十进制与十六进制数值实体。 */
    private static String htmlEntityDecode(String s) {
        if (s.indexOf('&') < 0) {
            return s;
        }
        String result = s;

        // 十六进制数值实体：&#x27; → '
        Matcher hexMatcher = HTML_ENTITY_HEX.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (hexMatcher.find()) {
            try {
                int code = Integer.parseInt(hexMatcher.group(1), 16);
                hexMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (NumberFormatException e) {
                hexMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(hexMatcher.group()));
            }
        }
        hexMatcher.appendTail(sb);
        result = sb.toString();

        // 十进制数值实体：&#39; → '
        Matcher decMatcher = HTML_ENTITY_DECIMAL.matcher(result);
        sb = new StringBuilder();
        while (decMatcher.find()) {
            try {
                int code = Integer.parseInt(decMatcher.group(1));
                if (code <= Character.MAX_VALUE) {
                    decMatcher.appendReplacement(sb,
                            Matcher.quoteReplacement(String.valueOf((char) code)));
                } else {
                    decMatcher.appendReplacement(sb,
                            Matcher.quoteReplacement(decMatcher.group()));
                }
            } catch (NumberFormatException e) {
                decMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(decMatcher.group()));
            }
        }
        decMatcher.appendTail(sb);
        result = sb.toString();

        // 具名实体
        Matcher namedMatcher = HTML_ENTITY_NAMED.matcher(result);
        sb = new StringBuilder();
        while (namedMatcher.find()) {
            String replacement = decodeNamedEntity(namedMatcher.group(1));
            namedMatcher.appendReplacement(sb,
                    Matcher.quoteReplacement(replacement != null
                            ? replacement : namedMatcher.group()));
        }
        namedMatcher.appendTail(sb);
        return sb.toString();
    }

    private static String decodeNamedEntity(String name) {
        return switch (name.toLowerCase()) {
            case "lt" -> "<";
            case "gt" -> ">";
            case "amp" -> "&";
            case "quot" -> "\"";
            case "apos" -> "'";
            case "nbsp" -> " ";
            case "sol" -> "/";
            case "bsol" -> "\\";
            case "colon" -> ":";
            case "semi" -> ";";
            case "equals" -> "=";
            case "lpar" -> "(";
            case "rpar" -> ")";
            case "tab" -> "\t";
            case "newline" -> "\n";
            default -> null;
        };
    }

    /** Unicode 与十六进制转义解码：\\u0027 与 \\x27 均还原为单引号。 */
    private static String unicodeUnescape(String s) {
        if (s.indexOf('\\') < 0) {
            return s;
        }
        String result = s;

        Matcher uMatcher = UNICODE_ESCAPE.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (uMatcher.find()) {
            try {
                int code = Integer.parseInt(uMatcher.group(1), 16);
                uMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (NumberFormatException e) {
                uMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(uMatcher.group()));
            }
        }
        uMatcher.appendTail(sb);
        result = sb.toString();

        Matcher xMatcher = HEX_ESCAPE.matcher(result);
        sb = new StringBuilder();
        while (xMatcher.find()) {
            try {
                int code = Integer.parseInt(xMatcher.group(1), 16);
                xMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(String.valueOf((char) code)));
            } catch (NumberFormatException e) {
                xMatcher.appendReplacement(sb,
                        Matcher.quoteReplacement(xMatcher.group()));
            }
        }
        xMatcher.appendTail(sb);
        return sb.toString();
    }

    private static boolean containsControlChar(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // 排除常见的合法空白字符，仅标记异常控制字符
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                return true;
            }
            if (c == 0x7F) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsFullwidth(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            // 全角字符区间：FF01–FF5E 对应 ASCII 21–7E
            if (c >= 0xFF01 && c <= 0xFF5E) {
                return true;
            }
        }
        return false;
    }

    /**
     * 面向 URL 与协议判定的强力归一化。
     *
     * <p>在标准归一化基础上额外移除所有空白与控制字符，用于伪协议检测——
     * 防御 {@code "java\tscript:alert(1)"} 与 {@code "  javascript:..."} 类绕过。
     */
    public static String normalizeForUrl(String raw) {
        String normalized = normalize(raw).normalized();
        return normalized.replaceAll("[\\s\\p{Cntrl}]", "").toLowerCase();
    }
}
