package com.aegis.core.cmd;

import com.aegis.core.normalize.PayloadNormalizer;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * [SEC-CMD-01] 命令注入检测器
 *
 * <p><b>安全原理：</b>
 * 命令注入的根因是<b>用户输入被拼接进由 shell 解析的命令字符串</b>。
 * shell 会将 {@code ; | & $ ` \n} 等元字符解释为命令分隔或替换符号，
 * 使攻击者得以追加任意命令。
 *
 * <p>本检测器工作在 RASP 层，钩取 {@code Runtime.exec} 与
 * {@code ProcessBuilder.start} 的实际调用参数，进行三项判定：
 * <ol>
 *   <li><b>调用形式判定</b>：单字符串形式的 {@code exec(String)} 会经 shell 解析，
 *       本身即为高危写法；参数数组形式则不经 shell，元字符失去特殊含义</li>
 *   <li><b>元字符检测</b>：参数中出现 shell 元字符</li>
 *   <li><b>敏感命令检测</b>：调用了信息收集或反弹 shell 类命令</li>
 * </ol>
 *
 * <p><b>威胁对应：</b>T-07 命令注入（STRIDE: Tampering, DREAD 9.0）
 */
public final class CommandInjectionDetector {

    /**
     * shell 元字符。
     *
     * <p>这些字符在 shell 中具有特殊语义：命令分隔、管道、后台执行、
     * 命令替换、重定向。用户输入中出现它们即意味着可能突破原命令边界。
     */
    private static final char[] SHELL_METACHARACTERS = {
            ';', '|', '&', '$', '`', '\n', '\r', '>', '<', '(', ')', '{', '}'
    };

    /** 敏感命令：信息收集、反弹 shell、文件下载类。 */
    private static final Set<String> SENSITIVE_COMMANDS = Set.of(
            "cat", "type", "more", "less", "head", "tail",
            "whoami", "id", "uname", "hostname", "ifconfig", "ipconfig",
            "netstat", "ps", "net", "systeminfo",
            "wget", "curl", "nc", "netcat", "ncat", "telnet",
            "bash", "sh", "zsh", "cmd", "powershell", "python", "perl", "ruby",
            "chmod", "chown", "rm", "del", "format", "mkfs"
    );

    /** 敏感文件路径，出现在命令参数中说明企图读取系统文件。 */
    private static final Set<String> SENSITIVE_PATHS = Set.of(
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ",
            "c:\\windows\\system32", "\\windows\\win.ini", "/root/.ssh"
    );

    private CommandInjectionDetector() {
    }

    /**
     * 检测命令执行是否存在注入风险。
     *
     * @param command      命令本体
     * @param arguments    命令参数列表
     * @param shellParsed  调用形式是否会经 shell 解析
     *                     （{@code Runtime.exec(String)} 为 true，
     *                     {@code ProcessBuilder(List)} 为 false）
     * @return 检测结果
     */
    public static Result detect(String command, List<String> arguments, boolean shellParsed) {
        List<String> evidence = new ArrayList<>();
        int score = 0;

        String fullCommand = buildFullCommand(command, arguments);
        String normalized = PayloadNormalizer.normalize(fullCommand).normalized();

        // 判定一：调用形式本身的风险
        // 单字符串形式会交由 shell 解析，是命令注入的必要条件
        if (shellParsed) {
            score += 30;
            evidence.add("使用了会经 shell 解析的命令执行形式，存在注入风险");
        }

        // 判定二：shell 元字符检测
        List<Character> foundMeta = findMetacharacters(normalized);
        if (!foundMeta.isEmpty()) {
            score += 50;
            StringBuilder sb = new StringBuilder("命令中包含 shell 元字符: ");
            for (char c : foundMeta) {
                sb.append(displayChar(c)).append(' ');
            }
            evidence.add(sb.toString().trim());
        }

        // 判定三：敏感命令检测
        String detectedSensitive = findSensitiveCommand(normalized);
        if (detectedSensitive != null) {
            score += 35;
            evidence.add("调用了敏感命令: " + detectedSensitive);
        }

        // 判定四：敏感文件访问
        String sensitivePath = findSensitivePath(normalized);
        if (sensitivePath != null) {
            score += 40;
            evidence.add("试图访问敏感文件: " + sensitivePath);
        }

        boolean injection = score >= 50;
        return new Result(injection, Math.min(score, 100), evidence, fullCommand);
    }

    /**
     * 面向网关层的启发式判定：参数值是否具备命令注入意图。
     *
     * <p><b>误报控制：</b>朴素做法是"出现 shell 元字符 + 出现敏感命令名"即告警，
     * 但这会把 SQL 载荷误判为命令注入——SQL 中的逗号、括号会被当作元字符，
     * 而 {@code id}、{@code user} 等常见列名恰好也是 Unix 命令名。
     *
     * <p>本实现要求二者构成<b>真实的命令注入结构</b>：
     * 必须存在"命令分隔符 + 紧随其后的敏感命令"这一模式，
     * 即攻击者确实在尝试追加一条新命令。仅出现括号、逗号等
     * 在其他语境中常见的字符不足以判定。
     */
    public static boolean looksLikeCommandInjection(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String normalized = PayloadNormalizer.normalize(value).normalized();

        // 仅采用真正的"命令分隔"字符，排除括号、逗号等 SQL/文本常见符号
        int separatorIndex = indexOfCommandSeparator(normalized);
        if (separatorIndex < 0) {
            return false;
        }

        // 分隔符之后必须紧跟敏感命令，才构成命令注入结构
        String tail = normalized.substring(separatorIndex + 1).trim();
        if (tail.isEmpty()) {
            return false;
        }
        return startsWithSensitiveCommand(tail);
    }

    /** 查找真正的命令分隔符位置。 */
    private static int indexOfCommandSeparator(String text) {
        // 这些字符在 shell 中用于分隔或串联命令，
        // 是命令注入区别于其他注入类型的结构特征
        char[] separators = {';', '|', '&', '`', '\n'};
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            for (char sep : separators) {
                if (c == sep) {
                    return i;
                }
            }
        }
        // $( 形式的命令替换
        int idx = text.indexOf("$(");
        return idx;
    }

    /** 判断文本是否以敏感命令开头。 */
    private static boolean startsWithSensitiveCommand(String text) {
        String lower = text.toLowerCase();
        // 去除可能的前导符号（如 | 后的空格、& 等）
        int start = 0;
        while (start < lower.length()
                && !Character.isLetterOrDigit(lower.charAt(start))
                && lower.charAt(start) != '/') {
            start++;
        }
        if (start >= lower.length()) {
            return false;
        }
        String candidate = lower.substring(start);

        for (String cmd : SENSITIVE_COMMANDS) {
            if (candidate.startsWith(cmd)) {
                int end = cmd.length();
                // 命令名后必须是空白、结束或路径分隔，避免 "identifier" 匹配 "id"
                if (end >= candidate.length()
                        || !Character.isLetterOrDigit(candidate.charAt(end))) {
                    return true;
                }
            }
        }
        // 绝对路径形式的命令调用，如 /bin/sh
        return candidate.startsWith("/bin/") || candidate.startsWith("/usr/bin/");
    }

    private static String buildFullCommand(String command, List<String> arguments) {
        StringBuilder sb = new StringBuilder(command == null ? "" : command);
        if (arguments != null) {
            for (String arg : arguments) {
                sb.append(' ').append(arg);
            }
        }
        return sb.toString();
    }

    private static List<Character> findMetacharacters(String text) {
        List<Character> found = new ArrayList<>();
        for (char meta : SHELL_METACHARACTERS) {
            if (text.indexOf(meta) >= 0) {
                found.add(meta);
            }
        }
        return found;
    }

    private static String findSensitiveCommand(String text) {
        String lower = text.toLowerCase();
        for (String cmd : SENSITIVE_COMMANDS) {
            // 以词边界匹配，避免 "concat" 误命中 "cat"
            if (containsWord(lower, cmd)) {
                return cmd;
            }
        }
        return null;
    }

    private static boolean containsWord(String text, String word) {
        int index = 0;
        while ((index = text.indexOf(word, index)) >= 0) {
            boolean leftBoundary = index == 0
                    || !Character.isLetterOrDigit(text.charAt(index - 1));
            int end = index + word.length();
            boolean rightBoundary = end >= text.length()
                    || !Character.isLetterOrDigit(text.charAt(end));
            if (leftBoundary && rightBoundary) {
                return true;
            }
            index = end;
        }
        return false;
    }

    private static String findSensitivePath(String text) {
        String lower = text.toLowerCase().replace('\\', '/');
        for (String path : SENSITIVE_PATHS) {
            if (lower.contains(path.toLowerCase().replace('\\', '/'))) {
                return path;
            }
        }
        return null;
    }

    private static String displayChar(char c) {
        return switch (c) {
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            default -> String.valueOf(c);
        };
    }

    /**
     * 命令注入检测结果。
     *
     * @param injection   是否判定为注入
     * @param score       风险评分
     * @param evidence    证据描述列表
     * @param fullCommand 完整命令，用于取证展示
     */
    public record Result(
            boolean injection,
            int score,
            List<String> evidence,
            String fullCommand
    ) {
    }
}
