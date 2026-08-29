package com.aegis.core.path;

import com.aegis.core.normalize.PayloadNormalizer;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * [SEC-PATH-01] 路径穿越检测器
 *
 * <p><b>安全原理：</b>
 * 常见的错误做法是���名单过滤 {@code "../"} 字符串。该方案存在根本缺陷：
 * <ul>
 *   <li>{@code "....//"} 过滤一次 {@code "../"} 后剩余 {@code "../"}，绕过成功</li>
 *   <li>{@code "..%2f"}、{@code "%252e%252e%252f"} 等编码形式无法被文本匹配覆盖</li>
 *   <li>{@code "..\\"} 在 Windows 下同样有效但不匹配 Unix 分隔符</li>
 * </ul>
 *
 * <p>正确做法是<b>路径规范化后做绝对路径前缀判定</b>：将用户输入与根目录拼接，
 * 调用 {@code normalize()} 消解所有 {@code .} 与 {@code ..} 语义，再检查
 * 结果是否仍位于根目录之下。这种方式基于文件系统的真实语义而非文本形态，
 * 因此对任何编码变形免疫。
 *
 * <p><b>威胁对应：</b>T-05 路径穿越（STRIDE: Information Disclosure, DREAD 7.5）
 */
public final class PathTraversalDetector {

    private PathTraversalDetector() {
    }

    /**
     * 判定用户提供的路径是否试图越出根目录。
     *
     * @param userPath 用户输入的路径（可能含编码）
     * @param rootDir  允许访问的根目录
     * @return 检测结果
     */
    public static Result check(String userPath, String rootDir) {
        if (userPath == null || userPath.isEmpty()) {
            return new Result(false, null, "路径为空");
        }

        // 多重解码：处理 %2e%2e%2f、%252e%252e 等编码绕过
        String decoded = PayloadNormalizer.normalize(userPath).normalized();

        // 空字节截断：a.txt%00.jpg 在某些底层实现中会被截断为 a.txt
        if (decoded.indexOf('\0') >= 0) {
            return new Result(true, decoded, "路径包含空字节，疑似截断攻击");
        }

        // 统一分隔符，防止 Windows 反斜杠形式绕过
        String unified = decoded.replace('\\', '/');

        try {
            Path root = Paths.get(rootDir).toAbsolutePath().normalize();
            // [关键] 使用 resolve + normalize 让文件系统语义消解 ../，
            // 而非用字符串匹配过滤 ../（后者可被 ....// 绕过）
            Path target = root.resolve(unified).normalize().toAbsolutePath();

            if (!target.startsWith(root)) {
                return new Result(true, target.toString(),
                        "规范化后的路径越出允许根目录: " + target);
            }
            return new Result(false, target.toString(), "路径合法");
        } catch (InvalidPathException e) {
            // 非法路径字符本身即可疑
            return new Result(true, unified, "路径包含非法字符: " + e.getMessage());
        }
    }

    /**
     * 快速判定：仅返回是否为穿越攻击。
     */
    public static boolean isTraversal(String userPath, String rootDir) {
        return check(userPath, rootDir).traversal();
    }

    /**
     * 无根目录上下文时的启发式判定，用于网关层对任意参数的粗筛。
     *
     * <p>网关不知道后端的文件根目录，只能判断参数是否具备穿越意图。
     */
    public static boolean looksLikeTraversal(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String decoded = PayloadNormalizer.normalize(value).normalized()
                .replace('\\', '/');
        // 规范化后仍包含上跳语义，或指向典型敏感文件
        if (decoded.contains("../") || decoded.contains("/..")) {
            return true;
        }
        String lower = decoded.toLowerCase();
        return lower.contains("/etc/passwd") || lower.contains("/etc/shadow")
                || lower.contains("win.ini") || lower.contains("boot.ini")
                || lower.contains("/proc/self/environ")
                || lower.contains("web-inf/web.xml");
    }

    /**
     * 路径检测结果。
     *
     * @param traversal   是否为穿越攻击
     * @param resolvedPath 规范化后的目标路径
     * @param detail      判定说明
     */
    public record Result(boolean traversal, String resolvedPath, String detail) {
    }
}
