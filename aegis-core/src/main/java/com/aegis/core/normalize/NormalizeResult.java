package com.aegis.core.normalize;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 载荷归一化结果。
 *
 * @param original    原始载荷
 * @param normalized  归一化后的载荷
 * @param lowerCase   归一化后的小写形式（比对用，避免重复计算）
 * @param decodeDepth 解码轮数，过深本身即为可疑信号
 * @param flags       归一化过程中发现的异常标记
 */
public record NormalizeResult(
        String original,
        String normalized,
        String lowerCase,
        int decodeDepth,
        Set<String> flags
) {

    /** 编码层数过多的标记。正常业务不会出现三重以上编码。 */
    public static final String FLAG_EXCESSIVE_ENCODING = "EXCESSIVE_ENCODING";

    /** 检出空字节，常用���截断攻击。 */
    public static final String FLAG_NULL_BYTE = "NULL_BYTE";

    /** 检出控制字符，常用于绕过关键字匹配。 */
    public static final String FLAG_CONTROL_CHAR = "CONTROL_CHAR";

    /** 检出全角字符，可能用于绕过 ASCII 特征匹配。 */
    public static final String FLAG_FULLWIDTH = "FULLWIDTH_CHAR";

    /** 检出注释结构。 */
    public static final String FLAG_COMMENT = "COMMENT_DETECTED";

    /** 解码达到上限仍未收敛，疑似解码炸弹。 */
    public static final String FLAG_DECODE_LIMIT = "DECODE_LIMIT_REACHED";

    public static NormalizeResult of(String original, String normalized,
                                     int depth, Set<String> flags) {
        return new NormalizeResult(original, normalized,
                normalized.toLowerCase(), depth,
                flags == null ? new LinkedHashSet<>() : flags);
    }

    /** 载荷是否在归一化阶段就暴露出可疑特征。 */
    public boolean isSuspicious() {
        return !flags.isEmpty();
    }

    /** 归一化阶段贡献的风险分。 */
    public int riskContribution() {
        int score = 0;
        if (flags.contains(FLAG_EXCESSIVE_ENCODING)) {
            score += 20;
        }
        if (flags.contains(FLAG_NULL_BYTE)) {
            score += 15;
        }
        if (flags.contains(FLAG_CONTROL_CHAR)) {
            score += 10;
        }
        if (flags.contains(FLAG_FULLWIDTH)) {
            score += 10;
        }
        if (flags.contains(FLAG_DECODE_LIMIT)) {
            score += 25;
        }
        return score;
    }
}
