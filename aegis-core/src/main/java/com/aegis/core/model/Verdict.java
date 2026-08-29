package com.aegis.core.model;

/**
 * 处置结论。
 *
 * <p>对应系统的三种防护模式：关闭防护（OFF）、仅记录（MONITOR）、拦截（BLOCK）。
 */
public enum Verdict {

    /** 放行：未检出威胁，或防护模式为 OFF */
    PASS("放行"),

    /** 记录：检出威胁但防护模式为 MONITOR，请求仍然放行 */
    MONITOR("记录"),

    /** 拦截：检出威胁且防护模式为 BLOCK，请求被阻断 */
    BLOCK("拦截");

    private final String displayName;

    Verdict(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
