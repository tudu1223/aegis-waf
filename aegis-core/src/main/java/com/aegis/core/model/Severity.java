package com.aegis.core.model;

/**
 * 威胁严重级别。
 *
 * <p>与 CVSS 3.1 评级区间对齐，便于测试报告中直接引用。
 */
public enum Severity {

    /** 信息级，仅记录 */
    INFO("信息", 0, "#64748B"),

    /** 低危，CVSS 0.1–3.9 */
    LOW("低危", 1, "#0EA5E9"),

    /** 中危，CVSS 4.0–6.9 */
    MEDIUM("中危", 2, "#F59E0B"),

    /** 高危，CVSS 7.0–8.9，指导书要求必须修复 */
    HIGH("高危", 3, "#F97316"),

    /** 严重，CVSS 9.0–10.0，指导书要求必须修复 */
    CRITICAL("严重", 4, "#E11D48");

    private final String displayName;
    private final int level;
    private final String color;

    Severity(String displayName, int level, String color) {
        this.displayName = displayName;
        this.level = level;
        this.color = color;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getLevel() {
        return level;
    }

    public String getColor() {
        return color;
    }

    /** 判断是否达到指导书定义的"高危"标准（CVSS ≥ 7.0），此类漏洞必须给出修复证明。 */
    public boolean isHighRisk() {
        return level >= HIGH.level;
    }

    /**
     * 依据风险评分映射严重级别。
     *
     * @param score 0–100 的综合风险评分
     */
    public static Severity fromScore(int score) {
        if (score >= 90) return CRITICAL;
        if (score >= 70) return HIGH;
        if (score >= 50) return MEDIUM;
        if (score >= 30) return LOW;
        return INFO;
    }
}
