package com.aegis.core.xss;

import java.util.List;

/**
 * HTML 净化结果。
 *
 * @param cleanHtml 净化后的安全 HTML
 * @param removals  被移除的危险内容清单，作为攻击证据留档
 * @param modified  内容是否被修改（即是否检出攻击）
 */
public record SanitizeResult(
        String cleanHtml,
        List<Removal> removals,
        boolean modified
) {

    public static SanitizeResult clean(String html) {
        return new SanitizeResult(html, List.of(), false);
    }

    /** 是否检出攻击载荷。 */
    public boolean hasThreat() {
        return !removals.isEmpty();
    }

    /**
     * 依据被移除内容的类型计算风险分。
     *
     * <p>[关键安全逻辑] 事件属性、危险协议、脚本类标签属于<b>确定性攻击标志</b>——
     * 正常业务内容不可能包含 {@code onerror} 或 {@code javascript:}。
     * 因此单独命中其中任一项即赋予足以触发拦截的分值，
     * 而非累加多项才达到阈值。
     */
    public int riskScore() {
        int score = 0;
        boolean hasDeterministicThreat = false;
        for (Removal r : removals) {
            score += r.type().getWeight();
            if (r.type().isDeterministic()) {
                hasDeterministicThreat = true;
            }
        }
        // 确定性攻击标志：直接提升至拦截阈值以上
        if (hasDeterministicThreat) {
            score = Math.max(score, 85);
        }
        return Math.min(score, 100);
    }

    /**
     * 单条移除记录。
     *
     * @param type    移除类型
     * @param target  被移除的标签名或属性名
     * @param detail  详细说明，含原始载荷片段
     */
    public record Removal(RemovalType type, String target, String detail) {
    }

    /** 移除类型，权重反映其危险程度。 */
    public enum RemovalType {

        /** 移除了不在白名单中的标签，如 script/iframe/svg */
        DISALLOWED_TAG("危险标签", 45, true),

        /** 移除了事件处理属性，如 onerror/onload */
        EVENT_ATTRIBUTE("事件属性", 45, true),

        /** 移除了危险协议，如 javascript:/data: */
        DANGEROUS_PROTOCOL("危险协议", 40, true),

        /** 移除了不在白名单中的普通属性 */
        DISALLOWED_ATTRIBUTE("非法属性", 20, false),

        /** 移除了 style 属性（可承载 expression 等攻击） */
        STYLE_ATTRIBUTE("样式属性", 25, false),

        /** 检出并中和了编码混淆 */
        ENCODED_PAYLOAD("编码混淆", 30, false);

        private final String displayName;
        private final int weight;
        private final boolean deterministic;

        RemovalType(String displayName, int weight, boolean deterministic) {
            this.displayName = displayName;
            this.weight = weight;
            this.deterministic = deterministic;
        }

        public String getDisplayName() {
            return displayName;
        }

        public int getWeight() {
            return weight;
        }

        /**
         * 是否为确定性攻击标志。
         *
         * <p>正常业务内容不可能包含事件属性、危险协议或脚本标签，
         * 命中即可确定为攻击，无需依赖多项累加。
         */
        public boolean isDeterministic() {
            return deterministic;
        }
    }
}
