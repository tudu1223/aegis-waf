package com.aegis.core.limit;

import com.aegis.core.model.Severity;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * [SEC-DOS-03] IP 信誉管理器
 *
 * <p><b>安全原理：</b>
 * 单次攻击行为可能是误报，但同一来源的持续攻击是明确的恶意信号。
 * 本管理器为每个来源 IP 维护累积风险评分，达到阈值后临时封禁。
 *
 * <p><b>两个关键设计：</b>
 * <ul>
 *   <li><b>时间衰减</b>：评分随时间指数衰减，避免历史行为永久影响当前判定。
 *       这对降低误报至关重要——共享出口 IP（如校园网 NAT）可能因个别用户的
 *       行为被误判，衰减机制保证正常用户不会被长期阻断。</li>
 *   <li><b>封禁自动过期</b>：封禁有明确时限而非永久，符合"失效安全"原则，
 *       防止误封导致业务长期不可用。</li>
 * </ul>
 *
 * <p><b>威胁对应：</b>T-06 CC 攻击与暴力破解（DREAD 7.5）
 */
public final class IpReputationManager {

    /**
     * 触发封禁的评分阈值。
     *
     * <p>取值权衡：过低会导致演示或安全测试场景下，来自同一来源的
     * 连续测试请求很快被"IP 封禁"统一拦下，掩盖了各类攻击的具体
     * 检测结果；过高则削弱对真实持续攻击的抑制能力。
     *
     * <p>此处取 300（约相当于连续 10 次严重攻击），配合每小时 10% 的
     * 时间衰减与 30 分钟的封禁时限，既能拦截持续攻击，
     * 又不会干扰正常的安全测试流程。
     */
    private static final int BLOCK_THRESHOLD = 300;

    /** 封禁时长。 */
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(30);

    /** 每小时的评分保留比例，即每小时衰减 10%。 */
    private static final double HOURLY_DECAY_FACTOR = 0.9;

    private final Cache<String, Reputation> reputations;

    public IpReputationManager() {
        this.reputations = Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterAccess(Duration.ofHours(24))
                .build();
    }

    /**
     * 依据检测到的威胁更新来源 IP 的信誉评分。
     *
     * @param ip       来源 IP
     * @param severity 本次威胁的严重级别
     * @return 更新后的信誉记录
     */
    public Reputation record(String ip, Severity severity) {
        if (ip == null || ip.isEmpty()) {
            return new Reputation("unknown", 0, 0, Instant.now(), Instant.now(), null);
        }
        Reputation current = reputations.getIfPresent(ip);
        Instant now = Instant.now();

        double score;
        long eventCount;
        Instant firstSeen;
        if (current == null) {
            score = 0;
            eventCount = 0;
            firstSeen = now;
        } else {
            score = applyDecay(current.score(), current.lastSeen(), now);
            eventCount = current.eventCount();
            firstSeen = current.firstSeen();
        }

        score += weightOf(severity);
        eventCount++;

        Instant blockedUntil = null;
        if (score >= BLOCK_THRESHOLD) {
            blockedUntil = now.plus(BLOCK_DURATION);
        } else if (current != null && current.blockedUntil() != null
                && current.blockedUntil().isAfter(now)) {
            // 保留尚未到期的封禁
            blockedUntil = current.blockedUntil();
        }

        Reputation updated = new Reputation(ip, score, eventCount,
                firstSeen, now, blockedUntil);
        reputations.put(ip, updated);
        return updated;
    }

    /**
     * 判断 IP 当前是否处于封禁状态。
     *
     * <p>封禁到期后自动解除，无需额外的清理任务。
     */
    public boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        Reputation rep = reputations.getIfPresent(ip);
        if (rep == null || rep.blockedUntil() == null) {
            return false;
        }
        return rep.blockedUntil().isAfter(Instant.now());
    }

    /** 查询 IP 的当前信誉，评分已应用时间衰减。 */
    public Reputation get(String ip) {
        Reputation rep = reputations.getIfPresent(ip);
        if (rep == null) {
            return null;
        }
        double decayed = applyDecay(rep.score(), rep.lastSeen(), Instant.now());
        return new Reputation(rep.ip(), decayed, rep.eventCount(),
                rep.firstSeen(), rep.lastSeen(), rep.blockedUntil());
    }

    /** 解除封禁，供管理员手工操作。 */
    public void unblock(String ip) {
        Reputation rep = reputations.getIfPresent(ip);
        if (rep != null) {
            reputations.put(ip, new Reputation(rep.ip(), 0, rep.eventCount(),
                    rep.firstSeen(), rep.lastSeen(), null));
        }
    }

    /** 返回风险评分最高的若干 IP，用于大屏攻击源榜单。 */
    public List<Reputation> topOffenders(int limit) {
        List<Reputation> all = new ArrayList<>(reputations.asMap().values());
        Instant now = Instant.now();
        List<Reputation> decayed = new ArrayList<>(all.size());
        for (Reputation r : all) {
            decayed.add(new Reputation(r.ip(),
                    applyDecay(r.score(), r.lastSeen(), now),
                    r.eventCount(), r.firstSeen(), r.lastSeen(), r.blockedUntil()));
        }
        decayed.sort(Comparator.comparingDouble(Reputation::score).reversed());
        return decayed.size() <= limit ? decayed : decayed.subList(0, limit);
    }

    /** 当前被封禁的 IP 数量。 */
    public long blockedCount() {
        Instant now = Instant.now();
        return reputations.asMap().values().stream()
                .filter(r -> r.blockedUntil() != null && r.blockedUntil().isAfter(now))
                .count();
    }

    public long trackedCount() {
        return reputations.estimatedSize();
    }

    public void clear() {
        reputations.invalidateAll();
    }

    /**
     * 应用指数时间衰减。
     *
     * <p>公式：{@code score × 0.9^(经过小时数)}。
     * 该机制保证偶发的误判不会长期影响正常用户。
     */
    private double applyDecay(double score, Instant lastSeen, Instant now) {
        if (lastSeen == null || score <= 0) {
            return Math.max(0, score);
        }
        double hours = Duration.between(lastSeen, now).toMillis() / 3_600_000.0;
        if (hours <= 0) {
            return score;
        }
        return score * Math.pow(HOURLY_DECAY_FACTOR, hours);
    }

    /** 依据威胁严重级别确定评分增量。 */
    private int weightOf(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 30;
            case HIGH -> 15;
            case MEDIUM -> 5;
            case LOW -> 2;
            case INFO -> 0;
        };
    }

    /**
     * IP 信誉记录。
     *
     * @param ip           来源 IP
     * @param score        当前风险评分
     * @param eventCount   累计触发的威胁事件数
     * @param firstSeen    首次出现时间
     * @param lastSeen     最近出现时间
     * @param blockedUntil 封禁到期时间，null 表示未封禁
     */
    public record Reputation(
            String ip,
            double score,
            long eventCount,
            Instant firstSeen,
            Instant lastSeen,
            Instant blockedUntil
    ) {
        public boolean isCurrentlyBlocked() {
            return blockedUntil != null && blockedUntil.isAfter(Instant.now());
        }
    }
}
