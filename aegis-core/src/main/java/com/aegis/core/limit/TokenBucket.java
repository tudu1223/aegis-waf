package com.aegis.core.limit;

/**
 * [SEC-DOS-01] 令牌桶限流算法
 *
 * <p><b>安全原理：</b>
 * 令牌桶以恒定速率生成令牌，请求需消耗令牌方可通过。桶容量决定了
 * 系统能容忍的<b>突发流量</b>规模，填充速率决定了<b>长期平均速率</b>上限。
 *
 * <p>相比固定窗口计数，令牌桶不存在"窗口边界突刺"问题（固定窗口在
 * 相邻两窗口交界处可通过双倍请求）；相比漏桶算法，令牌桶允许一定程度的
 * 突发，更贴合真实业务流量特征。
 *
 * <p>本实现为线程安全的惰性填充版本：不使用后台线程定时补充令牌，
 * 而是在每次请求到达时按时间差计算应补充的数量，开销为 O(1)。
 *
 * <p><b>威胁对应：</b>T-06 CC 攻击与暴力破解（STRIDE: DoS, DREAD 7.5）
 */
public final class TokenBucket {

    /** 桶容量，即允许的最大突发请求数。 */
    private final long capacity;

    /** 令牌填充速率（个/秒），即长期平均请求速率上限。 */
    private final double refillRatePerSecond;

    /** 当前可用令牌数。 */
    private double tokens;

    /** 上次填充时间戳（纳秒）。 */
    private long lastRefillNanos;

    public TokenBucket(long capacity, double refillRatePerSecond) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("桶容量必须为正数");
        }
        if (refillRatePerSecond <= 0) {
            throw new IllegalArgumentException("填充速率必须为正数");
        }
        this.capacity = capacity;
        this.refillRatePerSecond = refillRatePerSecond;
        this.tokens = capacity;
        this.lastRefillNanos = System.nanoTime();
    }

    /**
     * 尝试消耗一个令牌。
     *
     * @return true 表示放行，false 表示超出速率限制
     */
    public synchronized boolean tryAcquire() {
        return tryAcquire(1);
    }

    /**
     * 尝试消耗指定数量的令牌。
     *
     * @param permits 需要消耗的令牌数
     * @return 是否成功获取
     */
    public synchronized boolean tryAcquire(int permits) {
        refill();
        if (tokens >= permits) {
            tokens -= permits;
            return true;
        }
        return false;
    }

    /** 按经过的时间惰性补充令牌，避免后台定时线程的开销。 */
    private void refill() {
        long now = System.nanoTime();
        long elapsedNanos = now - lastRefillNanos;
        if (elapsedNanos <= 0) {
            return;
        }
        double elapsedSeconds = elapsedNanos / 1_000_000_000.0;
        double newTokens = elapsedSeconds * refillRatePerSecond;
        if (newTokens > 0) {
            tokens = Math.min(capacity, tokens + newTokens);
            lastRefillNanos = now;
        }
    }

    /** 当前可用令牌数，用于监控展示。 */
    public synchronized double availableTokens() {
        refill();
        return tokens;
    }

    /** 当前桶使用率（0–1），用于大屏流量水位展示。 */
    public synchronized double usageRatio() {
        refill();
        return 1.0 - (tokens / capacity);
    }

    public long getCapacity() {
        return capacity;
    }

    public double getRefillRatePerSecond() {
        return refillRatePerSecond;
    }
}
