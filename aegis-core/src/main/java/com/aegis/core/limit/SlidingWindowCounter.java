package com.aegis.core.limit;

/**
 * [SEC-DOS-02] 滑动窗口限流算法
 *
 * <p><b>安全原理：</b>
 * 固定窗口计数存在"边界突刺"缺陷：若窗口为 60 秒、阈值 600，攻击者可在
 * 第 59 秒发送 600 次、第 61 秒再发送 600 次，两秒内实际通过 1200 次请求。
 *
 * <p>滑动窗口将时间轴切分为多个细粒度桶，统计时汇总最近 N 个桶的计数，
 * 窗口随时间平滑滑动，消除边界突刺问题。本���现使用<b>环形数组</b>，
 * 空间复杂度 O(桶数)，单次更新时间复杂度 O(1)（摊还）。
 *
 * <p>与令牌桶配合使用：令牌桶控制瞬时突发，滑动窗口控制持续总量，
 * 二者取"与"关系，任一超限即拒绝。
 *
 * <p><b>威胁对应：</b>T-06 CC 攻击与暴力破解（DREAD 7.5）
 */
public final class SlidingWindowCounter {

    /** 窗口总时长（毫秒）。 */
    private final long windowMillis;

    /** 桶数量，决定窗口滑动的精度。 */
    private final int bucketCount;

    /** 单个桶的时长（毫秒）。 */
    private final long bucketMillis;

    /** 环形计数数组。 */
    private final long[] counts;

    /** 每个桶对应的时间片编号，用于判断桶是否过期。 */
    private final long[] bucketEpochs;

    /** 窗口内允许的最大请求数。 */
    private final long threshold;

    public SlidingWindowCounter(long windowMillis, int bucketCount, long threshold) {
        if (windowMillis <= 0 || bucketCount <= 0) {
            throw new IllegalArgumentException("窗口时长与桶数量必须为正数");
        }
        this.windowMillis = windowMillis;
        this.bucketCount = bucketCount;
        this.bucketMillis = Math.max(1, windowMillis / bucketCount);
        this.counts = new long[bucketCount];
        this.bucketEpochs = new long[bucketCount];
        this.threshold = threshold;
        java.util.Arrays.fill(bucketEpochs, -1);
    }

    /**
     * 记录一次请求并判断是否超出阈值。
     *
     * @return true 表示放行，false 表示超出窗口阈值
     */
    public synchronized boolean tryAcquire() {
        long now = System.currentTimeMillis();
        long currentEpoch = now / bucketMillis;
        int index = (int) (currentEpoch % bucketCount);

        // 桶已过期则重置：环形数组复用同一槽位表示不同时间片
        if (bucketEpochs[index] != currentEpoch) {
            bucketEpochs[index] = currentEpoch;
            counts[index] = 0;
        }

        long total = currentCount(currentEpoch);
        if (total >= threshold) {
            return false;
        }
        counts[index]++;
        return true;
    }

    /** 统计当前窗口内的请求总数。 */
    public synchronized long currentCount() {
        long currentEpoch = System.currentTimeMillis() / bucketMillis;
        return currentCount(currentEpoch);
    }

    private long currentCount(long currentEpoch) {
        long oldestValidEpoch = currentEpoch - bucketCount + 1;
        long total = 0;
        for (int i = 0; i < bucketCount; i++) {
            // 仅统计仍在窗口内的桶，过期桶自动被忽略
            if (bucketEpochs[i] >= oldestValidEpoch && bucketEpochs[i] <= currentEpoch) {
                total += counts[i];
            }
        }
        return total;
    }

    /** 窗口使用率（0–1），用于大屏水位展示。 */
    public synchronized double usageRatio() {
        if (threshold <= 0) {
            return 0;
        }
        return Math.min(1.0, (double) currentCount() / threshold);
    }

    public long getThreshold() {
        return threshold;
    }

    public long getWindowMillis() {
        return windowMillis;
    }
}
