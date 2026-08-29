package com.aegis.console.service;

import com.aegis.console.entity.DetectionEventEntity;
import com.aegis.console.repository.DetectionEventRepository;
import com.aegis.console.repository.SqlBaselineRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 统计聚合服务。
 *
 * <p>为态势总览大屏提供各类指标：请求总量、拦截数、威胁分布、
 * 攻击源排行、时序趋势、检测性能等。
 */
@Service
public class StatisticsService {

    private final DetectionEventRepository eventRepository;
    private final SqlBaselineRepository baselineRepository;

    /** 累计通过网关的请求总数，由网关上报累加。 */
    private final AtomicLong totalRequests = new AtomicLong(0);

    /** 服务启动时间，用于计算运行时长。 */
    private final Instant startedAt = Instant.now();

    public StatisticsService(DetectionEventRepository eventRepository,
                             SqlBaselineRepository baselineRepository) {
        this.eventRepository = eventRepository;
        this.baselineRepository = baselineRepository;
    }

    public void incrementRequests(long delta) {
        totalRequests.addAndGet(delta);
    }

    public long getTotalRequests() {
        return totalRequests.get();
    }

    /** 大屏总览指标。 */
    public Map<String, Object> overview() {
        Map<String, Object> map = new LinkedHashMap<>();

        long blocked = eventRepository.countByVerdict("BLOCK");
        long monitored = eventRepository.countByVerdict("MONITOR");
        long critical = eventRepository.countBySeverity("CRITICAL");
        long high = eventRepository.countBySeverity("HIGH");
        long total = eventRepository.count();
        long requests = Math.max(totalRequests.get(), total);

        map.put("totalRequests", requests);
        map.put("totalEvents", total);
        map.put("blockedCount", blocked);
        map.put("monitoredCount", monitored);
        map.put("criticalCount", critical);
        map.put("highCount", high);

        // 拦截率：已拦截 / 总威胁数
        double interceptRate = total == 0 ? 100.0 : (blocked * 100.0 / total);
        map.put("interceptRate", Math.round(interceptRate * 10) / 10.0);

        // 威胁水位：依据严重事件占比映射为 0-100 的风险指数
        int threatLevel = computeThreatLevel(critical, high, total);
        map.put("threatLevel", threatLevel);
        map.put("threatLevelLabel", threatLabelOf(threatLevel));

        Double avgCost = eventRepository.averageDetectionCost();
        map.put("avgDetectionMicros", avgCost == null ? 0 : Math.round(avgCost));
        map.put("avgDetectionMillis",
                avgCost == null ? 0.0 : Math.round(avgCost / 10.0) / 100.0);

        map.put("baselineTotal", baselineRepository.count());
        map.put("baselineConfirmed", baselineRepository.countByStatus("CONFIRMED"));
        map.put("uptimeSeconds", Duration.between(startedAt, Instant.now()).getSeconds());

        // 最近一小时的事件数，反映当前攻击活跃度
        map.put("recentHourEvents",
                eventRepository.countByCreatedAtAfter(Instant.now().minus(1, ChronoUnit.HOURS)));

        return map;
    }

    /** 威胁类型分布，用于饼图/玫瑰图。 */
    public List<Map<String, Object>> threatDistribution() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object[] row : eventRepository.countGroupByThreatType()) {
            Map<String, Object> item = new LinkedHashMap<>();
            String type = String.valueOf(row[0]);
            item.put("type", type);
            item.put("name", displayNameOf(type));
            item.put("value", ((Number) row[1]).longValue());
            result.add(item);
        }
        return result;
    }

    /** 攻击源排行榜。 */
    public List<Map<String, Object>> topAttackers(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object[] row : eventRepository.countGroupBySourceIp(PageRequest.of(0, limit))) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ip", String.valueOf(row[0]));
            item.put("count", ((Number) row[1]).longValue());
            result.add(item);
        }
        return result;
    }

    /** 受攻击接口排行。 */
    public List<Map<String, Object>> topEndpoints(int limit) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object[] row : eventRepository.countGroupByEndpoint(PageRequest.of(0, limit))) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("endpoint", String.valueOf(row[0]));
            item.put("count", ((Number) row[1]).longValue());
            result.add(item);
        }
        return result;
    }

    /**
     * 时序趋势数据。
     *
     * @param minutes 统计的时间跨度（分钟）
     * @param buckets 切分的时间桶数量
     */
    public List<Map<String, Object>> timeline(int minutes, int buckets) {
        Instant now = Instant.now();
        Instant from = now.minus(minutes, ChronoUnit.MINUTES);
        long bucketMillis = Duration.ofMinutes(minutes).toMillis() / buckets;

        long[] counts = new long[buckets];
        long[] blockedCounts = new long[buckets];

        List<DetectionEventEntity> events = eventRepository.findAllByOrderByIdAsc();
        for (DetectionEventEntity e : events) {
            if (e.getCreatedAt() == null || e.getCreatedAt().isBefore(from)) {
                continue;
            }
            long offset = e.getCreatedAt().toEpochMilli() - from.toEpochMilli();
            int index = (int) (offset / bucketMillis);
            if (index >= 0 && index < buckets) {
                counts[index]++;
                if ("BLOCK".equals(e.getVerdict())) {
                    blockedCounts[index]++;
                }
            }
        }

        List<Map<String, Object>> result = new ArrayList<>(buckets);
        for (int i = 0; i < buckets; i++) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("timestamp", from.toEpochMilli() + i * bucketMillis);
            item.put("events", counts[i]);
            item.put("blocked", blockedCounts[i]);
            result.add(item);
        }
        return result;
    }

    /** 依据严重事件占比计算威胁水位。 */
    private int computeThreatLevel(long critical, long high, long total) {
        if (total == 0) {
            return 0;
        }
        double weighted = (critical * 100.0 + high * 60.0) / total;
        return (int) Math.min(100, Math.round(weighted));
    }

    private String threatLabelOf(int level) {
        if (level >= 80) return "严重";
        if (level >= 60) return "高危";
        if (level >= 40) return "中等";
        if (level >= 20) return "较低";
        return "安全";
    }

    private String displayNameOf(String type) {
        return switch (type) {
            case "SQL_INJECTION" -> "SQL 注入";
            case "XSS" -> "跨站脚本";
            case "COMMAND_INJECTION" -> "命令注入";
            case "PATH_TRAVERSAL" -> "路径穿越";
            case "BROKEN_ACCESS_CONTROL" -> "越权访问";
            case "AUTH_FAILURE" -> "认证失败";
            case "INSECURE_DESERIALIZATION" -> "不安全反序列化";
            case "SSRF" -> "服务端请求伪造";
            case "RATE_ABUSE" -> "速率异常";
            case "INFO_DISCLOSURE" -> "信息泄露";
            default -> type;
        };
    }
}
