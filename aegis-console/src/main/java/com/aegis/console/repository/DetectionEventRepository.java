package com.aegis.console.repository;

import com.aegis.console.entity.DetectionEventEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 检测事件仓储。
 */
public interface DetectionEventRepository extends JpaRepository<DetectionEventEntity, Long> {

    Optional<DetectionEventEntity> findByEventId(String eventId);

    /** 按 TraceID 查询同一请求产生的全部事件，用于还原攻击证据链。 */
    List<DetectionEventEntity> findByTraceIdOrderByCreatedAtAsc(String traceId);

    Page<DetectionEventEntity> findAllByOrderByCreatedAtDesc(Pageable pageable);

    /** 取最新一条记录，用于构造哈希链。 */
    Optional<DetectionEventEntity> findFirstByOrderByIdDesc();

    @Query("SELECT e FROM DetectionEventEntity e WHERE "
            + "(:threatType IS NULL OR e.threatType = :threatType) AND "
            + "(:severity IS NULL OR e.severity = :severity) AND "
            + "(:sourceIp IS NULL OR e.sourceIp = :sourceIp) AND "
            + "(:layer IS NULL OR e.layer = :layer) AND "
            + "(:from IS NULL OR e.createdAt >= :from) AND "
            + "(:to IS NULL OR e.createdAt <= :to) "
            + "ORDER BY e.createdAt DESC")
    Page<DetectionEventEntity> search(@Param("threatType") String threatType,
                                      @Param("severity") String severity,
                                      @Param("sourceIp") String sourceIp,
                                      @Param("layer") String layer,
                                      @Param("from") Instant from,
                                      @Param("to") Instant to,
                                      Pageable pageable);

    long countByVerdict(String verdict);

    long countBySeverity(String severity);

    long countByCreatedAtAfter(Instant since);

    /** 威胁类型分布统计。 */
    @Query("SELECT e.threatType, COUNT(e) FROM DetectionEventEntity e GROUP BY e.threatType")
    List<Object[]> countGroupByThreatType();

    /** 攻击源排行统计。 */
    @Query("SELECT e.sourceIp, COUNT(e) FROM DetectionEventEntity e "
            + "WHERE e.sourceIp IS NOT NULL AND e.sourceIp <> '' "
            + "GROUP BY e.sourceIp ORDER BY COUNT(e) DESC")
    List<Object[]> countGroupBySourceIp(Pageable pageable);

    /** 按接口统计攻击次数。 */
    @Query("SELECT e.endpoint, COUNT(e) FROM DetectionEventEntity e "
            + "WHERE e.endpoint IS NOT NULL GROUP BY e.endpoint ORDER BY COUNT(e) DESC")
    List<Object[]> countGroupByEndpoint(Pageable pageable);

    /** 全部记录按 ID 升序，用于哈希链完整性校验。 */
    List<DetectionEventEntity> findAllByOrderByIdAsc();

    /** 平均检测耗时，用于性能指标展示。 */
    @Query("SELECT AVG(e.detectionCostMicros) FROM DetectionEventEntity e "
            + "WHERE e.detectionCostMicros IS NOT NULL")
    Double averageDetectionCost();
}
