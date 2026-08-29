package com.aegis.console.service;

import com.aegis.console.entity.SqlBaselineEntity;
import com.aegis.console.repository.SqlBaselineRepository;
import com.aegis.core.engine.DetectionEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SQL 基线管理服务。
 *
 * <p>基线是结构差分检测的参照系。本服务负责基线的学习、审核、
 * 启用与导出，并为前端提供 AST 结构的可视化数据。
 *
 * <p><b>为何基线需要人工审核：</b>
 * 若学习期内混入了攻击流量，攻击的 SQL 结构会被误当作合法基线记录，
 * 导致后续同类攻击被放行。因此学习到的基线默认为 {@code LEARNING} 状态，
 * 需管理员审核确认后才转为 {@code CONFIRMED} 参与检测判定。
 */
@Service
public class BaselineService {

    private final SqlBaselineRepository repository;
    private final DetectionEngine engine;
    private final ObjectMapper objectMapper;

    public BaselineService(SqlBaselineRepository repository,
                           DetectionEngine engine,
                           ObjectMapper objectMapper) {
        this.repository = repository;
        this.engine = engine;
        this.objectMapper = objectMapper;
    }

    /** 记录探针学习到的基线。 */
    @Transactional
    public void recordLearned(String endpoint, String sql, String fingerprint) {
        repository.findByEndpointAndFingerprint(endpoint, fingerprint)
                .ifPresentOrElse(existing -> {
                    existing.setHitCount(existing.getHitCount() == null
                            ? 1 : existing.getHitCount() + 1);
                    existing.setLastSeen(Instant.now());
                    repository.save(existing);
                }, () -> {
                    SqlBaselineEntity entity = new SqlBaselineEntity();
                    entity.setEndpoint(endpoint);
                    entity.setFingerprint(fingerprint);
                    entity.setSampleSql(sql);
                    entity.setStatus("LEARNING");
                    entity.setHitCount(1L);
                    entity.setFirstSeen(Instant.now());
                    entity.setLastSeen(Instant.now());
                    // 生成 AST 可视化数据，供基线管理页展示结构
                    entity.setAstJson(exportAstJson(sql, endpoint));
                    repository.save(entity);
                });
    }

    /** 手工添加基线。 */
    @Transactional
    public SqlBaselineEntity add(String endpoint, String sql) {
        String fingerprint = engine.fingerprint(sql, endpoint);
        return repository.findByEndpointAndFingerprint(endpoint, fingerprint)
                .orElseGet(() -> {
                    SqlBaselineEntity entity = new SqlBaselineEntity();
                    entity.setEndpoint(endpoint);
                    entity.setFingerprint(fingerprint);
                    entity.setSampleSql(sql);
                    // 手工添加视为已审核
                    entity.setStatus("CONFIRMED");
                    entity.setHitCount(0L);
                    entity.setFirstSeen(Instant.now());
                    entity.setLastSeen(Instant.now());
                    entity.setAstJson(exportAstJson(sql, endpoint));
                    return repository.save(entity);
                });
    }

    @Transactional
    public boolean confirm(Long id) {
        return repository.findById(id).map(entity -> {
            entity.setStatus("CONFIRMED");
            repository.save(entity);
            return true;
        }).orElse(false);
    }

    @Transactional
    public boolean disable(Long id) {
        return repository.findById(id).map(entity -> {
            entity.setStatus("DISABLED");
            repository.save(entity);
            return true;
        }).orElse(false);
    }

    @Transactional
    public void delete(Long id) {
        repository.deleteById(id);
    }

    @Transactional
    public void clear() {
        repository.deleteAll();
    }

    /** 列出全部基线。 */
    public List<Map<String, Object>> list(String endpoint) {
        List<SqlBaselineEntity> entities = (endpoint == null || endpoint.isBlank())
                ? repository.findAllByOrderByLastSeenDesc()
                : repository.findByEndpoint(endpoint);

        List<Map<String, Object>> result = new ArrayList<>();
        for (SqlBaselineEntity e : entities) {
            Map<String, Object> map = new HashMap<>();
            map.put("id", e.getId());
            map.put("endpoint", e.getEndpoint());
            map.put("fingerprint", e.getFingerprint());
            map.put("sampleSql", e.getSampleSql());
            map.put("status", e.getStatus());
            map.put("hitCount", e.getHitCount());
            map.put("firstSeen", e.getFirstSeen() == null ? 0 : e.getFirstSeen().toEpochMilli());
            map.put("lastSeen", e.getLastSeen() == null ? 0 : e.getLastSeen().toEpochMilli());
            map.put("ast", parseJson(e.getAstJson()));
            result.add(map);
        }
        return result;
    }

    /** 导出已确认的基线，供探针加载。 */
    public Map<String, List<String>> exportConfirmed() {
        Map<String, List<String>> result = new HashMap<>();
        for (SqlBaselineEntity e : repository.findByStatus("CONFIRMED")) {
            result.computeIfAbsent(e.getEndpoint(), k -> new ArrayList<>())
                    .add(e.getSampleSql());
        }
        return result;
    }

    private String exportAstJson(String sql, String endpoint) {
        try {
            return objectMapper.writeValueAsString(engine.exportAst(sql, endpoint));
        } catch (Exception e) {
            return "{}";
        }
    }

    private Object parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, Object.class);
        } catch (Exception e) {
            return Map.of();
        }
    }
}
