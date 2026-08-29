package com.aegis.console.repository;

import com.aegis.console.entity.SqlBaselineEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * SQL 基线仓储。
 */
public interface SqlBaselineRepository extends JpaRepository<SqlBaselineEntity, Long> {

    List<SqlBaselineEntity> findByEndpoint(String endpoint);

    Optional<SqlBaselineEntity> findByEndpointAndFingerprint(String endpoint, String fingerprint);

    List<SqlBaselineEntity> findByStatus(String status);

    List<SqlBaselineEntity> findByEndpointAndStatus(String endpoint, String status);

    long countByStatus(String status);

    List<SqlBaselineEntity> findAllByOrderByLastSeenDesc();
}
