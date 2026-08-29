package com.aegis.gateway;

import com.aegis.core.engine.DetectionEngine;
import com.aegis.core.limit.IpReputationManager;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * AEGIS 安全网关入口。
 *
 * <p>作为反向代理位于业务系统前方，承担 HTTP 层的安全防护：
 * <ul>
 *   <li>参数级攻击载荷的启发式预判</li>
 *   <li>请求速率限制与 IP 信誉管理</li>
 *   <li>注入 TraceID，与 RASP 探针联动形��完整证据链</li>
 * </ul>
 *
 * <p><b>与 RASP 层的分工：</b>网关只能看到 HTTP 参数文本，
 * 判定具有启发式性质；确定性判定由 RASP 层基于真实 SQL 完成。
 * 两层通过 TraceID 关联，兼顾拦截时效性与判定准确性。
 */
@SpringBootApplication
public class AegisGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AegisGatewayApplication.class, args);
    }

    @Bean
    public DetectionEngine detectionEngine() {
        return new DetectionEngine();
    }

    @Bean
    public IpReputationManager ipReputationManager() {
        return new IpReputationManager();
    }
}
