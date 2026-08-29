package com.aegis.console;

import com.aegis.core.engine.DetectionEngine;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * AEGIS 控制台服务入口。
 *
 * <p>职责：
 * <ul>
 *   <li>汇聚网关层与 RASP 层上报的检测事件</li>
 *   <li>维护 SQL 基线与防护策略</li>
 *   <li>提供统计聚合与实时推送能力</li>
 *   <li>构建带哈希链的审计日志</li>
 * </ul>
 */
@SpringBootApplication
public class AegisConsoleApplication {

    public static void main(String[] args) {
        SpringApplication.run(AegisConsoleApplication.class, args);
    }

    /** 检测引擎实例，供基线服务生成 AST 可视化数据。 */
    @Bean
    public DetectionEngine detectionEngine() {
        return new DetectionEngine();
    }

    /**
     * 跨域配置。
     *
     * <p>演示环境下前端与后端分端口运行，需要允许跨域。
     * 生产部署应将 allowedOriginPatterns 限定为具体的前端域名，
     * 而非通配符。
     */
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
