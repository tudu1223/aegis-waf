package com.aegis.gateway.config;

import com.aegis.gateway.proxy.ReverseProxyServlet;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * 网关 Servlet 与调度配置。
 */
@Configuration
@EnableScheduling
public class GatewayConfig {

    /**
     * 注册反向代理 Servlet。
     *
     * <p><b>映射策略：</b>仅接管业务路径前缀，而非使用 {@code /*} 通配。
     * 若映射为 {@code /*}，代理 Servlet 会截获包括网关自身管理接口
     * （{@code /aegis/**}）在内的所有请求，导致管理接口返回 404。
     *
     * <p>显式列举业务前缀既解决了该冲突，也使网关的转发范围
     * 变得明确可控——这在生产环境中同样是更安全的做法。
     */
    @Bean
    public ServletRegistrationBean<ReverseProxyServlet> proxyServlet(
            ReverseProxyServlet servlet) {
        ServletRegistrationBean<ReverseProxyServlet> registration =
                new ServletRegistrationBean<>(servlet, "/api/*", "/h2-console/*");
        registration.setName("aegisReverseProxy");
        registration.setLoadOnStartup(1);
        return registration;
    }
}
