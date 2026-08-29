package com.aegis.console.websocket;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.handler.TextWebSocketHandler;

/**
 * WebSocket 配置与会话处理。
 *
 * <p>大屏通过 {@code /ws/aegis} 建立长连接，接收实时检测事件与指标推送。
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final EventBroadcaster broadcaster;

    public WebSocketConfig(EventBroadcaster broadcaster) {
        this.broadcaster = broadcaster;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(handler(), "/ws/aegis")
                // 演示环境允许跨域；生产部署应限定为具体的前端域名
                .setAllowedOriginPatterns("*");
    }

    private WebSocketHandler handler() {
        return new TextWebSocketHandler() {
            @Override
            public void afterConnectionEstablished(WebSocketSession session) {
                broadcaster.register(session);
            }

            @Override
            public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
                broadcaster.unregister(session);
            }

            @Override
            public void handleTransportError(WebSocketSession session, Throwable exception) {
                broadcaster.unregister(session);
            }
        };
    }
}
