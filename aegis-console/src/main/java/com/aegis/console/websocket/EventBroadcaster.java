package com.aegis.console.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 实时事件广播器。
 *
 * <p>向所有已连接的大屏客户端推送检测事件与指标更新，
 * 使攻击发生到大屏呈现的时延控制在 500ms 以内（NFR-05）。
 *
 * <p>推送采用"尽力而为"策略：单个会话发送失败仅移除该会话，
 * 不影响其余客户端，也不阻塞事件写入流程。
 */
@Component
public class EventBroadcaster {

    private final Set<WebSocketSession> sessions = ConcurrentHashMap.newKeySet();
    private final ObjectMapper objectMapper;

    public EventBroadcaster(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void register(WebSocketSession session) {
        sessions.add(session);
    }

    public void unregister(WebSocketSession session) {
        sessions.remove(session);
    }

    /** 推送检测事件，用于大屏的实时威胁流。 */
    public void broadcastEvent(Map<String, Object> event) {
        send(Map.of("type", "EVENT", "data", event));
    }

    /** 推送指标更新，用于大屏的 KPI 卡片与图表。 */
    public void broadcastMetrics(Map<String, Object> metrics) {
        send(Map.of("type", "METRICS", "data", metrics));
    }

    /** 推送策略变更通知。 */
    public void broadcastPolicy(Map<String, Object> policy) {
        send(Map.of("type", "POLICY", "data", policy));
    }

    /** 推送演练进度，用于攻防演练台的流水线动效。 */
    public void broadcastRangeProgress(Map<String, Object> progress) {
        send(Map.of("type", "RANGE", "data", progress));
    }

    private void send(Map<String, Object> message) {
        if (sessions.isEmpty()) {
            return;
        }
        String json;
        try {
            json = objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            return;
        }
        TextMessage textMessage = new TextMessage(json);
        for (WebSocketSession session : sessions) {
            try {
                if (session.isOpen()) {
                    // 同步发送需加锁，WebSocketSession 非线程安全
                    synchronized (session) {
                        session.sendMessage(textMessage);
                    }
                } else {
                    sessions.remove(session);
                }
            } catch (IOException | IllegalStateException e) {
                // 单个客户端发送失败不应影响其他客户端
                sessions.remove(session);
            }
        }
    }

    public int connectionCount() {
        return sessions.size();
    }
}
