package com.aegis.gateway.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 请求体缓存包装器。
 *
 * <p><b>为何需要：</b>Servlet 的请求体是<b>一次性流</b>，读取后无法重读。
 * 而网关需要读取请求体做安全检测，之后还要把原始请求体转发给后端。
 * 若不做缓存，检测与转发只能二选一。
 *
 * <p>本包装器在构造时一次性读入全部请求体，之后每次调用
 * {@code getInputStream()} 都返回基于缓存字节的新流，
 * 使请求体可被多次消费。
 */
public class CachedBodyRequestWrapper extends HttpServletRequestWrapper {

    /** 请求体缓存上限，防止超大请求耗尽内存。 */
    private static final int MAX_BODY_SIZE = 2 * 1024 * 1024;

    private final byte[] cachedBody;

    public CachedBodyRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        byte[] body = request.getInputStream().readNBytes(MAX_BODY_SIZE);
        this.cachedBody = body;
    }

    /** 以字符串形式返回请求体，供检测逻辑分析。 */
    public String getBodyAsString() {
        return new String(cachedBody, StandardCharsets.UTF_8);
    }

    public int getBodySize() {
        return cachedBody.length;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream source = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return source.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // 网关采用同步阻塞模型，无需异步读取支持
            }

            @Override
            public int read() {
                return source.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return source.read(b, off, len);
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(
                getInputStream(), StandardCharsets.UTF_8));
    }
}
