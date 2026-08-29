package com.aegis.core.model;

/**
 * 威胁类型枚举。
 *
 * <p>对应 OWASP Top 10 (2021) 的主要攻击类别，用于事件分类、统计聚合与前端展示。
 */
public enum ThreatType {

    /** SQL 注入（OWASP A03:2021 Injection） */
    SQL_INJECTION("SQL 注入", "A03:2021"),

    /** 跨站脚本（OWASP A03:2021 Injection） */
    XSS("跨站脚本", "A03:2021"),

    /** 命令注入（OWASP A03:2021 Injection） */
    COMMAND_INJECTION("命令注入", "A03:2021"),

    /** 路径穿越（OWASP A01:2021 Broken Access Control） */
    PATH_TRAVERSAL("路径穿越", "A01:2021"),

    /** 越权访问（OWASP A01:2021 Broken Access Control） */
    BROKEN_ACCESS_CONTROL("越权访问", "A01:2021"),

    /** 认证失败，如 JWT 算法混淆（OWASP A07:2021） */
    AUTH_FAILURE("认证失败", "A07:2021"),

    /** 不安全反序列化（OWASP A08:2021） */
    INSECURE_DESERIALIZATION("不安全反序列化", "A08:2021"),

    /** 服务端请求伪造（OWASP A10:2021） */
    SSRF("服务端请求伪造", "A10:2021"),

    /** 速率异常：CC 攻击、暴力破解（OWASP A04:2021 Insecure Design） */
    RATE_ABUSE("速率异常", "A04:2021"),

    /** 敏感信息泄露（OWASP A05:2021 Security Misconfiguration） */
    INFO_DISCLOSURE("信息泄露", "A05:2021"),

    /** 检测引擎自身异常，用于可用性监控 */
    ENGINE_ERROR("引擎异常", "-");

    private final String displayName;
    private final String owaspCategory;

    ThreatType(String displayName, String owaspCategory) {
        this.displayName = displayName;
        this.owaspCategory = owaspCategory;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getOwaspCategory() {
        return owaspCategory;
    }
}
