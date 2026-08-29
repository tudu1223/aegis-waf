# AEGIS · OWASP Top 10 测试用例清单

> **指导书硬性要求**：至少执行 10 个 OWASP TOP 10 测试用例；修复所有高危漏洞（CVSS ≥ 7.0）。
> 本清单共 **22 个用例**，覆盖 OWASP Top 10 (2021) **全部十个类别**，超额完成要求。
>
> **本方案的结构优势**：靶场 `vuln-target` 中每个漏洞在 `vuln` 包有脆弱实现、在 `safe` 包有安全实现，
> 因此每个用例天然具备"修复前 / 修复后"双份代码证据 + AEGIS 拦截截图，
> 构成完整的**漏洞修复证明**闭环。

---

## 1. 测试环境与方法

| 项 | 说明 |
|---|---|
| 靶场地址 | `http://localhost:8090`（直连，无防护） |
| 网关地址 | `http://localhost:8000`（经 AEGIS 防护） |
| 测试工具 | OWASP ZAP、Burp Suite、curl、JMeter（CC 测试）、自研演练台 |
| 测试模式 | 每个用例执行三轮：① 直连靶场（验证漏洞存在）② 经网关-监控模式（验���检出）③ 经网关-拦截模式（验证阻断） |
| 证据留存 | 每轮保留请求/响应报文、AEGIS 事件截图、AST 差分图 |
| CVSS 评分 | 采用 CVSS 3.1 计算器，记录向量串 |

**三轮测试法是本报告测试章节的核心方法论**，务必在报告中明确阐述——它同时证明了"漏洞真实存在"与"防护真实有效"。

---

## 2. 用例总表

| 用例 | OWASP 类别 | 名称 | CVSS | 等级 | 检测层 |
|---|---|---|---|---|---|
| TC-01 | A03 注入 | SQL 注入 — 恒真式绕过认证 | 9.8 | 严重 | RASP |
| TC-02 | A03 注入 | SQL 注入 — UNION 联合查询脱库 | 9.1 | 严重 | RASP |
| TC-03 | A03 注入 | SQL 注入 — 注释截断 | 8.6 | 高 | RASP |
| TC-04 | A03 注入 | SQL 注入 — 内联注释混淆绕过 | 8.6 | 高 | RASP |
| TC-05 | A03 注入 | SQL 注入 — 时间盲注 | 7.5 | 高 | RASP |
| TC-06 | A03 注入 | SQL 注入 — 堆叠查询 | 9.8 | 严重 | RASP |
| TC-07 | A03 注入 | SQL 注入 — 多重 URL 编码绕过 | 8.6 | 高 | 网关+RASP |
| TC-08 | A03 注入 | 存储型 XSS — 事件属性 | 8.2 | 高 | 网关 |
| TC-09 | A03 注入 | 存储型 XSS — SVG 命名空间绕过 | 8.2 | 高 | 网关 |
| TC-10 | A03 注入 | 反射型 XSS — 伪协议 | 7.4 | 高 | 网关 |
| TC-11 | A03 注入 | 命令注入 — shell 元字符 | 9.8 | 严重 | RASP |
| TC-12 | A01 访问控制 | 水平越权（IDOR） | 8.1 | 高 | 网关 |
| TC-13 | A01 访问控制 | 垂直越权（普通用户访问管理接口） | 8.8 | 高 | 网关 |
| TC-14 | A01 访问控制 | 路径穿越读取任意文件 | 7.5 | 高 | 网关 |
| TC-15 | A02 加密失败 | 口令明文/弱哈希存储 | 7.5 | 高 | 代码审计 |
| TC-16 | A04 不安全设计 | 无限制暴力破解登录 | 7.5 | 高 | 网关 |
| TC-17 | A05 安全配置错误 | 详细报错泄露栈与 SQL | 5.3 | 中 | 代码审计 |
| TC-18 | A06 脆弱组件 | 依赖组件已知漏洞扫描 | — | — | SCA |
| TC-19 | A07 认证失败 | JWT 算法混淆（alg=none） | 9.8 | 严重 | 网关 |
| TC-20 | A08 数据完整性 | 不安全反序列化 | 9.8 | 严重 | RASP |
| TC-21 | A09 日志监控失败 | 攻击行为无审计记录 | 5.3 | 中 | 功能验证 |
| TC-22 | A10 SSRF | 服务端请求伪造探测内网 | 8.6 | 高 | 网关 |

> **CVSS ≥ 7.0 的高危用例共 18 个**，全部需在报告中给出修复证明。

---

## 3. 用例详情

### TC-01 · SQL 注入 — 恒真式绕过认证

| 项 | 内容 |
|---|---|
| **OWASP** | A03:2021 Injection |
| **CVSS 3.1** | 9.8 严重 · `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **目标接口** | `POST /api/auth/login` |
| **前置条件** | 靶场使用字符串拼接构造登录 SQL |

**攻击载荷**
```
username = admin' OR '1'='1' --
password = anything
```

**脆弱代码**（`vuln/VulnAuthService.java`）
```java
// [VULN-01] 受控漏洞：字符串拼接构造 SQL，存在注入
// 仅用于教学演示，禁止在生产环境使用此写法
String sql = "SELECT * FROM users WHERE username='" + username
           + "' AND password='" + md5(password) + "'";
```

**拼接后的真实 SQL**
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='...'
```

**预期结果**

| 轮次 | 预期 |
|---|---|
| ① 直连靶场 | **登录成功**，返回 admin 的 JWT — 漏洞确认存在 |
| ② 网关监控模式 | 请求放行，但产生 CRITICAL 事件；AST 差分显示新增 `OrExpression` + `TAUTOLOGY` 节点 |
| ③ 网关拦截模式 | RASP 探针在 SQL 执行前抛出 `SecurityException`，返回 HTTP 403；大屏红色子树弹出 |

**AST 差分预期输出**
```
基线指纹  SELECT * FROM users WHERE username = ? AND password = ?
实际指纹  SELECT * FROM users WHERE username = ? OR ? = ?
新增节点  WHERE/OrExpression          → OR_INJECTION   (CRITICAL)
          WHERE/OrExpression/EqualsTo → TAUTOLOGY      (CRITICAL)
缺失节点  WHERE/AndExpression/password = ?  → CONDITION_REMOVED
结构相似度 0.41   风险评分 95   处置 BLOCK
```

**修复方案**（`safe/SafeAuthService.java`）
```java
// [FIX-01] 使用参数化查询，SQL 结构与数据彻底分离
// PreparedStatement 将 ? 占位符绑定为纯数据，数据库不会将其解析为 SQL 语法，
// 从根本上消除注入可能，而非依赖过滤
String sql = "SELECT * FROM users WHERE username=? AND password=?";
try (PreparedStatement ps = conn.prepareStatement(sql)) {
    ps.setString(1, username);
    ps.setString(2, hash);   // 配合 TC-15：BCrypt 加盐哈希
    ...
}
```

**修复验证**：修复后重放载荷，登录失败返回 401，且 RASP 捕获的 SQL 指纹与基线一致。

---

### TC-02 · SQL 注入 — UNION 联合查询脱库

- **CVSS** 9.1 严重 · `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **接口** `GET /api/notes/search?keyword=`
- **载荷**
```
keyword = x' UNION SELECT username,password,email,1,1 FROM users --
```
- **预期**：① 返回全部用户凭据；② AST 根节点变为 `SetOperationList`，标注 `UNION_INJECTION`；③ 403 拦截
- **差分要点**：`风险特征 R-02 命中(+45)`，结构相似度 < 0.3
- **修复**：参数化查询 + 查询结果列白名单

---

### TC-03 · SQL 注入 — 注释截断

- **CVSS** 8.6 高
- **接口** `GET /api/notes/detail?id=`
- **载荷**
```
id = 1' --
id = 1' #
id = 1'/*
```
- **预期**：AST 中原有的 `AND owner=?` 条件消失，标注 `COMMENT_TRUNCATION` + `CONDITION_REMOVED`
- **说明**：此用例证明系统能检出"条件被剥离"这种**减法型**注入，而非只能检出新增结构——这是结构差分算法优于特征匹配的有力证据

---

### TC-04 · SQL 注入 — 内联注释混淆绕过 ⭐ 核心创新验证

- **CVSS** 8.6 高
- **载荷**（专门用于击穿传统正则 WAF）
```
id = 1/*!50000UNION*/SELECT/*!50000ALL*/1,2,3--
id = 1 UNI/**/ON SEL/**/ECT 1,2,3
id = 1 uNiOn/*abc*/sElEcT 1,2,3
```
- **预期**：三种变形**全部拦截**，且归一化后收敛为同一指纹
- **报告价值** ★：本用例是论证"AST 方案优于正则方案"的**关键实验**。报告中应并列展示：
  - ModSecurity 核心规则集对上述载荷的拦截情况（部分绕过）
  - AEGIS 的拦截情况（全部命中）
  - 原因分析：混淆改变的是**文本形态**，而 AST 解析后得到的是**语义结构**，二者正交

---

### TC-05 · SQL 注入 — 时间盲注

- **CVSS** 7.5 高
- **载荷**
```
id = 1' AND SLEEP(5) --
id = 1' AND (SELECT * FROM (SELECT SLEEP(5))a) --
id = 1' AND BENCHMARK(5000000,MD5('a')) --
```
- **预期**：命中风险特征 `R-05 时间盲注函数(+50)`，即使基线为空也能拦截（冷启动兜底验证）
- **验证点**：直连靶场时响应耗时 ≈ 5s，经网关拦截后响应 < 50ms

---

### TC-06 · SQL 注入 — 堆叠查询

- **CVSS** 9.8 严重
- **载荷**
```
id = 1'; DROP TABLE notes_backup; --
id = 1'; UPDATE users SET role='ADMIN' WHERE username='guest'; --
```
- **预期**：`parseStatements` 返回 2 条语句，命中 `R-03 堆叠查询(+50)`，标注 `STACKED_QUERY`
- **注意**：靶场需准备 `notes_backup` 表用于演示破坏效果，测试后自动重建

---

### TC-07 · SQL 注入 — 多重 URL 编码绕过

- **CVSS** 8.6 高
- **载荷**
```
单重  id=1%27%20OR%20%271%27%3D%271
双重  id=1%2527%2520OR%2520%25271%2527%253D%25271
三重  id=1%252527%252520OR%252520...
```
- **预期**：`PayloadNormalizer` 循环解码至不动点，三种编码深度均还原为同一 payload；深度 ≥ 3 额外加 20 风险分
- **验证点**：报告中给出解码深度与还原结果的对照表

---

### TC-08 · 存储型 XSS — 事件属性

- **CVSS** 8.2 高 · `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`
- **接口** `POST /api/notes/create` → `GET /api/notes/{id}`
- **载荷**
```html
<img src=x onerror=alert(document.cookie)>
<img src=x OnErRoR=alert(1)>
<img src="x" onerror = alert(1) >
```
- **脆弱代码**
```java
// [VULN-08] 受控漏洞：富文本内容未净化直接存储与回显
noteRepo.save(new Note(title, rawContent));   // rawContent 原样入库
```
- **预期**：`HtmlSanitizer` DOM 解析后移除全部 `on*` 属性，保留 `<img>` 标签与 `src`
- **修复**
```java
// [FIX-08] 基于 DOM 解析的三级白名单净化
// 不使用正则过滤（可被 <svg/onload>、编码等手法绕过），
// 而是将内容按 HTML 规范解析为 DOM 树后逐节点白名单裁决
SanitizeResult r = htmlSanitizer.sanitize(rawContent);
noteRepo.save(new Note(title, r.cleanHtml()));
auditLog.record(r.removals());   // 被移除的内容作为攻击证据留档
```

---

### TC-09 · 存储型 XSS — SVG / MathML 命名空间绕过

- **CVSS** 8.2 高
- **载荷**
```html
<svg/onload=alert(1)>
<svg><script>alert(1)</script></svg>
<math><mtext><script>alert(1)</script></mtext></math>
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
```
- **预期**：`svg`/`math`/`iframe` 均不在标签白名单，整体移除
- **报告价值**：证明白名单机制对**未知新型绕过手法**天然免疫

---

### TC-10 · 反射型 XSS — 伪协议

- **CVSS** 7.4 高
- **载荷**
```html
<a href="javascript:alert(1)">click</a>
<a href="java&#115;cript:alert(1)">click</a>
<a href="  java&#9;script:alert(1)">click</a>
<a href="JaVaScRiPt:alert(1)">click</a>
```
- **预期**：协议判定前先剥离空白与控制字符并多重解码，四种变形全部识别，`href` 置空
- **同时验证**：正常链接 `<a href="https://example.com">` 完整保留（不误伤）

---

### TC-11 · 命令注入

- **CVSS** 9.8 严重
- **接口** `POST /api/tools/ping`（靶场提供的网络诊断功能）
- **载荷**
```
host = 127.0.0.1; cat /etc/passwd
host = 127.0.0.1 | whoami
host = 127.0.0.1 && dir
host = 127.0.0.1`id`
```
- **脆弱代码**
```java
// [VULN-11] 受控漏洞：使用 shell 解析型命令执行且拼接用户输入
Runtime.getRuntime().exec("ping -c 1 " + host);
```
- **预期**：RASP `ProcessInterceptor` 检出 shell 元字符，CRITICAL 事件 + 阻断
- **修复**
```java
// [FIX-11] 参数数组化调用 + 输入白名单校验
// ProcessBuilder 接收 List<String>，各参数不经 shell 解析，
// 元字符失去特殊含义；同时用严格白名单校验主机名格式
if (!HOST_PATTERN.matcher(host).matches()) throw new IllegalArgumentException();
new ProcessBuilder(List.of("ping", "-c", "1", host)).start();
```

---

### TC-12 · 水平越权（IDOR）

- **CVSS** 8.1 高
- **场景**：用户 A（id=1001）登录后访问 `GET /api/notes/2002`（属于用户 B）
- **脆弱代码**
```java
// [VULN-12] 受控漏洞：仅校验登录态，未校验资源归属
return noteRepo.findById(noteId);
```
- **预期**：AEGIS 记录"跨用户资源访问"异常；修复后返回 403
- **修复**
```java
// [FIX-12] 资源属主强校验：查询时强制绑定当前主体 ID
return noteRepo.findByIdAndOwnerId(noteId, currentUser.getId())
               .orElseThrow(() -> new ForbiddenException("无权访问该资源"));
```

---

### TC-13 · 垂直越权

- **CVSS** 8.8 高
- **场景**：普通用户携带自己的合法 JWT 访问 `GET /api/admin/users`
- **预期**：RBAC 拦截，返回 403
- **修复**：`@PreAuthorize("hasRole('ADMIN')")` 注解式鉴权 + 网关侧路径-角色映射双重校验

---

### TC-14 · 路径穿越

- **CVSS** 7.5 高
- **接口** `GET /api/files/download?name=`
- **载荷**
```
name = ../../../../etc/passwd
name = ..%2f..%2f..%2fetc%2fpasswd
name = ....//....//etc/passwd
name = %252e%252e%252fetc%252fpasswd
```
- **预期**：路径规范化后前缀校验失败，403；四种变形全部拦截
- **报告要点**：说明为何"黑名单过滤 `../`"是错误做法（`....//` 过滤一次后仍为 `../`）

---

### TC-15 · 口令弱存储

- **CVSS** 7.5 高
- **检测方式**：代码审计 + 数据库查验
- **脆弱实现**：`MD5(password)` 无盐
- **预期**：数据库中可见相同口令的用户哈希值相同，可彩虹表破解
- **修复**
```java
// [FIX-15] BCrypt 自适应哈希，内置随机盐 + 可调工作因子
// 相同明文每次哈希结果不同，且计算代价可随硬件发展调高，抵抗暴力破解
private final PasswordEncoder encoder = new BCryptPasswordEncoder(12);
```
- **验证**：修复后同一口令两次注册产生不同哈希

---

### TC-16 · 暴力破解

- **CVSS** 7.5 高
- **方法**：JMeter 对 `/api/auth/login` 发起 1000 次并发口令尝试
- **预期**：
  - 令牌桶在超过 20 req/s 后开始拒绝
  - 滑动窗口在 60s 内超过 600 次触发封禁
  - IP 信誉累积至 100 分后封禁 30 分钟
  - 大屏限流曲线飙升，攻击源 TOP 榜首位亮起
- **附加**：登录接口独立配置更严格阈值（5 次/分钟）+ 失败计数锁定账户

---

### TC-17 · 详细报错泄露

- **CVSS** 5.3 中
- **载荷**：`GET /api/notes/detail?id=abc`（类型错误触发异常）
- **脆弱表现**：返回完整 Java 堆栈 + SQL 语句 + 数据库版本
- **修复**：全局 `@RestControllerAdvice` 统一异常处理，对外仅返回错误码与通用提示，详细信息仅写入服务端日志

---

### TC-18 · 脆弱组件扫描

- **方法**：`mvn dependency-check:check`（OWASP Dependency-Check）+ `npm audit`
- **预期**：生成 SCA 报告，列出所有依赖的已知 CVE
- **处置**：升级存在高危 CVE 的依赖，报告中附升级前后对照表
- **加分项**：若使用 Docker，用 Trivy 扫描镜像（指导书推荐工具，正好呼应）

---

### TC-19 · JWT 算法混淆

- **CVSS** 9.8 严重
- **载荷**：将 JWT 头部改为 `{"alg":"none","typ":"JWT"}`，删除签名段，伪造 `role: ADMIN`
- **脆弱代码**
```java
// [VULN-19] 受控漏洞：解析时未限定算法，接受 alg=none
Jwts.parser().parseClaimsJwt(token);
```
- **修复**
```java
// [FIX-19] 强制算法白名单，仅接受 HS256 签名令牌
// 拒绝 alg=none 与算法降级，防止签名绕过
Jwts.parser()
    .verifyWith(secretKey)
    .sig().add(Jwts.SIG.HS256).and()   // 算法白名单
    .build()
    .parseSignedClaims(token);
```
- **附加验证**：密钥强度 ≥ 256 bit；令牌有效期 30 分钟；含 `jti` 防重放

---

### TC-20 · 不安全反序列化

- **CVSS** 9.8 严重
- **接口** `POST /api/session/restore`（靶场提供的会话恢复功能）
- **载荷**：构造恶意序列化对象（教学演示用无害 payload，仅触发标记方法，**不使用真实 RCE gadget**）
- **修复**：禁用原生 `ObjectInputStream`，改用 Jackson JSON 并启用类型白名单
- **⚠ 合规提示**：本用例仅在本地隔离环境演示，payload 不含任何破坏性代码，符合指导书"严守法律红线"要求

---

### TC-21 · 日志与监控失败

- **验证方法**：执行 TC-01 至 TC-20 后，检查：
  1. 每个攻击是否都产生了对应的检测事件
  2. 事件是否包含完整的 TraceID、源 IP、载荷、判定依据
  3. 哈希链是否连续（篡改任一条记录后链校验应失败）
  4. 大屏是否实时呈现
- **预期**：22 个用例 100% 留痕，哈希链校验通过
- **报告价值**：此用例本身就是对 AEGIS 核心价值的整体验收

---

### TC-22 · SSRF

- **CVSS** 8.6 高
- **接口** `POST /api/notes/import?url=`（从 URL 导入笔记）
- **载荷**
```
url = http://127.0.0.1:8080/api/admin/users
url = http://169.254.169.254/latest/meta-data/     (云元数据)
url = http://[::1]:8080/
url = http://0177.0.0.1/                            (八进制绕过)
url = http://2130706433/                            (十进制绕过)
```
- **修复**
```java
// [FIX-22] 出站地址白名单 + 内网网段拒绝
// 先解析 DNS 得到真实 IP 再判定，防止 DNS Rebinding 与进制编码绕过
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
    || addr.isLinkLocalAddress() || isMetadataEndpoint(addr)) {
    throw new SecurityException("目标地址不在允许范围");
}
```

---

## 4. 测试报告模板（每个用例统一格式）

```
用例编号：TC-01
用例名称：SQL 注入 — 恒真式绕过认证
OWASP 类别：A03:2021 Injection
CVSS 3.1：9.8（严重）  向量：AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
测试时间：2026-XX-XX HH:MM
测试人：XXX

【测试目的】
【前置条件】
【测试步骤】
【攻击载荷】
【第一轮·直连靶场】  请求报文 / 响应报文 / 截图 → 结论：漏洞存在
【第二轮·监控模式】  AEGIS 事件截图 / AST 差分图 → 结论：成功检出
【第三轮·拦截模式】  403 响应 / 大屏截图 → 结论：成功阻断
【漏洞代码】        文件路径 + 行号 + 代码片段
【修复代码】        文件路径 + 行号 + 代码片段
【修复验证】        重放载荷的响应 → 结论：修复有效
【结论】            通过 / 不通过
```

---

## 5. 测试结果汇总表（报告中呈现）

| 用例 | 漏洞存在 | 检出 | 拦截 | 修复 | 复测 |
|---|---|---|---|---|---|
| TC-01 | ✓ | ✓ | ✓ | ✓ | 通过 |
| TC-02 | ✓ | ✓ | ✓ | ✓ | 通过 |
| … | | | | | |
| **合计** | **22/22** | **22/22** | **20/22**¹ | **18/18**² | **通过** |

¹ TC-18（组件扫描）与 TC-21（日志验证）不涉及运行时拦截
² 18 个 CVSS ≥ 7.0 的高危漏洞全部修复，满足指导书要求

---

## 6. 合规与伦理声明（报告必备章节）

指导书明确要求"严守法律红线、坚守道德底线"，报告中必须包含以下声明：

> 本项目所有攻击测试**均在本地隔离环境**（localhost）中针对**自建靶场系统**执行，
> 未对任何第三方系统进行未授权测试。靶场中的漏洞代码为教学目的**主动构造**，
> 集中隔离于 `vuln` 包并全部加注警示注释，不会随生产构建发布。
> 反序列化测试用例采用无害化 payload，不包含任何具备实际破坏能力的 gadget 链。
> 本项目严格遵守《中华人民共和国网络安全法》《数据安全法》及相关法律法规，
> 所有技术成果仅用于安全防护研究与教学实践。
