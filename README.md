<div align="center">

<img src="docs/assets/logo.svg" alt="AEGIS" width="88" height="88" />

# AEGIS

**基于 SQL 抽象语法树结构指纹的 Web 攻击语义检测平台**

**Semantic Web Attack Detection via SQL AST Structural Fingerprinting**

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17-orange.svg?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/17/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2-6DB33F.svg?style=flat-square&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Vue](https://img.shields.io/badge/Vue-3.4-4FC08D.svg?style=flat-square&logo=vuedotjs&logoColor=white)](https://vuejs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.2-646CFF.svg?style=flat-square&logo=vite&logoColor=white)](https://vitejs.dev/)

[![Tests](https://img.shields.io/badge/Unit%20Tests-63%2F63%20passing-success.svg?style=flat-square)](#安全测试--security-testing)
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-2021%20covered-success.svg?style=flat-square)](#覆盖的-owasp-top-10-类别--owasp-coverage)
[![Detection](https://img.shields.io/badge/Avg%20Latency-0.93ms-brightgreen.svg?style=flat-square)](#测试结果--test-results)
[![High Risk](https://img.shields.io/badge/CVSS%20%E2%89%A57.0-18%2F18%20protected-success.svg?style=flat-square)](#测试结果--test-results)
[![Report](https://img.shields.io/badge/Report-57%20pages%20LaTeX-B45309.svg?style=flat-square&logo=latex&logoColor=white)](report/AEGIS-综合设计报告.pdf)

[简体中文](#简体中文) · [English](#english)

</div>

---

<a name="简体中文"></a>

## 简体中文

### 一句话说明

传统 WAF 用正则黑名单匹配攻击特征串，本质是在**猜**一段文本像不像攻击，因而长期陷于"新绕过手法出现 → 补规则 → 再被绕过"的被动循环。

AEGIS 换一个维度解决问题：把 SQL 解析成**抽象语法树（AST）**，剥离全部字面量后计算**结构指纹**，与该接口的合法基线比对。攻击者无论使用何种编码、注释、大小写混淆，只要他**改变了 SQL 的语义结构**，AST 就必然变形，指纹就必然失配。

> **问**：正则规则不是很容易被绕过吗？
> **答**：我根本不用正则。攻击者可以混淆文本，但无法在不改变语法树的前提下改变 SQL 的语义——而改变语义正是注入攻击的目的本身。

### 核心创新

#### 1. SQL 抽象语法树结构指纹

自研词法分析器与递归下降语法分析器，将 SQL 解析为语法树后执行**字面量归一化**与**规范化序列化**，得到仅反映语义结构的定长指纹。该指纹具有三条关键性质：

| 性质 | 含义 |
|---|---|
| **参数无关** | 同一模板不同参数取值 → 指纹相同 |
| **形态无关** | 大小写、空白、注释拆分、内联注释 → 指纹相同 |
| **结构敏感** | 任何语法结构的改变 → 指纹必然不同 |

#### 2. 网关 + RASP 探针双层联动架构 ⭐

这是本项目技术格调的来源。

| | 网关层 | RASP 探针层 |
|---|---|---|
| 位置 | HTTP 流量入口 | 应用进程内部（字节码注入） |
| 可见对象 | HTTP 参数文本 | **拼接完成的真实 SQL** |
| 判定性质 | 启发式预判 | **确定性结构比对** |

网关只能看到参数，对"这个参数是否会造成注入"永远只能猜；RASP 探针钩住 JDBC 执行点，拿到的是即将送入数据库的真实语句，此时做 AST 比对是确定性证明。两层通过 **TraceID** 关联，可还原完整攻击证据链：

```
HTTP 请求 → 被污染的参数 → 生成的真实 SQL → AST 结构变异 → 处置结果
```

#### 3. 无正则的 XSS 语义净化

将内容按 HTML 规范解析为 DOM 树，依据"标签 → 属性 → 协议"三级白名单逐节点裁决。白名单机制保证：即使出现未知的新型绕过手法，只要它依赖白名单之外的标签或属性，就自动失效。

#### 4. 攻防对抗实时可视化

将结构差分结果渲染为可视化语法树，注入产生的变异子树高亮为红色并带脉冲光晕，配合完整的取证信息（判定依据、指纹对照、证据链、SQL 语法高亮）。

### 系统架构

```
┌────────────────────────────────────────────────────────────┐
│              aegis-web  ·  Vue 3 指挥中心 (5173)            │
│   态势总览 · 威胁事件 · AST 语义分析 · 基线管理 · 攻防演练      │
└───────────────────────┬────────────────────────────────────┘
                        │  REST + WebSocket
┌───────────────────────┴────────────────────────────────────┐
│           aegis-console  ·  控制台服务 (8080)                │
│   事件汇聚 · 哈希链审计 · 基线管理 · 统计聚合 · 实时推送        │
└──────┬──────────────────────────────────┬──────────────────┘
       │ 事件上报                          │ 事件上报
┌──────┴───────────────┐        ┌─────────┴──────────────────┐
│ aegis-gateway (8000) │ 反向代理 │   vuln-target  靶场 (8090)  │
│ 参数检测 · 限流       │───────►│  ┌──────────────────────┐  │
│ IP 信誉 · TraceID    │        │  │ aegis-agent RASP 探针 │  │
└──────┬───────────────┘        │  │ 钩取 JDBC / 命令执行   │  │
       │                        │  └──────────┬───────────┘  │
       └────────────┬───────────┴─────────────┘              │
                    ▼                                         │
        ┌───────────────────────────┐                        │
        │  aegis-core  检测引擎内核   │◄───────────────────────┘
        │  词法 · 语法 · 指纹 · 差分  │
        │  风险特征 · XSS · 限流      │
        └───────────────────────────┘
```

#### 模块说明

| 模块 | 说明 |
|---|---|
| `aegis-core` | 检测引擎内核。自研 SQL 词法/语法分析器、AST 指纹、结构差分、风险特征、XSS 语义净化、限流与 IP 信誉 |
| `aegis-agent` | RASP 探针。基于 ByteBuddy 字节码注入，钩取 JDBC 与命令执行 |
| `aegis-gateway` | 安全网关。反向代理 + 参数检测 + 限流 + TraceID 注入 |
| `aegis-console` | 控制台服务。事件汇聚、哈希链审计、基线管理、统计与实时推送 |
| `vuln-target` | 受控靶场。每个漏洞提供 `vuln`（脆弱）与 `safe`（安全）两份实现 |
| `aegis-web` | 前端指挥中心。Vue 3 + ECharts + AntV G6 |

### 快速开始

#### 环境要求

- JDK 17+
- Node.js 18+
- Maven 3.9+

#### 构建

```bash
git clone https://github.com/tudu1223/aegis-waf.git
cd aegis-waf
mvn install -DskipTests
cd aegis-web && npm install && cd ..
```

#### 启动

三个后端服务需按顺序启动（控制台 → 靶场 → 网关），**建议在独立终端窗口中分别执行**：

```bash
# 1. 控制台 (8080)
./run-service.sh console

# 2. 靶场 + RASP 探针 (8090)
./run-service.sh target dev BLOCK

# 3. 安全网关 (8000)
./run-service.sh gateway

# 4. 前端 (5173)
cd aegis-web && npm run dev
```

打开 <http://localhost:5173> 进入指挥中心。

> **注意**：Windows 的 Git Bash 下 `nohup` 启动的进程会随 shell 退出而终止，
> 因此需要独立终端窗口，或直接在 IDE 中运行各模块的 `main` 方法。

#### 端口说明

| 端口 | 服务 | 用途 |
|---|---|---|
| 5173 | 前端 | 指挥中心界面 |
| 8080 | 控制台 | API 与 WebSocket |
| 8000 | 网关 | **演示时访问此端口**（经防护） |
| 8090 | 靶场 | 直连（无网关防护，用于对比） |

#### 演示账户

| 用户名 | 口令 | 角色 |
|---|---|---|
| admin | admin123 | ADMIN |
| alice / bob / carol | password123 | USER |

### 安全测试 · Security Testing

#### 三轮测试法

项目采用"三轮测试法"验证防护的完整性，这也是安全测试报告的核心方法论：

| 轮次 | 配置 | 验证目标 |
|---|---|---|
| 第一轮 | 防护关闭 + 脆弱实现 | 漏洞真实存在 |
| 第二轮 | 防护开启 + 脆弱实现 | AEGIS 能检出并拦截 |
| 第三轮 | 防护关闭 + 安全实现 | 代码层面的修复有效 |

#### 执行

```bash
cd tests
python run_tests.py            # 执行全部三轮
python run_tests.py --round 2  # 仅执行第二轮
```

#### 测试结果 · Test Results

```
用例总数 19 · 漏洞复现 14 · 代码修复有效 19
网关可拦截类：12/12 被 AEGIS 实时拦截
CVSS ≥ 7.0 的高危漏洞：18/18 已获得防护
审计链完整性：✓ 通过
平均检测耗时：0.93 ms
```

单元测试：`mvn -pl aegis-core test` —— **63/63 通过**

#### 覆盖的 OWASP Top 10 类别 · OWASP Coverage

| 类别 | 用例 |
|---|---|
| A01 访问控制失效 | 水平越权、垂直越权、路径穿越 |
| A02 加密机制失效 | 口令弱存储（无盐 MD5） |
| A03 注入 | SQL 注入 ×7、XSS ×3、命令注入 |
| A04 不安全设计 | 无限制暴力破解 |
| A05 安全配置错误 | 详细报错信息泄露 |
| A07 认证失败 | JWT 算法混淆（alg=none） |
| A10 SSRF | 内网地址探测 |

### 项目结构

```
aegis-waf/
├── aegis-core/         检测引擎内核
│   └── src/main/java/com/aegis/core/
│       ├── sql/lexer/       词法分析器
│       ├── sql/parser/      递归下降语法分析器
│       ├── sql/fingerprint/ 归一化与结构指纹
│       ├── sql/diff/        结构差分定位
│       ├── sql/risk/        风险特征检测
│       ├── sql/visual/      可视化数据导出
│       ├── xss/             DOM 白名单净化
│       ├── path/ cmd/       路径穿越与命令注入
│       ├── limit/           令牌桶 · 滑动窗口 · IP 信誉
│       └── engine/          检测引擎门面
├── aegis-agent/        RASP 探针
├── aegis-gateway/      安全网关
├── aegis-console/      控制台服务
├── vuln-target/        受控靶场
│   └── src/main/java/com/target/
│       ├── vuln/            ⚠ 脆弱实现（教学用）
│       └── safe/            ✓ 安全实现（修复对照）
├── aegis-web/          前端
├── report/             LaTeX 综合设计报告
├── docs/design/        设计文档
└── tests/              安全测试脚本
```

### 设计报告

项目配套一份 57 页的综合设计报告，采用 LaTeX 排版，涵盖威胁建模、
算法的形式化定义与性质证明、系统设计、实验评估与结果分析。

- 成品：[`report/AEGIS-综合设计报告.pdf`](report/AEGIS-综合设计报告.pdf)
- 源码：`report/` 目录

重新编译（需 TeX Live 2023+，含 ctex 与 pgfplots）：

```bash
cd report
./build.sh          # 完整编译（含参考文献）
./build.sh quick    # 快速编译
./build.sh clean    # 清理中间文件
```

### 代码约定

安全相关代码使用统一标记，便于检索与审查：

| 标记 | 含义 |
|---|---|
| `[SEC-xxx-nn]` | 安全防护逻辑 |
| `[VULN-nn]` | 受控漏洞（仅用于教学演示） |
| `[FIX-nn]` | 对应的修复实现 |

#### 高危函数禁用

| 禁用项 | 替代方案 |
|---|---|
| 字符串拼接 SQL | `PreparedStatement` 参数化查询 |
| `Runtime.exec(String)` | `ProcessBuilder(List<String>)` 参数数组化 |
| `ObjectInputStream.readObject` | Jackson JSON + 类型白名单 |
| 无盐 MD5 存储口令 | BCrypt 自适应哈希 |
| 正则过滤 XSS | DOM 解析 + 三级白名单 |

### 技术栈

**后端**　JDK 17 · Spring Boot 3.2 · ByteBuddy · jsoup · Caffeine · H2/MySQL · JJWT
**前端**　Vue 3 · Vite 5 · Pinia · ECharts 5 · AntV G6 · SCSS
**测试**　JUnit 5 · Python（安全测试脚本）

### 已知局限

诚实记录当前实现的边界，也是后续改进的方向：

1. **依赖 SQL 可解析性** —— 遇到极端方言时降级为词法层特征检测
2. **基线依赖学习质量** —— 学习期混入攻击流量会污染基线，故需人工审核确认
3. **二阶注入** —— 可检出触发时刻的结构异常，但无法溯源到最初的写入请求
4. **业务逻辑漏洞** —— 越权、SSRF 等缺少后端上下文，网关层无法判定，需由代码层面防护
5. **加密流量** —— 网关需作为 TLS 终止点才能检测

### 合规与伦理声明

本项目所有攻击测试**均在本地隔离环境**中针对**自建靶场系统**执行，未对任何第三方系统进行未授权测试。

靶场中的漏洞代码为教学目的**主动构造**，集中隔离于 `vuln` 包并全部加注警示注释，不会随生产构建发布。反序列化类测试用例采用无害化载荷，不包含任何具备实际破坏能力的 gadget 链。

本项目严格遵守《中华人民共和国网络安全法》《数据安全法》及相关法律法规，所有技术成果仅用于**安全防护研究与教学实践**。

---

<a name="english"></a>

## English

### TL;DR

Traditional WAFs match attack signatures with regex blacklists — essentially *guessing* whether a piece of text looks like an attack. This traps them in an endless cycle: a new evasion technique appears, a rule is patched, then it gets bypassed again.

AEGIS solves the problem from a different angle: it parses SQL into an **Abstract Syntax Tree (AST)**, strips all literals, computes a **structural fingerprint**, and compares it against the endpoint's legitimate baseline. No matter what encoding, comments, or case obfuscation an attacker uses, if they **change the semantic structure of the SQL**, the AST necessarily deforms and the fingerprint necessarily mismatches.

> **Q**: Aren't regex rules easy to bypass?
> **A**: I don't use regex at all. An attacker can obfuscate text, but cannot change SQL semantics without changing the syntax tree — and changing semantics is precisely the goal of an injection attack.

### Key Innovations

#### 1. SQL AST Structural Fingerprinting

A hand-written lexer and recursive-descent parser build the syntax tree, then **literal normalization** and **canonical serialization** produce a fixed-length fingerprint that reflects only semantic structure. The fingerprint has three critical properties:

| Property | Meaning |
|---|---|
| **Parameter-invariant** | Same template, different values → identical fingerprint |
| **Form-invariant** | Case, whitespace, split comments, inline comments → identical fingerprint |
| **Structure-sensitive** | Any syntactic change → guaranteed different fingerprint |

#### 2. Gateway + RASP Dual-Layer Architecture ⭐

This is where the project's technical depth comes from.

| | Gateway Layer | RASP Agent Layer |
|---|---|---|
| Location | HTTP ingress | Inside the app process (bytecode injection) |
| Visibility | HTTP parameter text | **The fully-assembled, real SQL** |
| Verdict nature | Heuristic pre-judgment | **Deterministic structural comparison** |

The gateway only sees parameters — it can never do more than guess whether a parameter will cause injection. The RASP agent hooks the JDBC execution point and obtains the actual statement about to reach the database; AST comparison there is a deterministic proof. The two layers are correlated by **TraceID**, reconstructing the full attack evidence chain:

```
HTTP request → tainted parameter → generated SQL → AST mutation → verdict
```

#### 3. Regex-Free XSS Semantic Sanitization

Content is parsed into a DOM tree per the HTML specification, then adjudicated node by node against a three-tier whitelist (tag → attribute → protocol). The whitelist guarantees that even unknown novel evasion techniques fail automatically, as long as they rely on tags or attributes outside the allowed set.

#### 4. Real-Time Attack/Defense Visualization

Structural diff results are rendered as an interactive syntax tree. Mutated subtrees introduced by injection are highlighted in red with a pulsing glow, accompanied by complete forensic details (evidence, fingerprint comparison, evidence chain, SQL syntax highlighting).

### Architecture

See the diagram in the [Chinese section](#系统架构). Module responsibilities:

| Module | Description |
|---|---|
| `aegis-core` | Detection engine. Hand-written SQL lexer/parser, AST fingerprinting, structural diff, risk features, XSS sanitization, rate limiting, IP reputation |
| `aegis-agent` | RASP agent. ByteBuddy bytecode injection hooking JDBC and command execution |
| `aegis-gateway` | Security gateway. Reverse proxy + parameter detection + rate limiting + TraceID injection |
| `aegis-console` | Console service. Event aggregation, hash-chain audit, baseline management, statistics, real-time push |
| `vuln-target` | Controlled range. Each vulnerability ships both `vuln` (vulnerable) and `safe` (patched) implementations |
| `aegis-web` | Frontend command center. Vue 3 + ECharts + AntV G6 |

### Quick Start

**Requirements**: JDK 17+, Node.js 18+, Maven 3.9+

```bash
git clone https://github.com/tudu1223/aegis-waf.git
cd aegis-waf
mvn install -DskipTests
cd aegis-web && npm install && cd ..

# Start in separate terminal windows, in this order:
./run-service.sh console              # Console  (8080)
./run-service.sh target dev BLOCK     # Range + RASP agent (8090)
./run-service.sh gateway              # Gateway  (8000)
cd aegis-web && npm run dev           # Frontend (5173)
```

Open <http://localhost:5173>.

| Port | Service | Purpose |
|---|---|---|
| 5173 | Frontend | Command center UI |
| 8080 | Console | API and WebSocket |
| 8000 | Gateway | **Use this port for demos** (protected) |
| 8090 | Range | Direct access (unprotected, for comparison) |

**Demo accounts**: `admin / admin123` (ADMIN), `alice / password123` (USER)

### Security Testing

#### Three-Round Methodology

| Round | Configuration | Goal |
|---|---|---|
| 1 | Protection OFF + vulnerable impl | Confirm the vulnerability is real |
| 2 | Protection ON + vulnerable impl | Confirm AEGIS detects and blocks |
| 3 | Protection OFF + patched impl | Confirm the code-level fix works |

```bash
cd tests
python run_tests.py            # All three rounds
python run_tests.py --round 2  # Round 2 only
```

#### Results

```
19 test cases · 14 vulnerabilities reproduced · 19 code fixes verified
Gateway-blockable: 12/12 intercepted in real time
CVSS >= 7.0 high-risk: 18/18 protected
Audit chain integrity: PASS
Average detection latency: 0.93 ms
```

Unit tests: `mvn -pl aegis-core test` — **63/63 passing**

#### OWASP Top 10 (2021) Coverage

| Category | Cases |
|---|---|
| A01 Broken Access Control | Horizontal/vertical privilege escalation, path traversal |
| A02 Cryptographic Failures | Weak password storage (unsalted MD5) |
| A03 Injection | SQL injection ×7, XSS ×3, command injection |
| A04 Insecure Design | Unlimited brute force |
| A05 Security Misconfiguration | Verbose error disclosure |
| A07 Identification & Auth Failures | JWT algorithm confusion (alg=none) |
| A10 SSRF | Internal network probing |

### Tech Stack

**Backend** JDK 17 · Spring Boot 3.2 · ByteBuddy · jsoup · Caffeine · H2/MySQL · JJWT
**Frontend** Vue 3 · Vite 5 · Pinia · ECharts 5 · AntV G6 · SCSS
**Testing** JUnit 5 · Python

### Design Report

A 57-page comprehensive design report typeset in LaTeX accompanies this project,
covering threat modeling, formal definitions and property proofs of the
fingerprinting algorithm, system design, and experimental evaluation.

- PDF: [`report/AEGIS-综合设计报告.pdf`](report/AEGIS-综合设计报告.pdf)
- Source: `report/` directory

To rebuild (requires TeX Live 2023+ with ctex and pgfplots):

```bash
cd report
./build.sh          # Full build including bibliography
./build.sh quick    # Quick build
./build.sh clean    # Remove intermediates
```

### Known Limitations

Documented honestly — these are also the roadmap:

1. **Depends on SQL parsability** — falls back to lexical feature detection for exotic dialects
2. **Baseline quality matters** — attack traffic during the learning window can poison the baseline, hence mandatory human review
3. **Second-order injection** — detects structural anomalies at trigger time, but cannot trace back to the original write request
4. **Business-logic flaws** — privilege escalation, SSRF, etc. lack backend context and cannot be judged at the gateway; they require code-level defense
5. **Encrypted traffic** — the gateway must act as a TLS termination point

### Ethics & Compliance

All attack testing in this project is performed **exclusively in an isolated local environment** against a **self-built target range**. No unauthorized testing has been conducted against any third-party system.

Vulnerable code in the range is **deliberately constructed for educational purposes**, isolated within the `vuln` package with explicit warning comments, and is never shipped in production builds. Deserialization test cases use harmless payloads containing no gadget chains with real destructive capability.

This project complies with the *Cybersecurity Law of the People's Republic of China*, the *Data Security Law*, and related regulations. All technical outcomes are intended solely for **security research and educational practice**.

---

<div align="center">

**AEGIS** · Built as a comprehensive systems-security capstone project

Licensed under the [MIT License](LICENSE)

</div>
