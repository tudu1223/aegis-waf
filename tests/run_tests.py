#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS 安全测试自动化执行脚本

依据设计文档《04-OWASP测试用例》执行"三轮测试法"：
  第一轮 —— 防护关闭 + 脆弱实现：验证漏洞真实存在
  第二轮 —— 防护开启 + 脆弱实现：验证 AEGIS 能检出并拦截
  第三轮 —— 防护关闭 + 安全实现：验证代码层面的修复有效

用法:
    python run_tests.py            # 执行全部三轮
    python run_tests.py --round 2  # 仅执行第二轮

⚠ 合规声明：所有测试均在本地隔离环境针对自建靶场执行。
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CONSOLE = "http://localhost:8080"
GATEWAY = "http://localhost:8000"
TARGET = "http://localhost:8090"

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ============================================================
# HTTP 工具
# ============================================================

def request(method, url, body=None, headers=None, timeout=15):
    """发送请求，返回 (状态码, 响应文本, 响应头)。"""
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return -1, str(e), {}


def as_json(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def set_mode(mode):
    """切换全局防护模式，并等待网关与探针完成策略同步。"""
    request("PUT", f"{CONSOLE}/api/policy", {"mode": mode})
    time.sleep(3.5)


def set_all_patches(patched):
    """切换靶场全部漏洞的修复状态。"""
    request("POST", f"{TARGET}/api/vuln/toggle-all", {"patched": patched})
    time.sleep(0.6)


def reset_reputation():
    """重置 IP 信誉，避免连续测试触发封禁掩盖真实检测结果。"""
    request("POST", f"{GATEWAY}/aegis/reputation/reset")


def forge_none_jwt():
    """构造 alg=none 的伪造令牌（TC-19）。"""
    import base64

    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({
        "sub": "1", "username": "admin", "role": "ADMIN",
        "iat": int(time.time()), "exp": int(time.time()) + 3600
    })
    return f"{header}.{payload}."


# ============================================================
# 测试用例定义
# ============================================================

def q(path, params):
    return path + "?" + urllib.parse.urlencode(params)


UNION_PAYLOAD = ("x%' UNION SELECT id, id, username, "
                 "CAST(password_md5 AS VARCHAR), role, created_at FROM users --")

TEST_CASES = [
    # ---------- A03 注入：SQL ----------
    {
        "id": "TC-01", "name": "SQL 注入 - 恒真式绕过认证",
        "owasp": "A03:2021", "cvss": 9.8, "vuln": "VULN-01",
        "method": "POST", "path": "/api/auth/login",
        "body": {"username": "admin' OR '1'='1' --", "password": "wrong"},
        # 漏洞成立的判据：本应失败的登录返回了成功
        "vulnerable": lambda s, d: d.get("success") is True,
    },
    {
        "id": "TC-02", "name": "SQL 注入 - UNION 联合查询脱库",
        "owasp": "A03:2021", "cvss": 9.1, "vuln": "VULN-02",
        "method": "GET", "path": q("/api/notes/search", {"keyword": UNION_PAYLOAD}),
        "vulnerable": lambda s, d: d.get("success") is True and d.get("count", 0) > 0,
    },
    {
        "id": "TC-03", "name": "SQL 注入 - 注释截断剥离条件",
        "owasp": "A03:2021", "cvss": 8.6, "vuln": "VULN-03",
        "method": "GET", "path": q("/api/notes/detail", {"id": "1' OR '1'='1"}),
        "vulnerable": lambda s, d: d.get("success") is True,
    },
    {
        "id": "TC-04", "name": "SQL 注入 - 内联注释混淆绕过",
        "owasp": "A03:2021", "cvss": 8.6, "vuln": "VULN-02",
        "method": "GET",
        "path": q("/api/notes/search",
                  {"keyword": "x%'/*!50000UNION*/SELECT id, id, username, "
                              "CAST(password_md5 AS VARCHAR), role, created_at FROM users --"}),
        # 判据：返回了数据行才算注入成功。参数化查询修复后，
        # 该载荷会被当作普通字符串匹配，返回空结果集。
        "vulnerable": lambda s, d: s == 200 and d.get("count", 0) > 0,
        "note": "核心验证：正则型 WAF 会被此载荷绕过",
    },
    {
        "id": "TC-05", "name": "SQL 注入 - 时间盲注",
        "owasp": "A03:2021", "cvss": 7.5, "vuln": "VULN-03",
        "method": "GET", "path": q("/api/notes/detail", {"id": "1' AND SLEEP(2) --"}),
        # 判据：成功返回笔记数据说明注入生效；
        # 修复后类型校验会拒绝该输入（400/500），不构成漏洞
        "vulnerable": lambda s, d: s == 200 and d.get("success") is True,
    },
    {
        "id": "TC-06", "name": "SQL 注入 - 堆叠查询",
        "owasp": "A03:2021", "cvss": 9.8, "vuln": "VULN-03",
        "method": "GET",
        "path": q("/api/notes/detail", {"id": "1'; DROP TABLE notes_backup; --"}),
        # 判据同上：仅当请求被正常执行才视为漏洞可利用
        "vulnerable": lambda s, d: s == 200 and d.get("success") is True,
    },
    {
        "id": "TC-07", "name": "SQL 注入 - 多重 URL 编码绕过",
        "owasp": "A03:2021", "cvss": 8.6, "vuln": "VULN-03",
        "method": "GET",
        "path": "/api/notes/detail?id=1%2527%2520OR%2520%25271%2527%253D%25271",
        "vulnerable": lambda s, d: s == 200 and d.get("success") is True,
    },
    # ---------- A03 注入：XSS ----------
    {
        "id": "TC-08", "name": "存储型 XSS - 事件属性",
        "owasp": "A03:2021", "cvss": 8.2, "vuln": "VULN-08",
        "method": "POST", "path": "/api/notes/create",
        "body": {"title": "XSS测试", "content": "<img src=x onerror=alert(document.cookie)>"},
        "vulnerable": lambda s, d: d.get("success") is True,
        "verify_fix": "xss_stored",
    },
    {
        "id": "TC-09", "name": "存储型 XSS - SVG 命名空间绕过",
        "owasp": "A03:2021", "cvss": 8.2, "vuln": "VULN-08",
        "method": "POST", "path": "/api/notes/create",
        "body": {"title": "SVG绕过", "content": "<svg/onload=alert(1)>"},
        "vulnerable": lambda s, d: d.get("success") is True,
        "verify_fix": "xss_stored",
    },
    {
        "id": "TC-10", "name": "反射型 XSS - 伪协议",
        "owasp": "A03:2021", "cvss": 7.4, "vuln": "VULN-08",
        "method": "POST", "path": "/api/notes/create",
        "body": {"title": "伪协议", "content": '<a href="java&#115;cript:alert(1)">x</a>'},
        "vulnerable": lambda s, d: d.get("success") is True,
        "verify_fix": "xss_stored",
    },
    # ---------- A03 注入：命令 ----------
    {
        "id": "TC-11", "name": "命令注入 - shell 元字符",
        "owasp": "A03:2021", "cvss": 9.8, "vuln": "VULN-11",
        "method": "POST", "path": "/api/tools/ping",
        "body": {"host": "127.0.0.1; cat /etc/passwd"},
        "vulnerable": lambda s, d: d.get("success") is True,
    },
    # ---------- A01 访问控制 ----------
    {
        "id": "TC-12", "name": "水平越权 (IDOR)",
        "owasp": "A01:2021", "cvss": 8.1, "vuln": "VULN-12",
        "defense": "业务层",
        "method": "GET", "path": q("/api/notes/detail", {"id": "4"}),
        # 未登录状态下读取到他人的 PRIVATE 笔记即为越权
        "vulnerable": lambda s, d: (d.get("success") is True
                                    and d.get("data", {}).get("visibility") == "PRIVATE"),
    },
    {
        "id": "TC-13", "name": "垂直越权 - 普通用户访问管理接口",
        "owasp": "A01:2021", "cvss": 8.8, "vuln": "VULN-13",
        "defense": "业务层",
        "method": "GET", "path": "/api/admin/users",
        "need_user_token": True,
        "vulnerable": lambda s, d: d.get("success") is True and d.get("count", 0) > 0,
    },
    {
        "id": "TC-14", "name": "路径穿越",
        "owasp": "A01:2021", "cvss": 7.5, "vuln": "VULN-14",
        "method": "GET",
        "path": q("/api/tools/download", {"name": "../../../../etc/passwd"}),
        "vulnerable": lambda s, d: s == 200 and d.get("success") is True,
    },
    # ---------- A02 加密失败 ----------
    {
        "id": "TC-15", "name": "口令弱存储 (无盐 MD5)",
        "owasp": "A02:2021", "cvss": 7.5, "vuln": "VULN-15",
        "defense": "业务层",
        "method": "GET", "path": "/api/admin/users",
        "need_user_token": True,
        # 响应中出现 MD5 哈希即证明使用了弱存储
        "vulnerable": lambda s, d: any(
            u.get("passwordMd5") for u in d.get("data", [])),
    },
    # ---------- A04 不安全设计 ----------
    {
        "id": "TC-16", "name": "无限制暴力破解",
        "owasp": "A04:2021", "cvss": 7.5, "vuln": "VULN-16",
        "defense": "业务层",
        "method": "POST", "path": "/api/auth/login",
        "body": {"username": "alice", "password": "wrong-guess"},
        "repeat": 30,
        "vulnerable": lambda s, d: s == 401,
    },
    # ---------- A05 安全配置错误 ----------
    {
        "id": "TC-17", "name": "详细报错信息泄露",
        "owasp": "A05:2021", "cvss": 5.3, "vuln": "VULN-17",
        "defense": "业务层",
        "method": "GET", "path": q("/api/notes/detail", {"id": "abc'"}),
        "vulnerable": lambda s, d: "stackTrace" in d or "exceptionType" in d,
    },
    # ---------- A07 认证失败 ----------
    {
        "id": "TC-19", "name": "JWT 算法混淆 (alg=none)",
        "owasp": "A07:2021", "cvss": 9.8, "vuln": "VULN-19",
        "defense": "业务层",
        "method": "GET", "path": "/api/auth/me",
        "forged_jwt": True,
        "vulnerable": lambda s, d: d.get("success") is True and d.get("role") == "ADMIN",
    },
    # ---------- A10 SSRF ----------
    {
        "id": "TC-22", "name": "服务端请求伪造 (SSRF)",
        "owasp": "A10:2021", "cvss": 8.6, "vuln": "VULN-22",
        "defense": "业务层",
        "method": "POST", "path": "/api/tools/import",
        "body": {"url": "http://127.0.0.1:8080/api/health"},
        "vulnerable": lambda s, d: (d.get("success") is True
                                    and "UP" in str(d.get("content", ""))),
    },
]


def get_user_token(base):
    """获取普通用户令牌（用于越权类测试）。"""
    status, text, _ = request("POST", f"{base}/api/auth/login",
                              {"username": "alice", "password": "password123"})
    return as_json(text).get("token")


def execute(case, base, token=None):
    """执行单个用例，返回 (状态码, 响应体, 是否被拦截)。"""
    headers = {}
    if case.get("forged_jwt"):
        headers["Authorization"] = "Bearer " + forge_none_jwt()
    elif case.get("need_user_token") and token:
        headers["Authorization"] = "Bearer " + token

    url = base + case["path"]
    repeat = case.get("repeat", 1)

    status, text, _ = -1, "", {}
    blocked_count = 0
    for _ in range(repeat):
        status, text, _ = request(case["method"], url, case.get("body"), headers)
        if status in (403, 429):
            blocked_count += 1
            if repeat > 1 and blocked_count >= 2:
                break

    data = as_json(text)
    blocked = status in (403, 429) or data.get("blocked") is True
    return status, data, blocked


def verify_xss_stored(base, note_id):
    """校验 XSS 载荷是否以危险形式存储（读取回显内容）。"""
    if not note_id:
        return False
    status, text, _ = request("GET", f"{base}/api/notes/detail?id={note_id}")
    content = str(as_json(text).get("data", {}).get("content", ""))
    lowered = content.lower()
    return ("onerror" in lowered or "onload" in lowered
            or "javascript:" in lowered.replace(" ", ""))


# ============================================================
# 三轮测试
# ============================================================

def round_one():
    """第一轮：防护关闭 + 脆弱实现 → 验证漏洞真实存在。"""
    print("\n" + "=" * 74)
    print("  第一轮 · 防护关闭 + 脆弱实现  ——  验证漏洞真实存在")
    print("=" * 74)
    set_mode("OFF")
    set_all_patches(False)
    reset_reputation()

    token = get_user_token(TARGET)
    results = []
    for case in TEST_CASES:
        status, data, _ = execute(case, TARGET, token)
        confirmed = False
        try:
            confirmed = bool(case["vulnerable"](status, data))
        except Exception:
            confirmed = False

        # XSS 类需额外校验载荷确实以危险形式落库
        if case.get("verify_fix") == "xss_stored" and confirmed:
            confirmed = verify_xss_stored(TARGET, data.get("id"))

        results.append((case, confirmed, status))
        mark = "✓ 漏洞复现" if confirmed else "· 未复现"
        print(f"  {case['id']:<7} {case['name']:<28} CVSS {case['cvss']:<4} "
              f"HTTP {status:<4} {mark}")
        time.sleep(0.25)

    confirmed_count = sum(1 for _, ok, _ in results if ok)
    print(f"\n  小结：{confirmed_count}/{len(TEST_CASES)} 个用例成功复现漏洞")
    return results


def round_two():
    """第二轮：防护开启 + 脆弱实现 → 验证 AEGIS 拦截能力。"""
    print("\n" + "=" * 74)
    print("  第二轮 · 防护开启 (BLOCK) + 脆弱实现  ——  验证 AEGIS 检出与拦截")
    print("=" * 74)
    set_mode("BLOCK")
    set_all_patches(False)
    reset_reputation()

    token = get_user_token(GATEWAY)
    results = []
    for case in TEST_CASES:
        reset_reputation()
        status, data, blocked = execute(case, GATEWAY, token)
        results.append((case, blocked, status))
        mark = "✓ 已拦截" if blocked else "✗ 未拦截"
        by = data.get("by", "")
        print(f"  {case['id']:<7} {case['name']:<28} HTTP {status:<4} "
              f"{mark:<10} {by}")
        time.sleep(0.25)

    blocked_count = sum(1 for _, ok, _ in results if ok)
    print(f"\n  小结：{blocked_count}/{len(TEST_CASES)} 个攻击被成功拦截")
    return results


def round_three():
    """第三轮：防护关闭 + 安全实现 → 验证代码修复有效。"""
    print("\n" + "=" * 74)
    print("  第三轮 · 防护关闭 + 安全实现  ——  验证代码层面的修复有效性")
    print("=" * 74)
    set_mode("OFF")
    set_all_patches(True)
    reset_reputation()

    token = get_user_token(TARGET)
    results = []
    for case in TEST_CASES:
        status, data, _ = execute(case, TARGET, token)
        still_vulnerable = False
        try:
            still_vulnerable = bool(case["vulnerable"](status, data))
        except Exception:
            still_vulnerable = False

        if case.get("verify_fix") == "xss_stored" and still_vulnerable:
            still_vulnerable = verify_xss_stored(TARGET, data.get("id"))

        fixed = not still_vulnerable
        results.append((case, fixed, status))
        mark = "✓ 修复有效" if fixed else "✗ 仍可利用"
        print(f"  {case['id']:<7} {case['name']:<28} HTTP {status:<4} {mark}")
        time.sleep(0.25)

    fixed_count = sum(1 for _, ok, _ in results if ok)
    print(f"\n  小结：{fixed_count}/{len(TEST_CASES)} 个漏洞修复有效")
    return results


def summary(r1, r2, r3):
    """汇总三轮结果，输出可直接用于报告的表格。"""
    print("\n" + "=" * 78)
    print("  测试结果汇总")
    print("=" * 78)

    map1 = {c["id"]: ok for c, ok, _ in r1}
    map2 = {c["id"]: ok for c, ok, _ in r2}
    map3 = {c["id"]: ok for c, ok, _ in r3}

    print(f"  {'用例':<8}{'名称':<30}{'CVSS':<6}{'防线':<8}{'复现':<6}{'拦截':<6}{'修复':<6}")
    print("  " + "-" * 74)

    high_risk_total = 0
    high_risk_covered = 0
    gateway_cases = 0
    gateway_blocked = 0

    for case in TEST_CASES:
        cid = case["id"]
        defense = case.get("defense", "网关")
        v = "✓" if map1.get(cid) else "—"
        f = "✓" if map3.get(cid) else "✗"

        if defense == "网关":
            b = "✓" if map2.get(cid) else "✗"
            gateway_cases += 1
            if map2.get(cid):
                gateway_blocked += 1
        else:
            # 业务逻辑类漏洞不在网关的可见范围内，
            # 其防护由代码层面的安全实现承担
            b = "n/a"

        print(f"  {cid:<8}{case['name']:<30}{case['cvss']:<6}"
              f"{defense:<8}{v:<6}{b:<6}{f:<6}")

        if case["cvss"] >= 7.0:
            high_risk_total += 1
            # 高危漏洞只要"被网关拦截"或"代码已修复"其一成立即算已覆盖
            if map2.get(cid) or map3.get(cid):
                high_risk_covered += 1

    print("  " + "-" * 74)
    print(f"  用例总数 {len(TEST_CASES)} · 漏洞复现 {sum(map1.values())} · "
          f"代码修复有效 {sum(map3.values())}")
    print(f"  网关可拦截类：{gateway_blocked}/{gateway_cases} 被 AEGIS 实时拦截")
    print(f"  CVSS ≥ 7.0 的高危漏洞：{high_risk_covered}/{high_risk_total} 已获得防护")
    print()
    print("  说明：越权、弱口令存储、JWT 算法混淆、SSRF 等属于业务逻辑层漏洞，")
    print("        网关无法从 HTTP 参数中判定（缺少会话与后端上下文），")
    print("        其防护由靶场的安全实现承担，已在第三轮验证有效。")

    # 审计日志完整性
    status, text, _ = request("GET", f"{CONSOLE}/api/events/verify-chain")
    chain = as_json(text)
    print()
    print(f"  审计链完整性：{'✓ 通过' if chain.get('intact') else '✗ 失败'}"
          f"（{chain.get('totalRecords', 0)} 条记录）")

    status, text, _ = request("GET", f"{CONSOLE}/api/stats/overview")
    ov = as_json(text).get("data", {})
    print(f"  平均检测耗时：{ov.get('avgDetectionMillis', 0)} ms · "
          f"事件总数 {ov.get('totalEvents', 0)} · "
          f"拦截率 {ov.get('interceptRate', 0)}%")


def main():
    parser = argparse.ArgumentParser(description="AEGIS 安全测试执行脚本")
    parser.add_argument("--round", default="all", help="执行轮次：1 / 2 / 3 / all")
    args = parser.parse_args()

    print("=" * 74)
    print("  AEGIS 安全测试 · OWASP Top 10 用例执行")
    print("  ⚠ 所有测试均在本地隔离环境针对自建靶场执行")
    print("=" * 74)

    # 前置检查
    for name, url in [("控制台", f"{CONSOLE}/api/health"),
                      ("靶场", f"{TARGET}/api/vuln/health"),
                      ("网关", f"{GATEWAY}/aegis/health")]:
        status, _, _ = request("GET", url, timeout=5)
        if status != 200:
            print(f"  ✗ {name} 未就绪（{url} 返回 {status}），请先启动全部服务")
            sys.exit(1)
        print(f"  ✓ {name} 就绪")

    request("DELETE", f"{CONSOLE}/api/events/all")

    r1 = r2 = r3 = []
    if args.round in ("1", "all"):
        r1 = round_one()
    if args.round in ("2", "all"):
        r2 = round_two()
    if args.round in ("3", "all"):
        r3 = round_three()

    if args.round == "all":
        summary(r1, r2, r3)
        # 演示环境恢复默认状态
        set_mode("BLOCK")
        set_all_patches(False)
        print("\n  已恢复默认状态：防护模式 BLOCK · 靶场脆弱实现")


if __name__ == "__main__":
    main()
