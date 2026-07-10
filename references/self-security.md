# 自身安全工程细节 (J1–J5)

> 本技能的核心卖点: 检测工具本身**不泄漏数据**。本文档详述如何工程化保证这一点,
> 供用户审计与贡献者遵循。

## J1 纯本地无外联(双重保证)

### 静态层:`selfcheck.py`

扫描 `scripts/` 目录所有 `.py` 文件,grep 网络/外联符号:
`import socket` / `urllib` / `requests` / `http.client` / `curl` / `wget` / `https?://` / `eval` 等。

**白名单(三文件,各自理由)**:
- `verify_registry.py`: 唯一受控外联模块(真实联网,但默认关闭,只连官方 registry,不携带本地数据)
- `selfcheck.py`: 静态扫描器(网络符号仅作检测模式数据,非执行代码)
- `check.py`: 主入口(`import socket` 仅用于 monkeypatch 挂载守卫)

其余文件(engine/*、adapters/*)出现任何网络符号即 FAIL。

运行:`python3 scripts/check.py --self-check`(静态部分)。

### 运行时层:`check.py` socket 守卫

```python
class _GuardedSocket(socket.socket):
    def connect(self, address, *args, **kwargs):
        raise OutboundBlockedError("backdoor-check 禁止出站连接")
    def connect_ex(self, address, *args, **kwargs):
        raise OutboundBlockedError(...)

if not os.environ.get("BACKDOOR_CHECK_OUTBOUND"):
    socket.socket = _GuardedSocket
    socket.create_connection = _guard_create_connection
```

启动即 monkeypatch `socket.socket` 为守卫。任何模块(含 engine/adapters,甚至未来贡献者误加的网络调用)尝试建连都会抛 `OutboundBlockedError`。

**这是静态层的兜底**:即使静态扫描漏检,运行时也拦死。`--self-check` 实测验证(尝试 connect 1.1.1.1:80,预期被拦)。

### 受控外联边界:`verify_registry.py`

唯一例外。由 `check.py --verify-registry` 经**隔离子进程**调用:
- 主进程守卫不变;子进程设 `BACKDOOR_CHECK_OUTBOUND=1` 解除守卫
- 子进程只连接 `registry.npmjs.org`(硬编码白名单 + TLS 证书校验 `ssl.CERT_REQUIRED`)
- 只发 GET 拉 manifest,不携带任何本地数据/凭证
- User-Agent 不含本机标识:`backdoor-check/verify-registry (no local data)`
- 全程输出到本地 stdout

```python
# check.py 中隔离子进程调用
env["BACKDOOR_CHECK_OUTBOUND"] = "1"
subprocess.run([sys.executable, "verify_registry.py", "--package", ...], env=env)
```

---

## J2 脱敏(`report.redact`)

中心化脱敏,所有写入报告/日志的字符串必经 `redact()`。

**敏感模式**(命中即替换):
- 私钥头 `-----BEGIN ...-----`
- Bearer token
- Anthropic 风格 token(hex.随机串,如 `9433a9ac....MEQn`)
- OpenAI/通用 `sk-` 前缀
- key/value 形式(`api_key: xxx` / `TOKEN=xxx`)
- 超长 hex(≥40)/ base64(≥40)

**占位符**:`<redacted:len=N:hash=sha256前8位>`
- 保留长度与 sha256 前 8 位指纹
- 用户可自行比对是否同一凭证,**而不暴露原文**
- 宁可误脱敏(把长串当密钥),不可漏脱敏

**验证**:`--self-check` 展示脱敏样例:
```
原始: ANTHROPIC_AUTH_TOKEN="9433a9ac....MEQn" sk-proj-abc
脱敏: ANTHROPIC_AUTH_TOKEN="<redacted:len=31:hash=63b203b9>" sk-proj-abc
```

---

## J3 不外传

- 报告仅写本地 stdout 或 `--out <path>`
- `--verify-registry` 是唯一外联,且只读不写本地数据出站
- 技能零遥测:不上报使用情况、不上报检测结果

---

## J4 可审计

- 全脚本纯 Python 可读,无混淆、无编译 blob
- `--audit` 干跑:monkeypatch `platform.run` 为打印函数,打印所有将执行的系统命令及理由,不实际执行
- 本文档逐条解释每个机制读什么、不写什么
- `engine/platform.py` 集中所有系统命令调用,便于审计

---

## J5 本地输出

- `baseline.json`(完整性基线)、报告、watch 日志(后续)均留本地
- 技能自身不产生任何出站流量(除 opt-in 的 verify-registry)

---

## stdlib-only 约束

零第三方依赖,避免引入新供应链风险(与检测供应链攻击的目标一致):
- 无 `psutil`(用 `ps` / `/proc` shell out)
- 无 `PyYAML`(规则库用 JSON)
- 无 `requests`(verify_registry 用 `urllib.request`)
- 无 TLS 解密(不拦截 HTTPS 内容,只看连接目标)

代价:JSON 规则库无注释(靠文件内 `note` 字段 + README 说明);可读性略低但安全性更高。
