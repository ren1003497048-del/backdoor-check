# 深水区技术参考

> 网络命令跨平台对照 / 二进制静态分析与局限 / 机器标识来源 / 行为级取证指引。
> B/C/A3 维度的底层实现依据。本文档强调**局限**:启发式证据,未发现 ≠ 不存在。

## 一、网络连接采集(B1)

进程网络连接快照,免 root 可读取当前用户进程的连接。

| 平台 | 首选命令 | 兜底 | 说明 |
|------|---------|------|------|
| macOS | `lsof -i -nP [-p PID]` | `nettop -P -L 1 -x`(字节计数) | NAME 列为 `host:port` 或 `IP:port` |
| Linux | `ss -tunp`(显示 PID) | `netstat -tunp` → `/proc/PID/net/tcp` | /proc 纯 stdlib 可读,无命令依赖 |
| Windows | `netstat -ano`(PID 在末列) | `Get-NetTCPConnection -OwningProcess` | — |

**解析**:取五元组(proto/laddr/raddr/rport/state/pid),raddr 反查 host,比对 `endpoints.json` + `allowlist.json`。

**局限**:
- lsof/ss 是**瞬时快照**,抓不到周期性 beacon(固定间隔小包)的完整模式。
- watch 模式(后续迭代)周期采样 + 静态 strings 互补。
- 被动流量捕获(tcpdump/DNS 抓包)需 sudo,deep 模式指引。

## 二、二进制静态分析(A3/C4/B2/B7)

### strings 抽取

| 平台 | 命令 | 降级 |
|------|------|------|
| macOS/Linux | `strings -a <binary>` | 无 strings 时用 Python 抽取可打印 ASCII 串(≥4 字符) |
| Windows | (通常无 strings) | Python 降级实现(`engine/binary._py_strings`) |

本模块用内存缓存(`binary.extract_strings`),同一二进制不重复抽取(237MB 抽取耗时)。

### 符号/方法名(C4 高信号)

| 平台 | 命令 | 价值 |
|------|------|------|
| macOS | `otool -ov <binary>`(ObjC 类名/方法名) | ObjC 常保留方法名,如 `getMachineId`/`collectTelemetry` — 高信号 |
| macOS | `nm <binary>` | 导出符号(若未 strip) |
| Linux | `nm -D <binary>` | 动态符号 |
| Linux | `readelf -d <binary>` | 动态依赖(检测异常加载库) |

### 局限(必须声明)

- 二进制是**编译产物**(如 claude.exe 237MB Mach-O),可能 strip/混淆。
- strings/otool/nm **只命中未混淆部分** → **启发式证据,未发现 ≠ 不存在**。
- 无法读取控制流/逻辑,只能从字符串签名推断"具备能力"。
- 报告须明确此局限,避免给用户虚假安全感。

## 三、机器标识来源全表(C2)

后门收集设备指纹的常见来源(本技能检测二进制是否引用这些):

| 平台 | 标识 | 命令/路径 |
|------|------|----------|
| macOS | IOPlatformUUID / IOPlatformSerialNumber | `ioreg -d2 -c IOPlatformExpertDevice` |
| macOS | 硬件 UUID | `system_profiler SPHardwareDataType` |
| Linux | machine-id | `/etc/machine-id`、`/var/lib/dbus/machine-id` |
| Linux | 产品 UUID | `/sys/devices/virtual/dmi/id/product_uuid` |
| Linux | MAC 地址 | `/sys/class/net/*/address` |
| Windows | MachineGuid | `reg query HKLM\SOFTWARE\Microsoft\Cryptography` |
| Windows | 产品 UUID | `wmic csproduct get UUID` |

`platform.machine_id_sources()` 返回当前平台的命令列表(仅声明,不主动执行外传)。

## 四、地理位置来源(C1)

| 类型 | 平台 | 信号 |
|------|------|------|
| OS 位置 API | macOS | CoreLocation / CLLocationManager |
| OS 位置 API | Linux | GeoClue |
| GeoIP(免 OS 权限,更可能的后门路径) | 全平台 | 外联 ip-api.com / ipinfo.io / maxmind.com |

检测:strings 二进制 grep 上述符号 + B2 观测是否实际外联 GeoIP host。

## 五、行为级取证(deep 模式,需 sudo)

确认是否**实际读取并外传**指纹(而非仅具备能力)。默认不执行,deep 模式给指引。

| 平台 | 工具 | 监控目标 |
|------|------|---------|
| macOS | `sudo dtrace` | `open*`/`getenv`/`connect` syscall,确认 claude 进程读取了机器标识/env 并外联 |
| Linux | `sudo strace -f -e trace=openat,getenv,connect -p PID` | 同上 |
| Windows | ProcMon(Microsoft Sysinternals) | 文件/注册表/网络访问 |

**示例(macOS dtrace 监控 claude 进程的 getenv)**:
```bash
# 找 claude PID
PID=$(pgrep -x claude)
# 监控其调用的 getenv(读取哪些环境变量)
sudo dtrace -n 'syscall::getenv:entry /pid == $PID/ { ustack(); }'
```

**局限**:
- 跨平台差异大,命令复杂。
- 需 sudo,deep 模式仅提供指引,用户授权后执行。
- 行为级证据是"实锤",但获取成本高。

## 六、对抗与边界

- **rootkit 级隐藏**:若后门检测到本技能进程而隐匿行为,超出本技能能力(需内核级检测)。
- **商业闭源工具**:检测其二进制可能触 EULA,本技能定位"审计个人环境",README 加免责声明。
- **规则时效**:规则库不自动外联拉取(守无外联),靠用户手动更新或随技能发版。

## 七、Prompt Steganography 运行时实锤(capture_prompt.py)

静态分析(I 维度)能确认"版本是否含后门逻辑",但无法实锤"当前请求是否被标记"。
运行时捕获 claude 实际发送的 system prompt,检查 "Today's date is" 的撇号码点(U+0027 标准 / U+2019 / U+02BC / U+02B9)与日期分隔符(- 标准 / / 标记)。

### 方法 A:本地捕获 server(推荐,零依赖)

技能自带 `scripts/capture_prompt.py`(监听 127.0.0.1 回环,不外联):

```bash
# 终端 1: 起捕获 server
python3 ~/.claude/skills/backdoor-check/scripts/capture_prompt.py 8765

# 终端 2: 临时改 base_url 指向本地,触发一次请求
export ANTHROPIC_BASE_URL=http://127.0.0.1:8765
claude -p "hi"

# 捕获 server 自动分析撇号/日期,输出是否被标记。完成后恢复 base_url
```

判读:撇号 U+0027 + 日期用 `-` → ✅ 未标记;撇号 U+2019/02BC/02B9 或 日期用 `/` → 🚨 正被标记。

### 方法 B:mitmproxy(claude 拒绝 http base_url 时)

若 claude 强制 TLS 拒绝 http://localhost,用 mitmproxy 解密 HTTPS:`mitmproxy -p 8080` → 设 ANTHROPIC_BASE_URL 指向它并信任其 CA → 查看 claude 请求的 system prompt。

### 局限
- 方法 A 依赖 claude 接受 http base_url(部分版本强制 TLS)。
- 捕获单次请求;触发依赖 base_url+时区,需在目标配置下捕获。
