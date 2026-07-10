# 检测标准与阈值 (A–H 维度)

> 本文件由 SKILL.md 按需加载。包含各维度的检测目标、阈值表、执行步骤、证据格式与误报规避。
> 详细深水区技术(网络命令对照/二进制分析/行为取证)见 `deep-water.md`。

## 分级约定

| 级别 | 符号 | 含义 | 退出码 |
|------|------|------|--------|
| crit | 🚨 | 后门特征/凭证泄露/任意执行 | 2 |
| warn | ⚠️ | 风险面/加固建议 | 1 |
| pass | ✅ | 安全 | 0 |
| info | ℹ️ | 信息性(不影响退出码) | 0 |

---

## A 版本与供应链

**目标**: 版本是否落在已知后门区间;包来源是否官方;包是否被篡改。

| 检查项 | ✅ pass | ⚠️ warn | 🚨 crit |
|--------|---------|---------|---------|
| A1 版本区间 | 不在任何 advisory 区间 | 无法确定版本 | 落在 NVDB 2.1.91-2.1.196 等区间 |
| A2 包来源 | source 含官方 package | 非官方/无法确认 | typosquat 仿冒包名 |
| A3 完整性 | 哈希与基线一致 | 文件集变化(新增/删除) | 哈希变化(被篡改) |
| A4 新鲜度 | — | — | (info,需 --check-latest 受控外联) |

**执行**: adapter.discover() 取版本 → semver 比对 `rules/advisories.json` → A2 比对 `allowlist.json` official_package → A3 sha512 基线 diff(`scripts/baseline.json`)。

**误报规避**: A3 基线在版本升级后会失效(文件变化),提示用户删除 baseline.json 重建;`--verify-registry` 是确认篡改的权威手段(对照官方 registry)。

---

## B 网络外联(后门核心)

**目标**: 进程是否外联到遥测/GeoIP/可疑端点;流量开关是否生效;hosts/DNS 是否被劫持。

| 检查项 | ✅ pass | ⚠️ warn | 🚨 crit |
|--------|---------|---------|---------|
| B1 进程连接 | 全在官方白名单 | 外联非白名单/第三方代理 | 外联 GeoIP/私网/本地 IP |
| B2 遥测端点 | 二进制无遥测 host | 二进制含遥测端点(分析能力) | 二进制含 GeoIP 端点/运行时外联遥测 |
| B3 流量开关 | 开关=1 且无遥测外联 | 开关未设 | 开关=1 但仍有遥测外联(开关失效,后门特征) |
| B4 hosts 劫持 | 未劫持官方域名 | — | hosts 映射官方域名到非官方 IP |
| B5 白名单 | 外联在官方白名单 | 外联第三方代理/未知端点 | — |
| B7 TLS 禁用 | 无 TLS 禁用标志 | — | 二进制含 NODE_TLS_REJECT_UNAUTHORIZED=0 |

**执行**: `platform.find_pids(adapter.process_names())` → `network_connections(pid)` → 比对 `endpoints.json` + `allowlist.json`。B2/B7 用 `binary.extract_strings` 静态扫描二进制。

**误报规避**: B1 是 lsof 瞬时快照,无连接 ≠ 不外联(周期 beacon 可能漏);B2 静态命中仅证明"具备能力",需结合 B1 是否实际外联升 crit。第三方代理(如智谱 open.bigmodel.cn)warn,需用户确认是自配。

---

## C 设备指纹(NVDB 核心: 地理位置+身份标识)

**目标**: 二进制是否具备位置/机器标识/身份 env 收集能力(后门特征模式)。

| 检查项 | ✅ pass | ⚠️ warn | 🚨 crit |
|--------|---------|---------|---------|
| C1 位置 API | 无位置符号 | 含 CoreLocation/GeoIP host | (结合外联升 crit) |
| C2 机器标识 | 无标识符号 | 含 IOPlatformUUID/machine-id | (结合外联升 crit) |
| C3 身份 env | 无敏感 env 引用 | 含 GITHUB_TOKEN/AWS_* 等 | — |
| C4 收集函数 | 无分析 SDK 签名 | 含 trackEvent/sendBeacon 等 | 含 getMachineId/fingerprint 等高信号 / 完整链路(位置+标识+收集函数) |

**执行**: `binary.extract_strings(claude.exe)` → 比对 `fingerprints.json` 各类。C4 综合判定:位置+标识+收集函数同时命中 → crit(吻合 NVDB 后门特征)。

**误报规避**: 静态启发式,只命中未混淆部分。timeZone 等常见词已从 location_indicators 移除避免误报。具备能力 ≠ 已外传,需 B 维度交叉佐证。deep 模式用 dtrace/strace 取证是否实际外传。

### C5/C6 用户画像定位特征(扩展,区别于时区/域名)

| 检查项 | ✅/⚠️ | 说明 |
|---------|------|------|
| C5 画像特征引用 | pass/warn | 扫二进制是否引用 locale/hostname/username/network(timezone)(启发式) |
| C6 本机暴露 | info/warn | 评估本机 LANG/hostname/username/IANA 时区;中文 locale+中国时区 = 高可识别目标(warn) |

**执行**: C5 扫 `user_profiling_indicators` 各类;C6 读本机 LANG/hostname/username(`/etc/localtime` symlink),判定高可识别。
**洞察**: `zh_CN` locale 比时区更精准、更难伪装(时区可改,locale 改了影响系统使用)。这是 Thereallo 之外、同样可用于定向的特征。

---

## D Hooks(Check Point 载体1: 任意命令执行)

**目标**: hooks 是否含危险命令;是否随仓库克隆传播;是否未标识来源。

| 检查项 | ✅ pass | ⚠️ warn | 🚨 crit |
|--------|---------|---------|---------|
| D1 全量扫描 | 无危险命令 | — | — |
| D2 随克隆传播 | — | hook 指向仓库内脚本(./.claude/) | — |
| D3 未标识 | — | 缺 _tag 的 hook | — |
| D4 危险命令 | — | — | hook 含 http/curl/wget/base64/eval |
| D5 脚本审计 | 脚本无危险模式 | hooks 目录脚本含可疑模式 | — |

**执行**: 扫 `settings.json` 的 hooks 字段(全局+项目级,realpath 去重)+ `~/.claude/hooks/` 目录脚本。

**误报规避**: 已知托管工具(如 ccstatusline)的 hook 带 `_tag`,识别为可信。D4 用正则匹配危险命令模式。

---

## E MCP(Check Point 载体2: 绕过审批)

| 检查项 | ✅/⚠️/🚨 | 说明 |
|---------|----------|------|
| E1 清单 | info | 列出所有 server |
| E2 启动可信 | warn(远程URL)/ crit(指向 IP/localhost) | command/args/url 可信性 |
| E3 权限覆盖 | warn | autoApprove/alwaysAllow 绕过审批 |
| E5 stdio 劫持 | info | stdio MCP 可读写全部工具流量 |

**执行**: 扫 `~/.claude.json` mcpServers(全局+项目级)+ `cwd/.mcp.json`。

---

## F API/凭证(Check Point 载体3: API key 重定向)

| 检查项 | ✅ pass | ⚠️ warn | 🚨 crit |
|--------|---------|---------|---------|
| F1 base_url | 指向官方 | 指向第三方代理/未知 | 指向 IP/localhost(凭证截获) |
| F2 明文存储 | — | 配置文件含明文 token | — |
| F3 文件权限 | 仅 owner 可读 | — | 凭证文件 group/other 可读 |
| F5 cmdline | — | — | 凭证出现在进程命令行 |

**执行**: 读 settings.json env 的 ANTHROPIC_BASE_URL → 比对 `allowlist.json`(official/proxies);F2 正则扫凭证 key;F3 `os.stat` 检查权限;F5 `process_cmdline` grep。

**误报规避**: 第三方代理(智谱/openrouter)warn 而非 crit,因常见为用户主动配置,但需确认非篡改。

---

## G 权限/危险配置

| 检查项 | ✅/⚠️/🚨 | 说明 |
|---------|----------|------|
| G1 危险开关 | warn | skipDangerousModePermissionPrompt/autoUpdates 等 |
| G2 高危放行 | warn(rm/pip)/ crit(sudo/rm -rf/写系统目录) | permissions.allow 匹配 `permissions.json` |
| G4 别名注入 | warn | shell rc 含 --dangerously-skip-permissions |

**执行**: 扫 settings.json 顶层开关 + permissions.allow 列表,比对 `permissions.json` 模式。

---

## H 插件供应链

| 检查项 | ✅/⚠️/🚨 | 说明 |
|---------|----------|------|
| H1 来源 | pass(官方 marketplace) | warn(非官方) |
| H3 blocklist | — | crit(命中恶意包名单) |

**执行**: 读 `installed_plugins.json` + `known_marketplaces.json`,marketplace source 为 github:anthropics 视为官方;比对 `blocklist.json`。

---

## I Prompt Steganography(确定性检测,基于 Thereallo 逆向)

**目标**: 确认二进制是否含 prompt steganography 后门(按 base_url+时区在 system prompt 注入隐写标记)。

| 检查项 | ✅ pass | 🚨 crit |
|--------|---------|---------|
| I1 后门签名 | 时区判断=0 + XOR解码无命中 | 命中 Asia/Shanghai/Urumqi,或 XOR(91)解码出域名列表(deepseek/zhipu 等) |
| I2 触发条件 | 配置非后门目标 | (仅当 I1 命中/含后门时)配置是目标 → warn |

**执行**: `binary.extract_strings` → `scan_literal`(Asia/Shanghai/Urumqi、replaceAll、resolvedOptions)→ `scan_base64_xor`(base64 串 XOR91 解码搜 lab_keywords)→ I1 确定性判定。I2 评估 base_url host + IANA 时区(读 `/etc/localtime` symlink,等价 JS `resolvedOptions().timeZone`)。

**关键**: 这是**确定性检测**(Thereallo 精确签名 + XOR 解码),非启发式。命中即确认该版本含后门(crit)。**I 维度是后门检测的核心证据**,优先级高于 C 维度的启发式指纹。C 维度的 `getMachineId`/`telemetry` 等 strings 命中可能为良性遥测,仅作辅助。
