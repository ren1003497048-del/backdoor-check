---
name: backdoor-check
description: >
  检测 AI 编程工具/智能体(Claude Code / Cursor / GitHub Copilot / Windsurf / Cline / Aider / Continue 等)
  是否存在后门或可疑安全机制:版本与供应链完整性、静默外联与遥测、设备指纹与身份收集、
  Hooks 任意执行、MCP 权限绕过、API/凭证重定向、危险配置、插件供应链。
  纯本地运行、无出站请求(唯一例外 --verify-registry 受控校验)、报告脱敏、stdlib-only。

  当用户说"后门检测""安全体检""是不是被监控""有没有泄密""backdoor""安全扫描"
  "supply chain check""telemetry check""可疑外联""体检 AI 工具""检查 Claude/Cursor/Copilot 是否安全"
  "后门事件""NVDB""claude code 安全""claude code 后门"时立即触发本技能,不需要用户说完整指令。
---

# backdoor-check — AI 编程工具后门检测技能

检测 AI 编程工具是否存在后门或可疑安全机制。参考 `/doctor` 的 checkup 逻辑:
**扫描 → 诊断 → 分级报告 → 可选修复建议**。结构对本机 `infra-audit` 风格对齐。

## 背景:近期后门事件(检测设计依据)

- **NVDB 2026-07-08**:中国工信部国家漏洞库公告 Claude Code 2.1.91–2.1.196 内置监控机制,
  在用户不知情下将**地理位置**和**身份标识**外传远程服务器。
- **Check Point 2026**:三类配置层攻击载体——Hooks 任意执行 / MCP 绕过审批 / API key 重定向。
- **2026-03 源码泄露**:npm 包被植入 Vidar/GhostSocks 恶意软件。
- **2026-06-30 Thereallo 逆向(prompt steganography)**:Claude Code 2.1.91–2.1.196 按 base_url+时区触发,在 system prompt 的 "Today's date is" 注入隐写标记(撇号 U+2019/02BC/02B9 + 日期 - → /),域名列表 XOR(91)+base64 混淆。Anthropic 工程师已确认,2026-07-01 移除。**I 维度据此做确定性检测**(非启发式)。

本技能从**机制底层**(进程行为/网络外联/二进制/设备指纹/prompt 隐写)检测,而非只查版本号。
**版本(A1)只是辅助筛查**;核心证据是 I(prompt steganography 确定性签名)、C(指纹收集能力)、B(实际外联行为)等机制层检测。

## 自身安全(核心卖点,区别于其他安全工具)

技能本身**不泄漏数据**——一个不侵犯隐私的安全检测工具:

- **J1 纯本地无外联(双重保证)**:静态自审(scripts/ 无网络符号)+ 运行时 socket 守卫
  (check.py 启动即 monkeypatch socket,建连抛 OutboundBlockedError)。唯一例外
  `--verify-registry` 经隔离子进程连官方 registry,只 GET manifest,不携带本地数据。
- **J2 脱敏**:所有输出经 `redact()`,凭证替换为 `<redacted:len=N:hash=sha256前8位>`。
- **J3 不外传 / J4 可审计(`--audit` 干跑)/ J5 本地输出(零遥测)**。
- **stdlib-only**:零第三方依赖,不引入新供应链风险。

> 首次使用建议先运行 `python3 scripts/check.py --self-check` 验证技能自身安全。

## 使用前准备

读取详细检测标准与阈值: `@references/check-standards.md`

## 检测维度速查

| 代号 | 维度 | 核心检查项 |
|------|------|-----------|
| A | 版本与供应链 | A1版本区间(NVDB 2.1.91-2.1.196)/ A2包来源 / A3完整性基线diff / A4新鲜度 |
| B | 网络外联 | B1进程连接 / B2遥测端点 / B3流量开关有效性 / B4 hosts劫持 / B5白名单 / B6私网 / B7 TLS禁用 |
| C | 设备指纹 | C1位置API / C2机器标识 / C3身份env / C4二进制收集函数(后门特征) |
| D | Hooks | D1全量扫描 / D2随克隆传播 / D3未标识hook / D4危险命令 / D5脚本审计 |
| E | MCP | E1清单 / E2启动可信 / E3权限覆盖 / E4范围 / E5 stdio劫持 |
| F | API/凭证 | F1 base_url重定向 / F2明文 / F3文件权限 / F5 cmdline / F6凭证文件 |
| G | 权限/危险配置 | G1危险开关 / G2高危放行 / G4别名注入 / G5通配过宽 |
| H | 插件供应链 | H1来源 / H2代码审计 / H3 blocklist / H4完整性 |
| I | Prompt隐写(确定性) | I1 steganography签名+XOR(91)解码 / I2 触发条件评估(是否后门目标) |

## 执行流程

### Step 0:自身安全验证
```bash
python3 scripts/check.py --self-check
```
确认静态无外联 + 运行时守卫 + 脱敏生效。

### Step 1:选择模式

| 模式 | 命令 | 适用 |
|------|------|------|
| 快速扫描 | `--mode quick` | 廉价静态,无 B1 进程连接 |
| 交互体检 | `--mode interactive`(默认) | 全量 A–H,含 B1 |
| 深度取证 | `--mode deep` | + sudo dtrace/strace 行为级取证指引 |
| CI | `--mode ci --format json` | JSON + 退出码,接入流水线 |
| 单维度 | `--dim network` / `--dim A` | 聚焦某一维度 |

### Step 2:运行检测(管道式调用)
```bash
# 全量体检(人类可读 markdown)
python3 scripts/check.py --mode interactive

# CI 模式(只跑核心维度,JSON 输出,有 crit 则退出码 2)
python3 scripts/check.py --mode ci --format json --dims A,B,F || exit 1

# 单维度
python3 scripts/check.py --dim D --format text

# 审计干跑(打印将执行的命令,不实际执行)
python3 scripts/check.py --audit

# 受控外联:对照官方 registry 校验包完整性(检测源码泄露类篡改)
python3 scripts/check.py --verify-registry
```

### Step 3:解读报告

- 🚨 **crit**:后门特征/凭证泄露/任意执行 — 立即处理
- ⚠️ **warn**:风险面/加固建议 — 建议处理
- ✅ **pass**:安全
- ℹ️ **info**:信息性(不参与退出码)

**退出码**:0 全 pass / 1 有 warn / 2 有 crit。CI 模式据此拦截。

### Step 4:深度取证(deep 模式)
`--mode deep` 提供 sudo dtrace/strace/tcpdump 指引,确认是否**实际外传**指纹(而非仅具备能力)。
详见 `@references/deep-water.md`。

### Step 5:修复(需授权)
报告生成后,修复操作须经用户授权。本技能默认**只读**,不修改用户配置(基线文件 baseline.json
为技能自身状态,首次扫描自动建立)。遵循本机"破坏性操作必须二次确认"原则。

## 诚实局限(必须告知用户)

1. 二进制是编译产物(如 claude.exe 237MB),strings/otool/nm 只命中未混淆部分 → **启发式证据,未发现 ≠ 不存在**。
2. lsof 是瞬时快照,抓不到周期 beacon 全貌(watch 模式后续迭代 + 静态 strings 互补)。
3. 行为级取证(是否实际外传)需 sudo,deep 模式可选,默认不执行。
4. 规则不自动外联拉取(守无外联),靠手动更新或随技能发版。
5. rootkit 级隐藏(后门检测到本技能而隐匿)超出能力。

## 普适性(其他 AI 工具)

首发 `claude-code` adapter 完整。其他工具(Cursor/Copilot/Windsurf/Cline/Aider/Continue)
按 `@references/adapters-guide.md` 贡献 adapter。**工具无关兜底**:无 adapter 时按进程行为
启发式采集连接并 diff 通用 allowlist,给"未知 AI 工具进程外联告警"。

## 经验写入

每次完整扫描后,可将关键发现(命中样本 + 修复摘要)追加到 `~/.claude/EXPERIENCE.md`,
随时间形成安全基线历史。
