# backdoor-check

> 维护你对 AI 编程工具的知情权 —— 纯本地、零默认外联、开源的审计工具。

**[English](README_EN.md)** ｜ 中文

首发完整支持 Claude Code；通过可扩展 adapter 面向 Cursor / GitHub Copilot / Windsurf / Cline / Aider / Continue 等 AI 编程工具与智能体。它检查是否存在**值得你知情**的机制：未经告知的外联、设备指纹采集、凭证重定向、可疑的 Hooks / MCP / 插件行为、prompt 隐写。

**它不替你下“有 / 无后门”的结论；它把机制与证据摊开，让判断回到你手中。**

---

## 它能检测什么？

九个维度，每个维度都对应一类AI编程工具用户“值得知情”的机制：

| 代号 | 维度 | 检测内容 |
|------|------|---------|
| A | 版本与供应链 | 版本是否落在曾被报告的区间 / 包来源 / 完整性基线 / 官方 registry 对照 |
| B | 网络外联 | 进程连接快照 / 遥测端点命中 / 流量开关有效性 / hosts 动向 / 出站白名单 / 私网外联 / TLS 校验 |
| C | 设备指纹 | 地理位置 API / 机器标识读取 / 身份 env / 二进制内置采集函数 |
| D | Hooks | 全量扫描 / 随克隆传播 / 未声明 hook / 危险命令 / 脚本审计 |
| E | MCP | server 清单 / 启动命令可信性 / 权限覆盖 / stdio 劫持面 |
| F | API / 凭证 | base_url 重定向 / 明文存储 / 文件权限 / 凭证进入 cmdline |
| G | 权限 / 危险配置 | 危险开关 / 高危放行 / 别名注入 / 通配过宽 |
| H | 插件供应链 | marketplace 来源 / 代码审计 / blocklist / 完整性 |
| I | Prompt 隐写 | 隐写签名 + 解码 / 触发条件评估（你是否属于被定向标记的群体）|

> I 维度采用**确定性签名检测**（非启发式）：针对已披露的隐写手法（撇号 Unicode 变体、日期 `-`→`/` 变换、域名 XOR+base64），做可复现的字节级匹配。

---

## 它的安全设计

一个安全检测工具，首先不该自己成为新的隐私风险。backdoor-check 在工程上落实这一点：

- **纯本地，不外联（双重保证）**：静态自审（`scripts/` 无网络符号）+ 运行时 socket 守卫（启动即拦截出站，建连即抛错）。唯一例外是 `--verify-registry`，经隔离子进程连官方 registry，只 GET manifest，**不携带任何本地数据**。
- **报告脱敏**：所有凭证经 `redact()` 替换为 `<redacted:len=N:hash=sha256前8位>`，便于你比对而不暴露原文。
- **全程可审计**：`--audit` 干跑会打印所有将执行的系统命令；全脚本纯 Python、可读、无混淆。
- **零依赖**：不引入任何第三方库（规则库用 JSON 而非 YAML），避免给你的环境增加新的供应链风险。

这些不是卖点，而是一个安全工具请求你信任它之前应满足的前提。

---

## 快速开始

```bash
# 1. 先验证工具自身安全（静态无外联 + 运行时守卫 + 脱敏）
python3 scripts/check.py --self-check

# 2. 全量体检（人类可读 markdown 报告）
python3 scripts/check.py --mode interactive

# 3. CI 模式（JSON + 退出码;有 crit 则退出 2）
python3 scripts/check.py --mode ci --format json --dims A,B,F
echo "退出码: $?"  # 0=pass / 1=warn / 2=crit

# 4. 单维度检查
python3 scripts/check.py --dim network --format text

# 5. 深度取证（含 sudo dtrace/strace 指引,确认是否实际外传）
python3 scripts/check.py --mode deep

# 6. 受控外联:对照官方 registry 校验包完整性
python3 scripts/check.py --verify-registry

# 7. 审计干跑（打印将执行的命令,不实际执行）
python3 scripts/check.py --audit
```

Windows PowerShell 如遇中文或符号输出编码问题，可先执行：

```powershell
$env:PYTHONUTF8 = "1"
py scripts\check.py --self-check
```

**报告分级**：🚨 `crit`（后门特征 / 凭证泄露 / 任意执行，需立即处理）/ ⚠️ `warn`（风险面与加固建议）/ ✅ `pass` / ℹ️ `info`。

---

## 作为 Claude Code 技能 / 独立 CLI

**作为技能**：将本目录放入 `~/.claude/skills/backdoor-check/`，即可通过自然语言触发——“后门检测”、“安全体检”、“检查 Claude Code 是否安全”、“NVDB 后门”等（完整触发词见 `SKILL.md`）。

**作为独立 CLI**：`check.py` 无 Claude 依赖，任何环境都能跑：

```bash
python3 /path/to/backdoor-check/scripts/check.py --mode quick
```

---

## 普适性（不止 Claude Code）

首发 `claude-code` adapter 完整。其他工具通过贡献 adapter 支持：

- adapter 接口：`discover()` / `config_paths()` / `known_endpoints()` / `integrity_targets()` / `process_names()`
- 新增流程见 `references/adapters-guide.md`
- **工具无关兜底**：无 adapter 时，引擎按进程行为启发式采集连接并 diff 通用 allowlist，给“未知 AI 工具进程外联告警”。

路线：Phase 1 `claude-code`；Phase 2+ `cursor` / `windsurf` / `cline` / `copilot` / `aider` / `continue`（欢迎社区贡献）。

---

## CI 集成

```yaml
# GitHub Actions 示例
- name: backdoor-check
  run: |
    python3 skills/backdoor-check/scripts/check.py --mode ci --format json --dims A,B,F
```

退出码 `0` 全 pass / `1` 有 warn / `2` 有 crit。JSON schema 见 `references/ci-integration.md`。

---

## 诚实边界

没有人能承诺“绝对安全”，这个工具也一样。在采信它的结论前，请了解它的局限：

1. 二进制是编译产物（如 `claude.exe` 数百 MB），`strings` / `otool` / `nm` 只命中未混淆部分 → **这是启发式证据，“未发现” ≠ “不存在”**。
2. `lsof` 是瞬时快照，抓不到周期性 beacon 的全貌（watch 模式计划后续迭代）。
3. 行为级取证（是否**实际**外传）需要 `sudo`,`deep` 模式提供指引但默认不执行。
4. 规则不会自动联网拉取（守无外联），靠手动更新或随版本发布。
5. 检测商业闭源工具二进制，可能触及 EULA；本工具定位为“审计个人环境”，不替代企业级合规方案。
6. rootkit 级隐藏（后门检测到本工具而隐匿行为）超出能力。

如果你的威胁模型涉及上述场景，请结合纵深手段，不要只依赖单一工具。

---

## 如何贡献

贡献本身，就是参与技术平权——让更多人能审计自己的工具。

- **新增 adapter**（支持更多 AI 工具）：见 `references/adapters-guide.md`
- **新增检测规则**（JSON 规则库）：`scripts/rules/`，格式见各文件内说明
- **新增检测维度**：按 `references/check-standards.md` 模板
- **反馈误报 / 漏报**：附上脱敏后的报告片段与工具版本

---

## 目录结构

```
backdoor-check/
├── SKILL.md                # 技能入口（Claude Code 触发词）
├── README.md               # 中文（本项目主 README）
├── README_EN.md            # English
├── LICENSE                 # MIT
├── references/             # 详细文档（按需加载）
│   ├── check-standards.md  # A–I 维度标准 + 阈值表
│   ├── deep-water.md       # 网络命令 / 二进制分析 / 行为取证 深水区
│   ├── adapters-guide.md   # adapter 契约 + 新增指南
│   ├── rules-guide.md      # 规则库编写指南
│   ├── ci-integration.md   # JSON schema + CI 片段
│   └── self-security.md    # 自身安全工程细节
└── scripts/
    ├── check.py            # CLI 入口（含 socket 出站守卫）
    ├── selfcheck.py        # 静态自审
    ├── verify_registry.py  # 唯一受控外联模块
    ├── capture_prompt.py   # prompt 隐写运行时诊断（进阶,会临时改 base_url）
    ├── engine/             # 工具无关的检测原语
    ├── adapters/           # 工具适配层
    └── rules/              # JSON 规则库（社区可扩展）
```

---

## 致谢与声明

### 始于一个标记

2026 年 6 月，安全研究者 **Thereallo** 公开了一份 Claude Code 的逆向分析。报告显示：在一条与自定义 `ANTHROPIC_BASE_URL` 有关的路径上，客户端会把环境信号写入系统提示词——日期分隔符和 `Today's` 中的撇号在通常的渲染下几乎无从分辨，却能被机器读取；域名与关键词列表还经过 XOR（密钥 91）和 base64 处理。完整的技术细节见 [原始分析](https://thereallo.dev/blog/claude-code-prompt-steganography)。

这不是“所有用户都被标记”的证据，也不是对任何软件一概而论的判决。该报告显示，未设置 `ANTHROPIC_BASE_URL` 或使用官方 API 地址时，这条路径会提前返回。正因如此，backdoor-check 把它当作一项**可复现的历史签名**来检查：它服务于具体版本、具体配置和具体证据，而不以恐慌替代判断。

感谢所有把复杂机制还原为可被他人复核的研究者。这个项目沿用的，不只是他们发现的问题，更是他们的方法：拆开、说明、允许质疑。

### 目的合理，不代表机制可以不透明

模型提供者有理由防范账户转售、滥用与大规模蒸馏。Anthropic 也曾公开描述过利用欺诈账户和代理服务进行的大规模蒸馏活动。 [其公开说明](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks?selectAccount=true) 这种现实的利益冲突，需要真实而有效的防护。

但目的的正当性，不能自动免除手段的说明义务。当一个开发者工具已经能读取项目、执行命令、进入工作流时，使用者不该靠逆向工程才知道它在如何分类自己的环境。防滥用可以是明确的策略、可见的遥测字段、可审计的规则；不应把关键信号藏在普通人难以察觉的细节里。

### 知情权是一种公共权利

技术并不只是一组功能。它还规定了谁可以设定规则、谁必须接受默认值、谁拥有解释权。计算工具越深入工作、创作与公共生活，这种不对称就越不应被当作理所当然。

我们主张的并不激进：每一位使用者都有权知道，自己的环境是否被收集、分类或传递；这项权利不应取决于所在地、语言、组织规模，或所使用的是哪一家公司的工具。

这就是 backdoor-check 想承担的有限工作：默认在本地运行，报告先脱敏，依赖保持最少；从进程行为、网络连接、配置、供应链线索、设备指纹与 prompt 隐写中，降低审计的门槛。它不替你指定敌人，也不要求你相信它的结论；它只尽量让原本不可见的机制被看见。

我们欢迎复现、纠错、补充规则和新增 adapter，也欢迎工具维护者用更清楚的说明、更小的数据收集面和更可审计的实现来反驳它。真正值得信任的工具，不应害怕被看见。

---

## License

MIT —— 见 [LICENSE](LICENSE)。

希望本开源项目能帮助你我更清楚地了解每天所用的工具。
