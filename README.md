# backdoor-check

> 维护你对 AI 编程工具的知情权 —— 纯本地、零外联、开源的审计工具。

**[English](README_EN.md)** ｜ 中文

检测 Claude Code / Cursor / GitHub Copilot / Windsurf / Cline / Aider / Continue 等 AI 编程工具与智能体，是否存在**值得你知情**的机制：未经告知的外联、设备指纹采集、凭证重定向、可疑的 Hooks / MCP / 插件行为、prompt 隐写。

**它不替你下“是/否后门”的结论，而是把这些机制检测出来，摊给你看。**

---

## 它检测什么

九个维度，每个维度都是一类“值得知情”的机制：

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

## 它如何尊重你

一个安全检测工具，首先不该自己成为新的隐私风险。backdoor-check 在工程上落实这一点：

- **纯本地，不外联（双重保证）**：静态自审（`scripts/` 无网络符号）+ 运行时 socket 守卫（启动即拦截出站，建连即抛错）。唯一例外是 `--verify-registry`，经隔离子进程连官方 registry，只 GET manifest，**不携带任何本地数据**。
- **报告脱敏**：所有凭证经 `redact()` 替换为 `<redacted:len=N:hash=sha256前8位>`，便于你比对而不暴露原文。
- **全程可审计**：`--audit` 干跑会打印所有将执行的系统命令；全脚本纯 Python、可读、无混淆。
- **零依赖**：不引入任何第三方库（规则库用 JSON 而非 YAML），避免给你的环境增加新的供应链风险。

这些不是卖点，而是这个工具能请你信任它的前提。

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

## 诚实的边界

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

2026 年 6 月底，署名 **Thereallo** 的开发者揭开了 Claude Code 的后门机制；在他之前，Reddit 用户 **LegitMichel777** 已率先完成反编译。他们发现：这个被全球无数开发者信任的编程助手，会悄悄改写自己发回服务器的系统提示词——把日期里的连字符换成斜杠，把 “Today's date is” 里的撇号替换成三个肉眼无法分辨、机器却能瞬间读出的 Unicode 字符。触发条件是时区（Asia/Shanghai、Asia/Urumqi），或代理地址里出现中国的域名与 AI 实验室；那份域名列表本身，被 XOR（密钥 91）与 base64 藏了起来。整个过程没有任何告知——不弹窗、不请求授权，也不曾出现在任何一个版本的发布说明里。

Thereallo 的一句话，我们深以为然：“这未必是恶意的功能，但对一个要求用户信任的开发者工具来说，这是一个奇怪的选择。” 感谢他们。他们的发现与方法，既是这个项目存在的原因，也是它的方法：把工具内部的机制做一定的拆解与暴露，以保障站在一家千亿美金估值的巨头对面的、每一位普通用户的权益。

---

2026 年 6 月 30 日，Claude Code 工程师 **Thariq Shihipar** 在 X 上作出回应：这是一个 3 月启动的实验，“旨在防止未授权转售者的账户滥用，并抵御蒸馏（distillation）”；团队已有更强的缓解措施，“其实一直打算把它撤下来”。

我们理解蒸馏的担忧。前沿模型的训练成本巨大，能力被规模化复制，是任何公司都不愿承受的损失；Anthropic 也曾指出有大量欺诈账户对 Claude 发起系统性蒸馏。这是真实的利益冲突。

**但理解，不等于认同。**

判定标准被设成了时区与地理——任何一台系统时间指向中国、或代理穿过中国网络的设备，都被默认为值得标记的对象。数以百万计像我这样的普通中国用户，在不知情的情况下被“有罪推定”——仿佛个个都是来分食其成果的人。

Anthropic 一向以安全立身：它把“前沿 AI 安全（frontier AI safety）”写在使命中央，把“有益、无害、诚实（helpful, harmless, honest）”作为模型恪守的准则。可这一次，它口中的“安全”是它自己的安全——是它的模型不被复制、商业利益不被侵蚀的安全；而用户的安全，也就是知道自己正被如何标记、归类、发往何处的安全，似乎并不在其中。这至少说明，它所强调的安全是狭义的。也说明，当一家 AI 科技巨头同时是规则的制定者、执行者与解释者，一种不经意的傲慢几乎成为结构性的必然——它关于安全与透明的声明，又一次变得难以令人采信。

---

我主张一件朴素的事：每一个使用者，都有权知道自己的信息被如何收集、如何流转、被怎样对待。这不该取决于你来自哪里，也不分你用的是哪一家公司的工具。

这也是 backdoor-check 想做的：一个面向开发者与个人用户的本地工具，纯本地运行、零出站请求、报告脱敏、零第三方依赖；从机制底层——进程行为、网络外联、二进制静态分析、设备指纹、prompt 隐写——检测你的工具里是否存在那些值得你知情的机制。它已覆盖 Claude Code，也设计成可以检测 Cursor、Copilot、Windsurf、Cline、Aider、Continue，以及任何你能叫出名字的 AI 编程工具。

---

最后，我们呼吁更多的人——无论是 Thereallo 这样的专业研究者，还是每一位普通用户——在使用 AI 的过程中，既保护自己的数据权利，也尊重他人的隐私。这两件事，本不该冲突。

AI 本该让这个世界变得好一点。哪怕此刻并不尽然。我们正同时面对它带来的海量虚假信息、对就业的冲击，以及一连串尚未理清的伦理难题。而更深的反省或许在于：AI 并没有凭空制造偏见——它身上普遍可见的厌女倾向、科技至上主义，以及自恋式的自我中心，不过是当下社会某种身影的倒映。

---

## License

MIT —— 见 [LICENSE](LICENSE)。

如果你因为这个工具而更清楚自己每天在用什么，那就是它存在的意义。
