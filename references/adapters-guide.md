# Adapter 契约与新增指南

> 如何为新 AI 编程工具编写 adapter。首发 claude-code 完整,其他工具按本指南贡献。

## 一、adapter 接口契约

每个 adapter 是 `scripts/adapters/<tool>.py` 模块,暴露以下模块级符号:

```python
ADAPTER_NAME = "tool-name"           # 工具显示名

def discover() -> dict:
    """发现工具。返回 {found, version, source, path, package_path}。
    found=False 表示未安装。"""

def config_paths() -> list[str]:
    """该工具所有配置文件/目录路径(全局 + 项目级)。
    含 settings、MCP 配置、hooks 目录、插件清单等。"""

def known_endpoints() -> list[str]:
    """该工具已知合法 API host(与 rules/allowlist.json 同步)。"""

def integrity_targets() -> list[str]:
    """需校验完整性的文件路径(二进制、package.json 等),供 A3 哈希基线。"""

def process_names() -> list[str]:
    """进程名模式,供 network 维度归属连接。"""
```

在 `scripts/adapters/base.py` 的 `REGISTRY` 注册:
```python
REGISTRY = {
    "claude-code": "claude_code",
    "cursor": "cursor",          # 新增
    ...
}
```

## 二、各工具配置路径速查(贡献参考)

| 工具 | 二进制/发现 | 配置目录 | MCP 配置 |
|------|------------|---------|---------|
| Claude Code | `claude` CLI(npm `@anthropic-ai/claude-code`) | `~/.claude/` | `~/.claude.json` |
| Cursor | `cursor` CLI / Electron app | `~/.cursor/`、`~/Library/Application Support/Cursor/`(macOS) | `~/.cursor/mcp.json` |
| GitHub Copilot | VSCode 扩展 | VSCode `settings.json` | VSCode MCP |
| Windsurf | Electron app(Codeium) | `~/.codeium/`、`~/Library/Application Support/Windsurf/` | `~/.codeium/windsurf/mcp_config.json` |
| Cline | VSCode 扩展 | VSCode `globalStorage/saoudrizwan.claude-dev/` | VSCode MCP |
| Aider | `aider` pip 包 | `~/.aider.conf.yml`、`~/.aider/` | (aider 自身) |
| Continue | VSCode 扩展 | `~/.continue/`、`~/.config/continue/` | `~/.continue/config.json` |

## 三、新增 adapter step-by-step

1. **创建模块** `scripts/adapters/<tool>.py`,实现 5 个函数 + `ADAPTER_NAME`。
2. **discover()**:用 `platform.which()` 找二进制,读版本(CLI `--version` 或 package.json),解析包路径。
3. **config_paths()**:列出该工具所有配置文件(参考上表)。跨平台用 `os.path.expanduser("~")` + 平台判断。
4. **known_endpoints()**:从 `rules/allowlist.json` 的 `by_tool.<tool>` 同步官方 host。
5. **integrity_targets()**:返回二进制 + package.json 路径(A3 哈希)。
6. **process_names()**:进程名模式。
7. **注册**:在 `base.py` 的 `REGISTRY` 加映射。
8. **更新 allowlist.json**:加 `by_tool.<tool>` 条目(official_api_hosts/registry/package)。
9. **测试**:`python3 scripts/check.py --tool <tool> --mode quick`。

## 四、adapter 实现要点

- **不联网**:adapter 只读本地文件系统 + `claude --version` 之类本地命令。网络由 `verify_registry.py` 隔离处理。
- **容错**:配置文件可能不存在/格式异构(JSON/SQLite/TOML)。`fs.read_json` 失败返回 None,优雅降级。
- **跨平台**:macOS/Linux/Windows 路径差异,用 `platform.detect_os()` 分支。
- **脱敏**:路径在 `ToolInfo.to_dict` 中 home 替换为 `~`。

## 五、工具无关兜底

即使某工具无 adapter,引擎仍可检测:
- `platform.find_pids` 按进程名模式匹配 AI 工具(父进程为编辑器/含 ai 关键字)
- 采集其网络连接,diff 通用 `allowlist.json`
- 给"未知 AI 工具进程外联告警"

这保证普适底线:新工具出现时,即使无专属 adapter,也能从进程/网络层面告警。

## 六、Electron 类工具的特殊处理

Cursor/Windsurf 等 Electron 应用:
- 配置可能在 `~/Library/Application Support/<App>/`(macOS),含 JSON + SQLite
- 进程可能是 `Electron` / `<App> Helper`,需靠路径/参数区分工具归属
- 二进制是 Electron 框架 + 应用代码,strings 分析需定位应用代码而非框架

Phase 2+ 实现时需逆向其配置存储格式,贡献者可参考 claude_code.py 的实现模式。
