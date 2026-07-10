# -*- coding: utf-8 -*-
"""adapter 接口约定与注册表。

每个工具 adapter 是一个 Python 模块(adapters/<tool>.py),暴露以下模块级符号:
- ADAPTER_NAME: str               工具显示名
- discover() -> dict              发现工具,返回 {found, version, source, path, package_path}
- config_paths() -> list[str]     配置文件/目录路径(含全局与项目级)
- known_endpoints() -> list[str]  该工具已知合法 API host(从 allowlist 规则同步)
- integrity_targets() -> list[str] 需校验完整性的文件路径(二进制/package.json 等)
- process_names() -> list[str]    进程名模式(供 network 维度归属连接)

新增 adapter 流程见 references/adapters-guide.md。
"""
from __future__ import annotations

import importlib
from typing import Optional, Any

# 已注册 adapter: --tool 参数值 → 模块名
REGISTRY = {
    "claude-code": "claude_code",
    # Phase 2+(社区贡献): cursor / copilot / windsurf / cline / aider / continue
}


def load_adapter(tool_name: str) -> Optional[Any]:
    """按工具名加载 adapter 模块。返回模块对象或 None(未注册/未安装)。"""
    mod_name = REGISTRY.get(tool_name)
    if not mod_name:
        return None
    try:
        return importlib.import_module("adapters." + mod_name)
    except Exception:
        return None


def auto_discover() -> Optional[Any]:
    """自动发现本机已安装的工具,返回首个命中的 adapter 模块。

    MVP 顺序: claude-code 优先(本机主用)。Phase 2+ 扩展为多工具并行发现。
    """
    for tool_name in REGISTRY:
        mod = load_adapter(tool_name)
        if mod and hasattr(mod, "discover"):
            try:
                info = mod.discover()
                if info and info.get("found"):
                    return mod
            except Exception:
                continue
    return None
