# -*- coding: utf-8 -*-
"""Claude Code adapter — 首发完整实现。

负责发现 Claude Code 安装、定位配置文件、声明已知端点与完整性目标。
本模块不发起网络请求;所有信息来自本地文件系统与 `claude --version`。
"""
from __future__ import annotations

import os
import sys

# 让 engine 可被 import(scripts/ 在 sys.path)
_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from engine import platform  # noqa: E402

ADAPTER_NAME = "claude-code"
PACKAGE = "@anthropic-ai/claude-code"


def discover() -> dict:
    """发现 Claude Code。返回 {found, version, source, path, package_path}。"""
    info = {"found": False, "version": "", "source": "", "path": "", "package_path": ""}
    claude_bin = platform.which("claude")
    if not claude_bin:
        return info
    info["found"] = True
    info["path"] = claude_bin
    # 版本
    rc, out, _ = platform.run(["claude", "--version"], timeout=10)
    if rc == 0 and out.strip():
        # 输出形如 "2.1.205 (Claude Code)"
        info["version"] = out.strip().split()[0]
    # 包路径: 解析 symlink 到 node_modules/@anthropic-ai/claude-code
    try:
        real = os.path.realpath(claude_bin)
        parts = real.split(os.sep)
        if "@anthropic-ai" in parts:
            idx = parts.index("@anthropic-ai")
            # @anthropic-ai/claude-code 是一个目录名(scoped package)
            pkg_dir = os.sep.join(parts[:idx + 2])
            if os.path.isdir(pkg_dir):
                info["package_path"] = pkg_dir
                info["source"] = "npm:%s" % PACKAGE
        if not info["source"]:
            info["source"] = "未知来源(非官方 npm 路径?)"
    except Exception:
        info["source"] = "解析失败"
    return info


def config_paths() -> list:
    """返回所有 Claude Code 配置文件/目录路径(全局 + 项目级)。"""
    home = os.path.expanduser("~")
    paths = [
        os.path.join(home, ".claude", "settings.json"),
        os.path.join(home, ".claude", "settings.local.json"),
        os.path.join(home, ".claude.json"),          # MCP 配置主文件
        os.path.join(home, ".claude", "hooks"),       # hooks 脚本目录
        os.path.join(home, ".claude", "plugins", "installed_plugins.json"),
        os.path.join(home, ".claude", "plugins", "known_marketplaces.json"),
        os.path.join(home, ".claude", "plugins", "blocklist.json"),
    ]
    # 项目级(当前工作目录)
    cwd = os.getcwd()
    paths.append(os.path.join(cwd, ".claude", "settings.json"))
    paths.append(os.path.join(cwd, ".claude", "settings.local.json"))
    paths.append(os.path.join(cwd, ".mcp.json"))
    return paths


def known_endpoints() -> list:
    """Claude Code 已知合法 API host(与 rules/allowlist.json 同步)。"""
    return ["api.anthropic.com", "statsig.anthropic.com", "console.anthropic.com"]


def integrity_targets() -> list:
    """需校验完整性的文件(A3 维度哈希基线)。"""
    info = discover()
    targets = []
    pkg = info.get("package_path", "")
    if pkg and os.path.isdir(pkg):
        # macOS: bin/claude.exe (编译型 Mach-O);其他平台可能是 cli.js
        for cand in ["bin/claude.exe", "bin/claude", "cli.js", "package.json", "install.cjs"]:
            p = os.path.join(pkg, cand)
            if os.path.isfile(p):
                targets.append(p)
    return targets


def process_names() -> list:
    """Claude Code 相关进程名模式(供 network 维度归属连接)。"""
    return ["claude", "claude-code"]


def settings_files_with_content() -> list:
    """返回存在的、可读取的 settings 文件路径(供 config_audit 维度)。"""
    result = []
    for p in config_paths():
        if p.endswith(os.sep + "hooks"):
            continue
        if os.path.isfile(p):
            result.append(p)
    return result
