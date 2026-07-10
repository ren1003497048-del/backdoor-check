#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""backdoor-check — AI 编程工具后门检测技能主入口。

自身安全 (J1): 启动即 monkeypatch socket.socket 为守卫,禁止任何出站连接。
唯一例外 --verify-registry 经隔离子进程(verify_registry.py,设 BACKDOOR_CHECK_OUTBOUND=1)运行。

参考 /doctor 的 checkup 逻辑: 扫描 → 诊断 → 分级报告 → 可选修复建议。

用法:
    python3 check.py --self-check                 # 自身安全验证(静态+运行时)
    python3 check.py --mode quick                 # 快速扫描
    python3 check.py --mode interactive           # 交互式全量体检
    python3 check.py --mode deep                  # 深度取证(含 sudo 指引)
    python3 check.py --dim network                # 单维度
    python3 check.py --mode ci --format json      # CI 模式(JSON+退出码)
    python3 check.py --audit                      # 干跑: 打印将执行的命令
    python3 check.py --verify-registry            # 受控外联: 校验 npm 包完整性
"""
from __future__ import annotations

import os
import sys
import argparse
import json
import subprocess
import hashlib
import socket
from datetime import datetime

# ===== 路径设置 =====
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(SCRIPTS_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

# ===== J1 运行时无外联守卫 (必须在任何可能联网的 import 之后、使用之前挂载) =====


class OutboundBlockedError(Exception):
    """出站连接被守卫拦截。"""


class _GuardedSocket(socket.socket):
    """守卫 socket: 允许构造,但禁止任何出站连接。"""

    def connect(self, address, *args, **kwargs):
        raise OutboundBlockedError(
            "backdoor-check 禁止出站连接(自身安全保证 J1)。"
            "唯一例外: --verify-registry 经隔离子进程 verify_registry.py 运行。"
        )

    def connect_ex(self, address, *args, **kwargs):
        raise OutboundBlockedError("backdoor-check 禁止出站连接(connect_ex)。")


def _guard_create_connection(address, *args, **kwargs):
    raise OutboundBlockedError("backdoor-check 禁止出站连接(create_connection)。")


# 仅当未显式设置 BACKDOOR_CHECK_OUTBOUND=1 时挂载守卫(verify_registry 子进程会设此 env)
RUNTIME_GUARDED = not os.environ.get("BACKDOOR_CHECK_OUTBOUND")
if RUNTIME_GUARDED:
    socket.socket = _GuardedSocket
    socket.create_connection = _guard_create_connection


# ===== 引擎导入 =====
from engine import report as _report  # noqa: E402
from engine import platform as _platform  # noqa: E402


# ===== 维度映射 =====

# 维度代号 → (英文短名, 中文描述)
DIMENSIONS = {
    "A": ("version", "版本与供应链"),
    "B": ("network", "网络外联"),
    "C": ("fingerprint", "设备指纹"),
    "D": ("hooks", "Hooks"),
    "E": ("mcp", "MCP"),
    "F": ("api", "API/凭证"),
    "G": ("permissions", "权限/危险配置"),
    "H": ("plugins", "插件供应链"),
    "I": ("steganography", "Prompt隐写"),
}

# 模式 → 默认维度集
MODE_DIMS = {
    "interactive": list("ABCDEFGHI"),
    "quick": list("ABCDEFGHI"),       # quick 跑廉价静态子集,由各维度模块自行选静态分支
    "deep": list("ABCDEFGHI"),
    "ci": ["A", "B", "F", "I"],           # CI 默认核心三维度,可用 --dims 覆盖
}


# ===== 自身安全验证 =====

def test_runtime_guard() -> tuple:
    """验证运行时 socket 守卫已挂载且能拦截出站连接。"""
    if not RUNTIME_GUARDED:
        return False, "运行时守卫未启用(本进程检测到 BACKDOOR_CHECK_OUTBOUND,非主进程场景)"
    try:
        s = socket.socket()
        try:
            s.connect(("1.1.1.1", 80))
        finally:
            try:
                s.close()
            except Exception:
                pass
        return False, "守卫失败: 出站连接未被拦截(J1 运行时保证失效)"
    except OutboundBlockedError:
        return True, "运行时守卫生效: 出站连接被 OutboundBlockedError 拦截"
    except Exception as e:
        # 非 OutboundBlockedError 的失败: 未连上但非守卫拦,标记可疑
        return False, "守卫未明确生效(连接因 %s 失败,非 OutboundBlockedError)" % type(e).__name__


def run_selfcheck() -> int:
    """J1 静态 + 运行时双验证。"""
    import selfcheck
    static_ok, static_text = selfcheck.run_static_selfcheck(SCRIPTS_DIR)
    rt_ok, rt_text = test_runtime_guard()
    print(static_text)
    print()
    print("=== 运行时守卫测试 (J1 运行时层) ===")
    print(rt_text)
    print()
    print("=== 脱敏验证 (J2) ===")
    sample = 'ANTHROPIC_AUTH_TOKEN="0123456789abcdef0123456789abcdef.FakeSampleKeyNotReal" sk-proj-abc123XYZ'
    print("原始: %s" % sample)
    print("脱敏: %s" % _report.redact(sample))
    print()
    if static_ok and rt_ok:
        print("结论: ✅ 自身安全验证通过(静态无外联 + 运行时守卫 + 脱敏生效)")
        return 0
    print("结论: 🚨 自身安全验证未通过")
    return 1


# ===== 受控外联 (verify-registry 子进程隔离) =====

def run_verify_registry(package: str, version: str, local_sha512: str = None) -> int:
    """以隔离子进程运行 verify_registry.py(设 BACKDOOR_CHECK_OUTBOUND=1 解除守卫)。

    主进程始终无外联;仅此子进程在隔离上下文连接官方 registry。
    """
    env = dict(os.environ)
    env["BACKDOOR_CHECK_OUTBOUND"] = "1"
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, "verify_registry.py"),
           "--package", package, "--version", version]
    if local_sha512:
        cmd += ["--local-sha512", local_sha512]
    print("[check] 启动隔离子进程执行受控外联(主进程守卫不变):")
    print("  命令: %s" % " ".join(cmd))
    p = subprocess.run(cmd, env=env)
    return p.returncode


# ===== adapter 发现 (fallback, Phase 2 接入完整 adapter) =====

def discover_tool(tool_arg: str = None) -> "_report.ToolInfo":
    """发现待检测工具。Phase 1 用 fallback 直接探测 claude-code。"""
    info = _report.ToolInfo()
    # 优先尝试完整 adapter(Phase 2)
    try:
        from adapters import claude_code as _cc
        discovered = _cc.discover()
        if discovered:
            info.name = "claude-code"
            info.version = discovered.get("version", "")
            info.source = discovered.get("source", "")
            info.path = discovered.get("path", "")
            info.package_path = discovered.get("package_path", "")
            return info
    except Exception:
        pass
    # fallback: 直接探测 claude CLI
    info.name = tool_arg or "claude-code"
    claude_bin = _platform.which("claude")
    if claude_bin:
        info.path = claude_bin
        rc, out, _ = _platform.run(["claude", "--version"], timeout=10)
        if rc == 0:
            info.version = out.strip().split()[0] if out.strip() else ""
        info.source = "npm:@anthropic-ai/claude-code (fallback 探测)"
    else:
        info.source = "未发现(fallback)"
    return info


# ===== 维度调度 =====

def collect_platform_info() -> "_report.PlatformInfo":
    pi = _report.PlatformInfo()
    pi.os = _platform.detect_os()
    pi.arch = _platform.detect_arch()
    try:
        hn = os.uname()[1]
        pi.hostname_hash = hashlib.sha256(hn.encode("utf-8", "replace")).hexdigest()[:8]
    except Exception:
        pi.hostname_hash = ""
    return pi


def run_dimensions(dims: list, mode: str, tool_info: "_report.ToolInfo",
                   platform_info: "_report.PlatformInfo", report_obj: "_report.Report") -> None:
    """调度各维度检测。Phase 1: 模块未实现的维度记 info;Phase 3 填充真实检测。"""
    rules = load_rules()
    ctx = {
        "mode": mode,
        "tool": tool_info,
        "platform": platform_info,
        "rules": rules,
        "scripts_dir": SCRIPTS_DIR,
    }

    # 维度代号 → (engine 模块名, check 函数名)
    dim_modules = {
        "A": ("engine.version", "check"),
        "B": ("engine.network", "check"),
        "C": ("engine.fingerprint", "check"),
        "D": ("engine.config_audit", "check_hooks"),
        "E": ("engine.config_audit", "check_mcp"),
        "F": ("engine.config_audit", "check_api"),
        "G": ("engine.config_audit", "check_permissions"),
        "H": ("engine.config_audit", "check_plugins"),
        "I": ("engine.steganography", "check"),
    }
    for code in dims:
        en_name, cn_desc = DIMENSIONS.get(code, (code.lower(), code))
        mod_spec = dim_modules.get(code)
        if not mod_spec:
            report_obj.add(_report.Finding(
                id=code, dim=en_name, severity="info",
                title="未知维度 %s" % code))
            continue
        mod_name, func_name = mod_spec
        try:
            mod = __import__(mod_name, fromlist=[func_name])
            func = getattr(mod, func_name)
            findings = func(ctx) or []
            for f in findings:
                report_obj.add(f)
        except ImportError:
            report_obj.add(_report.Finding(
                id=code, dim=en_name, severity="info",
                title="%s维度检测待接入(模块 %s 尚未实现)" % (cn_desc, mod_name)))
        except Exception as e:
            report_obj.add(_report.Finding(
                id=code, dim=en_name, severity="warn",
                title="%s维度检测异常" % cn_desc, evidence=str(e)[:300],
                remediation="查看错误信息,可能是平台命令缺失或配置解析失败"))


def load_rules() -> dict:
    """加载规则库 JSON。缺失则返回空 dict(各维度优雅降级)。"""
    rules_dir = os.path.join(SCRIPTS_DIR, "rules")
    rules = {}
    for fn in os.listdir(rules_dir) if os.path.isdir(rules_dir) else []:
        if not fn.endswith(".json"):
            continue
        key = fn[:-5]
        try:
            with open(os.path.join(rules_dir, fn), "r", encoding="utf-8") as f:
                rules[key] = json.load(f)
        except Exception:
            rules[key] = None
    return rules


# ===== 审计模式 (monkeypatch platform.run 为打印) =====

def enable_audit_mode() -> None:
    """--audit: 把 platform.run 替换为"只打印不执行",反映所有将运行的系统命令。"""
    def _audit_run(cmd, timeout=10):
        # 命令可能含路径,轻度脱敏 home
        cmd_str = " ".join(str(c) for c in cmd)
        home = os.path.expanduser("~")
        if home in cmd_str:
            cmd_str = cmd_str.replace(home, "~")
        print("[audit] 将执行: %s" % cmd_str)
        return 0, "", ""
    _platform.run = _audit_run


# ===== 主流程 =====

def main() -> int:
    ap = argparse.ArgumentParser(
        description="backdoor-check: AI 编程工具后门检测(纯本地、无出站、报告脱敏)")
    ap.add_argument("--mode", choices=list(MODE_DIMS.keys()), default="interactive",
                    help="扫描模式: interactive/quick/deep/ci(默认 interactive)")
    ap.add_argument("--dim", help="单维度检查: network/version/hooks/mcp/api/permissions/plugins/fingerprint 或代号 A-H")
    ap.add_argument("--dims", help="逗号分隔的多维度,如 A,B,F(覆盖 mode 默认)")
    ap.add_argument("--tool", help="指定工具(默认 auto-discover claude-code)")
    ap.add_argument("--format", choices=["text", "markdown", "json"], help="输出格式(默认: ci→json, 其他→markdown)")
    ap.add_argument("--out", help="输出到文件(默认 stdout)")
    ap.add_argument("--audit", action="store_true", help="干跑: 只打印将执行的命令,不实际检测")
    ap.add_argument("--verify-registry", action="store_true",
                    help="受控外联: 对照官方 npm registry 校验包完整性(检测源码泄露类篡改)")
    ap.add_argument("--self-check", action="store_true", help="自身安全验证(静态无外联+运行时守卫+脱敏)")
    ap.add_argument("--check-latest", action="store_true", help="A4: 检查版本是否落后于最新(需受控外联)")
    args = ap.parse_args()

    # --- 自身验证 ---
    if args.self_check:
        return run_selfcheck()

    # --- 受控外联 ---
    if args.verify_registry:
        package = "@anthropic-ai/claude-code"
        version = "latest"
        # 尝试用当前版本
        tool = discover_tool(args.tool)
        if tool.version:
            version = tool.version
        return run_verify_registry(package, version)

    # --- 审计模式 ---
    if args.audit:
        enable_audit_mode()
        print("=== backdoor-check 审计模式(干跑,不实际执行任何命令) ===")

    # --- 确定维度集 ---
    if args.dim:
        dims = resolve_dim(args.dim)
    elif args.dims:
        dims = [d.strip().upper() for d in args.dims.split(",") if d.strip()]
    else:
        dims = MODE_DIMS.get(args.mode, list("ABCDEFGH"))

    # --- 收集信息 ---
    tool_info = discover_tool(args.tool)
    platform_info = collect_platform_info()

    # --- 构建报告 ---
    rep = _report.Report(tool=tool_info, platform=platform_info, scan_mode=args.mode)
    rep.generated_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    # 静态层实际扫描(反映真实状态,非硬编码)
    try:
        import selfcheck as _sc
        _static_ok, _ = _sc.run_static_selfcheck(SCRIPTS_DIR)
    except Exception:
        _static_ok = False
    rep.self_check = _report.SelfCheckInfo(
        no_outbound_static=_static_ok,
        no_outbound_runtime=RUNTIME_GUARDED,
        redaction=True)

    # --- 调度维度 ---
    run_dimensions(dims, args.mode, tool_info, platform_info, rep)

    # --- 深度模式附加 sudo 取证指引 ---
    if args.mode == "deep":
        rep.add(_report.Finding(
            id="DEEP", dim="forensics", severity="info",
            title="深度取证指引(需 sudo,默认不执行)",
            evidence=_platform.detect_os() + " 平台: 参考 references/deep-water.md",
            remediation="授权后执行 dtrace/strace/tcpdump 进行行为级取证(是否实际外传指纹)"))

    # --- 输出 ---
    fmt = args.format or ("json" if args.mode == "ci" else "markdown")
    if fmt == "json":
        out = rep.to_json()
    elif fmt == "text":
        out = rep.to_text()
    else:
        out = rep.to_markdown()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print("报告已写入: %s" % args.out, file=sys.stderr)
    else:
        print(out)

    # --- 退出码(CI 模式严格;其他模式也按 severity) ---
    return rep.exit_code()


def resolve_dim(dim: str) -> list:
    """dim 可以是代号(A)或英文短名(network)。返回代号列表。"""
    dim = dim.strip()
    # 代号
    if dim.upper() in DIMENSIONS:
        return [dim.upper()]
    # 英文短名反查
    for code, (en, _cn) in DIMENSIONS.items():
        if en == dim.lower():
            return [code]
    print("未知维度: %s(可用: A-H 或 network/version/hooks/mcp/api/permissions/plugins/fingerprint)" % dim,
          file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
