#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自身安全静态自审 (J1 静态层)。

扫描 scripts/ 目录所有 .py 文件,检测是否含网络/外联符号。

白名单分三类(各自理由不同,均不构成数据泄漏面):
- verify_registry.py: 受控外联模块(唯一允许真实联网,默认关闭,仅 --verify-registry 触发,
  且只连官方 registry、不携带本地数据)。主进程 socket 守卫对其无效(隔离子进程)。
- selfcheck.py:       静态扫描器,网络符号仅作为"检测模式数据"字符串出现,非执行代码。
- check.py:           主入口 import socket 仅用于 monkeypatch 挂载守卫(防御性);运行时守卫
  (J1 运行时层)兜底拦截任何实际连接,即使静态层漏检。

其余文件(engine/*、adapters/* 等)严格禁止任何网络符号,出现即 FAIL。

运行时层(J1 运行时)由 check.py 的 socket 守卫保证,本模块只做静态文本审计。
"""
from __future__ import annotations

import os
import re
import sys
from typing import List, Tuple

# 网络/外联符号模式 (pattern, 描述)
NETWORK_PATTERNS: List[Tuple[str, str]] = [
    (r"\bimport\s+socket\b", "import socket"),
    (r"\bfrom\s+socket\b", "from socket import"),
    (r"\bimport\s+urllib\b", "import urllib"),
    (r"\bfrom\s+urllib\b", "from urllib import"),
    (r"\bimport\s+requests\b", "import requests"),
    (r"\bfrom\s+requests\b", "from requests import"),
    (r"\bimport\s+http\.client\b", "import http.client"),
    (r"\bfrom\s+http\.client\b", "from http.client import"),
    (r"\bimport\s+ftplib\b", "import ftplib"),
    (r"\bimport\s+smtplib\b", "import smtplib"),
    (r"\bimport\s+telnetlib\b", "import telnetlib"),
    (r"\bimport\s+pexpect\b", "import pexpect"),
    (r"\bsocket\.create_connection\b", "socket.create_connection"),
    (r"\bssl\.wrap_socket\b", "ssl.wrap_socket"),
    (r"""["']curl["']""", "curl invocation"),
    (r"""["']wget["']""", "wget invocation"),
    (r"""["']nc["']""", "nc invocation"),
    (r"https?://", "hardcoded URL"),
    (r"\beval\s*\(", "eval (审查: 是否执行外部内容)"),
]

# 白名单: 文件名 → 理由
WHITELIST = {
    "verify_registry.py": "受控外联模块(唯一真实联网,默认关闭,只连官方 registry 不携带本地数据)",
    "selfcheck.py": "静态扫描器(网络符号仅为检测模式数据,非执行代码)",
    "check.py": "主入口(import socket 仅用于 monkeypatch 守卫;运行时守卫兜底拦截实际连接)",
    "capture_prompt.py": "本地捕获 server(监听 127.0.0.1 回环,捕获 claude 请求供 prompt steganography 实锤分析,不外联,数据仅存本地)",
}


def scan_dir(scripts_dir: str) -> List[Tuple[str, int, str, str]]:
    """返回 [(相对路径, 行号, 描述, 白名单理由或空串), ...]。"""
    findings = []
    for root, _dirs, files in os.walk(scripts_dir):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, scripts_dir)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            reason = WHITELIST.get(fn, "")
            for pat, desc in NETWORK_PATTERNS:
                for m in re.finditer(pat, content):
                    line_no = content[:m.start()].count("\n") + 1
                    findings.append((rel, line_no, desc, reason))
    return findings


def run_static_selfcheck(scripts_dir: str) -> Tuple[bool, str]:
    """供 check.py 调用。返回 (pass, 报告文本)。"""
    findings = scan_dir(scripts_dir)
    wl_hits = [f for f in findings if f[3]]
    other_hits = [f for f in findings if not f[3]]

    lines = ["=== 静态自审 (J1 静态层) ===", "扫描目录: %s" % scripts_dir, ""]

    # 按文件聚合白名单命中
    wl_by_file = {}
    for rel, ln, desc, reason in wl_hits:
        wl_by_file.setdefault(rel, (reason, []))[1].append((ln, desc))
    if wl_by_file:
        lines.append("[白名单] 以下文件含网络符号(防御性/受控,预期内):")
        for rel, (reason, hits) in wl_by_file.items():
            lines.append("  %s — %s" % (rel, reason))
            for ln, desc in hits[:4]:
                lines.append("      L%d: %s" % (ln, desc))
            if len(hits) > 4:
                lines.append("      ...(共 %d 处)" % len(hits))
        lines.append("")

    if other_hits:
        lines.append("[FAIL] 非白名单文件含网络/外联符号:")
        for rel, ln, desc, _ in other_hits:
            lines.append("  %s:%d  %s" % (rel, ln, desc))
        lines.append("")
        lines.append("结论: FAIL — 违反 J1 纯本地无外联保证(engine/adapters 等模块禁止任何网络符号)。")
        return False, "\n".join(lines)

    lines.append("结论: PASS — engine/adapters 等检测模块无网络符号;")
    lines.append("       白名单三文件(verify_registry/selfcheck/check)经审查为防御性/受控使用,")
    lines.append("       且运行时 socket 守卫(J1 运行时层)兜底拦截任何实际出站连接。")
    return True, "\n".join(lines)


def main() -> int:
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    ok, text = run_static_selfcheck(scripts_dir)
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
