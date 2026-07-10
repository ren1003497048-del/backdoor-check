# -*- coding: utf-8 -*-
"""报告与脱敏模块。

职责:
- Finding: 单条检测结果数据结构
- redact(): 中心化脱敏,所有输出必经此函数,保证凭证不泄漏
- Report: 装配 findings、分级汇总、JSON/markdown/text 输出、退出码

自身安全: 本模块不发起任何网络请求,纯本地字符串处理。
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


# ---------- 严重度 ----------

# crit=🚨 高危(后门/凭证泄露/任意执行) warn=⚠️ 中危(风险面/加固建议)
# pass=✅ 安全 info=ℹ️ 信息性(不参与退出码)
SEVERITY = {
    "crit": ("🚨", "高危"),
    "warn": ("⚠️", "中危"),
    "pass": ("✅", "安全"),
    "info": ("ℹ️", "信息"),
}
SEVERITY_RANK = {"crit": 3, "warn": 2, "pass": 1, "info": 0}


@dataclass
class Finding:
    """单条检测结果。"""
    id: str                 # 检查项编号,如 A1 / B3 / F1
    dim: str                # 维度英文短名,如 version / network / api
    severity: str           # crit / warn / pass / info
    title: str              # 一句话标题
    evidence: str = ""      # 证据(会自动脱敏)
    remediation: str = ""   # 修复建议
    advisory: str = ""      # 关联的已知事件标识,如 nvdb-2026-07-08

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "dim": self.dim,
            "severity": self.severity,
            "title": self.title,
            "evidence": redact(self.evidence),
            "remediation": self.remediation,
            "advisory": self.advisory,
        }


# ---------- 中心化脱敏 (J2) ----------
# 辅助函数须在 _SECRET_PATTERNS 之前定义(后者在模块加载时立即求值)


def _hash8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:8]


def _bearer_redact(m: re.Match) -> str:
    return m.group(1) + "<redacted:len=%d:hash=%s>" % (len(m.group(2)), _hash8(m.group(2)))


def _anthropic_token_redact(m: re.Match) -> str:
    full = m.group(1) + "." + m.group(2)
    return "<redacted:len=%d:hash=%s>" % (len(full), _hash8(full))


def _sk_redact(m: re.Match) -> str:
    return "<redacted:len=%d:hash=%s>" % (len(m.group(1)), _hash8(m.group(1)))


def _kv_redact(m: re.Match) -> str:
    return m.group(1) + "<redacted:len=%d:hash=%s>" % (len(m.group(2)), _hash8(m.group(2)))


def _long_hex_redact(m: re.Match) -> str:
    return "<redacted:len=%d:hash=%s>" % (len(m.group(1)), _hash8(m.group(1)))


def _long_b64_redact(m: re.Match) -> str:
    return "<redacted:len=%d:hash=%s>" % (len(m.group(1)), _hash8(m.group(1)))


# 敏感模式集合。命中任一即替换为脱敏占位符。
# 占位符保留长度与前8位 sha256 指纹,便于用户比对是否同一凭证而不暴露原文。
_SECRET_PATTERNS = [
    # 私钥头(整块脱敏,不逐行)
    (re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL),
     "<redacted:private-key>"),
    # Bearer token
    (re.compile(r"([Bb]earer\s+)([A-Za-z0-9_\-\.=]{20,})", re.DOTALL), _bearer_redact),
    # Anthropic 风格 token: hex.随机串  (如 9433a9ac....MEQn)
    (re.compile(r"\b([A-Fa-f0-9]{16,64})\.([A-Za-z0-9_\-]{8,})\b"), _anthropic_token_redact),
    # OpenAI / 通用 sk- 前缀
    (re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,})\b"), _sk_redact),
    # key/value 形式: TOKEN=xxx / "api_key": "xxx" / api-key: xxx
    (re.compile(r"(?i)((?:api[_\-]?key|auth[_\-]?token|access[_\-]?token|secret|password|passwd|token)"
                r"\s*[:=]\s*[\"']?)([^\s\"',}\]]{8,})", re.DOTALL), _kv_redact),
    # 超长 hex / base64 串(>=40 字符连续),可能是密钥/机器标识
    (re.compile(r"\b([A-Fa-f0-9]{40,})\b"), _long_hex_redact),
    (re.compile(r"\b([A-Za-z0-9+/]{40,}={0,2})\b"), _long_b64_redact),
]


def redact(text: str) -> str:
    """中心化脱敏。任何写入报告/日志的字符串都应先经此函数。

    设计原则:
    - 宁可误脱敏(把长串当密钥),不可漏脱敏
    - 占位符保留长度+sha256前8位,便于用户自行比对而不暴露原文
    """
    if not text:
        return text
    out = text
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl if isinstance(repl, str) else repl, out)
    return out


# ---------- 报告装配 ----------

@dataclass
class ToolInfo:
    name: str = "unknown"
    version: str = ""
    source: str = ""        # 如 npm:@anthropic-ai/claude-code
    path: str = ""          # 二进制/包路径(home 目录在 to_dict 中替换为 ~)
    package_path: str = ""  # 包目录(内部用,版本/完整性维度;to_dict 不输出避免路径泄露)

    def to_dict(self) -> Dict[str, Any]:
        p = self.path
        home = os.path.expanduser("~")
        if p and home in p:
            p = p.replace(home, "~")
        return {"name": self.name, "version": self.version, "source": self.source, "path": p}


@dataclass
class PlatformInfo:
    os: str = ""
    arch: str = ""
    hostname_hash: str = ""  # 主机名哈希,不存明文

    def to_dict(self) -> Dict[str, Any]:
        return {"os": self.os, "arch": self.arch, "hostname_hash": self.hostname_hash}


@dataclass
class SelfCheckInfo:
    no_outbound_static: bool = False    # 静态扫描无网络符号
    no_outbound_runtime: bool = False   # 运行时 socket 守卫已启用
    redaction: bool = True              # 脱敏已启用

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    tool: ToolInfo = field(default_factory=ToolInfo)
    platform: PlatformInfo = field(default_factory=PlatformInfo)
    self_check: SelfCheckInfo = field(default_factory=SelfCheckInfo)
    schema_version: str = "1.0"
    generated_at: str = ""   # 由调用方传入
    scan_mode: str = "interactive"

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def summary(self) -> Dict[str, Any]:
        total = len(self.findings)
        d: Dict[str, Any] = {"total": total, "pass": 0, "warn": 0, "crit": 0, "info": 0}
        for f in self.findings:
            if f.severity in d:
                d[f.severity] += 1
        if total == 0:
            d["score"] = 100
        else:
            score = 100 - (d["crit"] * 25 + d["warn"] * 8)
            d["score"] = max(0, score)
        return d

    def exit_code(self) -> int:
        """0 全 pass / 1 有 warn / 2 有 crit。info 不影响。"""
        has_crit = any(f.severity == "crit" for f in self.findings)
        has_warn = any(f.severity == "warn" for f in self.findings)
        if has_crit:
            return 2
        if has_warn:
            return 1
        return 0

    def to_json(self) -> str:
        import json
        s = self.summary()
        payload = {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "scan_mode": self.scan_mode,
            "tool": self.tool.to_dict(),
            "platform": self.platform.to_dict(),
            "self_check": self.self_check.to_dict(),
            "summary": s,
            "findings": [f.to_dict() for f in self.findings],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def to_markdown(self) -> str:
        s = self.summary()
        lines = []
        lines.append("# 🛡️ backdoor-check 安全体检报告")
        lines.append("")
        lines.append("**扫描模式**: %s  |  **生成时间**: %s" % (self.scan_mode, self.generated_at or "未记录"))
        lines.append("**工具**: %s %s (`%s`)" % (self.tool.name, self.tool.version, self.tool.source or "未知来源"))
        lines.append("**平台**: %s/%s  |  **自身安全**: 静态无外联=%s 运行时守卫=%s 脱敏=%s" % (
            self.platform.os, self.platform.arch,
            self.self_check.no_outbound_static, self.self_check.no_outbound_runtime, self.self_check.redaction))
        lines.append("")
        lines.append("## 总览")
        lines.append("")
        lines.append("| 维度 | 状态 | 关键发现 |")
        lines.append("|------|------|----------|")
        dims: Dict[str, List[Finding]] = {}
        for f in self.findings:
            dims.setdefault(f.dim, []).append(f)
        for dim, fs in dims.items():
            top = max(fs, key=lambda x: SEVERITY_RANK.get(x.severity, 0))
            icon = SEVERITY.get(top.severity, ("•", ""))[0]
            titles = "; ".join(f.id + ":" + f.title for f in fs[:3])
            lines.append("| %s | %s %s | %s |" % (dim, icon, top.severity, redact(titles)))
        lines.append("")
        lines.append("**评分**: %d/100  (pass=%d  warn=%d  crit=%d  info=%d)" % (
            s["score"], s["pass"], s["warn"], s["crit"], s["info"]))
        lines.append("")
        for sev, (icon, label) in [("crit", SEVERITY["crit"]), ("warn", SEVERITY["warn"])]:
            items = [f for f in self.findings if f.severity == sev]
            if not items:
                continue
            lines.append("## %s %s问题(%d)" % (icon, label, len(items)))
            lines.append("")
            for f in items:
                lines.append("### [%s] %s" % (f.id, f.title))
                if f.advisory:
                    lines.append("> 关联事件: `%s`" % f.advisory)
                lines.append("**证据**: `%s`" % redact(f.evidence))
                lines.append("**建议**: %s" % f.remediation)
                lines.append("")
        pass_items = [f for f in self.findings if f.severity == "pass"]
        if pass_items:
            lines.append("## ✅ 通过项(%d)" % len(pass_items))
            lines.append("")
            for f in pass_items:
                lines.append("- [%s] %s" % (f.id, f.title))
            lines.append("")
        lines.append("---")
        lines.append("_声明: 二进制层为静态启发式检测,未发现 ≠ 不存在。详见 references/deep-water.md_")
        return "\n".join(lines)

    def to_text(self) -> str:
        """简表模式(quick/单维度)。"""
        lines = ["backdoor-check 简表  (工具=%s %s  平台=%s/%s)" % (
            self.tool.name, self.tool.version, self.platform.os, self.platform.arch)]
        lines.append("-" * 60)
        for f in self.findings:
            icon = SEVERITY.get(f.severity, ("•", ""))[0]
            lines.append("%s [%s] %s" % (icon, f.id, f.title))
            if f.evidence:
                lines.append("     证据: %s" % redact(f.evidence)[:200])
        s = self.summary()
        lines.append("-" * 60)
        lines.append("评分 %d/100  (pass=%d warn=%d crit=%d)" % (s["score"], s["pass"], s["warn"], s["crit"]))
        return "\n".join(lines)
