# -*- coding: utf-8 -*-
"""I 维度: Prompt Steganography 确定性检测。

基于独立研究者 Thereallo(2026-06-30, thereallo.dev)对 Claude Code 2.1.196 的逆向,
Anthropic 工程师 Thariq Shihipar 已确认。机制: 按 base_url + 时区触发,改 system prompt
的 "Today's date is ..." 撇号(U+2019/U+02BC/U+02B9)与日期分隔符(- -> /),
域名列表用 XOR(91)+base64 混淆。标记随请求发给模型提供商。

本维度做**确定性检测**(非启发式):
- I1 静态签名 + XOR(91)解码: 命中即确认该版本含后门逻辑(crit)
- I2 触发条件评估: 你的 base_url + 时区是否为后门目标(配置层,关联 F1)

时间线: 2.1.91 引入,2026-07-01(约 2.1.197+)移除。
"""
from __future__ import annotations

import os
import re
import base64
from typing import List, Tuple

from engine import binary, fs
from engine.report import Finding
from adapters import base


def _get_iana_tz() -> str:
    """读取本机 IANA 时区名(等价 JS Intl.DateTimeFormat().resolvedOptions().timeZone)。

    macOS: /etc/localtime -> /var/db/timezone/zoneinfo/Asia/Shanghai
    Linux: /etc/localtime -> ../usr/share/zoneinfo/Asia/Shanghai
    """
    try:
        link = os.readlink("/etc/localtime")
        if "zoneinfo/" in link:
            return link.split("zoneinfo/")[-1]
    except Exception:
        pass
    return ""


def _extract_host(url: str) -> str:
    s = url or ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if ":" in s:
        s = s.rsplit(":", 1)[0]
    return s.lower().strip("[]")


def scan_base64_xor(text: str, keywords: List[str], key: int = 91) -> List[Tuple[str, str]]:
    """扫描文本里的 base64 串,解码后在 XOR(key) 字节空间搜关键词。

    原理: 混淆形式 = base64( XOR_key(原文) )。
    base64 解码得 XOR_key(原文);关键词 K 在原文中 <==> XOR_key(K) 在解码字节中。
    故对每个关键词预算 XOR_key(K) 字节序列,在 raw 里直接字节搜索(高效,免全文解码)。
    返回 [(keyword, blob前缀), ...]。
    """
    kw_xor = {kw: bytes(ord(c) ^ key for c in kw) for kw in keywords}
    hits: List[Tuple[str, str]] = []
    seen = set()
    for m in re.finditer(r"[A-Za-z0-9+/]{40,300}={0,2}", text):
        blob = m.group(0)
        if blob in seen:
            continue
        seen.add(blob)
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        for kw, kxor in kw_xor.items():
            if kxor in raw:
                hits.append((kw, blob[:48]))
    return hits


def check(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    adapter = base.load_adapter(ctx["tool"].name)

    fp = rules.get("fingerprints") or {}
    steg = fp.get("steganography") or {}
    tz_triggers = steg.get("timezone_triggers", ["Asia/Shanghai", "Asia/Urumqi"])
    lab_kw = steg.get("lab_keywords", [])
    xor_key = steg.get("xor_key", 91)

    targets = adapter.integrity_targets() if adapter else []
    bin_path = next((t for t in targets if t.endswith("claude.exe") or t.endswith("claude")), None)
    if not bin_path:
        findings.append(Finding(id="I1", dim="steganography", severity="info",
                                title="无二进制目标,跳过 prompt steganography 检测"))
        return findings

    text = binary.extract_strings(bin_path)

    # ---- I1: 确定性签名 ----
    tz_hits = binary.scan_literal(text, tz_triggers)
    xor_hits = scan_base64_xor(text, lab_kw, xor_key) if lab_kw else []
    replace_hits = binary.scan_literal(text, ['replaceAll("-", "/")', "resolvedOptions().timeZone"])

    confirmed = bool(tz_hits or xor_hits)
    if confirmed:
        ev = []
        if tz_hits:
            ev.append("时区判断明文: %s" % ", ".join(h[0] for h in tz_hits))
        if xor_hits:
            ev.append("XOR(%d)解码域名列表命中: %s" % (xor_key, ", ".join(sorted(set(h[0] for h in xor_hits)))))
        if replace_hits:
            ev.append("日期替换/时区解析符号: %s" % ", ".join(h[0] for h in replace_hits[:3]))
        findings.append(Finding(
            id="I1", dim="steganography", severity="crit",
            title="确认含 prompt steganography 后门逻辑(Thereallo 逆向特征)",
            evidence="; ".join(ev),
            advisory="claude-code-prompt-steganography-2026",
            remediation="升级到 2.1.197+(2026-07-01 已移除)。该版本按 base_url+时区在 system prompt 注入隐写标记(撇号 U+2019/02BC/02B9 + 日期 - -> /)"))
    else:
        findings.append(Finding(
            id="I1", dim="steganography", severity="pass",
            title="未检出 prompt steganography 后门签名(该版本已移除)",
            evidence="时区判断字符串=0; XOR(%d)解码域名列表无命中" % xor_key))

    # ---- I2: 触发条件评估(配置层,关联 F1)----
    reasons = []
    home = os.path.expanduser("~")
    settings = fs.read_json(os.path.join(home, ".claude", "settings.json")) or {}
    base_url = (settings.get("env") or {}).get("ANTHROPIC_BASE_URL", "")
    if base_url:
        host = _extract_host(base_url)
        lab_hit = next((kw for kw in lab_kw if kw in host), None)
        if lab_hit:
            reasons.append("base_url host(%s)含实验室关键词 %s" % (host, lab_hit))
        elif "anthropic.com" not in host:
            reasons.append("base_url 指向非官方 %s(可能为中国代理)" % host)
    iana = _get_iana_tz()
    if iana:
        if iana in tz_triggers:
            reasons.append("本机 IANA 时区 %s 命中后门时区触发" % iana)
    if reasons:
        # 当前版本已移除逻辑时为 info(历史风险提示);仍含逻辑时为 warn(正在被标记)
        sev = "warn" if confirmed else "info"
        findings.append(Finding(
            id="I2", dim="steganography", severity=sev,
            title="你的配置是 prompt steganography 后门的触发目标",
            evidence="; ".join(reasons),
            advisory="claude-code-prompt-steganography-2026",
            remediation="当前版本已移除该逻辑;但若 2026-04-02~07-01 曾用 2.1.91-2.1.196,历史请求已被标记"))

    return findings
