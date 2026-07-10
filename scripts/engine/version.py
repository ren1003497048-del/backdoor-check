# -*- coding: utf-8 -*-
"""A 维度: 版本与供应链完整性。

A1 版本区间(NVDB 2.1.91-2.1.196 等后门区间)/ A2 包来源(scope·registry·typosquat)
A3 完整性(sha512 基线 diff)/ A4 版本新鲜度

A3 的官方 registry 校验由 --verify-registry 独立入口(受控外联)触发,常规 check 只做本地基线 diff。
"""
from __future__ import annotations

import os
import json
from typing import List

from engine import fs
from engine.report import Finding
from adapters import base


def _parse_ver(v: str) -> tuple:
    """'2.1.205' -> (2, 1, 205)。非数字段按 0。"""
    parts = []
    for seg in (v or "").split("."):
        num = ""
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _in_range(v: str, gte: str, lte: str) -> bool:
    pv = _parse_ver(v)
    return _parse_ver(gte) <= pv <= _parse_ver(lte)


def _write_baseline(path: str, current: dict, tool) -> None:
    """冷启动时写入基线(技能自身状态文件,非用户配置)。"""
    try:
        payload = {
            "tool": {"name": tool.name, "version": tool.version, "source": tool.source},
            "integrity": current,
            "note": "backdoor-check 完整性基线。篡改会使后续扫描 A3 报 crit。可删除本文件重建。"
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def check(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    tool = ctx["tool"]
    version = tool.version
    advisories = (rules.get("advisories") or {}).get("advisories", [])
    allowlist_tool = (rules.get("allowlist") or {}).get("by_tool", {}).get(tool.name, {})

    adapter = base.load_adapter(tool.name)

    # ---- A1 版本区间 ----
    if not version:
        findings.append(Finding(
            id="A1", dim="version", severity="warn",
            title="无法确定工具版本",
            evidence="adapter discover() 未返回版本号",
            remediation="确认工具已安装且 CLI --version 可用"))
    else:
        hit = None
        for adv in advisories:
            if tool.name not in adv.get("tools", []):
                continue
            for rng in adv.get("affected_ranges", []):
                gte, lte = rng.get("gte"), rng.get("lte")
                if gte and lte and _in_range(version, gte, lte):
                    hit = (adv, rng)
                    break
            if hit:
                break
        if hit:
            adv, rng = hit
            findings.append(Finding(
                id="A1", dim="version", severity="crit",
                title="版本落在已知后门区间: %s" % adv["title"],
                evidence="当前 %s 落在后门区间 %s~%s" % (version, rng["gte"], rng["lte"]),
                advisory=adv["id"],
                remediation=adv.get("remediation", "升级到修复版本")))
        else:
            findings.append(Finding(
                id="A1", dim="version", severity="pass",
                title="版本 %s 不在任何已知后门区间" % version,
                evidence="已比对 %d 条 advisory(含 NVDB 2.1.91-2.1.196),均未命中" % len(advisories)))

    # ---- A2 包来源 ----
    official_pkg = allowlist_tool.get("official_package")
    if official_pkg and official_pkg in (tool.source or ""):
        findings.append(Finding(
            id="A2", dim="version", severity="pass",
            title="包来源为官方: %s" % official_pkg,
            evidence="source=%s" % tool.source))
    else:
        findings.append(Finding(
            id="A2", dim="version", severity="warn",
            title="包来源非官方或无法确认",
            evidence="source=%s (期望含 %s)" % (tool.source or "未知", official_pkg or "官方包名"),
            remediation="核对安装来源,警惕 typosquat 仿冒包名"))

    # ---- A3 完整性(基线 diff)----
    targets = adapter.integrity_targets() if adapter else []
    current = {}
    for t in targets:
        h = fs.file_hash(t)
        if h:
            # 路径脱敏: 用相对包名的短路径
            short = t
            if tool.package_path and t.startswith(tool.package_path):
                short = "<pkg>/" + t[len(tool.package_path):].lstrip("/")
            current[short] = h

    baseline_path = os.path.join(ctx["scripts_dir"], "baseline.json")
    baseline = fs.read_json(baseline_path) or {}
    baseline_files = (baseline.get("integrity") or {}) if isinstance(baseline, dict) else {}

    if not current:
        findings.append(Finding(
            id="A3", dim="version", severity="info",
            title="无完整性目标文件(未发现包目录)",
            remediation="确认工具安装路径"))
    elif not baseline_files:
        _write_baseline(baseline_path, current, tool)
        findings.append(Finding(
            id="A3", dim="version", severity="info",
            title="完整性基线已建立(首次扫描)",
            evidence="记录 %d 个文件哈希到 baseline.json;后续扫描将 diff 检测篡改" % len(current),
            remediation="建议在可信时刻建立基线;可用 --verify-registry 对照官方 registry"))
    else:
        modified = [p for p, h in current.items() if p in baseline_files and baseline_files[p] != h]
        added = [p for p in current if p not in baseline_files]
        removed = [p for p in baseline_files if p not in current]
        if modified:
            findings.append(Finding(
                id="A3", dim="version", severity="crit",
                title="完整性篡改: %d 个文件哈希变化" % len(modified),
                evidence="变更: %s" % ", ".join(modified[:5]),
                advisory="claude-code-leak-2026-03",
                remediation="包文件被修改,可能被植入恶意代码。用 --verify-registry 对照官方;不信任则重装"))
        elif added or removed:
            findings.append(Finding(
                id="A3", dim="version", severity="warn",
                title="完整性文件集变化(新增%d 删除%d)" % (len(added), len(removed)),
                evidence="可能是版本更新;若非主动更新需警惕",
                remediation="若刚升级,删除 baseline.json 重建基线"))
        else:
            findings.append(Finding(
                id="A3", dim="version", severity="pass",
                title="完整性校验通过: %d 个文件哈希与基线一致" % len(current)))

    # ---- A4 版本新鲜度 ----
    findings.append(Finding(
        id="A4", dim="version", severity="info",
        title="版本新鲜度: 当前 %s" % (version or "未知"),
        evidence="可用 --check-latest 对照官方最新版(受控外联,默认关闭)",
        remediation="定期更新到最新修复版本;后门修复通常在新版本"))

    return findings
