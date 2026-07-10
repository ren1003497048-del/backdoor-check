# -*- coding: utf-8 -*-
"""B 维度: 网络外联检测(后门事件核心)。

B1 进程连接快照 / B2 遥测端点命中(运行时+二进制strings) / B3 非必要流量开关有效性
B4 hosts·DNS 劫持 / B5 出站白名单比对 / B6 私网外联 / B7 TLS 校验禁用

后门特征(B3): 开关 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 但仍观测到遥测外联 → crit(开关失效/被绕过)。
"""
from __future__ import annotations

import ipaddress
from typing import List, Dict, Any

from engine import platform, binary, fs
from engine.report import Finding
from adapters import base


def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return False


def _host_of(addr: str) -> str:
    """连接 raddr 可能是 IP 或 host。返回小写 host/IP。"""
    if not addr:
        return ""
    # 去掉端口
    h = addr.rsplit(":", 1)[0] if ":" in addr and not addr.startswith("[") else addr
    return h.lower().strip("[]")


def _load_settings_env(adapter) -> dict:
    """读取 settings.json 的 env 字段。"""
    if not adapter:
        return {}
    for p in adapter.config_paths():
        if not p.endswith("settings.json"):
            continue
        d = fs.read_json(p)
        if isinstance(d, dict) and isinstance(d.get("env"), dict):
            return d["env"]
    return {}


def check(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    tool = ctx["tool"]
    mode = ctx.get("mode", "interactive")
    adapter = base.load_adapter(tool.name)

    ep_rules = rules.get("endpoints") or {}
    al_rules = rules.get("allowlist") or {}
    telemetry = {e["host"].lower(): e for e in ep_rules.get("telemetry_endpoints", [])}
    geoip = {e["host"].lower(): e for e in ep_rules.get("geoip_endpoints", [])}
    al_tool = (al_rules.get("by_tool") or {}).get(tool.name, {})
    official = set(h.lower() for h in al_tool.get("official_api_hosts", []))
    proxies = {p["host"].lower(): p for p in al_rules.get("known_third_party_proxies", [])}

    # ---- B3 非必要流量开关 ----
    env = _load_settings_env(adapter)
    disable_traffic = str(env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", ""))

    # ---- B4 hosts 劫持 ----
    hosts_text = platform.read_hosts()
    hijacked = []
    for h in official:
        for line in hosts_text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if h in line.lower():
                hijacked.append((h, line))
    if hijacked:
        findings.append(Finding(
            id="B4", dim="network", severity="crit",
            title="hosts 文件劫持官方 API 域名",
            evidence="被劫持: %s" % ", ".join("%s→%s" % (h, ln) for h, ln in hijacked[:3]),
            remediation="检查 /etc/hosts,移除非官方映射(API 流量可能被劫持到攻击者)"))
    else:
        findings.append(Finding(
            id="B4", dim="network", severity="pass",
            title="hosts 文件未劫持官方 API 域名"))

    # ---- B1 进程连接(quick 模式跳过,interactive/deep 执行)----
    conns: List[Dict] = []
    if mode != "quick":
        pids = platform.find_pids(adapter.process_names()) if adapter else []
        for pid in pids[:20]:  # 限制数量
            conns.extend(platform.network_connections(pid))
        # 去重
        seen = set()
        uniq = []
        for c in conns:
            key = (c.get("raddr"), c.get("rport"))
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        conns = uniq
        _analyze_connections(findings, conns, telemetry, geoip, official, proxies)
    else:
        findings.append(Finding(
            id="B1", dim="network", severity="info",
            title="quick 模式跳过进程连接快照(--mode interactive/deep 启用)"))

    # ---- B3 开关有效性(结合 B1 是否有遥测外联)----
    telemetry_seen = any(
        _host_of(c.get("raddr", "")) in telemetry or _host_of(c.get("raddr", "")) in geoip
        for c in conns)
    if disable_traffic == "1":
        if telemetry_seen:
            findings.append(Finding(
                id="B3", dim="network", severity="crit",
                title="非必要流量开关=1 但仍观测到遥测外联(开关失效,后门特征)",
                evidence="CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 但进程连接含遥测端点",
                advisory="nvdb-2026-07-08",
                remediation="开关被绕过,升级版本并用 --mode deep 取证"))
        else:
            findings.append(Finding(
                id="B3", dim="network", severity="pass",
                title="非必要流量已禁用(CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1)",
                evidence="且未观测到遥测外联"))
    else:
        findings.append(Finding(
            id="B3", dim="network", severity="warn",
            title="未设置非必要流量禁用开关",
            evidence="CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC 未设为 1",
            remediation="在 settings.json env 设置 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"))

    # ---- B2/B7 二进制 strings 静态分析 ----
    _check_binary_network(findings, ctx, adapter, telemetry, geoip)

    return findings


def _analyze_connections(findings, conns, telemetry, geoip, official, proxies):
    """B1/B2/B5/B6: 分析进程外联连接。"""
    if not conns:
        findings.append(Finding(
            id="B1", dim="network", severity="pass",
            title="未观测到进程外联连接(瞬时快照)"))
        return

    crit_targets, warn_targets, proxy_targets, unknown_targets = [], [], [], []
    for c in conns:
        host = _host_of(c.get("raddr", ""))
        if not host:
            continue
        if _is_private_ip(host):
            crit_targets.append((host, c.get("rport"), "私网/本地 IP 外联"))
            continue
        if host in geoip:
            crit_targets.append((host, c.get("rport"), "GeoIP 端点(地理位置收集)"))
        elif host in telemetry:
            warn_targets.append((host, c.get("rport"), telemetry[host].get("category", "遥测")))
        elif host in proxies:
            proxy_targets.append((host, c.get("rport"), proxies[host].get("provider", "第三方代理")))
        elif host in official:
            pass  # 官方端点,正常
        else:
            unknown_targets.append((host, c.get("rport")))

    if crit_targets:
        findings.append(Finding(
            id="B2", dim="network", severity="crit",
            title="进程外联到高危端点(%d)" % len(crit_targets),
            evidence="; ".join("%s:%s(%s)" % h for h in crit_targets[:5]),
            advisory="nvdb-2026-07-08",
            remediation="立即排查:这些端点可能是地理位置/指纹收集。终止进程并取证"))
    if warn_targets:
        findings.append(Finding(
            id="B2", dim="network", severity="warn",
            title="进程外联到遥测/分析端点(%d)" % len(warn_targets),
            evidence="; ".join("%s:%s(%s)" % h for h in warn_targets[:5]),
            remediation="确认是否为工具正常遥测;若不可接受,设置流量禁用开关"))
    if proxy_targets:
        findings.append(Finding(
            id="B5", dim="network", severity="warn",
            title="进程外联到第三方代理(%d)" % len(proxy_targets),
            evidence="; ".join("%s:%s(%s)" % h for h in proxy_targets[:5]),
            remediation="确认是自配代理(凭证会发往第三方)而非被篡改"))
    if unknown_targets:
        findings.append(Finding(
            id="B5", dim="network", severity="warn",
            title="进程外联到非白名单端点(%d)" % len(unknown_targets),
            evidence="; ".join("%s:%s" % h for h in unknown_targets[:5]),
            remediation="核对这些端点是否预期;未知外联需警惕"))
    if not (crit_targets or warn_targets or proxy_targets or unknown_targets):
        findings.append(Finding(
            id="B1", dim="network", severity="pass",
            title="进程外联均在官方白名单内(%d 连接)" % len(conns)))


def _check_binary_network(findings, ctx, adapter, telemetry, geoip):
    """B2(静态)/B7: 二进制 strings 扫描遥测端点 + TLS 校验禁用。"""
    if not adapter:
        return
    targets = adapter.integrity_targets()
    bin_path = next((t for t in targets if t.endswith("claude.exe") or t.endswith("claude")), None)
    if not bin_path:
        return
    text = binary.extract_strings(bin_path)

    # B2 静态: 二进制内是否硬编码遥测/GeoIP 端点
    all_ep = list(telemetry.keys()) + list(geoip.keys())
    hits = binary.scan_literal(text, all_ep)
    if hits:
        geoip_hits = [h for h in hits if h[0] in geoip]
        tele_hits = [h for h in hits if h[0] in telemetry]
        if geoip_hits:
            findings.append(Finding(
                id="B2", dim="network", severity="crit",
                title="二进制硬编码 GeoIP 端点(地理位置收集能力)",
                evidence=", ".join("%s(%d次)" % (h[0], h[1]) for h in geoip_hits[:5]),
                advisory="nvdb-2026-07-08",
                remediation="二进制具备地理位置查询能力。结合是否实际外联判定;不信任则停用"))
        if tele_hits:
            findings.append(Finding(
                id="B2", dim="network", severity="warn",
                title="二进制硬编码遥测端点(分析上报能力)",
                evidence=", ".join("%s(%d次)" % (h[0], h[1]) for h in tele_hits[:5]),
                remediation="二进制具备遥测上报能力。确认官方收集声明;用流量禁用开关抑制"))

    # B7: TLS 校验禁用
    tls_hits = binary.scan_literal(text, ["NODE_TLS_REJECT_UNAUTHORIZED=0", "rejectUnauthorized=false",
                                          "rejectUnauthorized: false"])
    if tls_hits:
        findings.append(Finding(
            id="B7", dim="network", severity="crit",
            title="二进制含 TLS 校验禁用标志(MITM/凭证截获前提)",
            evidence=", ".join("%s(%d次)" % (h[0], h[1]) for h in tls_hits),
            remediation="TLS 校验被禁用,流量可被中间人截获。高度可疑"))
