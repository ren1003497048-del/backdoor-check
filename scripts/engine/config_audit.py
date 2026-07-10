# -*- coding: utf-8 -*-
"""D/E/F/G/H 维度: 配置层审计(Check Point 披露的三类载体 + 权限/插件)。

D Hooks 任意执行 / E MCP 绕过审批 / F API key 重定向 + 凭证 / G 权限与危险配置 / H 插件供应链

不 import 任何网络模块(selfcheck 保证);host 解析用字符串处理,不用 urllib。
"""
from __future__ import annotations

import os
import re
from typing import List

from engine import fs, platform
from engine.report import Finding
from adapters import base


# 危险命令模式(D4)
_DANGER_CMD = re.compile(r"(https?://|curl\s|wget\s|base64\s|eval\b|sh\s+-c|nc\s+/)", re.IGNORECASE)
# 脚本内容危险模式(D5)
_DANGER_SCRIPT = re.compile(r"(curl\s|wget\s|eval\b|base64\s+-d|nc\s|/etc/|/usr/local/bin|>>?\s*/etc|\$\{.*\})", re.IGNORECASE)
# 凭证 key 名(F2)
_CREDED_KEYS = re.compile(r"(?i)(api[_\-]?key|auth[_\-]?token|access[_\-]?token|secret|password|token)")


def _extract_host(url: str) -> str:
    """从 URL 提取 host(不用 urllib,纯字符串)。"""
    s = url or ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if ":" in s:
        s = s.rsplit(":", 1)[0]
    return s.lower().strip("[]")


def _is_ip_or_localhost(host: str) -> bool:
    if not host:
        return False
    if host in ("localhost", "0.0.0.0", "::1"):
        return True
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _load_all_settings(adapter) -> list:
    """返回所有存在的 settings.json/settings.local.json 的 (path, dict) 列表(按真实路径去重)。"""
    result = []
    seen = set()
    if not adapter:
        return result
    for p in adapter.config_paths():
        if not p.endswith("settings.json") and not p.endswith("settings.local.json"):
            continue
        rp = os.path.realpath(p)
        if rp in seen:
            continue
        seen.add(rp)
        if not os.path.isfile(p):
            continue
        d = fs.read_json(p)
        if isinstance(d, dict):
            result.append((p, d))
    return result


# ============ D Hooks ============

def check_hooks(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    adapter = base.load_adapter(ctx["tool"].name)
    settings_list = _load_all_settings(adapter)

    total_hooks = 0
    untagged = []
    danger_cmds = []
    trusted_tags = {"ccstatusline-managed"}

    for path, d in settings_list:
        hooks = d.get("hooks", {})
        if not isinstance(hooks, dict):
            continue
        for event, blocks in hooks.items():
            if not isinstance(blocks, list):
                continue
            for block in blocks:
                tag = block.get("_tag", "")
                for hook in block.get("hooks", []):
                    total_hooks += 1
                    cmd = hook.get("command", "")
                    if not tag:
                        untagged.append((event, cmd))
                    if _DANGER_CMD.search(cmd or ""):
                        danger_cmds.append((event, cmd))
                    # D2: 随克隆传播的仓库内脚本
                    if cmd and ("/.claude/" in cmd or "./" in cmd):
                        findings.append(Finding(
                            id="D2", dim="hooks", severity="warn",
                            title="hook 指向仓库内脚本(随克隆传播)",
                            evidence="event=%s cmd=%s" % (event, cmd),
                            remediation="确认该脚本来源可信;仓库克隆会自动传播 hook 配置"))

    if danger_cmds:
        findings.append(Finding(
            id="D4", dim="hooks", severity="crit",
            title="hook 含危险命令(外联/eval/base64)(%d)" % len(danger_cmds),
            evidence="; ".join("%s:%s" % (e, c[:60]) for e, c in danger_cmds[:3]),
            advisory="check-point-cfg-attack-2026",
            remediation="立即移除该 hook;hooks 在项目初始化时自动执行且不经审批"))
    if untagged:
        findings.append(Finding(
            id="D3", dim="hooks", severity="warn",
            title="发现未标识来源的 hook(%d)" % len(untagged),
            evidence="; ".join("%s:%s" % (e, c[:60]) for e, c in untagged[:3]),
            remediation="确认这些 hook 来源;已知托管工具通常带 _tag"))

    # D5: 审计 hooks 目录脚本
    home = os.path.expanduser("~")
    hooks_dir = os.path.join(home, ".claude", "hooks")
    if os.path.isdir(hooks_dir):
        for fn in os.listdir(hooks_dir):
            if not fn.endswith((".sh", ".py", ".js")):
                continue
            content = fs.read_text(os.path.join(hooks_dir, fn))
            if _DANGER_SCRIPT.search(content):
                findings.append(Finding(
                    id="D5", dim="hooks", severity="warn",
                    title="hooks 目录脚本含可疑模式: %s" % fn,
                    evidence="匹配 curl/eval/系统路径等",
                    remediation="审查 %s 内容" % fn))

    if total_hooks > 0 and not danger_cmds:
        findings.append(Finding(
            id="D1", dim="hooks", severity="pass",
            title="已扫描 %d 个 hook,无危险命令模式" % total_hooks,
            evidence="hook 事件来自 %d 个配置文件" % len(settings_list)))
    elif total_hooks == 0:
        findings.append(Finding(
            id="D1", dim="hooks", severity="info",
            title="未发现 hooks 配置"))
    return findings


# ============ E MCP ============

def check_mcp(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    adapter = base.load_adapter(ctx["tool"].name)
    home = os.path.expanduser("~")
    servers = {}

    # ~/.claude.json 全局 mcpServers
    cd = fs.read_json(os.path.join(home, ".claude.json"))
    if isinstance(cd, dict):
        for k, v in (cd.get("mcpServers") or {}).items():
            servers[k] = v
        # 项目级
        for proj, pcfg in (cd.get("projects") or {}).items():
            if isinstance(pcfg, dict):
                for k, v in (pcfg.get("mcpServers") or {}).items():
                    servers["%s/%s" % (os.path.basename(proj), k)] = v

    # 项目 .mcp.json
    mcp_file = os.path.join(os.getcwd(), ".mcp.json")
    md = fs.read_json(mcp_file)
    if isinstance(md, dict):
        for k, v in (md.get("mcpServers") or {}).items():
            servers["local/" + k] = v

    if not servers:
        findings.append(Finding(
            id="E1", dim="mcp", severity="info",
            title="未发现 MCP server 配置"))
        return findings

    findings.append(Finding(
        id="E1", dim="mcp", severity="info",
        title="发现 %d 个 MCP server" % len(servers),
        evidence=", ".join(list(servers.keys())[:8])))

    remote_url = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = cfg.get("command", "")
        args = cfg.get("args", []) or []
        url = cfg.get("url", "")
        # E2: 远程 URL MCP
        if url:
            host = _extract_host(url)
            if _is_ip_or_localhost(host):
                findings.append(Finding(
                    id="E2", dim="mcp", severity="crit",
                    title="MCP server %s 指向 IP/localhost" % name,
                    evidence="url host=%s" % host,
                    remediation="stdio MCP 可读全部工具流量;指向本地可能是 C2"))
            else:
                remote_url.append((name, host))
        # E3: 权限覆盖
        for key in ("autoApprove", "alwaysAllow", "autoApproveTools"):
            if cfg.get(key):
                findings.append(Finding(
                    id="E3", dim="mcp", severity="warn",
                    title="MCP server %s 配置了自动批准(%s)" % (name, key),
                    evidence="绕过用户审批",
                    advisory="check-point-cfg-attack-2026",
                    remediation="移除自动批准,保留显式审批"))
        # E5: stdio MCP 可读全流量
        if cmd and cmd in ("npx", "node", "python", "python3"):
            pkg = args[1] if len(args) > 1 and args[0] == "-y" else (args[0] if args else "")
            findings.append(Finding(
                id="E5", dim="mcp", severity="info",
                title="stdio MCP %s 启动命令: %s %s" % (name, cmd, pkg),
                evidence="stdio MCP 可读写全部工具流量,需确认包来源可信"))

    if remote_url:
        findings.append(Finding(
            id="E2", dim="mcp", severity="warn",
            title="%d 个 MCP server 使用远程 URL" % len(remote_url),
            evidence=", ".join("%s→%s" % (n, h) for n, h in remote_url[:5]),
            remediation="确认远程 MCP host 可信;远程 server 可截获工具调用数据"))
    return findings


# ============ F API/凭证 ============

def check_api(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    adapter = base.load_adapter(ctx["tool"].name)
    al_rules = rules.get("allowlist") or {}
    al_tool = (al_rules.get("by_tool") or {}).get(ctx["tool"].name, {})
    official = set(h.lower() for h in al_tool.get("official_api_hosts", []))
    proxies = {p["host"].lower(): p for p in al_rules.get("known_third_party_proxies", [])}
    settings_list = _load_all_settings(adapter)

    # F1: base_url 重定向
    base_urls = []
    for path, d in settings_list:
        env = d.get("env", {}) or {}
        for k in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_API_BASE"):
            v = env.get(k)
            if v:
                base_urls.append((k, v, path))
    for k, v, path in base_urls:
        host = _extract_host(v)
        if host in official:
            findings.append(Finding(
                id="F1", dim="api", severity="pass",
                title="%s 指向官方端点 %s" % (k, host)))
        elif host in proxies:
            findings.append(Finding(
                id="F1", dim="api", severity="warn",
                title="%s 指向第三方代理 %s(%s)" % (k, host, proxies[host].get("provider", "")),
                evidence="API 流量与凭证会发往第三方;确认是自配而非被篡改",
                advisory="check-point-cfg-attack-2026",
                remediation="若为自配代理可接受;否则改回官方 %s" % (official or "api.anthropic.com")))
        elif _is_ip_or_localhost(host):
            findings.append(Finding(
                id="F1", dim="api", severity="crit",
                title="%s 指向 IP/localhost %s(凭证截获风险)" % (k, host),
                advisory="check-point-cfg-attack-2026",
                remediation="base_url 被篡改指向本地,凭证可能被截获。立即改回官方"))
        else:
            findings.append(Finding(
                id="F1", dim="api", severity="warn",
                title="%s 指向非白名单端点 %s" % (k, host),
                remediation="确认该端点可信;base_url 是流量总开关"))

    # F2: 明文凭证存储
    cred_files = []
    for path, d in settings_list:
        env = d.get("env", {}) or {}
        for k, val in env.items():
            if _CREDED_KEYS.search(k) and val:
                cred_files.append((path, k))
    if cred_files:
        findings.append(Finding(
            id="F2", dim="api", severity="warn",
            title="凭证明文存储在配置文件(%d 处)" % len(cred_files),
            evidence="; ".join("%s:%s" % (os.path.basename(p), k) for p, k in cred_files[:5]),
            remediation="改用环境变量/keychain;配置文件明文 token 任何能读文件的进程都能获取"))

    # F3/F6: 凭证文件权限
    home = os.path.expanduser("~")
    cred_candidates = [os.path.join(home, ".claude", "settings.json"),
                       os.path.join(home, ".claude.json"),
                       os.path.join(home, ".netrc"), os.path.join(home, ".npmrc"),
                       os.path.join(home, ".git-credentials"),
                       os.path.join(home, ".aws", "credentials")]
    world_readable = []
    for p in cred_candidates:
        if not os.path.isfile(p):
            continue
        mi = fs.file_mode(p)
        if mi.get("other_readable") or mi.get("group_readable"):
            world_readable.append((p, mi.get("mode_octal", "?")))
    if world_readable:
        findings.append(Finding(
            id="F3", dim="api", severity="crit",
            title="凭证文件对 group/other 可读(%d)" % len(world_readable),
            evidence="; ".join("%s(%s)" % (os.path.basename(p), m) for p, m in world_readable[:5]),
            remediation="chmod 600 这些文件;其他用户可读取其中凭证"))

    # F5: 凭证进 cmdline
    pids = platform.find_pids(adapter.process_names()) if adapter else []
    for pid in pids[:10]:
        cmdline = platform.process_cmdline(pid)
        if cmdline and re.search(r"(sk-[A-Za-z0-9]|token=|api_key=)", cmdline, re.IGNORECASE):
            findings.append(Finding(
                id="F5", dim="api", severity="crit",
                title="凭证出现在进程命令行(pid=%s)" % pid,
                evidence="cmdline 对本机所有用户可见",
                remediation="不要在命令行传凭证;用 env 或配置文件(并 chmod 600)"))
            break

    if not base_urls and not cred_files:
        findings.append(Finding(
            id="F1", dim="api", severity="info",
            title="未发现 base_url 配置(默认官方)"))
    return findings


# ============ G 权限/危险配置 ============

def check_permissions(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    adapter = base.load_adapter(ctx["tool"].name)
    perm_rules = (rules.get("permissions") or {})
    switches = perm_rules.get("dangerous_switches", [])
    patterns = perm_rules.get("high_risk_permission_patterns", [])
    flags = perm_rules.get("dangerous_flags", [])
    settings_list = _load_all_settings(adapter)

    # G1: 危险开关
    for path, d in settings_list:
        for sw in switches:
            key = sw["key"]
            if key in d and d[key] == sw["value"]:
                findings.append(Finding(
                    id="G1", dim="permissions", severity=sw["severity"],
                    title="危险开关 %s=%s(%s)" % (key, sw["value"], sw["reason"]),
                    evidence="文件: %s" % os.path.basename(path),
                    remediation="关闭该开关以恢复审批"))

    # G2: 高危权限放行
    hits = {"crit": [], "warn": []}
    for path, d in settings_list:
        allow = ((d.get("permissions") or {}).get("allow")) or []
        for item in allow:
            for pat in patterns:
                if pat["pattern"] in item:
                    hits[pat["severity"]].append((item, pat["reason"]))
                    break
    for sev in ("crit", "warn"):
        if hits[sev]:
            findings.append(Finding(
                id="G2", dim="permissions", severity=sev,
                title="%d 项%s级权限放行" % (len(hits[sev]), sev),
                evidence="; ".join("%s(%s)" % (i[:40], r) for i, r in hits[sev][:5]),
                remediation="收紧 permissions.allow,移除 sudo/rm/curl 等危险放行"))

    # G4: 别名注入危险 flag
    home = os.path.expanduser("~")
    for rc in [".zshrc", ".bashrc", ".bash_profile", ".zprofile"]:
        content = fs.read_text(os.path.join(home, rc))
        if not content:
            continue
        for flag in flags:
            if flag in content:
                findings.append(Finding(
                    id="G4", dim="permissions", severity="warn",
                    title="%s 含危险 flag %s" % (rc, flag),
                    remediation="移除别名中的 %s" % flag))

    if not findings:
        findings.append(Finding(
            id="G1", dim="permissions", severity="pass",
            title="未发现危险开关或高危权限放行"))
    return findings


# ============ H 插件供应链 ============

def check_plugins(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    blocklist = (rules.get("blocklist") or {})
    home = os.path.expanduser("~")
    installed = fs.read_json(os.path.join(home, ".claude", "plugins", "installed_plugins.json")) or {}
    marketplaces = fs.read_json(os.path.join(home, ".claude", "plugins", "known_marketplaces.json")) or {}
    plugins = installed.get("plugins", {}) if isinstance(installed, dict) else {}

    if not plugins:
        findings.append(Finding(
            id="H1", dim="plugins", severity="info",
            title="未发现已安装插件"))
        return findings

    # H1: marketplace 来源
    non_official = []
    for full_name in plugins:
        parts = full_name.split("@", 1)
        mkt = parts[1] if len(parts) > 1 else ""
        mkt_info = marketplaces.get(mkt, {}) if isinstance(marketplaces, dict) else {}
        src = (mkt_info.get("source") or {})
        src_type = src.get("source", "")
        repo = src.get("repo", "")
        if src_type == "github" and "anthropics" in repo.lower():
            pass  # 官方
        else:
            non_official.append((full_name, src_type, repo or src.get("path", "")))
    if non_official:
        findings.append(Finding(
            id="H1", dim="plugins", severity="warn",
            title="%d 个插件来自非官方 marketplace" % len(non_official),
            evidence="; ".join("%s(%s)" % (n, s) for n, s, _ in non_official[:5]),
            remediation="确认第三方插件来源可信;插件可执行代码并访问工具上下文"))
    else:
        findings.append(Finding(
            id="H1", dim="plugins", severity="pass",
            title="所有插件来自官方 marketplace"))

    # H3: blocklist 命中
    bad_pkgs = {p["name"].lower(): p for p in blocklist.get("malicious_packages", [])}
    for full_name, instances in plugins.items():
        for inst in instances:
            inst_path = inst.get("installPath", "")
            for bad in bad_pkgs:
                if bad in inst_path.lower() or bad in full_name.lower():
                    findings.append(Finding(
                        id="H3", dim="plugins", severity="crit",
                        title="插件命中恶意包名单: %s" % bad,
                        evidence="%s 匹配 %s" % (full_name, bad),
                        remediation="立即卸载该插件"))
    return findings
