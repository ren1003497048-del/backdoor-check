# -*- coding: utf-8 -*-
"""C 维度: 设备指纹/身份收集检测(NVDB 后门核心: 地理位置+身份标识)。

C1 地理位置 API(CoreLocation/GeoClue/GeoIP)/ C2 机器标识读取(IOPlatformUUID/machine-id)
C3 身份 env 收集 / C4 二进制硬编码指纹逻辑(strings + ObjC 方法名)

静态启发式: 检测二进制是否"具备"收集能力。具备能力 ≠ 已外传;
结合 B 维度(是否实际外联遥测端点)升 crit。
deep 模式: C1-C3 行为级取证(sudo dtrace/strace)给指引。

【局限】编译二进制可能 strip/混淆,strings 只命中未混淆部分 → 未发现 ≠ 不存在。
"""
from __future__ import annotations

from typing import List

from engine import binary, platform
from engine.report import Finding
from adapters import base

# 敏感凭证 env(命中=具备凭证收集能力);常见 USER/HOME/HOSTNAME 不报(误报多)
SENSITIVE_ENV = [
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "GL_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY",
    "SSH_AUTH_SOCK", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL",
]


def check(ctx: dict) -> List[Finding]:
    findings: List[Finding] = []
    rules = ctx.get("rules", {})
    tool = ctx["tool"]
    mode = ctx.get("mode", "interactive")
    adapter = base.load_adapter(tool.name)
    fp_rules = rules.get("fingerprints") or {}

    targets = adapter.integrity_targets() if adapter else []
    bin_path = next((t for t in targets if t.endswith("claude.exe") or t.endswith("claude")), None)
    if not bin_path:
        findings.append(Finding(
            id="C4", dim="fingerprint", severity="info",
            title="未找到二进制目标,跳过指纹静态分析"))
        return findings

    text = binary.extract_strings(bin_path)
    osname = platform.detect_os()

    location_pats = fp_rules.get("location_indicators", [])
    machine_pats = (fp_rules.get("machine_id_indicators", {}) or {}).get(osname, [])
    sdk_pats = fp_rules.get("analytics_sdk_signatures", [])

    loc_hits = binary.scan_literal(text, location_pats)
    mach_hits = binary.scan_literal(text, machine_pats)
    env_hits = binary.scan_literal(text, SENSITIVE_ENV)
    sdk_hits = binary.scan_literal(text, sdk_pats)

    # C1 地理位置
    if loc_hits:
        findings.append(Finding(
            id="C1", dim="fingerprint", severity="warn",
            title="二进制含地理位置相关符号(位置收集能力)",
            evidence=", ".join("%s(%d)" % (h[0], h[1]) for h in loc_hits[:5]),
            advisory="nvdb-2026-07-08",
            remediation="二进制具备位置查询能力。结合 B 维度是否外联 GeoIP 端点判定;不信任则停用"))
    else:
        findings.append(Finding(
            id="C1", dim="fingerprint", severity="pass",
            title="未发现地理位置收集符号(strings 启发式)"))

    # C2 机器标识
    if mach_hits:
        findings.append(Finding(
            id="C2", dim="fingerprint", severity="warn",
            title="二进制含机器标识访问符号(设备指纹能力)",
            evidence=", ".join("%s(%d)" % (h[0], h[1]) for h in mach_hits[:5]),
            advisory="nvdb-2026-07-08",
            remediation="二进制可读取机器唯一标识。结合是否外传判定"))
    else:
        findings.append(Finding(
            id="C2", dim="fingerprint", severity="pass",
            title="未发现机器标识访问符号(strings 启发式)"))

    # C3 身份 env
    if env_hits:
        findings.append(Finding(
            id="C3", dim="fingerprint", severity="warn",
            title="二进制引用敏感凭证/身份 env(凭证收集能力)",
            evidence=", ".join("%s(%d)" % (h[0], h[1]) for h in env_hits[:5]),
            remediation="二进制可读取这些环境变量。确认是否用于合法用途;避免在 env 放敏感凭证"))
    else:
        findings.append(Finding(
            id="C3", dim="fingerprint", severity="pass",
            title="未发现敏感凭证 env 引用(strings 启发式)"))

    # C4 分析 SDK / 指纹函数(高信号)
    if sdk_hits:
        # 高信号函数名直接关联后门特征
        high_sig = [h for h in sdk_hits if h[0] in
                    ("collectTelemetry", "sendAnalytics", "getMachineId", "getDeviceId",
                     "fingerprint", "deviceFingerprint", "sendBeacon", "getLocation")]
        sev = "warn"  # 启发式降级为 warn(良性遥测也可能命中;确定性后门检测见 I 维度)
        findings.append(Finding(
            id="C4", dim="fingerprint", severity=sev,
            title="二进制含分析/指纹收集函数(%d 个签名)" % len(sdk_hits),
            evidence=", ".join("%s(%d)" % (h[0], h[1]) for h in sdk_hits[:8]),
            advisory="nvdb-2026-07-08" if high_sig else "",
            remediation="二进制内置遥测/指纹收集逻辑。这是后门事件的核心特征模式;核对官方收集声明"))

    # 综合判定: 同时具备 位置+标识+收集函数 = 完整指纹链路
    if loc_hits and mach_hits and sdk_hits:
        findings.append(Finding(
            id="C4", dim="fingerprint", severity="warn",
            title="综合: 二进制具备完整指纹收集链路(位置+标识+收集函数)",
            evidence="位置符号 + 机器标识 + 收集函数 同时存在",
            advisory="nvdb-2026-07-08",
            remediation="高度吻合 NVDB 公告的后门特征。建议升级并用 --mode deep 取证是否实际外传"))

    # deep 模式: 行为级取证指引
    # ---- C5: 用户画像定位特征(locale/hostname/username/network)----
    profiling = fp_rules.get("user_profiling_indicators") or {}
    prof_cats = {k: profiling[k] for k in ("locale", "host_user", "network", "timezone")
                 if k in profiling and isinstance(profiling[k], list)}
    prof_hits = {}
    for cat, pats in prof_cats.items():
        for pat in pats:
            h = binary.scan_literal(text, [pat])
            if h:
                prof_hits.setdefault(cat, []).append((pat, h[0][1]))
    if prof_hits:
        ev = "; ".join("%s: %s" % (c, ",".join("%s(%d)" % (p, n) for p, n in v[:4]))
                       for c, v in prof_hits.items())
        findings.append(Finding(
            id="C5", dim="fingerprint", severity="warn",
            title="二进制引用用户画像定位特征(%d 类,启发式)" % len(prof_hits),
            evidence=ev,
            remediation="工具具备读取语言/locale/主机名/用户名/网络接口能力。多为良性(本地化),但组合感知可用于定向标记"))
    else:
        findings.append(Finding(id="C5", dim="fingerprint", severity="pass",
                                title="未发现用户画像定位特征引用"))

    # ---- C6: 本机用户画像暴露评估 ----
    import os as _os_c6
    import getpass as _gp_c6
    expose = []
    lang = _os_c6.environ.get("LANG", "") or _os_c6.environ.get("LC_ALL", "")
    if lang:
        expose.append("LANG/LC_ALL=%s" % lang)
    hn = ""
    try:
        hn = _os_c6.uname()[1] if hasattr(_os_c6, "uname") else ""
    except Exception:
        pass
    if hn:
        expose.append("hostname=%s" % hn)
    try:
        expose.append("username=%s" % _gp_c6.getuser())
    except Exception:
        pass
    iana = ""
    try:
        lk = _os_c6.readlink("/etc/localtime")
        if "zoneinfo/" in lk:
            iana = lk.split("zoneinfo/")[-1]
    except Exception:
        pass
    if iana:
        expose.append("IANA时区=%s" % iana)
    cn_lang = "zh" in lang.lower()
    cn_tz = any(t in iana for t in ("Shanghai", "Urumqi", "Beijing", "Chongqing", "Harbin", "Kashgar"))
    if expose:
        sev = "warn" if (cn_lang and cn_tz) else "info"
        title = "本机用户画像暴露" + ("(高可识别中文目标)" if (cn_lang and cn_tz) else "")
        rem = ("中文 locale + 中国时区 + 主机/用户名均暴露 → 高可识别。未来定向后门可据此识别你;必要时伪装时区/英文化环境降低指纹"
               if (cn_lang and cn_tz) else "常规暴露,风险可控")
        findings.append(Finding(
            id="C6", dim="fingerprint", severity=sev, title=title,
            evidence="; ".join(expose), remediation=rem))

    if mode == "deep":
        findings.append(Finding(
            id="C-DEEP", dim="fingerprint", severity="info",
            title="C1-C3 行为级取证指引(需 sudo,默认不执行)",
            evidence=("%s 平台: dtrace/strace 监控 claude 进程的 getenv/openat/connect,"
                      "确认是否实际读取并外传指纹。详见 references/deep-water.md" % osname),
            remediation="授权后执行行为级追踪,获取是否实际外传的实锤证据"))

    return findings
