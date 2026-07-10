#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""受控外联模块 — 唯一允许网络的模块 (J1 例外)。

仅由 check.py --verify-registry 经隔离子进程调用(子进程设 BACKDOOR_CHECK_OUTBOUND=1
解除主进程的 socket 守卫)。功能: 对照官方 npm registry 校验包完整性,
检测 2026-03 源码泄露类事件(npm 包被植入 Vidar/GhostSocks 恶意软件)。

安全约束:
- 只连接 registry.npmjs.org(硬编码白名单 + TLS 证书校验)
- 只发 GET 请求拉取 manifest,不携带任何本地数据/凭证
- 只读取 dist.integrity / dist.shasum,不下载包体
- 全程输出到本地 stdout,不上报任何信息
- 默认 User-Agent 不含本机标识
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import ssl
import urllib.request

# 硬编码白名单: 只允许连接官方 npm registry
ALLOWED_HOST = "registry.npmjs.org"
REGISTRY_URL = "https://%s" % ALLOWED_HOST


def fetch_manifest(package: str, version: str = "latest", timeout: int = 15) -> dict:
    """GET https://registry.npmjs.org/<package>/<version>,返回 manifest JSON。

    安全: 校验 host 必须为白名单;启用 TLS 证书校验;不携带本地数据。
    """
    # 防止通过 package/version 注入路径或 host
    if "/" in package or ".." in package or package.startswith("@") is False and "/" in package:
        # 允许 scoped 包 @scope/name,但禁止路径穿越
        pass
    safe_pkg = package.lstrip("/")
    if ".." in safe_pkg or "\x00" in safe_pkg:
        raise ValueError("非法 package 名: %s" % package)

    url = "%s/%s/%s" % (REGISTRY_URL, safe_pkg, version)
    # 再次校验解析后的 host
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname != ALLOWED_HOST:
        raise ValueError("目标 host 不在白名单: %s" % parsed.hostname)
    if parsed.scheme != "https":
        raise ValueError("必须使用 https")

    # TLS 证书校验(默认开启,显式创建 context 强调)
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    req = urllib.request.Request(url, headers={"User-Agent": "backdoor-check/verify-registry (no local data)"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = resp.read().decode("utf-8", "replace")
    return json.loads(data)


def main() -> int:
    ap = argparse.ArgumentParser(description="受控 registry 校验(唯一外联模块)")
    ap.add_argument("--package", required=True, help="npm 包名,如 @anthropic-ai/claude-code")
    ap.add_argument("--version", default="latest", help="版本,默认 latest")
    ap.add_argument("--local-sha512", default=None, help="本地包的 sha512(可选,用于比对)")
    args = ap.parse_args()

    print("[verify-registry] 受控外联: 仅连接 %s,只 GET manifest,不携带本地数据" % ALLOWED_HOST)
    print("[verify-registry] package=%s version=%s" % (args.package, args.version))
    try:
        manifest = fetch_manifest(args.package, args.version)
    except Exception as e:
        print("[verify-registry] 失败: %s" % e)
        return 1

    dist = manifest.get("dist", {})
    integrity = dist.get("integrity", "")
    shasum = dist.get("shasum", "")
    tarball = dist.get("tarball", "")

    print("[verify-registry] 官方 dist.integrity: %s" % integrity)
    print("[verify-registry] 官方 dist.shasum:    %s" % shasum)
    print("[verify-registry] 官方 tarball:        %s" % tarball)

    if args.local_sha512:
        # integrity 格式: sha512-<base64>
        if integrity.startswith("sha512-"):
            import hashlib, base64
            official_b64 = integrity[len("sha512-"):]
            try:
                official_hex = base64.b64decode(official_b64).hex()
                local_hex = args.local_sha512.lower()
                if official_hex == local_hex:
                    print("[verify-registry] 比对: ✅ 本地哈希与官方一致(包未被篡改)")
                    return 0
                else:
                    print("[verify-registry] 比对: 🚨 本地哈希与官方不符(包可能被篡改!)")
                    print("  官方: %s" % official_hex[:32] + "...")
                    print("  本地: %s" % local_hex[:32] + "...")
                    return 2
            except Exception as e:
                print("[verify-registry] 比对解析失败: %s" % e)
                return 1
        else:
            print("[verify-registry] 官方 integrity 非 sha512 格式,无法比对")
    else:
        print("[verify-registry] 未提供 --local-sha512,仅展示官方 manifest,未做比对")
    return 0


if __name__ == "__main__":
    # 本模块是唯一允许网络的模块,由 check.py 以 BACKDOOR_CHECK_OUTBOUND=1 调用
    sys.exit(main())
