# -*- coding: utf-8 -*-
"""平台抽象层。

职责: 封装跨平台(macOS/Linux/Windows)的系统命令,提供统一的检测原语。
所有命令调用集中在此,便于审计(--audit 可列出全部将执行的命令)。

自身安全: 本模块只用 subprocess 调用本地系统命令(lsof/ps/strings/otool 等),
不发起任何网络请求。socket 守卫在 check.py 启动时已挂载,即使误调用网络也会被拦。
"""
from __future__ import annotations

import os
import sys
import shutil
import hashlib
import subprocess
from typing import List, Dict, Optional, Tuple


# ---------- 基础 ----------

def detect_os() -> str:
    """返回 'darwin' / 'linux' / 'windows'。"""
    p = sys.platform.lower()
    if p.startswith("darwin"):
        return "darwin"
    if p.startswith("linux"):
        return "linux"
    if p.startswith("win") or p == "cygwin":
        return "windows"
    return p


def detect_arch() -> str:
    return os.uname().machine if hasattr(os, "uname") else (os.environ.get("PROCESSOR_ARCHITECTURE", "unknown"))


def run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    """运行命令,返回 (returncode, stdout, stderr)。失败不抛异常,返回 (非0, "", 错误信息)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


# ---------- 进程 ----------

def find_pids(name_patterns: List[str]) -> List[int]:
    """按进程名模式查找 PID。用 ps(跨平台)。"""
    rc, out, _ = run(["ps", "-A", "-o", "pid=,comm="], timeout=10)
    if rc != 0:
        # windows 降级
        rc, out, _ = run(["tasklist", "/FO", "CSV", "/NH"], timeout=10)
        # 简化:windows 不返回 pid(后续网络连接用 netstat 自带 PID)
        return []
    pids = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        comm = parts[1]
        for pat in name_patterns:
            if pat.lower() in comm.lower():
                pids.append(pid)
                break
    return sorted(set(pids))


def process_cmdline(pid: int) -> str:
    """读取进程命令行(脱敏由调用方决定)。"""
    osname = detect_os()
    if osname == "linux":
        try:
            with open("/proc/%d/cmdline" % pid, "r", encoding="utf-8", errors="replace") as f:
                return f.read().replace("\x00", " ").strip()
        except Exception:
            return ""
    if osname == "darwin":
        rc, out, _ = run(["ps", "-p", str(pid), "-o", "command="], timeout=5)
        return out.strip() if rc == 0 else ""
    # windows
    rc, out, _ = run(["wmic", "process", "where", "processid=%d" % pid, "get", "commandline"], timeout=5)
    return out.strip() if rc == 0 else ""


# ---------- 网络 (B 维度原语) ----------

def network_connections(pid: Optional[int] = None) -> List[Dict[str, str]]:
    """采集进程网络连接快照。返回 [{proto, laddr, lport, raddr, rport, state, pid}]。

    优先级: darwin=lsof / linux=ss→netstat→/proc / windows=netstat。
    免 root 可读取当前用户进程的连接。
    """
    osname = detect_os()
    conns: List[Dict[str, str]] = []
    if osname == "darwin":
        cmd = ["lsof", "-i", "-nP", "-w"]
        if pid:
            cmd += ["-p", str(pid)]
        rc, out, _ = run(cmd, timeout=10)
        if rc == 0:
            conns = _parse_lsof(out)
    elif osname == "linux":
        rc, out, _ = run(["ss", "-tunp"], timeout=10)
        if rc != 0:
            rc, out, _ = run(["netstat", "-tunp"], timeout=10)
        if rc == 0:
            conns = _parse_ss(out)
        # /proc 兜底(纯 stdlib,无命令依赖)
        if not conns and pid is not None:
            conns = _parse_proc_net(pid)
    elif osname == "windows":
        cmd = ["netstat", "-ano"]
        rc, out, _ = run(cmd, timeout=10)
        if rc == 0:
            conns = _parse_netstat_win(out)
    return conns


def _parse_lsof(out: str) -> List[Dict[str, str]]:
    """解析 lsof -i 输出。NAME 列形如 '1.2.3.4:443' 或 'host:https' 或 '*:*'。"""
    conns = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        pid = parts[1]
        proto = parts[7]
        name = parts[8]
        state = parts[9] if len(parts) > 9 else ""
        raddr, rport = _split_addr(name)
        if raddr in (None, "", "*"):
            continue
        conns.append({"proto": proto, "raddr": raddr, "rport": rport,
                      "laddr": "", "lport": "", "state": state, "pid": pid})
    return conns


def _split_addr(name: str) -> Tuple[str, str]:
    """'1.2.3.4:443' -> ('1.2.3.4','443'); 'host:https' -> ('host','https'); '*:*' -> ('*','*')。"""
    if ":" in name:
        h, _, p = name.rpartition(":")
        return h, p
    return name, ""


def _parse_ss(out: str) -> List[Dict[str, str]]:
    """解析 ss -tunp。列: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process。"""
    conns = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        peer = parts[4]
        pid = ""
        if len(parts) >= 7 and "users:" in parts[6]:
            # users:((\"cmd\",pid=123,fd=4))
            import re
            m = re.search(r"pid=(\d+)", parts[6])
            pid = m.group(1) if m else ""
        raddr, rport = _split_addr(peer)
        if raddr in (None, "", "*", "0.0.0.0", "::"):
            continue
        conns.append({"proto": "", "raddr": raddr, "rport": rport,
                      "laddr": "", "lport": "", "state": state, "pid": pid})
    return conns


def _parse_netstat_win(out: str) -> List[Dict[str, str]]:
    conns = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0]
        foreign = parts[2]
        pid = parts[-1]
        raddr, rport = _split_addr(foreign)
        if raddr in (None, "", "*", "0.0.0.0", "::"):
            continue
        conns.append({"proto": proto, "raddr": raddr, "rport": rport,
                      "laddr": "", "lport": "", "state": parts[3] if proto == "TCP" else "", "pid": pid})
    return conns


def _parse_proc_net(pid: int) -> List[Dict[str, str]]:
    """Linux /proc/<pid>/net/tcp 兜底解析。仅返回外网 ESTABLISHED。"""
    conns = []
    try:
        with open("/proc/%d/net/tcp" % pid, "r", encoding="utf-8", errors="replace") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local, remote, state = parts[1], parts[2], parts[3]
                if state != "01":  # 01 = ESTABLISHED
                    continue
                rip, rport = remote.split(":")
                rport = str(int(rport, 16))
                # hex IP -> dotted
                rip_int = int(rip, 16)
                raddr = "%d.%d.%d.%d" % (rip_int & 0xff, (rip_int >> 8) & 0xff,
                                         (rip_int >> 16) & 0xff, (rip_int >> 24) & 0xff)
                if raddr.startswith("0.0.0.0") or raddr.startswith("127."):
                    continue
                conns.append({"proto": "tcp", "raddr": raddr, "rport": rport,
                              "laddr": "", "lport": "", "state": "ESTABLISHED", "pid": str(pid)})
    except Exception:
        pass
    return conns


def read_hosts() -> str:
    """读取 /etc/hosts(或 Windows 的 hosts)。"""
    paths = ["/etc/hosts"]
    if detect_os() == "windows":
        paths = [r"C:\Windows\System32\drivers\etc\hosts"]
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            continue
    return ""


def dns_resolvers() -> str:
    """读取 DNS resolver 配置文本(供 B4 检测劫持)。"""
    osname = detect_os()
    if osname == "darwin":
        rc, out, _ = run(["scutil", "--dns"], timeout=5)
        return out if rc == 0 else ""
    if osname == "linux":
        for p in ["/etc/resolv.conf"]:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                pass
        rc, out, _ = run(["resolvectl", "status"], timeout=5)
        return out if rc == 0 else ""
    return ""


# ---------- 二进制 (A3/C4 原语) ----------

def binary_strings(path: str, max_lines: int = 200000) -> str:
    """strings 抽取(跨平台降级)。返回拼接文本。"""
    if not os.path.isfile(path):
        return ""
    for tool in ["strings"]:
        if which(tool):
            rc, out, _ = run([tool, "-a", path], timeout=60)
            if rc == 0:
                lines = out.splitlines()
                if len(lines) > max_lines:
                    lines = lines[:max_lines]
                return "\n".join(lines)
            return ""
    # 无 strings 命令:用 Python 抽取可打印 ASCII 串(>=4 字符)
    return _py_strings(path, max_lines)


def _py_strings(path: str, max_lines: int) -> str:
    """纯 Python 的 strings 实现(无系统命令时降级)。"""
    result = []
    try:
        with open(path, "rb") as f:
            buf = bytearray()
            while len(result) < max_lines:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                for b in chunk:
                    if 32 <= b < 127:
                        buf.append(b)
                    else:
                        if len(buf) >= 4:
                            result.append(buf.decode("ascii", "replace"))
                        buf = bytearray()
            if len(buf) >= 4:
                result.append(buf.decode("ascii", "replace"))
    except Exception:
        pass
    return "\n".join(result[:max_lines])


def binary_deps(path: str) -> str:
    """动态依赖列表(检测异常加载库)。"""
    if not os.path.isfile(path):
        return ""
    osname = detect_os()
    if osname == "darwin":
        if which("otool"):
            rc, out, _ = run(["otool", "-L", path], timeout=30)
            return out if rc == 0 else ""
    elif osname == "linux":
        if which("readelf"):
            rc, out, _ = run(["readelf", "-d", path], timeout=30)
            return out if rc == 0 else ""
        if which("ldd"):
            rc, out, _ = run(["ldd", path], timeout=30)
            return out if rc == 0 else ""
    return ""


def binary_symbols(path: str) -> str:
    """导出符号/ObjC 方法名(C4 高信号)。"""
    if not os.path.isfile(path):
        return ""
    osname = detect_os()
    if osname == "darwin":
        if which("otool"):
            rc, out, _ = run(["otool", "-ov", path], timeout=60)
            if rc == 0:
                return out
        if which("nm"):
            rc, out, _ = run(["nm", path], timeout=60)
            return out if rc == 0 else ""
    elif osname == "linux":
        if which("nm"):
            rc, out, _ = run(["nm", "-D", path], timeout=60)
            return out if rc == 0 else ""
    return ""


# ---------- 文件系统原语 ----------

def file_hash(path: str, algo: str = "sha512") -> Optional[str]:
    if not os.path.isfile(path):
        return None
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def file_mode_info(path: str) -> Dict[str, Any]:
    """文件权限信息: octal 权限、是否 group/other 可读。"""
    import stat as _stat
    if not os.path.exists(path):
        return {"exists": False}
    try:
        st = os.stat(path)
    except Exception as e:
        return {"exists": True, "error": str(e)}
    mode = _stat.S_IMODE(st.st_mode)
    return {
        "exists": True,
        "mode_octal": oct(mode),
        "group_readable": bool(mode & 0o040),
        "other_readable": bool(mode & 0o004),
        "world_readable": bool(mode & 0o044),
    }


# ---------- 机器标识来源 (C2 原语,仅枚举命令,不主动读取外传) ----------

def machine_id_sources() -> List[List[str]]:
    """返回当前平台可读取机器标识的命令列表(供 fingerprint 静态分析二进制是否引用,
    以及 deep 模式取证参考)。本函数不执行这些命令,仅声明。"""
    osname = detect_os()
    if osname == "darwin":
        return [
            ["ioreg", "-d2", "-c", "IOPlatformExpertDevice"],
            ["system_profiler", "SPHardwareDataType"],
            ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth"],
        ]
    if osname == "linux":
        return [
            ["cat", "/etc/machine-id"],
            ["cat", "/var/lib/dbus/machine-id"],
            ["cat", "/sys/class/net/*/address"],
            ["cat", "/sys/devices/virtual/dmi/id/product_uuid"],
        ]
    if osname == "windows":
        return [
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
            ["wmic", "csproduct", "get", "UUID"],
        ]
    return []
