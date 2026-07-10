#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行时 prompt steganography 实锤工具(行为级验证)。

起本地 HTTP server,捕获 claude 实际发送的 system prompt,检查
"Today's date is ..." 的撇号码点(U+0027 标准 / U+2019 / U+02BC / U+02B9)
与日期分隔符(- 标准 / / 标记),判定是否被注入隐写标记。

这是 I 维度(静态签名)的行为级补充:静态能确认"版本是否含后门逻辑",
本工具能实锤"当前实际请求是否被标记"。

安全: 监听 127.0.0.1(本地回环),不外联;捕获数据仅存本地。

用法:
  1. 在另一终端临时设置: export ANTHROPIC_BASE_URL=http://localhost:8765
  2. 触发一次 claude 请求: claude -p "hi"  (或任意会话首条消息)
  3. 本工具自动捕获并分析,输出撇号/日期判定
  4. 恢复原 base_url

注意: claude 可能强制 TLS(拒绝 http base_url);若捕获不到,改用 mitmproxy
(见 references/deep-water.md)。
"""
from __future__ import annotations

import json
import os
import re
import sys
import http.server
import socketserver

# 撇号变体 → 含义(Thereallo 逆向)
APOS_VARIANTS = {
    "'": ("U+0027", "标准(无标记)"),
    "’": ("U+2019", "已知域名命中(后门标记)"),
    "ʼ": ("U+02BC", "实验室关键词命中(后门标记)"),
    "ʹ": ("U+02B9", "两者命中(后门标记)"),
}


class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    captured = {}

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        # 提取 system prompt(Anthropic API 格式: system 可能是 str 或 [{type:text,text:...}] 列表)
        sys_prompt = ""
        s = data.get("system")
        if isinstance(s, str):
            sys_prompt = s
        elif isinstance(s, list):
            for item in s:
                if isinstance(item, dict):
                    sys_prompt += item.get("text", "") or ""
                elif isinstance(item, str):
                    sys_prompt += item
        _CaptureHandler.captured = {"system": sys_prompt, "has_data": bool(data)}
        # 返回错误响应(让 claude 结束请求,不继续对话)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        resp = {"type": "error", "error": {"type": "overloaded_error",
                                           "message": "backdoor-check capture complete"}}
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, *args):
        pass  # 静默


def _analyze(prompt: str):
    """分析 system prompt 的撇号 + 日期分隔符。返回 (info, error)。"""
    if not prompt:
        return None, "未捕获到 system prompt"
    # 找 "Today?s date is YYYY-MM-DD" 或 "YYYY/MM/DD"
    m = re.search(r"Today.{0,3}s date is ([0-9]{4}[-/][0-9]{2}[-/][0-9]{2})", prompt)
    if not m:
        # 找近似短语
        if "date is" in prompt:
            idx = prompt.find("date is")
            return None, "找到 'date is' 但格式不匹配,片段: %s" % prompt[max(0, idx-30):idx+40]
        return None, "未在 system prompt 找到 'Today's date is' 短语(该版本可能已移除日期注入)"
    date_str = m.group(1)
    sep = "/" if "/" in date_str else "-"
    # 撇号: Today 后第 5 个字符(Today + 撇号 + s)
    idx = prompt.find("Today")
    apos_char = prompt[idx + 5] if idx >= 0 and idx + 5 < len(prompt) else ""
    code = "U+%04X" % ord(apos_char[0]) if apos_char else "?"
    apos_info = APOS_VARIANTS.get(apos_char, (code, "未知变体(可能新版标记)"))
    marked = (apos_info[0] != "U+0027") or (sep == "/")
    return {"apos": apos_info, "date": date_str, "sep": sep, "marked": marked}, None


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print("[capture] 本地监听 http://127.0.0.1:%d (不外联,数据存本地)" % port)
    print("[capture] 步骤: 另一终端 export ANTHROPIC_BASE_URL=http://127.0.0.1:%d 后运行 claude -p hi" % port)
    print("[capture] 等待捕获...(超时 120s, Ctrl+C 中止)")
    _CaptureHandler.captured = {}
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", port), _CaptureHandler) as httpd:
        httpd.timeout = 120
        deadline = 120
        import time
        start = time.time()
        try:
            while not _CaptureHandler.captured and (time.time() - start) < deadline:
                httpd.handle_request()
        except KeyboardInterrupt:
            pass
    if not _CaptureHandler.captured:
        print("[capture] 未捕获到请求(claude 可能拒绝 http base_url,见 deep-water.md mitmproxy 方案)")
        return 1
    info, err = _analyze(_CaptureHandler.captured.get("system", ""))
    print("\n" + "=" * 50)
    print("运行时 prompt steganography 实锤分析")
    print("=" * 50)
    if err:
        print("ℹ️ %s" % err)
    else:
        apos_info = info["apos"]
        print("撇号: %s (%s)" % apos_info)
        print("日期: %s (分隔符: %s)" % (info["date"], info["sep"]))
        if info["marked"]:
            print("结论: 🚨 检测到隐写标记(撇号非标准 或 日期用 /)→ 当前请求正被标记!")
        else:
            print("结论: ✅ 未检测到隐写标记(撇号 U+0027 标准, 日期用 -)")
    # 存捕获(脱敏: system prompt 可能含敏感,截断)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured_prompt.json")
    try:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({
                "apos": info["apos"][0] if info else None,
                "date": info["date"] if info else None,
                "sep": info["sep"] if info else None,
                "marked": info["marked"] if info else None,
                "system_prompt_excerpt": (_CaptureHandler.captured.get("system", ""))[:500],
            }, f, ensure_ascii=False, indent=2)
        print("捕获已存: %s" % out)
    except Exception as e:
        print("存捕获失败: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
