# -*- coding: utf-8 -*-
"""二进制静态分析 helper: strings 抽取(带缓存)+ 模式扫描。

供 A3(完整性)/B2/B7(网络 strings)/C4(指纹逻辑)调用。

【局限】编译型二进制(如 claude.exe 237MB)可能 strip/混淆,
strings 只命中未混淆部分 → 启发式证据,未发现 ≠ 不存在。
报告须声明此局限。
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple, Dict

from engine import platform

# 内存缓存: 同一二进制不重复抽取(237MB 抽取耗时)
_strings_cache: Dict[str, str] = {}

# 缓存文本上限(避免内存爆炸;超出截断,足够覆盖签名扫描)
_CACHE_TEXT_LIMIT = 64 * 1024 * 1024  # 64MB


def extract_strings(path: str, max_lines: int = 500000) -> str:
    """抽取二进制 strings(带内存缓存)。"""
    if not path or not os.path.isfile(path):
        return ""
    if path in _strings_cache:
        return _strings_cache[path]
    text = platform.binary_strings(path, max_lines=max_lines)
    if len(text) > _CACHE_TEXT_LIMIT:
        text = text[:_CACHE_TEXT_LIMIT]
    _strings_cache[path] = text
    return text


def scan_literal(text: str, patterns: List[str]) -> List[Tuple[str, int, str]]:
    """字面量扫描(找签名字符串,非正则)。返回 [(pattern, count, sample), ...]。"""
    results = []
    for pat in patterns:
        if not pat:
            continue
        idx = text.find(pat)
        if idx >= 0:
            count = text.count(pat)
            start = max(0, idx - 20)
            sample = text[start:idx + len(pat) + 20].replace("\n", " ").strip()
            results.append((pat, count, sample[:100]))
    return results


def scan_regex(text: str, patterns: List[str]) -> List[Tuple[str, int, str]]:
    """正则扫描。返回 [(pattern, count, sample), ...]。"""
    results = []
    for pat in patterns:
        try:
            matches = list(re.finditer(pat, text))
            if matches:
                m = matches[0]
                sample = text[max(0, m.start() - 10):m.end() + 10].replace("\n", " ").strip()
                results.append((pat, len(matches), sample[:100]))
        except re.error:
            continue
    return results


def find_urls(text: str) -> List[str]:
    """从 strings 文本抽取 URL(host 列表,去重)。"""
    urls = set()
    for m in re.finditer(r"https?://([A-Za-z0-9.\-]+)", text):
        urls.add(m.group(1).lower())
    return sorted(urls)


def clear_cache() -> None:
    """清理 strings 缓存(长 watch 模式避免内存增长)。"""
    _strings_cache.clear()
