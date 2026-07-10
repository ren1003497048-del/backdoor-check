# -*- coding: utf-8 -*-
"""文件系统 helper: 配置读取/文件发现/哈希/权限。

纯本地文件操作,不发起任何网络请求。供 config_audit / version 等维度调用。
"""
from __future__ import annotations

import os
import json
from typing import Any, Optional, Dict, List

from engine import platform


def read_json(path: str) -> Optional[Any]:
    """读取 JSON 文件,失败返回 None(容错)。"""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def read_text(path: str, limit: Optional[int] = None) -> str:
    """读取文本文件。limit 限制字节数。"""
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit) if limit else f.read()
    except Exception:
        return ""


def file_hash(path: str) -> Optional[str]:
    return platform.file_hash(path, "sha512")


def file_mode(path: str) -> Dict[str, Any]:
    return platform.file_mode_info(path)


def exists(path: str) -> bool:
    return os.path.exists(path)


def list_dir(path: str) -> List[str]:
    """列出目录下文件(非递归)。不存在返回空。"""
    if not path or not os.path.isdir(path):
        return []
    try:
        return os.listdir(path)
    except Exception:
        return []


def expand(path: str) -> str:
    return os.path.expanduser(path)
