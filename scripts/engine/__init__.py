# -*- coding: utf-8 -*-
"""backdoor-check 检测引擎包。

模块:
- platform:       跨平台系统命令原语(进程/网络/二进制/文件系统)
- report:         报告装配 + 中心化脱敏 + 分级输出 + 退出码
- (Phase 3)       network / binary / fs / fingerprint / config_audit

自身安全: 本包不直接发起网络;socket 守卫在 check.py 启动时挂载。
"""
