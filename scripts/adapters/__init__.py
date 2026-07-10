# -*- coding: utf-8 -*-
"""backdoor-check 工具适配层。

每个 AI 编程工具一个 adapter 模块,负责:
- discover(): 发现工具(版本/路径/来源)
- config_paths(): 该工具的配置文件路径
- known_endpoints(): 该工具已知合法 API host
- integrity_targets(): 需校验完整性的文件
- process_names(): 进程名模式(网络连接归属)

首发: claude_code(完整)。其他工具见 references/adapters-guide.md,按模板贡献。
"""
