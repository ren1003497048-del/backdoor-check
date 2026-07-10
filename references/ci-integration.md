# CI 集成

> 将 backdoor-check 接入 CI/CD 流水线,在 PR/提交时自动检测后门与配置风险。

## 一、JSON 输出 schema

`--mode ci --format json` 输出:

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-07-09T18:30:00",
  "scan_mode": "ci",
  "tool": {
    "name": "claude-code",
    "version": "2.1.205",
    "source": "npm:@anthropic-ai/claude-code",
    "path": "~/.npm-global/bin/claude"
  },
  "platform": {
    "os": "darwin",
    "arch": "arm64",
    "hostname_hash": "a1b2c3d4"
  },
  "self_check": {
    "no_outbound_static": true,
    "no_outbound_runtime": true,
    "redaction": true
  },
  "summary": {
    "total": 24,
    "pass": 7,
    "warn": 9,
    "crit": 3,
    "info": 5,
    "score": 0
  },
  "findings": [
    {
      "id": "C4",
      "dim": "fingerprint",
      "severity": "crit",
      "title": "综合: 二进制具备完整指纹收集链路",
      "evidence": "<redacted:...>",
      "remediation": "...",
      "advisory": "nvdb-2026-07-08"
    }
  ]
}
```

**字段**:
- `summary.score`:0–100,`100 - crit*25 - warn*8`(下限 0)
- `findings[].advisory`:关联的已知事件 ID(如 `nvdb-2026-07-08`),便于联动事件库
- `self_check`:技能自身安全状态(均为 true 才可信)

## 二、退出码

| 退出码 | 含义 | CI 行为 |
|--------|------|---------|
| 0 | 全 pass(可能含 info) | 通过 |
| 1 | 有 warn | 可配置(建议通过但告警) |
| 2 | 有 crit | 失败(拦截) |

## 三、GitHub Actions

```yaml
name: backdoor-check
on: [pull_request, push]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Claude Code(如需检测)
        run: npm install -g @anthropic-ai/claude-code
      - name: backdoor-check
        run: |
          python3 skills/backdoor-check/scripts/check.py \
            --mode ci --format json --dims A,B,F \
            --out backdoor-report.json
          # 退出码 2(crit)则失败
        continue-on-error: false
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: backdoor-report
          path: backdoor-report.json
```

**注意**:CI 环境通常无 claude 进程运行,B1(进程连接)可能无数据;建议 CI 跑 `--dims A,B,F`(版本/网络静态/凭证)或 `A,F`(版本/凭证)。

## 四、GitLab CI

```yaml
backdoor-check:
  script:
    - python3 skills/backdoor-check/scripts/check.py --mode ci --format json --dims A,B,F
  artifacts:
    when: always
    paths:
      - backdoor-report.json
```

## 五、pre-commit

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: backdoor-check
      name: backdoor-check
      entry: python3 skills/backdoor-check/scripts/check.py --mode ci --dims A,F
      language: system
      pass_filenames: false
```

## 六、baseline 策略(A3 完整性)

A3 依赖 `scripts/baseline.json` 做哈希 diff:
- **首次运行**(无基线):自动建立基线(info),记录当前文件哈希。
- **后续运行**:diff 检测篡改(哈希变化 → crit)。
- **版本升级后**:文件会变化(误报),需删除 `baseline.json` 重建。
- **CI 中**:基线应提交到仓库(在可信时刻建立),作为团队共享的完整性基准。

```bash
# 在可信时刻建立/重建基线
rm -f skills/backdoor-check/scripts/baseline.json
python3 skills/backdoor-check/scripts/check.py --dim A
git add skills/backdoor-check/scripts/baseline.json
git commit -m "chore: refresh backdoor-check baseline"
```

## 七、CI 维度选择建议

| 场景 | 推荐 --dims | 理由 |
|------|------------|------|
| 快速 PR 检查 | A,F | 版本+凭证(廉价,无进程依赖) |
| 完整检查 | A,B,F | + 网络静态(二进制 strings) |
| 本地全量 | (不指定,默认 A-H) | 全维度 |
