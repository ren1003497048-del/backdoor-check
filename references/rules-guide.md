# 规则库扩展指南(未来防御,泛化各版本)

> 如何为 backdoor-check 新增检测签名,使其覆盖未来出现的新后门/新版本。
> 核心思想:**引擎不动,只加规则**。新后门事件 = 新增签名 + 版本区间。

## 一、签名驱动架构

检测能力分三层:
- **引擎**(engine/):工具无关原语,稳定不改
- **规则**(rules/*.json):检测签名 + 版本区间 + 端点/指纹,**社区可扩展**
- **适配**(adapters/):工具配置路径

新增后门检测 = 改规则库,不动引擎。

## 二、新增后门事件的步骤

### 1. advisories.json 加事件(版本区间)
```json
{
  "id": "<事件标识-YYYY-MM>",
  "title": "...",
  "source": "<研究者/公告来源>",
  "affected_ranges": [{"gte": "x.y.z", "lte": "x.y.z"}],
  "severity": "crit|warn",
  "remediation": "..."
}
```

### 2. 对应规则文件加签名

| 后门类型 | 规则文件 | 加什么 |
|---------|---------|--------|
| prompt 注入(steganography) | fingerprints.json `steganography` | 触发条件/载体签名(时区/撇号/xor_key+lab_keywords) |
| 遥测/外联 | endpoints.json | 端点 host + severity |
| 指纹收集 | fingerprints.json | 机器标识/env/SDK 函数签名 |
| 配置载体(hooks/MCP/base_url) | permissions.json | 危险开关/权限模式 |

### 3. 签名无法覆盖时,加检测模块

在 engine/ 加模块(参考 `steganography.py` 的 XOR 解码器),暴露 `check(ctx) -> List[Finding]`,
在 check.py 的 `dim_modules` 注册维度代号(如 "J": ("engine.newcheck", "check"))。

## 三、版本-签名映射:确定性优先于版本

用户反馈:版本是最简单的问题,只作辅助筛查,不作核心依据。因此:

- **A1 版本检查**:辅助初筛(快速判断是否落在已知区间)。
- **I 维度静态签名 + XOR 解码**:不依赖版本号,直接在二进制找签名。**即使版本号被篡改也能检出**。这才是核心证据。
- 签名不绑定版本 → 任何版本的二进制都可扫。旧版含签名 → crit;新版移除 → pass。

## 四、泛化到各版本

- **签名驱动**:签名不绑定版本,扫任意版本二进制。
- **XOR 解码器泛化**:对任何 base64+XOR 混淆,调 `xor_key` 即可还原。新混淆后门只需加 key + 关键词到 `fingerprints.json/steganography`。
- **规则库版本化**:rules/*.json 含 `version` + `updated`,随安全研究更新(不自动外联拉取)。

## 五、贡献流程

1. 发现新后门/签名 → 对应 rules/*.json 加条目
2. 本地测试:`python3 scripts/check.py --dim <X> --format text` 验证命中
3. 构造测试数据验证检出率(如 steganography 的 XOR 解码器测试)
4. `python3 scripts/check.py --self-check` 确认不破坏自身安全
5. 提交 PR

## 六、当前已覆盖的后门签名

| 事件 | 签名位置 | 检测维度 |
|------|---------|---------|
| NVDB 后门(2.1.91-2.1.196) | advisories.json | A1(版本辅助) |
| prompt steganography(Thereallo) | fingerprints.json/steganography | I1(签名+XOR 确定性) |
| 配置层三载体(Check Point) | permissions.json | D/E/F |
| 源码泄露(2026-03) | advisories.json | A3(完整性)+ --verify-registry |
| 用户画像定位特征 | fingerprints.json/user_profiling_indicators | C5/C6(启发式) |
