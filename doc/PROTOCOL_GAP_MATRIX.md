# WindLetter v1.0 协议差距矩阵（重写基线）

## 1. 目的与使用方式

本矩阵用于把 `doc/Wind Letter v1.0协议.md` 的要求逐条映射到实现状态，作为：

- 重写开发排期依据
- 评审与验收打勾清单
- 回归测试覆盖索引

状态枚举：

- `NotStarted`：未实现
- `InProgress`：实现中
- `Done`：已实现并有测试
- `Blocked`：存在外部阻塞

当前基线（v1.0 分支重建初期）：**全部协议项默认 `NotStarted`**，除非另有标注。

## 2. 总体结论

- 当前仓库已完成 Maven 多模块骨架，尚未进入协议代码实现阶段。
- v1.0 必做项（字段、流程、校验、错误）均未完成实现与验证闭环。
- 本文档作为“从 0 到 1”的执行与验收主清单。

## 3. 必做项矩阵（v1.0）

| ID | 协议章节 | 要求 | 优先级 | 状态 | 验收标准 |
|---|---|---|---|---|---|
| WL-001 | §0/附录1 | 传输唯一结构（outer 字段集）固定 | MUST | NotStarted | JSON 字段齐全，未知关键字段拒绝 |
| WL-002 | §1.1 | `aad=Base64URL(JCS(recipients))` | MUST | NotStarted | 复算一致，不一致即拒绝 |
| WL-003 | §1.1/§5.2 | `jwe_protected_hash/jwe_recipients_hash` 绑定校验 | MUST | NotStarted | 任一不匹配返回 InvalidMessage |
| WL-004 | §1.2 | `protected` 字段校验（ver/typ/cty/wind_mode/enc/key_alg） | MUST | NotStarted | 白名单外值拒绝 |
| WL-005 | §1.3/§4.1 | public 模式字段约束（sender/recipient kid） | MUST | NotStarted | 缺失/多余字段均拒绝 |
| WL-006 | §1.3/§4.2/§6 | obfuscation 模式字段约束（epk/rid/可选ek） | MUST | NotStarted | 与算法 profile 严格匹配 |
| WL-007 | §3.0/§4.0C | signed/unsigned 结构切换规则 | MUST | NotStarted | `cty/typ/alg/kid/signature` 一致性通过 |
| WL-008 | §4.0A | ECC-only 规则：无 `ek`，`Z=SS_ECC` | MUST | NotStarted | 出现 `ek` 或缺失必要字段即拒绝 |
| WL-009 | §4.0B | Hybrid 规则：有 `ek`，`Z=SS_ECC||SS_PQ` | MUST | NotStarted | `ek` 缺失或解封装失败即拒绝 |
| WL-010 | §4.1/§4.2 | `KEK` 派生参数（salt/info/L）按算法固定 | MUST | NotStarted | 派生参数与协议一致 |
| WL-011 | §4.1/§4.2 | CEK Wrap/Unwrap（A256KW） | MUST | NotStarted | wrap/unwrap 对称且错误可归类 |
| WL-012 | §4.1/§4.2 | GCM AAD 拼接 `ASCII(protected+"."+aad)` | MUST | NotStarted | 篡改 protected/aad/iv/ct/tag 必失败 |
| WL-013 | §4.2/§6.1 | obfuscation `rid` 派生与常量时比较 | MUST | NotStarted | rid 不命中 -> NotForMe |
| WL-014 | §6.2 | 分桶填充 `{8,16,32}` 与诱饵长度一致性 | MUST | NotStarted | m 映射桶正确；>32 拒绝 |
| WL-015 | §7.2 | 算法白名单严格执行 | MUST | NotStarted | 非白名单返回 Unsupported/Invalid |
| WL-016 | §7.1 | 长度规范校验（iv/tag/rid/ek/signature 等） | MUST | NotStarted | 长度异常拒绝 |
| WL-017 | §8 | 错误语义统一（NotForMe/InvalidMessage） | MUST | NotStarted | 对外错误口径可控且稳定 |
| WL-018 | §9 | 安全边界显式声明（非前向安全等） | MUST | NotStarted | API 文档明确风险边界 |

## 4. 可选增强项（v1.0+）

| ID | 项目 | 优先级 | 状态 | 说明 |
|---|---|---|---|---|
| WL-X01 | 文本 Armor 格式增强 | SHOULD | NotStarted | 不改变 wire JSON 语义 |
| WL-X02 | 向量导入导出工具 | SHOULD | NotStarted | 便于跨语言互操作 |
| WL-X03 | 更细粒度内部诊断码 | MAY | NotStarted | 对外仍保持统一错误 |

## 5. 与测试计划映射

- `WL-001~WL-007`：结构与流程测试（见 `doc/TEST_PLAN_V1.md` 的单元与端到端正例）
- `WL-008~WL-014`：算法与模式测试（含 public/obfuscation + ECC/Hybrid）
- `WL-015~WL-018`：负例与安全边界测试

## 6. 更新规则

- 每完成一项实现并补齐测试后，状态才可从 `NotStarted/InProgress` 更新为 `Done`。
- 未通过测试不得标记 `Done`。
- 任何协议解释变更必须同步更新本矩阵和对应测试。

---

协议来源：`doc/Wind Letter v1.0协议.md`。
