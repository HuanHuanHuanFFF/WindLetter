# WindLetter v1.0 测试计划（验收基线）

## 1. 目标

确保 v1.0 实现满足协议正确性、安全性与工程可维护性要求，覆盖：

- public/obfuscation 两种模式
- signed/unsigned 两种内层类型
- ECC-only/Hybrid 两种算法组合
- 正例、负例、回归与互操作

## 2. 测试分层

### 2.1 单元测试（模块内）

- `core`
  - Base64URL/JCS 输入输出一致性
  - 长度校验、字段枚举校验、错误码映射

- `crypto`
  - X25519 共享秘密一致性
  - ML-KEM-768 封装/解封装一致性
  - HKDF 参数一致性（`salt/info/L`）
  - A256KW wrap/unwrap 一致性
  - A256GCM AAD/iv/tag 验证
  - Ed25519 sign/verify

- `protocol`
  - recipients->aad 计算一致
  - binding hash 计算与校验
  - signed/unsigned 字段存在性校验
  - profile 规则（ECC-only/Hybrid）
  - obfuscation rid 计算与常量时比较
  - 分桶填充逻辑 `{8,16,32}`

### 2.2 组件测试（跨模块）

- protocol + crypto 集成：完整 encrypt/decrypt 编排
- armor + protocol 集成：wire JSON 编解码稳定性
- api + protocol 集成：请求到结果语义完整性

### 2.3 端到端测试（E2E）

最小覆盖矩阵（至少）：

1. public + signed + X25519
2. public + signed + X25519Kyber768
3. public + unsigned + X25519
4. obfuscation + signed + X25519
5. obfuscation + signed + X25519Kyber768
6. obfuscation + unsigned + X25519Kyber768

每组包含：

- 单收件人
- 多收件人
- obfuscation 分桶诱饵场景

## 3. 负例测试（安全关键）

### 3.1 篡改检测

- 修改 `protected` / `aad` / `iv` / `ciphertext` / `tag`
- 修改 `recipients` 任一字段
- 修改内层 `jwe_protected_hash/jwe_recipients_hash`
- 修改 `signature` 或签名输入任一位

预期：均返回 `INVALID_MESSAGE`（或协议规定的统一错误口径）。

### 3.2 命中与路由

- public 模式无 `kid` 命中
- obfuscation 模式所有 `rid` 不命中

预期：返回 `NOT_FOR_ME`，且不泄露更多细节。

### 3.3 白名单与结构违规

- 非法 `enc/key_alg/cty/typ/ver`
- ECC-only 出现 `ek`
- Hybrid 缺失 `ek`
- signed 缺失 `alg/kid/signature`
- unsigned 出现 `signature`

预期：返回 `UNSUPPORTED` 或 `INVALID_MESSAGE`（按契约定义）。

### 3.4 边界值

- recipients 数量 `0/1/8/9/16/17/32/33`
- 字段长度非预期（rid/iv/tag/signature/ek）

预期：边界内成功，越界拒绝。

## 4. 互操作测试

- 固定测试向量（输入密钥、随机种子、期望 wire 字段）可重放。
- 同一向量在不同实现/语言下得到一致验证结果。
- 版本字段为 `1.0` 的消息必须可稳定处理。

## 5. 测试数据与策略

- 使用可复现随机源（测试环境）与真实 CSPRNG（生产环境）分离。
- 向量样本按模式/算法/签名类型分目录存放。
- 每个失败样本标注对应协议条款与错误类别。

## 6. CI 验收门槛

- 所有单元、组件、E2E、负例测试通过。
- 协议必做项（`doc/PROTOCOL_GAP_MATRIX.md` 的 WL-001~WL-018）100% 标记 `Done`。
- 无 `TODO/临时代码/绕过校验`。
- 关键安全测试（篡改检测、统一错误口径）不得降级为可选。

## 7. 回归与发布策略

- 每次合并请求必须跑全量测试。
- 新增算法 profile 时必须新增对应正例+负例+向量。
- 发布前执行一次“协议矩阵对账”（实现、测试、文档三方一致）。

---

测试依据：`doc/Wind Letter v1.0协议.md` 与 `doc/PROTOCOL_GAP_MATRIX.md`。
