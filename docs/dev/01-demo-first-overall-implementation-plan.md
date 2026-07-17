# WindLetter v1.0 Demo-First 整体实现计划

> 状态：阶段 2 已完成并封板；阶段 3 已获用户确认并进入开发。ML-KEM kid 协议修订与 Public Hybrid 设计已完成，当前按阶段 3 可执行计划推进。

**目标：** 在不使用 mock、不绕过协议校验、不过度建设未来框架的前提下，完成 WindLetter v1.0 当前已定义能力的真实、完整、可运行 Demo。

**总体方法：** 先打通一个最小但真实的纵向协议闭环，再沿 signed、Hybrid、obfuscation、API、armor 逐步扩展。每个阶段都必须增加可经真实 JSON wire 运行的能力，并在阶段结束后停下来向用户报告证据、确认下一阶段范围。

**技术基线：** Java 17、Maven 多模块、Bouncy Castle、Jackson、RFC 8785 JCS、JUnit 5。

---

## 1. 计划约束与权威顺序

本计划服从以下顺序：

1. 当前真实源码决定“已经实现了什么”。
2. `docs/Wind Letter v1.0协议.md` 决定协议行为。
3. 本计划决定 Demo-First 的开发顺序和阶段边界。
4. `docs/風笺设计.md`、旧开发提示词和历史计划仅作背景；与以上内容冲突时不作为实现依据。

执行约束：

- 所有开发继续在 `spike/demo-v0` 上进行。
- 每个阶段开始前重新检查分支、HEAD、工作区、源码、协议和测试基线。
- 阶段内允许把紧密相邻的职责合并，不按单个类或单个函数切碎任务。
- 阶段结束后必须更新本文状态、提交验证证据并停止，等待用户确认下一阶段。
- 未经用户明确要求，不提交、不合并、不推送。
- 不丢弃、覆盖或顺手整理用户已有改动。

## 2. 2026-07-13 真实基线

会话基线：

- 分支：`spike/demo-v0`
- HEAD：`2d29bb35126e`
- JDK：`C:\Users\幻\.jdks\ms-17.0.16`
- 全量测试：106 个测试通过，0 failure，0 error
- 工作区中 `docs/README.md` 被 Git 标记为修改，但内容 diff 为空；本计划不处理该文件

| 模块 | 当前真实状态 | 距离完整 Demo 的主要缺口 |
|---|---|---|
| `windletter-core` | 已有错误码和基础测试 | 需要校准内部细分错误与公开错误语义的边界 |
| `windletter-crypto` | 主要原语与 51 个测试已存在，可作为稳定基础层 | 协议层还没有把原语编排成完整收发链；敏感材料生命周期需要在调用层落实 |
| `windletter-protocol` | 已有 outer wire 模型和 strict parser，35 个测试通过 | 缺 Sender、Receiver、AAD/JCS、路由、KEK/CEK、GCM flow、inner、binding、签名与完整矩阵 |
| `windletter-api` | 已有接口、DTO、SPI，19 个测试通过 | 只有契约，没有实际 Sender/Receiver；私钥仍以原始 `byte[]` material 表达 |
| `windletter-armor` | Maven 模块存在 | 尚无可用实现，且部分格式缺少足够正式的编码规范 |
| `windletter-testkit` | Maven 模块存在 | 尚无完整向量、负例矩阵、跨模块 E2E 或可运行 Demo 入口 |

当前端到端主链断点位于 outer parser 之后：仓库能解析部分真实 outer wire，但还不能从真实 payload 生成 Wind Letter，也不能完成路由、解密、inner/binding/验签并恢复 payload。

## 3. 总体切分决策

本计划采用 7 个大阶段：

1. Public × X25519 × unsigned 第一条真实纵向主链，并收口安全基础。
2. 在同一主链加入 signed/Ed25519 身份认证。
3. 扩展 public Hybrid，封板 public 四组合。
4. 扩展 obfuscation X25519、rid 路由与固定分桶。
5. 扩展 obfuscation Hybrid，封板完整八组合。
6. 接通 `windletter-api` 的真实 Sender/Receiver 编排。
7. 完成 armor、testkit、可运行 Demo 和最终全量门禁。

选择 7 个阶段的原因：

- 前 5 个阶段每次只增加一个协议正交维度，失败时能定位到 signed、Hybrid 或 obfuscation，而不是在一次大集成中混杂。
- API 的密钥契约安全问题在阶段 1 处理，实际高层 facade 在协议矩阵稳定后单独接通，避免协议层反向依赖 API。
- Armor 当前存在规范缺口，把它与 API 分开可以防止未定义格式阻塞协议主链，也避免最终阶段同时承担 API、armor、testkit 和 Demo 四项大集成。
- 每一阶段都是可评审的能力增量，不把计划切成长期没有端到端价值的小组件。

不采用以下路线：

- 不先横向写完全部 Sender 再写 Receiver；真实集成风险暴露太晚。
- 不一次实现全部 8 个协议组合；难以隔离 mode、algorithm、inner 和 wire 问题。
- 不先建设算法插件、通用 KMS、DI 容器或性能体系；它们不缩短当前 Demo 主链。

## 4. 进入实现时采用的协议解释

批准本计划即表示以下内容作为 Demo 阶段默认解释；若用户或正式协议后续给出更明确结论，以新结论更新计划后执行。

### 4.1 Inner wire

- signed inner 使用 flattened JWS：`protected`、`payload`、`signature`。
- unsigned inner 的 `inner_bytes` 直接是 `{protected,payload}` 根对象，不采用附录展示用的 outer `ciphertext` 包装。
- signed inner protected 必须有 `typ="wind+jws"`。
- unsigned inner protected 必须有 `typ="wind+inner"`。
- outer `cty` 与 inner `typ` 必须严格匹配。

这是对正式协议中 signed header 字段表与其他章节之间不一致的收口，不允许实现根据样例“猜一种能跑的格式”。

### 4.2 Canonical bytes 与认证输入

- `outer.aad = Base64URL(JCS(final recipients array))`。
- protected binding 对 decoded protected JSON 的 JCS bytes 做 SHA-256。
- recipients binding 对最终 recipients 数组的 JCS bytes 做 SHA-256。
- AES-GCM AAD 使用 wire 上原样的 `ASCII(protected_b64 + "." + aad_b64)`。
- Sender 对 protected、inner header、inner payload 和 recipients 采用唯一确定性序列化规则，并用字节级测试锁定。

### 4.3 Strict validation

Outer 与 inner 都必须：

- 拒绝 duplicate member、unknown field、缺失字段、禁止字段、`null`、错误 JSON 类型和 trailing content。
- Base64URL 必须使用无 padding 的 canonical 表示，解码后重编码不一致即拒绝。
- 严格检查固定长度和 mode/key_alg/cty 的条件字段。
- 对 JSON 深度、recipient 数量、ciphertext 和 payload 设置明确的实现上限，并在阶段 1 子计划中写成常量和边界测试。
- obfuscation outer 的 recipients 数量只能是 8、16 或 32；当前 parser 接受 1 个 entry 是已知协议偏差，阶段 1 修复。

### 4.4 错误语义

公开的消息处理结果只区分：

- `NOT_FOR_ME`：public 没有 kid 命中，或 obfuscation 完整扫描后没有 rid 命中。
- `INVALID_MESSAGE`：解析、结构、AAD、unwrap、GCM、inner、binding、签名等其他消息失败。

内部仍保留细分 `ErrorCode` 供测试和受控诊断使用，但公开结果不得形成“在哪一步失败”的 oracle。现有 `UNSUPPORTED` 状态需要在阶段 1 明确限制为本地调用/能力配置错误，不能用于区分攻击者提交的 wire 内容。

### 4.5 密钥与敏感数据生命周期

- production API/SPI 不返回或长期持有私钥 `byte[]`。
- 私钥通过已有 crypto handle 和 `AutoCloseable` lease 暴露，调用方使用 try-with-resources。
- CEK、KEK、ECC/PQ shared secret 和临时私钥在所有成功/失败路径中关闭或清零。
- 不在日志、异常消息或 Demo 输出中显示私钥、shared secret、CEK、KEK 或完整敏感标识。

### 4.6 Obfuscation

- Sender 只接受 1 到 32 个真实收件人，并填充到 8、16、32。
- 真实项与诱饵在最终计算 AAD/binding 前使用 CSPRNG 随机重排。
- Receiver 不推断真实人数，也不区分哪些 entry 是诱饵。
- rid 使用常量时间比较；Hybrid 扫描不因单个 entry 不匹配而提前返回。

### 4.7 Armor 边界

- 正式 Wind Letter v1.0 wire 是 outer JSON；Armor 作为 WindLetter 项目扩展，只可逆封装 exact UTF-8 outer JSON bytes，不改变协议语义。
- Base64URL text armor 和 binary armor 必须先形成明确 framing/canonical/error contract 再实现。
- 现有文档没有给出足以唯一实现 `WIND_BASE_1024F_V1` 的完整 1024 字符表和 bit packing。阶段 7 开始前必须由用户批准完整 contract；在此之前不自行发明，也不宣称该格式完成。

## 5. 阶段总表

| 阶段 | 能力增量 | 主要模块 | 状态 |
|---|---|---|---|
| G0 | 批准本总体计划和默认协议解释 | `docs/dev` | 已完成 |
| 1 | public × X25519 × unsigned 真实多收件人 E2E | protocol、api contract | 已完成（285 tests；0 failure/error/skip） |
| 2 | public × X25519 × signed | protocol | 未开始（等待用户确认） |
| 3 | public × Hybrid × signed/unsigned | protocol | 未开始 |
| 4 | obfuscation × X25519 × signed/unsigned | protocol | 未开始 |
| 5 | obfuscation × Hybrid × signed/unsigned；8 组合封板 | protocol、testkit tests | 未开始 |
| 6 | API Sender/Receiver 真实 raw-wire 编排 | api、protocol | 未开始 |
| 7 | Armor、最终 testkit、可运行 Demo | armor、api、testkit | 未开始 |

## 6. 阶段 1：Public X25519 Unsigned 真实纵向主链

### 能力目标

从真实 payload 和至少两个真实收件人开始，完成：

```text
ProtocolSender
  -> UTF-8 outer JSON bytes
  -> strict parser
  -> public kid routing
  -> X25519/HKDF/A256KW/AES-GCM
  -> strict unsigned inner
  -> binding
  -> original payload
```

本阶段同时修复会污染后续所有分支的安全基础：duplicate key、obfuscation bucket、canonical Base64URL、AAD/JCS 和 API raw-private-key contract。

### 预计主修改面

- `windletter-protocol/.../parser/`
- `windletter-protocol/.../canonical/`
- `windletter-protocol/.../auth/`
- `windletter-protocol/.../binding/`
- `windletter-protocol/.../inner/`
- `windletter-protocol/.../routing/`
- `windletter-protocol/.../sender/`
- `windletter-protocol/.../receiver/`
- `windletter-api/.../spi/` 的 handle/lease 契约
- `windletter-api/pom.xml` 的 crypto handle 依赖

阶段子计划：`docs/dev/02-phase-1-public-x25519-unsigned-plan.md`

### 完成判定

- 同一真实消息中的至少两个收件人都能从实际 JSON bytes 恢复原 payload。
- 非收件人得到 `NOT_FOR_ME`；命中后的任何认证失败得到 `INVALID_MESSAGE`。
- recipients、aad、protected、iv、ciphertext、tag 和两项 binding 的独立篡改均不能返回 payload。
- duplicate/unknown/malformed/non-canonical Base64URL 和非法 obfuscation bucket 被拒绝。
- production API/SPI 不再返回原始私钥 `byte[]`，所有 lease 有销毁测试。
- E2E 不 mock 协议核心，不在 Sender/Receiver 间直接传内存 DTO。
- `mvn -q -pl windletter-protocol,windletter-api -am test` 与 `mvn -q test` 通过。

### 实际完成证据（2026-07-14）

- 已完成 `public × X25519 × unsigned` 的真实 Sender → JSON String → strict Receiver 纵向链；三个真实收件人分别只凭同一 String、自己的 private handle 和 sender public-key resolver 恢复同一 binary payload。
- Sender 使用真实 RFC 7638 kid、X25519、HKDF-SHA256、A256KW、A256GCM、JCS AAD 与两项 binding；Receiver 固定执行 strict parse/profile → AAD → routing → sender-key binding → unwrap → GCM → strict inner → binding。
- 已覆盖 unrelated `NOT_FOR_ME`、multi-recipient 首/中/尾路由、strict outer/inner、资源上限、canonical Base64URL、AAD/unwrap/GCM/inner/binding 定向负例，以及经过真实 GCM 重加密后确实到达两项 binding gate 的攻击 fixture。
- API/SPI 已改为 owned lease / borrowed handle 契约，production surface 不再返回 raw private-key bytes；成功与失败路径均有关闭或清零证据。
- JDK 17 最终 `mvn -q clean test` exit 0；clean 后 core 1、crypto 51、protocol 195、API 38，共 285 tests，0 failure、0 error、0 skipped。
- `git diff --check` 通过；最终 spec 与 code/security review 均 PASS，无未处理 Critical/Important 或 P0/P1。
- 详细任务、向量、错误语义和后置债务见 `docs/dev/02-phase-1-public-x25519-unsigned-plan.md`。

### 本阶段不做

- Ed25519 signed
- Hybrid
- obfuscation 发送/路由主链
- armor
- API facade 实现
- 通用 key-management 框架

## 7. 阶段 2：Signed 与 Ed25519 来源认证

### 能力目标

在阶段 1 主链上增加 `public × X25519 × signed`，并保持 unsigned 不回归：

- `cty="wind+jws"` 和 `typ="wind+jws"`。
- strict signed inner。
- exact `protected_b64 + "." + payload_b64` 签名输入。
- Ed25519 Sender 签名、Receiver 可信公钥解析和验签。
- `SIGNED_VALID` 与 `UNSIGNED` 明确区分。

预计主修改面：

- `windletter-protocol/.../inner/`
- `windletter-protocol/.../signature/`
- 阶段 1 的 `ProtocolSender`、`ProtocolReceiver` 和 result model

阶段子计划：`docs/dev/03-phase-2-signed-authentication-plan.md`

### 完成判定

- public/X25519/signed 真实多收件人 E2E 通过。
- 正确签名只在可信 key 验证后返回认证身份。
- 协议层对坏签名/未知 signing kid 使用 `SIGNATURE_INVALID`，对严格结构错误使用 `INVALID_FIELD`；阶段 6 的 API facade 再统一为安全的公开错误语义。
- binding 和 signature 的定向负例必须使用“经过真实 GCM 重新加密、GCM 本身仍合法”的恶意 inner fixture，确保测试确实到达 binding/验签层。
- signed 失败不返回 payload；unsigned 不伪造 sender identity。
- 阶段 1 全部正负例继续通过。
- 相关模块测试和 `mvn -q test` 通过。

### 实际封板（2026-07-17）

- `public × X25519 × signed × 三收件人` 已从同一个真实 JSON wire 恢复 binary 与 empty payload，并返回 `SIGNED_VALID` 和可信 Ed25519 identity。
- Binding、signature、unknown real signing key 和 strict signed inner 负例均使用真实密码学链路；需要到达 inner gate 的用例使用真实 A256GCM 重新加密。
- Task 5 focused gate 15/15 通过；protocol 模块 345 tests 通过。
- Microsoft OpenJDK 17.0.16 下最终 `mvn -q clean test`：44 suites、435 tests，0 failure、0 error、0 skipped。
- Spec review 与 code/security review 均 PASS，无未处理 P0/P1；开放 P2 记录在阶段子计划 §11。
- 阶段 2 由 6 个独立闭环提交组成；未推送，既有 `docs/README.md` 行尾状态噪音未纳入提交。

## 8. 阶段 3：Public Hybrid 封板

### 能力目标

新增：

- `public × X25519ML-KEM-768 × unsigned`
- `public × X25519ML-KEM-768 × signed`
- 每个真实收件人独立 ML-KEM encapsulation 和 `ek`。
- `Z = SS_ECC || SS_PQ`、Hybrid 专用 HKDF info、KEK/CEK unwrap。
- X25519-only 与 Hybrid 条件字段严格隔离。

预计主修改面：

- `windletter-crypto/.../api/` 与 `.../bc/` 的 ML-KEM secret lifecycle
- `windletter-protocol/.../key/`
- `windletter-protocol/.../recipient/`
- public routing、Sender、Receiver
- Hybrid wire/strict tests

阶段设计：`docs/dev/04-phase-3-public-hybrid-design.md`

阶段实施计划：`docs/dev/05-phase-3-public-hybrid-implementation-plan.md`

### 完成判定

- public 的 2 algorithm × 2 signing 共 4 个组合全部经真实 wire E2E。
- 至少两个不同 Hybrid 收件人都能解密同一消息，且各自 entry 使用独立 `ek`。
- Hybrid 缺少/多出条件字段、ML-KEM kid 错误、`ek` 长度错误均被拒绝。
- direct protocol flow 对 decapsulation/unwrap 使用相同 code、泛化 message 和 null cause，不返回 payload；未来 API facade 再统一公开错误。
- 相关模块测试和 `mvn -q test` 通过。

## 9. 阶段 4：Obfuscation X25519、rid 与固定分桶

### 能力目标

新增：

- `obfuscation × X25519 × unsigned`
- `obfuscation × X25519 × signed`
- 每消息临时 X25519 epk。
- `rid/ecc` 派生、完整扫描和常量时间比较。
- 8/16/32 固定 bucket、ECC 等长诱饵和 CSPRNG shuffle。

预计主修改面：

- `windletter-protocol/.../routing/Obfuscation*`
- `windletter-protocol/.../padding/`
- obfuscation recipient builder、Sender、Receiver
- obfuscation strict/negative tests

阶段子计划：`docs/dev/05-phase-4-obfuscation-x25519-plan.md`

### 完成判定

- signed/unsigned 两种 obfuscation/X25519 多收件人 E2E 通过。
- 非收件人完成全列表扫描后得到 `NOT_FOR_ME`。
- bucket 覆盖 `1→8`、`8→8`、`9→16`、`16→16`、`17→32`、`32→32`。
- Sender 拒绝 0 和 33 个真实收件人；Receiver 拒绝非 8/16/32 的 wire。
- 诱饵与真实项全部进入最终 AAD/binding；不能通过字段长度区分。
- public 四组合不回归，相关模块测试和 `mvn -q test` 通过。

## 10. 阶段 5：Obfuscation Hybrid 与八组合封板

### 能力目标

新增最后两个协议组合：

- `obfuscation × X25519ML-KEM-768 × unsigned`
- `obfuscation × X25519ML-KEM-768 × signed`
- 每个 Hybrid entry 独立 ML-KEM `ek`。
- `rid/hybrid` 逐 entry 计算与完整扫描。
- 1088-byte Hybrid 诱饵 `ek`。
- 统一全矩阵 strict conditional validation 和错误语义。

预计主修改面：

- obfuscation Hybrid recipient builder/router
- Sender/Receiver 共用 flow
- `windletter-protocol/src/test/` 的 8 组合矩阵与篡改矩阵
- `windletter-testkit/src/test/` 的首批跨模块矩阵（如果模块依赖已经适合）

阶段子计划：`docs/dev/06-phase-5-obfuscation-hybrid-plan.md`

### 完成判定

- 2 mode × 2 algorithm × 2 signing 共 8 个组合全部真实 E2E。
- 文本 payload 和包含零字节/非 UTF-8 的 binary payload 都能往返。
- public/obfuscation 多收件人、8/16/32 bucket 全覆盖。
- 相同业务输入连续发送两次时，IV/ciphertext 必须不同；obfuscation 的 epk/rid、Hybrid 的 `ek` 也必须体现真实随机性。
- 所有组合覆盖字段错配、AAD、unwrap、GCM、inner、binding、signature 关键负例。
- Hybrid obfuscation 不因首个不匹配/诱饵提前结束；非收件人与命中后失败的公开语义正确。
- 相关模块测试和 `mvn -q test` 通过。

## 11. 阶段 6：接通 windletter-api 真实编排

### 能力目标

让调用者只通过 `WindLetterSender` / `WindLetterReceiver` 和 SPI 即可完成 8 个协议组合的 raw JSON 收发：

- resolver/store → private-key lease/public material。
- API request → protocol request。
- ProtocolSender → `EncryptedMessage.wireJson`。
- `DecryptRequest.wireJson` → strict parser → ProtocolReceiver → `DecryptResult`。
- `VerificationPolicy`、认证身份和错误映射。
- 一个简单 composition root；不引入 DI 容器。

预计主修改面：

- `windletter-api/pom.xml`
- `windletter-api/.../model/`
- `windletter-api/.../spi/`
- `windletter-api/.../impl/DefaultWindLetterSender.java`
- `windletter-api/.../impl/DefaultWindLetterReceiver.java`
- mapper、error mapper、runtime composition root

阶段子计划：`docs/dev/07-phase-6-api-orchestration-plan.md`

### 完成判定

- 用户只经公开 API 能以 `ArmorFormat.NONE` 跑通全部 8 个组合。
- API public mode 明确区分 sender encryption identity 与 signing identity。
- 所有 key lease 使用 try-with-resources；失败路径也销毁敏感 handle/material。
- `decrypt` 不绕过 signed 消息验签；`REQUIRE_SIGNED_VALID` 不接受 unsigned。
- `DecryptStatus`、`VerificationStatus`、payload、identity 和 `ErrorCode` 组合一致。
- API 真实 E2E、错误映射测试和 `mvn -q test` 通过。

## 12. 阶段 7：Armor、Testkit 与可运行 Demo

### 能力目标

在不改变 outer JSON 协议语义的前提下完成：

- 批准后的 Base64URL text armor contract 与实现。
- 批准后的 binary armor contract 与实现。
- 若完整字符表/packing contract 获批准，则实现 `WIND_BASE_1024F_V1`；否则不能把它计入完成项。
- Armor auto-detect、严格解析、长度/版本/非法输入处理。
- API armor 编排。
- testkit 完整正例、负例、向量和回归矩阵。
- 可由明确 Maven 命令运行的 `WindLetterDemo`。

预计主修改面：

- `windletter-armor/src/main/`
- `windletter-armor/src/test/`
- API armor mapper/输入选择
- `windletter-testkit/.../keys/InMemoryDemoKeyRepository.java`
- `windletter-testkit/.../demo/WindLetterDemo.java`
- `windletter-testkit/.../matrix/`、`negative/`、`vectors/`、`regression/`
- README/Demo 运行文档

阶段子计划：`docs/dev/08-phase-7-armor-testkit-demo-plan.md`

### Demo 必须实际展示

1. 输入真实 payload、多个真实收件人和可选签名身份。
2. 选择 mode、key algorithm、signed/unsigned 和 armor。
3. Sender 生成真实 outer JSON，并经实际 armor 文本或 bytes 传递。
4. Receiver 从 armor 重新解析 outer JSON。
5. Receiver 完成 strict validation、routing、unwrap、GCM、inner、binding 和可选验签。
6. 输出恢复的 payload 和 `SIGNED_VALID` / `UNSIGNED`。
7. 展示 `NOT_FOR_ME` 与统一 `INVALID_MESSAGE`，不泄露内部失败阶段。

### 完成判定

- Armor round-trip 保持 exact outer JSON bytes，不重解释协议字段。
- 非法 armor 不进入密码学主链，并映射为安全的公开错误。
- 自动化测试覆盖全部 8 个协议组合和所有获批准 armor 格式。
- Demo 至少实际运行以下代表用例：
  - public + X25519 + unsigned + 多收件人
  - public + Hybrid + signed + 多收件人
  - obfuscation + X25519 + signed
  - obfuscation + Hybrid + unsigned + padding
- 最终验收使用 `mvn -q clean verify`，排除陈旧构建产物和 Surefire 报告干扰。
- Surefire 全模块汇总为 0 failure、0 error、0 skipped；测试总数不得低于原有 106 加本计划新增测试。
- Demo 入口可复制运行，不依赖测试 runner，不输出任何密钥或 shared secret。
- README/Demo 文档包含 JDK 17 要求、命令、输入和预期结果。

## 13. 完整 Demo 覆盖矩阵

| Mode | Key algorithm | Unsigned | Signed | 首次完成 |
|---|---|---:|---:|---:|
| public | X25519 | 阶段 1 | 阶段 2 | 阶段 2 |
| public | X25519ML-KEM-768 | 阶段 3 | 阶段 3 | 阶段 3 |
| obfuscation | X25519 | 阶段 4 | 阶段 4 | 阶段 4 |
| obfuscation | X25519ML-KEM-768 | 阶段 5 | 阶段 5 | 阶段 5 |

附加矩阵：

- 每个组合：真实 wire 序列化/解析、text payload、binary payload。
- public：至少两个真实收件人；目标位于首/中/尾；非收件人。
- obfuscation：1/8/9/16/17/32 个真实收件人边界及 8/16/32 最终 bucket。
- signed：正确 key、未知 key、错误 key、坏签名、cty/typ 错配。
- wire：duplicate、unknown、missing/forbidden field、错误类型、trailing content、非 canonical Base64URL、固定长度。
- authentication：AAD、wrapped CEK、iv、ciphertext、tag、两项 binding、signature 独立篡改。
- armor：每个获批准格式 round-trip、非法字符、padding、截断、错误 magic/version、auto-detect 冲突。

## 14. 每阶段统一执行流程

每个阶段都按以下顺序执行：

1. 运行 `git status --short --branch`，记录 HEAD 和用户已有改动。
2. 重新阅读阶段涉及的真实源码、正式协议段落和本文状态。
3. 使用指定 JDK 17 运行相关测试与全量基线。
4. 在 `docs/dev/` 创建该阶段子计划，写明精确文件、测试、顺序和完成条件。
5. 采用测试先行方式实现，先建立能失败的协议/负例测试，再写生产代码。
6. 运行 focused tests、相关模块 tests 和 `mvn -q test`。
7. 复核真实 wire、敏感材料生命周期、公开错误语义和 P0/P1 风险。
8. 运行 `git diff --check`，核对实际变更文件，并检查没有新增 `@Disabled`、假阳性断言或被 mock 的密码学原语。
9. 更新本文阶段状态、能力矩阵、已知债务和实际验证证据。
10. 向用户报告“完成了什么、未完成什么、测试结果、风险与下一阶段建议”。
11. 停止开发，等待用户明确确认后再进入下一阶段。

默认验证命令：

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
mvn -q -pl <涉及模块> -am test
mvn -q test
```

## 15. 阶段通用质量门禁

每个阶段只有同时满足以下条件才能报告完成：

- 新增能力经过真实密码学原语和真实 JSON wire，而不是 mock/DTO shortcut。
- 正例、负例、端到端测试都存在并通过。
- 当前 106 个基线测试不得减少；不得用 `@Disabled`、放宽断言或只验证“不抛异常”制造通过。
- 测试可使用 in-memory key store/SPI fixture，但必须调用真实 Bouncy Castle 原语和正式 Sender/Receiver 主链。
- strict validation、AAD、binding、签名等适用安全步骤没有被绕过。
- 没有未处理的 P0/P1 协议、安全或正确性问题。
- 不因错误差异泄露 recipient、unwrap、GCM、binding 或签名失败阶段。
- 敏感 handle/material 在成功与异常路径均正确销毁。
- JDK 17 下 focused tests 和全量 reactor 均通过。
- `git diff --check` 无错误，实际变更文件与阶段范围一致。
- 普通维护性问题记录为 Demo 后债务，不冒充协议阻塞。
- 用户已经收到证据；下一阶段尚未自动开始。

## 16. Demo 后统一处理的事项

除非后续证明它们阻塞协议正确性，否则以下工作不进入当前 7 个阶段：

- parser/branch 重复代码的美化重构。
- 通用算法注册表、provider 插件化、ServiceLoader。
- DI 容器和跨模块通用框架。
- HSM、远程 KMS、复杂 key rotation、多租户密钥管理。
- 持久 replay cache、账户系统、网络传输或消息队列。
- streaming/分片/压缩、大 payload 零拷贝。
- public 大规模 recipient 优化、obfuscation `m>32` 分包。
- benchmark、并发压测、缓存、批量并行和生产观测。
- Web UI、网络级 Demo、跨实现互操作服务器。
- 为 v2 字段、未来算法或前向安全提前建设抽象。
- 不影响行为的命名、package 和抽象层美化。

## 17. 当前阻塞与下一步

阶段 2 已完成，`public × X25519` 的 unsigned 与 signed 两条真实多收件人链路均已封板。阶段 3 已获用户确认；2026-07-18 使用指定 JDK 17 重新验证全仓 44 suites、435 tests，0 failure、0 error、0 skipped。

ML-KEM-768 kid 已通过正式协议末尾“开发修订”冻结为 `BASE64URL(SHA-256(raw 1184-byte public key))`，不再依赖未稳定的 ML-KEM JWK 表示。阶段 3 设计已经独立复审，无开放 Critical/Important。

已知但不阻塞下一阶段的问题：

- 正式协议对 signed inner 的 `typ`、flattened JWS 展示结构和 receiver 侧非 JCS 接受策略仍有文档歧义；可执行 profile 已由阶段 2 exact-byte tests 冻结，正式文档清理作为 P2 后置。
- Stage 1 保留少量 hardening：GCM AAD helper 显式 ASCII 校验、outer protected strict UTF-8 decoder、wire writer 异常分类收窄、含数组值对象的相等语义与第三方 provider 违约防御。
- 阶段 2 的 signed/unsigned orchestration 重复、effective payload 上限、Java immutable string 清零边界和 API dormant invariants 等 P2 详见 `docs/dev/03-phase-2-signed-authentication-plan.md` §11。
- `WIND_BASE_1024F_V1` 仍缺完整字符表和 bit packing contract；必须在阶段 7 前获得明确决议，当前不阻塞阶段 3 Hybrid 主链。

下一步按 `docs/dev/05-phase-3-public-hybrid-implementation-plan.md` 从 Task 1 开始：先关闭 ML-KEM encapsulation shared-secret 生命周期，再依次完成 raw-key kid、Hybrid KEK、recipient builder、paired routing、unsigned/signed flow 与完整 E2E。范围仍限定为 `public × X25519ML-KEM-768 × unsigned/signed`，不同时引入 obfuscation、Armor 或 API facade。
