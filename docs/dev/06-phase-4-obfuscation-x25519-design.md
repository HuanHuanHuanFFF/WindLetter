# WindLetter Phase 4 Obfuscation X25519 Design

> 状态：2026-07-18 已获用户确认并完成协议语义冻结，独立复核无开放 P0/P1；实施计划已写入 `docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md`，尚未修改生产代码。

## 1. 目标与范围

阶段 4 只完成以下两个真实协议组合：

- `obfuscation × X25519 × unsigned`
- `obfuscation × X25519 × signed`

两条链路都必须使用真实 X25519、HKDF-SHA256、A256KW、A256GCM，以及 signed 分支的真实 Ed25519。Sender 必须生成每消息临时 `epk`、`rid/ecc`、8/16/32 固定分桶、等长诱饵与 CSPRNG shuffle；Receiver 必须完整扫描并以常量时间比较 `rid`。

阶段 4 不实现 Obfuscation Hybrid、API facade、armor、testkit 跨模块入口、通用 flow 框架或性能优化。

## 2. 审计基线

### 2.1 已有能力

- `Epk`、`ObfuscationRecipient` 和 outer JSON 投影已经存在。
- strict outer parser 已要求 obfuscation 使用 `epk`、禁止 sender `kid`，校验 32-byte X25519 `epk.x`、16-byte `rid`、40-byte wrapped CEK，并只接受 8/16/32 个 entry。
- `OuterAad`、`OuterBinding`、unsigned/signed inner codec、A256GCM、A256KW、Ed25519 和 outer writer 可直接复用。
- `BouncyCastleX25519Crypto` 已支持生成、使用和关闭临时私钥 handle，并拒绝低阶公钥。
- 阶段启动基线为 Microsoft OpenJDK 17.0.16；`mvn -q clean test` 为 56 suites、513 tests，0 failure、0 error、0 skipped。

### 2.2 主链断点

当前生产代码没有 `rid/ecc` 派生、obfuscation recipient 构建、bucket/decoy/shuffle、完整扫描 CEK recovery，也没有四个 obfuscation X25519 flow。现有实现只能严格解析别人已经构造好的 obfuscation wire。

## 3. 已选择的设计

采用 obfuscation X25519 专用深模块，不修改已封板的 public flow，也不提前抽取 mode/algorithm/signing 通用框架。

### 3.1 `ObfuscationX25519KeyDeriver`

建议位置：`windletter-protocol/src/main/java/com/windletter/protocol/key/ObfuscationX25519KeyDeriver.java`

核心 interface：

```java
DerivedMaterial derive(X25519PrivateKeyHandle ownKey, byte[] peerPublicKey)
```

一次 X25519 计算同时派生：

- `rid = HKDF-SHA256("wind", SS_ECC, "rid/ecc", 16)`
- `KEK = HKDF-SHA256("wind", SS_ECC, "WindLetter v1 KEK | X25519", 32)`

`DerivedMaterial` 必须防御性复制并可幂等关闭；关闭后清零 owned `rid` 和 KEK，任何再次读取都必须失败。调用方通过 accessor 获得的副本归调用方清零。调用方传入的 private-key handle 始终为 borrowed，不得关闭。共享秘密只在模块内部存在，并在所有路径清零。

### 3.2 `ObfuscationX25519RecipientBuilder`

建议位置：`windletter-protocol/src/main/java/com/windletter/protocol/recipient/ObfuscationX25519RecipientBuilder.java`

核心 interface：

```java
PreparedRecipients build(List<byte[]> realRecipientPublicKeys, byte[] cek)
```

该模块内部完成：

1. 预验证 1..32 个不同的 32-byte X25519 公钥并制作 owned snapshots。
2. 每次 `build` 生成且最终关闭一个临时 X25519 handle。
3. 对每个真实收件人派生 rid/KEK、A256KW wrap 同一 CEK，并构造无 `kid`、无 `ek` 的真实 entry。
4. 选择最小的 8/16/32 bucket，生成随机 16-byte rid 与随机 40-byte encrypted key 诱饵。
5. 确保全部真实和诱饵 rid 唯一；真实 rid 冲突必须以 `INTERNAL_ERROR` 直接失败，不得重新生成 epk 或继续 padding；诱饵碰撞时重新采样，损坏或持续碰撞的随机源必须有限失败，不能无限循环。
6. 使用调用方注入或默认的 `SecureRandom` 执行 Fisher-Yates shuffle。
7. 返回只含公开数据的 `PreparedRecipients(Epk, finalRecipients)`；其中列表及所有 byte array 都必须是不可变/防御性复制的 snapshots，不依赖已关闭的 ephemeral handle。

分桶和 shuffle 隐藏在 builder 内部，不新增公开的通用 padding interface。Phase 5 可以新增 Hybrid 对应实现，Demo 后再评估合并。

### 3.3 `ObfuscationX25519CekRecovery`

建议位置：`windletter-protocol/src/main/java/com/windletter/protocol/routing/ObfuscationX25519CekRecovery.java`

核心 interface：

```java
byte[] recover(
        Epk epk,
        List<RecipientEntry> recipients,
        List<X25519PrivateKeyHandle> localKeys
)
```

该模块把完整扫描、选择规则、KEK 生命周期和 A256KW unwrap 收敛在一个 interface 后面，只向 flow 返回 caller-owned 32-byte CEK：

- 预先拒绝重复 wire rid 和重复本地 X25519 公钥记录。
- 对每个本地候选只做一次 X25519/双 HKDF 派生，并对所有 entry 使用 `MessageDigest.isEqual` 比较固定 16-byte rid。
- 即使已经命中也继续扫描全部 entry 与全部本地候选。
- 多个不同本地身份命中时，扫描结束后按 `(wire index, local key input index)` 的字典序选择；wire 顺序优先，本地输入顺序只处理同一 wire entry 的极低概率 rid 碰撞。
- 只 unwrap 被选中的 entry，不因 unwrap 失败回退到后续 entry。
- CekRecovery 在自身 `finally` 清零全部候选 rid、selected/unselected/replaced KEK 与临时公钥 snapshots；local handles 保持 borrowed。

### 3.4 四个 flow

新增：

- `ObfuscationX25519UnsignedSender`
- `ObfuscationX25519UnsignedReceiver`
- `ObfuscationX25519SignedSender`
- `ObfuscationX25519SignedReceiver`

Sender request 不再需要发送方静态 X25519 私钥。unsigned request 只包含 payload、message id、timestamp 和收件人静态 X25519 公钥；signed request 额外包含发送方 Ed25519 私钥。

Receiver request 不再需要 sender X25519 resolver。unsigned request 包含 wire 与本地 X25519 private handles；signed request 额外包含可信 Ed25519 resolver。

## 4. 数据流与安全门序

### 4.1 Sender

1. 验证 request、payload、UUID、timestamp 和 1..32 个不同收件人。
2. 生成随机 32-byte CEK 与 12-byte IV。
3. Recipient builder 生成单个 per-message epk、全部真实 entry、诱饵和最终 shuffle 顺序。
4. 以最终 epk 构建 outer protected，以最终 recipients 计算 AAD 与 binding。
5. unsigned 编码严格 inner；signed 使用 exact prepared segments 与真实 Ed25519 签名。
6. 使用 `ASCII(protected + "." + aad)` 作为真实 GCM AAD，加密 inner 并写出 wire JSON。
7. Recipient builder 必须已经在返回前关闭 ephemeral handle；flow 清零自己拥有的 CEK、IV、inner、signing input、signature 和 GCM AAD。

禁止在 padding 或 shuffle 之前计算 binding、签名或 GCM。

### 4.2 Receiver

1. strict parse，并要求精确的 obfuscation/X25519/unsigned 或 signed profile。
2. 复算并常量时间验证 outer AAD。
3. 完整扫描 rid，并恢复唯一选定 entry 的 CEK；recovery 模块在 unwrap 完成后、返回 caller-owned CEK 前清零 selected/unselected KEK。
4. 真实 AES-GCM 解密 outer ciphertext。
5. strict decode inner，并先验证 inner/outer binding。
6. signed 分支仅在 binding 成功后解析 trusted signer、核对 signing kid 与实际公钥并验证 exact received segments；unsigned 完全跳过 Ed25519。
7. 只有全部门通过后才返回 payload 和认证结果。
8. Receiver flow 在统一 `finally` 路径清零 caller-owned CEK、decrypted inner、GCM AAD、signed verification 临时数组及其它 owned 敏感材料；所有 borrowed local handles 始终不关闭。

## 5. 路由与错误语义

- 重复 wire rid：`INVALID_FIELD`，不得开始私钥路由。
- 重复本地 X25519 公钥：本地配置错误，映射 `INTERNAL_ERROR`。
- 本地 X25519 key 列表为空：视为没有本地候选，返回 `NOT_FOR_ME`。
- 有效候选完成全扫描后无命中：`NOT_FOR_ME`。
- 所有 attacker-controlled X25519 agreement failure（包括低阶/全零 epk）以及已命中 entry 的 A256KW unwrap 失败：统一映射为 `KEY_UNWRAP_FAILED`、泛化 message `obfuscation recipient key recovery failed`、null cause；不得 fallback。
- null/closed/foreign borrowed handle、HKDF 参数或长度违约等本地配置/provider contract failure：映射 `INTERNAL_ERROR`，允许保留仅供本地诊断的 cause。
- GCM、binding、signature 继续使用既有 `GCM_AUTH_FAILED`、`BINDING_FAILED`、`SIGNATURE_INVALID` 内部分类。
- Phase 6 API/投递边界必须把命中后的失败统一映射为公开 `InvalidMessage`；阶段 4 不新增错误码。

## 6. 分桶、诱饵与随机性合同

| 真实收件人数 | 最终 bucket |
|---:|---:|
| 1..8 | 8 |
| 9..16 | 16 |
| 17..32 | 32 |

约束：

- `0` 和 `33` 必须在任何密码操作前拒绝。
- X25519 真实 entry 与诱饵 entry 在 wire 上都只有 16-byte rid 与 40-byte encrypted key，均不含 `ek`。
- 一个 outer message 只生成一个 epk；连续两次发送不得复用 epk。
- CEK、IV、ephemeral key、诱饵内容和排列均来自 CSPRNG。
- 每个诱饵 rid 最多采样 128 次；仍无法得到全局唯一 rid 时以 `INTERNAL_ERROR` 有限失败。
- identity permutation 是 Fisher-Yates 的合法随机结果，测试不得要求每次一定改变顺序；测试应使用可控随机源验证算法调用与确定排列，并用真实随机源验证跨消息新鲜性。

## 7. 测试与完成判定

### 7.1 组件门禁

- rid/ecc 与 KEK 固定向量、真实发送/接收双向一致。
- shared secret、候选 rid、selected/unselected KEK、caller-owned CEK、decrypted inner、GCM AAD 和 signed verification 临时数组在成功/失败路径清零，borrowed handles 不关闭。
- bucket 覆盖 `1→8`、`8→8`、`9→16`、`16→16`、`17→32`、`32→32`。
- 0/33、重复真实公钥、通过可控派生器触发的真实 rid collision、诱饵重采样上限、provider 违约均有负例。
- full-scan recovery 覆盖首/中/尾命中、多个本地 key、同一 wire index 的本地 tie-break、空本地 key 列表、重复 rid、低阶 epk、非收件人和 unwrap no-fallback。

### 7.2 真实 E2E

- unsigned/signed 各覆盖 text、binary 与 empty payload。
- 同一条 padded/shuffled wire 分别只提供首、中、尾真实收件人的 private handle，均恢复相同 payload。
- unrelated handle 只有在完整扫描后返回 `NOT_FOR_ME`。
- 诱饵与真实项全部进入最终 AAD、binding 和 GCM 认证输入。
- authenticated tamper 覆盖 epk、rid、encrypted key、entry 顺序、AAD、GCM、两项 binding、signature、protected/payload exact segments；合法但被替换的随机 epk 在完整扫描后通常为 `NOT_FOR_ME`，低阶 epk 为泛化 key-recovery failure，结构/长度错误由 strict parser 拒绝。
- 连续两次相同业务输入的 epk、rid、IV 和 ciphertext 体现真实随机性。

### 7.3 Strict 与回归

- 补齐 obfuscation writer round-trip 与 `epk.x` / `rid` canonical Base64URL 回归。
- strict parser 继续拒绝错误 kty/crv、kid/ek 条件字段、非 8/16/32 bucket、unknown/missing/type/length/canonical 错误。
- public X25519/Hybrid × unsigned/signed 四组合全部回归。
- 指定 JDK 17 下 protocol 及依赖模块和全 reactor `mvn -q clean test` 全绿；0 failure、0 error、0 skipped、无新增 `@Disabled`。
- 独立 spec review 与 code/security review 无开放 P0/P1。

## 8. 实施闭环

实施计划应拆成 6 个可独立验证、独立提交的闭环：

1. rid/ecc + KEK 联合派生与 secret lifecycle。
2. per-message epk、真实 recipient、bucket、decoy、rid uniqueness 与 shuffle。
3. full-scan constant-time CEK recovery。
4. obfuscation X25519 unsigned 完整收发。
5. obfuscation X25519 signed 完整收发。
6. bucket/strict/tamper/randomness/public regression 最终矩阵与阶段封板。

每个生产闭环必须按 RED → GREEN → focused/module gate → spec review → code/security review → 单独 commit 执行。普通维护性 P2 登记但不阻塞；任何协议、密码学、认证 P0/P1 必须修复后才能进入下一闭环。

提交边界固定为：本协议修订、阶段设计与总体状态更新组成当前 docs-only commit；后续实施计划首次创建单独组成一个 docs-only commit；六个生产/测试闭环再各自提交，并可在同一闭环中更新该任务的 RED/GREEN/review 证据；阶段最终状态与封板矩阵只进入第 6 个封板提交。

## 9. 备选方案与取舍

未采用方案：

- 把 rid、padding 和 routing 分别复制进四个 flow：初始文件少，但安全门序、清零和完整扫描重复，容易产生 signed/unsigned 分叉。
- 先重构 public/obfuscation/algorithm/signing 通用框架：长期重复可能更少，但会同时扩大已封板 public flow 的回归面，违反 Demo First。

当前方案只新增 X25519 obfuscation 所需的最小深模块，允许局部重复，并把通用化推迟到 8 组合完整 Demo 之后。

## 10. Deferred P2

以下事项不阻塞阶段 4，但必须在阶段报告中保留影响和后续建议：

1. `PublicX25519KekDeriver` 与新 deriver 会有少量 X25519/KEK 逻辑重复；Demo 后再统一，不在本阶段重构 public flow。
2. API `EncryptRequest` 仍要求 sender encryption identity，与 obfuscation per-message epk 不完全匹配；Phase 6 接线时修正。
3. 正式协议的公开错误仍是 `InvalidMessage`，direct protocol flow 使用细分内部错误；Phase 6 必须统一公开映射。
4. Phase 5 Hybrid 需要 1088-byte decoy `ek` 与逐 entry decapsulation；不在阶段 4 提前建设通用 padding/router 框架。
