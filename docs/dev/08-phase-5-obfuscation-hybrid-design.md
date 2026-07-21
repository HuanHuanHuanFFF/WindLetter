# WindLetter Phase 5：Obfuscation Hybrid 设计

> 状态：2026-07-21 审计完成，协议歧义已通过 v1.0 末尾“开发修订”冻结；等待实施计划闭环后进入生产代码。

## 1. 目标与范围

阶段 5 只新增最后两个协议组合并封板八组合：

- `obfuscation × X25519ML-KEM-768 × unsigned`
- `obfuscation × X25519ML-KEM-768 × signed`

必须使用真实 X25519、ML-KEM-768、HKDF-SHA256、A256KW、A256GCM 和 Ed25519，经过真实 JSON wire、strict parser、AAD、inner/outer binding 与可选验签。

本阶段不接 `windletter-api`、armor 或 Demo CLI；不重构已经封板的 public/obfuscation X25519 flow，也不提前建设通用算法框架。

## 2. 真实基线与主链断点

阶段进入证据：

- 分支：`spike/demo-v0`，与 `origin/spike/demo-v0` 同步。
- HEAD：`0b64a815a97fccddd0bb7860476f006a03976a5d`。
- 工作区：仅既存 `docs/README.md` 行尾状态噪音；继续排除。
- JDK：Microsoft OpenJDK 17.0.16。
- fresh 全仓：67 suites、606 tests，0 failure、0 error、0 skipped。

已有能力：

- strict outer parser 已要求 Obfuscation Hybrid entry 为 `rid16 + ek1088 + encrypted_key40`，bucket 为 8/16/32。
- wire model 与 writer 已能保存、输出 Hybrid `ek`。
- crypto 已有真实 ML-KEM-768 encapsulate/decapsulate、X25519、HKDF、A256KW/GCM 和 Ed25519。
- Public Hybrid 已证明 `SS_ECC || SS_PQ`、逐收件人 encapsulation 与生命周期模式。
- Obfuscation X25519 已证明单消息 EPK、bucket/decoy/shuffle、full scan、四条 signed/unsigned 门序。

当前断点不是 wire，而是：

1. 没有从同一 Hybrid `Z` 同时派生 `rid/hybrid` 与 KEK 的深模块。
2. 没有单 EPK、逐 pair 独立 `ek`、1088-byte decoy 的 recipient builder。
3. 没有执行 `local hybrid pair × wire entry` ML-KEM decapsulation 的完整扫描 recovery。
4. 没有 Obfuscation Hybrid 的 unsigned/signed Sender/Receiver。

## 3. 权威协议合同

### 3.1 原子 Hybrid 身份

一个收件人身份是不可拆分的：

```text
(X25519 public/private key, ML-KEM-768 public/private key)
```

- Sender 和 Receiver 按完整 pair 判重。
- 允许两个不同 pair 复用单个 X25519 或 ML-KEM component。
- 不允许把两条本地记录交叉组合。
- 本规则覆盖 Phase 4 对单一 X25519 component 的判重；后者只适用于纯 X25519 profile。
- wire 中不出现 Hybrid kid；public 模式 kid router 不参与本阶段。

### 3.2 每 entry 联合派生

```text
SS_ECC = X25519(sk_eph, pk_x25519_recv)
(ek, SS_PQ) = ML-KEM-768.Encap(pk_mlkem_recv)
Z = SS_ECC || SS_PQ

rid = HKDF-SHA256("wind", Z, "rid/hybrid", 16)
KEK = HKDF-SHA256(
  "wind",
  Z,
  "WindLetter v1 KEK | X25519ML-KEM-768",
  32
)
encrypted_key = A256KW(KEK, common_CEK)
```

`rid`、KEK 和 `ek` 必须对应同一次 encapsulation；不得重复 decapsulation 分别派生 rid 与 KEK，也不得跨 entry 混用材料。

### 3.3 Padding 与最终顺序

```text
validate 1..32 complete pairs
→ one fresh per-message X25519 EPK
→ build every real entry independently
→ pad to 8/16/32 with {random rid16, ek1088, encrypted_key40}
→ enforce globally unique rid
→ CSPRNG Fisher-Yates shuffle
→ freeze final recipients
→ AAD + binding
→ inner + optional signature
→ AES-GCM
```

真实 rid 冲突直接失败；每个诱饵 rid 最多独立重采样 128 次。identity permutation 是合法随机结果，测试不得要求每次一定改变顺序。

## 4. 深模块边界

### 4.1 `ObfuscationHybridKeyDeriver`

Sender：

```java
SenderMaterial deriveForSender(
    X25519PrivateKeyHandle ephemeral,
    byte[] recipientX25519PublicKey,
    byte[] recipientMlkem768PublicKey
)
```

返回可关闭的 `rid16 + kek32 + ek1088` owned snapshots。

Receiver：

```java
ReceiverContext openForReceiver(
    X25519PrivateKeyHandle x25519PrivateKey,
    MLKem768PrivateKeyHandle mlkem768PrivateKey,
    byte[] epkX
)

DerivedMaterial ReceiverContext.deriveEntry(byte[] ek)
```

Context 对一个本地 pair 只做一次 X25519，随后对每个 entry 独立 ML-KEM decapsulation，并由同一个 `Z` 同时产生 rid/KEK。Context、结果对象均可幂等关闭；所有 private-key handles 都是 borrowed。

对 attacker-controlled `CryptoOperationException`，该 API 不允许直接终止或静默忽略：

- X25519/低阶 EPK 失败时建立 failure-latched context，以全零 dummy `SS_ECC` 继续处理该 local pair 的全部 entry。
- ML-KEM decapsulation 失败时使用全零 dummy `SS_PQ` 完成该组合的双 HKDF 与固定长度比较，并把结果标记为不可选择。
- `ReceiverContext`/`DerivedMaterial` 暴露只读的 candidate-failure 状态；dummy 结果永远不得成为有效命中。
- provider null/错长、HKDF 违约和 local handle 错误仍立即作为 `INTERNAL_ERROR`，不走 dummy 路径。

### 4.2 `ObfuscationHybridRecipientBuilder`

输入：1..32 个 `ObfuscationHybridRecipientKeys` 原子公钥 pair 与同一个 32-byte CEK。

职责：

- 预验证和防御性快照，拒绝重复完整 pair。
- 生成、使用并关闭一把 per-message X25519 ephemeral handle。
- 每个真实 pair 独立 encapsulate、联合派生、wrap。
- 先完成全部真实 entry，再生成同形诱饵并 shuffle。
- 返回仅包含公开 immutable snapshots 的 `PreparedRecipients(Epk, recipients)`。

### 4.3 `ObfuscationHybridCekRecovery`

输入：`Epk`、8/16/32 wire entries、`ObfuscationHybridRecipientPrivateKeys` 原子本地 pair。

职责：

1. 在读取 local handles 前验证/freeze wire 并拒绝 duplicate rid。
2. 完整验证本地 pair 与公开 key snapshots；重复完整 pair 为 `INTERNAL_ERROR`。
3. 为每个 local pair 建立一个 receiver context。
4. 按 wire-order outer、local-input-order inner 执行全部组合；每个组合都 decap、双 HKDF、固定 16-byte 常量时间比较。
5. 保存字典序最小命中的 KEK，但即使命中也继续扫描。
6. 全局锁存任一 context/entry 的 attacker-controlled candidate crypto failure；失败组合仍执行 dummy compare，但不得被选择。
7. 扫描结束后先检查 failure latch：一旦锁存，必须以泛化 `KEY_UNWRAP_FAILED` 结束且 unwrap 次数为零，即使其它组合已有命中。
8. 未锁存失败时只 unwrap 一次；失败不 fallback。
9. 只向 flow 返回 caller-owned 32-byte CEK，统一清除其余材料。

正式协议没有本地 pair 数量上限；阶段 5 不擅自截断本地列表。最多 32-entry wire 带来的 ML-KEM 计算成本登记为 P2 性能/DoS hardening，不改变本阶段正确性门序。

### 4.4 四条 flow

新增：

- `ObfuscationHybridUnsignedSender`
- `ObfuscationHybridUnsignedReceiver`
- `ObfuscationHybridSignedSender`
- `ObfuscationHybridSignedReceiver`

直接沿用 Phase 4 flow 的门序和安全边界，只替换 paired request、Hybrid builder/recovery、`key_alg="X25519ML-KEM-768"`，并要求每个 entry 都有 `ek`。允许局部重复，不抽象八组合公共框架。

## 5. Receiver 门序与错误语义

```text
strict parse + exact profile
→ AAD consistency
→ duplicate wire rid check
→ validate atomic local pairs
→ full local-pair × wire-entry scan
→ select min(wireIndex, localInputIndex)
→ unwrap exactly once
→ AES-GCM
→ strict inner
→ binding
→ signed only: trusted signer binding + exact-segment Ed25519 verify
→ return payload/authentication
```

错误边界：

- 完整扫描成功完成且无 rid 命中：`NOT_FOR_ME`。
- 空本地 pair 列表执行零候选扫描后为 `NOT_FOR_ME`；null、无法快照或包含 null 的本地列表为 `INTERNAL_ERROR`。
- 错误/交换的合法 1088-byte `ek` 经 ML-KEM 隐式拒绝得到替代 secret、最终无命中：`NOT_FOR_ME`。
- 低阶 EPK、attacker-controlled decapsulation `CryptoOperationException`、selected unwrap 失败：`KEY_UNWRAP_FAILED`，固定泛化 message、null cause；candidate crypto failure 必须全局锁存、继续 dummy 扫描，并在任何 unwrap 前优先失败。
- null/closed/foreign handle、本地公钥错误长度、provider null/错长、HKDF/provider contract failure：`INTERNAL_ERROR`。
- 命中后的 GCM、inner、binding、signature 失败保持现有内部分类，不得 fallback 或返回 identity。
- Phase 6 API 边界把除 `NOT_FOR_ME` 外的无效消息统一映射为公开 `InvalidMessage`。

随机 1088-byte decoy 必须通过真实 provider 的 ML-KEM implicit rejection 测试；不支持该行为的 provider 不能用于 Obfuscation Hybrid。

## 6. 敏感材料与所有权

- Sender 的 per-message X25519 ephemeral handle：owned，所有路径关闭。
- Receiver 的 X25519/ML-KEM handles：borrowed，protocol 不关闭。
- `MLKem768Encapsulation`：owned，try-with-resources 关闭 shared secret。
- `SS_ECC`、`SS_PQ`、`Z`、rid、KEK、CEK、inner、GCM AAD、签名临时输入：成功/失败路径 best-effort 清零。
- EPK、ML-KEM ciphertext、wire snapshots 是公开材料，但 mutable byte arrays 仍必须 defensive copy，避免 TOCTOU。

## 7. 测试与阶段门禁

组件门禁：

- exact `SS_ECC || SS_PQ`、`rid/hybrid` 和 Hybrid KEK info 固定向量。
- 真实 BC sender/receiver rid、KEK 一致；每个真实 entry 的 `ek` 独立。
- bucket `1/8/9/16/17/32 → 8/8/16/16/32/32`。
- `N` 次 X25519、`N×M` 次 ML-KEM decapsulation、`N×M` 次常量时间比较；首项命中也不减少。
- Sender/Receiver 均拒绝重复完整 pair；共享 X25519 的不同 pair、共享 ML-KEM 的不同 pair均合法；交换或交叉组合不得命中。
- duplicate wire priority、空本地列表、首/中/尾、tie-break、single unwrap、no-fallback、错误外观与所有权。
- 首/中/尾 candidate crypto failure 后即使存在真实命中，也保持 `N×M` decap/compare、最终泛化失败且 unwrap 次数为零。
- 真实随机 1088-byte decoy implicit rejection。

E2E 门禁：

- unsigned/signed 各覆盖 8/16/32 bucket 与 text/binary/empty payload，避免无意义的全笛卡尔重复。
- 首/中/尾真实 recipient、unrelated pair、真实 JSON writer/parser round-trip。
- stale AAD、EPK/rid/ek/encrypted_key、recipients order、IV/ciphertext/tag、binding、signer/signature/exact segments 负例。
- 相同业务输入连续发送时 EPK、目标 rid、真实 ek、IV 和 ciphertext 体现新鲜随机性。
- public 四组合和 Obfuscation X25519 两组合全部回归，最终八组合均为真实 crypto/wire E2E。

最终必须满足：focused、protocol 及依赖、fresh 全仓 JDK 17 测试全绿；测试数不低于 606，无新增 `@Disabled`/skip；`git diff --check` 通过；独立 spec 与 code/security review 无开放 P0/P1；全部 P2 记录影响与后续建议。

## 8. 实施闭环与提交边界

1. 正式协议修订 + 本设计 + 总体状态（docs-only）。
2. 详细实施计划（docs-only）。
3. Hybrid 联合 deriver。
4. Hybrid recipient builder。
5. Hybrid full-scan CEK recovery。
6. unsigned 完整收发。
7. signed 完整收发 + 八组合 strict/tamper/randomness 封板。

每个闭环按 RED → GREEN → focused/module gate → spec review → code/security review → 独立 commit 执行。P0/P1 阻塞下一闭环；P2 记录但不阻塞 Demo。

## 9. Deferred P2

1. 最多 `local pair count × 32` 次 ML-KEM decapsulation 的性能、并行化、限流和 DoS 预算；阶段 5 保证完整扫描正确性，不擅自截断本地身份。
2. Phase-specific deriver/builder/recovery 与四条 flow 的重复；八组合封板后再评估共用 helper。
3. 统计 timing、shuffle 分布与更强 provider 差异测试；当前以固定调用计数、无提前退出和真实 BC E2E 作为 Demo 门禁。
4. 把八组合 fixture/向量迁移到 `windletter-testkit`；当前该模块没有 `src`，不为共享 fixture 框架扩大主链。
5. API 公开 `InvalidMessage` 映射、Hybrid key lease 与 DTO 接线属于 Phase 6。
