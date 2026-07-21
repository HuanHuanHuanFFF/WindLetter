# WindLetter Phase 5：Obfuscation Hybrid 实施计划

**Goal:** 完成 `obfuscation × X25519ML-KEM-768 × {unsigned,signed}` 两个真实协议组合，并以八组合 E2E、strict、tamper 和 randomness 矩阵封板阶段 5。

**Architecture:** 新增 Hybrid obfuscation 专用联合派生、recipient builder、full-scan CEK recovery 和四条 flow。复用现有 wire/AAD/binding/inner/crypto 基础，但不修改已封板的 public 与 Obfuscation X25519 主链，不提前抽取通用算法框架。

**Status:** 2026-07-21 协议修订与设计已在 `cd26447` 完成；Task 1/2/3 已提交，Task 4 已实现并通过提交前门禁，Task 5 开始执行。

## 1. 执行基线与硬约束

- 分支必须始终为 `spike/demo-v0`。
- 本阶段进入 HEAD：`0b64a815a97fccddd0bb7860476f006a03976a5d`；设计闭环提交：`cd26447`。
- `docs/README.md` 是既存行尾状态噪音，内容 diff 为空；不得编辑、暂存、提交或恢复。
- 指定 JDK：`C:\Users\幻\.jdks\ms-17.0.16`。
- 进入阶段 fresh 基线：67 suites、606 tests，0 failure、0 error、0 skipped。
- 协议真相：`docs/Wind Letter v1.0协议.md`，特别是 2026-07-21 Obfuscation Hybrid 开发修订。
- 设计真相：`docs/dev/08-phase-5-obfuscation-hybrid-design.md`。
- 生产任务必须 test-first：RED 必须证明缺少目标行为，而不是构造无关编译错误；GREEN 后运行 focused 与依赖 reactor gate。
- 每个任务独立 spec review、code/security review、变更范围核对和 commit。
- P0/P1 必须在当前闭环修复；P2 记录影响与建议但不阻塞 Demo。
- 不自动 push；push 是阶段完成后的独立用户授权动作。

本阶段所有 Maven 命令都必须先在当前 PowerShell 会话固定并确认 JDK 17：

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
java -version
```

## 2. 固定协议与实现合同

### 2.1 Sender 材料

每条消息只生成一个 X25519 ephemeral handle。对每个完整 recipient pair 独立执行：

```text
SS_ECC = X25519(sk_eph, pk_x25519_recv)
(ek, SS_PQ) = ML-KEM-768.Encap(pk_mlkem_recv)
Z = SS_ECC || SS_PQ
rid = HKDF-SHA256("wind", Z, "rid/hybrid", 16)
KEK = HKDF-SHA256(
  "wind", Z,
  "WindLetter v1 KEK | X25519ML-KEM-768",
  32
)
encrypted_key = A256KW(KEK, common_CEK)
```

`rid` 与 KEK 必须来自同一个 `Z`，且每个真实 entry 的 `ek`、`SS_PQ`、KEK 独立。

### 2.2 Receiver 完整扫描

```text
strict/profile + AAD
→ duplicate wire rid before local handles
→ validate exact local pairs
→ create one receiver context per local pair
→ for wireIndex in final wire order
     for localIndex in caller order
       decap current entry.ek
       derive rid and KEK from same Z
       constant-time compare exactly once
       remember first valid match only
→ candidate-failure latch check
→ no valid match: NOT_FOR_ME
→ unwrap selected entry exactly once
→ GCM → inner → binding → optional signature
```

正常候选必须满足：`N` 次 X25519 agreement、`N×M` 次 ML-KEM decapsulation、`N×M` 次 comparator；命中不改变调用数。

### 2.3 Receiver candidate crypto failure latch

- failure latch/dummy 路径只适用于 Receiver 的 attacker-controlled 候选处理；Sender 的 X25519 agreement 或 ML-KEM encapsulation 失败必须终止发送，绝不能返回 dummy `SenderMaterial`。
- Receiver `openForReceiver` 的 X25519 `CryptoOperationException` 或全零 secret：建立 failure-latched context，以全零 32-byte dummy `SS_ECC` 继续该 local pair。
- Receiver `deriveEntry` 的 ML-KEM decapsulation `CryptoOperationException`：以全零 32-byte dummy `SS_PQ` 完成双 HKDF 与 comparator。
- failure-latched material 永远不可被选择，即使 dummy rid 与 wire rid 相等。
- recovery 全局锁存任一 candidate failure；完整扫描后、任何 unwrap 前以 `KEY_UNWRAP_FAILED` 结束。
- 即使其它组合有效命中，也必须 zero unwrap 并失败。
- 固定 message：`obfuscation hybrid recipient key recovery failed`；cause 为 null。
- null/closed/foreign handle、错误本地公钥长度、provider null/错长、HKDF 违约属于 `INTERNAL_ERROR`，不走 dummy 路径。

### 2.4 Pair 与重复规则

- Sender/Receiver 只按完整 `(X25519, ML-KEM-768)` pair 判重。
- exact pair 重复必须拒绝。
- 相同 X25519、不同 ML-KEM pair 合法。
- 相同 ML-KEM、不同 X25519 pair 合法。
- 两张独立 handle 列表或跨记录交叉拼接禁止。
- duplicate wire rid 必须在读取 local handle 前以 `INVALID_FIELD` 拒绝。

### 2.5 空候选与 wrong `ek`

- 空本地 pair 列表：零候选扫描后 `NOT_FOR_ME`。
- null、不可快照或含 null 的本地列表：`INTERNAL_ERROR`。
- 恰好 1088 字节的 wrong/swapped `ek` 通过 ML-KEM implicit rejection 得到替代 secret；完整扫描无 rid 命中时为 `NOT_FOR_ME`。
- 选中 entry 的 encrypted key 损坏：泛化 `KEY_UNWRAP_FAILED`，不得 fallback。

## 3. 预计文件结构

### 3.1 新增生产代码

```text
windletter-protocol/src/main/java/com/windletter/protocol/key/
  ObfuscationHybridKeyDeriver.java

windletter-protocol/src/main/java/com/windletter/protocol/recipient/
  ObfuscationHybridRecipientKeys.java
  ObfuscationHybridRecipientBuilder.java

windletter-protocol/src/main/java/com/windletter/protocol/routing/
  ObfuscationHybridRecipientPrivateKeys.java
  ObfuscationHybridCekRecovery.java

windletter-protocol/src/main/java/com/windletter/protocol/flow/
  ObfuscationHybridUnsignedSender.java
  ObfuscationHybridUnsignedReceiver.java
  ObfuscationHybridSignedSender.java
  ObfuscationHybridSignedReceiver.java
```

### 3.2 新增核心测试

```text
windletter-protocol/src/test/java/com/windletter/protocol/key/
  ObfuscationHybridKeyDeriverTest.java

windletter-protocol/src/test/java/com/windletter/protocol/recipient/
  ObfuscationHybridRecipientBuilderTest.java

windletter-protocol/src/test/java/com/windletter/protocol/routing/
  ObfuscationHybridCekRecoveryTest.java

windletter-protocol/src/test/java/com/windletter/protocol/flow/
  ObfuscationHybridFlowTestFixtures.java
  ObfuscationHybridUnsignedSenderTest.java
  ObfuscationHybridUnsignedReceiverTest.java
  ObfuscationHybridUnsignedMultiRecipientE2ETest.java
  ObfuscationHybridSignedSenderTest.java
  ObfuscationHybridSignedReceiverTest.java
  ObfuscationHybridSignedMultiRecipientE2ETest.java
  ObfuscationHybridTamperE2ETest.java
  ObfuscationHybridRandomnessE2ETest.java
  WindLetterEightProfilePayloadE2ETest.java
```

### 3.3 最终扩展的现有测试

```text
windletter-protocol/src/test/java/com/windletter/protocol/parser/
  OuterWireParserTest.java
  OuterWireCanonicalBase64UrlTest.java

windletter-protocol/src/test/java/com/windletter/protocol/codec/
  JacksonOuterWireWriterTest.java
```

不在本阶段新增 `windletter-testkit/src`；共享 fixture/向量迁移是 P2。

## 4. Task 1：Hybrid 联合派生与 failure-latched receiver context

### 4.1 生产 API

新增 `ObfuscationHybridKeyDeriver`：

```java
public final class ObfuscationHybridKeyDeriver {
    public ObfuscationHybridKeyDeriver(
        X25519Crypto x25519,
        MLKem768Crypto mlkem768,
        HkdfCrypto hkdf
    );

    public SenderMaterial deriveForSender(
        X25519PrivateKeyHandle ephemeral,
        byte[] recipientX25519PublicKey,
        byte[] recipientMlkem768PublicKey
    );

    public ReceiverContext openForReceiver(
        X25519PrivateKeyHandle recipientX25519PrivateKey,
        MLKem768PrivateKeyHandle recipientMlkem768PrivateKey,
        byte[] epkX
    );
}
```

`SenderMaterial`：owned `rid16`、`kek32`、`ek1088`；defensive copy、close 幂等、close 后 accessor 失败，只清除 rid/KEK，`ek` 为公开 ciphertext。

`ReceiverContext`：借用两把 private handle，拥有 32-byte `SS_ECC` 与 failure flag；`deriveEntry(ek1088)` 每次真实 decap 并返回 `DerivedMaterial(rid16,kek32,candidateCryptoFailed)`；close 清 `SS_ECC`，不关闭 handles。

`DerivedMaterial`：owned rid/KEK、defensive copy、close 幂等、close 后 accessor 失败；candidate failure 为不可变标志。

### 4.2 RED

先新增 `ObfuscationHybridKeyDeriverTest`，测试因生产类/API 不存在而失败。RED 只覆盖本任务合同：

- exact `Z = SS_ECC || SS_PQ` 顺序。
- `rid/hybrid`、Hybrid KEK info、salt、16/32-byte 长度。
- 真实 BC sender/receiver 对相同 entry 得到相同 rid/KEK。
- 两次 sender derive 产生独立 1088-byte `ek`。
- Sender X25519 agreement 或 ML-KEM encapsulation `CryptoOperationException` 必须终止且不返回 `SenderMaterial`。
- 仅 Receiver 的 X25519 与 ML-KEM candidate `CryptoOperationException` 返回 failure-latched dummy material，不提前终止候选扫描。
- dummy rid 即使相等也带 failure flag。
- provider null/错长、HKDF failure 为 contract failure。
- accessor defensive copy、close/清零、borrowed handles 不关闭。

### 4.3 GREEN 与门禁

实现只包含联合派生与生命周期，不包含 wrap、padding、routing 或 flow。

Focused：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybridKeyDeriverTest,ObfuscationX25519KeyDeriverTest,PublicHybridKekDeriverTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

完成条件：focused 通过；独立 spec/code-security review P0=0/P1=0；提交只含 deriver/test/本计划证据。

建议 commit：

```text
feat(protocol): derive obfuscation hybrid key material
```

### 4.4 实际证据（2026-07-21）

- 初始 RED：测试因 `ObfuscationHybridKeyDeriver` 不存在而编译失败。
- 安全 RED：恶意 HKDF provider 修改第一次 IKM 后，第二次调用未看到原始 `Z`；实现改为两次 HKDF 各用独立副本并在调用后清零。
- GREEN：新测试类 17 tests，覆盖真实 BC sender/receiver、一致向量、sender 失败、receiver dummy/failure flag、provider contract、closed/foreign X25519 与 ML-KEM handle、生命周期和清零。
- focused 三套件通过；`windletter-protocol` 及依赖 reactor 通过。
- 独立 spec/test review 与 code/security review：生产 P0=0、P1=0；两个测试合同缺口（dummy rid 相等仍失败、ML-KEM closed/foreign 分类）已补齐。
- 范围保持为 deriver/test/本计划证据，不包含 wrap、padding、routing 或 flow。

## 5. Task 2：Per-entry Hybrid recipient builder

### 5.1 生产 API

新增 `ObfuscationHybridRecipientKeys`：32-byte X25519 public key + 1184-byte ML-KEM public key 的 defensive-copy 原子 record。

新增：

```java
public final class ObfuscationHybridRecipientBuilder {
    public ObfuscationHybridRecipientBuilder(
        X25519Crypto x25519,
        MLKem768Crypto mlkem768,
        HkdfCrypto hkdf,
        A256KeyWrapCrypto keyWrap
    );

    public PreparedRecipients build(
        List<ObfuscationHybridRecipientKeys> realRecipients,
        byte[] cek
    );
}
```

package-private constructor可注入 `SecureRandom`。`PreparedRecipients` 必须验证 EPK 32、bucket 8/16/32、每 entry `rid16/ek1088/encryptedKey40`、全局 rid 唯一并制作不可变 snapshots。

### 5.2 RED

新增 `ObfuscationHybridRecipientBuilderTest`：

- 所有输入在 generate/encap/wrap/random 前验证。
- 0/33、null、错误长度、exact pair duplicate 拒绝。
- 共享 X25519 或共享 ML-KEM 的不同完整 pair 合法。
- 一个 build 只生成/关闭一个 ephemeral handle。
- 每个真实 pair 独立 encapsulate；`ek` 两两不同；同一 CEK 可由对应 KEK unwrap。
- `1/8/9/16/17/32 → 8/8/16/16/32/32`。
- 所有真实项完成后才开始 decoy random；decoy 三字段各自使用随机数据。
- 真实 rid collision 失败；decoy rid 全局唯一且每个 decoy 独立最多 128 次。
- Fisher-Yates 使用最终完整列表；确定随机源可杀 identity-only/错误边界 mutation。
- 失败路径关闭 ephemeral/encapsulation 并清 owned secret/copies。

### 5.3 GREEN 与门禁

Focused：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybridRecipientBuilderTest,ObfuscationHybridKeyDeriverTest,ObfuscationX25519RecipientBuilderTest,PublicHybridRecipientBuilderTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

完成条件：真实/诱饵 entry 同形，单 EPK、逐 entry 独立 ek、bucket/唯一性/shuffle 全部锁定；P0/P1=0。

建议 commit：

```text
feat(protocol): build obfuscation hybrid recipients
```

### 5.4 实际证据（2026-07-21）

- RED：`ObfuscationHybridRecipientKeys` 与 `ObfuscationHybridRecipientBuilder` 不存在，focused 测试按预期编译失败。
- GREEN：新测试 14 cases，覆盖真实 BC 三收件人、单 EPK、逐 pair 独立 encapsulation/ek、完整 pair 判重、共享单 component、全部 bucket、真实项先于诱饵、Hybrid 三字段随机诱饵、全局 rid 唯一、每诱饵独立 128 次预算、Fisher-Yates、失败清理与 immutable final snapshots。
- focused 四套件 58 tests 通过；`windletter-protocol` 及依赖 reactor 通过。
- 两路独立 spec/test 与 code/security review：生产 P0=0、P1=0；随机诱饵字段进入 wire 与每诱饵独立重采样预算两个测试缺口已补齐。
- 范围保持为 key-pair value object、builder、test 与本计划证据，不包含 receiver routing 或 flow。

## 6. Task 3：完整扫描与单次 CEK recovery

### 6.1 生产 API

新增 `ObfuscationHybridRecipientPrivateKeys`：借用的 X25519 + ML-KEM private-handle 原子 pair；构造时拒绝 null，但不关闭 handles。

新增：

```java
public final class ObfuscationHybridCekRecovery {
    public ObfuscationHybridCekRecovery(
        ObfuscationHybridKeyDeriver keyDeriver,
        A256KeyWrapCrypto keyWrap
    );

    public byte[] recover(
        Epk epk,
        List<RecipientEntry> recipients,
        List<ObfuscationHybridRecipientPrivateKeys> privateKeyPairs
    );
}
```

package-private constructor允许注入固定长度 comparator 以验证调用次数，但生产默认 `MessageDigest::isEqual`。

### 6.2 RED

新增 `ObfuscationHybridCekRecoveryTest`：

- EPK、bucket、entry type/长度/`ek` presence 在 local handles 前验证。
- duplicate wire rid 在 local handles 前 `INVALID_FIELD`。
- exact local pair duplicate 为 `INTERNAL_ERROR`；共享单 component 的不同 pair 合法。
- 空本地列表为 `NOT_FOR_ME`；null/含 null/无法快照为 `INTERNAL_ERROR`。
- 正常输入严格 `N` 次 X25519、`N×M` 次 ML-KEM decap、`N×M` 次 comparator。
- 首/中/尾命中、多 local、local 逆序、多个命中按 `(wireIndex,localIndex)`。
- selected unwrap 恰好一次；unwrap 失败不得 fallback。
- wrong/swapped `ek` 通过 implicit rejection，完整扫描后 `NOT_FOR_ME`。
- 真实 BC 随机 1088-byte decoy 能完成完整扫描。
- 首/中/尾 decap failure 后仍完成 `N×M`，即使随后真实命中也 zero unwrap + 泛化 `KEY_UNWRAP_FAILED`/固定 message/null cause。
- 低阶 EPK 对全部 local pair 走 failure-latched dummy scan；必须保持 `N×M` 次 ML-KEM decap、`2×N×M` 次 HKDF、`N×M` 次 compare、0 次 unwrap，最终不得 `NOT_FOR_ME`。
- provider/local contract failure 为 `INTERNAL_ERROR`。
- A256KW `CryptoOperationException` 为泛化 `KEY_UNWRAP_FAILED`；provider null/错长输出及其它 provider contract failure 为 `INTERNAL_ERROR`。
- wire/public snapshots、context/material、selected/unselected KEK、provider CEK 全路径清除；borrowed handles 不关闭。

### 6.3 GREEN 与门禁

实现必须先 freeze 全部 wire，再检查 local pair。循环固定为 wire outer/local inner，第一命中天然是规范 tie-break；后续仍完整派生与比较，但不替换 selected KEK。

Focused：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybridCekRecoveryTest,ObfuscationHybridKeyDeriverTest,ObfuscationX25519CekRecoveryTest,PublicHybridKidRouterTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

完成条件：full scan、failure latch、tie-break、single unwrap/no fallback 和错误外观均有可杀 mutation 的测试；P0/P1=0。

建议 commit：

```text
feat(protocol): recover obfuscation hybrid cek
```

### 6.4 实际证据（2026-07-21）

- RED：`ObfuscationHybridRecipientPrivateKeys` 与 `ObfuscationHybridCekRecovery` 不存在，focused 测试按预期编译失败。
- GREEN：新测试 10 tests；真实 BC builder wire 可恢复 CEK，wrong/rotated exact-length `ek` 与随机 decoy 经完整扫描为 `NOT_FOR_ME`。
- 固定工作量已锁定：2 local × 8 wire 始终为 2 X25519、16 decap、32 HKDF、16 compare；测试记录并验证 wire-outer/local-inner 顺序。
- ML-KEM failure 在第 1/8/16 个候选注入，包含先命中后末尾失败，均完整扫描、0 unwrap、泛化失败；真实 BC zero EPK 对两个 local pair 走完整 dummy scan。
- duplicate wire rid 与全部 malformed wire 在任何 local handle 前拒绝；完整 pair 判重、共享单 component、unsnapshotable local list、tie-break、单次 unwrap/no fallback 与错误映射均有回归。
- focused 四套件 48 tests 通过；`windletter-protocol` 及依赖 reactor 通过；两路独立审查确认生产/测试 P0=0、P1=0。
- 范围保持为 private-pair value object、full-scan recovery、test 与本计划证据，不包含 GCM/inner/binding flow。

## 7. Task 4：Obfuscation Hybrid unsigned 完整收发

### 7.1 生产 API

新增 `ObfuscationHybridUnsignedSender/Receiver`，沿用 Phase 4 unsigned 请求/结果形状，但将 recipient 输入改为完整 Hybrid public/private pair。

Sender 精确门序：

```text
validate request
→ random CEK + IV
→ Hybrid builder 得到 final EPK/recipients
→ protected(key_alg=Hybrid, cty=wind+inner)
→ AAD + binding
→ strict unsigned inner
→ GCM
→ real writer
→ clear owned materials
```

Receiver 精确门序：

```text
strict parse + exact unsigned Hybrid profile
→ AAD
→ Hybrid CEK recovery
→ GCM
→ strict unsigned inner
→ binding
→ return UNSIGNED
```

### 7.2 RED

新增 sender/receiver unit tests、共享真实 BC fixture 与 unsigned multi-recipient E2E：

- 请求 snapshots 与 duplicate complete-pair 规则。
- protected 精确 profile；所有 entry 必须有 `ek` 且无 kid。
- final shuffled recipients 进入 AAD 与两项 binding。
- binary payload 含 `0x00` 与非 UTF-8 字节的真实 JSON round-trip。
- 8-bucket 至少一个真实收件人；只给目标完整 private pair 即可解密。
- unrelated pair 完整扫描后 `NOT_FOR_ME`。
- GCM/binding 失败不返回 payload。
- borrowed handles 不关闭，CEK/IV/inner/GCM AAD 清除。

### 7.3 GREEN 与门禁

Focused：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybridUnsignedSenderTest,ObfuscationHybridUnsignedReceiverTest,ObfuscationHybridUnsignedMultiRecipientE2ETest,ObfuscationHybridCekRecoveryTest,ObfuscationX25519UnsignedMultiRecipientE2ETest,PublicHybridUnsignedMultiRecipientE2ETest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

完成条件：真实 BC/wire unsigned 闭环通过，strict/AAD/recovery/GCM/inner/binding 无绕过；P0/P1=0。

建议 commit：

```text
feat(protocol): add obfuscation hybrid unsigned flow
```

### 7.4 实际证据（2026-07-21）

- RED：共享 fixture、sender/receiver unit 与真实 multi-recipient E2E 因 `ObfuscationHybridUnsignedSender/Receiver` 不存在而按预期编译失败。
- GREEN：新增两条完整 flow 和 6 个 Task 4 tests；真实 BC 三收件人经 builder 形成 8-entry bucket，每个完整 private-key pair 均可从实际 JSON wire 恢复包含零字节与非 UTF-8 字节的 binary payload，unrelated pair 为 `NOT_FOR_ME`。
- wire/profile 已锁定：`cty=wind+inner`、`key_alg=X25519ML-KEM-768`、单 EPK；所有 entry 均为 `rid16/ek1088/encryptedKey40` 且无 kid，最终 shuffled recipients 同时进入 AAD、两项 binding 与 wire。
- Receiver 门序已用 poisoned local list 锁定：malformed/profile/AAD/duplicate-rid 均先于本地 handle 读取；recovery 异常原样透传，ciphertext tamper 为 `GCM_AUTH_FAILED`，认证后的错误 binding 为 `BINDING_FAILED`。
- Sender 成功与 GCM 失败、Receiver 成功与 GCM 认证失败均直接持有原始 CEK/IV/inner/GCM-AAD/provider-output 引用并验证 finally 清零；borrowed X25519/ML-KEM handles 保持开启。
- focused 六套件 21 tests 通过；`windletter-protocol` 及依赖 reactor 通过；三路独立协议、安全、测试/代码审查确认 P0=0、P1=0。
- 范围保持为 unsigned sender/receiver、共享测试 fixture、三类 Task 4 tests 与本计划证据，不包含 signed flow 或 Task 6 矩阵。

## 8. Task 5：Obfuscation Hybrid signed 完整收发

### 8.1 生产 API

新增 `ObfuscationHybridSignedSender/Receiver`。recipient recovery 与 unsigned 相同；signed 分支复用 `SignedInnerCodec`、可信 `SigningKeyResolver` 和现有 Ed25519 kid 双重绑定。

Receiver 必须严格保持：

```text
recipient recovery → GCM → strict signed inner → binding
→ trusted signer lookup
→ resolver record kid check
→ actual public-key-derived kid check
→ verify exact received protected_b64 + "." + payload_b64
→ return SIGNED_VALID identity
```

### 8.2 RED

新增 signed sender/receiver unit tests与真实 multi-recipient E2E：

- outer `cty=wind+jws`、inner `typ=wind+jws/alg=EdDSA`。
- exact prepared segments 签名，receiver 不重新 JCS 签名输入。
- binary/text/empty payload 的至少一个真实闭环；完整 bucket 矩阵留最终 Task 6。
- binding failure 发生在 signer resolver 前。
- unknown signer、record kid mismatch、实际公钥 kid mismatch、wrong key、signature flip 均不返回 identity。
- unrelated recipient 不调用 signer resolver。
- borrowed encryption/signing handles 不关闭；临时签名输入和 secret 清除。

### 8.3 GREEN 与门禁

Focused：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybridSignedSenderTest,ObfuscationHybridSignedReceiverTest,ObfuscationHybridSignedMultiRecipientE2ETest,ObfuscationHybridUnsignedMultiRecipientE2ETest,ObfuscationX25519SignedMultiRecipientE2ETest,PublicHybridSignedMultiRecipientE2ETest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

完成条件：真实 signed wire、binding-before-identity 与 exact Ed25519 verification 全部锁定；P0/P1=0。

建议 commit：

```text
feat(protocol): add obfuscation hybrid signed flow
```

## 9. Task 6：八组合 strict/tamper/randomness 与阶段封板

### 9.1 非重复 E2E 矩阵

Builder 组件覆盖全部 `1/8/9/16/17/32` 边界；最终真实 BC E2E 用以下最小矩阵覆盖两种签名状态、三种 bucket、三类 payload、padded/exact bucket：

| Profile | 真实人数 | Bucket | Payload | 额外断言 |
|---|---:|---:|---|---|
| unsigned | 1 | 8 | binary | 真实项 + 诱饵 implicit rejection |
| unsigned | 16 | 16 | text | 首/中/尾真实 recipient |
| unsigned | 17 | 32 | empty | 首/中/尾 + unrelated |
| signed | 8 | 8 | text | 首/中/尾 + trusted signer |
| signed | 9 | 16 | empty | padded + exact signature segments |
| signed | 32 | 32 | binary | 首/中/尾 + unrelated + signer |

每条 Hybrid wire 断言所有 entry `rid16/ek1088/encryptedKey40`，所有真实 `ek` 两两不同，AAD 等于 final shuffled recipients 的 JCS。

另新增紧凑的 `WindLetterEightProfilePayloadE2ETest`：对 8 个 mode × algorithm × signing profile 分别运行 text 与含零字节/非 UTF-8 的 binary payload，共 16 个真实 crypto + JSON wire round-trip。该矩阵只证明 payload/profile 全覆盖；多收件人、bucket、tamper 继续由专项测试承担，避免重复笛卡尔积。

### 9.2 Tamper 门禁

- stale AAD 下修改 rid/ek/encrypted key：`AAD_MISMATCH`，recipient crypto 未调用。
- 使用真实生成且与消息无关的合法 X25519 EPK：完整扫描后确定为 `NOT_FOR_ME`；低阶 EPK：泛化 recovery failure。
- wrong/swapped `ek`：修改后同步重算 `outer.aad`，保持 ciphertext/tag 不变；断言在 GCM 前完成 `N×M` decap/compare 后为 `NOT_FOR_ME`。
- 保持匹配 rid/ek、损坏 selected encrypted key：泛化 `KEY_UNWRAP_FAILED`、no fallback。
- recipients 重排并重算 AAD、IV/ciphertext/tag 修改：`GCM_AUTH_FAILED`。
- 使用真实 CEK 重加密错误 binding：`BINDING_FAILED`。
- unknown signer、signature flip、exact protected/payload segment 修改：`SIGNATURE_INVALID` 或既有可信身份错误分类。
- 所有失败不得释放 payload 或 identity。

### 9.3 Strict/writer characterization

现有 parser/writer 生产代码已支持 Hybrid obfuscation；首次测试可能直接 GREEN，必须如实记录为 characterization，不制造伪 RED：

- required/forbidden `epk`、kid、rid、ek、encrypted key。
- rid 15/17、ek 1087/1089、encrypted key 39/41、epk.x 31/33。
- bucket 7/9/15/17/31/33。
- rid/ek/encrypted key/epk.x 的 padding、非法 alphabet、non-canonical trailing bits。
- 8-entry Hybrid writer → strict parser round-trip，逐 entry 保持三字段与顺序。

### 9.4 Randomness 与八组合回归

相同业务输入连续 unsigned 发送两次，断言 EPK、IV、目标 rid、目标真实 ek、ciphertext 不同。identity shuffle 不要求每次不同。

最终回归包含：

- public × X25519 × unsigned/signed
- public × Hybrid × unsigned/signed
- obfuscation × X25519 × unsigned/signed
- obfuscation × Hybrid × unsigned/signed

### 9.5 验证命令

Focused matrix：

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationHybrid*Test,ObfuscationX25519*E2ETest,PublicX25519*E2ETest,PublicHybrid*E2ETest,JacksonOuterWireWriterTest,OuterWireCanonicalBase64UrlTest,OuterWireParserTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
```

Protocol 及依赖：

```powershell
mvn -q -pl windletter-protocol -am test
```

Fresh full reactor：

```powershell
mvn -q clean test
```

统计并核对：

- 0 failure、0 error、0 skipped。
- tests 不低于进入阶段的 606。
- 无新增 `@Disabled`、skip、弱断言。
- 对比阶段基线与 `git diff --diff-filter=D`，不得删除既有 test class/test method 后用新增数量掩盖覆盖下降。
- `git diff --check` 通过。
- `docs/README.md` 仍未纳入。
- final spec 与 code/security review P0=0/P1=0。

完成后更新本计划实际证据、Deferred P2 和 overall 阶段状态。

建议 commit：

```text
test(protocol): close obfuscation hybrid phase
```

## 10. 每任务统一执行步骤

1. `git status --short --branch`、HEAD 与范围核对。
2. 读取该任务真实源码、协议段落和本计划合同。
3. 运行上一个闭环 focused baseline。
4. 写本任务最小但完整 RED，记录真实失败原因。
5. 实现 GREEN，不提前实现后续任务。
6. 运行 focused gate；必要时运行 protocol dependency reactor。
7. 独立 spec review。
8. 独立 code/security review。
9. 修复所有 P0/P1；登记 P2 影响与建议。
10. `git diff --check`、测试数、disabled/skip、变更文件范围核对。
11. 只暂存本闭环文件，确认 `docs/README.md` 未暂存。
12. 单独 commit；不自动 push。

## 11. Phase 5 P0/P1 checklist

- [ ] rid 与 KEK 来自同一 entry、同一个 `SS_ECC || SS_PQ`。
- [ ] 每个真实 entry 独立 ML-KEM encapsulation。
- [ ] 单消息一个 EPK，全部真实项先于 padding/shuffle。
- [ ] Hybrid decoy 三字段长度正确且来自 CSPRNG。
- [ ] 只按完整 pair 判重；单 component 复用合法；无交叉拼接。
- [ ] duplicate wire rid 在 local handle 前拒绝。
- [ ] 正常输入严格 `N×M` decap/compare，命中无提前退出。
- [ ] candidate crypto failure 全局锁存、dummy scan、zero unwrap。
- [ ] tie-break 固定，selected unwrap 恰好一次且 no fallback。
- [ ] wrong/swapped valid ek 与 provider failure 的语义不混淆。
- [ ] strict → AAD → recovery → GCM → inner → binding → signature 门序正确。
- [ ] signed exact segments 与可信实际公钥 kid 绑定。
- [ ] borrowed handles 不关闭；owned secrets 全路径清除。
- [ ] 八组合真实 crypto/JSON wire E2E 全绿。
- [ ] 所有失败不返回 payload/identity。
- [ ] final P0=0、P1=0。

## 12. Deferred P2 初始登记

以下 P2 不阻塞阶段 5；每个任务若新增 P2，追加影响与建议：

1. **完整扫描性能/DoS 预算**：每条消息最多 `local pair count × 32` 次 ML-KEM decapsulation；当前保证协议完整扫描，不截断身份。Demo 后评估限流、预算、并行和本地候选索引。
2. **阶段专用代码重复**：deriver/builder/recovery 与四条 flow 会和已有 profile 重复；影响是维护成本，不影响当前协议正确性。八组合封板后再统一 helper。
3. **统计 timing/shuffle 测试**：当前以固定调用数、无 early-return、确定随机源与真实 BC E2E 作为门禁；更强统计测试后置。
4. **testkit 迁移**：`windletter-testkit` 当前无 `src`，本阶段不为共享 fixture 扩大基础设施；Phase 6/7 再建立跨模块 public-surface matrix。
5. **API 错误映射与 key lease**：protocol 内部细分错误保留；Phase 6 必须将除 `NOT_FOR_ME` 外的无效消息统一为 `InvalidMessage`，并由 API lease 负责关闭完整 Hybrid handle pair。
6. **四条 flow 的 immutable 临时数据清理边界**：Java `String`/record 中的公开 wire 数据不能主动清除；不含 private key，但会增加短期内存副本。Demo 后评估更窄生命周期。
7. **Task 1 长度与恶意 provider 测试穷举**：核心 null/短/长和关键 mutation 已覆盖，但尚未穷举每个 primitive/HKDF 输出的全部 null、±1 组合，也未逐一验证 provider 修改 public EPK/EK 参数。当前生产输入均 defensive clone、输出均精确验长；影响是测试完备性而非已知协议错误，Task 6 tamper/strict 封板后再补 mutation matrix。
8. **Task 1 测试 helper 重复**：单个 deriver 测试文件较长；只影响维护成本。阶段完成后与其它 profile fixture 一并抽取，不在主链中提前建设 testkit。
9. **Task 2 异常 List 快照 hardening**：普通稳定列表会在 crypto 前完整验证和复制；恶意或并发变化的自定义 `List` 可能使初始 `size()` 与迭代项数不一致。影响限本地调用方合同，不是远程协议漏洞；Demo 后可先 `List.copyOf` 再统一验数验项。
10. **Task 2 provider 重复 `ek` 灾难检测**：每个真实 pair 已独立调用 encapsulation，正常 BC 与测试均证明 `ek` 独立；builder 不额外拒绝底层 RNG/provider 灾难性重复的 1088-byte ciphertext。Demo 后可加入 per-message `ek` 唯一性防御。
11. **Task 2 failure-path 穷举**：尚未直接测试 ephemeral public key null/错长、A256KW null/39/41-byte 输出及 shuffle `nextInt` 失败；生产长度校验与 finally 路径已审查正确。影响为回归覆盖完整性，Task 6 或 Demo 后补 mutation matrix。
12. **Task 3 更大 bucket 的顺序矩阵**：固定扫描调用数和 wire-outer 顺序已在 8-entry bucket 锁定，16/32 bucket 由 builder/最终 E2E 覆盖但未逐项记录 decap 顺序。影响仅为测试深度；Task 6 可按成本补一个 32-entry 计数用例。
13. **Task 3 清零观测深度**：selected KEK/wrapped/provider CEK、candidate/wire rid、provider secrets 已直接观察；malformed-local/HKDF INTERNAL 分支以及 EPK、wire `ek`、未选中 encrypted-key snapshot 未全部持有引用逐项断言。生产 finally 路径已审查正确；Demo 后用共享 tracking fixture 补齐。
14. **Task 3 原子 pair 负例深度**：duplicate complete pair 与共享单 component 已覆盖，但未单独构造“跨两条记录交叉拼接才会命中”的负例。生产始终以 record pair 建 context，不生成交叉组合；最终多收件人 E2E 后再补显式 mutation test。
15. **Task 4 重复边界与 provider-contract 测试深度**：本闭环锁定了真实主链、关键门序、GCM/binding 失败与原始引用清零，但未重复铺开 33 recipients、全部 UUID/时间边界、GCM null/错长、Result 契约和 authenticated malformed-inner。相邻 profile 与底层组件已有对应证据；Task 6 优先补跨 profile/tamper 矩阵，剩余重复 mutation 留 Demo 后。
16. **GCM provider 故障诊断粒度**：Receiver 与既有 flow 一致，将 GCM runtime、null 输出和真实 tag 认证失败统一映射为 `GCM_AUTH_FAILED`。这不会释放 payload，且 Phase 6 API 仍会统一为 `InvalidMessage`；影响仅为内部 provider 故障诊断，Demo 后可引入更明确的 provider-contract 分类。
17. **Task 4 borrowed-handle 失败路径显式覆盖**：成功与 unrelated 路径已证明真实 handle 未关闭，生产 flow/recovery 也没有关闭 borrowed handles；AAD、GCM、binding 每条失败路径尚未逐一重复读取 handle 证明开放。影响为测试完备性，不是已知生命周期错误，Task 6 或 Demo 后统一补 tracking fixture。
