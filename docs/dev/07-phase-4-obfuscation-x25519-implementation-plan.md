# WindLetter Phase 4 Obfuscation X25519 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** 完成 obfuscation × X25519 × unsigned/signed 的真实 Sender、Receiver、固定分桶、诱饵、完整扫描、wire 和对抗测试，并保持四个 public 组合全部回归通过。

**Architecture:** 新增三个 Obfuscation X25519 专用深模块：一次 X25519 同时派生 rid/KEK、每消息临时 epk 的 recipient builder、完整 Cartesian 扫描并内聚 unwrap 的 CEK recovery。四个 flow 只编排已经冻结的 strict parse → AAD → recovery → GCM → inner → binding → optional signature 门序，不改 public flow，也不提前建设 Hybrid/API/armor 或通用 mode 框架。

**Tech Stack:** Java 17、Maven reactor、Bouncy Castle 1.83、Jackson、RFC 8785 JCS、JUnit 5。

**Status:** 2026-07-18 Task 1 `rid/ecc + KEK` 联合派生已完成 RED/GREEN、spec review 与 code/security review，随本闭环提交；Task 2 尚未开始。

---

## 1. 执行基线与硬约束

计划编写时的实时基线：

- 分支：spike/demo-v0
- HEAD：b1978f3（docs(protocol): design obfuscation x25519 phase）
- JDK：C:\Users\幻\.jdks\ms-17.0.16
- mvn -q test：56 suites、513 tests、0 failure、0 error、0 skipped
- 开始编写本计划前，业务工作区只有既存 docs/README.md 行尾状态噪音；内容 diff 为空。本文件与 01/06 的状态更新组成单独 docs-only 闭环，所有提交必须排除 docs/README.md
- 协议真相：docs/Wind Letter v1.0协议.md，尤其末尾 2026-07-18 Obfuscation X25519 开发修订
- 设计真相：docs/dev/06-phase-4-obfuscation-x25519-design.md

执行规则：

- 每项生产行为先写测试并观察 RED，再写最小实现；
- 一个 Task 形成一个可独立验证、独立 review、独立提交的闭环；
- 每个 Task 先做 spec review，再做 code/security review；开放 P0/P1 必须修复并复审；
- tracking/failing provider 只用于参数、门序、完整扫描、错误语义和清零测试；真实 E2E 必须使用真实 BC X25519、HKDF-SHA256、A256KW、A256GCM 和 Ed25519；
- 不修改已封板 public flow，不新增错误码，不重排 ErrorCode；
- 不自动 push；不暂存 docs/README.md；
- 每次提交可同步更新本计划中该 Task 的 RED/GREEN/review/commit 证据；
- P2 不阻塞，但必须登记影响和建议；任何协议、密码学、认证 P0/P1 都阻塞下一 Task。

## 2. 文件结构与职责

### 2.1 新增 key/recipient/routing

- windletter-protocol/src/main/java/com/windletter/protocol/key/ObfuscationX25519KeyDeriver.java
  - 一次 X25519 共享秘密同时派生 16-byte rid/ecc 与 32-byte KEK；拥有并清理共享秘密和派生结果。
- windletter-protocol/src/test/java/com/windletter/protocol/key/ObfuscationX25519KeyDeriverTest.java
  - 固定向量、双向一致、provider contract、close/zeroization。
- windletter-protocol/src/main/java/com/windletter/protocol/recipient/ObfuscationX25519RecipientBuilder.java
  - 每消息 epk、真实 recipient、8/16/32 bucket、诱饵、唯一 rid、128 次有界重采样和 Fisher-Yates shuffle。
- windletter-protocol/src/test/java/com/windletter/protocol/recipient/ObfuscationX25519RecipientBuilderTest.java
  - 分桶边界、真实 unwrap、随机性、碰撞、资源所有权。
- windletter-protocol/src/main/java/com/windletter/protocol/routing/ObfuscationX25519CekRecovery.java
  - 完整 rid 扫描、选择规则、错误归一、A256KW unwrap 和全部候选材料清理。
- windletter-protocol/src/test/java/com/windletter/protocol/routing/ObfuscationX25519CekRecoveryTest.java
  - Cartesian 比较计数、首中尾/多 key/tie-break、no-fallback、异常 code/message/cause。

### 2.2 新增 flow

- windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedSender.java
- windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedReceiver.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedSenderTest.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedReceiverTest.java
- windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519SignedSender.java
- windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519SignedReceiver.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedSenderTest.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedReceiverTest.java

### 2.3 新增阶段封板测试

- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519FlowTestFixtures.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedMultiRecipientE2ETest.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedMultiRecipientE2ETest.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519TamperE2ETest.java
- windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519RandomnessE2ETest.java

### 2.4 修改测试与文档

- windletter-protocol/src/test/java/com/windletter/protocol/codec/JacksonOuterWireWriterTest.java
  - 增加 Obfuscation X25519 writer → strict parser round-trip。
- windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireCanonicalBase64UrlTest.java
  - 增加 protected.epk.x 与 recipients[i].rid canonical Base64URL。
- windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireParserTest.java
  - 补齐 Obfuscation X25519 条件字段、bucket 和 strict 回归。
- docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md
  - 每个闭环记录证据和 P2。
- docs/dev/01-demo-first-overall-implementation-plan.md
  - 仅在 Task 6 全部门禁通过后更新阶段完成状态。

现有生产 parser、wire records、OuterJsonMapper、OuterAad、OuterBinding、inner codecs 和 public flows 默认只复用、不修改；若实现发现必须修改，先证明是 P0/P1 主链阻塞并单独报告。

## 3. 冻结的实现合同

### 3.1 联合派生

同一个 32-byte SS_ECC 只计算一次：

~~~text
rid = HKDF-SHA256(
    salt=UTF8("wind"),
    ikm=SS_ECC,
    info=UTF8("rid/ecc"),
    length=16
)

KEK = HKDF-SHA256(
    salt=UTF8("wind"),
    ikm=SS_ECC,
    info=UTF8("WindLetter v1 KEK | X25519"),
    length=32
)
~~~

X25519 provider 的 CryptoOperationException 在 Receiver 侧统一视为攻击者可控 agreement failure；HKDF provider failure 必须由 deriver 包装为本地 IllegalStateException，避免与低阶 epk 混淆。

### 3.2 Receiver 错误矩阵

| 场景 | ErrorCode | message | cause |
|---|---|---|---|
| 重复 wire rid | INVALID_FIELD | 明确本地诊断 | 可为空 |
| 重复本地 X25519 公钥 | INTERNAL_ERROR | 明确本地诊断 | 可为空；若源自 accessor/provider 异常则保留 |
| 空 localKeys / 全扫描无命中 | NOT_FOR_ME | 不暴露命中线索 | 空 |
| X25519 CryptoOperationException（含低阶/全零 epk） | KEY_UNWRAP_FAILED | obfuscation recipient key recovery failed | 必须为空 |
| selected A256KW unwrap 抛 CryptoOperationException，或返回 null/非 32-byte CEK | KEY_UNWRAP_FAILED | obfuscation recipient key recovery failed | 必须为空 |
| null/closed/foreign handle、X25519 handle/public-key contract、HKDF contract 违约 | INTERNAL_ERROR | 明确本地诊断 | 保留存在的 cause；显式 null 校验可为空 |
| A256KW unwrap 抛出非 CryptoOperationException 的意外本地 runtime failure | INTERNAL_ERROR | 明确本地诊断 | 保留 |
| GCM、binding、signature | 既有分类 | 既有 flow 语义 | 既有内部合同 |

不得把命中后的任何失败降级为 NOT_FOR_ME，不得对后续 entry fallback。这里有意把 selected encrypted_key 导致的正常 unwrap 完整性失败，以及 unwrap provider 返回 null/错误长度的结果，收敛为同一 Receiver 外观；Task 2 Sender 侧 wrap 的 null/错误长度仍属于本地 INTERNAL_ERROR。只有 unwrap 抛出非 CryptoOperationException 的意外 runtime failure 才按本地 provider 故障保留诊断 cause。

### 3.3 所有权

- Sender/Receiver 的业务私钥 handles 始终 borrowed，不关闭。
- Recipient builder 是 per-message ephemeral X25519 handle 的唯一 owner，成功失败都关闭。
- DerivedMaterial 拥有 rid/KEK；close 幂等、清零，close 后 accessor 抛 IllegalStateException。
- CekRecovery 在自身 finally 清理全部候选 rid、selected/unselected/replaced KEK 和公钥 snapshots。
- CekRecovery 返回 caller-owned CEK；Receiver flow 在 finally 清理 CEK、decrypted inner、GCM AAD 和签名临时数组。
- Epk、ObfuscationRecipient、PreparedRecipients 只返回公开数据的防御性 snapshots。

## 4. Task 1：rid/ecc + KEK 联合派生

**Files:**

- Create: windletter-protocol/src/main/java/com/windletter/protocol/key/ObfuscationX25519KeyDeriver.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/key/ObfuscationX25519KeyDeriverTest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md（仅记录 Task 1 证据）

- [x] **Step 1: 写固定向量与生命周期 RED**

测试沿用 PublicX25519KekDeriverTest 使用的 RFC 7748 Alice private、Bob public 与 shared secret 字节，但这些现有常量是 private；必须在新测试内复制协议向量常量，不得直接引用不可访问符号，并固定：

~~~java
private static final byte[] EXPECTED_RID = HEX.parseHex(
        "31960c71ff806835cb242176264ebd4b"
);
private static final byte[] EXPECTED_KEK = HEX.parseHex(
        "277479809bf70197fc456c17b12429319823906852875eb2353482fb3a4e0cb6"
);

try (X25519PrivateKeyHandle alice = x25519.importPrivateKey(ALICE_PRIVATE);
     ObfuscationX25519KeyDeriver.DerivedMaterial material =
             deriver.derive(alice, BOB_PUBLIC)) {
    assertArrayEquals(EXPECTED_RID, material.rid());
    assertArrayEquals(EXPECTED_KEK, material.kek());
}
~~~

同时先写这些 RED：

- Sender/Receiver 两侧真实 X25519 得到相同 rid 和 KEK；
- recording provider 精确断言每次 derive 只调用一次 X25519、随后调用两次 HKDF；
- exact UTF-8 salt/info 与 16/32 长度；
- shared secret 在成功、第一/第二次 HKDF 失败、长度违约时清零；
- rid/KEK provider output 在成功复制进 DerivedMaterial 后以及所有失败路径都清零；
- close 清零 owned output、可重复 close、close 后 rid()/kek() 都失败；
- borrowed handle 未关闭；
- null、31/33-byte peer、null/错误长度 shared、null/错误长度 HKDF output 作为本地 provider contract 以 IllegalStateException 拒绝；provider 返回 32-byte 全零 shared secret 必须显式转为 CryptoOperationException；
- X25519 CryptoOperationException 原样保留；HKDF CryptoOperationException 包装为带 cause 的 IllegalStateException。

实际证据（2026-07-18）：新增 16 个 `ObfuscationX25519KeyDeriverTest` 测试，覆盖真实 BC 固定向量与双向一致、provider 调用与精确参数、输入/异常合同、防御性复制、borrowed handle，以及 shared/rid/KEK/close 的成功和失败清零路径。

- [x] **Step 2: 运行 RED**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519KeyDeriverTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: compilation failure，唯一原因是 ObfuscationX25519KeyDeriver 不存在。

实际 RED（2026-07-18）：最小固定向量与完整 16-test 两个安全节点均运行上述命令并得到 exit 1；失败阶段为 `maven-compiler-plugin:testCompile`，最终全部诊断仅为 `ObfuscationX25519KeyDeriver` 或其嵌套 `DerivedMaterial` 不存在。

- [x] **Step 3: 实现公开表面与 ownership**

生产类公开表面固定为：

~~~java
public final class ObfuscationX25519KeyDeriver {
    public ObfuscationX25519KeyDeriver(X25519Crypto x25519, HkdfCrypto hkdf);

    public DerivedMaterial derive(
            X25519PrivateKeyHandle ownKey,
            byte[] peerPublicKey
    );

    public static final class DerivedMaterial implements AutoCloseable {
        public byte[] rid();
        public byte[] kek();
        @Override public void close();
    }
}
~~~

derive 的最小实现顺序：

~~~java
shared = x25519.deriveSharedSecret(ownKey, peerPublicKey.clone());
requireExactLength(shared, 32, "X25519 shared secret");
rejectAllZeroAsCryptoOperationException(shared);
ridProviderOutput = deriveHkdf(HKDF_RID_INFO, shared, 16);
kekProviderOutput = deriveHkdf(HKDF_KEK_INFO, shared, 32);
return new DerivedMaterial(ridProviderOutput, kekProviderOutput); // constructor clones
~~~

finally 始终清理 shared、ridProviderOutput 和 kekProviderOutput；DerivedMaterial 构造器先校验并复制两个 provider output，只拥有自己的副本。accessor 继续只返回副本，close 后将内部副本清零并置为 destroyed。这样即使测试 provider 保留其返回数组的别名，derive 返回时该 provider-owned 输出也已经归零，而 material 仍可正常使用。

实际实现（2026-07-18）：仅新增 `ObfuscationX25519KeyDeriver`；一次 X25519 后按 `rid/ecc` 16-byte、`WindLetter v1 KEK | X25519` 32-byte 顺序使用同一 shared reference 派生，HKDF provider failure 分类、所有临时数组清零和 `DerivedMaterial` ownership 均由该深模块内聚。

- [x] **Step 4: 跑 focused 与 module gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519KeyDeriverTest,PublicX25519KekDeriverTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
mvn -q -pl windletter-protocol -am test
~~~

Expected: 两条命令 exit 0；0 failure/error/skipped；public deriver 无回归。

实际 GREEN（2026-07-18）：focused exit 0，2 suites、24 tests、0 failure、0 error、0 skipped；module reactor exit 0，46 suites、491 tests（core 1、crypto 55、protocol 435）、0 failure、0 error、0 skipped；`git -c safe.directory="D:/CodingProject/WindLetter" diff --check` exit 0。

- [x] **Step 5: review、证据与提交**

Spec review 核对协议开发修订第 2、8、9 条；code/security review 核对双 HKDF 参数、异常区分、ownership transfer 和所有失败路径。修复全部 P0/P1，更新本 Task 证据后只提交上述两个源码/测试文件与本计划证据。

实际双审（2026-07-18）：独立 spec review 与 code/security review 均为 P0=0、P1=0；生产实现无需返工。两个非阻塞测试硬化 P2 已登记为本计划第 9、10 项，不影响当前协议、密码学或资源生命周期正确性。本闭环只提交新 deriver、对应 16-test 与本 Task 证据，提交信息如下；Task 2 未开始。

最终提交前复验（2026-07-18）：JDK 17 module reactor 为 46 suites、491 tests，full reactor 为 57 suites、529 tests；均为 0 failure、0 error、0 skipped。

~~~text
feat(protocol): derive obfuscation x25519 key material
~~~

## 5. Task 2：per-message epk、bucket、decoy 与 shuffle

**Files:**

- Create: windletter-protocol/src/main/java/com/windletter/protocol/recipient/ObfuscationX25519RecipientBuilder.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/recipient/ObfuscationX25519RecipientBuilderTest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md（仅记录 Task 2 证据）

- [ ] **Step 1: 写真实 recipient 与 bucket RED**

使用真实 BC primitives，创建 3 个 recipient，断言每个真实 recipient 都能用自己的 static private key 与返回 epk 恢复同一 CEK：

~~~java
ObfuscationX25519RecipientBuilder.PreparedRecipients prepared =
        builder.build(publicKeys, cek);

assertEquals("OKP", prepared.epk().kty());
assertEquals("X25519", prepared.epk().crv());
assertEquals(32, prepared.epk().x().length);
assertEquals(8, prepared.recipients().size());
~~~

测试随后必须对三个 private handle 分别使用 Task 1 deriver 和返回的 epk.x 派生 rid/KEK，在 8 个 entry 中以 MessageDigest.isEqual 定位真实项，再用真实 A256KW unwrap 并逐一 assertArrayEquals(cek, unwrapped)；每次循环在 finally 清理 rid、KEK 和 unwrapped 副本。最终必须恰好找到 3 个不同真实项。

参数化 bucket 必须逐项断言 `1→8`、`8→8`、`9→16`、`16→16`、`17→32`、`32→32`；测试 fixture 使用可生成有效非低阶 shared secret 的 tracking X25519/HKDF provider，不能把任意 32-byte 测试数组误当作真实 X25519 公钥。

每个 entry 必须只有 16-byte rid、40-byte encryptedKey、null ek；返回列表不可修改。

- [ ] **Step 2: 写预验证、碰撞、随机源与关闭 RED**

测试必须证明：

- 0/33、null list/null item、31/33-byte key、重复真实公钥、null/31/33-byte CEK 在 generate/derive/wrap/random 前拒绝；
- 一次 build 只生成一个 ephemeral handle，所有真实 recipient 共用其 epk；
- ephemeral handle 在 success、derive failure、wrap failure、真实 rid collision、decoy exhaustion、shuffle failure 路径均关闭一次；
- 真实 rid collision → INTERNAL_ERROR，且不重生 epk、不继续 padding；
- 诱饵 rid 与全部已用 rid 冲突时重采样；单个诱饵连续 128 次冲突后 → INTERNAL_ERROR；
- A256KW null/非 40-byte output → INTERNAL_ERROR，临时 KEK 与 CEK snapshot 清零；
- A256KW wrap 或 SecureRandom nextBytes/nextInt 抛出的本地 provider failure → INTERNAL_ERROR 并保留 cause；
- deterministic SecureRandom 验证 Fisher-Yates 的 nextInt(i + 1) 调用序列；identity permutation 合法；
- 连续两次真实 build 的 epk 和真实 rid 不复用；
- 修改输入 public key/CEK 或 accessor 返回数组不能改变 PreparedRecipients。

- [ ] **Step 3: 运行 RED**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519RecipientBuilderTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: compilation failure，唯一原因是 ObfuscationX25519RecipientBuilder 不存在。

- [ ] **Step 4: 实现 builder 深模块**

公开表面固定为：

~~~java
public final class ObfuscationX25519RecipientBuilder {
    public ObfuscationX25519RecipientBuilder(
            X25519Crypto x25519,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap
    );

    ObfuscationX25519RecipientBuilder(
            X25519Crypto x25519,
            HkdfCrypto hkdf,
            A256KeyWrapCrypto keyWrap,
            SecureRandom secureRandom
    );

    public PreparedRecipients build(
            List<byte[]> realRecipientPublicKeys,
            byte[] cek
    );

    public record PreparedRecipients(
            Epk epk,
            List<RecipientEntry> recipients
    ) { }
}
~~~

Builder 必须用传入的同一个 X25519Crypto 实例生成 ephemeral handle，并在构造器内创建 ObfuscationX25519KeyDeriver(x25519, hkdf)；不得允许调用方把 provider 不兼容的 ephemeral generator 与 deriver 拼在一起。

实现顺序不得调整：

~~~text
validate/snapshot all inputs
→ generate exactly one ephemeral handle
→ snapshot/validate epk public key
→ derive/wrap all real recipients
→ reject real rid collision
→ choose 8/16/32 target
→ add equal-length decoys with per-decoy 128-attempt limit
→ Fisher-Yates over complete real+decoy list
→ return immutable PreparedRecipients
→ close ephemeral and clear all owned temporary arrays
~~~

bucket 函数和 shuffle 保持 private；不得新增 padding framework。shuffle 固定为：

~~~java
for (int i = recipients.size() - 1; i > 0; i--) {
    int j = secureRandom.nextInt(i + 1);
    Collections.swap(recipients, i, j);
}
~~~

- [ ] **Step 5: 跑 focused 与 module gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519RecipientBuilderTest,ObfuscationX25519KeyDeriverTest,PublicX25519RecipientBuilderTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
mvn -q -pl windletter-protocol -am test
~~~

Expected: exit 0；0 failure/error/skipped；public recipient builder 无回归。

- [ ] **Step 6: review、证据与提交**

Spec review 核对开发修订第 1、3、4、5、9 条；code/security review 核对 prevalidation-before-crypto、全局 rid 唯一、随机源、ephemeral owner 和所有异常清理。修复全部 P0/P1 后提交：

~~~text
feat(protocol): build obfuscation x25519 recipients
~~~

## 6. Task 3：完整扫描与 CEK recovery

**Files:**

- Create: windletter-protocol/src/main/java/com/windletter/protocol/routing/ObfuscationX25519CekRecovery.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/routing/ObfuscationX25519CekRecoveryTest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md（仅记录 Task 3 证据）

- [ ] **Step 1: 写真实恢复、完整扫描与选择 RED**

真实 BC round-trip：使用 Task 2 输出的同一条 8-entry wire，分别只提供三个真实 recipient 的 local handle，均恢复原 CEK；unrelated 和 empty localKeys 为 NOT_FOR_ME。

包内测试构造器注入 recording comparator，严格断言比较次数：

~~~java
assertEquals(
        localKeys.size() * recipients.size(),
        comparator.comparisons()
);
~~~

覆盖：

- 命中位于首/中/尾仍完成 N × M 比较；
- recording deriver 精确断言每个 local handle 只 derive 一次，总次数等于 localKeys.size()；
- local key 输入顺序与 wire 顺序相反时选择最小 wire index；
- 同一 wire index 的 rid collision 按最小 local input index；
- duplicate wire rid 在读取任何 local handle 前 INVALID_FIELD；
- duplicate local public key 为 INTERNAL_ERROR；
- only selected entry unwrap 一次。

- [ ] **Step 2: 写 no-fallback、错误外观与清理 RED**

精确断言统一攻击者错误：

~~~java
ProtocolException failure = assertThrows(ProtocolException.class, operation);
assertEquals(ErrorCode.KEY_UNWRAP_FAILED, failure.errorCode());
assertEquals("obfuscation recipient key recovery failed", failure.getMessage());
assertNull(failure.getCause());
~~~

该断言必须覆盖：

- real BC low-order/all-zero epk；
- X25519 provider CryptoOperationException；
- selected wrapped CEK integrity failure；
- unwrap 返回 null/非 32-byte CEK。

另外覆盖：

- closed/foreign/null handle、publicKey null/31/33-byte、HKDF provider failure，以及 unwrap 抛出的非 CryptoOperationException runtime failure → INTERNAL_ERROR；保留存在的 cause，显式 null/长度校验可无 cause；
- wire entry 类型错误、rid/ek/encryptedKey 条件违约 → INVALID_FIELD；
- 首个 wire match unwrap 失败、后续 match 可成功时仍只 unwrap 首个且不 fallback；
- success/failure/NOT_FOR_ME 下全部 candidate rid、全部 KEK、公钥 snapshots 清零；
- returned CEK 是 caller-owned defensive result，borrowed handles 未关闭。

- [ ] **Step 3: 运行 RED**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519CekRecoveryTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: compilation failure，唯一原因是 ObfuscationX25519CekRecovery 不存在。

- [ ] **Step 4: 实现 recovery 深模块**

公开表面固定为：

~~~java
public final class ObfuscationX25519CekRecovery {
    public ObfuscationX25519CekRecovery(
            ObfuscationX25519KeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap
    );

    ObfuscationX25519CekRecovery(
            ObfuscationX25519KeyDeriver keyDeriver,
            A256KeyWrapCrypto keyWrap,
            BiPredicate<byte[], byte[]> ridComparator
    );

    public byte[] recover(
            Epk epk,
            List<RecipientEntry> recipients,
            List<X25519PrivateKeyHandle> localKeys
    );
}
~~~

公开构造器必须注入 MessageDigest::isEqual。算法顺序：

~~~text
validate epk and every X25519 obfuscation entry
→ reject duplicate wire rid
→ snapshot/validate local public keys and reject duplicate local keys
→ derive one DerivedMaterial per local key
→ compare every candidate rid against every wire rid without early return
→ select lexicographically smallest (wireIndex, localIndex)
→ if none: NOT_FOR_ME
→ unwrap exactly selected entry once
→ return 32-byte CEK
→ finally close all DerivedMaterial and clear all snapshots/copies
~~~

不得以 boolean 短路跳过 comparator；选择可使用：

~~~java
if (matches && (selected == null
        || wireIndex < selected.wireIndex()
        || (wireIndex == selected.wireIndex()
        && localIndex < selected.localIndex()))) {
    selected = new Selection(wireIndex, localIndex);
}
~~~

- [ ] **Step 5: 跑 focused 与 module gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519CekRecoveryTest,ObfuscationX25519RecipientBuilderTest,ObfuscationX25519KeyDeriverTest,PublicKidRouterTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
mvn -q -pl windletter-protocol -am test
~~~

Expected: exit 0；统一错误的 code/message/cause 精确通过；完整扫描计数精确等于 N × M。

- [ ] **Step 6: review、证据与提交**

Spec review 核对开发修订第 6、7、8、9 条；code/security review 检查 early-return、duplicate priority、timing comparator、no-fallback、error oracle 和所有 candidate 生命周期。P0/P1 清零后提交：

~~~text
feat(protocol): recover obfuscation x25519 cek
~~~

## 7. Task 4：Obfuscation X25519 unsigned 完整收发

**Files:**

- Create: windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedSender.java
- Create: windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedReceiver.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519FlowTestFixtures.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedSenderTest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedReceiverTest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedMultiRecipientE2ETest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md（仅记录 Task 4 证据）

- [ ] **Step 1: 写真实 unsigned wire RED**

使用真实 BC 组件和 3 个真实 recipient，Sender 从 binary payload 生成 8-entry JSON wire；Receiver 只拿其中一个 private handle 即恢复：

~~~java
ObfuscationX25519UnsignedSender.Result sent = sender.send(
        new ObfuscationX25519UnsignedSender.Request(
                payload, MESSAGE_ID, TIMESTAMP, recipientPublicKeys
        )
);
ObfuscationX25519UnsignedReceiver.Result received = receiver.receive(
        new ObfuscationX25519UnsignedReceiver.Request(
                sent.wireJson(), List.of(secondRecipient)
        )
);

assertEquals("obfuscation", sent.message().protectedHeader().windMode());
assertEquals("X25519", sent.message().protectedHeader().keyAlg());
assertEquals("wind+inner", sent.message().protectedHeader().cty());
assertEquals(8, sent.message().recipients().size());
assertArrayEquals(payload.data(), received.payload().data());
assertEquals(ProtocolAuthenticationStatus.UNSIGNED, received.authenticationStatus());
~~~

同时覆盖 text、empty payload 和 unrelated key → NOT_FOR_ME。

- [ ] **Step 2: 运行 RED**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519UnsignedSenderTest,ObfuscationX25519UnsignedReceiverTest,ObfuscationX25519UnsignedMultiRecipientE2ETest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: compilation failure，唯一原因是两个 unsigned flow 不存在。

- [ ] **Step 3: 实现 unsigned Sender**

公开表面：

~~~java
public final class ObfuscationX25519UnsignedSender {
    public ObfuscationX25519UnsignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm
    );

    ObfuscationX25519UnsignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            SecureRandom secureRandom
    );

    public Result send(Request request);

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            List<byte[]> recipientPublicKeys
    ) { }

    public record Result(WindLetter message, String wireJson) { }
}
~~~

门序固定：

~~~text
Request prevalidation/snapshot
→ random CEK + IV
→ recipientBuilder.build (epk + final padded/shuffled recipients)
→ ProtectedHeader(obfuscation, X25519, wind+inner, Epk)
→ protectedValue
→ OuterAad + OuterBinding over final recipients
→ strict UnsignedInnerCodec
→ ASCII(protected + "." + aad)
→ real A256GCM
→ WindLetter + strict writer
→ finally clear CEK/IV/inner/GCM AAD and request accessor copies
~~~

- [ ] **Step 4: 实现 unsigned Receiver 与门序 tests**

公开表面：

~~~java
public final class ObfuscationX25519UnsignedReceiver {
    public ObfuscationX25519UnsignedReceiver(
            ObfuscationX25519CekRecovery cekRecovery,
            A256GcmCrypto gcm
    );

    public Result receive(Request request);

    public record Request(
            String wireJson,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) { }

    public record Result(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus
    ) { }
}
~~~

Receiver Request 只在构造时拒绝 null 列表，并用 `Collections.unmodifiableList(new ArrayList<>(recipientPrivateKeys))` 固定列表结构；不得使用会提前拒绝 null 元素的 `List.copyOf`。列表中的 handles 仍是 borrowed，null/closed/foreign handle 必须进入 CekRecovery 后按本地 `INTERNAL_ERROR` 合同统一处理，而不是在 record 构造器泄漏 `NullPointerException`。

Receiver 门序固定：

~~~text
strict parse + exact obfuscation/X25519/wind+inner profile
→ OuterAad.verify
→ CekRecovery full scan + unwrap
→ GCM decrypt
→ strict UnsignedInnerCodec.decode
→ OuterBinding.verify
→ return UNSIGNED result
→ finally clear caller-owned CEK/decrypted inner/GCM AAD
~~~

测试用 counting/failing provider 证明 AAD failure 早于 private-key routing，NOT_FOR_ME 早于 GCM，binding failure 不返回 payload；GCM/binding 使用既有错误码。Sender/Receiver 不关闭任何业务 private handle。

清零断言必须观察生产代码实际传递/返回的原始 mutable array 引用，不能只捕获副本：

- Sender 测试用 tracking SecureRandom 保留写入 CEK/IV 的原始引用，用 delegating/failing A256GcmCrypto 保留 key、iv、aad、plaintext 原始引用；在 success、recipientBuilder failure、GCM failure 返回后逐项断言全零。
- Receiver 测试通过 recovery 内的 recording A256KW 与 delegating/failing A256GcmCrypto 保留 caller-owned CEK、GCM AAD、decrypted inner 原始引用；在 success、recovery failure、GCM failure、inner failure、binding failure 后，对当次已经物化的数组逐项断言全零。
- 测试自身为诊断或重加密制作的 owned copy 必须由测试 finally 清理，但不得把“测试清理副本”当作生产清零证据。
- 每条成功和代表性失败路径最后都断言全部 borrowed recipient handles 仍开放。

- [ ] **Step 5: 跑 focused、public regression 与 module gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519UnsignedSenderTest,ObfuscationX25519UnsignedReceiverTest,ObfuscationX25519UnsignedMultiRecipientE2ETest,PublicX25519UnsignedSenderTest,PublicX25519UnsignedReceiverTest,PublicHybridUnsignedSenderTest,PublicHybridUnsignedReceiverTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
mvn -q -pl windletter-protocol -am test
~~~

Expected: exit 0；真实 raw JSON round-trip 通过；public unsigned 无回归。

- [ ] **Step 6: review、证据与提交**

Spec review 核对最终 recipients 进入 AAD/binding/GCM；code/security review 检查 profile、门序、清零、错误透传和无 sender static encryption identity。P0/P1 清零后提交：

~~~text
feat(protocol): add obfuscation x25519 unsigned flow
~~~

## 8. Task 5：Obfuscation X25519 signed 完整收发

**Files:**

- Create: windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519SignedSender.java
- Create: windletter-protocol/src/main/java/com/windletter/protocol/flow/ObfuscationX25519SignedReceiver.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519FlowTestFixtures.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedSenderTest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedReceiverTest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedMultiRecipientE2ETest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md（仅记录 Task 5 证据）

- [ ] **Step 1: 写真实 signed wire RED**

真实 Ed25519 sender、3 个 X25519 recipient、binary/text/empty payload：

~~~java
assertEquals("wind+jws", sent.message().protectedHeader().cty());
assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID, received.authenticationStatus());
assertEquals("trusted-sender-1", received.authenticatedSender().identityId());
assertArrayEquals(payload.data(), received.payload().data());
~~~

trusted resolver 必须返回 actual Ed25519 public key 与 exact signing kid 绑定的 TrustedEd25519Key。

- [ ] **Step 2: 运行 RED**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519SignedSenderTest,ObfuscationX25519SignedReceiverTest,ObfuscationX25519SignedMultiRecipientE2ETest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: compilation failure，唯一原因是两个 signed flow 不存在。

- [ ] **Step 3: 实现 signed Sender**

公开表面：

~~~java
public final class ObfuscationX25519SignedSender {
    public ObfuscationX25519SignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    );

    ObfuscationX25519SignedSender(
            ObfuscationX25519RecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519,
            SecureRandom secureRandom
    );

    public Result send(Request request);

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            Ed25519PrivateKeyHandle senderSigningPrivateKey,
            List<byte[]> recipientPublicKeys
    ) { }

    public record Result(WindLetter message, String wireJson) { }
}
~~~

在 Task 4 Sender 的 final protected/recipients 之后执行：

~~~text
derive actual Ed25519 kid
→ SignedInnerCodec.prepare(message + binding + signingKid)
→ sign exact prepared signingInput
→ require 64-byte signature
→ SignedInnerCodec.assemble
→ real GCM
~~~

finally 清理 signing public snapshot、signingInput、signature、inner、CEK、IV、GCM AAD；Ed25519 handle borrowed。

Signed Sender 测试用 tracking Ed25519 provider 保留生产传入的 signingInput 原始引用和 provider 返回的 signature 原始引用，并复用 Task 4 的 CEK/IV/inner/GCM AAD 原始引用捕获；success、sign throws、signature null/错误长度、GCM-after-signing failure 后都断言当次已物化数组全零，sender signing handle 仍开放。

- [ ] **Step 4: 实现 signed Receiver 与认证门 tests**

公开表面：

~~~java
public final class ObfuscationX25519SignedReceiver {
    public ObfuscationX25519SignedReceiver(
            ObfuscationX25519CekRecovery cekRecovery,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    );

    public Result receive(Request request);

    public record Request(
            String wireJson,
            Ed25519VerificationKeyResolver senderSigningKeys,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) { }

    public record Result(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus,
            ProtocolSenderIdentity authenticatedSender
    ) { }
}
~~~

Signed Receiver Request 对 `recipientPrivateKeys` 使用与 Task 4 相同的允许 null 元素不可变快照；`senderSigningKeys` 只做 null 引用预验证。任何 null/closed/foreign recipient handle 都由 CekRecovery 映射 `INTERNAL_ERROR`，不得在 Request record 构造阶段改变错误外观。

Receiver 在 Task 4 的 GCM 后固定执行：

~~~text
strict SignedInnerCodec.decode
→ OuterBinding.verify
→ resolve trusted signing record
→ record kid == requested kid
→ derive kid from actual trusted public key
→ actual kid == requested kid
→ verify exact decoded protected_b64 + "." + payload_b64 bytes
→ return SIGNED_VALID + trusted identity
~~~

覆盖 unknown signer、record kid mismatch、actual public key mismatch、verify false、verify throws、non-canonical exact segments；binding 必须早于 resolver/verify，recipient recovery failure 必须早于 signer resolver。

Signed Receiver 测试必须让 recording resolver/Ed25519 provider 保留 trusted public-key snapshot、exact signingInput 和 signature 的生产原始引用，并复用 Task 4 Receiver 的 CEK/GCM AAD/decrypted inner 捕获；success、binding failure、unknown/mismatched signer、verify false/throws 后逐项断言已物化数组全零，recipient handles 保持 borrowed/open，caller-owned trusted resolver/key record 未被修改。

- [ ] **Step 5: 跑 focused、unsigned/public regression 与 module gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519SignedSenderTest,ObfuscationX25519SignedReceiverTest,ObfuscationX25519SignedMultiRecipientE2ETest,ObfuscationX25519UnsignedSenderTest,ObfuscationX25519UnsignedReceiverTest,ObfuscationX25519UnsignedMultiRecipientE2ETest,PublicX25519SignedSenderTest,PublicX25519SignedReceiverTest,PublicHybridSignedSenderTest,PublicHybridSignedReceiverTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
mvn -q -pl windletter-protocol -am test
~~~

Expected: exit 0；signed/unsigned obfuscation 与四个 public flow 全绿。

- [ ] **Step 6: review、证据与提交**

Spec review 核对 exact segments、binding-before-signature 和可信身份返回；code/security review 检查 signing-key confusion、错误 oracle、owned arrays 和 borrowed handles。P0/P1 清零后提交：

~~~text
feat(protocol): add obfuscation x25519 signed flow
~~~

## 9. Task 6：完整矩阵、strict/writer 回归与阶段封板

**Files:**

- Modify: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519FlowTestFixtures.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519UnsignedMultiRecipientE2ETest.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519SignedMultiRecipientE2ETest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519TamperE2ETest.java
- Create: windletter-protocol/src/test/java/com/windletter/protocol/flow/ObfuscationX25519RandomnessE2ETest.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/codec/JacksonOuterWireWriterTest.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireCanonicalBase64UrlTest.java
- Modify: windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireParserTest.java
- Modify: docs/dev/07-phase-4-obfuscation-x25519-implementation-plan.md
- Modify after all gates pass: docs/dev/01-demo-first-overall-implementation-plan.md

- [ ] **Step 1: bucket、payload 与首中尾真实 E2E**

Task 2 的组件测试保留全部 `1/8/9/16/17/32 → 8/8/16/16/32/32` 边界；本步骤的真实 E2E 不做 bucket × payload 的笛卡尔重复。Unsigned 独立选择 8/16/32 三个 bucket 的代表用例，signed 也独立选择 8/16/32 三个代表用例，共 6 个 bucket E2E；text、binary、empty payload 分布到这些用例中而非与 bucket 全排列。两类 flow 还必须共同覆盖：

- 同一条 padded/shuffled wire 中，计算所有真实 recipient 的 rid 位置，分别只提供 wire 顺序首/中/尾真实 recipient 的 private handle，均恢复相同 payload；
- unrelated handle 在完整扫描后 NOT_FOR_ME；
- 所有真实/诱饵 entry 均为 16-byte rid + 40-byte encryptedKey + null ek；
- 最终 recipients 的完整顺序同时进入 aad、jwe_recipients_hash 和 GCM AAD。

- [ ] **Step 2: authenticated tamper 矩阵**

fixture 使用真实 sender；用于验证生产清零的 tracking SecureRandom/A256GcmCrypto 必须保存生产收到的原始 mutable array 引用，并在 flow 返回后断言全零。需要越过 GCM 做 authenticated mutation 时，fixture 另行制作测试自己拥有的 CEK/IV/GCM AAD/inner 副本，用真实 BC A256GCM 重新加密并在测试 finally 清理；这些副本只服务 tamper 构造，不算生产清零证据。

逐项覆盖：

| 篡改 | 预期 |
|---|---|
| missing/unknown/wrong semantic value epk kty/crv，或 decoded x 长度错误 | strict INVALID_FIELD |
| epk.kty/crv/x JSON type 错误，或 malformed/non-canonical epk.x Base64URL | strict MALFORMED_WIRE |
| 合法随机 epk 替换 | 完整扫描后 NOT_FOR_ME |
| 低阶/全零 epk | 统一 KEY_UNWRAP_FAILED/message/null cause |
| rid 替换且 aad 未更新 | AAD_MISMATCH |
| duplicate rid 并重算 aad | INVALID_FIELD，早于本地 key 读取 |
| selected encryptedKey 替换并重算 aad | 统一 KEY_UNWRAP_FAILED，无 fallback |
| recipients 顺序改变并重算 aad | GCM_AUTH_FAILED |
| aad 直接替换 | AAD_MISMATCH |
| iv/ciphertext/tag | GCM_AUTH_FAILED |
| 真实重加密但 inner protected/recipients binding 错 | BINDING_FAILED |
| signed flipped signature | SIGNATURE_INVALID |
| signed unknown real signer | SIGNATURE_INVALID |
| signed protected/payload exact segment 改写并真实重加密 | SIGNATURE_INVALID |

所有失败都不得返回 payload 或认证身份。

- [ ] **Step 3: randomness 与 writer/strict regression**

连续两次相同业务输入时，测试必须用同一个目标收件人 private handle 分别结合两条消息的 epk 重新执行 Task 1 派生，得到 `firstTargetRid` 与 `secondTargetRid`；先按内容确认它们各自恰好存在于对应 wire，再断言真实 rid 新鲜。不得用 `Set<byte[]>`，也不得只依靠包含诱饵的全体 rid 集合变化：

~~~java
assertFalse(Arrays.equals(firstEpk, secondEpk));
assertFalse(Arrays.equals(firstIv, secondIv));
assertFalse(Arrays.equals(firstTargetRid, secondTargetRid));
assertFalse(Arrays.equals(firstCiphertext, secondCiphertext));
~~~

JacksonOuterWireWriterTest 增加 8-entry Obfuscation X25519 round-trip，逐 entry 比较 rid/encryptedKey/ek。

OuterWireCanonicalBase64UrlTest 增加：

- non-canonical protected.epk.x；
- non-canonical recipients[0].rid；
- padded、非法 alphabet 对应字段。

OuterWireParserTest 显式回归：

- wrong/missing epk kty/crv/x；
- obfuscation protected 多 kid；
- X25519 recipient 多 ek；
- rid 15/17 bytes；
- encryptedKey 39/41 bytes；
- bucket 7/9/15/17/31/33；
- unknown/missing/type/conditional/canonical 错误及既有优先级。

生产 parser 已有行为时只加测试，不改生产 parser。

Writer/parser 当前基础设施可能让本 Step 新增测试首次运行即通过；若实际 first-run GREEN，必须如实记录“已有行为被新增回归测试封板”，不得人为破坏生产代码或伪造 RED。只有测试暴露真实缺口时才进入对应 RED → 最小生产修复 → GREEN。

- [ ] **Step 4: 运行 focused 阶段六组合矩阵**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am "-Dtest=ObfuscationX25519UnsignedMultiRecipientE2ETest,ObfuscationX25519SignedMultiRecipientE2ETest,ObfuscationX25519TamperE2ETest,ObfuscationX25519RandomnessE2ETest,PublicX25519UnsignedMultiRecipientE2ETest,PublicX25519SignedMultiRecipientE2ETest,PublicHybridUnsignedMultiRecipientE2ETest,PublicHybridSignedMultiRecipientE2ETest,JacksonOuterWireWriterTest,OuterWireCanonicalBase64UrlTest,OuterWireParserTest" "-Dsurefire.failIfNoSpecifiedTests=false" test
~~~

Expected: exit 0；obfuscation 两组合和 public 四组合全部真实 wire 回归通过。

- [ ] **Step 5: module 与 full reactor gate**

~~~powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-protocol -am test
mvn -q clean test
git -c safe.directory=* diff --check
~~~

Expected:

- 全部命令 exit 0；
- full reactor tests 不少于阶段开始的 513；
- 0 failure、0 error、0 skipped；
- 没有新增 @Disabled；
- docs/README.md 内容 diff 仍为空、未暂存、未提交；
- 实际变更只属于 Phase 4；
- public X25519/Hybrid × unsigned/signed 四组合无回归。

- [ ] **Step 6: final spec review 与 code/security review**

Spec review 逐项核对正式协议开发修订、Phase 4 设计和本计划。Code/security review 检查：

- per-message ephemeral key freshness；
- rid/KEK 同一 shared secret；
- bucket/decoy indistinguishability 和 shuffle-before-auth；
- full Cartesian scan、constant-time comparator、tie-break、no-fallback；
- attacker/local error separation；
- AAD、GCM、binding、signature 门序；
- sensitive arrays 与 borrowed handles；
- E2E 不含 mock core chain。

所有 Critical/Important/P0/P1 修复并复审后才能封板。

- [ ] **Step 7: 写完成证据与 P2 register**

在本计划记录每个闭环 commit、focused/module/full test counts、review 结论、两组合真实能力和全部 Deferred P2。更新 overall plan 为 Phase 4 完成，把下一候选指向 Phase 5 Obfuscation Hybrid，但停止开发等待用户确认。

- [ ] **Step 8: 提交阶段封板**

~~~text
test(protocol): close obfuscation x25519 phase
~~~

## 10. P0/P1 completion checklist

- [ ] 同一消息只有一个新 X25519 epk，跨消息不复用。
- [ ] 同一次 SS_ECC 派生 exact rid/ecc 与 KEK 参数。
- [ ] 真实 recipient 都能 unwrap 同一 CEK。
- [ ] 1/8/9/16/17/32 正确映射 8/8/16/16/32/32。
- [ ] 诱饵与真实 X25519 entry wire 长度一致、无 ek。
- [ ] 全部 rid 唯一；真实冲突拒绝，诱饵最多重采样 128 次。
- [ ] final shuffle 在 AAD/binding/signature/GCM 前完成。
- [ ] Receiver 拒绝 duplicate wire rid 和 duplicate local key。
- [ ] 每个 local key 只 derive 一次，并比较全部 local × wire 组合。
- [ ] 多命中按 (wire index, local input index) 选择。
- [ ] selected unwrap 失败不 fallback。
- [ ] empty/unrelated local keys 只有完整扫描后 NOT_FOR_ME。
- [ ] attacker-controlled agreement/unwrap failure 具有相同 code/message/null cause。
- [ ] X25519 handle/public-key、HKDF contract 与 unwrap 非 CryptoOperationException runtime failure 为 INTERNAL_ERROR 并保留存在的本地 cause；selected unwrap 的 CryptoOperationException/null/错误长度按冻结合同统一为 KEY_UNWRAP_FAILED。
- [ ] unsigned 完全跳过 Ed25519。
- [ ] signed 只在 binding 后解析可信 signer 并验 exact segments。
- [ ] 任意失败不返回 payload/identity。
- [ ] ephemeral handle、shared secret、rid、KEK、CEK、inner、GCM AAD 和签名临时数组按 ownership 清理。
- [ ] borrowed X25519/Ed25519 handles 不关闭。
- [ ] Obfuscation X25519 signed/unsigned 真实 wire E2E、tamper、randomness、strict matrix 全绿。
- [ ] public 四组合、JDK 17 full reactor、reviews 和 diff gate 全绿。
- [ ] 没有开放 P0/P1。

## 11. Deferred P2 register

以下事项默认不阻塞 Phase 4，但阶段报告必须保留影响和建议：

1. ObfuscationX25519KeyDeriver 与 PublicX25519KekDeriver 有少量 X25519/KEK 重复；影响是维护重复，不影响当前协议，完整 Demo 后再统一。
2. API EncryptRequest 仍要求 sender encryption identity；影响是 Phase 6 不能直接映射 obfuscation per-message epk，Phase 6 接线时修正 DTO/mapper。
3. protocol 内部细分错误与正式协议公开 InvalidMessage 尚未统一；影响是直接暴露内部错误可能形成 oracle，Phase 6 API/投递边界必须统一映射。
4. Phase 5 Hybrid 需要逐 entry ML-KEM decapsulation、rid/hybrid 和 1088-byte decoy ek；本阶段不提前抽象通用 padding/router。
5. 四个 obfuscation flow 与四个 public flow 会有编排和错误 helper 重复；当前允许局部重复，八组合 Demo 完成后再评估抽取。
6. UnsignedInnerCodec/SignedInnerCodec 在失败前可能已物化不可销毁的 ProtocolPayload 或 immutable Base64URL string；当前清理原始 decrypted inner 和 mutable signing arrays，统一可销毁 payload 模型留到 Demo 后。
7. package-private recording rid comparator 是验证完整扫描的测试 seam；它不进入公开 API，后续若抽取通用 router 再评估是否保留。
8. 不用耗时统计证明 constant-time，也不做 shuffle/randomness 的统计分布或 benchmark；本阶段以固定长度 MessageDigest.isEqual、完整比较计数、真实新鲜性和 code review 为门禁，统计验证留到 Demo 后。
9. Task 1 测试尚不能杀死“删除 HKDF `info.clone()`”的 future mutant；当前生产实现确实对两个 static info 做防御性复制，不影响运行正确性。影响是未来 provider 防御回归可能漏测；Demo 后在同一测试连续 derive 两轮并断言第二轮 context 完整。
10. Task 1 防御性复制测试有两处把 `material.rid()`/`material.kek()` 临时副本直接交给断言，测试无法随后显式清零。内容是固定测试数据且不影响生产安全；后续测试 hardening 应保存为局部变量并在 finally 清理。

执行期间新增 P2 必须追加编号、写清影响与建议；不得用 P2 名义推迟协议、密码学、认证正确性问题。
