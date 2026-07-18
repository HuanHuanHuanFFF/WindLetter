# WindLetter Phase 3 Public Hybrid Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成 `public × X25519ML-KEM-768 × unsigned/signed` 的真实多收件人 Sender、Receiver、wire 和对抗测试，并保持阶段 1/2 全部能力回归通过。

**Architecture:** 保留现有 X25519-only flow 不动，新增 Hybrid 专用 key-id、KEK deriver、recipient builder、paired router 和四个 flow。ML-KEM kid 固定为原始 1184 字节公钥的 SHA-256；每个 recipient 独立 encapsulate；Receiver 只按完整 X25519/ML-KEM kid pair 路由。先关闭 ML-KEM secret ownership，再依次接通 KDF、recipient、unsigned、signed 和完整 E2E。

**Tech Stack:** Java 17、Maven reactor、Bouncy Castle 1.83、Jackson、RFC 8785 JCS、JUnit 5。

---

## 1. 执行基线与约束

计划编写时的已验证基线：

- 分支：`spike/demo-v0`
- 协议修订提交：`de54e12`
- Phase 3 设计提交：`99455b4`
- JDK：`C:\Users\幻\.jdks\ms-17.0.16`
- `mvn -q test`：44 suites、435 tests、0 failure、0 error、0 skipped
- 工作区仅有用户既存的 `docs/README.md` 行尾状态噪音，所有阶段 3 提交必须排除该文件

执行规则：

- 每项生产行为都先写测试并观察预期 RED，再写最小实现；
- 一个 task 是一个可独立验证的闭环，对应一个提交；
- 每项先做 spec review，再做 code/security review；Critical/Important/P0/P1 必须修复并复审；
- 不并行修改共享源码；
- 不自动 push；
- 不新增错误码，不重排 `ErrorCode`；
- 不用 mock 替代真实 X25519、ML-KEM、HKDF、A256KW、GCM 或 Ed25519 E2E；
- tracking/failing provider 只用于 provider contract、门序、清零和 borrowed-handle ownership 测试。

## 2. 文件结构

### 2.1 修改

- `windletter-crypto/src/main/java/com/windletter/crypto/api/MLKem768Encapsulation.java`
  - 保持 record，增加显式 shared-secret 销毁能力。
- `windletter-crypto/src/main/java/com/windletter/crypto/bc/BouncyCastleMLKem768Crypto.java`
  - 清零 encapsulation 临时数组。
- `windletter-crypto/src/test/java/com/windletter/crypto/bc/BouncyCastleMLKem768CryptoTest.java`
  - 所有 encapsulation result 使用 try-with-resources。
- `windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireParserTest.java`
  - 补齐 Hybrid/X25519 条件字段回归。
- `docs/dev/01-demo-first-overall-implementation-plan.md`
  - 阶段封板后写入结果。
- 本计划文档
  - 每个 task 完成后勾选并记录验证证据。

### 2.2 新增 crypto/key

- `windletter-crypto/src/test/java/com/windletter/crypto/api/MLKem768EncapsulationTest.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/key/MLKem768KeyId.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/key/MLKem768KeyIdTest.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/key/PublicHybridKekDeriver.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/key/PublicHybridKekDeriverTest.java`

### 2.3 新增 recipient/routing

- `windletter-protocol/src/main/java/com/windletter/protocol/recipient/PublicHybridRecipientKeys.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/recipient/PublicHybridRecipientBuilder.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/recipient/PublicHybridRecipientBuilderTest.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/routing/PublicHybridRecipientPrivateKeys.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/routing/PublicHybridKidRouter.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/routing/PublicHybridKidRouterTest.java`

### 2.4 新增 flow

- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridUnsignedSender.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridUnsignedReceiver.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedSenderTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedReceiverTest.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridSignedSender.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridSignedReceiver.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedSenderTest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedReceiverTest.java`

### 2.5 新增阶段封板测试

- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridFlowTestFixtures.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedMultiRecipientE2ETest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedMultiRecipientE2ETest.java`
- `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridTamperE2ETest.java`

## 3. Task 1：ML-KEM encapsulation secret 生命周期

**Files:**

- Modify: `windletter-crypto/src/main/java/com/windletter/crypto/api/MLKem768Encapsulation.java`
- Modify: `windletter-crypto/src/main/java/com/windletter/crypto/bc/BouncyCastleMLKem768Crypto.java`
- Modify: `windletter-crypto/src/test/java/com/windletter/crypto/bc/BouncyCastleMLKem768CryptoTest.java`
- Create: `windletter-crypto/src/test/java/com/windletter/crypto/api/MLKem768EncapsulationTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录 RED/GREEN/review/commit）

- [x] **Step 1: 写 owned-result RED**

测试必须包含：

```java
@Test
void closeClearsSecretAndPreservesCiphertext() {
    byte[] ciphertext = filled(MLKem768Encapsulation.CIPHERTEXT_LEN, (byte) 0x31);
    byte[] secret = filled(MLKem768Encapsulation.SHARED_SECRET_LEN, (byte) 0x52);
    MLKem768Encapsulation result = new MLKem768Encapsulation(ciphertext, secret);

    result.close();
    result.close();

    assertArrayEquals(new byte[MLKem768Encapsulation.SHARED_SECRET_LEN], result.sharedSecret());
    assertArrayEquals(ciphertext, result.ciphertext());
}

@Test
void constructorAndAccessorsDefensivelyCopy() {
    byte[] ciphertext = filled(1088, (byte) 1);
    byte[] secret = filled(32, (byte) 2);
    try (MLKem768Encapsulation result = new MLKem768Encapsulation(ciphertext, secret)) {
        ciphertext[0] = 9;
        secret[0] = 9;
        byte[] firstCiphertext = result.ciphertext();
        byte[] firstSecret = result.sharedSecret();
        firstCiphertext[0] = 8;
        firstSecret[0] = 8;
        assertEquals(1, result.ciphertext()[0]);
        assertEquals(2, result.sharedSecret()[0]);
    }
}

private static byte[] filled(int length, byte value) {
    byte[] result = new byte[length];
    Arrays.fill(result, value);
    return result;
}
```

- [x] **Step 2: 运行 RED**

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-crypto -am -Dtest=MLKem768EncapsulationTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是 `MLKem768Encapsulation` 尚未实现 `AutoCloseable.close()`。

2026-07-18 RED 证据：使用指定 JDK 17 执行上述测试（PowerShell 中对两个 `-D` 参数加引号），exit 1；`testCompile` 仅报告测试第 20、32、34 行找不到 `MLKem768Encapsulation.close()`，与预期一致。首次未加引号的 PowerShell 调用被 Maven 参数解析直接拒绝，未计作 RED 证据。

- [x] **Step 3: 写最小 GREEN**

```java
public record MLKem768Encapsulation(byte[] ciphertext, byte[] sharedSecret)
        implements AutoCloseable {
    // 保留现有长度校验、构造 defensive copy 和 accessor defensive copy。

    @Override
    public void close() {
        Arrays.fill(sharedSecret, (byte) 0);
    }
}
```

`BouncyCastleMLKem768Crypto.encapsulate` 使用这一生命周期：

```java
SecretWithEncapsulation providerResult = null;
byte[] ciphertext = null;
byte[] sharedSecret = null;
try {
    providerResult = generator.generateEncapsulated(publicKeyParameter);
    ciphertext = providerResult.getEncapsulation();
    sharedSecret = providerResult.getSecret();
    return new MLKem768Encapsulation(ciphertext, sharedSecret);
} finally {
    if (sharedSecret != null) Arrays.fill(sharedSecret, (byte) 0);
    if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
    destroyQuietly(providerResult);
}
```

已有 BC tests 中每个 result 改为 try-with-resources，避免测试本身遗留真实 KEM secret。

- [x] **Step 4: 运行 GREEN 与 crypto 回归**

```powershell
mvn -q -pl windletter-crypto -am -Dtest=MLKem768EncapsulationTest,BouncyCastleMLKem768CryptoTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0；官方 CCTV vector、round-trip、tampered ciphertext、closed/foreign handle 测试全绿。

2026-07-18 GREEN 证据：

- 指定 JDK 17 focused 命令 exit 0：`MLKem768EncapsulationTest` 4 tests、`BouncyCastleMLKem768CryptoTest` 9 tests，共 13 tests，0 failures/errors/skipped。
- `mvn -q -pl windletter-crypto -am test` exit 0：`windletter-crypto` 共 55 tests，0 failures/errors/skipped；官方 CCTV vector、round-trip、tampered ciphertext、closed/foreign handle 均通过。
- `MLKem768Encapsulation` 保留长度/null 校验与构造器/accessor defensive copy；`close()` 幂等清零内部 shared secret，ciphertext 保持可用且不变。
- `BouncyCastleMLKem768Crypto.encapsulate` 在 `finally` 清零 provider 返回的 secret/ciphertext 临时数组并 best-effort destroy provider holder；BC tests 对 encapsulation result 使用 try-with-resources，并清零显式 test-local secret。

- [x] **Step 5: spec review、quality/security review、提交**

检查内部 secret 确实被清零、ciphertext 未被破坏、provider 临时 secret 在异常路径也清零。

2026-07-18 review 证据：

- 独立 spec review：Critical 0、Important 0、Minor/P2 0，批准进入 code/security review；
- 独立 code/security review：Critical 0、Important 0，批准最终验证与单闭环提交；
- 主任务重新运行 focused tests 与 `windletter-crypto` 全模块，分别 exit 0；模块结果为 8 suites、55 tests、0 failures/errors/skipped；
- 本闭环提交信息固定为 `fix(crypto): destroy ML-KEM encapsulation secrets`，实际 hash 由提交后的 `git log` 记录；
- 非阻塞 P2 已登记到 §12：测试异常路径的 secret 副本 cleanup 范围，以及 provider 临时数组/destroy 的直接 instrumentation 覆盖。

```text
fix(crypto): destroy ML-KEM encapsulation secrets
```

## 4. Task 2：ML-KEM raw-public-key kid

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/key/MLKem768KeyId.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/key/MLKem768KeyIdTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

- [x] **Step 1: 写固定向量 RED**

```java
@Test
void derivesSha256OfRaw1184BytePublicKey() {
    byte[] publicKey = new byte[1184];
    for (int i = 0; i < publicKey.length; i++) {
        publicKey[i] = (byte) (i & 0xff);
    }

    assertEquals(
            "7NTPOwdCAmuWvE0fGJTJZ5R3RxDExM43huxxjF4IzVc",
            MLKem768KeyId.derive(publicKey)
    );
}

@Test
void rejectsAnythingExceptRaw1184Bytes() {
    assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(null));
    assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(new byte[1183]));
    assertThrows(IllegalArgumentException.class, () -> MLKem768KeyId.derive(new byte[1185]));
}
```

同时断言输出为 43 个 canonical Base64URL 字符且不含 `=`。

2026-07-18 test-first 证据：新增 `MLKem768KeyIdTest`，固定锁定 1184 字节递增 raw public key 的预计算 kid；同时覆盖 null、1183/1185 字节拒绝、43 字符 canonical Base64URL、无 `=` 以及输入数组不被修改。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=MLKem768KeyIdTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是 `MLKem768KeyId` 不存在。

2026-07-18 RED 证据：使用指定 JDK 17 执行上述命令（PowerShell 中对两个 `-D` 参数加引号），exit 1；`testCompile` 仅在测试第 21、32、33、34 行报告找不到 `MLKem768KeyId`，与预期一致。

- [x] **Step 3: 实现固定公式**

```java
public final class MLKem768KeyId {
    private static final int PUBLIC_KEY_LENGTH = 1184;

    private MLKem768KeyId() {
    }

    public static String derive(byte[] rawPublicKey) {
        if (rawPublicKey == null || rawPublicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("rawPublicKey must contain exactly 1184 bytes");
        }
        try {
            return Base64Url.encode(
                    MessageDigest.getInstance("SHA-256").digest(rawPublicKey)
            );
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }
}
```

不得使用 JWK、JCS、DER、SPKI、算法名或长度前缀。

2026-07-18 GREEN 实现：`MLKem768KeyId` 是 `public final` utility class，仅接受 1184 字节 raw public key，直接计算 `SHA-256(rawPublicKey)` 并调用现有 `Base64Url.encode`；未引入 JWK/JCS/DER/PEM/SPKI 或任何前缀，且不修改输入数组。SHA-256 不可用时抛出带 cause 的 `IllegalStateException("SHA-256 is unavailable")`。

- [x] **Step 4: 运行 GREEN 与现有 kid 回归**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=MLKem768KeyIdTest,X25519KeyIdTest,Ed25519KeyIdTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0，三个算法的 key-id tests 全绿。

2026-07-18 GREEN 证据：

- 指定 JDK 17 focused 命令 exit 0：`MLKem768KeyIdTest`、`X25519KeyIdTest`、`Ed25519KeyIdTest` 各 2 tests，共 6 tests，0 failures/errors/skipped。
- `mvn -q -pl windletter-protocol -am test` exit 0：`windletter-protocol` 26 suites / 347 tests；连同 `windletter-core` 1 test、`windletter-crypto` 55 tests，共 403 tests，0 failures/errors/skipped。

- [x] **Step 5: review、提交**

2026-07-18 review/verification 证据：

- 独立 spec review：Critical 0、Important 0、Minor/P2 0；固定向量经独立计算一致，批准进入 code/quality review；
- 独立 code/quality/security review：Critical 0、Important 0、Minor/P2 0，批准最终验证与单闭环提交；
- 主任务重新运行 focused key-id tests：6 tests、0 failures/errors/skipped；重新运行 protocol 及依赖模块：35 suites / 403 tests、0 failures/errors/skipped；
- `git diff --check` 通过，Task 3 无 diff，`docs/README.md` 未产生内容 diff且不纳入提交；
- 本闭环提交信息固定为 `feat(protocol): derive ML-KEM key identifiers`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): derive ML-KEM key identifiers
```

## 5. Task 3：Hybrid combiner 与双向 KEK

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/key/PublicHybridKekDeriver.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/key/PublicHybridKekDeriverTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

### 5.1 Required API

```java
public final class PublicHybridKekDeriver {
    public PublicHybridKekDeriver(
            X25519Crypto x25519,
            MLKem768Crypto mlkem768,
            HkdfCrypto hkdf
    );

    public SenderDerivation deriveForSender(
            X25519PrivateKeyHandle senderX25519PrivateKey,
            byte[] recipientX25519PublicKey,
            byte[] recipientMlkem768PublicKey
    );

    public byte[] deriveForReceiver(
            X25519PrivateKeyHandle recipientX25519PrivateKey,
            byte[] senderX25519PublicKey,
            MLKem768PrivateKeyHandle recipientMlkem768PrivateKey,
            byte[] encapsulationCiphertext
    );

    static byte[] deriveCombined(HkdfCrypto hkdf, byte[] ssEcc, byte[] ssPq);

    public record SenderDerivation(byte[] kek, byte[] encapsulationCiphertext)
            implements AutoCloseable {
        // 构造/accessor defensive copy；close 只清零内部 KEK。
    }
}
```

- [x] **Step 1: 写 combiner 固定向量 RED**

```java
@Test
void combinesEccBeforePqWithExactHybridInfo() {
    byte[] ssEcc = sequence(0x00, 32);
    byte[] ssPq = sequence(0x20, 32);

    byte[] kek = PublicHybridKekDeriver.deriveCombined(
            new BouncyCastleHkdfCrypto(), ssEcc, ssPq
    );

    assertArrayEquals(
            HexFormat.of().parseHex(
                    "42299fcde7930ae6fc402785a0c231f37886973394e7123f3e5bf58f3406209c"
            ),
            kek
    );
}

private static byte[] sequence(int start, int length) {
    byte[] result = new byte[length];
    for (int i = 0; i < length; i++) {
        result[i] = (byte) (start + i);
    }
    return result;
}
```

另写长度、null、HKDF null/错误长度/异常、输出 defensive copy 和 `SenderDerivation.close()` 清零测试。

2026-07-18 test-first 证据：先只写 exact combiner 固定向量并观察类不存在 RED；最小 combiner GREEN 后，再扩展真实 BC 双向、完整 public API、provider contract、all-zero X25519、数组清零、borrowed handles 与 `SenderDerivation` lifecycle 测试，并在完整 API 实现前再次观察编译 RED。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridKekDeriverTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是 Hybrid deriver 不存在。

2026-07-18 RED 证据：

- 首轮 fixed-vector RED 使用指定 JDK 17，focused Maven exit 1，唯一原因是 `PublicHybridKekDeriver` 不存在；
- 扩展行为 RED exit 1，编译错误只来自 constructor、`deriveForSender`、`deriveForReceiver` 和 `SenderDerivation` 尚不存在，固定向量 combiner 已经 GREEN。

- [x] **Step 3: 实现 combiner 和 sender/receiver**

核心 combiner 必须是：

```java
byte[] z = new byte[64];
System.arraycopy(ssEcc, 0, z, 0, 32);
System.arraycopy(ssPq, 0, z, 32, 32);
try {
    byte[] kek = hkdf.derive(
            "wind".getBytes(StandardCharsets.UTF_8),
            z,
            "WindLetter v1 KEK | X25519ML-KEM-768".getBytes(StandardCharsets.UTF_8),
            32
    );
    if (kek == null || kek.length != 32) {
        if (kek != null) {
            Arrays.fill(kek, (byte) 0);
        }
        throw new IllegalStateException("HKDF provider returned a non-32-byte KEK");
    }
    return kek;
} catch (CryptoOperationException e) {
    throw new IllegalStateException("HKDF provider failed", e);
} finally {
    Arrays.fill(z, (byte) 0);
}
```

Sender 使用 try-with-resources 读取 `MLKem768Encapsulation`；Receiver 使用 matched ML-KEM handle decapsulate。双方在 finally 清零 X25519/PQ secrets，校验所有 provider 返回长度，不关闭 borrowed handles。

2026-07-18 GREEN 实现：新增计划规定的 constructor、sender/receiver 双向 API、package-private combiner 与 owned `SenderDerivation`。实现严格使用 `SS_ECC || SS_PQ`、固定 salt/info/L；校验所有输入和 provider output；拒绝 all-zero X25519；sender 关闭 encapsulation result；成功/失败均清零 X/PQ secrets、组合 Z、sender 临时 KEK 和 ciphertext snapshot；borrowed handles 保持可用。

- [x] **Step 4: 加入真实 BC 双向测试并运行 GREEN**

```java
try (X25519PrivateKeyHandle sender = x25519.generatePrivateKey();
     X25519PrivateKeyHandle recipientX = x25519.generatePrivateKey();
     MLKem768PrivateKeyHandle recipientPq = mlkem.generatePrivateKey();
     PublicHybridKekDeriver.SenderDerivation senderResult =
             deriver.deriveForSender(sender, recipientX.publicKey(), recipientPq.publicKey())) {
    byte[] receiverKek = deriver.deriveForReceiver(
            recipientX, sender.publicKey(), recipientPq,
            senderResult.encapsulationCiphertext()
    );
    assertArrayEquals(senderResult.kek(), receiverKek);
    Arrays.fill(receiverKek, (byte) 0);
}
```

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridKekDeriverTest,PublicX25519KekDeriverTest,BouncyCastleMLKem768CryptoTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0；固定向量和真实双向 KEK 一致。

2026-07-18 GREEN 证据：

- 指定 JDK 17 focused matrix exit 0：`PublicHybridKekDeriverTest` 9、`PublicX25519KekDeriverTest` 8、`BouncyCastleMLKem768CryptoTest` 9，共 26 tests，0 failures/errors/skipped；
- `mvn -q -pl windletter-protocol -am test` exit 0：protocol 27 suites / 356 tests；连同 core/crypto 共 36 suites / 412 tests，0 failures/errors/skipped；
- `git diff --check` 通过，Task 4 无 diff，`docs/README.md` 仍无内容 diff且不纳入提交。

- [x] **Step 5: review、提交**

重点检查 `SS_ECC`、`SS_PQ`、`Z`、KEK 的成功/失败清零以及 borrowed-handle ownership。

2026-07-18 review/verification 证据：

- 独立 spec review：Critical 0、Important 0；指出 sender closure 应字面使用 try-with-resources，已修正并复跑 9 tests 全绿；
- 独立 code/security review：Critical 0、Important 0、Minor 0，批准最终验证与单闭环提交；
- review 确认 provider alias/output ownership、all-zero X25519、HKDF cause、错误 output 清零、sender/receiver KEK ownership、record lifecycle 与 borrowed handles 均正确；
- 两项非阻塞测试增强已登记到 §12，不阻塞 Demo；
- 本闭环提交信息固定为 `feat(protocol): derive public hybrid KEKs`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): derive public hybrid KEKs
```

## 6. Task 4：Hybrid recipient builder

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/recipient/PublicHybridRecipientKeys.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/recipient/PublicHybridRecipientBuilder.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/recipient/PublicHybridRecipientBuilderTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

### 6.1 Required API

```java
public record PublicHybridRecipientKeys(
        byte[] x25519PublicKey,
        byte[] mlkem768PublicKey
) {
    // 32/1184-byte validation and defensive accessors.
}

public final class PublicHybridRecipientBuilder {
    public PublicHybridRecipientBuilder(
            PublicHybridKekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap
    );

    public List<PublicRecipient> build(
            X25519PrivateKeyHandle senderKey,
            List<PublicHybridRecipientKeys> recipients,
            byte[] cek
    );
}
```

- [x] **Step 1: 写真实两收件人 RED**

测试生成一个 sender 和两个不同 X25519/ML-KEM recipient pairs，调用 builder 后断言：

```java
assertEquals(2, entries.size());
assertEquals(X25519KeyId.derive(x1.publicKey()), entries.get(0).kid().x25519());
assertEquals(MLKem768KeyId.derive(pq1.publicKey()), entries.get(0).kid().mlkem768());
assertEquals(1088, entries.get(0).ek().length);
assertEquals(40, entries.get(0).encryptedKey().length);
assertFalse(Arrays.equals(entries.get(0).ek(), entries.get(1).ek()));
```

每个 recipient 使用自己的 private pair 调用 `deriveForReceiver` 并 unwrap，必须恢复同一 32-byte CEK。

另覆盖 null、0/33 recipients、32/1184 长度、重复完整 pair、defensive copy、provider 错误长度和 KEK/CEK snapshot 清零。

2026-07-18 RED 测试范围：新增真实 BC 两收件人 round-trip，锁定双 kid、独立 1088-byte `ek`、40-byte wrapped CEK 以及两组接收方私钥各自恢复同一 CEK；随后补齐 keys defensive copy/长度、全量 pair pre-validation、完整二元组重复、same-component/different-pair、1..32/顺序/immutable、wrap throws/null/39 与临时数组清零。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridRecipientBuilderTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是 recipient keys/builder 不存在。

2026-07-18 RED 证据：指定 JDK 17 focused 命令 exit 1，编译失败仅因为 `PublicHybridRecipientBuilder` 与 `PublicHybridRecipientKeys` 尚不存在。首轮实现后真实测试还捕获了一次 snapshot ownership 错误（转入 spec 的 raw key 被提前清零，触发 X25519 low-order），经所有权 clone 修正后进入 GREEN。

- [x] **Step 3: 实现每收件人独立 encapsulation**

```java
for (PublicHybridRecipientKeys keys : validatedSnapshots) {
    String xKid = X25519KeyId.derive(keys.x25519PublicKey());
    String pqKid = MLKem768KeyId.derive(keys.mlkem768PublicKey());
    try (PublicHybridKekDeriver.SenderDerivation derived =
                 kekDeriver.deriveForSender(
                         senderKey,
                         keys.x25519PublicKey(),
                         keys.mlkem768PublicKey()
                 )) {
        byte[] wrapped = keyWrap.wrap(derived.kek(), cekSnapshot);
        if (wrapped == null || wrapped.length != 40) {
            if (wrapped != null) {
                Arrays.fill(wrapped, (byte) 0);
            }
            throw new IllegalStateException(
                    "A256KW provider returned a non-40-byte wrapped CEK"
            );
        }
        result.add(new PublicRecipient(
                new RecipientKid(xKid, pqKid),
                wrapped,
                derived.encapsulationCiphertext()
        ));
    }
}
```

在任何 crypto 调用前完成全部 pair 验证和重复 pair 检查。重复检测使用派生 kid 二元组，不依赖 byte-array record equality。

2026-07-18 GREEN 实现：`PublicHybridRecipientKeys` 严格校验 32/1184 字节并在构造/accessor defensive copy；builder 在任何 agreement/encapsulation/wrap 前完成 1..32、null、CEK 和全部 pair snapshot/二元 kid 重复检查。每个收件人独立调用 `deriveForSender`，显式持有并 finally 清零 KEK、`ek`、wrapped output 与 CEK snapshot，`SenderDerivation` 使用 try-with-resources；结果保持输入顺序并通过 `List.copyOf` 返回，借用 sender handle 不关闭。

- [x] **Step 4: 运行 GREEN 与 X25519 builder 回归**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridRecipientBuilderTest,PublicHybridKekDeriverTest,PublicX25519RecipientBuilderTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0。

2026-07-18 GREEN 证据：

- 指定 JDK 17 focused matrix exit 0：`PublicHybridRecipientBuilderTest` 7、`PublicHybridKekDeriverTest` 9、`PublicX25519RecipientBuilderTest` 8，共 24 tests，0 failures/errors/skipped；
- `mvn -q -pl windletter-protocol -am test` exit 0：core 1 suite / 1 test、crypto 8 suites / 55 tests、protocol 28 suites / 363 tests，合计 37 suites / 419 tests，0 failures/errors/skipped。

- [x] **Step 5: review、提交**

2026-07-18 review/verification 证据：

- 独立 spec review：Critical 0、Important 0、Minor 0、P2 0，批准进入 code/security review；
- 独立 code/security review：Critical 0、Important 0、Minor 0，批准最终验证与单闭环提交；
- review 确认全 pair pre-validation、二元 kid 去重、逐 recipient 独立 encapsulation、array ownership、wrap failure cleanup、immutable result 与 borrowed sender 均正确；
- 主任务重新运行 focused matrix：24 tests 全绿；protocol 及依赖模块：37 suites / 419 tests、0 failures/errors/skipped；
- 三项非阻塞维护/测试 P2 已登记到 §12，不阻塞 Demo；
- 本闭环提交信息固定为 `feat(protocol): build public hybrid recipients`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): build public hybrid recipients
```

## 7. Task 5：Hybrid paired kid routing

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/routing/PublicHybridRecipientPrivateKeys.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/routing/PublicHybridKidRouter.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/routing/PublicHybridKidRouterTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

### 7.1 Required API

```java
public record PublicHybridRecipientPrivateKeys(
        X25519PrivateKeyHandle x25519PrivateKey,
        MLKem768PrivateKeyHandle mlkem768PrivateKey
) {
    // Borrowed handles; record is not AutoCloseable.
}

public final class PublicHybridKidRouter {
    public Match route(
            List<RecipientEntry> recipients,
            List<PublicHybridRecipientPrivateKeys> privateKeys
    );

    public record Match(
            PublicRecipient recipient,
            X25519PrivateKeyHandle x25519PrivateKey,
            MLKem768PrivateKeyHandle mlkem768PrivateKey
    ) {
    }
}
```

- [x] **Step 1: 写 pair-only RED**

至少覆盖：

```java
assertSame(firstWireEntry, router.route(wireEntries, List.of(firstPair)).recipient());
assertEquals(
        ErrorCode.NOT_FOR_ME,
        assertThrows(ProtocolException.class,
                () -> router.route(wireEntries, List.of(unrelatedPair))).errorCode()
);
```

并单独测试：

- X kid 命中但 PQ kid 不命中；
- PQ kid 命中但 X kid 不命中；
- X/PQ 分别来自两个本地 pair 的交叉错配；
- 重复本地完整 pair → `INVALID_FIELD`；
- 不可信 wire 重复完整 pair/结构问题 → `INVALID_FIELD`；
- 多个不同 pair 命中时选择 wire 顺序第一个，但必须完成扫描后才返回；
- 本地 handle public-key accessor 抛异常、返回 null 或返回错误长度 → `INTERNAL_ERROR`；
- borrowed handles 在成功和失败后仍可使用。

2026-07-18 RED 测试范围：先锁定完整 X25519/ML-KEM kid pair 才能路由、unrelated pair 为 `NOT_FOR_ME`；随后补齐首/中/尾、X-only/PQ-only/cross mismatch、重复 local/matching wire、unrelated duplicate、多个 distinct match 后继续扫描、X/PQ accessor contract failure、snapshot 清零与 borrowed/record/Match invariants。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridKidRouterTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是 private-pair/router 不存在。

2026-07-18 RED 证据：指定 JDK 17 focused 命令 exit 1，编译失败仅因为 `PublicHybridRecipientPrivateKeys` 与 `PublicHybridKidRouter` 尚不存在。

- [x] **Step 3: 实现 local-map + wire-first full scan**

```java
Map<KidPair, PublicHybridRecipientPrivateKeys> localByPair = buildValidatedLocalMap(privateKeys);
Match first = null;
Set<KidPair> matchedWirePairs = new HashSet<>();
for (RecipientEntry entry : recipients) {
    if (!(entry instanceof PublicRecipient recipient)) continue;
    KidPair pair = new KidPair(recipient.kid().x25519(), recipient.kid().mlkem768());
    PublicHybridRecipientPrivateKeys local = localByPair.get(pair);
    if (local == null) continue;
    if (!matchedWirePairs.add(pair)) throw invalid("matching hybrid recipient pair is duplicated");
    if (first == null) {
        first = new Match(recipient, local.x25519PrivateKey(), local.mlkem768PrivateKey());
    }
}
if (first == null) throw new ProtocolException(ErrorCode.NOT_FOR_ME, "no hybrid recipient pair matches");
return first;

private record KidPair(String x25519, String mlkem768) {
    private KidPair {
        if (x25519 == null || mlkem768 == null) {
            throw new IllegalArgumentException("hybrid kid pair values must not be null");
        }
    }
}

private static ProtocolException invalid(String message) {
    return new ProtocolException(ErrorCode.INVALID_FIELD, message);
}

private static ProtocolException internal(String message, Throwable cause) {
    return new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
}
```

构建 local map 时从两个 handles 取得公钥、校验 32/1184 bytes、派生两个 kid，并在 finally 清零公钥快照。只在 accessor/本地 key snapshot 校验与 kid 派生边界捕获本地异常，并用 `internal("failed to inspect local hybrid key handles", cause)` 映射；不要把本地产生的 `INTERNAL_ERROR` 再送入 `invalid()`。具有合法 accessor 的 foreign handle 可完成路由，但必须在后续 crypto provider ownership 检查处映射为 `INTERNAL_ERROR`。

2026-07-18 GREEN 实现：private-pair record 仅校验两个 borrowed handles 非 null且不实现 `AutoCloseable`；router 先完整构建本地二元 kid map，重复完整 pair 为 `INVALID_FIELD`，accessor/null/长度/kid 派生失败统一保留 cause 映射 `INTERNAL_ERROR`，并在 finally 清零两个 public snapshots。wire 按原顺序 full scan，仅完整 pair 匹配，缺少 PQ kid 为 `INVALID_FIELD`；只跟踪匹配本地的 wire pair 重复，选择第一个 distinct match但不提前返回，且始终不关闭 handles。

- [x] **Step 4: 运行 GREEN 与现有 router 回归**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridKidRouterTest,PublicKidRouterTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0。

2026-07-18 GREEN 证据：

- 指定 JDK 17 focused matrix exit 0：`PublicHybridKidRouterTest` 7、`PublicKidRouterTest` 6，共 13 tests，0 failures/errors/skipped；
- `mvn -q -pl windletter-protocol -am test` exit 0：core 1 suite / 1 test、crypto 8 suites / 55 tests、protocol 29 suites / 370 tests，合计 38 suites / 426 tests，0 failures/errors/skipped。

- [x] **Step 5: review、提交**

2026-07-18 review/verification 证据：

- 独立 spec review：Critical 0、Important 0、Minor 0；1 项非阻塞测试增强 P2；
- 独立 code/security review：Critical 0、Important 0、Minor 0；2 项非阻塞注释/测试 P2；
- review 确认完整 pair 路由、wire-order full scan、duplicate 规则、`INTERNAL_ERROR` cause、snapshot 清零与 borrowed ownership 均正确；
- 主任务使用指定 JDK 17 重新运行 protocol 及依赖模块：38 suites / 426 tests、0 failures/errors/skipped；
- 三项 P2 已登记到 §12，不阻塞 Demo；
- 本闭环提交信息固定为 `feat(protocol): route public hybrid key pairs`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): route public hybrid key pairs
```

## 8. Task 6：Public Hybrid unsigned 完整收发

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridUnsignedSender.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridUnsignedReceiver.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedSenderTest.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedReceiverTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

### 8.1 Required public shape

```java
public final class PublicHybridUnsignedSender {
    public PublicHybridUnsignedSender(
            PublicHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm
    );

    PublicHybridUnsignedSender(
            PublicHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            SecureRandom secureRandom
    );

    public Result send(Request request);

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            X25519PrivateKeyHandle senderPrivateKey,
            List<PublicHybridRecipientKeys> recipients
    ) {
    }

    public record Result(WindLetter message, String wireJson) {
    }
}

public final class PublicHybridUnsignedReceiver {
    public PublicHybridUnsignedReceiver(
            PublicHybridKekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap,
            A256GcmCrypto gcm
    );

    public Result receive(Request request);

    public record Request(
            String wireJson,
            SenderX25519PublicKeyResolver senderKeys,
            List<PublicHybridRecipientPrivateKeys> recipientPrivateKeys
    ) {
    }

    public record Result(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus
    ) {
    }
}
```

`PublicHybridUnsignedSender.Result` 与现有 unsigned Sender 一致；Receiver Result 为 payload/messageId/timestamp/`UNSIGNED`。

- [x] **Step 1: 写真实 wire round-trip RED**

使用 BC 生成 sender 和两个 Hybrid recipients，payload 必须包含 `0x00`、`0xff` 和非 UTF-8 bytes。只把 Sender 返回的 `wireJson` 交给 Receiver：

```java
PublicHybridUnsignedSender.Result sent = sender.send(request);
PublicHybridUnsignedReceiver.Result received = receiver.receive(
        new PublicHybridUnsignedReceiver.Request(
                sent.wireJson(),
                kid -> Optional.of(senderPublicKey),
                List.of(secondRecipientPrivatePair)
        )
);
assertArrayEquals(payloadBytes, received.payload().data());
assertEquals(ProtocolAuthenticationStatus.UNSIGNED, received.authenticationStatus());
```

2026-07-18 RED 测试范围：使用真实 BC X25519、ML-KEM-768、A256KW、A256GCM 生成 sender 与两个完整 Hybrid recipients；锁定每个 recipient 独立 `ek`、只传递真实 `wireJson`、第二收件人恢复包含 `0x00`、`0xff`、`0xc3 0x28` 非 UTF-8 序列的二进制 payload，并返回 `UNSIGNED`。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridUnsignedSenderTest,PublicHybridUnsignedReceiverTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是两个 unsigned Hybrid flow 不存在。

2026-07-18 RED 证据：指定 JDK 17 focused 命令 exit 1；test compile 失败仅因为 `PublicHybridUnsignedSender` 与 `PublicHybridUnsignedReceiver` 不存在，无其他编译错误。

- [x] **Step 3: 实现 Sender 主链**

```text
validate request
→ generate one 32-byte CEK and 12-byte IV
→ protected: typ=wind+jwe, cty=wind+inner, ver=1.0,
  wind_mode=public, enc=A256GCM, key_alg=X25519ML-KEM-768,
  kid only contains sender X25519 kid
→ builder builds all recipients with independent ek
→ AAD and binding
→ strict unsigned inner
→ real A256GCM
→ real JSON writer
→ finally clear CEK/IV/inner/GCM AAD/public-key snapshots
```

2026-07-18 GREEN Sender 实现：严格校验 UUID v4/timestamp/1..32 完整 recipient pairs 并防御性快照；每封信只生成一个 32-byte CEK 与 12-byte IV，构造精确 public Hybrid protected profile，复用 builder 生成每收件人独立 encapsulation，计算 recipients JCS AAD 与内外 binding，编码 strict unsigned inner 后执行真实 A256GCM 与 outer writer；成功和异常路径均清零 sender public snapshot、CEK、IV、inner 与 GCM AAD，且不关闭 borrowed handles。

- [x] **Step 4: 实现 Receiver 精确门序与泛化 key recovery**

```text
strict parse/profile → AAD → paired route → sender X25519 resolve/kid bind
→ Hybrid deriveForReceiver → A256KW unwrap → GCM → strict unsigned inner
→ binding → UNSIGNED result
```

```java
private static ProtocolException keyRecoveryFailed() {
    return new ProtocolException(
            ErrorCode.KEY_UNWRAP_FAILED,
            "hybrid recipient key recovery failed"
    );
}
```

攻击者输入导致的 X25519/ML-KEM/unwrap failure 使用同一泛化异常且不附 cause。unrelated pair 为 `NOT_FOR_ME` 且不调用 decapsulation。Router 已产生的 `NOT_FOR_ME`、`INVALID_FIELD`、`INTERNAL_ERROR` 原样保留；closed/foreign handle、HKDF/provider null/错误长度等本地/provider contract failure 映射为 `INTERNAL_ERROR`，不得落入 `keyRecoveryFailed()`。

2026-07-18 GREEN Receiver 实现：严格执行 parse/profile → AAD → paired route → sender X25519 resolve/kid bind → Hybrid derive → unwrap → GCM → strict inner → binding；攻击者可控的 X25519 low-order、ML-KEM decapsulation 和 A256KW integrity failure 全部收敛为固定 `KEY_UNWRAP_FAILED` / `hybrid recipient key recovery failed` / null cause，router 协议异常原样透传，本地 handle、HKDF 与 provider contract failure 映射 `INTERNAL_ERROR`；finally 清零 sender public snapshot、KEK、CEK、GCM AAD 与 inner plaintext，不关闭任何 borrowed handle。

- [x] **Step 5: 增加门序、ownership、error RED/GREEN**

覆盖 profile、AAD、unrelated pair、unknown sender、matched-pair wrong `ek`、router accessor contract failure、closed/foreign handle、unwrap null/错误长度、GCM、inner、binding、借用 handles 不关闭、CEK/KEK/inner/GCM AAD 清零；分别锁定 router `INTERNAL_ERROR` 透传与 attacker-controlled key recovery 的 code/message/null cause。

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridUnsignedSenderTest,PublicHybridUnsignedReceiverTest,PublicX25519UnsignedSenderTest,PublicX25519UnsignedReceiverTest,OuterWireParserTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0，旧 X25519 unsigned 回归不变。

2026-07-18 GREEN/回归证据：

- Task 6 新测试：`PublicHybridUnsignedSenderTest` 5、`PublicHybridUnsignedReceiverTest` 14，共 19 tests；覆盖真实两收件人 round-trip、profile/AAD/binding、门序、unrelated pair 零 resolver/零 decapsulation、sender resolver、wrong `ek`/wrapped CEK、统一 key-recovery oracle、router `INTERNAL_ERROR`、closed/foreign handles、provider/HKDF/unwrap contracts、GCM/inner/binding、清零与 borrowed ownership；
- 计划 focused matrix exit 0：Hybrid 19、既有 X25519 unsigned 23、`OuterWireParserTest` 55，共 97 tests，0 failures/errors/skipped；
- `mvn -q -pl windletter-protocol -am test` exit 0：core 1 suite / 1 test、crypto 8 suites / 55 tests、protocol 31 suites / 389 tests，合计 40 suites / 445 tests，0 failures/errors/skipped；
- `git diff --check` exit 0；既存 `docs/README.md` 改动未触碰，未 stage、未 commit、未 push。

- [x] **Step 6: review、提交**

2026-07-18 review/verification 证据：

- 独立 spec review：Critical/P0 0、Important/P1 0、Minor 0；2 项非阻塞 P2；
- 独立 code/security review：Critical 0、Important 0、Minor 0；4 项非阻塞 P2，其中 1 项与 spec review 重合；
- review 确认真实 BC wire 主链、完整 pair 语义、严格门序、三类 key-recovery 统一错误、provider/local contract 分类、owned arrays 清零与 borrowed handles 均正确；
- 主任务使用指定 JDK 17 重新运行 protocol 及依赖模块：40 suites / 445 tests、0 failures/errors/skipped；
- 合并去重后的 5 项 P2 已登记到 §12，不阻塞 Demo；
- 本闭环提交信息固定为 `feat(protocol): add public hybrid unsigned flow`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): add public hybrid unsigned flow
```

## 9. Task 7：Public Hybrid signed 完整收发

**Files:**

- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridSignedSender.java`
- Create: `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicHybridSignedReceiver.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedSenderTest.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedReceiverTest.java`
- Modify: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`（勾选步骤并记录证据）

### 9.1 Required public shape

Signed flow 的完整 public shape：

```java
public final class PublicHybridSignedSender {
    public PublicHybridSignedSender(
            PublicHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    );

    PublicHybridSignedSender(
            PublicHybridRecipientBuilder recipientBuilder,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519,
            SecureRandom secureRandom
    );

    public Result send(Request request);

    public record Request(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            X25519PrivateKeyHandle senderEncryptionPrivateKey,
            Ed25519PrivateKeyHandle senderSigningPrivateKey,
            List<PublicHybridRecipientKeys> recipients
    ) {
    }

    public record Result(WindLetter message, String wireJson) {
    }
}

public final class PublicHybridSignedReceiver {
    public PublicHybridSignedReceiver(
            PublicHybridKekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    );

    public Result receive(Request request);

    public record Request(
            String wireJson,
            SenderX25519PublicKeyResolver senderEncryptionKeys,
            Ed25519VerificationKeyResolver senderSigningKeys,
            List<PublicHybridRecipientPrivateKeys> recipientPrivateKeys
    ) {
    }

    public record Result(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus,
            ProtocolSenderIdentity authenticatedSender
    ) {
    }
}
```

- [x] **Step 1: 写真实 signed round-trip RED**

```java
assertEquals("X25519ML-KEM-768", sent.message().protectedHeader().keyAlg());
assertEquals("wind+jws", sent.message().protectedHeader().cty());
assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID, received.authenticationStatus());
assertEquals("trusted-sender-1", received.authenticatedSender().identityId());
```

测试必须从 wire JSON 接收，trusted resolver 返回与 exact signing kid 绑定的真实 Ed25519 public key。

- [x] **Step 2: 运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridSignedSenderTest,PublicHybridSignedReceiverTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: compilation failure，原因是两个 signed Hybrid flow 不存在。

- [x] **Step 3: 实现 signed Sender**

复用 Task 6 outer 主链，但：

```text
cty=wind+jws
→ derive Ed25519 kid from actual signing public key
→ SignedInnerCodec.prepare
→ sign exact prepared protected_b64 + "." + payload_b64 bytes
→ SignedInnerCodec.assemble
→ GCM
```

所有 private handles 为 borrowed；finally 清零 signing public snapshot、signing input、signature、inner、CEK、IV 和 GCM AAD。

- [x] **Step 4: 实现 signed Receiver**

复用 Task 6 到 binding 为止，然后：

```text
strict SignedInnerCodec.decode
→ binding
→ trusted Ed25519 resolver
→ trusted record kid equality
→ rederive Ed25519 kid from trusted public key
→ verify exact received protected_b64 + "." + payload_b64 bytes
→ SIGNED_VALID + trusted identity
```

未知 signer、错误 key 和 false verification 为 `SIGNATURE_INVALID`；resolver/provider contract failure 为 `INTERNAL_ERROR`；任何失败不返回 payload/identity。

- [x] **Step 5: 加入 gate-order 与回归 tests**

确认 binding 失败发生在 signing resolver 前；unrelated pair 发生在 sender/signing resolver 前；signed flow 原样保留 router 的 `INTERNAL_ERROR`，且 attacker-controlled key-recovery code/message/cause 与 Task 6 相同。

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridSignedSenderTest,PublicHybridSignedReceiverTest,PublicHybridUnsignedSenderTest,PublicHybridUnsignedReceiverTest,PublicX25519SignedSenderTest,PublicX25519SignedReceiverTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0。

Task 7 Step 1-5 实际证据：

- 真实 BC 双收件人 binary round-trip 已覆盖：outer 为 `X25519ML-KEM-768` / `wind+jws`，Receiver 从 wire JSON 定位第二个完整 key pair，恢复原 payload，并只在验签成功后返回 `SIGNED_VALID` 与 trusted identity；
- RED 使用指定 JDK 17 运行两个新测试类，编译按预期失败，唯一原因是 `PublicHybridSignedSender` / `PublicHybridSignedReceiver` 尚不存在；
- Sender 已实现 actual borrowed Ed25519 handle 公钥重派生 kid、`SignedInnerCodec.prepare`、exact prepared signing input 签名、64-byte signature contract、assemble、GCM 与 strict outer writer，并在所有路径清零 owned public snapshots、CEK、IV、signing input、signature、inner 和 AAD；
- Receiver 已实现 strict profile/AAD、完整 pair routing、sender X25519 resolve/kid bind、Hybrid derive/unwrap、GCM、strict signed inner decode、binding、trusted signing record 双重 kid 校验、exact received segments 验签；attacker-controlled derive/decap/unwrap 失败继续统一为 `KEY_UNWRAP_FAILED` / `hybrid recipient key recovery failed` / null cause；
- 新增 Sender 6 tests、Receiver 12 tests；覆盖 unrelated/router/binding 门序、unknown signer、trusted record/public mismatch、verify false/throw、non-canonical exact segments、三类 Hybrid key-recovery、owned-array cleanup 与 borrowed handles；
- 指定 focused matrix exit 0；随后运行 `mvn -q -pl windletter-protocol -am test`：42 suites / 463 tests、0 failures/errors/skipped；
- Step 6 的正式 review、提交证据见下；本轮识别的非阻塞明文生命周期 P2 已登记到 §12。

- [x] **Step 6: review、提交**

2026-07-18 review/verification 证据：

- 独立 spec review：Critical/P0 0、Important/P1 0、Minor 0；4 项可延期 P2；
- 独立 code/security review：Critical 0、Important 0、Minor 0；5 项可延期 P2；
- review 确认 exact Prepared/Decoded segments、binding-before-resolver/verify、trusted record kid + 实际公钥 kid + Ed25519 verify 三道身份门、Task 6 key-recovery 语义、owned arrays 与 borrowed handles 均正确；
- 主任务使用指定 JDK 17 重新运行 protocol 及依赖模块：42 suites / 463 tests、0 failures/errors/skipped；
- 合并去重后的 6 项 Task 7 相关 P2 均已登记到 §12，不阻塞 Demo；
- 本闭环提交信息固定为 `feat(protocol): add public hybrid signed flow`，实际 hash 由提交后的 `git log` 记录。

```text
feat(protocol): add public hybrid signed flow
```

## 10. Task 8：四组合 E2E、对抗矩阵与阶段封板

**Files:**

- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridFlowTestFixtures.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridUnsignedMultiRecipientE2ETest.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridSignedMultiRecipientE2ETest.java`
- Create: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicHybridTamperE2ETest.java`
- Modify: `windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireParserTest.java`
- Modify after all gates pass: `docs/dev/05-phase-3-public-hybrid-implementation-plan.md`
- Modify after all gates pass: `docs/dev/01-demo-first-overall-implementation-plan.md`

- [ ] **Step 1: 三收件人真实 wire E2E**

对 unsigned 和 signed 分别创建三个不同 X25519/ML-KEM pairs。目标位于首、中、尾时，只向 Receiver 提供该目标自己的 pair，必须从同一条 wire 恢复相同 binary payload；unrelated pair 为 `NOT_FOR_ME`。

同时覆盖 empty payload，并断言三个 1088-byte `ek` 两两不同。

- [ ] **Step 2: authenticated Hybrid tamper**

为需要越过 GCM 的测试使用真实 CEK/IV、真实 Hybrid KEK、重新计算 AAD/binding 并真实 GCM 加密，分别构造：

- matched pair 的 `ek` 替换为另一把 ML-KEM 公钥产生的 ciphertext；
- 交换两个 recipient 的 `ek` 并重算 AAD；
- wrong inner binding；
- signed 分支 flipped signature、unknown real signer、protected/payload segment change。

前两项必须是同一 `KEY_UNWRAP_FAILED` code/message 且 cause 都为 null；binding 和 signature 分别命中既有错误码。

- [ ] **Step 3: strict Hybrid parser 回归**

在 `OuterWireParserTest` 显式覆盖：

- Hybrid 缺 `kid.mlkem768`；
- Hybrid 缺 `ek`；
- Hybrid kid 31/33 bytes；
- Hybrid `ek` 1087/1089 bytes；
- X25519-only 多 `kid.mlkem768` 或 `ek`；
- padded、非 canonical 或非法 alphabet Base64URL；
- protected sender kid 出现 `mlkem768`。

生产 parser 已有行为时，只增加回归测试，不改 parser。

- [ ] **Step 4: 运行 focused matrix**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicHybridUnsignedMultiRecipientE2ETest,PublicHybridSignedMultiRecipientE2ETest,PublicHybridTamperE2ETest,PublicX25519UnsignedMultiRecipientE2ETest,PublicX25519SignedMultiRecipientE2ETest,OuterWireParserTest -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected: exit 0。

- [ ] **Step 5: module 与 full reactor gate**

```powershell
mvn -q -pl windletter-protocol -am test
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q clean test
git -c safe.directory=* diff --check
```

Expected:

- 全部命令 exit 0；
- tests 不少于阶段开始的 435；
- 0 failure、0 error、0 skipped；
- 没有新增 `@Disabled`；
- `docs/README.md` 不得被暂存或提交，`git diff -- docs/README.md` 仍为空且既存状态噪音不扩大；
- `git diff --cached --name-only` 不包含 `docs/README.md`；
- 实际变更文件只属于 Phase 3。

- [ ] **Step 6: final spec review 与 code/security review**

Spec review 逐项核对正式协议开发修订、设计文档和本计划；security review 检查 key confusion、pair routing、implicit rejection、error oracle、provider contract、secret zeroization、borrowed handles 和真实测试链路。

所有 Critical/Important/P0/P1 修复并复审后才能继续。

- [ ] **Step 7: 写完成证据与 P2 register**

在本计划记录：

- 每个闭环 commit；
- focused/module/full test counts；
- 四组合和三收件人证据；
- review 结论；
- 未阻塞的 P2。

更新 overall plan 为阶段 3 完成，并把下一步指向阶段 4，但停止开发等待用户确认。

- [ ] **Step 8: 提交阶段封板**

```text
test(protocol): close public hybrid phase
```

## 11. P0/P1 completion checklist

- [ ] ML-KEM kid 是 raw 1184-byte public key 的 SHA-256，不是 JWK/JCS/DER/SPKI。
- [ ] 固定向量为 `7NTPOwdCAmuWvE0fGJTJZ5R3RxDExM43huxxjF4IzVc`。
- [ ] `Z = SS_ECC || SS_PQ` 且 Hybrid HKDF 固定向量匹配。
- [ ] 每个 recipient 独立真实 encapsulate，`ek` 不复用。
- [ ] Router 只按完整 pair 匹配，拒绝重复 local/wire pair。
- [ ] unrelated PQ handle 为 `NOT_FOR_ME` 且不 decapsulate。
- [ ] matched pair wrong `ek` 与 unwrap failure 使用相同 code/message/null cause。
- [ ] provider/local contract failure 为 `INTERNAL_ERROR`。
- [ ] unsigned 完全跳过 Ed25519。
- [ ] signed 只在 binding 后验签，并只返回可信 identity。
- [ ] 任意失败不返回 payload/identity。
- [ ] borrowed X25519、ML-KEM、Ed25519 handles 不被 flow 关闭。
- [ ] ML-KEM internal secret、ECC/PQ secrets、Z、KEK、CEK、inner、GCM AAD 和签名临时数组按 ownership 清零。
- [ ] public X25519/Hybrid × unsigned/signed 四组合真实 wire E2E 全绿。
- [ ] binary/empty payload、首中尾 recipient 和 non-recipient 全绿。
- [ ] strict Hybrid conditional/canonical/length matrix 全绿。
- [ ] JDK 17 full reactor gate、reviews 和 diff gate 通过。
- [ ] 没有开放 P0/P1。

## 12. Deferred P2 register

以下事项默认不阻塞阶段 3，除非实现证明其影响协议或安全正确性：

1. 抽取 X25519/Hybrid 与 signed/unsigned 的共享 orchestration。
2. 为 byte-array records 统一 content-based `equals/hashCode`。
3. 定义 encapsulation result 与 key handles 的并发 close/operation 行为。
4. 把 ML-KEM kid 和 Hybrid KDF 向量发布到 `windletter-testkit`。
5. Phase 6 API facade 接线时，统一校验 `RecipientPublicKeyMaterial`、`DecryptionKeyLease` 中外部 kid 与实际公钥的绑定。
6. 进一步减少公开公钥、kid、`ek` 和 immutable string 的临时副本。
7. Hybrid 与 X25519-only flow 的错误 helper 重复。
8. 测试 fixture 可能重复已有 signed/unsigned authenticated-tamper 构造逻辑。
9. `BouncyCastleMLKem768CryptoTest` 的 round-trip/tamper/import 用例在 `decapsulate()` 意外抛错时，`expectedSecret` 副本尚未进入 `finally` 清零范围；正常路径已清零，测试专用，不阻塞 Demo。
10. `BouncyCastleMLKem768Crypto.encapsulate` 的 provider getter 临时数组与 holder destroy 已经代码审查和 BC 1.83 字节码核验，但尚无直接 instrumentation 回归测试。
11. `PublicHybridKekDeriverTest` 尚未单独注入 X25519 provider 返回 null；生产实现已统一拒绝 null/错误长度并在 `finally` 清理，不是实现缺陷。
12. `PublicHybridKekDeriverTest` 尚未通过完整 sender API 注入 HKDF 失败来直接观察 encapsulation close；生产实现的 try-with-resources 与 outer `finally` 已经代码/安全审查确认。
13. `PublicHybridRecipientBuilder` 的 API 注释尚未像 X25519 builder 一样显式写明 sender handle 与调用方 CEK 均为 caller-owned；实现 ownership 正确。
14. `PublicHybridRecipientBuilderTest` 的多收件人 success tracking 只直接观察最后一次 wrap 的临时数组清零；生产循环每次都使用同一 per-recipient `finally`，异常矩阵也已覆盖。
15. 若 SHA-256 平台不可用导致 pair kid 派生在中途异常，已构造但尚未返回的 `RecipientSpec` 公钥副本可进一步统一清零；仅为非敏感公钥副本，不影响协议或安全正确性。
16. `PublicHybridKidRouterTest` 尚未直接注入 kid derivation failure；生产实现已由统一 `catch (RuntimeException)` 映射为保留 cause 的 `INTERNAL_ERROR`，标准 JDK 下 SHA-256 不可用也难以稳定构造。
17. `PublicHybridKidRouter.Match` 的 API 注释尚未显式说明其中两个 private-key handles 仍为 borrowed；实现从不关闭 handles，ownership 行为正确。
18. `PublicHybridKidRouterTest` 尚未直接观察成功路由时正确长度公钥快照清零，accessor 直接抛异常的分支也未逐个断言 handle 未关闭；生产实现由统一 `finally` 清理且不存在 `close()` 调用。
19. `PublicHybridUnsignedReceiver` 与 `PublicHybridSignedReceiver` 在重派生 sender X25519 kid 时，若标准 JDK 的 SHA-256 平台能力异常，会裸抛 `IllegalStateException` 且该异常分支的公开公钥 snapshot 未进入统一 `finally`；Java 17 必须提供 SHA-256，正常 Demo 路径不可触发，后续可统一映射 `INTERNAL_ERROR`。
20. `PublicHybridUnsignedSender` 与 `PublicHybridSignedSender` 目前拒绝 null GCM result，但尚未额外检查自定义 provider 返回的 ciphertext 长度必须等于 inner plaintext 长度；真实 BC provider 满足合同，属于 provider hardening。
21. `PublicHybridUnsignedReceiver.Result` 的公开构造器只校验字段非 null，未强制 `authenticationStatus == UNSIGNED`；生产 `receive()` 固定只构造 `UNSIGNED`，仅影响外部手工构造语义。
22. Task 6 清零测试尚未直接 instrument Sender/Receiver 各自取得的 sender 公开公钥 snapshot；生产实现的正常成功/失败路径均在 `finally` 清零，且该数据不是秘密。
23. unsigned/signed inner decode 在 binding 或验签完成前已经物化不可销毁的 `ProtocolPayload` 防御性副本；失败时 decrypted inner 会清零且 payload 不会返回，但 DTO 内部副本只能随 GC 回收，后续需由统一 payload/model cleanup 能力处理。
24. `SignedInnerCodec.Prepared` 持有可逆的 Base64URL payload string；关闭时会清零 signing input，但 immutable string 只能随 GC 回收。后续可改为可关闭的字节缓冲区，并与“验证成功后转移 payload 所有权”的模型一起处理。
25. signed Receiver 对 unknown signer 与 Ed25519 verify false 均返回 `SIGNATURE_INVALID`，但内部诊断 message 不同；当前必须先通过 recipient key recovery 与 GCM 才能到达该层，Phase 6 API facade 对外暴露时可统一公开错误文案，避免未来形成可信 signing-kid 枚举差异。
26. 少数 Task 7 测试 helper 取得的 public-key、`ek` 等非秘密副本只在正常断言路径清零，断言中断时可能等待 GC；不影响生产实现、协议或敏感数据安全。

阶段完成时必须把仍开放的 P2 和影响写入用户报告。
