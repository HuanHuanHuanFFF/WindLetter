# Phase 1 Public X25519 Unsigned Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` to implement this plan task-by-task. Every production behavior follows RED → verify RED → GREEN → verify GREEN. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成 `public × X25519 × unsigned × 多收件人` 的第一条真实 WindLetter 纵向主链，并收口 strict parser、AAD/JCS、binding、RFC 7638 kid 与私钥 lease 安全基础。

**Architecture:** `windletter-protocol` 接受 provider-neutral crypto handle 和已解析的公钥材料，不依赖 `windletter-api`；Sender 生成真实 outer JSON，Receiver 必须从该 JSON 重新 strict parse 后才能恢复 payload。`windletter-api` 本阶段只把 raw private `byte[]` SPI 改为显式所有权的 `AutoCloseable` lease，不提前实现不完整 facade。

**Tech Stack:** Java 17、Maven、JUnit 5.10.2、Jackson 2.17.1、RFC 8785 JCS 1.1、Bouncy Castle 1.83。

---

## 0. 执行状态与项目覆盖规则

- 当前分支：`spike/demo-v0`
- 阶段起点 HEAD：`2d29bb35126e`
- 阶段基线：JDK 17 下 `mvn -q test` 退出码 0，原有 106 个测试全部保留
- 用户已于 2026-07-13 批准进入阶段 1
- 用户约束覆盖通用 skill：本阶段不创建第二 worktree，不提交、不合并、不推送
- `docs/README.md` 仍有 Git 行尾状态噪音且内容 diff 为空；本阶段不处理

阶段状态：

| Task | 状态 |
|---|---|
| 1. API 私钥 lease 与加密身份契约 | 已完成（38 API tests） |
| 2. Strict outer parser 安全加固 | 已完成（58 focused tests；108 reactor tests） |
| 3. Base64URL/JCS/JSON 投影/RFC 7638 kid | 已完成（9 focused tests；119 reactor tests） |
| 4. Outer AAD、binding 与 wire writer | 已完成（7 focused tests；74 protocol tests） |
| 5. Strict unsigned inner codec | 已完成（60 focused tests；134 protocol tests） |
| 6. X25519 KEK 与 recipient 构建 | 已完成（16 focused tests；202 reactor tests） |
| 7. Public X25519 unsigned Sender | 已完成（6 focused tests；156 protocol tests） |
| 8. Public routing 与 Receiver | 已完成（23 focused tests；179 protocol tests） |
| 9. 多收件人 E2E、tamper 与阶段封板 | 已完成（10 focused E2E/tamper tests；195 protocol tests；285 reactor tests） |

最终封板证据（2026-07-14）：

- 分支仍为 `spike/demo-v0`，HEAD 仍为阶段起点 `2d29bb35126e`；未 commit、stage、merge 或 push。
- JDK `C:\Users\幻\.jdks\ms-17.0.16` 下，API、protocol、两模块组合验证及最终 `mvn -q clean test` 均为 exit 0。
- clean 后 Surefire 汇总：core 1、crypto 51、protocol 195、API 38；总计 285 tests，0 failure、0 error、0 skipped。
- `git diff --check` 通过；`docs/README.md` 仍只是会话前已有的行尾状态噪音，内容 diff 为空且本阶段未修改。
- 最终 spec review 与 code/security review 均 PASS；唯一 outer `null` / wrong-type 测试证据缺口已补齐并复核关闭，无未处理 Critical/Important 或 P0/P1。

## 1. 阶段边界

本阶段必须交付：

```text
真实 payload bytes
  -> static sender X25519
  -> N 个 static recipient X25519 public keys
  -> per-recipient HKDF-SHA256 KEK
  -> per-recipient A256KW wrapped shared CEK
  -> recipients JCS / outer AAD
  -> unsigned inner + two outer bindings
  -> AES-256-GCM
  -> UTF-8 outer JSON String
  -> strict parser
  -> public kid routing
  -> unwrap / GCM / strict inner / binding
  -> original payload bytes + UNSIGNED
```

本阶段明确不做：

- Ed25519、signed inner、`wind+jws`
- ML-KEM-768、Hybrid
- obfuscation Sender/Receiver、rid、epk、padding；只修复现有 obfuscation parser 的 bucket P1
- Armor
- `DefaultWindLetterSender` / `DefaultWindLetterReceiver`
- testkit Demo main
- 算法注册表、DI、ServiceLoader、HSM/KMS、streaming

## 2. 已冻结协议 Profile

### 2.1 Outer protected

Sender 生成的 decoded protected 必须只有：

```json
{
  "typ": "wind+jwe",
  "cty": "wind+inner",
  "ver": "1.0",
  "wind_mode": "public",
  "enc": "A256GCM",
  "key_alg": "X25519",
  "kid": {
    "x25519": "BASE64URL(32-byte RFC7638 sender kid)"
  }
}
```

禁止 `epk`、ML-KEM kid、`wind+jws` 和任何 unknown/duplicate field。

### 2.2 Recipient entry

每项必须只有：

```json
{
  "kid": {
    "x25519": "BASE64URL(32-byte RFC7638 recipient kid)"
  },
  "encrypted_key": "BASE64URL(40-byte A256KW output)"
}
```

Sender 接受 1..32 个 recipient，保留调用方输入顺序，拒绝重复派生 kid。Public 的 32 是 Demo 资源上限，不冒充正式协议的新语义。

### 2.3 Unsigned inner

`inner_bytes` 使用 JCS UTF-8 编码的直接根对象，不增加调试视图中的 `ciphertext` 包装：

```json
{
  "protected": {
    "typ": "wind+inner",
    "ts": 1731800000,
    "wind_id": "canonical-lowercase-uuid-v4",
    "jwe_protected_hash": "BASE64URL(32 bytes)",
    "jwe_recipients_hash": "BASE64URL(32 bytes)"
  },
  "payload": {
    "meta": {
      "content_type": "application/octet-stream",
      "original_size": 3
    },
    "body": {
      "data": "AAEC"
    }
  }
}
```

`ts` 是非负 Unix epoch seconds；`wind_id` 必须通过 UUID v4 version/variant 和 canonical text 校验；`original_size` 必须等于 decoded payload bytes 长度。零长度 payload 合法。

### 2.4 精确密码输入

```text
CEK = CSPRNG(32 bytes)
IV  = CSPRNG(12 bytes)

SS_ECC = X25519(sender_static_private, recipient_static_public)

KEK = HKDF-SHA256(
  salt = UTF8("wind"),
  ikm  = SS_ECC,
  info = UTF8("WindLetter v1 KEK | X25519"),
  L    = 32
)

encrypted_key = A256KW(KEK, CEK) // 40 bytes

outer.aad = Base64URL(JCS(final recipients array))
gcm_aad   = ASCII(protected_b64 + "." + aad_b64)

jwe_protected_hash  = SHA256(JCS(decoded protected JSON))
jwe_recipients_hash = SHA256(JCS(final recipients array))
```

所有 Base64URL 均无 padding 且必须 canonical。Binding 比较使用 `MessageDigest.isEqual`。X25519 low-order/all-zero secret 必须拒绝。

### 2.5 RFC 7638 X25519 kid

对 32-byte X25519 public key：

```text
jwk = JCS({"crv":"X25519","kty":"OKP","x":Base64URL(publicKey)})
kid = Base64URL(SHA256(jwk))
```

固定向量：

```text
publicKey = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
jwk       = {"crv":"X25519","kty":"OKP","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}
kid       = u809Vppx5ixWMOohxWr2aM3m5bD0LQ67g_GPmubQus4
```

### 2.6 资源限制

在 `ProtocolLimits` 中固定：

```java
public static final int MAX_JSON_DEPTH = 32;
public static final int MAX_RECIPIENTS = 32;
public static final int MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
public static final int MAX_INNER_BYTES = 12 * 1024 * 1024;
public static final int MAX_CIPHERTEXT_BYTES = 12 * 1024 * 1024;
public static final int MAX_WIRE_UTF8_BYTES = 20 * 1024 * 1024;
```

这些是实现资源限制。Parser 在 JSON parse 前检查 wire UTF-8 byte length，并使用 Jackson `StreamReadConstraints` 限制 depth/document/string；decoded ciphertext、inner 和 payload 各自再检查。

### 2.7 Handle 所有权

- API `*Lease` **拥有**其中 handle；`close()` 必须关闭 handle、幂等，并使 lease accessor 失败。
- Protocol Sender/Receiver **借用**调用方传入的 static private-key handle，不关闭它；调用边界由未来 API facade 的 try-with-resources 关闭 lease。
- Protocol flow 拥有并在 `finally` 清零 CEK、KEK、shared secret、decrypted inner 临时数组。
- 同一 composition root 必须使用匹配 provider family；BC 会拒绝其他 provider 创建的 handle。

## 3. 文件结构

### 3.1 API

Create:

- `windletter-api/src/main/java/com/windletter/api/model/SenderEncryptionIdentityRef.java`
- `windletter-api/src/main/java/com/windletter/api/spi/SenderEncryptionKeyLease.java`
- `windletter-api/src/main/java/com/windletter/api/spi/DecryptionKeyLease.java`
- `windletter-api/src/main/java/com/windletter/api/spi/SigningIdentityLease.java`
- `windletter-api/src/main/java/com/windletter/api/spi/RecipientPublicKeyMaterial.java`
- `windletter-api/src/main/java/com/windletter/api/spi/X25519PublicKeyMaterial.java`
- `windletter-api/src/main/java/com/windletter/api/spi/RecipientPublicKeyResolver.java`
- `windletter-api/src/main/java/com/windletter/api/spi/SenderPublicKeyResolver.java`
- `windletter-api/src/main/java/com/windletter/api/spi/SenderEncryptionKeyStore.java`

Replace/remove:

- `windletter-api/src/main/java/com/windletter/api/spi/DecryptionKeyMaterial.java`
- `windletter-api/src/main/java/com/windletter/api/spi/SigningIdentityMaterial.java`

Modify:

- `windletter-api/pom.xml`
- `windletter-api/src/main/java/com/windletter/api/model/EncryptRequest.java`
- `windletter-api/src/main/java/com/windletter/api/model/EncryptAndSignRequest.java`
- `windletter-api/src/main/java/com/windletter/api/model/Payload.java`
- `windletter-api/src/main/java/com/windletter/api/spi/RecipientKeyStore.java`
- `windletter-api/src/main/java/com/windletter/api/spi/IdentityService.java`

### 3.2 Protocol

Create:

- `windletter-protocol/src/main/java/com/windletter/protocol/ProtocolLimits.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/codec/Base64Url.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/codec/StrictJson.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/codec/JcsCanonicalizer.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/codec/OuterJsonMapper.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/codec/JacksonOuterWireWriter.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/auth/OuterAad.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/binding/OuterBinding.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/key/X25519KeyId.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/key/PublicX25519KekDeriver.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolPayload.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/model/ProtocolAuthenticationStatus.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/inner/UnsignedInnerCodec.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/recipient/PublicX25519RecipientBuilder.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/routing/PublicKidRouter.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/SenderX25519PublicKeyResolver.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519UnsignedSender.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/flow/PublicX25519UnsignedReceiver.java`

Modify:

- `windletter-protocol/src/main/java/com/windletter/protocol/parser/JacksonOuterWireParser.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/parser/ParserSupport.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/parser/ObfuscationOuterBranchParser.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/wire/WindLetter.java`
- `windletter-protocol/src/main/java/com/windletter/protocol/wire/WireChecks.java`

## 4. Task 1：API 私钥 lease 与加密身份契约

**Files:**

- Test: `windletter-api/src/test/java/com/windletter/api/spi/PrivateKeyLeaseContractTest.java`
- Test: `windletter-api/src/test/java/com/windletter/api/spi/SigningIdentityLeaseContractTest.java`
- Test/modify: existing API model tests
- Production: API files listed in §3.1

- [x] **Step 1.1：写 lease RED tests**

最小断言：

```java
@Test
void shouldCloseOwnedX25519HandleIdempotently() {
    BouncyCastleX25519Crypto crypto = new BouncyCastleX25519Crypto();
    X25519PrivateKeyHandle handle = crypto.generatePrivateKey();
    DecryptionKeyLease lease = DecryptionKeyLease.x25519("kid", handle);

    lease.close();
    lease.close();

    assertThrows(IllegalStateException.class, handle::publicKey);
    assertThrows(IllegalStateException.class, lease::x25519PrivateKey);
}
```

对 `SenderEncryptionKeyLease` 和 `SigningIdentityLease` 做同样所有权测试；反射断言三个 lease 不暴露 private-key `byte[]` accessor。

- [x] **Step 1.2：运行 RED**

```powershell
mvn -q -pl windletter-api -am "-Dtest=PrivateKeyLeaseContractTest,SigningIdentityLeaseContractTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected：`testCompile` 因 lease 类型不存在而失败。

- [x] **Step 1.3：添加 crypto 依赖和最小 lease 实现**

关键接口：

```java
public final class DecryptionKeyLease implements AutoCloseable {
    public static DecryptionKeyLease x25519(String kid, X25519PrivateKeyHandle key);
    public static DecryptionKeyLease hybrid(
        String xKid, X25519PrivateKeyHandle xKey,
        String pqKid, MLKem768PrivateKeyHandle pqKey
    );
    public String x25519Kid();
    public X25519PrivateKeyHandle x25519PrivateKey();
    public String mlkem768Kid();
    public MLKem768PrivateKeyHandle mlkem768PrivateKey();
    @Override public void close();
}
```

`close()` 必须尝试关闭全部 owned handles；任何 accessor 在 lease close 后抛 `IllegalStateException`。

- [x] **Step 1.4：替换 raw material SPI**

```java
public interface RecipientKeyStore {
    List<DecryptionKeyLease> openAll(RecipientIdentityRef identity);
}

public interface IdentityService {
    Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef ref);
    Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String kid);
    Optional<SenderIdentity> resolveSenderBySigningKid(String kid);
}
```

删除 `DecryptionKeyMaterial`、`SigningIdentityMaterial`，不保留并行 raw-key compatibility layer。

- [x] **Step 1.5：增加发送方 encryption identity 与 public resolvers**

```java
public record SenderEncryptionIdentityRef(String identityId, String keySelector) {}

public interface SenderEncryptionKeyStore {
    Optional<SenderEncryptionKeyLease> open(SenderEncryptionIdentityRef identity);
}

public interface RecipientPublicKeyResolver {
    Optional<RecipientPublicKeyMaterial> resolve(RecipientRef recipient);
}

public interface SenderPublicKeyResolver {
    Optional<X25519PublicKeyMaterial> resolveX25519ByKid(String kid);
}
```

`EncryptRequest` 和 `EncryptAndSignRequest` 都增加独立 `senderEncryptionIdentity`；后者仍保留 `senderSigningIdentity`，两种身份不得合并。

- [x] **Step 1.6：收紧 Payload originalSize**

写 RED：`new Payload("x", new byte[]{1}, 2)` 必须拒绝。GREEN：constructor 要求 `originalSize == data.length`。

- [x] **Step 1.7：运行 GREEN 与 API 回归**

```powershell
mvn -q -pl windletter-api -am test
```

Expected：API 与依赖模块全部通过；production API/SPI 不再有 raw private `byte[]` material。

## 5. Task 2：Strict outer parser 安全加固

**Files:**

- Test/modify: `windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireParserTest.java`
- Test/create: `windletter-protocol/src/test/java/com/windletter/protocol/parser/OuterWireCanonicalBase64UrlTest.java`
- Production: `ProtocolLimits.java`、`StrictJson.java`、`Base64Url.java` 和 parser files

- [x] **Step 2.1：写 duplicate/trailing RED**

覆盖 outer、decoded protected、recipient、nested kid 的 duplicate member，以及单一 JSON root 后追加第二个 token。全部预期 `MALFORMED_WIRE`。

- [x] **Step 2.2：写 canonical Base64URL RED**

使用“URL alphabet 合法、无 `=`、可解码，但 unused trailing bits 非零”的值；decode 后 re-encode 与原文不同，必须 `MALFORMED_WIRE`。覆盖 `protected/aad/iv/ciphertext/tag/kid/encrypted_key`。

- [x] **Step 2.3：写 recipient count RED**

- public：1、2、32 接受；0、33 拒绝。
- obfuscation：8、16、32 接受；1、7、9、15、17、31、33 拒绝。
- 将现有 obfuscation 单 entry 正例 fixture 改成 8 entries。

- [x] **Step 2.4：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=OuterWireParserTest,OuterWireCanonicalBase64UrlTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected：duplicate、canonical re-encode 和 bucket/count 断言失败。

- [x] **Step 2.5：实现 StrictJson 与 ProtocolLimits**

`StrictJson.newMapper()` 使用：

```java
StreamReadConstraints.builder()
    .maxNestingDepth(ProtocolLimits.MAX_JSON_DEPTH)
    .maxDocumentLength(ProtocolLimits.MAX_WIRE_UTF8_BYTES)
    .maxStringLength(ProtocolLimits.MAX_WIRE_UTF8_BYTES)
    .build();
```

并启用 `StreamReadFeature.STRICT_DUPLICATE_DETECTION`、`DeserializationFeature.FAIL_ON_TRAILING_TOKENS`。

- [x] **Step 2.6：实现 canonical Base64URL**

```java
public static byte[] decodeCanonical(String value, String fieldPath) {
    rejectNullBlankPaddingAndNonUrlAlphabet(value);
    byte[] decoded = Base64.getUrlDecoder().decode(value);
    if (!encode(decoded).equals(value)) {
        throw malformed(fieldPath + " must use canonical Base64URL");
    }
    return decoded;
}
```

另提供只用于 payload 的 `decodeCanonicalAllowEmpty`。`ParserSupport` 委托该工具，不能保留第二套 decoder。

- [x] **Step 2.7：实现 count/size limits**

Outer parse 前检查 UTF-8 byte length；public 1..32；obfuscation `{8,16,32}`；decoded ciphertext 不超过 12 MiB。`WindLetter` 构造器也要求 non-empty recipients。

- [x] **Step 2.8：运行 GREEN 与 parser 回归**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=OuterWireParserTest,OuterWireCanonicalBase64UrlTest" -Dsurefire.failIfNoSpecifiedTests=false test
mvn -q -pl windletter-protocol -am test
```

## 6. Task 3：JCS、JSON 投影与 RFC 7638 kid

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/codec/JcsCanonicalizerTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/codec/OuterJsonMapperTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/key/X25519KeyIdTest.java`
- Production: `JcsCanonicalizer.java`、`OuterJsonMapper.java`、`X25519KeyId.java`

- [x] **Step 3.1：写 JCS/JSON projection RED**

硬编码 two-recipient vector：

```text
[{
  "encrypted_key":"EREREREREREREREREREREREREREREREREREREREREREREREREREREQ",
  "kid":{"x25519":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}
},{
  "encrypted_key":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg",
  "kid":{"x25519":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}
}]
```

实际 expected 使用无换行的一行 JCS 字符串。断言对象插入顺序不影响 JCS、数组顺序影响结果。

- [x] **Step 3.2：写 RFC 7638 RED**

使用 §2.5 固定向量，断言 public key 长度必须 32，kid 与硬编码值完全一致。

- [x] **Step 3.3：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=JcsCanonicalizerTest,OuterJsonMapperTest,X25519KeyIdTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

Expected：production types 不存在而 testCompile 失败。

- [x] **Step 3.4：实现最小 production classes**

`JcsCanonicalizer` 使用 `org.erdtman.jcs.JsonCanonicalizer`，本地 wrapper 不 import 同名 simple class。`OuterJsonMapper` 是 protected/recipients/outer 唯一 typed→JSON 投影，后续 writer、AAD、binding 必须共用。

- [x] **Step 3.5：运行 GREEN**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=JcsCanonicalizerTest,OuterJsonMapperTest,X25519KeyIdTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

## 7. Task 4：Outer AAD、binding 与 wire writer

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/auth/OuterAadTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/binding/OuterBindingTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/codec/JacksonOuterWireWriterTest.java`
- Production: `OuterAad.java`、`OuterBinding.java`、`JacksonOuterWireWriter.java`

- [x] **Step 4.1：写 AAD RED**

硬编码 §6 two-recipient JCS 的 AAD：

```text
W3siZW5jcnlwdGVkX2tleSI6IkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUSIsImtpZCI6eyJ4MjU1MTkiOiJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFIn19LHsiZW5jcnlwdGVkX2tleSI6IklpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJZyIsImtpZCI6eyJ4MjU1MTkiOiJBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJIn19XQ
```

断言 `gcmInput("abc","def") == ASCII("abc.def")`，array reorder 改变 AAD，object member insertion order 不改变。

- [x] **Step 4.2：写 binding RED**

断言：

- protected hash 是 decoded protected semantic JSON 的 JCS SHA-256。
- recipients hash 是 final array JCS SHA-256。
- 两项各自篡改触发 `BINDING_FAILED`。
- `Hashes` constructor/accessor 防御性复制。

- [x] **Step 4.3：写 writer round-trip RED**

构造 typed `WindLetter`，writer 输出必须经现有 strict parser 成功解析，并保留 protected/aad/recipient/iv/ciphertext/tag bytes。

- [x] **Step 4.4：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=OuterAadTest,OuterBindingTest,JacksonOuterWireWriterTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 4.5：实现服务**

关键签名：

```java
public final class OuterAad {
    public String compute(List<RecipientEntry> recipients);
    public void verify(WindLetter letter);
    public byte[] gcmInput(String protectedValue, String aadValue);
}

public final class OuterBinding {
    public Hashes compute(ProtectedHeader header, List<RecipientEntry> recipients);
    public void verify(Hashes actual, ProtectedHeader header, List<RecipientEntry> recipients);
    public record Hashes(byte[] protectedHash, byte[] recipientsHash) {}
}

public final class JacksonOuterWireWriter {
    public String write(WindLetter letter);
}
```

`verify` 必须先解码 actual raw 32 B，再用 `MessageDigest.isEqual` 比较。

- [x] **Step 4.6：运行 GREEN 与 protocol 回归**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=OuterAadTest,OuterBindingTest,JacksonOuterWireWriterTest" -Dsurefire.failIfNoSpecifiedTests=false test
mvn -q -pl windletter-protocol -am test
```

## 8. Task 5：Strict unsigned inner codec

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/inner/UnsignedInnerCodecTest.java`
- Production: `ProtocolPayload.java`、`ProtocolAuthenticationStatus.java`、`UnsignedInnerCodec.java`

- [x] **Step 5.1：写 round-trip RED**

覆盖 arbitrary binary、零字节、零长度 payload、timestamp、UUID v4、两项 32-byte binding 和 defensive copies。

- [x] **Step 5.2：写 strict negative RED**

逐层覆盖 duplicate、unknown、null、wrong type、trailing content、非 canonical Base64URL、binding 非 32 B、非 UUID v4、negative/unsafe integer timestamp、original size mismatch、payload 超 8 MiB，以及 `alg/kid/signature` 出现。

- [x] **Step 5.3：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=UnsignedInnerCodecTest -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 5.4：实现 codec**

```java
public final class UnsignedInnerCodec {
    public byte[] encode(Message message);
    public Message decode(byte[] innerBytes);

    public record Message(
        String messageId,
        long timestamp,
        ProtocolPayload payload,
        OuterBinding.Hashes binding
    ) {}
}
```

Encode 使用 JCS；decode 使用 `StrictJson`，只接受 `{protected,payload}` 直接根对象。

- [x] **Step 5.5：运行 GREEN**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=UnsignedInnerCodecTest -Dsurefire.failIfNoSpecifiedTests=false test
```

## 9. Task 6：X25519 KEK 与 recipient 构建

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/key/PublicX25519KekDeriverTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/recipient/PublicX25519RecipientBuilderTest.java`
- Production: `PublicX25519KekDeriver.java`、`PublicX25519RecipientBuilder.java`

- [x] **Step 6.1：写 HKDF vector RED**

固定输入/输出：

```text
SS_ECC = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
salt   = 77696e64
info   = UTF8("WindLetter v1 KEK | X25519")
PRK    = 521a3be705d4ae4110c12cd63287e698c224cd8806f3cec048d03be799f10db2
KEK    = 277479809bf70197fc456c17b12429319823906852875eb2353482fb3a4e0cb6
```

另用真实双方 handle 断言 Sender/Receiver 派生相同 KEK，low-order public key 和 closed handle 被拒绝。

- [x] **Step 6.2：写 multi-recipient builder RED**

两个真实 recipient 必须：

- 各自派生 RFC 7638 kid。
- 各自派生不同 KEK。
- wrap 同一个 32-byte CEK，输出两个 40-byte encrypted_key。
- 不含 `ek/mlkem768/rid`。
- 拒绝 0/33、重复 public key、31-byte/low-order public key。

- [x] **Step 6.3：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=PublicX25519KekDeriverTest,PublicX25519RecipientBuilderTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 6.4：实现并清零 secrets**

```java
public final class PublicX25519KekDeriver {
    public byte[] derive(X25519PrivateKeyHandle ownKey, byte[] peerPublicKey);
}

public final class PublicX25519RecipientBuilder {
    public List<PublicRecipient> build(
        X25519PrivateKeyHandle senderKey,
        List<byte[]> recipientPublicKeys,
        byte[] cek
    );
}
```

Deriver 在 `finally` 清零 shared secret；builder 每轮在 `finally` 清零 KEK。Borrowed sender handle 保持可用。

- [x] **Step 6.5：运行 GREEN**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=PublicX25519KekDeriverTest,PublicX25519RecipientBuilderTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

## 10. Task 7：Public X25519 unsigned Sender

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519UnsignedSenderTest.java`
- Production: `PublicX25519UnsignedSender.java`

- [x] **Step 7.1：写 Sender RED**

测试：

- 两 recipient 输出能被 strict parser 解析。
- protected profile 精确为 public/X25519/wind+inner。
- AAD 在 final recipients 后计算。
- inner 两项 binding 对应 final protected/recipients。
- 一份 ciphertext、每 recipient 一份 wrapped CEK。
- 相同业务输入连续发送，IV/ciphertext 不同。
- wire 不出现 private key、shared secret、CEK/KEK。
- borrowed sender handle 在成功和 recipient 构建失败后仍可用。

- [x] **Step 7.2：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519UnsignedSenderTest -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 7.3：实现 Sender**

```java
public final class PublicX25519UnsignedSender {
    public Result send(Request request);

    public record Request(
        ProtocolPayload payload,
        String messageId,
        long timestamp,
        X25519PrivateKeyHandle senderPrivateKey,
        List<byte[]> recipientPublicKeys
    ) {}

    public record Result(WindLetter message, String wireJson) {}
}
```

固定顺序：validate → CEK/IV → protected → recipients → AAD/binding → inner → GCM → outer/writer。Sender 在 `finally` 清零 CEK/IV 临时副本和 inner bytes，但不关闭 borrowed handle。

- [x] **Step 7.4：运行 GREEN 与 parser round-trip**

```powershell
mvn -q -pl windletter-protocol -am -Dtest=PublicX25519UnsignedSenderTest -Dsurefire.failIfNoSpecifiedTests=false test
mvn -q -pl windletter-protocol -am test
```

## 11. Task 8：Public routing 与 Receiver

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/routing/PublicKidRouterTest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519UnsignedReceiverTest.java`
- Production: `PublicKidRouter.java`、`SenderX25519PublicKeyResolver.java`、`PublicX25519UnsignedReceiver.java`

- [x] **Step 8.1：写 routing RED**

覆盖首/中/尾位置；无本地 kid 为 `NOT_FOR_ME`；同一 kid 多次命中或多 local handle 派生同一 kid为 `INVALID_FIELD`；不允许将 kid 命中后的 unwrap/GCM 失败降级为 `NOT_FOR_ME`。

- [x] **Step 8.2：写 Receiver RED**

Receiver 输入必须是 `wireJson`，内部调用 `OuterWireParser`，不能接受 Sender 的 typed DTO shortcut。测试：

- 第二 recipient 恢复 payload。
- unknown sender kid 为 InvalidMessage 内部原因，而不是 NotForMe。
- target encrypted_key 错误为 `KEY_UNWRAP_FAILED`。
- iv/ciphertext/tag 错误为 `GCM_AUTH_FAILED`。
- malformed inner 和 binding mismatch 不返回 payload。
- borrowed recipient handles 在 success/failure 后仍可用，由调用者关闭。

- [x] **Step 8.3：运行 RED**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=PublicKidRouterTest,PublicX25519UnsignedReceiverTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 8.4：实现 Receiver**

```java
@FunctionalInterface
public interface SenderX25519PublicKeyResolver {
    Optional<byte[]> resolve(String x25519Kid);
}

public final class PublicX25519UnsignedReceiver {
    public Result receive(Request request);

    public record Request(
        String wireJson,
        SenderX25519PublicKeyResolver senderKeys,
        List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {}

    public record Result(
        ProtocolPayload payload,
        String messageId,
        long timestamp,
        ProtocolAuthenticationStatus authenticationStatus
    ) {}
}
```

固定顺序：strict parse/profile → AAD → unique local kid route → sender key resolve + RFC7638 check → X25519/KEK → unwrap → GCM → strict inner → binding → payload。成功状态固定 `UNSIGNED`。

- [x] **Step 8.5：清零与错误映射**

- CEK/KEK/decrypted inner 在所有路径清零。
- AAD mismatch → `AAD_MISMATCH`。
- 无 recipient match → `NOT_FOR_ME`。
- 命中后 unwrap → `KEY_UNWRAP_FAILED`。
- GCM → `GCM_AUTH_FAILED`。
- binding → `BINDING_FAILED`。
- API facade 尚未实现；阶段 6 将上述 internal code 统一映射为公开 `INVALID_MESSAGE`，仅保留 `NOT_FOR_ME`。

- [x] **Step 8.6：运行 GREEN**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=PublicKidRouterTest,PublicX25519UnsignedReceiverTest" -Dsurefire.failIfNoSpecifiedTests=false test
```

## 12. Task 9：多收件人 E2E、tamper 与阶段封板

**Files:**

- Test: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519UnsignedMultiRecipientE2ETest.java`
- Test: `windletter-protocol/src/test/java/com/windletter/protocol/flow/PublicX25519UnsignedTamperE2ETest.java`
- Test support: `windletter-protocol/src/test/java/com/windletter/protocol/flow/ProtocolFlowTestFixtures.java`
- Docs: this plan and `docs/dev/01-demo-first-overall-implementation-plan.md`

- [x] **Step 9.1：写 real-wire multi-recipient E2E RED**

三套真实 BC X25519 recipient handles；Sender 输出 String；每个 Receiver 只拿 String、自己的 handle 和 sender public resolver。分别断言：

- 三个 recipient 恢复同一 binary payload。
- unrelated handle 得到 `NOT_FOR_ME`。
- result 为 `UNSIGNED`，无 sender signing identity。
- zero-length payload 可往返。
- Sender/Receiver 之间没有 `WindLetter` DTO 传递。

- [x] **Step 9.2：写 tamper RED**

逐项独立篡改并断言无 payload：

| Tamper | Expected internal code |
|---|---|
| recipients 内容/顺序，aad 不变 | `AAD_MISMATCH` |
| aad | `AAD_MISMATCH` |
| protected 的合法编码字节 | `GCM_AUTH_FAILED` 或更早 profile invalid |
| target encrypted_key | `KEY_UNWRAP_FAILED` |
| iv | `GCM_AUTH_FAILED` |
| ciphertext | `GCM_AUTH_FAILED` |
| tag | `GCM_AUTH_FAILED` |
| authenticated inner protected binding | `BINDING_FAILED` |
| authenticated inner recipients binding | `BINDING_FAILED` |

最后两项使用 test-only deterministic `SecureRandom` 获得已知 CEK/IV，再以真实 A256GCM 重新加密恶意 inner；不能通过普通 bit flip 假装测到 binding gate。

- [x] **Step 9.3：运行 RED，补齐最小集成缺口**

```powershell
mvn -q -pl windletter-protocol -am "-Dtest=PublicX25519UnsignedMultiRecipientE2ETest,PublicX25519UnsignedTamperE2ETest" -Dsurefire.failIfNoSpecifiedTests=false test
```

- [x] **Step 9.4：运行阶段 focused suites**

```powershell
mvn -q -pl windletter-api -am test
mvn -q -pl windletter-protocol -am test
mvn -q -pl windletter-protocol,windletter-api -am test
```

- [x] **Step 9.5：执行全量 clean 验证**

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q clean test
git -c safe.directory=D:/CodingProject/WindLetter diff --check
git -c safe.directory=D:/CodingProject/WindLetter status --short --branch
```

Expected：所有命令 exit 0；Surefire 0 failure/error/skip；总测试数大于 106。

- [x] **Step 9.6：阶段 review**

按顺序执行：

1. Spec compliance review：逐项核对本文 profile、9 个 task、正负例和范围禁止项。
2. Code quality/security review：重点检查 exact bytes、错误顺序、constant-time binding、zeroization、borrowed/owned handle 边界、无敏感日志。
3. 修复 review 问题后重新运行 focused + full clean tests。

- [x] **Step 9.7：更新阶段证据并停止**

把 §0 task 状态改为已完成，在总体计划更新阶段 1 状态、实际测试数、已知技术债与阶段 2 建议。向用户报告后停止，不开始 signed 代码。

## 13. 阶段完成门

只有以下全部成立才能称为阶段 1 完成：

- [x] 三个真实 public X25519 recipient 均从实际 JSON String 恢复相同 payload。
- [x] 非收件人为 `NOT_FOR_ME`；所有命中后的失败不降级为 NotForMe。
- [x] X25519、HKDF、A256KW、A256GCM、SHA-256、JCS 均为真实实现。
- [x] RFC 7638 kid、AAD、GCM AAD、两项 binding 有硬编码字节向量。
- [x] Outer/inner duplicate、unknown、type、null、trailing、canonical Base64URL 和 size limit 负例全绿。
- [x] AAD、unwrap、GCM、inner、两项 binding 独立 tamper 均不返回 payload。
- [x] API/SPI production surface 不再返回 raw private-key bytes。
- [x] API lease 关闭 owned handles；protocol flow 不关闭 borrowed static handles。
- [x] CEK、KEK、shared secret、decrypted inner 临时数组在成功/失败路径清零。
- [x] 没有 Ed25519、Hybrid、obfuscation flow、Armor 或 API facade 越界实现。
- [x] JDK 17 `mvn -q clean test`、`git diff --check` 通过。
- [x] Spec review 与 code/security review 无未处理 P0/P1。
- [x] 阶段结果在本次交付中报告给用户，阶段 2 尚未开始。

## 14. 阶段 1 后置债务与阶段 2 建议

不阻塞阶段 1、默认后置的 hardening：

- `OuterAad.gcmInput` 显式拒绝非 ASCII / 非 Base64URL 输入，避免依赖当前主链的不可达前提。
- outer protected decoded bytes 改为显式 strict UTF-8 decoder，避免依赖后续字段校验拒绝替换字符。
- `JacksonOuterWireWriter` 缩窄 `RuntimeException` 包装范围，保留调用方模型错误的诊断精度。
- 统一处理含 `byte[]` record 的值相等语义、`OuterJsonMapper` 的少量重复防御复制，以及第三方 provider 严重违约时的额外 alias/异常防御。
- parser/package 命名、通用算法注册、性能与并发优化继续留到完整 Demo 后，除非后续阶段证明其阻塞协议正确性。

阶段 2 建议只增加 `public × X25519 × signed`：strict flattened JWS inner、Ed25519 exact signing input、可信 sender signing-key resolver、验签与 `SIGNED_VALID`，并保持本阶段 unsigned 全量回归。阶段 2 不同时引入 Hybrid、obfuscation、Armor 或 API facade；开始前等待用户确认并另写阶段子计划。
