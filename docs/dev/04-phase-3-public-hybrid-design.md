# WindLetter Phase 3 Public Hybrid 设计

> 状态：用户已批准 ML-KEM kid 决议并授权在没有其他阻塞时进入开发；本文经独立审查通过并完成可执行子计划后，作为阶段 3 的设计基线。

## 1. 目标与范围

阶段 3 只完成以下两条新链路：

- `public × X25519ML-KEM-768 × unsigned`
- `public × X25519ML-KEM-768 × signed`

两条链路都必须使用真实 Bouncy Castle X25519、ML-KEM-768、HKDF-SHA256、A256KW 和 A256GCM，实现真实 JSON wire 的多收件人端到端收发；Ed25519 只用于 signed 分支，unsigned 分支不得调用签名能力。

本阶段不做：

- obfuscation 与 padding；
- Armor；
- `windletter-api` facade 接线；
- testkit 对外向量发布；
- signed/unsigned 或 X25519/Hybrid 的通用框架重构；
- 性能、并发和工业化扩展设计。

## 2. 权威协议决议

正式协议末尾的“开发修订”已经冻结 ML-KEM-768 公钥 kid：

```text
kid_raw = SHA-256(pk_mlkem768_raw)
kid.mlkem768 = BASE64URL_NO_PADDING(kid_raw)
```

其中 `pk_mlkem768_raw` 必须恰好是 FIPS 203 的 1184 字节原始公钥。哈希输入不得是 JWK、JSON、DER、PEM、SPKI，也不得带算法名、长度或其他前后缀。

Sender 必须从实际用于 encapsulation 的 ML-KEM 公钥重新派生 kid。Receiver 的本地成对密钥记录也必须从 handle 对应公钥重新派生并核对 kid。调用方提供的 kid 只能作为查找提示，不能替代公钥绑定验证。

X25519 和 Ed25519 kid 继续使用现有 RFC 7638 JWK Thumbprint 规则。

## 3. Hybrid 密码学主链

每个收件人独立计算：

```text
SS_ECC = X25519(sender_static_private, recipient_x25519_public)
(ek, SS_PQ) = ML-KEM-768.Encaps(recipient_mlkem768_public)
Z = SS_ECC || SS_PQ

KEK = HKDF-SHA256(
  salt = UTF8("wind"),
  ikm  = Z,
  info = UTF8("WindLetter v1 KEK | X25519ML-KEM-768"),
  L    = 32
)

encrypted_key = A256KW(KEK, common_CEK)
```

约束：

- `SS_ECC` 与 `SS_PQ` 都必须恰好 32 字节；
- 拼接顺序只能是 ECC 在前、PQ 在后；
- 每个 recipient 必须独立 encapsulate，不能复用 `ek`、`SS_PQ` 或 KEK；
- 同一封消息仅 CEK、IV 和 outer ciphertext 在收件人之间共享；
- `ek` 为 1088 字节，`encrypted_key` 为 40 字节。

## 4. 组件边界

### 4.1 ML-KEM secret ownership

现有 `MLKem768Encapsulation` record 会长期保存 shared secret，无法主动销毁。阶段 3 保留其 record 形态、类名和访问器含义，并让它实现 `AutoCloseable`：

- 构造和访问继续 defensive copy；
- `close()` 幂等清零内部 shared-secret 数组；
- ciphertext 是公开传输材料，close 不销毁它；
- close 后 `sharedSecret()` 只能取得已清零内容，调用方不得再使用该结果；
- Bouncy Castle adapter 在构造返回值后清零 provider 临时 secret/ciphertext 副本；
- protocol flow 使用 try-with-resources，并清零从访问器取得的 secret 副本。

该改动先作为独立 crypto 安全实现与验证闭环完成，不与 Hybrid flow 混在同一闭环。

### 4.2 Key ID

新增 `MLKem768KeyId`，职责只有：

- 接受恰好 1184 字节的原始公钥；
- 计算 SHA-256；
- 返回无 padding 的 canonical Base64URL；
- 不保留输入快照；
- 通过硬编码固定向量锁定字节公式。

### 4.3 Hybrid KEK deriver

新增 `PublicHybridKekDeriver`，集中负责：

- Sender：X25519 agreement、ML-KEM encapsulation、`Z` 拼接和 HKDF；
- Receiver：X25519 agreement、ML-KEM decapsulation、相同 `Z` 和 HKDF；
- 校验 provider 返回长度；
- 在成功和失败路径清零 `SS_ECC`、`SS_PQ`、`Z` 和中间副本；
- Sender 通过可关闭结果对象交付 32 字节 KEK 和 1088 字节 `ek`；
- 不关闭调用方借用的 X25519/ML-KEM private handles。

### 4.4 Recipient builder

新增 `PublicHybridRecipientBuilder`。每个输入必须是一个不可拆分的：

```text
(recipient X25519 public key, recipient ML-KEM-768 public key)
```

Builder 从两把实际公钥派生两个 kid，调用 Hybrid deriver，使用得到的 KEK 包装同一个 CEK，并输出：

```json
{
  "kid": {
    "x25519": "...",
    "mlkem768": "..."
  },
  "ek": "1088 bytes before Base64URL",
  "encrypted_key": "40 bytes before Base64URL"
}
```

重复的完整 key pair/kid pair 必须在 Sender 构建阶段拒绝。不同收件人不得共享可变数组。

### 4.5 Paired routing

新增 Hybrid 专用 router，不复用只按 X25519 kid 工作的 `PublicKidRouter`。

本地候选是原子记录：

```text
(X25519PrivateKeyHandle, MLKem768PrivateKeyHandle)
```

Router 先完整检查本地候选并建立 `(x25519Kid, mlkem768Kid) -> borrowed handle pair` map：

1. 从两个 handle 读取公钥快照；
2. 分别重算 X25519 kid 和 ML-KEM kid；
3. 拒绝重复的本地完整 pair；
4. 清零公钥快照；
5. 不关闭借用 handles。

随后按 wire 顺序完整扫描 recipients，只在一个 entry 的两个 kid 同时匹配本地 map 时记录候选；扫描完成、确认不存在重复 wire pair 后，返回 wire 顺序中的第一个不同 pair 命中。

Router 必须拒绝重复的本地完整 key/kid pair，也必须拒绝不可信 wire 中重复出现并命中本地的完整 kid pair。多个不同本地 pair 分别命中不同 wire entries 时，固定选择 wire 顺序中的第一个，不继续尝试后续 entry；这样与现有 public router 的确定性选择一致，也避免失败后回退到另一密钥形成额外 oracle。

没有完整 pair 命中才是 `NOT_FOR_ME`。X25519 kid 单独命中、ML-KEM kid 单独命中或来自两条本地记录的交叉命中都不得进入 decapsulation。

### 4.6 Sender/Receiver flow

阶段 3 新增四个 Hybrid 专用 flow：

- `PublicHybridUnsignedSender`
- `PublicHybridUnsignedReceiver`
- `PublicHybridSignedSender`
- `PublicHybridSignedReceiver`

它们复用现有 strict outer parser、AAD、binding、inner codec、GCM、签名 key resolver 与认证结果类型，但不先抽取通用算法策略或基类。这样可以限制对阶段 1/2 已封板链路的回归面。

## 5. 精确门序

Sender：

```text
validate request/profile
→ generate one CEK and IV
→ build Hybrid protected header
→ independently build all Hybrid recipients
→ compute recipients AAD and outer binding
→ build unsigned or signed inner
→ signed branch signs SignedInnerCodec.Prepared 生成的 exact protected_b64 + "." + payload_b64
→ A256GCM encrypt
→ serialize real outer JSON
→ clear owned secrets/temporaries
```

Receiver：

```text
strict outer parse/profile
→ AAD consistency
→ paired recipient routing
→ resolve sender X25519 public key and rederive its kid
→ X25519 agreement
→ ML-KEM decapsulation of matched entry.ek
→ Z = SS_ECC || SS_PQ
→ Hybrid HKDF
→ CEK unwrap
→ A256GCM decrypt
→ strict unsigned/signed inner parse
→ inner/outer binding
→ signed branch resolves trusted Ed25519 key and verifies exact received protected_b64 + "." + payload_b64 bytes
→ return payload and authentication result
```

任何失败都不得返回 payload 或认证身份。

## 6. 错误语义

- strict wire shape、字段条件或长度错误：沿用 parser 的 malformed/invalid-field 语义；
- 没有完整 recipient key pair 命中：`NOT_FOR_ME`；
- sender X25519 resolver 查无对应 kid、返回错误长度或返回公钥与 protected kid 不绑定：沿用阶段 1/2 的 `INVALID_FIELD`；resolver 自身抛异常或返回 null Optional 才是 `INTERNAL_ERROR`；
- 无关的真实 ML-KEM handle 因完整 pair kid 不匹配，在 routing 阶段得到 `NOT_FOR_ME`，且不得调用 decapsulation；
- pair 已匹配但 `ek` 并非封装给该 ML-KEM 公钥、ML-KEM 隐式拒绝后的 A256KW failure，以及攻击者输入可能触发的 decapsulation/unwrap exception：统一为 `KEY_UNWRAP_FAILED`，使用相同的泛化 message 且不附带可区分 cause；
- attacker-controlled sender X25519 公钥导致的 low-order/agreement failure 同样属于泛化 `KEY_UNWRAP_FAILED`；closed/foreign/wrong-provider recipient handle 等本地使用错误属于 `INTERNAL_ERROR`；
- Hybrid HKDF 的输入长度全部由本地流程固定，因此 HKDF 抛异常、返回 null 或错误长度属于 provider contract failure，映射为 `INTERNAL_ERROR`；
- GCM、binding、signature：沿用现有独立错误码；
- 本地 recipient handle 返回错误长度、同一原子 pair 的 kid/public-key 记录不一致、crypto provider 返回 null/错误长度等 contract failure：`INTERNAL_ERROR`。

Phase 3 的 protocol flow 仍保留 `KEY_UNWRAP_FAILED`、`GCM_AUTH_FAILED`、`BINDING_FAILED` 和 `SIGNATURE_INVALID` 等内部受控诊断码；本阶段只保证调用者不能通过 code、message 或 cause 区分“ML-KEM decapsulation”与“A256KW unwrap”。未来接通 `windletter-api` facade 时，再按正式公开错误模型把除 `NOT_FOR_ME` 外的无效消息统一映射为公开的 invalid-message 结果。

## 7. 测试策略

必须新增并锁定：

- ML-KEM owned result 的 defensive copy、幂等 close、close 后访问和清零；
- ML-KEM kid 固定向量、长度和 canonical Base64URL；
- Hybrid HKDF 固定向量，证明 `SS_ECC || SS_PQ` 顺序、salt、info 和输出长度；
- 真实 ML-KEM encapsulate/decapsulate 后 Sender/Receiver KEK 相同；
- 两个以上不同 Hybrid recipients 的 `ek` 独立；
- paired router 的完整命中、单边命中、交叉错配、unrelated、重复本地 pair 和重复 wire pair；
- unsigned 与 signed 的 binary payload（包含 `0x00` 与非 UTF-8 字节）真实 wire 多收件人 E2E；
- 目标 recipient 位于 wire 首、中、尾位置时都能恢复同一 payload，完全无关的本地 pair 为 `NOT_FOR_ME`；
- 篡改 `ek`、matched pair 搭配不属于该 ML-KEM 公钥的 `ek`、交换两个 recipient 的 `ek`、unrelated PQ handle、错误 kid、authenticated binding/signature tamper；其中 unrelated handle 必须在 routing 阶段得到 `NOT_FOR_ME` 且不 decapsulate，matched-pair `ek` 错配必须得到泛化 `KEY_UNWRAP_FAILED`；
- Hybrid required/forbidden 条件字段、kid 与 `ek` 的 strict/canonical Base64URL 和长度负例回归；
- 阶段 1/2 全回归和完整 JDK 17 reactor gate。

测试不得用 mock 替代 X25519、ML-KEM、HKDF、A256KW、GCM 或 Ed25519 主链。tracking provider 只用于验证失败顺序、清零和 borrowed-handle ownership。

同时继承整体计划的通用 gate：focused test 与 module/reactor test 都必须通过；测试总量不得减少；不得新增 `@Disabled`、skip 或弱化断言；`git diff --check` 必须通过；提交前必须核对实际变更文件只属于当前闭环。

## 8. 完成门禁

阶段 3 只有同时满足以下条件才可封板：

- public 的 `2 algorithms × 2 signing modes` 四组合全部通过真实 JSON wire E2E；
- 至少两个不同 Hybrid recipients 只持有自己的 paired private handles 即可解密同一条 wire；
- 每项 `ek` 都来自独立真实 encapsulation；
- kid、combiner/HKDF、AAD、binding、unwrap、GCM 和签名均有正负例；
- binary payload、收件人在首/中/尾、non-recipient、Hybrid strict conditional/canonical/length 矩阵均通过；
- 失败不泄露 payload/identity，且 direct flow 的 code/message/cause 不能区分 decapsulation 与 unwrap；
- borrowed handles 不被关闭，owned secrets 可验证地 best-effort 清零；
- focused、module 与全仓 JDK 17 测试通过，测试总量不减少，无新增 disabled/skipped/弱断言，`git diff --check` 与变更范围核对通过；
- spec review 和 code/security review 通过；
- 没有开放 P0/P1；
- P2 全部登记进阶段完成报告；
- 更新总体计划后停止，等待用户确认下一阶段。

## 9. 明确后置的 P2

- 抽取 X25519/Hybrid 与 signed/unsigned 的共享 flow orchestration；
- 为 byte-array value types 统一 content-based equality；
- 定义并发 close/operation 行为；
- 把 Hybrid 固定向量发布到 `windletter-testkit`；
- API facade 接通前统一 API DTO 中外部 kid 与公钥的绑定策略；
- 进一步减少公开密钥和 immutable string 的临时副本。
