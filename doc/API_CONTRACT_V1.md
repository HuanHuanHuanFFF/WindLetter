# WindLetter v1.0 API 契约（工业化接口设计）

## 1. 目标

定义 WindLetter v1.0 的稳定对外接口，确保：

- 协议能力完整暴露（public/obfuscation + signed/unsigned + rid/填充）。
- 内部实现可替换（算法库、序列化细节可演进）。
- 调用方获得稳定、可预期的输入输出与错误语义。

## 2. 设计原则

- `MUST` 面向场景 API，而非暴露协议内部可变结构。
- `MUST` 将策略参数显式化（mode、keyAlg、signingOption）。
- `MUST` 区分“不是给我”与“消息无效”。
- `SHOULD` 保持幂等和不可变值对象（request/result/message）。

## 3. 核心枚举与值对象

### 3.1 枚举

- `WindMode`
  - `PUBLIC`
  - `OBFUSCATION`

- `KeyAlgProfile`
  - `X25519`
  - `X25519_ML_KEM_768`

- `SigningOption`
  - `SIGNED`
  - `UNSIGNED`

- `ArmorFormat`
  - `NONE`
  - `BASE64URL`
  - `WIND_BASE_1024F_V1`
  - `BINARY`

- `VerificationStatus`
  - `SIGNED_VALID`
  - `UNSIGNED`
  - `NOT_APPLICABLE`
  - `FAILED`

- `DecryptStatus`
  - `SUCCESS`
  - `NOT_FOR_ME`
  - `INVALID_MESSAGE`
  - `UNSUPPORTED`

### 3.2 消息对象

- `EncryptedMessage`
  - `String wireJson`（必填）
  - `String armor`（文本封装时可选）
  - `byte[] armorBytes`（二进制封装时可选）
  - `ArmorFormat armorFormat`（默认 `NONE`）
  - 说明：仅承载稳定外部表示，不暴露内部协议实体。

- `Payload`
  - `String contentType`
  - `byte[] data`
  - `long originalSize`

## 4. 发送 API

### 4.1 接口

- `WindLetterSender`
  - `EncryptedMessage encrypt(EncryptRequest req)`
  - `EncryptedMessage encryptAndSign(EncryptAndSignRequest req)`

### 4.2 请求对象约束

- `EncryptRequest`
  - `WindMode mode`
  - `KeyAlgProfile keyAlgProfile`
  - `ArmorFormat armorFormat`（可选，默认 `NONE`）
  - `Payload payload`
  - `List<RecipientRef> recipients`
  - `Map<String, Object> customHeaders`（可选，受白名单控制）

- `EncryptAndSignRequest` 继承 `EncryptRequest`
  - `SigningIdentityRef senderSigningIdentity`

通用约束：

- `mode/keyAlgProfile/payload/recipients` 必填。
- `recipients` 非空，且在混淆模式满足桶策略约束（真实人数 `<= 32`）。
- unsigned 模式不得传签名身份。

## 5. 接收 API

### 5.1 接口

- `WindLetterReceiver`
  - `DecryptResult decrypt(DecryptRequest req)`
  - `DecryptResult decryptAndVerify(DecryptRequest req)`

### 5.2 请求对象

- `DecryptRequest`
  - `String wireJson` / `String armor` / `byte[] armorBytes`（至少一项）
  - `ArmorFormat armorFormat`（可选；有 armor 时可指定格式，不指定则自动识别）
  - `RecipientIdentityRef myIdentity`
  - `VerificationPolicy verificationPolicy`（可选，默认按 `cty` 自动）

## 6. 结果对象与错误语义

### 6.1 `DecryptResult`

- `DecryptStatus status`
- `Payload payload`（仅 `SUCCESS` 时存在）
- `SenderIdentity senderIdentity`（可选，signed 成功时存在）
- `VerificationStatus verificationStatus`
- `ErrorCode errorCode`（非成功时可选）
- `String messageId`（来自 `wind_id`，成功时可选）
- `Long timestamp`（来自 `ts`，成功时可选）

### 6.2 错误分类（对外）

- `NOT_FOR_ME`：
  - public: 未命中本地 recipient kid
  - obfuscation: 全部 rid 不命中

- `INVALID_MESSAGE`：
  - AAD 不一致、GCM 失败、绑定失败、验签失败、字段违规等

- `UNSUPPORTED`：
  - 版本/算法/profile 不支持

要求：

- `MUST` 不把内部失败步骤直接回显到外部错误文本。
- `SHOULD` 通过内部诊断码记录详细原因，外部仅给稳定语义。

## 7. 密钥与身份服务契约

### 7.1 `RecipientKeyStore`

职责：

- 通过 recipient 标识解析静态解密私钥（X25519、ML-KEM）。
- 支持多键命中与轮换场景。

行为：

- 查无此键：返回空，不抛业务异常。
- 多键命中：按策略返回主键或报配置异常（实现可配置）。

### 7.2 `IdentityService`

职责：

- 发送侧：解析发件人加密/签名身份及私钥材料。
- 接收侧：解析签名 `kid` 对应公钥并校验可信域。

行为：

- 解析失败归类为 `UNSUPPORTED` 或 `INVALID_MESSAGE`，不得泄露敏感细节。

## 8. 序列化与 wire 契约

- `MUST` 输出协议定义字段名，不得自定义重命名。
- `MUST` 对 `recipients` 使用 JCS 计算 `aad`。
- `MUST` 绑定 `jwe_protected_hash/jwe_recipients_hash`。
- `MUST` signed/unsigned 严格按 `cty/typ` 和字段存在性切换。
- `MUST` 保持 v1.0 白名单限制。

## 9. 兼容与演进

- v1.0 API 允许新增字段/可选参数，避免破坏现有方法签名。
- 新算法通过新增 `KeyAlgProfile` 引入，不改变已有 profile 语义。
- 不同版本协议通过 version gate 控制，不共用隐式行为。

## 10. 非目标

- 不提供网络匿名传输能力。
- 不承诺前向安全（与协议 §9 一致）。
- 不提供密钥托管策略实现，仅定义接口契约。

---

协议依据：`doc/Wind Letter v1.0协议.md`（重点：§1~§9）。
