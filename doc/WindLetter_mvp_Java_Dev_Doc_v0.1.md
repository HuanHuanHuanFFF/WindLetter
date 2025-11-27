# Wind Letter MVP Java 基础库开发文档（mvp）

> 面向实现者 / AI 开发助手的**开发说明书**。  
> 目标：根据本开发文档 +《WindLetter_v1_spec_final.md》即可直接用 Java 实现一套可互操作的 Wind Letter v1 基础库，并完成自检测试。

---

## 0. 元信息

- 文档名称：Wind Letter MVP Java 基础库开发文档
- 版本：mvp
- 协议版本：Wind Letter v1.0
- 作者：幻風（设计） / AI（整理）
- 目标语言：Java（JVM 平台；后续可用 Kotlin 调用）
- 适用场景：本地加密聊天 / 日记等应用的**协议实现与验证**（不包含 UI 与网络传输）

---

## 1. 文档目的与范围

### 1.1 目的

本开发文档给出 **Wind Letter v1.0** 协议在 Java 语言上的**最小可用实现方案**，包括：

1. 协议要求的线格式（JWE + 内嵌 JWS）的映射模型；
2. 必须实现的密码学操作（ECC + PQC + AEAD）；
3. 建议的模块划分与对外 API 能力；
4. 自检与互操作测试的基本要求。

目标是：**实现者只要严格按本开发文档 + 协议规范编码，即可获得一套安全、可互通的基础库**，用于后续聊天应用 / 加密存储等上层产品。

### 1.2 范围（本迭代 mvp）

本次开发仅实现：

- 协议线格式：  
  - 外层：**JWE JSON**（唯一传输对象）；  
  - 内层：**JWS JSON**（放在 JWE 密文里）；
  - 可选：聊天用 JSON-Armor / 文本 Armor。
- 安全算法组合（**写死白名单**）：
  - 对称加密（AEAD）：`A256GCM`（AES-256-GCM）；
  - ECC：
    - 密钥交换 / KEM：X25519（曲线为 OKP, crv = "X25519"）；
    - 签名：Ed25519（JWS.alg = "EdDSA"）；
  - PQC：
    - KEM：`ML-KEM-768`（Kyber-768 对应的 Java 实现，使用 BouncyCastle PQC）。
- 收件人模式：
  - 必须支持：`wind_mode = "public"`；
  - 可为后续预留：`wind_mode = "obfuscation"`（混淆收件人），本迭代可以只做占位与解析。

不在本迭代范围：

- PQC 签名算法（如 Dilithium/Falcon）；
- UI、网络层协议（WebSocket/HTTP 等）；
- 密钥备份恢复、账号系统；
- 高级混淆策略参数（如“真实人数 vs 假收件人”调节公式，仅在 風笺设计文档中说明，库层只需预留）。

---

## 2. 参考规范与“真值表”

本开发文档依赖以下规范文件，它们是**协议真值表**，开发中如有冲突，以这些规范为准：

1. **《WindLetter_v1_spec_final.md》**  
   - 描述 Wind Letter v1 的正式线格式、字段含义、AEAD + JWS 绑定方式，以及安全硬规则。
2. **《WindLetter JSON示例.md》**  
   - 提供从 Armor → JWE → JWS → payload 的完整 JSON 结构示意。
3. **《風笺设计.md》**  
   - 提供 WindBase1024F、自定义编码、混淆收件人模式等设计背景。

实现要求：

- 任何字段、算法标识、验证规则，都必须与上述规范保持一致；
- 若本开发文档与规范描述发生矛盾，**优先以《WindLetter_v1_spec_final.md》为准**，并修改代码与本开发文档。

---

## 3. 技术选型与安全硬约束

### 3.1 运行环境

- Java 版本：**JDK 17**（如需兼容安卓，可限制使用更低级 API，但本版以 17 为基线）
- 构建工具：Maven 或 Gradle（二选一即可）
- 目标平台：桌面 / 服务器 / Android（后续可用 Kotlin 封装）

### 3.2 密码学库

必须使用工业成熟库，不允许自己重写算法原语：

- 随机源：
  - `java.security.SecureRandom`
- 对称加密 / AEAD：
  - AES-256-GCM，可优先使用 JDK 内置 JCE 实现；
  - 如需兼容性，可考虑 BouncyCastle Provider。
- ECC：
  - X25519（密钥交换）：BouncyCastle `X25519` 实现；
  - Ed25519（签名）：BouncyCastle `Ed25519` 或 JDK 17 标准提供的 EdDSA 实现。
- PQC（KEM）：
  - ML-KEM-768（Kyber-768），建议使用 BouncyCastle PQC 模块。
- 哈希与 KDF：
  - SHA-256：JDK `MessageDigest`；
  - HKDF-SHA256：可使用成熟实现或在可信参考实现基础上移植。
- 压缩（可选）：
  - Zstd：可接入 `zstd-jni` 等成熟库，用于 `"zip": "zstd"`。
- CRC32C：
  - 用于 Armor `checksum` 字段，可使用 Guava 或自行调用 Java 标准库的 CRC32C 实现。

### 3.3 安全硬规则（实现时必须写死）

与《WindLetter_v1_spec_final》保持一致：

1. **算法白名单**（任何不在列表内的算法都直接拒绝）：
   - JWE.enc：仅 `"A256GCM"`；
   - recipients[*].header.alg：仅 `"ECDH-ES+A256KW"`（X25519）与 `"ML-KEM-768"`；
   - JWS.alg：仅 `"EdDSA"`（Ed25519）。
2. **CEK / IV 规则**：
   - 每条消息 CEK 必须为 32 字节新随机；
   - IV 长度 12 字节；  
     - 生成方式：`iv = HKDF-SHA256(CEK, salt=0x00, info="wind+jwe/iv/v1" || wind_id)[0..11]`；
     - 写入 JWE.iv，解密端直接使用 `jwe.iv`，不必重复派生；
     - **同一 CEK 下决不可复用 iv**。
3. **JSON 规范化（JCS）**：
   - 参照 RFC 8785；
   - 用于：`outer.protected_json`、`recipients` 以及 `pht/rch` 的计算；
   - 需要严格实现：键排序、数字/字符串表示、空白处理等。
4. **AAD 规则**：
   - `aad_b64 = BASE64URL( JCS(recipients) )`；
   - `AAD_bytes = ASCII(jwe.protected) + "." + ASCII(aad_b64)`；
   - 解密端必须重新计算 aad_b64 并与报文中的 aad 字段比较（不一致直接拒绝）。
5. **签名绑定规则**：
   - `pht = BASE64URL( SHA256( JCS(outer.protected_json) ) )`；
   - `rch = BASE64URL( SHA256( JCS(outer.recipients) ) )`；
   - JWS.protected 中必须包含 `pht` 和 `rch` 字段；
   - 验签前需重新计算并常量时间比较。
6. **比较方式**：
   - 对 `tag`、`pht`、`rch`、签名结果等敏感字节串使用**常量时间比较**。
7. **错误对外信息**：
   - 对上层/用户统一报告「Invalid message」或等价的模糊错误；
   - 详细错误类别仅在日志或调试模式下使用（注意不泄露密钥和敏感内容）。

---

## 4. 模块划分与职责

建议按功能拆分为以下逻辑模块（具体包名/类名开发时可以调整，但职责需保持）：

### 4.1 `crypto` 模块：密码原语与密钥管理

**职责：**

- 提供所有密码学基本操作：
  - 生成随机字节；
  - 生成 ECC / PQC 密钥对；
  - 计算 SHA-256 / HKDF-SHA256；
  - 执行 X25519 ECDH、ML-KEM-768 封装/解封；
  - 执行 Ed25519 签名与验签；
  - 执行 AES-256-GCM 加解密；
  - 常量时间比较。

**核心类型（示例）**

- `WindRandom`：封装 `SecureRandom`；
- `EccKeyPair`, `EccPublicKey`, `EccPrivateKey`；
- `PqcKemKeyPair`, `PqcKemPublicKey`, `PqcKemPrivateKey`；
- `WindCek`：会话对称密钥（32 bytes）；
- `WindHash`：SHA-256/HKDF 封装；
- `WindAead`：AES-GCM 封装；
- `CryptoException`：密码级错误。

### 4.2 `jcs` 模块：JSON 规范化

**职责：**

- 实现 RFC 8785 JSON Canonicalization Scheme；
- 提供从任意对象 / JSON 字符串 → 规范化 JSON 字符串 → UTF-8 字节的流程。

**核心接口（示例）**

- `String canonicalize(Object jsonTree)`
- `String canonicalize(String jsonText)`
- `byte[] canonicalizeToUtf8(Object jsonTree)`

### 4.3 `model` 模块：数据模型（POJO）

**职责：**

- 映射协议中所有 JSON 对象到 Java 类：
  - JWE：
    - `WindJwe`；
    - `Recipient`, `RecipientHeader`；
  - JWS：
    - `WindJws`；
    - `JwsProtectedHeader`；
  - Payload：
    - `WindPayloadMeta`, `WindPayloadBody` 等；
  - Armor：
    - `WindArmorJson`, `WindArmorText` 等（也可以只用轻量结构）。

**字段映射示例**

```java
class WindJwe {
    String protectedB64;
    String aad;
    List<Recipient> recipients;
    String iv;
    String ciphertext;
    String tag;
}

class Recipient {
    RecipientHeader header;
    String encryptedKey;
}

class RecipientHeader {
    String kid;   // 或 rid（obfuscation 模式）
    String alg;   // "ECDH-ES+A256KW" / "ML-KEM-768"
    Epk epk;
}

class Epk {
    String kty;   // 固定 "OKP"
    String crv;   // 固定 "X25519"
    String x;     // Base64URL 编码公钥
}
```

JWS：

```java
class WindJws {
    String protectedB64;
    String payloadB64;
    String signatureB64;
}

class JwsProtectedHeader {
    String typ;     // "wind+jws"
    String alg;     // "EdDSA"
    String kid;     // Base64URL(sender-kid)
    Long ts;        // 可选
    String pht;     // Base64URL(SHA256(JCS(outer.protected_json)))
    String rch;     // Base64URL(SHA256(JCS(outer.recipients)))
}
```

Payload（示例，可扩展）：

```java
class WindPayload {
    Meta meta;
    Body body;
}

class Meta {
    String contentType;  // "text/utf-8"
    Long originalSize;   // 原始字节长度
}

class Body {
    String type;         // "text" / "binary" / ...
    String text;         // 当 type="text" 时
    // 后续可扩展字段
}
```

### 4.4 `encode` 模块：Base64URL & WindBase1024F

**职责：**

- 提供统一的编码工具：
  - Base64URL 编解码；
  - WindBase1024F 编解码（可分阶段实现：mvp 只需定义接口与占位实现，内部可以暂时调用 Base64URL）；
- 为 Armor 与 JSON 字段服务。

**接口示例**

```java
interface WindEncoding {
    String base64UrlEncode(byte[] data);
    byte[] base64UrlDecode(String text);

    String windBase1024fEncode(byte[] data); // TODO: v1.1 实现
    byte[] windBase1024fDecode(String text); // TODO: v1.1 实现
}
```

### 4.5 `jwe` 模块：外层封装与解封装

**职责：**

- 负责构造 / 解析 JWE 对象；
- 负责 recipients、aad、iv、ciphertext、tag 的一致性；
- 不关心具体 Payload 业务内容，仅视其为“JWS 字节串”。

核心能力：

- `WindJwe buildJwe(WindJws innerJws, List<RecipientPublicInfo> recipients, WindMode mode)`
- `DecryptResult decryptJwe(WindJwe jwe, RecipientKeyStore keyStore)`

### 4.6 `jws` 模块：内层签名与验签

**职责：**

- 根据外层 JWE，构造受约束的 JWS 对象：
  - 负责计算 `pht` / `rch`；
  - 负责 Base64URL(protected/payload) 与签名计算；
- 提供验签接口。

核心能力：

- `WindJws signPayload(WindPayload payload, JwsSigningContext ctx)`  
  - `ctx` 中包含：发送者私钥、outer.protected_json、outer.recipients 等。
- `VerifyResult verifyJws(WindJws jws, JwsVerifyContext ctx)`

### 4.7 `armor` 模块：聊天装甲与纯文本 Armor

**职责：**

- 根据《WindLetter_v1_spec_final》中的 §16：
  - 实现 JSON-Armor；
  - 实现 PGP 风格纯文本 Armor；
- `type` 固定为 `"wind-letter"`；
- `encoding` 支持 `"base64url"`，预留 `"windbase1024f"`。

核心能力：

- `String toJsonArmor(String jweJson, ArmorEncoding encoding)`
- `String fromJsonArmor(String armorJson)`
- `String toTextArmor(String jweJson, ArmorEncoding encoding)`
- `String fromTextArmor(String armorText)`

### 4.8 `api` 模块：对外高级接口

**职责：**

- 面向上层应用（聊天/日记），提供**少量高层 API**：
  - 生成身份；
  - 发送（加密+签名）消息；
  - 接收（解密+验签）消息；
  - 自检。

接口示例见第 8 章。

### 4.9 `testkit` 模块：自检与互操作测试

**职责：**

- 提供一键自检入口，如 `WindLetter.selfCheck()`；
- 提供加载测试向量（JSON 文件）的工具；
- 实现规范中 §13 的篡改失败用例。

---

## 5. 数据模型与 JSON 映射细节

本节强调**线格式 ↔ Java 模型映射时的细节要求**。

### 5.1 仅传输 JWE 一层

- 网络上传输的**唯一对象**为 JWE JSON（以及可选的 Armor 外壳）；
- 内层 JWS 与 payload 不直接出现在传输层。

### 5.2 JSON 字段命名与类型

严格遵守《WindLetter_v1_spec_final》中的命名：

- 外层 JWE 字段：
  - `protected`：字符串，Base64URL；
  - `aad`：字符串，Base64URL；
  - `recipients`：数组；
  - `iv`：字符串，Base64URL；
  - `ciphertext`：字符串，Base64URL；
  - `tag`：字符串，Base64URL。
- recipients[*].header：
  - `kid` 或 `rid`（二选一）；
  - `alg`：字符串；
  - `epk`：对象，`{kty, crv, x}`。
- JWS.protected（解码后）字段：
  - `typ`、`alg`、`kid`、`ts`、`pht`、`rch` 等；
- Payload：
  - 至少包含 `{ "meta": {...}, "body": {...} }` 结构，字段名与类型需与规范一致。

注意：

- 所有 JSON 序列化使用 UTF-8；
- JCS 规范化前必须确保 JSON 对象结构正确（无重复键等）。

---

## 6. 密码流程实现说明（发送 / 接收）

本节是对《WindLetter_v1_spec_final》中 §5 和 §6 的**实现化版本**。

### 6.1 发送流程（伪代码）

输入：

- `payload`：业务明文对象 `WindPayload`；
- `senderSignKey`：Ed25519 私钥；
- `recipients`：一组收件人公钥（包含 ECC X25519 和/或 PQC ML-KEM-768 公钥）；
- `windMode`：`public` 或 `obfuscation`（本迭代可优先实现 `public`）。

步骤：

1. 生成随机 `CEK`（32B）与 `wind_id`（128 bit 随机）。
2. 组装 `protected_json`：

   ```json
   {
     "typ": "wind+jwe",
     "cty": "wind+jws",
     "ver": "1.0",
     "wind_mode": "public",
     "enc": "A256GCM"
   }
   ```

3. 对 `protected_json` 做 JCS → UTF-8 → Base64URL，得到 `protected_b64`。
4. 依据收件人列表构造 `recipients` 数组：
   - 对于 ECC 收件人：
     - 生成临时 X25519 `epk`；
     - 使用 ECDH-ES+A256KW 语义封装 CEK 为 `encrypted_key`；
     - 构造 `header = { "kid": ..., "alg": "ECDH-ES+A256KW", "epk": {...} }`。
   - 对于 PQC 收件人：
     - 使用 ML-KEM-768 封装 CEK 为 `encrypted_key`；
     - 构造 `header = { "kid": ..., "alg": "ML-KEM-768", "epk": {...?} }`（如算法本身无 epk，可按规范定义存放 sender 侧临时信息或省略）。
5. 计算 `aad_b64 = BASE64URL( JCS(recipients) )`。
6. 拼接 `AAD_bytes = ASCII(protected_b64) + "." + ASCII(aad_b64)`。
7. 构造内层 JWS：
   1. 将 `payload` 序列化为 JSON 文本 `payload_json`；
   2. 计算：
      - `pht = BASE64URL( SHA256( JCS(outer.protected_json) ) )`；
      - `rch = BASE64URL( SHA256( JCS(outer.recipients) ) )`；
   3. 构造 `jws_protected_json`：

      ```json
      {
        "typ": "wind+jws",
        "alg": "EdDSA",
        "kid": "BASE64URL(sender-kid)",
        "ts": 1731800000,
        "pht": "...",
        "rch": "..."
      }
      ```

   4. 规范化并 Base64URL 得到 `jws_protected_b64`；
   5. `payload_b64 = BASE64URL( UTF8(payload_json) )`；
   6. 签名输入：`sign_input = ASCII(jws_protected_b64 + "." + payload_b64)`；
   7. `signature_b64 = BASE64URL( Sign_Ed25519(senderSignKey, sign_input) )`；
   8. 得到 `WindJws`。
8. （可选）根据 `"zip":"zstd"` 压缩 JWS 字节并做长度分桶填充（本迭代可默认不开启压缩）。
9. 派生 `iv = HKDF-SHA256(CEK, salt=0x00, info="wind+jwe/iv/v1" || wind_id)[0..11]`。
10. 使用 AES-256-GCM：

    ```text
    ciphertext, tag = A256GCM_Encrypt(
        key = CEK,
        iv = iv,
        aad = AAD_bytes,
        plaintext = jws_bytes
    )
    ```

11. 构造 `WindJwe`：

    ```json
    {
      "protected": protected_b64,
      "aad": aad_b64,
      "recipients": [...],
      "iv": BASE64URL(iv),
      "ciphertext": BASE64URL(ciphertext),
      "tag": BASE64URL(tag)
    }
    ```

12. 若需要 Armor，则在外层再包一层 JSON-Armor 或文本 Armor。

### 6.2 接收流程（伪代码）

输入：

- 传输过来的 JWE JSON 字符串（或 Armor 文本）；
- 本地密钥存储 `RecipientKeyStore`（包含 ECC+PQC 私钥与 kid 索引）。

步骤：

1. 若为 Armor，先解装甲得到 JWE JSON。
2. 反序列化为 `WindJwe`。
3. 校验算法白名单：
   - `enc` 必须为 `"A256GCM"`；
   - `recipients[*].header.alg` 必须属于 `{ "ECDH-ES+A256KW", "ML-KEM-768" }`。
4. 重算 `aad_expected = BASE64URL( JCS(recipients) )`，与 `jwe.aad` 比较；不一致 → 拒绝。
5. 构造 `AAD_bytes = ASCII(jwe.protected) + "." + ASCII(aad_expected)`。
6. 遍历 `recipients`，尝试解封 CEK：
   - 若 header.kid 匹配本地某个私钥：
     - 按 `alg` 调用相应 KEM / ECDH-ES+A256KW 解封，得到 CEK；
   - 若 `wind_mode = "obfuscation"` 且使用 `rid`：
     - 根据 風笺设计文档中的 SKID 计算方式，本地算出自己的 rid 与 header.rid 比对；
     - 成功匹配后再解封 CEK。
7. 使用 CEK、`jwe.iv`、`AAD_bytes` 调用 AES-256-GCM 解密：
   - 失败（tag 校验失败）→ 拒绝；
   - 成功得到内层 JWS 字节。
8. 反序列化为 `WindJws` 对象。
9. 解码 `jws.protected` 与 `payload`：
   - 得到 `JwsProtectedHeader` 与 `payload_json`；
   - 重新计算：
     - `pht_expected = BASE64URL( SHA256( JCS(outer.protected_json) ) )`；
     - `rch_expected = BASE64URL( SHA256( JCS(outer.recipients) ) )`；
   - 与 JWS 中的 `pht` / `rch` 常量时间比较；不一致 → 拒绝。
10. 根据 `kid` 查询发送者公钥，执行 Ed25519 验签；
    - 失败 → 拒绝；
    - 成功 → 信任来源。
11. 解析 `payload_json` 为 `WindPayload`，交给上层应用。

---

## 7. 对外 API 能力设计（建议）

本节给出**建议的高层 API 能力**，实现者可以在不打破语义的前提下调整类名和签名。

### 7.1 身份与密钥管理

```java
class WindIdentity {
    String windId;        // 身份 ID，用于 UI 展示/索引
    EccKeyPair signKey;   // Ed25519
    EccKeyPair kemEccKey; // X25519（如与签名分离）
    PqcKemKeyPair kemPqcKey; // ML-KEM-768
}

interface IdentityService {
    WindIdentity generateIdentity();
    void storeIdentity(WindIdentity identity);       // 本地安全存储
    WindIdentity loadIdentity(String windId);
}
```

### 7.2 发送方高层接口

```java
class WindLetterSender {

    EncryptedMessage encryptAndSign(
        WindPayload payload,
        WindIdentity sender,
        List<RecipientPublicInfo> recipients,
        WindMode mode // PUBLIC / OBFUSCATION
    ) throws WindLetterException;
}
```

- `EncryptedMessage` 持有：
  - `WindJwe` 对象；
  - 序列化后的 JWE JSON 字符串；
  - 可选：Armor 形式。

### 7.3 接收方高层接口

```java
class WindLetterReceiver {

    DecryptResult decryptAndVerify(
        String jweOrArmorText,
        RecipientKeyStore keyStore
    ) throws WindLetterException;
}
```

`DecryptResult` 包含：

- `WindPayload payload`；
- `String senderWindId`（如从 kid 映射得到）；
- `boolean signatureValid`；
- `AlgorithmProfile profile`（实际使用的 ECC/PQC 组合）等。

### 7.4 自检接口

```java
class WindLetter {

    static SelfCheckReport selfCheck();
}
```

- 自检内容见第 9 章。

---

## 8. 错误处理与日志规范

### 8.1 错误分类（内部）

可以根据需要定义错误码 / 异常类型，例如：

- `ParsingError`：JSON 格式不合法；
- `AlgorithmNotAllowedError`：算法不在白名单；
- `KeyNotFoundError`：找不到对应的私钥或公钥；
- `AeadAuthFailedError`：GCM tag 校验失败；
- `SignatureInvalidError`：JWS 验签失败；
- `BindingMismatchError`：`pht` / `rch` 不匹配；
- `ReplayDetectedError`：wind_id 已使用（如实现了去重）。

### 8.2 对外异常

- 统一封装为 `WindLetterException`；
- 对上层调用者仅暴露**较粗粒度**错误：
  - `INVALID_MESSAGE`
  - `UNSUPPORTED_ALGORITHM`
  - `KEY_MISSING`
  - 等。

### 8.3 日志

- 仅在 debug 模式下记录详细错误原因；
- 严禁在日志中打印：
  - 明文内容；
  - 私钥 / CEK / KEM 密钥材料；
  - 完整的 `encrypted_key` / `epk` 原文；
- 可以记录：
  - 算法名、字段缺失情况；
  - wind_id（如非敏感用途）；
  - 错误码。

---

## 9. 测试与验证策略

### 9.1 自检（SelfCheck）

`WindLetter.selfCheck()` 至少执行以下步骤：

1. 生成两份身份 `A` 和 `B`；
2. 用 `A` → `B` 发送一条简单文本 `"Hello, Wind-Letter!"` 的消息；
3. 使用 `B` 解密并验签：
   - 明文与原文完全一致；
   - 签名验证通过；
   - 算法组合在白名单内；
4. 再用 `B` → `A` 做一次反向测试。

返回报告内容：

- `boolean allPassed`;
- 明确的测试项列表与结果。

### 9.2 互操作黄金用例

根据规范 §13：

- 准备一组**固定测试向量**（可以写在 JSON 文件中），包括：
  - 一个完整的 JWE JSON；
  - 解密后得到的 JWS JSON；
  - payload 明文；
  - 各种 pht/rch/hash 中间值（可选）。
- 要求库实现：
  - 能解析该 JWE；
  - 解密 + 验签 + 提取明文，与测试向量完全一致；
  - 如果使用库重建该消息，生成的 JWE 在规范允许范围内**等价**（字段顺序允许不同，内容一致）。

### 9.3 篡改失败用例（负向测试）

实现以下自动化测试（任选一处 1 bit 修改 → 必须失败）：

1. 修改 JWE 中的：
   - `protected` / `recipients` / `iv` / `ciphertext` / `tag`；
   - 期望：AEAD 解密失败。
2. 修改 JWS 中的：
   - `protected` / `payload` / `signature`；
   - 期望：验签失败。
3. 修改 JWS.protected 中的：
   - `pht` 或 `rch`；
   - 期望：绑定检测失败。
4. 换壳攻击：
   - 保留内层 JWS 不变，替换外层 `protected` 或 `recipients`；
   - 期望：`pht` / `rch` 不匹配，验签失败。
5. 算法降级攻击：
   - 将 `enc` / `alg` 改为非白名单值；
   - 期望：解析阶段直接拒绝。

### 9.4 性能与资源测试（基础）

本迭代只做简单 sanity check：

- 在单机环境下发送/解密 1,000 条消息；
- 确认：
  - 无内存泄漏或异常；
  - 平均延迟在可接受范围内（如 < 10ms/条，具体视环境决定）。

---

## 10. 迭代计划（Roadmap 建议）

本开发文档对应 **Java 基础库 mvp**，建议后续迭代方向：

1. **mvp（当前）**
   - 完成 public 模式；
   - 支持 ECC + PQC（X25519 + ML-KEM-768）；
   - 实现自检与基本互操作测试。

2. **v0.2**
   - 完整实现 `wind_mode = "obfuscation"`：
     - 引入 rid / SKID 计算；
     - 支持混入虚假收件人；
     - 控制显示人数 S 与真实人数 m 的关系（参见《風笺设计.md》）。
   - 增强 TestKit：增加混淆模式测试向量。

3. **v0.3**
   - 实现 WindBase1024F 真正的 1024 进制编码；
   - 完成 JSON-Armor / Text-Armor 对 WindBase1024F 的支持；
   - 增加更多 payload 类型（文件、图片指针等）。

4. **v1.0**
   - 若需要，引入 PQC 签名（例如 Dilithium）+ Ed25519 双签；
   - 提供稳定 API 与版本化发布（Maven 中央仓库等）。

---

## 11. 实现者 Checklist（给未来的你 / AI）

在开始编码前，请确认：

- [ ] 已阅读并理解《WindLetter_v1_spec_final.md》；
- [ ] 已选定并引入 BouncyCastle（含 PQC 模块）等密码库；
- [ ] 已选定 JSON 与 JCS 实现方案；
- [ ] 已理解：**只传一个 JWE JSON，对外隐藏 JWS**；
- [ ] 已理解：`aad = BASE64URL(JCS(recipients))` 且参与 GCM AAD；
- [ ] 已理解：`pht/rch` 的绑定作用；
- [ ] 已在代码中写死算法白名单与安全硬规则；
- [ ] 已预留 Armor 与 WindBase1024F 扩展点。

做到这些，你就可以放心开写 Java 代码了——后续只需要把每一条规则翻译成测试，再让 AI 逐步补全代码即可。  

喵。

---

## 12. 实现细节注意事项（供 AI / 开发者特别关注）

在落地代码实现时，请尤其注意以下三个坑位，这些是实际 Java 生态中非常容易踩雷的点：

1. **Bouncy Castle 版本选择（PQC / ML-KEM-768）**
   - ML-KEM-768 属于较新的 PQC 算法，只有在**较新版本**的 Bouncy Castle 中才提供稳定支持。
   - 要求在 `build.gradle.kts` / `pom.xml` 中使用 **最新稳定版** Bouncy Castle（例如 `1.78` 或更高版本），否则：
     - 可能根本没有 PQC 包；
     - 或者 PQC 相关类的包名 / API 与本开发文档假设不一致。
   - 若发现 `org.bouncycastle.pqc` 相关类缺失，优先检查版本而不是“自行实现算法”。

2. **JCS 实现务必使用专用库（不要自己调 Jackson）**
   - 本项目要求严格符合 **RFC 8785 JSON Canonicalization Scheme (JCS)**。
   - Java 生态中常用的 Jackson/Gson 等 JSON 库**默认行为与 JCS 不兼容**，典型问题：
     - 数字 `1` / `1.0` 的序列化形式不稳定；
     - 字段顺序、空白处理等与规范不同。
   - 要求：
     - 直接使用现成的 `java-json-canonicalization` 或等价的 JCS 实现库；
     - 不要试图通过“配置 Jackson”来逼近 JCS，容易产生微妙不兼容，破坏签名与 pht/rch 绑定。

3. **Base64URL 必须无 Padding**
   - 本协议中所有 Base64URL 字段都要求**无 Padding**（即结尾不允许出现 `=` 号）。
   - Java 标准库 `Base64.getUrlEncoder()` 默认是**带 Padding**的。
   - 实现 Base64URL 编码时必须调用：
     ```java
     Base64.getUrlEncoder().withoutPadding()
     ```
   - 解码时建议使用 `Base64.getUrlDecoder()`，它能自动接受无 Padding 的输入。
   - 若忘记 `.withoutPadding()`，会导致：
     - 线格式与协议不兼容；
     - 与其它实现（或测试向量）无法互操作；
     - pht/rch 计算结果也会不一致。
