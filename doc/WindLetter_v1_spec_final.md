# **Wind Letter v1.0 需求文档**

> 目标：提供 **清晰、可落地** 的线格式与校验规则，让社区能 **互通实现**。遵循 **模块化** 和 **奥卡姆剃刀**的原则。

------

## 0. 总览（一张图——只传这一条 JSON）

> **线上传输唯一对象**：JWE（内含隐藏签名的 JWS 作为密文）

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"public\",\"enc\":\"A256GCM\"})",
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "header": {
        "kid": "BASE64URL(kid-alice-ecc)",
        "alg": "ECDH-ES+A256KW",
        "epk": { "kty": "OKP", "crv": "X25519", "x": "BASE64URL(...)" }
      },
      "encrypted_key": "BASE64URL(...)"
    }
  ],
  "iv": "BASE64URL(...)",
  "ciphertext": "BASE64URL(...)",
  "tag": "BASE64URL(...)"
}
```

- **只有这一个 JSON** 在网络上传输。
- 解密后得到一个 **JWS 对象**（内层），用于 **来源认证**；外界看不到签名者（对外匿名）。

------

## 1. 设计目标

- **安全默认**：改任意 1 bit 即校验失败（AEAD + 受保护头 + 绑定指纹）。
- **最小外泄**：外层元数据最小化（仅必要字段）。
- **可互操作**：命名与分层对齐 **JOSE**（JWE/JWS），便于复用成熟库。
- **实现简单**：规则 **写死在实现**，消息体不自述“是否校验/如何校验”。

------

## 2. 名词与缩写

- **JWE**：JSON Web Encryption（外层，加密封装）
- **JWS**：JSON Web Signature（内层，签名认证；放在密文里）
- **CEK / K_session**：每条消息的对称加密密钥（32B，随机）
- **AAD**：Additional Authenticated Data（附加认证数据）
- **JCS**：RFC 8785 JSON Canonicalization Scheme（JSON 规范化）
- **kid**：Key ID（公钥指纹/标识）
- **rid**：Routing ID（盲送模式下的接收者可识别指纹，旁观者不可关联）

------

## 3. 线格式（外层 JWE）

### 3.1 `protected`（Base64URL 编码的 JSON）

```json
{
  "typ": "wind+jwe",          // 类型标识（实现白名单）
  "cty": "wind+jws",          // 密文中装的是 JWS 对象
  "ver": "1.0",               // 协议版本（字符串）
  "wind_mode": "public",      // "public" 或 "obfuscation"
  "enc": "A256GCM"            // 对称算法（白名单：仅 A256GCM）
  // 可选：开启压缩时添加 "zip":"zstd"（需配长度分桶，见 §8）
}
```

> **MUST** 使用 **JCS** 规范化后再 Base64URL；整个 `protected` 会进入 **AAD**。

### 3.2 `recipients`（数组，整体进入 AAD）

**public 模式（常规）**

```json
[
  {
    "header": {
      "kid": "BASE64URL(kid-alice-ecc)",
      "alg": "ECDH-ES+A256KW",
      "epk": { "kty": "OKP", "crv": "X25519", "x": "BASE64URL(...)" }
    },
    "encrypted_key": "BASE64URL(...)"
  }
]
```

**obfuscation（盲送）模式（可选）**

- 把 `kid` 换成 **`rid`**，并可混入 **诱饵** 条目；统一长度。
- `rid` 建议：`Trunc128( HKDF-SHA256( ECDH(epk, sk_rec), info="wind+rid/v1" || wind_id ) )`

```json
[
  {
    "header": {
      "alg": "ECDH-ES+A256KW",
      "epk": { "kty": "OKP", "crv": "X25519", "x": "BASE64URL(...)" },
      "rid": "BASE64URL(...)"
    },
    "encrypted_key": "BASE64URL(...)"
  }
]
```

**算法白名单（实现写死）**

- `enc`：`A256GCM`
- `recipients[*].header.alg`：`ECDH-ES+A256KW`（X25519）或 `ML-KEM-768`（PQC，自定义标识需库支持）

> 未在白名单内 → **拒绝**。

### 3.3 `aad`

- **规则写死**：`aad = BASE64URL( JCS(recipients) )`

### 3.4 AAD 组合（加密/解密双方都必须一致）

```
AAD_bytes = ASCII( jwe.protected ) + ASCII(".") + ASCII( jwe.aad )
```

- 任何一端实现不同 ⇒ **GCM tag 不通过**。

### 3.5 `iv`, `ciphertext`, `tag`

- `iv`：12 字节（Base64URL）。
   **发送方生成逻辑（固定写死）**：
   `iv = HKDF-SHA256( ikm=CEK, salt=0x00, info="wind+jwe/iv/v1" || wind_id )[0..11]`
   说明：CEK 为每条消息 32B 随机，因而派生出的 iv 在“同一 CEK 下唯一”。
   **接收方无需派生**，直接取 `jwe.iv` 使用（CEK 未解封前也无法派生 iv，且没有必要校验派生过程）。
- `ciphertext`：AEAD 加密后的密文（内容是 **JWS JSON** 字节）。
- `tag`：16 字节（GCM 标签）。

------

## 4. 内层 JWS（隐藏签名；解密后可见）

> 用于**认证来源**；把外层绑定进签名，防“换壳/降级”。

### 4.1 JWS Protected Header（Base64URL 编码的 JSON）

```json
{
  "typ": "wind+jws",
  "alg": "EdDSA",                    // Ed25519（白名单）
  "kid": "BASE64URL(sender-kid)",    // 签名者公钥ID
  "ts": 1731800000,                  // 可选：签名时间（展示/时效）

  // 绑定外层（写死：JCS + SHA-256）
  "pht": "BASE64URL( SHA256( JCS(outer.protected_json) ) )",
  "rch": "BASE64URL( SHA256( JCS(outer.recipients) ) )"
}
```

### 4.2 JWS Payload（业务明文）

- 自由结构。建议把**易泄露的元信息**（如 `content_type`、`original_size`、业务字段）放在这里。

```json
{
  "meta": { "content_type": "text/utf-8", "original_size": 3210 },
  "body": { "type": "text", "text": "Hello, Wind-Letter!" }
}
```

### 4.3 JWS Signature

- 标准 JWS：`Sign_Ed25519( ASCII( b64url(protected) + "." + b64url(payload) ) )`

------

## 5. 发送方流程（最小实现）

1. 生成 `CEK`（32B 随机）与 `wind_id`（128bit 随机）。
2. 组装并 **JCS** 规范化 `protected_json`；Base64URL → `protected_b64`。
3. 组装 `recipients` 并封装 `CEK`（每个收件人写入 `header` 与 `encrypted_key`）。
4. 计算 `aad_b64 = BASE64URL( JCS(recipients) )`；`AAD_bytes = ASCII(protected_b64) + "." + ASCII(aad_b64)`。
5. 组装 **JWS**（内层）：
   - 计算 `pht`、`rch`；
   - `JWS_protected_b64` + `JWS_payload_b64` → `JWS_signature_b64`（Ed25519）。
6. （可选）压缩 JWS 字节；若开启压缩 → **长度分桶填充**（§8）。
7. 计算 `iv`（HKDF 派生，§3.5）；`ciphertext, tag = A256GCM_Encrypt(CEK, iv, AAD_bytes, JWS_bytes)`。
8. 输出 JWE：`{ protected: protected_b64, aad: aad_b64, recipients, iv, ciphertext, tag, }`。

------

## 6. 接收方流程（最小实现）

1. 解析 JWE；校验算法是否在白名单。
2. 计算 `aad_expected = BASE64URL( JCS(recipients) )`；若 `aad != aad_expected` → 拒绝。
3. `AAD_bytes = ASCII(protected_b64) + "." + ASCII(aad_expected)`。
4. 解封 `CEK`（遍历 `recipients`，尝试 `ECDH-ES+A256KW`/`ML-KEM-768`）。
5. `JWS_bytes = A256GCM_Decrypt(CEK, iv, AAD_bytes, ciphertext, tag)`；失败 → 拒绝。
6. 解析 **JWS**，重算 `pht/rch` 与外层对比（**常量时间比较**），不相等 → 拒绝。
7. 根据 `kid` 验签（Ed25519），失败 → 拒绝。
8. 读取 `payload`（再决定业务策略/展示）。

------

## 7. 硬规则（**必须**）

- **算法白名单**（实现写死）：
  - `enc = "A256GCM"`；
  - `recipients[*].header.alg ∈ { "ECDH-ES+A256KW", "ML-KEM-768" }`；
  - `JWS.alg = "EdDSA"`（Ed25519）；
  - 其余一律拒绝，**禁止降级/回退**。
- **CEK/IV**：
  - 每条消息 `CEK` **全新随机**（32B）；
  - `iv` 12B，由发送方按 §3.5 的 HKDF 规则**派生并写入 JWE**；
  - **同一 CEK 下绝不复用 iv**。
- **JCS**：RFC 8785；UTF-8；键唯一；不要使用超过 2^53 的裸整数（用字符串）。
- **验证顺序**：**先 AEAD** → **再 JWS**（含 `pht/rch`）→ 才处理业务。
- **比较**：`tag`/`pht`/`rch`/签名结果使用**常量时间比较**。
- **错误**：对外统一 “Invalid message”。
- **版本号**：所有版本字段一律字符串：如 `"ver":"1.0"`。

------

## 8. 压缩与长度侧信道（可选）

- 默认**不开启压缩**（不含 `zip` 字段）。
- 若开启：`"zip":"zstd"`，**必须**在**压缩后、加密前**做**长度分桶填充**（例如桶：512/1024/2048/4096…），将数据填充到**最近的上界**；避免泄露精确长度。
- 填充实现建议：用 0x00 填充，或在 payload 内显式存储 original_length 字段以安全截断。
- 不在外层暴露 `original_size`；如需展示，把它放到 **内层 payload**。

------

## 9. 收件人隐私（两档）

- **public**：`header.kid` 明文可见，所有收件人可见其他收件人。
- **obfuscation / blind**：使用 `header.rid`（每条消息唯一、不可关联），可加入 **decoy** 与统一长度；收件人自行验证匹配，旁观者看不出真实对象。
- 两档都将 `recipients` 整体纳入 **AAD** 与内层 `rch` 绑定，防篡改。

------

## 10. 重放与时效（建议）

- `wind_id` 去重（接收端维护已见表）；
- 在内层 `JWS.protected` 使用 `ts`，可选 `nbf/exp`；接收端容忍少量时钟漂移（如 ±5min）。

------

## 11. 兼容性与扩展

- **JOSE 库**：JWE/JWS 命名与分层与 JOSE 对齐；自定义算法名（如 `ML-KEM-768`）需确认目标库可注册/扩展。
- **Profile 扩展**：将来可增加 `enc = "A256GCM-SIV"`（抗 nonce 误用）或“双签”（Ed25519+PQC）等 profile，不改变主结构。

------

## 12. 合规的“未加密”接收策略（若产品线需要）

- 可以接收**未加密**内容，但**一律标记 UNTRUSTED**；
- 若内容包裹 **JWS** 且验签通过，可显示“签名通过（未知/已知签名者）”，但**保密性=无**，权限降级。

------

## 13. 互操作测试（黄金用例与篡改清单）

**黄金用例**：实现需能逐字节重现以下要点：

- `protected_b64` 与 `aad_b64 = BASE64URL(JCS(recipients))`；
- 解密后 JWS 的 `pht/rch` 与外层匹配；
- 签名/验签通过。

**篡改应失败**（任选其一修改 → 必须失败）：

- 改 `protected` / `recipients` / `iv` / `ciphertext` / `tag` 的任意 bit → **AEAD 失败**
- 改内层 `payload` / `JWS.protected` / `signature` 的任意 bit → **JWS 失败**
- 改 `JWS.protected.pht` 或 `rch` → **JWS 失败**
- 把内层 JWS 换壳 → **JWS 失败（pht/rch 不匹配）**
- `enc`/`alg` 不在白名单 → **直接拒绝**

------

## 14. 安全小抄（实现务必自检）

- 随机源：系统 CSPRNG（不要自己写 PRNG）。
- 资源限幅：限制 `recipients` 数量与解压尺寸；流式处理防 zip bomb/DoS。
- 日志：仅记录必要错误码，**不**记录密钥材料、`encrypted_key`、`epk` 原文。
- 文档与代码同源：把本规范中“**写死**”的规则放入常量/单元测试。

------

## 15. 附：结构示例（解码视图，便于对照）

**JWE `protected` 解码**

```json
{
  "typ": "wind+jwe",
  "cty": "wind+jws",
  "ver": "1.0",
  "wind_mode": "public",
  "enc": "A256GCM"
}
```

**JWS（解密后内层）**

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jws\",\"alg\":\"EdDSA\",\"kid\":\"BASE64URL(sender-kid)\",\"ts\":1731800000,\"wind_id\":\"...\",\"pht\":\"BASE64URL(SHA256(JCS(outer.protected_json)))\",\"rch\":\"BASE64URL(SHA256(JCS(outer.recipients)))\"})",
  "payload": "BASE64URL({\"meta\":{\"content_type\":\"text/utf-8\",\"original_size\":3210},\"body\":{\"type\":\"text\",\"text\":\"Hello, Wind-Letter!\"}})",
  "signature": "BASE64URL(...)"
}
```

------

## **16. 聊天场景的装甲封装（可选，外层壳，不进校验）**

为聊天/复制粘贴友好而设的**Transport Envelope**，解装甲后得到 **JWE JSON**。这种装甲封装格式 **仅用于展示结构和内容**，实际网络传输时，数据统一采用 **Base64** 编码。

此装甲格式仅在 **聊天场景** 或 **邮件场景**下使用，之后会根据具体传输媒介切换为其他格式（如 PGP 格式的文本装甲）。它不参与协议的校验过程，仅作为格式封装。

### **16.1 JSON-Armor（推荐，用于展示）**

```json
{
  "type": "wind-letter",
  "encoding": "base64url",        // 或 "windbase1024f"
  "v": "1",
  "data": "eyJwcm90ZWN0ZWQiOiJCRVNFNjRVUkwuLi4ifQ",  // 加密后的数据部分
  "checksum": "crc32c:7Q3G5A"     // 可选：早期损坏检测
}
```

- **`type`**: 固定值，标识消息类型，`wind-letter`。
- **`encoding`**: 数据的编码方式，可以是 `base64url` 或者 `windbase1024f`（可选的专用编码格式）。
- **`v`**: 版本号，表示此消息格式的版本，`1` 是当前版本。
- **`data`**: 实际的加密数据，经过加密后的 **JWE** 数据。
- **`checksum`**: 可选字段，用于早期损坏检测，存储 CRC32 校验和。

> **注意**：这种 JSON-Armor 仅用于展示数据结构和内容，实际传输时将统一用 **Base64** 编码的 JWE 对象。

### **16.2 纯文本 Armor（PGP 风格）**

这种包装方式类似于 **PGP**，用于邮件或文本场景时，直接通过纯文本方式对加密数据进行包装。它提供了人类可读的文本格式，使得加密数据在需要时可以通过文本形式传输。

```
-----BEGIN WIND LETTER-----
Armor: base64url; v=1
eyJwcm90ZWN0ZWQiOiJCRVNFNjRVUkwuLi4ifQ
=crc32c:7Q3G5A
-----END WIND LETTER-----
```

- **`type`**: 固定值，标识消息类型，`wind-letter`。
- **`encoding`**: 数据的编码方式，使用 `base64url` 编码。
- **`v`**: 版本号，`1` 为当前版本。
- **`data`**: 加密后的数据部分。
- **`checksum`**: 可选的 CRC32 校验和。

这种 **Armor** 格式便于 **聊天场景** 或 **复制粘贴**，让加密消息能够以简洁的文本形式呈现并传输，接收方在解密时只需要解析其中的数据即可。

> **注意**：实际网络传输时仍使用 **Base64 编码** 的 JWE，只有在聊天、邮件等场景下才使用 **JSON-Armor** 或 **纯文本 Armor**。