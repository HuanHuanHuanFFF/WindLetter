# Wind Letter v1.0协议

## 0. 总览(协议传输通用JSON)

### 公开模式

#### 传输唯一结构,通用JSON

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"public\",\"enc\":\"A256GCM\",\"key_alg\":\"X25519Kyber768\",\"kids\":{\"x25519\":\"BASE64URL(kid-ecc-sender)\"}})",
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "kids": {
        "x25519": "BASE64URL(kid-ecc-recv)",
        "mlkem768": "BASE64URL(kid-pq-recv)"
      },
      "ek": "BASE64URL(mlkem_ct_for_this_recipient)",
      "encrypted_key": "BASE64URL(wrap(CEK))"
    }
  ],
  "iv": "BASE64URL(GCM_IV_12bytes)",
  "ciphertext": "BASE64URL(AES256GCM(plaintext=inner_JWS_bytes, key=CEK, iv=IV, aad=ASCII(outer.protected+\".\"+outer.aad)))",
  "tag": "BASE64URL(GCM_tag_16bytes)"
}
```

#### JSON内部全部展视图

> 注：以下“JSON内部全部展视图”仅用于实现/调试：它表示把传输字段（Base64URL字符串）进行解码/解密后的内存视图展开；真实传输格式仍以上一节“传输唯一结构,通用JSON”为准。

```json
{
  "protected": {
    "typ": "wind+jwe",
    "cty": "wind+jws",
    "ver": "1.0",
    "wind_mode": "public",
    "enc": "A256GCM",
    "key_alg": "X25519Kyber768",
    "kids": {
      "x25519": "BASE64URL(kid-ecc-sender)"
    }
  },
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "kids": {
        "x25519": "BASE64URL(kid-ecc-recv)",
        "mlkem768": "BASE64URL(kid-pq-recv)"
      },
      "ek": "<MLKEM768_Ciphertext_Encapsulation: 1088 bytes>",
      "encrypted_key": "<wrap(CEK)>"
    }
  ],
  "iv": "BASE64URL(GCM-IV)",
  "ciphertext": {
    "protected": {
      "typ": "wind+jws",
      "alg": "EdDSA",
      "kid": "<sender-kid>",
      "ts": 1731800000,
      "wind_id": "<wind-id>",
      "jwe_protected_hash": "<BASE64URL(SHA256(JCS(protected_json)))>",
      "jwe_recipients_hash": "<BASE64URL(SHA256(JCS(outer.recipients)))>"
    },
    "payload": {
      "meta": {
        "content_type": "text/plain; charset=utf-8",
        "original_size": 3210
      },
      "body": {
        "data": "<BASE64URL(raw_bytes)>"
      }
    },
    "signature": "<Ed25519(signature)>"
  },
  "tag": "<16 bytes GCM tag>"
}
```

### 混淆模式

#### 传输唯一结构,通用JSON

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"obfuscation\",\"enc\":\"A256GCM\",\"key_alg\":\"X25519Kyber768\",\"epk\":{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"BASE64URL(Sender_Ephemeral_Public_Key)\"}})",
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "rid": "BASE64URL(rid_hybrid_16bytes)",
      "ek": "BASE64URL(MLKEM768_Ciphertext_Encapsulation_for_this_recipient)",
      "encrypted_key": "BASE64URL(wrap(CEK))"
    }
  ],
  "iv": "BASE64URL(GCM_IV_12bytes)",
  "ciphertext": "BASE64URL(AES256GCM(plaintext=inner_JWS_bytes, key=CEK, iv=IV, aad=ASCII(outer.protected+\".\"+outer.aad)))",
  "tag": "BASE64URL(GCM_tag_16bytes)"
}
```

#### JSON内部全部展视图

```json
{
  "protected": {
    "typ": "wind+jwe",
    "cty": "wind+jws",
    "ver": "1.0",
    "wind_mode": "obfuscation",
    "enc": "A256GCM",
    "key_alg": "X25519Kyber768",
    "epk": {
      "kty": "OKP",
      "crv": "X25519",
      "x": "<Sender_Ephemeral_Public_Key: bytes>"
    }
  },
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "rid": "<rid_hybrid: 16 bytes>",
      "ek": "<MLKEM768_Ciphertext_Encapsulation: 1088 bytes>",
      "encrypted_key": "<wrap(CEK)>"
    }
  ],
  "iv": "BASE64URL(GCM-IV)",
  "ciphertext": {
    "protected": {
      "typ": "wind+jws",
      "alg": "EdDSA",
      "kid": "<sender-kid>",
      "ts": 1731800000,
      "wind_id": "<wind-id>",
      "jwe_protected_hash": "<BASE64URL(SHA256(JCS(protected_json)))>",
      "jwe_recipients_hash": "<BASE64URL(SHA256(JCS(outer.recipients)))>"
    },
    "payload": {
      "meta": {
        "content_type": "text/plain; charset=utf-8",
        "original_size": 3210
      },
      "body": {
        "data": "<BASE64URL(raw_bytes)>"
      }
    },
    "signature": "<Ed25519(signature)>"
  },
  "tag": "<16 bytes GCM tag>"
}
```

## 字段设计
### 认证与绑定
> 通过这些机制，可以做到传输过程中 1 bit 不改，避免换壳攻击（外层字段被 GCM + 内层 hash 双重约束）。
- `protected`：外层保护头（算法/模式等元信息）；被 GCM 认证；内层用 `jwe_protected_hash` 绑定它。
- `recipients`：收件人入口列表；其 JCS 用于算 `aad`；内层用 `jwe_recipients_hash` 绑定它。
- `aad`：`BASE64URL(JCS(recipients))`，让 `recipients` 也进入 GCM 认证范围。
- `iv`：AES-GCM 的随机 IV（12 bytes）。
- `ciphertext`：AES-GCM 密文（明文是内层 `JWS_Bytes`；展开视图里显示解密后的对象）。
- `tag`：AES-GCM 认证标签（16 bytes）。
- `jwe_protected_hash / jwe_recipients_hash`：内层签名内的“外壳指纹”，防换壳/转投。

### 外层 `protected` 内字段
- `ver`：协议版本。
- `typ/cty`：协议标签与内容类型提示（工程路由用）。
- `wind_mode`：传输模式（public / obfuscation）。
- `enc`：AEAD 算法（白名单校验）。
- `key_alg`：密钥封装组合（ECC-only / Hybrid）。

### 公开模式（public）
- `protected.kids.x25519`：发送方 X25519 公钥 kid（暴露发件人）。
- `recipients[i].kids.x25519`：接收方 X25519 公钥 kid（暴露收件人）。
- `recipients[i].kids.mlkem768`：接收方 ML-KEM-768 公钥 kid（暴露收件人）。
- `recipients[i].ek`：ML-KEM 封装密文（每消息/每收件人一份）。
- `recipients[i].encrypted_key`：用 `KEK` 包装的 `CEK`（unwrap 得到 CEK）。

### 混淆模式（obfuscation）
- `protected.epk.kty/crv/x`：发送方临时 X25519 公钥（参与共享秘密与派生）。
- `recipients[i].rid`：收件人指纹（对外匿名，用于快速匹配 entry）。
- `recipients[i].ek`：ML-KEM 封装密文（收件人解封装得到 PQ 共享秘密）。
- `recipients[i].encrypted_key`：用 `KEK` 包装的 `CEK`。

### 内层（解密后得到）
- `ciphertext.protected.ts`：时间戳，展示给用户（也可用于防重放）。
- `ciphertext.protected.wind_id`：消息 ID（上层可用于去重/反重放）。
- `ciphertext.protected.alg/kid/signature`：签名算法/公钥标识/签名值（启用签名时才有）。

### payload
- `payload.meta.content_type`：MIME（如何解释 data）。
- `payload.meta.original_size`：原始字节长度。
- `payload.body.data`：原始 bytes 的 Base64URL（无填充）。


## 协议流程
### 1.  算法选择
### 2. 是否签名
### 3. 加密
### 4. 传输 接收
### 5. 验证 解密

## 算法白名单（v1.0）

v1.0 仅允许以下算法与组合（其余一律拒绝）。

### 1) 密文加密套件（可选其一）

- **ECC-only**
  - `key_alg = "X25519"`
  - `enc = "A256GCM"`

- **Hybrid（ECC+PQC）**
  - `key_alg = "X25519Kyber768"`（X25519 + ML-KEM-768）
  - `enc = "A256GCM"`

### 2) 签名（可选）

- `inner_jws.protected.alg = "EdDSA"`（Ed25519）

### 3) 固定依赖（不可选）

- **KDF**：HKDF-SHA256（从共享秘密派生 `session_key / KEK / CEK` 等密钥材料）
- **Hash**：SHA-256（计算绑定哈希/指纹：`jwe_protected_hash / jwe_recipients_hash` 等）
- **JSON 规范化**：JCS（RFC 8785，用于对 JSON 做一致序列化，保证哈希输入可复现）
- **Key Wrap**：A256KW（AES Key Wrap，用 `KEK` 包装/解包 `CEK`，写入 `encrypted_key`）
- **编码**：Base64URL（无填充，用于字段传输编码：`iv / tag / ciphertext / signature` 等）
- **标识**：UUID v4（`wind_id`，用于消息标识/去重/追踪）

## 长度规范

| 项目                  | 长度          | 依据 / 备注                                                                                                                 |
|:--------------------|:------------|:------------------------------------------------------------------------------------------------------------------------|
| **CEK (A256GCM)**   | **32 B**    | NIST SP 800-38D; [[RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518)]                                              |
| **GCM IV (Nonce)**  | **12 B**    | 推荐 96-bit 以获得最高效率与安全。[[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)] |
| **GCM Tag**         | **16 B**    | 规定 128-bit 认证标签。[[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)]                                                    |
| **HKDF 哈希**         | **SHA-256** | HashLen=32 for SHA-256。[[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)]                                             |
| **KEK**             | **32 B**    | 匹配 A256KW 要求的 256-bit 密钥输入。[[RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)]                                         |
| **rid**             | **16 B**    | 协议自定义 (128-bit 截断哈希)                                                                                                    |
| **wind_id**         | **16 B**    | UUID v4 (128-bit)。[[RFC 4122](https://www.rfc-editor.org/rfc/rfc4122)]                                                  |
| **ts**              | **64-bit**  | 实现约定 (Unix Timestamp)                                                                                                   |
| **X25519 公钥**       | **32 B**    | 输入点格式为 32 字节。[[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748)]                                                    |
| **X25519 共享密钥**     | **32 B**    | 输出共享秘密为 32 字节。[[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748)]                                                   |
| **ML-KEM-768 共享密钥** | **32 B**    | FIPS 203 (Final) Algorithm 13。[[FIPS 203](https://csrc.nist.gov/pubs/fips/203/ipd)]                                     |
| **ML-KEM-768 密文**   | **1088 B**  | FIPS 203 (Final) Table 2。[[FIPS 203](https://csrc.nist.gov/pubs/fips/203/ipd)]                                          |
| **Ed25519 签名**      | **64 B**    | Ed25519 签名固定长度。[[RFC 8032 §5.1.6](https://www.rfc-editor.org/rfc/rfc8032)]                                              |
| **kid (指纹)**        | **32 B**    | JWK Thumbprint SHA-256。[[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)]                                             |
| **JCS**             | **变长**      | JSON Canonicalization Scheme (用于 AAD/Hash 计算)。[[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)]                      |

> 总规则：本表中长度均指“原始字节”；传输字段统一 Base64URL（无填充），除非特别声明为 UUID 文本。

## 签名流程 (Signature Process)

### 1. 准备绑定数据 (Binding Preparation)

为了防止“换壳攻击”，内层 JWS 必须与外层 JWE 的关键元数据（保护头与收件人列表）进行密码学绑定。在构建内层 Header
之前，发送方必须先确定外层的 `protected` 和 `recipients` 结构。

1. **解码外层保护头 (protected) 为 JSON 对象**：
   
- `protected_json = JSON.parse(Base64URL_Decode(outer.protected))`
  
2. **计算外层保护头哈希**：
   $$
   \text{hash}\_\text{protected}=\text{SHA256}\big(\text{JCS}(\text{protected}\_\text{json})\big)
   $$

3. **计算外层收件人哈希**：
   $$
   \text{hash}\_\text{recipients}=\text{SHA256}\big(\text{JCS}(\text{outer.recipients})\big)
   $$

### 2. 构建内层头部 (Header Construction)

构建 JWS Protected Header JSON 对象。该对象必须包含必要的算法标识、时间戳、唯一 ID 以及上一步计算的哈希绑定。

* **结构定义**：

```json
{
  "alg": "EdDSA",
  "kid": "<Sender_Key_Thumbprint>",
  "ts": <Current_Unix_Timestamp>,
  "wind_id": "<UUID_v4>",
  "jwe_protected_hash": "BASE64URL(hash_protected)",
  "jwe_recipients_hash": "BASE64URL(hash_recipients)"
}
```

* **注意**：字段需按字母序排序以符合 JCS 规范建议（尽管最终传输使用 Base64URL）。

### 3. 序列化输入 (Input Serialization)

将头部和负载转换为 JWS 签名所需的输入格式。

1. **编码头部**：
   $$
   \text{header}\_\text{b64} = \text{Base64URL}(\text{UTF8}(\text{InnerHeader}\_\text{JSON}))
   $$

2. **编码负载** (Payload)：
   $$
   \text{payload}\_\text{b64} = \text{Base64URL}(\text{UTF8}(\text{InnerPayload}\_\text{JSON}))
   $$

3. **生成签名输入串** (Signing Input)：
   $$
   \text{SigInput} = \text{header}\_\text{b64} + "." + \text{payload}\_\text{b64}
   $$

### 4. 计算数字签名 (Calculating Signature)

使用发送方的长期身份私钥对输入串进行签名。

* **算法**：Ed25519 (RFC 8032)
* **私钥**：$sk_{sign}$ (Sender's Static Ed25519 Private Key)

$$
\text{signature} = \text{Ed25519}\_\text{Sign}(\text{sk}\_\text{sign}, \text{SigInput})
$$

### 5. 组装内层对象 (Assembly)

最终生成的 JWS 对象（即外层加密的 `plaintext` 输入）。

* **结构定义**：

```json
{
  "protected": "header_b64",
  "payload": "payload_b64",
  "signature": "BASE64URL(signature)"
}
```

## 验证消息:

### 简述:

* **外层 AES-GCM 认证范围**：`ciphertext`、`tag` 与 **AAD**（JWE 规定的 `ASCII(base64url(protected) + "." + aad)`），并且 *
  *标签计算依赖 `iv`**。因此 `protected_b64`、`aad`、`iv`、`ciphertext` 任一比特被改，**GCM 验证失败**（除去随标签长度而来的可忽略伪造概率）。

* **内层 JWS 认证范围**：`ciphertext.protected` 与 `ciphertext.payload`（以及对应的 `signature` 校验）。这两者任何一处改 1
  bit，**JWS 验签失败**。

* **外层字段的双重绑定**：`outer.protected` 与 `outer.recipients` 已被上一条 **GCM 的 AAD** 直接认证；你又在 JWS 头加入
  `jwe_protected_hash` / `jwe_recipients_hash` **再次绑定**（defense-in-depth）。任一处改动都会在 **GCM 或 JWS** 层被拒绝。

## 验证流程 (Verification Process)

### 1. 外层完整性校验 (Outer Integrity Check)

**目标**：保证整个 JSON 在传输过程中 1 bit 不改。

1. **AAD 一致性复核**：
   接收方独立计算收件人列表的摘要，并与报文中的 `aad` 字段比对：
   $$
   \text{calc}\_\text{aad} = \text{Base64URL}( \text{JCS}(\text{json.recipients}) )
   $$
    * **判定**：若 `calc_aad != json.aad`，**拒绝**（说明有人修改了收件人列表）。

2. **构建 GCM 参数**：
    * **Key**: 上一步解密流程得到的 **CEK**。
    * **IV**: 直接取 `json.iv`。
    * **AAD Input**: 拼接外层头与 AAD 字段（注意是 ASCII 拼接）：
      $$
      \text{AAD}_{\text{bytes}} = \text{ASCII}(\text{json.protected}) + "." + \text{ASCII}(\text{json.aad})
      $$

3. **AES-GCM 解密与验真**：
   执行解密操作（此步骤隐含了 Tag 校验）：
   $$
   \text{JWS}\_\text{Bytes} = \text{AES-GCM-Decrypt}(\text{key}=\text{CEK}, \text{iv}=\text{IV}, \text{aad}=\text{AAD}_{\text{bytes}}, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})$$
    * **判定**：若解密抛出异常（Tag 校验失败），**拒绝**（说明密文、Tag 或 AAD 被篡改）。
    * **成功**：获得内层明文 `JWS_Bytes`。

### 2. 内外层绑定校验 (Binding Check)

**目标**：防止“换壳攻击”（攻击者将合法内层 JWS 放入伪造外层 JWE 中）。

1. **提取内层绑定指纹**：
    - 从内层 JWS Header 读取 `jwe_protected_hash` 与 `jwe_recipients_hash`。

2. **计算期望指纹 (Expected Fingerprints)**：
    - `protected_json = JSON.parse(Base64URL_Decode(outer.protected))`

$$
\text{exp}\_\text{jwe}\_\text{protected}\_\text{hash}=\text{Base64URL}\Big(\text{SHA256}\big(\text{JCS}(\text{protected}\_\text{json})\big)\Big)
$$

$$
\text{exp}\_\text{jwe}\_\text{recipients}\_\text{hash}=\text{Base64URL}\Big(\text{SHA256}\big(\text{JCS}(\text{outer.recipients})\big)\Big)
$$

3. **常量时间比较 (Constant-Time Compare)**：
    - 使用常量时间比较分别比对：
        - `inner.jwe_protected_hash` vs `exp_jwe_protected_hash`
        - `inner.jwe_recipients_hash` vs `exp_jwe_recipients_hash`
    - 任一不匹配则 **拒绝**（外壳与内芯不再绑定，疑似被替换）。

### 3. 来源认证与签名校验 (Signature Verification)

**目标**：确认发件人身份，并确保业务正文 (Payload) 未被篡改。

1. **获取发件人公钥**：
   从内层 JWS Header 获取 `kid`，在本地可信列表或公钥簿中查找对应的 **Ed25519 公钥** ($pk_{sign}$)。

2. **重构签名输入 (Signing Input)**：
   拼接内层头部和 Payload 的 Base64URL 形式：
   $$
   \text{SigInput} = \text{ASCII}(\text{inner.protected}\_\text{b64}) + "." + \text{ASCII}(\text{inner.payload}\_\text{b64})
   $$

3. **执行验签**：
   使用 Ed25519 算法验证签名：
   $$
   \text{Valid} = \text{Ed25519.Verify}(pk_{sign}, \text{SigInput}, \text{inner.signature})
   $$
    * **判定**：
        * 若 `Valid` 为 `False`：**拒绝**（正文被篡改或私钥不匹配）。

## 密钥材料与标识派生参数（HKDF-SHA-256）

### 1) Hybrid Combiner → KEK

- **salt**：`"wind"`
- **info**：`"WindLetter v1 KEK | X25519Kyber768"`
- **L**：`32`

---

### **2) rid (混合指纹)**

- **salt**: `"wind"`
- **info**: `"rid/hybrid"`
- **L**: `16`
- **IKM**: $SS_{ECC}$∣∣ $SS_{PQ}$ (拼接输入)

---

### 3) GCM IV

- **IV 生成**：`Random(12 bytes, 96-bit)`
- **说明**：不使用派生 IV（每条消息随机、独立）

## 加密解密流程

### 混合算法：X25519Kyber768 (Hybrid Combiner)

#### 1. 公开模式 (Public Mode)

##### 1. 加密流程 (发送方)

1. **准备密钥**：生成随机的内容加密密钥 (**CEK**, 32字节) 和初始向量 (**IV**, 12字节)。
2. **ECC 计算**：使用 **发送方静态私钥** ($sk_{static}^{sender}$) 和 **接收方静态公钥** ($pk_{static}^{recv}$) 计算：
   $$SS_{ECC} = \text{X25519}(sk_{static}^{sender}, pk_{static}^{recv})$$
3. **PQC 封装**：针对接收方 PQC 公钥执行 ML-KEM 封装，生成共享秘密 $SS_{PQ}$ 和密文 $ct$：
   $$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{static}^{recv})$$

    * 将 $ct$ 填入 `recipients[i].ek`。
4. **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    * 派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
5. **加密 CEK**：

    * 使用 **A256KW** 包裹 CEK：$C_{key} = \text{AES-KeyWrap}(KEK, CEK)$。
    * 将 $C_{key}$ 填入 `recipients[i].encrypted_key`。
6. **加密 Payload**：

    * 使用 CEK 加密内层数据：
      $$
      \big(\text{ciphertext},\ \text{tag}\big)=\text{AES-GCM-Encrypt}(\text{key}=CEK,\ \text{iv}=IV,\ \text{aad}=AAD,\ \text{pt}=\text{JWS}\_\text{Bytes})
      $$

##### 2. 解密流程 (接收方)

1. **识别与 ECC**：从 Header 获取发送方 ID，查找其公钥。使用 **接收方静态私钥** ($sk_{static}^{recv}$) 计算：
   $$SS_{ECC} = \text{X25519}(sk_{static}^{recv}, pk_{static}^{sender})$$
2. **PQC 恢复**：从 `recipients[i].ek` 提取密文 $ct$，解封装得到：
   $$SS_{PQ} = \text{ML-KEM.Decap}(sk_{static}^{recv}, ct)$$
3. **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    * 执行 HKDF 操作计算出 **KEK**。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
4. **解密 CEK**：
    * 解开 `encrypted_key` 得到会话密钥：$CEK = \text{AES-KeyUnwrap}(KEK, C_{key})$。
5. **解密 Payload**：
    * 使用 CEK 解密外层密文得到内层数据：
      $$\text{JWS}\_\text{Bytes} = \text{AES-GCM-Decrypt}(\text{key}=CEK, \text{iv}=IV, \text{aad}=AAD, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})$$

---

#### 2. 混淆模式 (Obfuscation Mode)

##### 1. 加密流程 (发送方)

1. **准备密钥**：生成随机的内容加密密钥 (**CEK**, 32字节) 和初始向量 (**IV**, 12字节)。
2. **X25519 协商**：
    * 生成临时密钥对 $(sk_{eph}, pk_{eph})$。
    * 计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{eph}, pk_{static}^{recv})$。
    * 将 $pk_{eph}$ 填入 `protected.epk`。
3. **ML-KEM 封装**：
    * 针对接收方 PQC 公钥执行封装：$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{static}^{recv})$。
    * 将 $ct$ (1088字节) 填入 `recipients[i].ek`。*(注意：每位收件人独有一份)*
4. **计算路由指纹 (rid)**：
    * 拼接共享秘密：$IKM_{rid} = SS_{ECC} \ || \ SS_{PQ}$。
    * 计算混合指纹：

      $$rid = \text{HKDF-Expand}\big(\text{HKDF-Extract}(\text{salt="wind"}, IKM_{rid}), \text{info="rid/hybrid"}, L=16\big)$$
    * 将 $rid$ 填入 `recipients[i].rid`。
5. **混合派生 KEK (Combiner)**：

    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    * 派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
6. **加密 CEK**：

    * 使用 **A256KW** 包裹 CEK：$C_{key} = \text{AES-KeyWrap}(KEK, CEK)$。
    * 将 $C_{key}$ 填入 `recipients[i].encrypted_key`。
7. **加密 Payload**：
    * 使用 CEK 加密内层数据：
      $$
      (\text{ciphertext}, \text{tag}) = \text{AES-GCM-Encrypt}(\text{key}=CEK, \text{iv}=IV, \text{aad}=AAD, \text{pt}=\text{JWS\_Bytes})
      $$

##### 2. 解密流程 (接收方)

1. **X25519 恢复**：

    * 从 `protected.epk` 提取发送方临时公钥。
    * 计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{static}^{recv}, pk_{eph})$。
2. **ML-KEM 恢复**：

    * 从 `recipients[i].ek` 提取密文。
    * 解封装抗量子共享秘密：$SS_{PQ} = \text{ML-KEM.Decap}(sk_{static}^{recv}, ek)$。
3. **校验路由指纹 (rid Check)**：
    * 拼接共享秘密：$IKM_{rid} = SS_{ECC} \ || \ SS_{PQ}$。
    * **本地重算指纹**：

      $$rid_{check} = \text{HKDF-Expand}\big(\text{HKDF-Extract}(\text{salt="wind"}, IKM_{rid}), \text{info="rid/hybrid"}, L=16\big)$$
    * **比对**：将 $rid_{check}$ 与消息头中的 `recipients[i].rid` 进行**常量时间比较**。
    * *判定*：若不匹配，则说明该条目不是发给自己的（或已被篡改），跳过或拒绝；若匹配，继续执行后续步骤。
4. **混合派生 KEK (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    * 执行 HKDF 操作计算出 **KEK**。
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
5. **解密 CEK**：

    * 使用 KEK 解密 `recipients[i].encrypted_key` 得到会话密钥：$CEK = \text{AES-KeyUnwrap}(KEK, C_{key})$。
6. **解密 Payload**：

    * 使用 CEK 解密外层密文得到内层数据：
      $$
      \text{JWS}\_\text{Bytes} = \text{AES-GCM-Decrypt}(\text{key}=CEK, \text{iv}=IV, \text{aad}=AAD, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})
      $$

## 混淆模式下计算 rid

**记号与标准**

- **HKDF**: 使用 HMAC-SHA-256。[[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)]
- **输出编码**: Base64URL（无填充）。
- **算法参考**: X25519 [[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)];
  ML-KEM-768 [[FIPS 203](https://csrc.nist.gov/pubs/fips/203/ipd)]。

---

### 1) 混合指纹计算逻辑 (Hybrid RID)

**输入准备**

- **ECC 共享秘密**：$SS_{\mathrm{ECC}}=\mathrm{X25519}(sk, pk)$ (32 bytes)
- **PQC 共享秘密**：$SS_{\mathrm{PQ}}=\mathrm{MLKEM768}(\dots)$ (32 bytes)
- **密钥输入材料 (IKM)**：直接拼接
  $$
  IKM = SS_{\mathrm{ECC}} \ || \ SS_{\mathrm{PQ}}
  $$

**HKDF 派生公式**

$$rid = \text{Base64URL}\bigg( \text{HKDF-Expand}\big(\text{HKDF-Extract}(\text{salt="wind"}, IKM), \text{info="rid/hybrid"}, L=16\big) \bigg)$$

### 2) 写入与校验

**发送方**：
计算出唯一的 $rid$ 后，写入`recipients[i]`：

```json
{
  "rid": "BASE64URL(rid_hybrid_16bytes)",
  "ek": "BASE64URL(MLKEM768_Ciphertext...)",
  "encrypted_key": "BASE64URL(wrap(CEK))"
}
```

接收方： 必须先完成 X25519 和 ML-KEM-768 的计算，得到两个共享秘密后，按上述公式重算 rid' ，并与 Header 中的字段进行
常量时间比较 (Constant-Time Compare)。

### 3) 说明与注意

安全性 (AND 逻辑)：$rid$ 的生成同时依赖 ECC 和 PQC 私钥。即使 ECC 被破解，攻击者因无法解开 PQC 部分，仍无法计算出 $rid$，从而无法通过匹配 `rid` 来去匿名化接收者。

唯一性：由于 $epk$ (临时公钥) 和 $ct$ (PQC密文) 对每条消息、每个接收者都是变化的，因此 $rid$ 具有一次性特征，不可跨消息追踪。

输出格式：统一使用 Base64URL（无填充）。

## 填充策略 (Bucket Padding Algorithm)

为防止流量分析攻击者通过消息体积推断接收者数量（去匿名化），混淆模式强制执行 **固定分桶填充**。

### 1. 分桶参数

- **硬下限 (Limitmin)**: **8** (即使是 1 对 1 私聊，也必须伪装成 8 人群聊)。
- **硬上限 (Limitmax)**: **32** (单条消息最多支持 32 人，超过需分包)。
- **桶集合 (Buckets)**: **{8,16,32}**。

### 2. 计算逻辑

设真实接收者数量为 m：

1. **越界检查**：若 m>32，拒绝加密或执行上层分包逻辑。

2. **确定目标长度 (S)**：
   根据 $m$ 的值，将其向上取整到最近的标准桶位：
    - 若 $1 \le m \le 8$，则 $S = 8$
    - 若 $9 \le m \le 16$，则 $S = 16$
    - 若 $17 \le m \le 32$，则 $S = 32$

3. **诱饵数量 (Countdecoy)**：

   Countdecoy=S−m

### 3. 诱饵构造 (Decoy Construction)

为了确保不可区分性，诱饵条目必须在数据结构和字节长度上与真实条目**完全一致**。诱饵数据应由密码学安全的伪随机数生成器 (CSPRNG) 生成。

- **rid**: 随机 16 字节 (Base64URL)。
- **encrypted_key**: 随机 40 字节 (Base64URL)。*(对应 AES-KeyWrap 的 32B+8B)*
- **ek** (仅混合模式): 随机 1088 字节 (Base64URL)。*(对应 ML-KEM-768 密文长度)*
- *(注：在纯 ECC 模式下，不生成 `ek` 字段)*

## 安全边界

### 1. 不提供向前安全
- 公开模式与混淆模式均不保证向前安全。若**接收方长期解密私钥** (X25519 或 ML-KEM-768) 在未来泄露，攻击者可能对既往捕获的报文复原共享秘密并解密历史消息。
### 2. 仅保护传输层
- 若投递层依赖中心化聊天软件的一对一私聊，通常**无法提供**强匿名与“聊天关系隐藏”；如需更强的投递匿名性，应使用具备匿名特性的投递/网络方案 (不在此协议范围内) 。
- 此协议主要对抗**传输链路上的被动窃听/篡改**；设备被入侵，密钥被盗等场景无法提供任何保护。
### 3. 混淆模式仅有限保护元信息
- 如需降低“发给谁/发给多少人”等社交关系元信息泄露风险，应选择**混淆模式**；公开模式**不提供**元信息保护能力。
- 注意：混淆模式仍可能受到**流量分析**影响 (例如报文大小、发送频率、时间关联、网络侧关联等) 。
### 4. 适用范围与安全经济学
- 此协议配合良好的信息安全习惯可显著提高攻击成本，对高资源对手依然无法保证安全，在一般威胁模型下提供合理安全性。