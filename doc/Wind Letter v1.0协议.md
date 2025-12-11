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
  "ciphertext": "BASE64URL(AES256GCM(plaintext=inner_JWS_bytes, key=CEK, iv=IV, aad=ASCII(protected_b64+\".\"+aad)))",
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
        "wind_mode": "public",
        "enc": "A256GCM",
        "key_alg": "X25519Kyber768",
        "kids": { "x25519": "BASE64URL(kid-ecc-sender)"}
    },
    "aad": "BASE64URL( JCS(recipients) )",
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
            "jwe_protected_hash": "<SHA256( JCS(outer.protected_json) )>",
            "jwe_recipients_hash": "<SHA256( JCS(outer.recipients) )>"
        },
        "payload": {
            "meta": {
                "content_type": "text/utf-8",
                "original_size": 3210
            },
            "body": {
                "type": "text",
                "text": "Hello, Wind-Letter!"
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
      "rids": { "x25519": "BASE64URL(rid_x25519)", "mlkem768": "BASE64URL(rid_mlkem768)" },
      "ek": "BASE64URL(MLKEM768_Ciphertext_Encapsulation_for_this_recipient)",
      "encrypted_key": "BASE64URL(wrap(CEK))"
    }
  ],
  "iv": "BASE64URL(GCM_IV_12bytes)",
  "ciphertext": "BASE64URL(AES256GCM(plaintext=inner_JWS_bytes, key=CEK, iv=IV, aad=ASCII(protected_b64+\".\"+aad)))",
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
    "aad": "BASE64URL( JCS(recipients) )",
    "recipients": [
        {
            "rids": {
                "x25519": "…",
                "mlkem768": "…"
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
            "jwe_protected_hash": "<SHA256( JCS(outer.protected_json) )>",
            "jwe_recipients_hash": "<SHA256( JCS(outer.recipients) )>"
        },
        "payload": {
            "meta": {
                "content_type": "text/utf-8",
                "original_size": 3210
            },
            "body": {
                "type": "text",
                "text": "Hello, Wind-Letter!"
            }
        },
        "signature": "<Ed25519(signature)>"
    },
    "tag": "<16 bytes GCM tag>"
}
```

## 长度规范

| 项目 | 长度 | 依据 / 备注 |
| :--- | :--- | :--- |
| **CEK (A256GCM)** | **32 B** | NIST SP 800-38D; [[RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518)] |
| **GCM IV (Nonce)** | **12 B** | 推荐 96-bit 以获得最高效率与安全。[[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)] |
| **GCM Tag** | **16 B** | 规定 128-bit 认证标签。[[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)] |
| **HKDF 哈希** | **SHA-256** | HashLen=32 for SHA-256。[[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)] |
| **KEK** | **32 B** | 匹配 A256KW 要求的 256-bit 密钥输入。[[RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)] |
| **rid** | **16 B** | 协议自定义 (128-bit 截断哈希) |
| **wind_id** | **16 B** | UUID v4 (128-bit)。[[RFC 4122](https://www.rfc-editor.org/rfc/rfc4122)] |
| **ts** | **64-bit** | 实现约定 (Unix Timestamp) |
| **X25519 公钥** | **32 B** | 输入点格式为 32 字节。[[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748)] |
| **X25519 共享密钥** | **32 B** | 输出共享秘密为 32 字节。[[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748)] |
| **ML-KEM-768 共享密钥** | **32 B** | FIPS 203 (IPD) Algorithm 13。[[FIPS 203](https://csrc.nist.gov/pubs/fips/203/ipd)] |
| **ML-KEM-768 密文** | **1088 B** | FIPS 203 (IPD) Table 2。[[FIPS 203](https://csrc.nist.gov/pubs/fips/203/ipd)] |
| **Ed25519 签名** | **64 B** | Ed25519 签名固定长度。[[RFC 8032 §5.1.6](https://www.rfc-editor.org/rfc/rfc8032)] |
| **kid (指纹)** | **32 B** | JWK Thumbprint SHA-256。[[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)] |

## 验证消息:

### 简述:
* **外层 AES-GCM 认证范围**：`ciphertext`、`tag` 与 **AAD**（JWE 规定的 `ASCII(base64url(protected) + "." + aad)`），并且 **标签计算依赖 `iv`**。因此 `protected_b64`、`aad`、`iv`、`ciphertext` 任一比特被改，**GCM 验证失败**（除去随标签长度而来的可忽略伪造概率）。

* **内层 JWS 认证范围**：`ciphertext.protected` 与 `ciphertext.payload`（以及对应的 `signature` 校验）。这两者任何一处改 1 bit，**JWS 验签失败**。

* **外层字段的双重绑定**：`outer.protected` 与 `outer.recipients` 已被上一条 **GCM 的 AAD** 直接认证；你又在 JWS 头加入 `jwe_protected_hash` / `jwe_recipients_hash` **再次绑定**（defense-in-depth）。任一处改动都会在 **GCM 或 JWS** 层被拒绝。

## 验证流程 (Verification Process)

### 1. 外层完整性校验 (Outer Integrity Check)

**目标**：保证整个 JSON 在传输过程中 1 bit 不改。

1.  **AAD 一致性复核**：
    接收方独立计算收件人列表的摘要，并与报文中的 `aad` 字段比对：
    $$
    \text{calc_aad} = \text{Base64URL}( \text{JCS}(\text{json.recipients}) ) 
    $$

    * **判定**：若 `calc_aad != json.aad`，**拒绝**（说明有人修改了收件人列表）。

2.  **构建 GCM 参数**：
    * **Key**: 上一步解密流程得到的 **CEK**。
    * **IV**: 直接取 `json.iv`。
    * **AAD Input**: 拼接外层头与 AAD 字段（注意是 ASCII 拼接）：
        $$
        \text{AAD}_{\text{bytes}} = \text{ASCII}(\text{json.protected}) + "." + \text{ASCII}(\text{json.aad})
        $$

3.  **AES-GCM 解密与验真**：
    执行解密操作（此步骤隐含了 Tag 校验）：
    $$
    \text{JWS_Bytes} = \text{AES-GCM-Decrypt}(\text{key}=\text{CEK}, \text{iv}=\text{IV}, \text{aad}=\text{AAD}_{\text{bytes}}, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})
    $$
    * **判定**：若解密抛出异常（Tag 校验失败），**拒绝**（说明密文、Tag 或 AAD 被篡改）。
    * **成功**：获得内层明文 `JWS_Bytes`。

### 2. 内外层绑定校验 (Binding Check)

**目标**：防止“换壳攻击”（防止攻击者将合法的内层 JWS 放入伪造的外层 JWE 中）。

1.  **解析内层**：
    将 `JWS_Bytes` 反序列化为 JWS 对象，提取其 Header 中的 `pht` 和 `rch` 字段。

2.  **计算预期哈希 (Expected Hash)**：
    接收方基于**自己收到的外层数据**，重新计算指纹：
    $$
    \text{exp_pht} = \text{Base64URL}( \text{SHA256}( \text{JCS}(\text{outer.protected}) ) )
    $$
    $$
    \text{exp_rch} = \text{Base64URL}( \text{SHA256}( \text{JCS}(\text{outer.recipients}) ) )
    $$

3.  **指纹比对**：
    使用常量时间比较 (Constant-Time Compare) 核对指纹：
    * **判定**：
        $$
        \text{Check}(\text{inner.pht} == \text{exp_pht}) \quad \text{AND} \quad \text{Check}(\text{inner.rch} == \text{exp_rch})
        $$
    * 若任一不匹配，**拒绝**（说明外壳已被替换，不再与内芯匹配）。

### 3. 来源认证与签名校验 (Signature Verification)

**目标**：确认发件人身份，并确保业务正文 (Payload) 未被篡改。

1.  **获取发件人公钥**：
    从内层 JWS Header 获取 `kid`，在本地可信列表或公钥簿中查找对应的 **Ed25519 公钥** ($pk_{sign}$)。

2.  **重构签名输入 (Signing Input)**：
    拼接内层头部和 Payload 的 Base64URL 形式：
    $$
    \text{SigInput} = \text{ASCII}(\text{inner.protected_b64}) + "." + \text{ASCII}(\text{inner.payload_b64})
    $$

3.  **执行验签**：
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

### 2) rid（方案 A）
> 仅用于识别/路由，不参与解密；输出使用 Base64URL（无填充）

**X25519 路**

- **salt**：`"wind"`
- **info**：`"rid/x25519"`
- **N**：`16`

**ML-KEM-768 路**
- **salt**：`"wind"`
- **info**：`"rid/mlkem768"`
- **N**：`16`

---

### 3) GCM IV
- **IV 生成**：`Random(12 bytes, 96-bit)`
- **说明**：不使用派生 IV（每条消息随机、独立）

## 加密解密流程

### 混合算法：X25519Kyber768 (Hybrid Combiner)

#### 1. 公开模式 (Public Mode)

##### 1. 加密流程 (发送方)
1.  **准备密钥**：生成随机的内容加密密钥 (**CEK**, 32字节) 和初始向量 (**IV**, 12字节)。
2.  **ECC 计算**：使用 **发送方静态私钥** ($sk_{static}^{sender}$) 和 **接收方静态公钥** ($pk_{static}^{recv}$) 计算：
    $$SS_{ECC} = \text{X25519}(sk_{static}^{sender}, pk_{static}^{recv})$$
3.  **PQC 封装**：针对接收方 PQC 公钥执行 ML-KEM 封装，生成共享秘密 $SS_{PQ}$ 和密文 $ct$：
    $$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{static}^{recv})$$
    * 将 $ct$ 填入 `recipients[i].ek`。
4.  **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。  
    * 派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
5.  **加密 CEK**：
    * 使用 **A256KW** 包裹 CEK：$C_{key} = \text{AES-KeyWrap}(KEK, CEK)$。
    * 将 $C_{key}$ 填入 `recipients[i].encrypted_key`。
6.  **加密 Payload**：
    * 使用 CEK 加密内层数据：
     $$\big(\text{ciphertext},\ \text{tag}\big)=\text{AES-GCM-Encrypt}(\text{key}=CEK,\ \text{iv}=IV,\ \text{aad}=AAD,\ \text{pt}=\text{JWS_Bytes})$$

##### 2. 解密流程 (接收方)
1.  **识别与 ECC**：从 Header 获取发送方 ID，查找其公钥。使用 **接收方静态私钥** ($sk_{static}^{recv}$) 计算：
    $$SS_{ECC} = \text{X25519}(sk_{static}^{recv}, pk_{static}^{sender})$$
2.  **PQC 恢复**：从 `recipients[i].ek` 提取密文 $ct$，解封装得到：
    $$SS_{PQ} = \text{ML-KEM.Decap}(sk_{static}^{recv}, ct)$$
3.  **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。  
    * 执行 HKDF 操作计算出 **KEK**。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
4.  **解密 CEK**：
    * 解开 `encrypted_key` 得到会话密钥：$CEK = \text{AES-KeyUnwrap}(KEK, C_{key})$。
5.  **解密 Payload**：
    * 使用 CEK 解密外层密文得到内层数据：
        $$\text{JWS_Bytes} = \text{AES-GCM-Decrypt}(\text{key}=CEK, \text{iv}=IV, \text{aad}=AAD, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})$$

---

#### 2. 混淆模式 (Obfuscation Mode)

##### 1. 加密流程 (发送方)
1.  **准备密钥**：生成随机的内容加密密钥 (**CEK**, 32字节) 和初始向量 (**IV**, 12字节)。
2.  **X25519 协商**：
    * 生成临时密钥对 $(sk_{eph}, pk_{eph})$。
    * 计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{eph}, pk_{static}^{recv})$。
    * 将 $pk_{eph}$ 填入 `protected.epk`。
3.  **ML-KEM 封装**：
    * 针对接收方 PQC 公钥执行封装：$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{static}^{recv})$。
    * 将 $ct$ (1088字节) 填入 `recipients[i].ek`。*(注意：每位收件人独有一份)*
4.  **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。  
    * 派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
5.  **加密 CEK**：
    * 使用 **A256KW** 包裹 CEK：$C_{key} = \text{AES-KeyWrap}(KEK, CEK)$。
    * 将 $C_{key}$ 填入 `recipients[i].encrypted_key`。
6.  **加密 Payload**：
    * 使用 CEK 加密内层数据：
      $$\big(\text{ciphertext},\ \text{tag}\big)=\text{AES-GCM-Encrypt}(\text{key}=CEK,\ \text{iv}=IV,\ \text{aad}=AAD,\ \text{pt}=\text{JWS_Bytes})$$

##### 2. 解密流程 (接收方)
1.  **X25519 恢复**：
    * 从 `protected.epk` 提取发送方临时公钥。
    * 计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{static}^{recv}, pk_{eph})$。
2.  **ML-KEM 恢复**：
    * 从 `recipients[i].ek` 提取密文。
    * 解封装抗量子共享秘密：$SS_{PQ} = \text{ML-KEM.Decap}(sk_{static}^{recv}, ek)$。
3.  **混合派生 (Combiner)**：
    * 拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。  
    * 执行 HKDF 操作计算出 **KEK**。  
      **参数**：`salt="wind"`；`info="WindLetter v1 KEK | X25519Kyber768"`；`Length=32`。
4.  **解密 CEK**：
    * 使用 KEK 解密 `recipients[i].encrypted_key` 得到会话密钥：$CEK = \text{AES-KeyUnwrap}(KEK, C_{key})$。
5.  **解密 Payload**：
    * 使用 CEK 解密外层密文得到内层数据：
        $$\text{JWS_Bytes} = \text{AES-GCM-Decrypt}(\text{key}=CEK, \text{iv}=IV, \text{aad}=AAD, \text{ct}=\text{ciphertext}, \text{tag}=\text{tag})$$


## 混淆模式下计算 rid
**记号**  
- 使用 HKDF-HMAC-SHA256；`Trunc_N(·)` 取前 N 字节；输出使用 Base64URL（无填充）。  
- `N = 16`（128-bit）
- 出处：HKDF 定义见 RFC 5869；X25519 见 RFC 7748；ML-KEM-768 见 FIPS 203。

---

### 1) 发送方（写入 `recipients[i].rids`）

#### X25519 路
生成会话秘密：
$$
SS_{\mathrm{ECC}}=\mathrm{X25519}\!\left(sk_{\mathrm{eph}},\ pk^{\mathrm{recv}}_{\mathrm{ecc}}\right)
$$

派生 rid：
$$
\begin{aligned}
\mathrm{PRK}_{\mathrm{ecc}} &= \mathrm{HKDF\mbox{-}Extract}\big(\text{"wind"},\ SS_{\mathrm{ECC}}\big) \\
rid_{\mathrm{x25519}} &= \mathrm{Base64URL}\!\Big(\mathrm{Trunc}_N\big(\mathrm{HKDF\mbox{-}Expand}(\mathrm{PRK}_{\mathrm{ecc}},\ \text{"rid/x25519"},\ N)\big)\Big)
\end{aligned}
$$

#### ML-KEM-768 路
封装并得到密文：
$$
(SS_{\mathrm{PQ}},\ ct_{\mathrm{PQ}})=\mathrm{MLKEM768.Encap}\!\left(pk^{\mathrm{recv}}_{\mathrm{pq}}\right)
$$

派生 rid：
$$
\begin{aligned}
\mathrm{PRK}_{\mathrm{pq}} &= \mathrm{HKDF\mbox{-}Extract}\big(\text{"wind"},\ SS_{\mathrm{PQ}}\big) \\
rid_{\mathrm{mlkem768}} &= \mathrm{Base64URL}\!\Big(\mathrm{Trunc}_N\big(\mathrm{HKDF\mbox{-}Expand}(\mathrm{PRK}_{\mathrm{pq}},\ \text{"rid/mlkem768"},\ N)\big)\Big)
\end{aligned}
$$

写入收件人条目（示例）：
```json
{"rids": { "x25519": "<rid_x25519>", "mlkem768": "<rid_mlkem768>" }}
```

---

### 2) 接收方（匹配自己的条目）

逐路重算（与发送方同式）：

X25519（`epk` 来自 `protected.epk`）：
$$
SS_{\mathrm{ECC}}=\mathrm{X25519}\!\left(sk^{\mathrm{recv}}_{\mathrm{ecc}},\ epk\right)
$$

ML-KEM-768（`ct_{\mathrm{PQ}}` 即 `recipients[i].ek`）：
$$
SS_{\mathrm{PQ}}=\mathrm{MLKEM768.Decap}\!\left(sk^{\mathrm{recv}}_{\mathrm{pq}},\ ct_{\mathrm{PQ}}\right)
$$

从 `SS` 通过同一 HKDF 标签链得到
$rid'_{\mathrm{x25519}}$ 与 $rid'_{\mathrm{mlkem768}}$，用**常量时间比较**定位：

```
ct_eq(rid'_x25519,  recipients[i].rids.x25519) &&
ct_eq(rid'_mlkem768, recipients[i].rids.mlkem768)
```

---

#### 3) 说明与注意
- 固定 `salt="wind"` 依然安全：$SS_{\mathrm{ECC}}$ 随 $epk$ 变，$SS_{\mathrm{PQ}}$ 随 $ct_{\mathrm{PQ}}$ 变，故不同消息的 $rid$ 自然不同，外部无法重算。  
- `rid_*` 仅用于识别/路由，不参与解密或权限判定。  
- 输出统一 **Base64URL**（无填充）；比较时使用**常量时间**比较。  
- 参考：HKDF（RFC 5869）、X25519（RFC 7748）、ML-KEM-768（FIPS 203）。
