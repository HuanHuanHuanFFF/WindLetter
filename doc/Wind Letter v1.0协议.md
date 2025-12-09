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





保证1bit不改的集合:

```
aad
iv
ciphertext
tag
```



## 长度规范

| 项目                             | 长度                                      | 依据 / 备注                                                  |
| -------------------------------- | ----------------------------------------- | ------------------------------------------------------------ |
| **CEK（A256GCM）**               | **32 B**                                  | A256GCM 使用 256-bit 密钥。                                  |
| **GCM IV（Nonce）**              | **12 B（96-bit）**                        | JWA/NIST 要求与推荐使用 96-bit IV。([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7638.html?utm_source=chatgpt.com)) |
| **GCM Tag**                      | **16 B（128-bit）**                       | JWA 要求 128-bit 认证标签。                                  |
| **HKDF 哈希**                    | **SHA-256（HashLen=32 B）**               | RFC 5869。([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8032.html?utm_source=chatgpt.com)) |
| **KEK（由混合 KDF 得）**         | **32 B**                                  | 与 A256GCM/A256KW 强度对齐。                                 |
| **HKDF-Expand 长度（→ KEK）**    | **32 B**                                  | 产出 256-bit KEK（上行一致）。([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8032.html?utm_source=chatgpt.com)) |
| **HKDF-Expand 长度（→ IV）**     | **12 B**                                  | 直接派生 96-bit IV。([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8032.html?utm_source=chatgpt.com)) |
| **rid**                          | **16 B（默认）/ 32 B（可选）**            | 识别/路由用；Base64URL 表示。—                               |
| **wind_id**                      | **16 B 随机（建议 UUIDv4）**              | UUID 总长 128 bit；v4 实际随机位 ~122 bit。([datatracker.ietf.org](https://datatracker.ietf.org/doc/rfc9562/?utm_source=chatgpt.com)) |
| **ts（时间戳）**                 | **64-bit Unix time**                      | 实现约定。—                                                  |
| **X25519 公钥 / 共享秘密**       | **32 B / 32 B**                           | RFC 7748。([openid-foundation-japan.github.io](https://openid-foundation-japan.github.io/rfc7638.ja.html?utm_source=chatgpt.com)) |
| **ML-KEM-768 共享秘密**          | **32 B**                                  | FIPS 203。([datatracker.ietf.org](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-eddsa-00?utm_source=chatgpt.com)) |
| **ML-KEM-768 封装密文（ek/ct）** | **1088 B**                                | FIPS 203 定长。([datatracker.ietf.org](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-eddsa-00?utm_source=chatgpt.com)) |
| **Ed25519 签名**                 | **64 B**                                  | RFC 8032。([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8032.html?utm_source=chatgpt.com)) |
| **kid（指纹）**                  | **JWK Thumbprint（SHA-256 → 32 B 摘要）** | RFC 7638。([datatracker.ietf.org](https://datatracker.ietf.org/doc/html/rfc7638?utm_source=chatgpt.com)) |

## 验证消息:

### 简述:
* **外层 AES-GCM 认证范围**：`ciphertext`、`tag` 与 **AAD**（JWE 规定的 `ASCII(base64url(protected) + "." + aad)`），并且 **标签计算依赖 `iv`**。因此 `protected_b64`、`aad`、`iv`、`ciphertext` 任一比特被改，**GCM 验证失败**（除去随标签长度而来的可忽略伪造概率）。

* **内层 JWS 认证范围**：`ciphertext.protected` 与 `ciphertext.payload`（以及对应的 `signature` 校验）。这两者任何一处改 1 bit，**JWS 验签失败**。

* **外层字段的双重绑定**：`outer.protected` 与 `outer.recipients` 已被上一条 **GCM 的 AAD** 直接认证；你又在 JWS 头加入 `jwe_protected_hash` / `jwe_recipients_hash` **再次绑定**（defense-in-depth）。任一处改动都会在 **GCM 或 JWS** 层被拒绝。



## 加密解密流程

### 混合算法：X25519Kyber768 (Hybrid Combiner)


#### 1. 公开模式 

##### 1. 加密流程 (发送方)
1.  **ECC**: 使用 **发送方静态私钥** ($sk_{static}^{sender}$) 和 **接收方静态公钥** 计算：
    $$ SS_{ECC} = \text{X25519}(sk_{static}^{sender}, pk_{static}^{recv}) $$
2.  **PQC**: 同样执行 ML-KEM 封装，生成 $ct$ 和 $SS_{PQ}$ (随机)。
3.  **Combiner**: $Z = SS_{ECC} \ || \ SS_{PQ}$，后续同 HKDF 流程。

##### 2. 解密流程 (接收方)
1.  **识别**: 从 `protected.kids.x25519` 获取发送方 ID，查找对应的 **发送方静态公钥** ($pk_{static}^{sender}$)。
2.  **ECC**: 使用 **接收方静态私钥** ($sk_{static}^{recv}$) 计算：
    $$ SS_{ECC} = \text{X25519}(sk_{static}^{recv}, pk_{static}^{sender}) $$
3.  **PQC**: 解开 `ek` 得到 $SS_{PQ}$。
4.  **Combiner**: 混合后解密。

#### 2. 混淆模式 (Ephemeral-Static ECC + Ephemeral PQC)

##### 1. 加密流程 (发送方)
1.  **准备密钥**：生成随机的内容加密密钥 (**CEK**)。
2.  **X25519 协商**：
    *   生成临时密钥对 $(sk_{eph}, pk_{eph})$。
    *   计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{eph}, pk_{recv\_static})$。
    *   将 $pk_{eph}$ 填入 `protected.epk`。
3.  **ML-KEM 封装**：
    *   针对接收方公钥执行封装：$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{recv\_static})$。
    *   将 $ct$ (1088字节) 填入 `recipients[i].ek`。*(注意：每位收件人独有一份)*
4.  **混合派生 (Combiner)**：
    *   拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    *   派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。
5.  **加密 CEK**：
    *   使用 KEK 加密 CEK：$C_{key} = \text{AES-GCM-Encrypt}(KEK, CEK)$。
    *   将 $C_{key}$ 填入 `recipients[i].encrypted_key`。

##### 2. 解密流程 (接收方)
1.  **X25519 恢复**：
    *   从 `protected.epk` 提取发送方临时公钥。
    *   计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{recv\_static}, pk_{eph})$。
2.  **ML-KEM 恢复**：
    *   从 `recipients[i].ek` 提取密文。
    *   解封装抗量子共享秘密：$SS_{PQ} = \text{ML-KEM.Decap}(sk_{recv\_static}, ek)$。
3.  **混合派生 (Combiner)**：
    *   拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    *   执行与发送方相同的 HKDF 操作，计算出 **KEK**。
4.  **解密 CEK**：
    *   使用 KEK 解密 `recipients[i].encrypted_key`：$CEK = \text{AES-GCM-Decrypt}(KEK, C_{key})$。




# 混淆模式下计算 rid（方案 A，salt = "wind"）
**记号**  
- 使用 HKDF-HMAC-SHA256；`Trunc_N(·)` 取前 N 字节；输出使用 Base64URL（无填充）。  
- 建议 `N = 16`（128-bit）；如不敏感于体积可取 `N = 32`。  
- 出处：HKDF 定义见 RFC 5869；X25519 见 RFC 7748；ML-KEM-768 见 FIPS 203。

---

## 1) 发送方（写入 `recipients[i].rids`）

### X25519 路
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

### ML-KEM-768 路
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

## 2) 接收方（匹配自己的条目）

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

### 3) 说明与注意
- 固定 `salt="wind"` 依然安全：$SS_{\mathrm{ECC}}$ 随 $epk$ 变，$SS_{\mathrm{PQ}}$ 随 $ct_{\mathrm{PQ}}$ 变，故不同消息的 $rid$ 自然不同，外部无法重算。  
- `rid_*` 仅用于识别/路由，不参与解密或权限判定。  
- 输出统一 **Base64URL**（无填充）；比较时使用**常量时间**比较。  
- 参考：HKDF（RFC 5869）、X25519（RFC 7748）、ML-KEM-768（FIPS 203）。
