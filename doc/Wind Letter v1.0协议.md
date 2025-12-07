# Wind Letter v1.0协议

## 0. 总览(协议传输通用JSON)

传输唯一结构,通用JSON

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"obfuscation\",\"enc\":\"A256GCM\",\"key_alg\":\"X25519Kyber768\",\"epk\":{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"BASE64URL(Sender_Ephemeral_Public_Key)\"},\"ek\":\"BASE64URL(MLKEM768_Ciphertext_Encapsulation)\"})",
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "rids": { "x25519": "…", "mlkem768": "…" },
      "encrypted_key": "BASE64URL(wrap(CEK))"
    }
  ],
  "iv": "BASE64URL(GCM_IV_12bytes)",
  "ciphertext": "BASE64URL(AES256GCM(plaintext=inner_JWS_bytes, key=CEK, iv=IV, aad=ASCII(protected_b64+\".\"+aad)))",
  "tag": "BASE64URL(GCM_tag_16bytes)"
}

```

传输JSON内容嵌套层全部解密、解base64url后展开的完全结构

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
        },
        "ek": "<MLKEM768_Ciphertext_Encapsulation: 1088 bytes>"
    },
    "aad": "BASE64URL( JCS(recipients) )",
    "recipients": [
        {
            "rids": {
                "x25519": "…",
                "mlkem768": "…"
            },
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

## 验证消息:

### 简述:

- 由 AES-GCM 认证的：`aad`, `iv`, `ciphertext`, `tag`, 任何一个改 1 bit → GCM 校验失败
- 由 JWS 签名认证的：`ciphertext.protected`（含 `jwe_*_hash`）、`ciphertext.payload`, `ciphertext.signature`, 改密文任何内容1bit→签名认证失败
- 再结合 `jwe_protected_hash` / `jwe_recipients_hash`，间接保证 `outer.protected` 与 `outer.recipients` 也 1 bit 不改→整个消息1bit不改才能认证成功



好的，这是适配你最新 JSON 结构（`epk` 和 `ek` 位于 Protected Header）的精简版加密解密流程说明：



## 加密解密流程

### 混合算法：X25519Kyber768 (Hybrid Combiner)

#### 1. 加密流程 (发送方)
1.  **准备密钥**：生成随机的内容加密密钥 (**CEK**)。
2.  **X25519 协商**：
    *   生成临时密钥对 $(sk_{eph}, pk_{eph})$。
    *   计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{eph}, pk_{recv\_static})$。
    *   将 $pk_{eph}$ 填入 `protected.epk`。
3.  **ML-KEM 封装**：
    *   针对接收方公钥执行封装：$(SS_{PQ}, \ ct) = \text{ML-KEM.Encap}(pk_{recv\_static})$。
    *   将 $ct$ (1088字节) 填入 `protected.ek`。
4.  **混合派生 (Combiner)**：
    *   拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    *   派生 KEK：$KEK = \text{HKDF-Expand}(\text{HKDF-Extract}(Salt, Z), \text{Info}, \text{Length})$。
5.  **加密 CEK**：
    *   使用 KEK 加密 CEK：$C_{key} = \text{AES-GCM-Encrypt}(KEK, CEK)$。
    *   将 $C_{key}$ 填入 `recipients[0].encrypted_key`。

#### 2. 解密流程 (接收方)
1.  **X25519 恢复**：
    *   从 `protected.epk` 提取发送方临时公钥。
    *   计算经典共享秘密：$SS_{ECC} = \text{X25519}(sk_{recv\_static}, pk_{eph})$。
2.  **ML-KEM 恢复**：
    *   从 `protected.ek` 提取密文。
    *   解封装抗量子共享秘密：$SS_{PQ} = \text{ML-KEM.Decap}(sk_{recv\_static}, ek)$。
3.  **混合派生 (Combiner)**：
    *   拼接秘密：$Z = SS_{ECC} \ || \ SS_{PQ}$。
    *   执行与发送方相同的 HKDF 操作，计算出 **KEK**。
4.  **解密 CEK**：
    *   使用 KEK 解密 `recipients[0].encrypted_key`：$CEK = \text{AES-GCM-Decrypt}(KEK, C_{key})$。



# 混淆模式下计算 rid（方案 A，salt = "wind"）
**记号**  
- 使用 HKDF-HMAC-SHA256；`Trunc_N(·)` 取前 N 字节；输出使用 Base64URL（无填充）。  
- 建议 `N = 16`（128-bit）；如不敏感于体积可取 `N = 32`。

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

X25519：
$$
SS_{\mathrm{ECC}}=\mathrm{X25519}\!\left(sk^{\mathrm{recv}}_{\mathrm{ecc}},\ epk\right)
$$

ML-KEM-768：
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

## 3) 说明与注意
- 固定 `salt="wind"` 依然安全：`SS_{\mathrm{ECC}}` 随 `epk` 变、`SS_{\mathrm{PQ}}` 随 `ct_{\mathrm{PQ}}` 变，故不同消息的 `rid_*` 自然不同，外部无法重算。  
- `rid_*` 仅用于识别/路由，不参与解密或权限判定。  
- 输出统一 Base64URL（无填充）；比较时使用常量时间比较。

