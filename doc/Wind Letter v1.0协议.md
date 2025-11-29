# Wind Letter v1.0协议

## 0. 总览(协议传输通用JSON)

传输唯一结构,通用JSON

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"public\",\"enc\":\"A256GCM\"})",

  "aad": "BASE64URL(JCS(recipients))",

  "recipients": [
    {
      "header": {
        "kid": "BASE64URL(kid-alice-ecc)",      // public 模式；obfuscation 时会换成 rid
        "alg": "ECDH-ES+A256KW",
        "epk": {
          "kty": "OKP",
          "crv": "X25519",
          "x": "BASE64URL(sender-ephemeral-pubkey)"
        }
      },
      "encrypted_key": "BASE64URL(CEK 密文)"
    }
  ],

  "iv": "BASE64URL(GCM-IV)",
  "ciphertext": "BASE64URL(JWS 密文)",
  "tag": "BASE64URL(GCM-Tag)"
}

```

传输JSON内容嵌套层全部解密、解base64url后展开的完全结构

```json
{
  "protected": {
    "typ": "wind+jwe",      // 固定：说明这是 WindLetter 的 JWE 对象
    "cty": "wind+jws",      // 固定：密文里面装的是一个 JWS 对象
    "ver": "1.0",           // 协议版本号
    "wind_mode": "public",  // 工作模式："public" 或 "obfuscation"
    "enc": "A256GCM"        // 对称加密算法（固定 A256GCM）
    // 可选："zip": "zstd"  // 若启用压缩，才会出现
  },

  // AAD = BASE64URL( JCS(recipients) )，只参与 GCM 认证，本身不是密文
  "aad": "BASE64URL( JCS(recipients) )",

    
   	"key_alg": "WIND-HYB-X25519+MLKEM768",   // 全局混合封装算法ID,这里用“完整混合算法ID”
    "ephemeral_keys": [			// 使用到的所有算法的临时密钥（仅混淆模式下存在）
        { "alg": "X25519",     "pub": "BASE64URL(...)" },
        { "alg": "ML-KEM-768", "pub": "BASE64URL(...)" }
      ]
    },
    "recipients": [
      {
       	"kid": "BASE64URL(kid-alice-ecc)",   // public 模式
        // "rid": "BASE64URL(...)",         // obfuscation 模式
        // 可以是 “封装 CEK 所需的全部密文/数据”的打包结果
        "encrypted_key": "BASE64URL( CEK 封装数据 )"
      }
    ],
    
  // [密文参数] GCM 的随机 IV（12 字节），BASE64URL 编码
  "iv": "BASE64URL( GCM-IV )",

  // [密文] 实际上传输时，这里是 BASE64URL( AES-GCM( 内层 JWS 字节 ) )
  // 为了说明结构，这里展开成“解密后”的 JWS JSON：
  "ciphertext": {
    "protected": {
      "typ": "wind+jws",                    // 固定：说明这是 WindLetter 的 JWS 对象
      "alg": "EdDSA",                       // 签名算法（Ed25519）
      "kid": "BASE64URL(sender-kid)",       // 签名者（发送方）公钥指纹
      "ts": 1731800000,                     // 可选：签名时间（Unix 时间戳）
      "wind_id": "BASE64URL(wind-id)",      // 此消息唯一 ID，用于去重、防重放

      // 把外层 JWE 绑定进签名，防止“换壳 / 换收件人列表”
      "jwe_protected_hash": "BASE64URL( SHA256( JCS(outer.protected_json) ) )",  // 绑定外层 protected
      "jwe_recipients_hash": "BASE64URL( SHA256( JCS(outer.recipients) ) )"       // 绑定外层 recipients
    },

    // 实际上传输时：payload 是 BASE64URL( 业务明文 JSON 字节 )
    // 这里为方便理解，直接展开成解码后的明文 JSON 结构：
    "payload": {
      "meta": {
        "content_type": "text/utf-8",  // 业务内容的类型（如 text/utf-8, application/json）
        "original_size": 3210          // 可选：原始明文字节长度，用于展示/截断
      },
      "body": {
        "type": "text",                // 业务类型：如 "text"、"json"、"file" 等
        "text": "Hello, Wind-Letter!"  // 实际的聊天内容 / 日志内容 等
      }
    },

    // [密文] 对上面 protected + payload 的签名值（Ed25519），BASE64URL 编码
    "signature": "BASE64URL( Ed25519(signature) )"
  },

  // [密文] GCM 的认证 tag（16 字节），BASE64URL 编码
  "tag": "BASE64URL( GCM-Tag )"
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

## 混淆模式下计算rid

### 发送端：生成 rid（每个收件人一条）

对每个收件人 R：

1. **全局临时密钥**

   - 先为每个算法生成一对临时密钥对（只生成一次）：
     - X25519：`(ephem_priv_x, ephem_pub_x)`
     - ML-KEM-768：`(ephem_priv_kem, ephem_pub_kem)`
   - `ephem_pub_*` 写进 `protected.ephemeral_keys`；私钥只在本地保存。

2. **算多算法 shared secret**

   - 对 R 的各算法shared secret：
     - `secret_x = KEX_X25519(ephem_priv_x, R_pub_x)`
     - `secret_k = KEX_MLKEM(ephem_priv_kem, R_pub_k)`
   - 把它们按 `alg` 排好序，然后拼接成一个大 secret。
     - secret_all =  alg1_utf8 || 0x00 || secret1 ||  alg2_utf8 || 0x00 || secret2 ||  ... 

3. **用 KDF 派生 master、rid、CEK**

   - `master = HKDF( secret_all, salt="Wind-HYB", info="master" )`

   - `rid_bytes = HKDF( master, info="rid", L=32 )`

   - `rid = BASE64URL(rid_bytes)`，写到该收件人的：

     ```json
     { "rid": "BASE64URL(rid)", "encrypted_key": "..." }
     ```

   - `encrypted_key` 是密文,需要接收者确定自己身份后用私钥解密,然后才能得到CEK

------

### 接收端：算自己的 rid，找到那条 recipient

收到整条 JWE 后（obfuscation 模式）：

1. 从 `protected.ephemeral_keys` 取出所有临时公钥。
2. 用自己的私钥，对每个算法做同样的 KEX：
   - `secret_x' = KEX_X25519(my_priv_x, ephem_pub_x)`
   - `secret_k' = KEX_MLKEM(my_priv_kem, ephem_pub_k)`
   - 同样按 `alg` 排序，拼接
     - secret_all =  alg1_utf8 || 0x00 || secret1 ||  alg2_utf8 || 0x00 || secret2 ||  ... 
3. 用**完全相同的 HKDF 规则**算：
   - `master'`, `rid_bytes'`
   - `my_rid = BASE64URL(rid_bytes')`。
4. 在 `recipients` 数组里找：
   - 有哪一条满足 `recipient.rid == my_rid`：
   - 找到 → 就是你的那条，用 私钥解密`encrypted_key` 得到CEK, 如有多个做标准拼接后得到CEK 
   - 找不到 → 这条消息不是发给你。
   