> 约定：
>
> - `"BASE64URL(...)"` 都是占位（你实现时用真实 Base64url 替换）。
> - 这是 **结构示意**，不是可以直接验签的真实数据。

------

## 0.（可选）聊天场景的装甲封装 JSON-Armor

如果你用“外壳”来方便聊天 / 复制粘贴，大概长这样：

```json
{
  "type": "wind-letter",
  "encoding": "base64url",        // 或 "windbase1024f"
  "v": "1",
  "data": "BASE64URL( <下面整段 JWE JSON 的 UTF-8 字节> )"
}
```

真正要做加解密的是 **data 解出来的那段 JWE JSON** ↓

------

## 1. 外层 JWE JSON（网络上传的主体）

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jwe\",\"cty\":\"wind+jws\",\"ver\":\"1.0\",\"wind_mode\":\"public\",\"enc\":\"A256GCM\"})",
  "aad": "BASE64URL(JCS(recipients))",
  "recipients": [
    {
      "header": {
        "kid": "BASE64URL(kid-alice-ecc)",
        "alg": "ECDH-ES+A256KW",
        "epk": {
          "kty": "OKP",
          "crv": "X25519",
          "x": "BASE64URL(...)"
        }
      },
      "encrypted_key": "BASE64URL(...)"
    }
  ],
  "iv": "BASE64URL(...)",
  "ciphertext": "BASE64URL(...)",
  "tag": "BASE64URL(...)"
}
```

> 注意：
>
> - `protected` 解出来是：`{ "typ":"wind+jwe", "cty":"wind+jws", "ver":"1.0", "wind_mode":"public", "enc":"A256GCM" }`（可选再多一个 `"zip":"zstd"`）。
> - 外层 **不再有 `ts` / `wind_id` / `meta`** 这些字段，和你之前的 `WindLetter.json` 老稿不一样。

------

## 2. 解密后得到的内层 JWS JSON

把上面的 `ciphertext` 用 CEK + `iv` + `AAD_bytes` 解密后，你会拿到一个 **JWS 对象**：

```json
{
  "protected": "BASE64URL({\"typ\":\"wind+jws\",\"alg\":\"EdDSA\",\"kid\":\"BASE64URL(sender-kid)\",\"ts\":1731800000,\"pht\":\"BASE64URL(SHA256(JCS(outer.protected_json)))\",\"rch\":\"BASE64URL(SHA256(JCS(outer.recipients)))\"})",
  "payload": "BASE64URL({\"meta\":{\"content_type\":\"text/utf-8\",\"original_size\":3210},\"body\":{\"type\":\"text\",\"text\":\"Hello, Wind-Letter!\"}})",
  "signature": "BASE64URL(...)"
}
```

> 这里：
>
> - `ts` 是签名时间（可选，用来展示/时效）。
> - `pht` = SHA256(JCS(外层 protected_json))，把外壳 header 绑进签名。
> - `rch` = SHA256(JCS(outer.recipients))，把收件人列表绑进签名。

------

## 3. JWS payload 解出来的业务明文 JSON

再把 `payload` Base64url 解出来，就是你自己真正的业务内容了，比如聊天消息：

```json
{
  "meta": {
    "content_type": "text/utf-8",
    "original_size": 3210
  },
  "body": {
    "type": "text",
    "text": "Hello, Wind-Letter!"
  }
}
```

------

你可以直接按这三层结构来写库：

1. **最外层（可选）装甲**：`type/encoding/v/data`
2. **JWE**：`protected/aad/recipients/iv/ciphertext/tag`
3. **JWS**：`protected/payload/signature` → 明文 `meta/body`

之后要是你想，我也可以帮你把这个“完整 JSON 示例”抄进一份 **开发文档模板** 里，当成实现的对照样本用喵 🐱‍💻