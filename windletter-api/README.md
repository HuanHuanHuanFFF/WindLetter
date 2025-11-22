# windletter-api

High-level API surface:
- WindIdentity model and IdentityService storage interface.
- Sender/Receiver facades for encrypt+sign and decrypt+verify flows.
- Envelope models for encrypted output and decrypt results.
Uses crypto/protocol/armor modules; implementations are placeholders.

---

高层 API 面：
- WindIdentity 模型与 IdentityService 存储接口。
- 加密+签名、解密+验签的 Sender/Receiver 外观。
- 加密结果与解密结果的封装模型。
依赖 crypto/protocol/armor，具体实现仍为占位。
