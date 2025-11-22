# WindLetter

Java library scaffold for Wind Letter protocol.

- doc/ : spec, design, and dev docs.
- windletter-core/ : shared constants, algorithm whitelist, encoding helpers.
- windletter-crypto/ : crypto primitives adapter layer (AES-GCM, HKDF, Ed25519, X25519, ML-KEM-768 placeholders).
- windletter-protocol/ : JWE/JWS/Payload models and JCS interface.
- windletter-armor/ : JSON/Text armor models and codecs (placeholders).
- windletter-api/ : high-level Sender/Receiver/Identity interfaces.
- windletter-testkit/ : self-check and interop test placeholders.

Build with JDK 17: `./gradlew clean build`.

---

风笺协议的 Java 库骨架。

- doc/：协议规范、设计与开发文档。
- windletter-core/：公共常量、算法白名单、编码辅助。
- windletter-crypto/：密码原语适配层（AES-GCM、HKDF、Ed25519、X25519、ML-KEM-768 占位）。
- windletter-protocol/：JWE/JWS/载荷模型与 JCS 接口。
- windletter-armor/：JSON/Text 装甲模型与编解码占位。
- windletter-api/：高层 Sender/Receiver/Identity 接口。
- windletter-testkit/：自检与互操作测试占位。

使用 JDK 17 构建：`./gradlew clean build`。
