# WindLetter

WindLetter 是一个面向 `Wind Letter v1.0` 协议的 Java 库项目。

当前分支处于**重构阶段**：从旧实现迁移到新的工业化分层架构与接口设计（类似成熟密码库的 API 组织方式，但协议本身保持 Wind Letter v1.0）。

## Repository Layout

- `doc/`：协议规范、设计文档、开发参考与版本说明。
- `windletter-core/`：常量、错误模型、编码与基础工具。
- `windletter-crypto/`：密码原语适配层（AEAD/KDF/KEM/签名等）。
- `windletter-protocol/`：协议数据模型、规范化、绑定与校验逻辑。
- `windletter-armor/`：JSON/Text Armor 编解码。
- `windletter-api/`：对应用暴露的高层接口（Sender/Receiver/Request/Result）。
- `windletter-testkit/`：自检、向量测试、互操作测试。

## Build

- JDK: `17+`
- Build tool: `Maven`

常用命令：

```bash
mvn test
```

## Documentation

- 文档索引见：`doc/README.md`
- 当前主协议文档：`doc/Wind Letter v1.0协议.md`
- 重构设计文档：
  - `ARCHITECTURE_V1_REWRITE.md`
  - `PROTOCOL_GAP_MATRIX.md`
  - `API_CONTRACT_V1.md`
  - `TEST_PLAN_V1.md`
