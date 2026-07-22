# 阶段 7 完成报告：WindLetter v1.0 Demo

> 日期：2026-07-22
> 分支：`spike/demo-v0`
> 结论：阶段 7 完成；当前定义的 WindLetter v1.0 Demo 已具备真实、完整、可运行的端到端链路。

## 1. 完成结果

- 三种 armor 共用严格 v1 frame：binary、canonical Base64URL、WIND_BASE_1024F_V1。
- WindBase 使用冻结的 1024 码点字表、10-bit MSB-first packing、严格 surrogate 与尾部零 bit 校验。
- Sender 全部 8 个 profile 可输出 raw、Base64URL、WindBase 或 binary。
- Receiver 可从显式或自动识别的 armor 恢复 exact outer JSON UTF-8 bytes，再进入 strict outer parser、路由、解密、binding 与可选验签。
- `DecryptRequest` 强制 raw/text/binary exact-one；损坏 armor 在打开 recipient key lease 前统一返回 `INVALID_MESSAGE`。
- `windletter-testkit` 提供真实 BC 密钥句柄和 API lease 驱动的内存 Demo repository，不 mock 协议或密码学主链。
- 非 JUnit `WindLetterDemo` 已通过公开 API 实际完成生成、armor 传递、解析、路由、解密和认证结果展示。

## 2. 最终验证证据

指定 JDK：`C:\Users\幻\.jdks\ms-17.0.16`

```powershell
mvn -q clean verify
```

结果：94 suites / 919 tests，0 failure、0 error、0 skipped。

```powershell
mvn -q -pl windletter-testkit -am -Pdemo verify
```

结果：进程成功退出并输出：

- public / X25519 / unsigned / Base64URL：`SUCCESS`、`UNSIGNED`、2 recipients。
- public / Hybrid / signed / WindBase：`SUCCESS`、`SIGNED_VALID`、2 recipients。
- obfuscation / X25519 / signed / binary：`SUCCESS`、`SIGNED_VALID`、8 recipient slots。
- obfuscation / Hybrid / unsigned / WindBase：`SUCCESS`、`UNSIGNED`、8 recipient slots。
- 无关密钥：`NOT_FOR_ME`。
- 截断 WindBase：`INVALID_MESSAGE`，`keyLeases=0`。
- 结束标记：`DEMO_OK successes=4`。

## 3. 完整能力检查

| 能力 | 状态 | 主要证据 |
|---|---|---|
| public / obfuscation | 完成 | 8-profile API 与 testkit 矩阵 |
| X25519 / X25519ML-KEM-768 | 完成 | 真实 BC key handle、KEK/CEK 与收发链 |
| signed / unsigned | 完成 | `SIGNED_VALID` / `UNSIGNED` 矩阵与 Demo |
| 多收件人 | 完成 | 每条成功链路使用 2 个真实收件人 |
| obfuscation 路由与填充 | 完成 | 2 个真实收件人填充到 8 槽并成功解密 |
| strict outer wire / AAD / binding | 完成 | 既有协议严格测试与 919 项全仓回归 |
| armor | 完成 | exact bytes、CRC、UTF-8、canonical、篡改、截断、错格式、超限 |
| API Sender / Receiver | 完成 | 8 profiles × 4 formats × text/binary payload |
| 错误语义 | 完成 | `NOT_FOR_ME`、统一 `INVALID_MESSAGE`、key-before-parse 隔离 |
| 可运行 Demo | 完成 | `-Pdemo verify` 非 JUnit main 实际运行 |

## 4. 最终安全与正确性复查

- 开放 P0：0。
- 开放 P1：0。
- 没有禁用测试、mock 核心密码学链路或绕过 strict validation/AAD/binding/验签的 Demo 分支。
- CRC-32 只承担传输损坏检测，不被描述或使用为攻击者不可伪造的认证；安全边界仍是 GCM、binding 和签名。
- Demo 不输出私钥、shared secret、CEK、KEK 或敏感随机材料。
- WindBase 符号遍历、截断和计数均按 Unicode code point；`String.length()` 只用于 UTF-16 边界遍历或明确标注的 `armorUtf16Units` 展示。
- 公开 Receiver 只收敛不可信 armor/protocol 失败；本地字表资源或配置故障不会被伪装成远端坏消息。

## 5. 已知 P2 与影响

以下项目不影响协议、安全、当前能力完整性或 Demo 运行，按约定推迟到 Demo 后：

1. Armor 当前为内存型 API，存在数组复制；20 MiB 上限控制风险，但 streaming/zero-copy 可改善大消息性能。
2. 补充平面汉字的字体覆盖与聊天平台显示尚未做多平台 smoke；编码按码点可逆，影响主要是显示体验。
3. API 模块保留了早期私有 E2E fixture，与最终 testkit 矩阵有部分重复；只增加维护成本。
4. 跨语言互操作目前以冻结 armor 向量为主，尚无第二种独立实现参与验证。
5. Demo 使用生成式内存密钥和固定场景，没有 CLI 参数、持久化 KMS 或网络传输；不影响真实协议链，但限制演示交互性。
6. 字表说明文件名仍含 `draft`；内容和 SHA-256 已冻结，仅是命名债务。
7. Armor framing 当前作为项目传输扩展记录在开发规范中；若未来成为跨实现正式标准，需要迁入正式协议发布流程。

## 6. 下一步

等待用户确认后再进入 Demo 后优化。默认不继续做架构、性能、命名或工业化扩展。
