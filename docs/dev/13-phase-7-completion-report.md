# 阶段 7 完成报告：WindLetter v1.0 Demo

> 日期：2026-07-23
> 分支：`spike/demo-v0`
> 结论：阶段 7 完成；最终 Armor 修订已接入，当前定义的 WindLetter v1.0 Demo 具备真实、完整、可运行的端到端链路。

## 1. 完成结果

- Binary、标准 Base64 PEM 与 風笺文本共享严格公共帧；版本改为正整数 canonical unsigned LEB128，v1 binary 向量保持不变。
- Base64 使用 RFC 4648 标准字母表、`=` padding、64 ASCII 字符换行及固定 PEM 头尾。
- 風笺使用固定头尾、冻结的 `WLA`/版本引导、`凪` 终止符和 WindBase1024F v1 正文字表；遍历、截断和换行均按 Unicode 码点。
- Sender 全部 8 个 profile 可输出 raw、`BASE64_PEM`、`WIND_BASE_1024F_V1` 或 binary。
- Receiver 可按显式格式解码，或仅根据精确 English/Chinese header 自动路由；不再按 ASCII/非 ASCII 猜测，也不跨格式回退。
- `DecryptRequest` 强制 raw/text/binary exact-one；错误头部、未知/非规范版本、损坏和错格式 Armor 均在打开 recipient key lease 前返回 `INVALID_MESSAGE`。
- `windletter-testkit` 使用真实 BC 密钥句柄和 API lease 驱动的内存 Demo repository，不 mock 协议或密码学主链。
- 非 JUnit `WindLetterDemo` 已通过公开 API 完成生成、Armor 传递、解析、路由、解密和认证结果展示。
- 正式协议的 `开发修订` 已冻结本次 Armor 规则；完整字符表与哈希见 `docs/WindLetter Armor规则.md`。

## 2. 最终验证证据

指定 JDK：`C:\Users\幻\.jdks\ms-17.0.16`

```powershell
mvn -q -pl windletter-testkit -am -Pdemo verify
```

结果：95 suites / 928 tests，0 failure、0 error、0 skipped；非 JUnit Demo 同次成功输出：

- public / X25519 / unsigned / Base64 PEM：`SUCCESS`、`UNSIGNED`、2 recipients。
- public / Hybrid / signed / 風笺：`SUCCESS`、`SIGNED_VALID`、2 recipients。
- obfuscation / X25519 / signed / binary：`SUCCESS`、`SIGNED_VALID`、8 recipient slots。
- obfuscation / Hybrid / unsigned / 風笺：`SUCCESS`、`UNSIGNED`、8 recipient slots。
- 无关密钥：`NOT_FOR_ME`。
- 截断 風笺：`INVALID_MESSAGE`，`keyLeases=0`。
- 结束标记：`DEMO_OK successes=4`。

## 3. 完整能力检查

| 能力 | 状态 | 主要证据 |
|---|---|---|
| public / obfuscation | 完成 | 8-profile API 与 testkit 矩阵 |
| X25519 / X25519ML-KEM-768 | 完成 | 真实 BC key handle、KEK/CEK 与收发链 |
| signed / unsigned | 完成 | `SIGNED_VALID` / `UNSIGNED` 矩阵与 Demo |
| 多收件人 | 完成 | 每条成功链路使用2个真实收件人 |
| obfuscation 路由与填充 | 完成 | 2个真实收件人填充到8槽并成功解密 |
| strict outer wire / AAD / binding | 完成 | 既有协议严格测试与928项全仓回归 |
| Armor | 完成 | PEM/風笺头尾、版本、exact bytes、CRC、UTF-8、canonical、篡改、截断、错格式、超限 |
| API Sender / Receiver | 完成 | 8 profiles × 4 formats × text/binary payload |
| 错误语义 | 完成 | `NOT_FOR_ME`、统一 `INVALID_MESSAGE`、parse-before-key 隔离 |
| 可运行 Demo | 完成 | `-Pdemo verify` 非 JUnit main 实际运行 |

## 4. 安全与正确性复查

- 开放 P0：0；开放 P1：0。
- 没有禁用测试、mock 核心密码学链路或绕过 strict validation/AAD/binding/验签的 Demo 分支。
- CRC-32 只承担传输损坏检测；安全边界仍是 GCM、binding 和签名。
- 未知或非规范 Armor 版本、错误头部及显式格式错配均在私钥访问前失败。
- Demo 不输出私钥、shared secret、CEK、KEK 或敏感随机材料。
- 内部 JSON 字段仍使用协议原有 Base64URL；标准 Base64 只用于外部 PEM Armor。

## 5. 已知 P2 与影响

以下项目不影响协议、安全、当前能力完整性或 Demo 运行，继续放到 Demo 后：

1. Armor 为内存型 API，存在数组和字符串复制；20 MiB 上限控制风险，streaming/zero-copy 可改善大消息性能。
2. 补充平面汉字的字体覆盖与聊天平台显示尚未做多平台 smoke；编码按码点可逆，影响主要是显示体验。
3. API 模块的早期私有 E2E fixture 与最终 testkit 矩阵仍有部分重复，只增加维护成本。
4. 跨语言互操作目前以冻结向量为主，尚无第二种独立实现参与验证。
5. Demo 使用生成式内存密钥和固定场景，没有 CLI 参数、持久化 KMS 或网络传输；不影响真实协议链，但限制演示交互性。
6. 旧字表说明文件名仍含 `draft`；其字表内容有效，最终 framing 已由正式 Armor 规则取代。

## 6. 下一步

核心库 Demo 与最终 Armor 已完成；下一步可在独立项目中开发 JavaFX 桌面端。
