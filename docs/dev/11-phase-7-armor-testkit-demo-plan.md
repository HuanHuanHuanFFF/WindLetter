# 阶段 7：Armor、Testkit 与可运行 Demo 计划

> 状态：进行中；Task 1—5 已完成，下一步 Task 6 可独立运行 Demo
> 日期：2026-07-22
> 分支：`spike/demo-v0`

## 1. 阶段目标

本阶段在不改变 Wind Letter v1.0 outer JSON 协议语义的前提下，完成可逆、严格、可自动检测的传输封装，并把全部 8 个协议 profile 经公开 API、真实 armor 和独立 Demo 入口跑通。

本阶段完成后，项目才能声明“完整 Demo 可运行”；单独完成某一种 codec、API 接线或测试矩阵都不等于阶段完成。

## 2. 真实基线审计

2026-07-22 阶段开始时重新核对：

- `spike/demo-v0` 的本地 HEAD 与 `origin/spike/demo-v0` 均为 `6e326b5`。
- 工作区只有既存 `docs/README.md` 行尾噪音，继续不纳入任何阶段提交。
- `windletter-armor` 只有 POM 与 README，没有 main/test Java 源码。
- `windletter-testkit` 只有 POM 与 README，没有 main/test Java 源码。
- 正式 `docs/Wind Letter v1.0协议.md` 定义的是 outer JSON wire，没有 armor framing；armor 是 WindLetter 项目传输扩展，不能改变 AAD、binding、密文或签名语义。
- `windletter-api` 已预留 `NONE`、`BASE64URL`、`WIND_BASE_1024F_V1`、`BINARY`，但默认 Sender/Receiver 运行时明确只接受 `NONE`。
- `DecryptRequest` 当前没有禁止同时提供 raw wire 与 armor，存在输入歧义；阶段 7 API 接线前必须改为 exact-one。
- 指定 Microsoft JDK 17.0.16 下执行 `mvn -q test` 成功退出；阶段开始前基线仍是 87 suites / 746 tests，0 failure、0 error、0 skipped。

当前主链断点：Sender 只能返回 raw JSON，Receiver 不能从任何 armor 恢复 outer JSON，testkit 没有最终矩阵，仓库没有可独立运行的 Demo 入口。

## 3. Armor v1 contract

### 3.1 共同原则

- armor 的输入和输出语义是 exact UTF-8 outer JSON bytes，不重新序列化 JSON。
- 三种 armor 格式共用同一个 v1 binary frame；text codec 只编码该 frame。
- 编码器和解码器都限制 outer JSON 为 `ProtocolLimits.MAX_WIRE_UTF8_BYTES`（20 MiB）。
- frame 校验成功后仍必须进入现有 strict outer parser；armor 不能替代 wire validation、AAD、binding、GCM 或验签。
- 非法 armor 在打开私钥或进入密码学主链前失败；公开 Receiver 统一映射为 `INVALID_MESSAGE`。

### 3.2 共同 binary frame

| 偏移 | 长度 | 内容 |
|---:|---:|---|
| 0 | 3 | ASCII magic：`WLA`（`57 4C 41`） |
| 3 | 1 | armor frame version：`01` |
| 4 | 4 | outer JSON UTF-8 byte length，无符号大端序 |
| 8 | N | exact outer JSON UTF-8 bytes |
| 8+N | 4 | CRC-32，大端序；覆盖 magic、version、length 与 payload |

固定开销为 12 bytes。CRC-32 只用于传输损坏检测，不作为攻击者不可伪造的认证；消息安全仍由 outer/inner 密码学与认证链保证。

Binary armor 就是该 frame 的原始 bytes，不再嵌套第二层编码。

### 3.3 Base64URL text armor

- 内容是完整 binary frame 的 RFC 4648 URL-safe Base64 编码。
- 必须无 `=` padding、无空白、无换行，且使用规范编码。
- 解码后重新编码必须与输入逐字符相同。
- 不增加 ASCII 前缀；frame 内的 magic/version 负责格式与版本确认。

### 3.4 WIND_BASE_1024F_V1 text armor

- 字表使用已冻结的 `docs/dev/wind-base-1024f-v1-alphabet.txt` 精确 1024 码点顺序。
- binary frame 按 bitstream 从高位到低位读取，每 10 bit 映射为一个字表索引。
- 最后一组不足 10 bit 时只在低位补 0；不增加额外符号。
- 解码器从 frame length 恢复精确 byte 数，并要求：符号数恰为 `ceil(frameBytes * 8 / 10)`，所有尾部 padding bit 为 0。
- 所有遍历和长度计算必须按 Unicode code point；禁止用 `String.length()`、`char[]` 或 UTF-16 code unit 作为符号数或索引。
- 输入出现不在冻结字表中的码点、孤立 surrogate、非规范尾部或错误 frame 时必须失败。

### 3.5 文本自动检测

`DecryptRequest.armorFormat == null` 且提供 text armor 时：

1. 若全部字符属于无 padding Base64URL ASCII 字母表，按 `BASE64URL` 严格解码。
2. 否则若全部 Unicode 码点都属于冻结的 1024 字表，按 `WIND_BASE_1024F_V1` 严格解码。
3. 混合、空白或未知字符直接失败，不做宽松猜测或 fallback。

两个字母表完全不相交，因此检测结果唯一。显式 format 不允许自动 fallback 到另一格式。

### 3.6 严格失败优先级

同一输入同时存在多个问题时，按以下顺序拒绝：

1. null、空输入、输入表示冲突或编码长度超限。
2. text alphabet、Unicode scalar 或 Base64URL canonical 失败。
3. frame 最小长度或 magic 失败。
4. frame version 不支持。
5. payload length 超限、溢出或与实际 frame 长度不一致。
6. CRC-32 不匹配。
7. payload 不是 strict UTF-8。
8. 进入现有 outer wire strict parser，并沿用其错误优先级。

Armor 内部异常可保留诊断原因；公开 API 不返回具体失败阶段，避免形成解析/密码学 oracle。

## 4. 开发闭环与提交顺序

每个任务独立测试、独立 commit，并在 commit 后立即 push。

### Task 1：阶段审计与 contract（已完成）

- 本计划与总体计划状态同步。
- 完成条件：真实基线、frame、三种格式、auto-detect、错误顺序和阶段门均明确。

### Task 2：Binary frame + Base64URL codec（已完成）

- 在 `windletter-armor` 实现 frame、strict UTF-8、大小限制、CRC-32 与 canonical Base64URL。
- 正例覆盖 exact bytes round-trip、空 JSON、非 ASCII UTF-8 边界和最大值邻接。
- 负例覆盖 magic、version、length、CRC、padding、空白、非法字符、非规范 Base64URL、无效 UTF-8和超限。
- 完成条件：armor 模块相关测试全部通过，现有全仓测试无回归。
- 完成证据：2026-07-22 使用指定 JDK 17，聚焦测试与 `mvn -q test` 均通过；全仓 89 suites / 754 tests，0 failure、0 error、0 skipped。

### Task 3：WIND_BASE_1024F_V1 codec（已完成）

- 将冻结字表作为 jar resource 纳入 `windletter-armor`，启动时校验 1024 码点、唯一性与 SHA-256。
- 实现 10-bit MSB-first packing/unpacking、严格码点解析、尾部零 bit 与 canonical 校验。
- 建立 0..N 尾长、补充平面、未知码点、重复/错序字表防回归测试和确定性向量。
- 完成条件：任何 `String.length()`/`char` 误用都能被测试捕获，三种 armor 对同一 frame 恢复 identical bytes。
- 完成证据：冻结字表 resource 与设计文件逐 byte 相同且 SHA-256 为 `255519fb0d061d88fbd9a8d216ceb6494e09e9fb72e80d7c1815ca4aef794eba`；固定向量、全部尾长与严格负例通过；指定 JDK 17 全仓 91 suites / 761 tests，0 failure、0 error、0 skipped。

### Task 4：API Sender/Receiver armor 编排（已完成）

- `windletter-api` 依赖 `windletter-armor`。
- Sender 先生成真实 raw outer JSON，再按请求格式生成 text/binary armor；`EncryptedMessage.wireJson` 仍保留用于观测和调试。
- `DecryptRequest` 强制 raw/text/binary exact-one；显式格式与表示必须一致。
- Receiver 在任何 key lease 打开前完成 armor 解码、strict UTF-8 与 outer parse。
- 非法 armor 映射为统一 `INVALID_MESSAGE`，本地配置/资源错误仍抛本地异常。
- 完成条件：全部 8 个 profile 经 `NONE`、`BASE64URL`、`WIND_BASE_1024F_V1`、`BINARY` 的公开 API round-trip。
- 完成证据：公开 API 已覆盖 8 profiles × 4 formats × text/binary payload；Base64URL/WindBase 文本自动识别通过，损坏 armor 在 recipient key lease 打开前统一返回 `INVALID_MESSAGE`；`DecryptRequest` 已强制三种输入表示 exact-one。指定 JDK 17 全仓 811 tests，0 failure、0 error、0 skipped。

### Task 5：最终 testkit 与负例矩阵（已完成）

- 建立生产链使用的内存 Demo key repository，不用 mock 核心协议或密码学。
- 覆盖 public/obfuscation × X25519/Hybrid × signed/unsigned × 所有 armor。
- 覆盖多收件人、obfuscation padding、NOT_FOR_ME、INVALID_MESSAGE、armor 篡改、wrong format、截断和超限。
- 增加 deterministic armor vectors 与关键协议回归入口。
- 完成证据：`windletter-testkit` 已提供基于真实 BC 私钥句柄与 API lease 的单场景内存密钥仓库；107 项聚焦测试覆盖 8 profiles × 4 formats × text/binary payload、多收件人、obfuscation 8 槽填充、所有 profile/armor 的 `NOT_FOR_ME`、截断、等长篡改、wrong format、20 MiB 超限，以及三种 armor 固定向量。指定 JDK 17 全仓 93 suites / 918 tests，0 failure、0 error、0 skipped。

### Task 6：可独立运行的 WindLetterDemo（下一步）

- 提供不依赖 JUnit 的 `main` 入口和明确 Maven 运行命令。
- 实际生成密钥、payload、多收件人、可选签名、outer JSON 与 armor，随后由 Receiver 恢复 payload。
- 至少展示总体计划要求的四个代表 profile，并输出 `SIGNED_VALID` / `UNSIGNED`、`NOT_FOR_ME`、`INVALID_MESSAGE`。
- 不输出私钥、shared secret、CEK、KEK 或敏感随机材料。

### Task 7：阶段封板

- 使用指定 JDK 17 运行 `mvn -q clean verify`。
- 汇总全部 Surefire 报告，要求 0 failure、0 error、0 skipped。
- 实际运行 Demo 命令并核对输出。
- 复查 P0/P1、安全错误映射、secret 生命周期和完整矩阵；记录但不阻塞的 P2。
- 更新总体计划与阶段报告，等待用户确认 Demo 后优化阶段。

## 5. 阶段完成判定

- exact outer JSON UTF-8 bytes 经每种 armor round-trip 后逐 byte 相同。
- armor 篡改和非法输入在密码学前拒绝，公开错误不泄露内部阶段。
- 公开 API 覆盖 8 profiles × 4 formats，并保留 signed/unsigned 正确认证结果。
- 多收件人、混淆 padding、NOT_FOR_ME 和 INVALID_MESSAGE 有真实回归测试。
- Demo 可复制运行且不依赖测试 runner。
- fresh `mvn -q clean verify` 与实际 Demo 均成功。

## 6. 当前风险与推迟项

### 阶段内已解决

- 已解决 P1：`DecryptRequest` 强制 raw/text/binary exact-one，并校验显式格式与表示一致。
- 已解决 P1：三种 codec 均在分配和解码前执行编码长度与 frame length 上限。
- 已解决 P1：WindBase 按 Unicode code point 遍历，并用 267 个补充平面字及 surrogate 负例锁定。
- 已解决 P1：Receiver 只将 `ArmorException` 收敛为 `INVALID_MESSAGE`，本地资源/配置异常仍作为本地故障抛出。

### Demo 后可继续优化的 P2

- streaming armor API、零拷贝和超大消息性能。
- 字体覆盖、聊天平台显示效果及更多真实平台 smoke。
- test matrix 辅助代码去重与参数化美化。
- 跨语言实现和正式互操作发布包。
- 将文件名中的 `draft` 重命名为最终规范名。
