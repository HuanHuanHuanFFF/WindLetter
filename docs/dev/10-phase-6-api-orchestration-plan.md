# Phase 6：windletter-api 真实编排实施计划

> 状态：执行中
> 分支：`spike/demo-v0`
> 起始 HEAD：`f1be4e16c34e60216fe5970e5a705c4059bd5a4f`
> 基线：Microsoft OpenJDK 17.0.16；fresh `mvn -q clean test` 为 80 suites / 694 tests，0 failure、0 error、0 skipped
> 工作区边界：既存 `docs/README.md` 行尾状态噪音不处理、不暂存、不提交

## 1. 阶段目标

让调用者只通过公开的 `WindLetterSender`、`WindLetterReceiver`、DTO 和 SPI，就能使用真实 Bouncy Castle 原语与真实 JSON wire 完成 Wind Letter v1.0 的全部 8 个 profile：

| mode | key algorithm | unsigned | signed |
|---|---|---:|---:|
| public | X25519 | 必须 | 必须 |
| public | X25519ML-KEM-768 | 必须 | 必须 |
| obfuscation | X25519 | 必须 | 必须 |
| obfuscation | X25519ML-KEM-768 | 必须 | 必须 |

本阶段只支持 `ArmorFormat.NONE` 与单一 raw `wireJson`。Armor、testkit 基础设施和可运行 Demo 入口属于阶段 7，不在本阶段发明格式或提前接线。

## 2. 真实基线与主链断点

当前 `windletter-api` 只有 DTO、SPI 和 owned lease 契约：

- `windletter-api/pom.xml` 只有 core、crypto 依赖，没有 protocol 依赖。
- 没有 `impl`、runtime composition root 或 mapper。
- 现有 11 suites / 38 tests 只覆盖 DTO、public material 与 lease 契约。
- 协议层已经有 8 个 Sender 与 8 个 Receiver concrete flow，均经过真实 crypto + JSON wire E2E。

因此主链断在：

```text
API request
  -> resolver/store + owned lease
  -> profile-safe mapping
  -> concrete protocol flow
  -> raw wire / safe DecryptResult
```

## 3. 本阶段冻结的合同

### 3.1 Sender 输入与身份

- public 必须提供 sender X25519 encryption identity；obfuscation 使用每消息临时 EPK，必须不提供也不打开静态 sender encryption lease。
- signed 必须提供独立 Ed25519 signing identity。public 的 encryption identity 与 signing identity 是不同密钥角色，不要求相同 kid。
- `customHeaders` 当前无法映射到正式 v1.0 inner（只允许 `content_type`、`original_size`），非空值必须作为本地参数错误拒绝；禁止静默丢弃或私自扩展 wire。
- 本阶段输出只允许 `ArmorFormat.NONE`，返回 `EncryptedMessage(wireJson, null, null, NONE)`。
- message id 使用 UUID v4，timestamp 使用 Unix epoch seconds。

### 3.2 Profile 与 key binding

- 先按调用参数或 strict outer header 选择唯一 profile，不顺序试跑多个 flow。
- X25519 profile 必须有完整 X25519 material；Hybrid 必须有不可拆分的 X25519 + ML-KEM-768 pair。
- recipient ref、resolver material、sender lease、receiver lease、signing lease、verification material 的声明 kid，均必须与真实 public key 派生 kid 一致。
- request 中存在 kid hint 时必须与 resolver/lease record 和真实派生值一致。
- 重复完整 recipient/candidate 必须拒绝；Hybrid 不得跨 lease 拼接 component。
- SPI/provider 返回 null、null element、已关闭、长度错误或 metadata/key 不一致属于本地 operational failure，不能伪装成 `NOT_FOR_ME`。

### 3.3 VerificationPolicy

| 输入 | AUTO_BY_CTY | ALLOW_UNSIGNED | REQUIRE_SIGNED_VALID |
|---|---|---|---|
| signed valid | SUCCESS / SIGNED_VALID | SUCCESS / SIGNED_VALID | SUCCESS / SIGNED_VALID |
| signed invalid 或未知 signer | INVALID_MESSAGE | INVALID_MESSAGE | INVALID_MESSAGE |
| unsigned valid | SUCCESS / UNSIGNED | SUCCESS / UNSIGNED | INVALID_MESSAGE |

- `ALLOW_UNSIGNED` 只允许真实 `wind+inner`，绝不把失败的 `wind+jws` 降级成 unsigned。
- `decryptAndVerify` 无条件采用 `REQUIRE_SIGNED_VALID`。
- `senderIdentity` 只有完成 binding 与 Ed25519 验签并得到 `SIGNED_VALID` 后才可返回。

### 3.4 公开错误语义

远程可控 wire 只公开两种失败：

- exact protocol `NOT_FOR_ME` -> `DecryptStatus.NOT_FOR_ME` + `ErrorCode.NOT_FOR_ME`；
- 其他 `ProtocolException` -> `DecryptStatus.INVALID_MESSAGE` + generic `ErrorCode.INVALID_MESSAGE`。

公开结果不得泄露 malformed、AAD、unwrap、GCM、inner、binding 或 signature 的内部阶段、异常消息或 cause。`INTERNAL_ERROR`、SPI/provider 违约、kid/material 不一致与 lease close failure 作为本地异常抛出，不映射成 wire 结果。

结果不变量：

| status | verification | payload | identity | id / ts | error |
|---|---|---|---|---|---|
| SUCCESS | UNSIGNED | 有 | null | 有 | null |
| SUCCESS | SIGNED_VALID | 有 | 有 | 有 | null |
| NOT_FOR_ME | NOT_APPLICABLE | null | null | null | NOT_FOR_ME |
| INVALID_MESSAGE | FAILED | null | null | null | INVALID_MESSAGE |

### 3.5 Lease 所有权

- API 对成功返回的全部 sender encryption、signing 与 recipient decryption leases 负责关闭；protocol 只借用 handle。
- success、`NOT_FOR_ME`、invalid、SPI/mapper/runtime exception 全路径都必须关闭。
- 关闭一个 lease 失败后仍继续关闭其余 lease；首个关闭失败保留，后续失败作为 suppressed。
- close failure 必须阻止 success 结果返回。
- Receiver 一次打开全部候选，把全部兼容候选一次交给唯一 flow；禁止逐 lease 重试或在命中后认证失败时 fallback。

## 4. 分批闭环与提交边界

每个实现任务遵循 RED -> GREEN -> focused/relevant reactor -> 独立复核 -> 单独提交。Tracking SPI 可验证调用和关闭，但 E2E 必须使用真实 BC X25519、ML-KEM、HKDF、A256KW、A256GCM 与 Ed25519。

### Task 1：计划与 API 合同

- 新增本计划并修正总体计划的阶段状态。
- 用失败测试锁定 mode-specific sender identity、拒绝 custom headers、32-byte Ed25519 public key、`DecryptResult` 完整不变量与 generic `INVALID_MESSAGE`。
- 完成后形成一个独立合同闭环提交。

### Task 2：Public X25519 API 闭环

- 增加 protocol compile dependency 与最小 production composition。
- 实现 public X25519 signed/unsigned Sender 与 Receiver 映射。
- 验证多收件人、真实 wire、payload、签名身份、key binding 和 sender/recipient/signing lease 生命周期。

### Task 3：Public Hybrid API 闭环

- 实现 public Hybrid signed/unsigned。
- 验证真实 ML-KEM encapsulation/decapsulation、完整 pair、multi-recipient 与所有 handle 关闭。

### Task 4：Obfuscation X25519 API 闭环

- 实现 obfuscation X25519 signed/unsigned。
- 验证真实 EPK、padding/shuffle/rid 路由，并证明不访问 sender static encryption key store。

### Task 5：Obfuscation Hybrid API 闭环

- 实现 obfuscation Hybrid signed/unsigned。
- 验证真实逐 entry ML-KEM、原子 pair、完整扫描、padding 与安全失败语义。

### Task 6：策略、错误、生命周期与八组合封板

- 完成 strict pre-dispatch、三种 verification policy 与 `decryptAndVerify`。
- 覆盖 `NOT_FOR_ME`、malformed/AAD/GCM/binding/signature tamper 的统一外观与 identity 不释放。
- 覆盖 success、NFM、invalid、resolver exception、close exception 的全部 lease 关闭。
- 建立 8 profiles × text/binary = 16 条只经公开 API/SPI 的真实 crypto E2E。
- 增加简单 `WindLetterRuntime` composition root，不引入 DI/ServiceLoader 框架。
- 更新本计划与总体计划的完成证据后执行全仓门禁。

## 5. 阶段完成判定

- 公开 API 能以 raw JSON 跑通 8 个 profile，且 16 条 text/binary 矩阵全部使用真实 crypto。
- public multi-recipient 与 obfuscation padding/routing 均通过 API seam。
- signed 必验签，unsigned 不伪造 identity，`REQUIRE_SIGNED_VALID` 与 `decryptAndVerify` 拒绝 unsigned。
- 所有 wire-controlled failure 只有 `NOT_FOR_ME` 或 generic `INVALID_MESSAGE` 两种公开外观。
- 所有声明 kid 与真实 key 绑定；Hybrid pair 不被拆分或交叉拼接。
- 所有 owned leases 在成功和失败路径关闭；close failure 不吞掉且不会返回 payload。
- focused tests、`mvn -q -pl windletter-api -am test`、fresh `mvn -q clean test` 全绿。
- `git diff --check` 通过；无新增 `@Disabled/@Ignore`；独立 protocol/security/test review 为 P0=0、P1=0。

## 6. 明确后置到阶段 7 或 Demo 后的 P2

- Armor 输入 exact-one contract、所有 armor 编排与 auto-detect（阶段 7）。
- 把 verification key 与 sender identity 两次查询合并为原子 trusted identity record，以消除 TOCTOU。
- 将 canonical kid 校验统一下沉到所有 material/lease 构造器；阶段 6 mapper 先完整执行真实派生校验。
- 通用 flow registry、DI 容器、ServiceLoader、算法插件框架。
- replay store、候选数量 policy cap、缓存、性能与 timing 基准。
- 清理 dormant `UNSUPPORTED`、`SigningOption` 等冗余类型。
- 去除 16 条 concrete flow 的少量 dispatch/mapper 重复。

以上 P2 若未演变成协议、安全或正确性 P0/P1，不阻塞 Demo 主链。
