# WindLetter v1.0 重写架构设计（工业化基线）

## 1. 文档目标

本文件定义 WindLetter v1.0 的实现架构基线，目标是：

- 对齐 `doc/Wind Letter v1.0协议.md` 的字段、流程、校验与错误语义。
- 提供可扩展、可维护、可测试的模块边界。
- 作为后续实现与代码评审的架构约束，不允许跨层“偷跑”实现。

本文件是 v1.0 的强约束文档，术语 `MUST/SHOULD/MAY` 采用 RFC 风格。

## 2. 总体原则

- `MUST` 分层实现：`core -> crypto -> protocol -> armor -> api`，`testkit` 横向验证。
- `MUST` 保持 API 层编排职责，不直接实现密码细节。
- `MUST` 以协议字段与行为兼容为第一优先级，不以“实现方便”改协议。
- `MUST` 统一错误口径，对外最小化泄露（`NotForMe / InvalidMessage / Unsupported`）。
- `SHOULD` 面向 profile 扩展算法，不在业务流程中硬编码具体算法分支。

## 3. 模块职责与边界

### 3.1 `windletter-core`

职责：

- 协议常量（字段名、枚举、固定参数 `salt/info/L`、长度约束）。
- 基础错误模型、错误码、异常到错误码映射。
- 基础编码工具（Base64URL、字节比较、时间戳/UUID 校验）。
- 不依赖具体算法实现，不依赖 JSON 引擎的高级对象模型。

边界：

- `MUST NOT` 依赖 `crypto/protocol/api`。

### 3.2 `windletter-crypto`

职责：

- 提供密码原语适配接口与实现：X25519、ML-KEM-768、HKDF-SHA256、A256KW、A256GCM、Ed25519、SHA-256。
- 提供算法 profile 注册（`X25519`、`X25519Kyber768`）与组合逻辑。
- 提供常量时间比较能力（签名、哈希、rid）。

边界：

- `MUST` 仅处理字节级输入输出，不感知业务 DTO。
- `MUST NOT` 直接解析/拼装外层协议 JSON。

### 3.3 `windletter-protocol`

职责：

- 传输对象（wire DTO）定义与字段约束。
- JCS 规范化、AAD 构建、内外层绑定哈希计算。
- 加密/解密协议编排（public/obfuscation + signed/unsigned）。
- 协议语义校验与错误归类（含白名单、必填/省略规则）。

边界：

- `MUST` 调用 `crypto` 接口，不可内嵌算法实现。
- `MUST NOT` 直接向应用暴露可变内部对象。

### 3.4 `windletter-armor`

职责：

- Wire JSON 与文本装甲（例如文本块包裹）编解码。
- 输入输出格式化、严格解析、容错边界控制。

边界：

- `MUST NOT` 承担签名/解密业务判断。

### 3.5 `windletter-api`

职责：

- 对外高层 API：`WindLetterSender`、`WindLetterReceiver`。
- 请求参数与结果对象（稳定 API 契约）。
- 依赖注入（密钥仓库、身份解析器、策略）。

边界：

- `MUST NOT` 暴露内部 `protocol` 可变实体。
- `MUST NOT` 允许调用方绕过协议校验步骤。

### 3.6 `windletter-testkit`

职责：

- 协议向量测试、互操作测试、负例安全测试。
- 规范条款到测试项映射。
- CI 验收门槛与回归保护。

## 4. 依赖关系（强约束）

- `windletter-core`：无内部依赖。
- `windletter-crypto`：依赖 `core`。
- `windletter-protocol`：依赖 `core + crypto`。
- `windletter-armor`：依赖 `core + protocol`（只依赖模型/编解码接口）。
- `windletter-api`：依赖 `core + protocol + armor`。
- `windletter-testkit`：依赖所有模块（仅测试范围）。

禁止反向依赖与跨层直连。

## 5. 运行时流程（v1.0）

### 5.1 发送流程

1. API 层接收请求，完成基础参数校验（mode/keyAlg/signingOption）。
2. Protocol 层构建 inner（signed: `wind+jws`；unsigned: `wind+inner`）。
3. Protocol 调用 Crypto 按 profile 计算 `SS_ECC/(SS_PQ)`，派生 `KEK` 与可选 `rid`。
4. Protocol 生成 `recipients`（混淆模式含分桶诱饵）。
5. Protocol 计算 `aad=Base64URL(JCS(recipients))`，构造 GCM AAD。
6. Protocol 输出 `OuterWireMessage`；Armor 负责序列化。

### 5.2 接收流程

1. Armor 解析输入，Protocol 做结构与白名单预检。
2. Protocol 依据 mode 定位条目（public: `kid`；obfuscation: `rid` 常量时比较）。
3. Protocol 调用 Crypto 解包 CEK，执行 GCM 解密。
4. Protocol 执行绑定校验（`jwe_protected_hash/jwe_recipients_hash`）。
5. Signed 模式执行验签；Unsigned 模式跳过验签。
6. API 返回 `DecryptResult`，状态区分 `success/notForMe/invalid/unsupported`。

## 6. 可扩展设计点

- 算法扩展：通过 `KeyAlgorithmProfile` 与 `SignatureProfile` 扩展，不改主流程接口。
- 模式扩展：通过 `WindModeHandler` 策略扩展（现有 `public/obfuscation`）。
- 编码扩展：Armor 支持 JSON 以外封装时，不影响 protocol 核心语义。
- 错误扩展：内部错误码可新增，但外部错误类别保持稳定。

## 7. 安全实现约束

- `MUST` 使用 CSPRNG 生成 `CEK/IV/Decoy`。
- `MUST` 对 `rid/hash/signature` 做常量时间比较。
- `MUST` 对外统一错误粒度，避免泄露命中条目或失败环节。
- `MUST` 严格执行字段必填/省略规则（尤其 signed/unsigned、ECC-only/Hybrid 差异）。
- `MUST` 固定 v1.0 白名单：
  - `enc=A256GCM`
  - `key_alg in {X25519, X25519Kyber768}`
  - `alg=EdDSA`（仅签名模式）

## 8. 版本与兼容策略

- `ver="1.0"` 是 wire 版本锚点，v1.0 实现对该版本 `MUST` 严格兼容。
- 新增算法/字段时，`MUST` 通过 profile + version gate 引入，不能隐式改变 v1.0 行为。
- 对外 API 采用“向后兼容新增、避免破坏性修改”的策略。

## 9. 实施顺序（落地建议）

1. 先完成 `core` 常量/错误与 `crypto` 接口。
2. 再实现 `protocol` 的 wire+validator+jcs/aad/binding。
3. 最后接 `armor` 与 `api`，并由 `testkit` 统一验收。

---

协议依据：`doc/Wind Letter v1.0协议.md`（重点：§1~§9 与附录示例）。
