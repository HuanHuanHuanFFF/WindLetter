# WIND_BASE_1024F_V1 字母表规范

> 2026-07-23 修订：字表顺序仍有效；framing、bit packing、版本引导和文本头尾现已冻结，最终规则见 `docs/WindLetter Armor规则.md`。

> 状态：v1 字母表已确认并冻结；本文件只负责字表顺序，最终 framing、bit packing 与版本引导见 `docs/WindLetter Armor规则.md`。
> 日期：2026-07-22

## 1. 目标与术语

`WIND_BASE_1024F_V1` 使用恰好 1024 个互不重复的单 Unicode 码点汉字，每个符号可承载 10 bit。这里的“幽灵汉字”是项目视觉命名，不是 Unicode 的正式字符类别；协议实现只按码点精确匹配。

v1 同时使用 BMP 与补充平面汉字。Java `String` 使用 UTF-16，因此不得以 `String.length()` 作为符号数；实现必须使用 `codePoints()`、`codePointCount(...)` 或等价的码点遍历。

## 2. 字母表与索引规则

完整且唯一权威的 1024 字顺序见 [`wind-base-1024f-v1-alphabet.txt`](./wind-base-1024f-v1-alphabet.txt)。该文件是单行、无 BOM、无行尾换行的严格 UTF-8 文本。

- 映射规则：`symbol = alphabet[value]`，其中 `value` 为 `0..1023`。
- 索引从 0 开始。
- 所有质数索引（`2..1021`，共 172 个）上的字符都包含 `風` 部件。
- 其中 162 个在 IDS 中直接包含 `風`；索引 `7, 79, 263, 353, 547, 607, 673, 839, 937, 997` 的 10 个字符通过中间部件递归包含 `風`。
- “质数索引含風”是构造不变量，不表示非质数索引不得出现含風字符。

含風检查使用 BabelStone IDS 16.0 数据递归核验。IDS 受地区字形与数据版本影响，因此该检查是字表构造证据，不是解码器的运行时依赖；解码器只依赖本仓库冻结的精确码点序列。

## 3. 机器校验结果

- Unicode 标量数：1024
- 唯一码点数：1024
- UTF-16 code unit 数：1291
- 补充平面码点数：267
- 严格 UTF-8 长度：3339 bytes
- UTF-8 BOM：无
- 换行与其他空白：无
- Unicode 17 已分配字符：1024 / 1024
- Unicode General Category：全部为 `Lo` / Other Letter
- CJK Compatibility Ideographs：0
- Unicode decomposition mapping：0
- NFC / NFKC：不改变字母表
- 0 下标质数索引：172
- 递归含 `風`：172 / 172
- UTF-8 SHA-256：`255519fb0d061d88fbd9a8d216ceb6494e09e9fb72e80d7c1815ca4aef794eba`
- `alphabet[0] = 𩘫`（`U+2962B`）
- `alphabet[1023] = 㓧`（`U+34E7`）

合法性以 Unicode 17 `UnicodeData.txt` 核验；结构检查参考 [BabelStone IDS Database](https://www.babelstone.co.uk/CJK/IDS.HTML)。

任何字符、顺序或文件编码变化都会改变映射和哈希，必须作为新的字表版本处理，不能静默替换。

## 4. 尚未冻结的协议项

本规范尚未决定 bit packing、尾部不足 10 bit 的处理、原始长度恢复、版本/framing、校验和、文本前缀、大小限制和 strict decoder 错误优先级。这些必须在阶段 7 armor contract 中单独批准并测试。

## 5. 已知 P2

- 补充平面字符在 Java 中占用 surrogate pair；若实现误用 `char` 或 `String.length()` 会破坏索引，阶段 7 必须用自动化测试锁定码点处理。
- 生僻字和补充平面字符的字体、输入框、聊天平台覆盖不稳定，可能显示为方框或在不合规平台被替换；阶段 7 需做 UTF-8 round-trip 与目标平台 smoke。
- IDS 的“含風”结构判定不是 Unicode 规范属性且可能随数据版本或地区字形变化；它只用于设计验证，不影响已冻结映射及解码正确性。
