# WIND_BASE_1024F_V1 稀有汉字字母表草案

> 状态：待用户确认；本文件只冻结候选字母表，不代表 framing 与 bit packing 已获批准。
> 日期：2026-07-22

## 1. 目标与术语

本草案为 `WIND_BASE_1024F_V1` 提供恰好 1024 个单码点汉字，因此每个符号可承载 10 bit。这里的“幽灵汉字”是项目视觉命名，不是 Unicode 的正式字符类别；正式描述统一使用“稀有汉字字母表”。

Unicode 17 将 CJK Unified Ideographs Extension A（`U+3400..U+4DBF`）描述为 rare ideographs。本草案只使用 BMP 的 CJK Unified Ideographs，不使用 CJK Compatibility Ideographs、变体选择符、组合序列或补充平面字符。

参考：

- [Unicode 17 Chapter 18](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-18/)
- [Unicode Extension A names list](https://www.unicode.org/charts/nameslist/c_3400.html)
- [Unicode Normalization Forms](https://www.unicode.org/reports/tr15/)

## 2. 字母表构造

按零基索引定义：

1. `0..53`：保留 `docs/風笺设计.md` 已确定的 54 字历史前缀，顺序不变。
2. `54..1023`：依 Unicode 码点升序加入 `U+3400..U+37C9`，共 970 字。

因此：

- `alphabet[0] = 風`（`U+98A8`）
- `alphabet[53] = 霾`（`U+973E`）
- `alphabet[54] = 㐀`（`U+3400`）
- `alphabet[1023] = 㟉`（`U+37C9`）

历史前缀中有少量较常见的气象字，这是兼容旧设计的有意保留；新增 970 字全部来自 Extension A 的稀有字区。

## 3. 权威字表文件

完整 1024 字见 [`wind-base-1024f-v1-alphabet.txt`](./wind-base-1024f-v1-alphabet.txt)。文件按 32 行 × 32 字排版；规范字母表是删除 `CR`/`LF` 后按行连接得到的 1024 个 Unicode 标量，任何其他空白都不是字母表内容。

映射规则为 `symbol = alphabet[value]`，其中 `value` 范围为 `0..1023`。解码器必须按 Unicode 码点精确匹配，不得按字形、读音、简繁关系或兼容等价关系匹配。

## 4. 机器校验结果

- Unicode 标量数：1024
- 唯一码点数：1024
- UTF-16 code unit 数：1024（全部位于 BMP，无 surrogate pair）
- 每个码点 General Category：`Lo` / Other Letter
- NFC：不得改变字母表
- NFKC：不得改变字母表
- UTF-8 长度：3072 bytes
- 去除换行后的 UTF-8 SHA-256：`8cb9615f910e94783164c8dd08651cad16e260266c03b49fc44da14f326bbf2a`

## 5. 尚未冻结的协议项

本草案没有决定 bit packing、尾部不足 10 bit 的处理、长度恢复、版本/framing、校验和、文本前缀、大小限制和 strict decoder 错误优先级。这些必须在阶段 7 armor contract 中单独批准并测试。

## 6. 已知 P2

Extension A 的字体覆盖不如常用汉字，一些聊天平台可能显示为方框；这通常不改变底层码点和复制粘贴结果，但影响可读性与视觉效果。阶段 7 应在目标平台做真实 round-trip 与字体展示 smoke，并在正式冻结前决定是否改用覆盖率更高的稀有 BMP 字集合。
