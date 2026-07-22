# WindLetter v1.0 Demo 运行说明

## 运行命令

在仓库根目录使用 JDK 17：

```powershell
$env:JAVA_HOME='C:\Users\幻\.jdks\ms-17.0.16'
$env:Path="$env:JAVA_HOME\bin;$env:Path"
mvn -q -pl windletter-testkit -am -Pdemo verify
```

该命令先验证依赖模块与全部测试，再运行不依赖 JUnit 的
`com.windletter.testkit.demo.WindLetterDemo` 主入口。

## Demo 实际覆盖

- public / X25519 / unsigned / 标准 Base64 PEM
- public / X25519ML-KEM-768 / signed / 風笺 WindBase1024F v1
- obfuscation / X25519 / signed / binary
- obfuscation / X25519ML-KEM-768 / unsigned / 風笺 WindBase1024F v1
- 多收件人，以及 obfuscation 的 8 槽填充
- `SIGNED_VALID`、`UNSIGNED`、`NOT_FOR_ME`、`INVALID_MESSAGE`
- 损坏 風笺 Armor 在打开 recipient key lease 前失败

Demo 只输出 profile、状态、收件人槽位与编码长度，不输出私钥、shared secret、CEK、KEK 或随机密钥材料。風笺的 `armorCodePoints` 是 Unicode 码点数；`armorUtf16Units` 仅用于展示为什么不能以 `String.length()` 作为符号数。

## 2026-07-23 实际运行结果

```text
WindLetter v1.0 Demo
SUCCESS profile=public/X25519/unsigned armor=BASE64_PEM recipients=2 wireUtf8Bytes=1503 armorCodePoints=2105 armorUtf16Units=2105 status=SUCCESS auth=UNSIGNED payloadBytes=42
SUCCESS profile=public/X25519_ML_KEM_768/signed armor=WIND_BASE_1024F_V1 recipients=2 wireUtf8Bytes=9005 armorCodePoints=7359 armorUtf16Units=9336 status=SUCCESS auth=SIGNED_VALID payloadBytes=42
SUCCESS profile=obfuscation/X25519/signed armor=BINARY recipients=8 wireUtf8Bytes=3288 armorBytes=3300 status=SUCCESS auth=SIGNED_VALID payloadBytes=42
SUCCESS profile=obfuscation/X25519_ML_KEM_768/unsigned armor=WIND_BASE_1024F_V1 recipients=8 wireUtf8Bytes=30122 armorCodePoints=24516 armorUtf16Units=31105 status=SUCCESS auth=UNSIGNED payloadBytes=42
NOT_FOR_ME status=NOT_FOR_ME error=NOT_FOR_ME
INVALID_MESSAGE status=INVALID_MESSAGE error=INVALID_MESSAGE keyLeases=0
DEMO_OK successes=4
```

同次 Maven verify 汇总为 95 suites / 928 tests，0 failure、0 error、0 skipped。
