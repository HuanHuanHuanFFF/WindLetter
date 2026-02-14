package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.VerificationPolicy;
import java.util.Arrays;

/**
 * 接收侧解密请求。
 *
 * @param wireJson 原始 wire JSON
 * @param armor 文本封装
 * @param armorBytes 二进制封装
 * @param armorFormat armor 格式。为 null 表示自动识别
 * @param myIdentity 本地接收身份
 * @param verificationPolicy 验签策略，null 时默认 AUTO_BY_CTY
 */
public record DecryptRequest(
    String wireJson,
    String armor,
    byte[] armorBytes,
    ArmorFormat armorFormat,
    RecipientIdentityRef myIdentity,
    VerificationPolicy verificationPolicy
) {

    public DecryptRequest {
        armorBytes = copyNullable(armorBytes);

        boolean hasWireJson = !ModelChecks.isBlank(wireJson);
        boolean hasTextArmor = !ModelChecks.isBlank(armor);
        boolean hasBinaryArmor = armorBytes != null && armorBytes.length > 0;

        // 保证调用方至少提供一种输入表示。
        if (!hasWireJson && !hasTextArmor && !hasBinaryArmor) {
            throw new IllegalArgumentException("wireJson, armor or armorBytes must be provided");
        }
        if (hasTextArmor && hasBinaryArmor) {
            throw new IllegalArgumentException("armor and armorBytes must not be provided together");
        }
        if (armorBytes != null && armorBytes.length == 0) {
            throw new IllegalArgumentException("armorBytes must not be empty");
        }

        if (armorFormat == null) {
            if (hasBinaryArmor) {
                armorFormat = ArmorFormat.BINARY;
            } else if (hasTextArmor) {
                // 文本封装但未指定格式时，交由后续解析器自动识别具体文本格式。
                armorFormat = null;
            } else {
                armorFormat = ArmorFormat.NONE;
            }
        } else {
            switch (armorFormat) {
                case NONE -> {
                    if (hasTextArmor || hasBinaryArmor) {
                        throw new IllegalArgumentException("armor data must be absent when armorFormat is NONE");
                    }
                }
                case BINARY -> {
                    if (!hasBinaryArmor || hasTextArmor) {
                        throw new IllegalArgumentException("armorBytes is required and armor must be blank when armorFormat is BINARY");
                    }
                }
                case BASE64URL, WIND_BASE_1024F_V1 -> {
                    if (!hasTextArmor || hasBinaryArmor) {
                        throw new IllegalArgumentException("text armor is required and armorBytes must be absent for text-based armorFormat");
                    }
                }
            }
        }
        myIdentity = ModelChecks.requireNonNull(myIdentity, "myIdentity");
        verificationPolicy = verificationPolicy == null
            ? VerificationPolicy.AUTO_BY_CTY
            : verificationPolicy;
    }

    /**
     * 返回二进制封装副本，避免外部修改内部状态。
     */
    @Override
    public byte[] armorBytes() {
        return copyNullable(armorBytes);
    }

    private static byte[] copyNullable(byte[] value) {
        if (value == null) {
            return null;
        }
        return Arrays.copyOf(value, value.length);
    }
}
