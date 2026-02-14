package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import java.util.Arrays;

/**
 * 对外稳定密文载体。
 *
 * @param wireJson 标准 wire JSON（必填）
 * @param armor 可选文本封装表示
 * @param armorBytes 可选二进制封装表示（仅 BINARY 使用）
 * @param armorFormat armor 的格式，null 时默认 NONE
 */
public record EncryptedMessage(String wireJson, String armor, byte[] armorBytes, ArmorFormat armorFormat) {

    public EncryptedMessage {
        wireJson = ModelChecks.requireNonBlank(wireJson, "wireJson");
        armorFormat = armorFormat == null ? ArmorFormat.NONE : armorFormat;
        armorBytes = copyNullable(armorBytes);

        boolean hasTextArmor = !ModelChecks.isBlank(armor);
        boolean hasBinaryArmor = armorBytes != null && armorBytes.length > 0;

        if (hasTextArmor && hasBinaryArmor) {
            throw new IllegalArgumentException("armor and armorBytes must not be provided together");
        }
        if (armorBytes != null && armorBytes.length == 0) {
            throw new IllegalArgumentException("armorBytes must not be empty");
        }

        switch (armorFormat) {
            case NONE -> {
                if (hasTextArmor || hasBinaryArmor) {
                    throw new IllegalArgumentException("armor data must be absent when armorFormat is NONE");
                }
            }
            case BINARY -> {
                if (hasTextArmor || !hasBinaryArmor) {
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
