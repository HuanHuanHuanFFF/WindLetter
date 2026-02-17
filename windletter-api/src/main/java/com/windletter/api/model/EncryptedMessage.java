package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import java.util.Arrays;

/**
 * Stable outward-facing encrypted message container.
 *
 * @param wireJson standard wire JSON (required)
 * @param armor optional text armor representation
 * @param armorBytes optional binary armor representation (used only for BINARY)
 * @param armorFormat armor format, defaults to NONE when null
 */
public record EncryptedMessage(String wireJson, String armor, byte[] armorBytes, ArmorFormat armorFormat) {

    /**
     * Canonical constructor with wire/armor consistency checks.
     *
     * @throws IllegalArgumentException if wire/armor fields conflict with {@code armorFormat}
     */
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
     * Returns a copy of binary armor to prevent external mutation of internal state.
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
