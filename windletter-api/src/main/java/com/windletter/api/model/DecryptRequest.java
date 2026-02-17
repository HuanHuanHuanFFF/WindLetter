package com.windletter.api.model;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.VerificationPolicy;
import java.util.Arrays;

/**
 * Receiver-side decrypt request.
 *
 * @param wireJson raw wire JSON
 * @param armor text armor
 * @param armorBytes binary armor
 * @param armorFormat armor format; null means auto-detect
 * @param myIdentity local receiver identity
 * @param verificationPolicy verification policy, defaults to AUTO_BY_CTY when null
 */
public record DecryptRequest(
    String wireJson,
    String armor,
    byte[] armorBytes,
    ArmorFormat armorFormat,
    RecipientIdentityRef myIdentity,
    VerificationPolicy verificationPolicy
) {

    /**
     * Canonical constructor with input-shape validation and armor-format compatibility checks.
     *
     * @throws IllegalArgumentException if no input representation is provided or armor settings conflict
     */
    public DecryptRequest {
        armorBytes = copyNullable(armorBytes);

        boolean hasWireJson = !ModelChecks.isBlank(wireJson);
        boolean hasTextArmor = !ModelChecks.isBlank(armor);
        boolean hasBinaryArmor = armorBytes != null && armorBytes.length > 0;

        // Ensure the caller provides at least one input representation.
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
                // When text armor is provided without format, let downstream parser auto-detect the concrete armor format.
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
