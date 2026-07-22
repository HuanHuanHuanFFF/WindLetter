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
        if (armorBytes != null && armorBytes.length == 0) {
            throw new IllegalArgumentException("armorBytes must not be empty");
        }

        int representationCount = (hasWireJson ? 1 : 0)
            + (hasTextArmor ? 1 : 0)
            + (hasBinaryArmor ? 1 : 0);
        if (representationCount != 1) {
            throw new IllegalArgumentException(
                "exactly one of wireJson, armor or armorBytes must be provided"
            );
        }

        if (armorFormat == null) {
            if (hasBinaryArmor) {
                armorFormat = ArmorFormat.BINARY;
            } else if (hasTextArmor) {
                // The receiver strictly auto-detects the concrete text format.
                armorFormat = null;
            } else {
                armorFormat = ArmorFormat.NONE;
            }
        } else {
            switch (armorFormat) {
                case NONE -> {
                    if (!hasWireJson) {
                        throw new IllegalArgumentException(
                            "wireJson is required when armorFormat is NONE"
                        );
                    }
                }
                case BINARY -> {
                    if (!hasBinaryArmor) {
                        throw new IllegalArgumentException(
                            "armorBytes is required when armorFormat is BINARY"
                        );
                    }
                }
                case BASE64_PEM, WIND_BASE_1024F_V1 -> {
                    if (!hasTextArmor) {
                        throw new IllegalArgumentException(
                            "text armor is required for a text-based armorFormat"
                        );
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
