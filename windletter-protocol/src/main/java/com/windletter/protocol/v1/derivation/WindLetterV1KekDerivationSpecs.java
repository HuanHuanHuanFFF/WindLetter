package com.windletter.protocol.v1.derivation;

import com.windletter.protocol.derivation.KekDerivationSpec;
import java.nio.charset.StandardCharsets;

/**
 * WindLetter v1.0 protocol derivation specs.
 */
public final class WindLetterV1KekDerivationSpecs {

    private static final byte[] WIND_SALT = ascii("wind");
    private static final int SHARED_SECRET_LEN = 32;

    public static final KekDerivationSpec KEK_ECC = new KekDerivationSpec(
            "v1/kek/ecc",
            WIND_SALT,
            ascii("WindLetter v1 KEK | X25519"),
            SHARED_SECRET_LEN,
            32);

    public static final KekDerivationSpec KEK_HYBRID = new KekDerivationSpec(
            "v1/kek/hybrid",
            WIND_SALT,
            ascii("WindLetter v1 KEK | X25519ML-KEM-768"),
            SHARED_SECRET_LEN * 2,
            32);

    public static final KekDerivationSpec RID_ECC = new KekDerivationSpec(
            "v1/rid/ecc",
            WIND_SALT,
            ascii("rid/ecc"),
            SHARED_SECRET_LEN,
            16);

    public static final KekDerivationSpec RID_HYBRID = new KekDerivationSpec(
            "v1/rid/hybrid",
            WIND_SALT,
            ascii("rid/hybrid"),
            SHARED_SECRET_LEN * 2,
            16);

    private WindLetterV1KekDerivationSpecs() {
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
