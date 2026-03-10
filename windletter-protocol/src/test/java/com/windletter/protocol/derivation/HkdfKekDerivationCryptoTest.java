package com.windletter.protocol.derivation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.CryptoOperationException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HkdfKekDerivationCryptoTest {

    private static final KekDerivationSpec ECC_SPEC = new KekDerivationSpec(
            "test/kek/ecc",
            "wind".getBytes(StandardCharsets.US_ASCII),
            "WindLetter v1 KEK | X25519".getBytes(StandardCharsets.US_ASCII),
            32,
            32);

    private static final KekDerivationSpec HYBRID_SPEC = new KekDerivationSpec(
            "test/kek/hybrid",
            "wind".getBytes(StandardCharsets.US_ASCII),
            "WindLetter v1 KEK | X25519ML-KEM-768".getBytes(StandardCharsets.US_ASCII),
            64,
            32);

    private final HkdfKekDerivationCrypto crypto = new HkdfKekDerivationCrypto();

    @Test
    void shouldRejectInvalidInputLength() {
        assertThrows(IllegalArgumentException.class, () -> crypto.derive(ECC_SPEC, new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> crypto.derive(HYBRID_SPEC, new byte[63]));
    }

    @Test
    void shouldThrowNotImplementedForValidInput() {
        assertThrows(CryptoOperationException.class, () -> crypto.derive(ECC_SPEC, fixed32(0x11)));
        assertThrows(CryptoOperationException.class, () -> crypto.derive(HYBRID_SPEC, fixed64(0x22)));
    }

    private static byte[] fixed32(int seed) {
        byte[] out = new byte[32];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (seed + i);
        }
        return out;
    }

    private static byte[] fixed64(int seed) {
        byte[] out = new byte[64];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (seed + i);
        }
        return out;
    }
}
