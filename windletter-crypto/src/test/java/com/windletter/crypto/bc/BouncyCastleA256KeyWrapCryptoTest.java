package com.windletter.crypto.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.crypto.api.CryptoOperationException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class BouncyCastleA256KeyWrapCryptoTest {

    private final BouncyCastleA256KeyWrapCrypto crypto = new BouncyCastleA256KeyWrapCrypto();
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    void shouldWrapAndUnwrapRoundTrip() {
        byte[] kek = randomBytes(32);
        byte[] cek = randomBytes(32);

        byte[] wrapped = crypto.wrap(kek, cek);
        byte[] unwrapped = crypto.unwrap(kek, wrapped);

        assertEquals(40, wrapped.length);
        assertArrayEquals(cek, unwrapped);
    }

    @Test
    void shouldRejectTooShortPlaintextKey() {
        byte[] kek = randomBytes(32);
        assertThrows(IllegalArgumentException.class, () -> crypto.wrap(kek, randomBytes(8)));
    }

    @Test
    void shouldRejectTooShortWrappedKey() {
        byte[] kek = randomBytes(32);
        assertThrows(IllegalArgumentException.class, () -> crypto.unwrap(kek, randomBytes(16)));
    }

    @Test
    void shouldThrowCryptoOperationExceptionWhenKekDoesNotMatch() {
        byte[] kek1 = randomBytes(32);
        byte[] kek2 = randomBytes(32);
        byte[] cek = randomBytes(32);

        byte[] wrapped = crypto.wrap(kek1, cek);
        assertThrows(CryptoOperationException.class, () -> crypto.unwrap(kek2, wrapped));
    }

    private byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        secureRandom.nextBytes(out);
        return out;
    }
}
