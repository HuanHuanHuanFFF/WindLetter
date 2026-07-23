package com.windletter.protocol.recipient;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicX25519RecipientBuilderTest {

    private static final byte[] CEK = HexFormat.of().parseHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );

    @Test
    void buildsTwoRealRecipientsThatCanEachUnwrapTheSameCek() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(x25519, hkdf);
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(deriver, keyWrap);
        byte[] cek = CEK.clone();

        try (X25519PrivateKeyHandle sender = x25519.generatePrivateKey();
             X25519PrivateKeyHandle first = x25519.generatePrivateKey();
             X25519PrivateKeyHandle second = x25519.generatePrivateKey()) {
            List<byte[]> publicKeys = List.of(first.publicKey(), second.publicKey());
            List<PublicRecipient> recipients = builder.build(sender, publicKeys, cek);

            assertEquals(2, recipients.size());
            for (int i = 0; i < recipients.size(); i++) {
                PublicRecipient recipient = recipients.get(i);
                X25519PrivateKeyHandle receiver = i == 0 ? first : second;
                byte[] kek = deriver.derive(receiver, sender.publicKey());
                byte[] unwrapped = keyWrap.unwrap(kek, recipient.encryptedKey());
                try {
                    assertEquals(X25519KeyId.derive(publicKeys.get(i)), recipient.kid().x25519());
                    assertNull(recipient.kid().mlkem768());
                    assertNull(recipient.ek());
                    assertEquals(40, recipient.encryptedKey().length);
                    assertArrayEquals(cek, unwrapped);
                } finally {
                    Arrays.fill(kek, (byte) 0);
                    Arrays.fill(unwrapped, (byte) 0);
                }
            }
            assertArrayEquals(CEK, cek);
            assertEquals(32, sender.publicKey().length);
        }
    }

    @Test
    void validatesEveryInputAndDuplicateKidBeforeInvokingCrypto() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        CountingKeyWrapCrypto keyWrap = new CountingKeyWrapCrypto();
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, hkdf),
                keyWrap
        );
        byte[] valid = filled(32, (byte) 1);
        List<byte[]> tooMany = uniqueKeys(33);

        assertThrows(IllegalArgumentException.class, () -> builder.build(null, List.of(valid), CEK));
        assertThrows(IllegalArgumentException.class, () -> builder.build(DUMMY_HANDLE, null, CEK));
        assertThrows(IllegalArgumentException.class, () -> builder.build(DUMMY_HANDLE, List.of(), CEK));
        assertThrows(IllegalArgumentException.class, () -> builder.build(DUMMY_HANDLE, tooMany, CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, Arrays.asList((byte[]) null), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(new byte[31]), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(new byte[33]), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(valid, valid.clone()), CEK));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(valid), null));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(valid), new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(valid), new byte[33]));

        assertEquals(0, x25519.calls);
        assertEquals(0, hkdf.calls);
        assertEquals(0, keyWrap.calls);
    }

    @Test
    void acceptsExactly32RecipientsAndReturnsAnImmutableOrderedList() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        CountingKeyWrapCrypto keyWrap = new CountingKeyWrapCrypto();
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, hkdf),
                keyWrap
        );
        List<byte[]> keys = uniqueKeys(32);

        List<PublicRecipient> recipients = builder.build(DUMMY_HANDLE, keys, CEK);

        assertEquals(32, recipients.size());
        assertEquals(32, x25519.calls);
        assertEquals(32, hkdf.calls);
        assertEquals(32, keyWrap.calls);
        for (int i = 0; i < recipients.size(); i++) {
            assertEquals(X25519KeyId.derive(keys.get(i)), recipients.get(i).kid().x25519());
        }
        assertThrows(UnsupportedOperationException.class,
                () -> recipients.add(recipients.get(0)));
    }

    @Test
    void snapshotsAllRecipientKeysBeforeTheFirstCryptoOperation() {
        byte[] first = filled(32, (byte) 1);
        byte[] second = filled(32, (byte) 2);
        byte[] expectedSecond = second.clone();
        String expectedSecondKid = X25519KeyId.derive(expectedSecond);
        MutatingX25519Crypto x25519 = new MutatingX25519Crypto(second);
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, new CountingHkdfCrypto()),
                new CountingKeyWrapCrypto()
        );

        List<PublicRecipient> recipients = builder.build(DUMMY_HANDLE, List.of(first, second), CEK);

        assertTrue(allZero(second));
        assertArrayEquals(expectedSecond, x25519.peers.get(1));
        assertEquals(expectedSecondKid, recipients.get(1).kid().x25519());
    }

    @Test
    void rejectsLowOrderRecipientWithoutClosingBorrowedSenderHandle() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                new BouncyCastleA256KeyWrapCrypto()
        );
        try (X25519PrivateKeyHandle sender = x25519.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class,
                    () -> builder.build(sender, List.of(new byte[32]), CEK));
            assertEquals(32, sender.publicKey().length);
        }
    }

    @Test
    void clearsKekWhenWrappingFailsAndLeavesBorrowedHandleOpen() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        FailingKeyWrapCrypto keyWrap = new FailingKeyWrapCrypto();
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, new BouncyCastleHkdfCrypto()),
                keyWrap
        );
        try (X25519PrivateKeyHandle sender = x25519.generatePrivateKey();
             X25519PrivateKeyHandle recipient = x25519.generatePrivateKey()) {
            assertThrows(CryptoOperationException.class,
                    () -> builder.build(sender, List.of(recipient.publicKey()), CEK));
            assertTrue(allZero(keyWrap.capturedKek));
            assertArrayEquals(CEK, keyWrap.capturedCek);
            assertEquals(32, sender.publicKey().length);
        }
    }

    @Test
    void rejectsNon40ByteWrappedOutputAndClearsKek() {
        CountingX25519Crypto x25519 = new CountingX25519Crypto();
        CountingHkdfCrypto hkdf = new CountingHkdfCrypto();
        ShortKeyWrapCrypto keyWrap = new ShortKeyWrapCrypto();
        PublicX25519RecipientBuilder builder = new PublicX25519RecipientBuilder(
                new PublicX25519KekDeriver(x25519, hkdf),
                keyWrap
        );

        assertThrows(IllegalStateException.class,
                () -> builder.build(DUMMY_HANDLE, List.of(filled(32, (byte) 3)), CEK));
        assertTrue(allZero(keyWrap.capturedKek));
    }

    @Test
    void validatesConstructorDependencies() {
        PublicX25519KekDeriver deriver = new PublicX25519KekDeriver(
                new CountingX25519Crypto(),
                new CountingHkdfCrypto()
        );
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519RecipientBuilder(null, new CountingKeyWrapCrypto()));
        assertThrows(IllegalArgumentException.class,
                () -> new PublicX25519RecipientBuilder(deriver, null));
    }

    private static final X25519PrivateKeyHandle DUMMY_HANDLE = new X25519PrivateKeyHandle() {
        @Override
        public byte[] publicKey() {
            return new byte[32];
        }

        @Override
        public void close() {
        }
    };

    private static List<byte[]> uniqueKeys(int count) {
        List<byte[]> keys = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] key = new byte[32];
            key[0] = (byte) (i + 1);
            keys.add(key);
        }
        return keys;
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }

    private static boolean allZero(byte[] value) {
        if (value == null) {
            return false;
        }
        for (byte current : value) {
            if (current != 0) {
                return false;
            }
        }
        return true;
    }

    private static class CountingX25519Crypto implements X25519Crypto {
        protected int calls;

        @Override
        public X25519PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey) {
            calls++;
            return filled(32, (byte) calls);
        }
    }

    private static final class MutatingX25519Crypto extends CountingX25519Crypto {
        private final byte[] toMutate;
        private final List<byte[]> peers = new ArrayList<>();

        private MutatingX25519Crypto(byte[] toMutate) {
            this.toMutate = toMutate;
        }

        @Override
        public byte[] deriveSharedSecret(X25519PrivateKeyHandle privateKey, byte[] peerPublicKey) {
            peers.add(peerPublicKey.clone());
            if (peers.size() == 1) {
                Arrays.fill(toMutate, (byte) 0);
            }
            return super.deriveSharedSecret(privateKey, peerPublicKey);
        }
    }

    private static final class CountingHkdfCrypto implements HkdfCrypto {
        private int calls;

        @Override
        public byte[] extract(byte[] salt, byte[] ikm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] expand(byte[] prk, byte[] info, int length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
            calls++;
            return filled(32, (byte) calls);
        }
    }

    private static class CountingKeyWrapCrypto implements A256KeyWrapCrypto {
        protected int calls;

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            calls++;
            return filled(40, (byte) calls);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class FailingKeyWrapCrypto implements A256KeyWrapCrypto {
        private byte[] capturedKek;
        private byte[] capturedCek;

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            capturedKek = kek;
            capturedCek = keyToWrap.clone();
            throw new CryptoOperationException("wrap failed");
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class ShortKeyWrapCrypto implements A256KeyWrapCrypto {
        private byte[] capturedKek;

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            capturedKek = kek;
            return new byte[39];
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            throw new UnsupportedOperationException();
        }
    }
}
