package com.windletter.protocol.binding;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderKid;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OuterBindingTest {

    private static final String KID_ONE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    private static final String KID_TWO = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
    private static final byte[] EXPECTED_PROTECTED_HASH = HexFormat.of().parseHex(
            "31375bdfe89634f634d25eaa9486d8a82ba9ef83ef0605a7ad4f20d86a04e353"
    );
    private static final byte[] EXPECTED_RECIPIENTS_HASH = HexFormat.of().parseHex(
            "48cc14bbeb7453b757cf8d4f5f7dd9c3b84cb19933a67d3253d97ce7eadb8753"
    );

    private final OuterBinding binding = new OuterBinding();

    @Test
    void computesSha256OfCanonicalSemanticProtectedHeaderAndFinalRecipients() {
        OuterBinding.Hashes hashes = binding.compute(vectorHeader(), vectorRecipients());

        assertArrayEquals(EXPECTED_PROTECTED_HASH, hashes.protectedHash());
        assertArrayEquals(EXPECTED_RECIPIENTS_HASH, hashes.recipientsHash());
    }

    @Test
    void hashesRequireExactLengthsAndDefensivelyCopyConstructorAndAccessorArrays() {
        byte[] protectedHash = EXPECTED_PROTECTED_HASH.clone();
        byte[] recipientsHash = EXPECTED_RECIPIENTS_HASH.clone();
        OuterBinding.Hashes hashes = new OuterBinding.Hashes(protectedHash, recipientsHash);

        protectedHash[0] ^= 1;
        recipientsHash[0] ^= 1;
        assertArrayEquals(EXPECTED_PROTECTED_HASH, hashes.protectedHash());
        assertArrayEquals(EXPECTED_RECIPIENTS_HASH, hashes.recipientsHash());

        byte[] exposedProtected = hashes.protectedHash();
        byte[] exposedRecipients = hashes.recipientsHash();
        exposedProtected[1] ^= 1;
        exposedRecipients[1] ^= 1;
        assertArrayEquals(EXPECTED_PROTECTED_HASH, hashes.protectedHash());
        assertArrayEquals(EXPECTED_RECIPIENTS_HASH, hashes.recipientsHash());

        assertThrows(IllegalArgumentException.class, () -> new OuterBinding.Hashes(new byte[31], new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> new OuterBinding.Hashes(new byte[32], new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> new OuterBinding.Hashes(null, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> new OuterBinding.Hashes(new byte[32], null));
    }

    @Test
    void verifiesBothBindingItemsAndClassifiesEitherMismatch() {
        OuterBinding.Hashes valid = binding.compute(vectorHeader(), vectorRecipients());
        assertDoesNotThrow(() -> binding.verify(valid, vectorHeader(), vectorRecipients()));

        byte[] badProtected = valid.protectedHash();
        badProtected[0] ^= 1;
        ProtocolException protectedFailure = assertThrows(
                ProtocolException.class,
                () -> binding.verify(
                        new OuterBinding.Hashes(badProtected, valid.recipientsHash()),
                        vectorHeader(), vectorRecipients()
                )
        );
        assertEquals(ErrorCode.BINDING_FAILED, protectedFailure.errorCode());

        byte[] badRecipients = valid.recipientsHash();
        badRecipients[0] ^= 1;
        ProtocolException recipientsFailure = assertThrows(
                ProtocolException.class,
                () -> binding.verify(
                        new OuterBinding.Hashes(valid.protectedHash(), badRecipients),
                        vectorHeader(), vectorRecipients()
                )
        );
        assertEquals(ErrorCode.BINDING_FAILED, recipientsFailure.errorCode());
    }

    private static ProtectedHeader vectorHeader() {
        return new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "public", "A256GCM", "X25519",
                new SenderKid(KID_ONE)
        );
    }

    private static List<RecipientEntry> vectorRecipients() {
        return List.of(
                new PublicRecipient(new RecipientKid(KID_ONE, null), filled(40, 0x11), null),
                new PublicRecipient(new RecipientKid(KID_TWO, null), filled(40, 0x22), null)
        );
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
