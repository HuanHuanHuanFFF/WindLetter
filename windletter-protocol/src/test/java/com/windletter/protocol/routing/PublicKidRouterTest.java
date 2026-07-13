package com.windletter.protocol.routing;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PublicKidRouterTest {

    @Test
    void routesFirstMatchingRecipientWithoutClosingBorrowedHandle() {
        X25519PrivateKeyHandle local = handle(filled(32, (byte) 0x21));
        PublicRecipient first = recipient(X25519KeyId.derive(local.publicKey()));
        List<RecipientEntry> recipients = List.of(first, recipient(X25519KeyId.derive(filled(32, (byte) 0x42))));

        PublicKidRouter.Match match = new PublicKidRouter().route(recipients, List.of(local));

        assertSame(first, match.recipient());
        assertSame(local, match.privateKey());
        assertEquals(32, local.publicKey().length);
    }

    @Test
    void routesMiddleAndLastPositions() {
        X25519PrivateKeyHandle local = handle(filled(32, (byte) 0x21));
        String localKid = X25519KeyId.derive(local.publicKey());
        PublicRecipient middle = recipient(localKid);
        PublicRecipient last = recipient(localKid);
        PublicRecipient unrelated = recipient(X25519KeyId.derive(filled(32, (byte) 0x42)));

        assertSame(middle, new PublicKidRouter().route(
                List.of(unrelated, middle, recipient(X25519KeyId.derive(filled(32, (byte) 0x43)))),
                List.of(local)
        ).recipient());
        assertSame(last, new PublicKidRouter().route(
                List.of(unrelated, recipient(X25519KeyId.derive(filled(32, (byte) 0x43))), last),
                List.of(local)
        ).recipient());
        assertEquals(32, local.publicKey().length);
    }

    @Test
    void emptyOrUnmatchedLocalKeysReturnNotForMe() {
        PublicRecipient recipient = recipient(X25519KeyId.derive(filled(32, (byte) 0x42)));

        assertCode(ErrorCode.NOT_FOR_ME, () -> new PublicKidRouter().route(List.of(recipient), List.of()));
        X25519PrivateKeyHandle unrelated = handle(filled(32, (byte) 0x21));
        assertCode(ErrorCode.NOT_FOR_ME,
                () -> new PublicKidRouter().route(List.of(recipient), List.of(unrelated)));
        assertEquals(32, unrelated.publicKey().length);
    }

    @Test
    void rejectsDuplicateLocalKidAndDuplicateMatchingRecipient() {
        byte[] localPublic = filled(32, (byte) 0x21);
        X25519PrivateKeyHandle first = handle(localPublic);
        X25519PrivateKeyHandle duplicate = handle(localPublic);
        PublicRecipient recipient = recipient(X25519KeyId.derive(localPublic));

        assertCode(ErrorCode.INVALID_FIELD,
                () -> new PublicKidRouter().route(List.of(recipient), List.of(first, duplicate)));
        assertCode(ErrorCode.INVALID_FIELD,
                () -> new PublicKidRouter().route(List.of(recipient, recipient(localKid(first))), List.of(first)));
        assertEquals(32, first.publicKey().length);
        assertEquals(32, duplicate.publicKey().length);
    }

    @Test
    void multipleDistinctLocalMatchesSelectWireFirstAfterFullDuplicateScan() {
        X25519PrivateKeyHandle firstLocal = handle(filled(32, (byte) 0x21));
        X25519PrivateKeyHandle secondLocal = handle(filled(32, (byte) 0x42));
        PublicRecipient firstOnWire = recipient(localKid(secondLocal));
        PublicRecipient secondOnWire = recipient(localKid(firstLocal));

        PublicKidRouter.Match match = new PublicKidRouter().route(
                List.of(firstOnWire, secondOnWire),
                List.of(firstLocal, secondLocal)
        );

        assertSame(firstOnWire, match.recipient());
        assertSame(secondLocal, match.privateKey());

        assertCode(ErrorCode.INVALID_FIELD, () -> new PublicKidRouter().route(
                List.of(firstOnWire, secondOnWire, recipient(localKid(secondLocal))),
                List.of(firstLocal, secondLocal)
        ));
    }

    @Test
    void ignoresDuplicateKidThatDoesNotMatchAnyLocalKey() {
        String unrelatedKid = X25519KeyId.derive(filled(32, (byte) 0x42));
        X25519PrivateKeyHandle local = handle(filled(32, (byte) 0x21));
        PublicRecipient match = recipient(localKid(local));

        assertSame(match, new PublicKidRouter().route(
                List.of(recipient(unrelatedKid), recipient(unrelatedKid), match),
                List.of(local)
        ).recipient());
    }

    private static String localKid(X25519PrivateKeyHandle handle) {
        return X25519KeyId.derive(handle.publicKey());
    }

    private static void assertCode(ErrorCode code, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(code, failure.errorCode());
    }

    private static PublicRecipient recipient(String kid) {
        return new PublicRecipient(new RecipientKid(kid, null), new byte[40], null);
    }

    private static X25519PrivateKeyHandle handle(byte[] publicKey) {
        return new X25519PrivateKeyHandle() {
            @Override
            public byte[] publicKey() {
                return publicKey.clone();
            }

            @Override
            public void close() {
            }
        };
    }

    private static byte[] filled(int length, byte value) {
        byte[] result = new byte[length];
        java.util.Arrays.fill(result, value);
        return result;
    }
}
