package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static com.windletter.protocol.flow.SignedProtocolFlowTestFixtures.BINARY_PAYLOAD;
import static com.windletter.protocol.flow.SignedProtocolFlowTestFixtures.CONTENT_TYPE;
import static com.windletter.protocol.flow.SignedProtocolFlowTestFixtures.IDENTITY_ID;
import static com.windletter.protocol.flow.SignedProtocolFlowTestFixtures.MESSAGE_ID;
import static com.windletter.protocol.flow.SignedProtocolFlowTestFixtures.TIMESTAMP;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicX25519SignedMultiRecipientE2ETest {

    @Test
    void firstMiddleAndLastRecipientsRestoreTheSameAuthenticatedBinaryPayloadFromOneWireString() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            String wireJson = fixture.send(fixture.binaryPayload());

            for (X25519PrivateKeyHandle recipient : fixture.recipients()) {
                PublicX25519SignedReceiver.Result result = fixture.receiver().receive(
                        fixture.receiveRequest(wireJson, recipient)
                );

                assertAuthenticatedResult(fixture, result, BINARY_PAYLOAD);
                assertEquals(32, recipient.publicKey().length, "receiver must not close borrowed handle");
            }

            AtomicInteger encryptionResolverCalls = new AtomicInteger();
            AtomicInteger signingResolverCalls = new AtomicInteger();
            PublicX25519SignedReceiver.Request unrelatedRequest = new PublicX25519SignedReceiver.Request(
                    wireJson,
                    kid -> {
                        encryptionResolverCalls.incrementAndGet();
                        return java.util.Optional.of(fixture.senderEncryptionKey.publicKey());
                    },
                    kid -> {
                        signingResolverCalls.incrementAndGet();
                        return java.util.Optional.of(fixture.trustedSigningKey());
                    },
                    java.util.List.of(fixture.unrelatedRecipient)
            );

            assertProtocolCode(
                    ErrorCode.NOT_FOR_ME,
                    () -> fixture.receiver().receive(unrelatedRequest)
            );
            assertEquals(0, encryptionResolverCalls.get());
            assertEquals(0, signingResolverCalls.get());
            assertEquals(32, fixture.unrelatedRecipient.publicKey().length);
        }
    }

    @Test
    void firstMiddleAndLastRecipientsRestoreTheSameAuthenticatedEmptyPayloadFromOneWireString() {
        try (SignedProtocolFlowTestFixtures fixture = new SignedProtocolFlowTestFixtures()) {
            ProtocolPayload empty = fixture.emptyPayload();
            String wireJson = fixture.send(empty);

            for (X25519PrivateKeyHandle recipient : fixture.recipients()) {
                PublicX25519SignedReceiver.Result result = fixture.receiver().receive(
                        fixture.receiveRequest(wireJson, recipient)
                );

                assertAuthenticatedResult(fixture, result, new byte[0]);
                assertEquals(32, recipient.publicKey().length);
            }
        }
    }

    private static void assertAuthenticatedResult(
            SignedProtocolFlowTestFixtures fixture,
            PublicX25519SignedReceiver.Result result,
            byte[] expectedPayload
    ) {
        assertArrayEquals(expectedPayload, result.payload().data());
        assertEquals(CONTENT_TYPE, result.payload().contentType());
        assertEquals(expectedPayload.length, result.payload().originalSize());
        assertEquals(MESSAGE_ID, result.messageId());
        assertEquals(TIMESTAMP, result.timestamp());
        assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID, result.authenticationStatus());
        assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
        assertEquals(fixture.signingKid, result.authenticatedSender().signingKid());
    }
}
