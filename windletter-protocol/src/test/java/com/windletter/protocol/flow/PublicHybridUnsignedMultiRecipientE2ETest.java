package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicHybridUnsignedMultiRecipientE2ETest {

    @Test
    void firstMiddleAndLastPairsRestoreOneRealBinaryWireAndUnrelatedStopsBeforeResolver() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String wire = fixture.sendUnsigned(fixture.binaryPayload());

            fixture.assertThreeRecipientWire(wire);
            assertRoundTrips(fixture, wire, ProtocolFlowTestFixtures.BINARY_PAYLOAD);

            AtomicInteger resolverCalls = new AtomicInteger();
            PublicHybridUnsignedReceiver.Request unrelatedRequest =
                    new PublicHybridUnsignedReceiver.Request(
                            wire,
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.senderEncryptionKey.publicKey());
                            },
                            List.of(fixture.unrelated.privateKeys())
                    );
            assertProtocolCode(ErrorCode.NOT_FOR_ME,
                    () -> fixture.unsignedReceiver().receive(unrelatedRequest));
            assertEquals(0, resolverCalls.get());
            assertPairOpen(fixture.unrelated);
        }
    }

    @Test
    void firstMiddleAndLastPairsRestoreOneRealEmptyWire() {
        try (PublicHybridFlowTestFixtures fixture = new PublicHybridFlowTestFixtures()) {
            String wire = fixture.sendUnsigned(fixture.emptyPayload());

            fixture.assertThreeRecipientWire(wire);
            assertRoundTrips(fixture, wire, new byte[0]);
        }
    }

    private static void assertRoundTrips(
            PublicHybridFlowTestFixtures fixture,
            String wire,
            byte[] expectedData
    ) {
        for (PublicHybridFlowTestFixtures.HybridPair recipient : fixture.recipients()) {
            PublicHybridUnsignedReceiver.Result result = fixture.unsignedReceiver().receive(
                    fixture.unsignedRequest(wire, recipient)
            );
            byte[] actualData = result.payload().data();
            try {
                assertArrayEquals(expectedData, actualData);
                assertEquals(ProtocolFlowTestFixtures.CONTENT_TYPE,
                        result.payload().contentType());
                assertEquals(expectedData.length, result.payload().originalSize());
                assertEquals(ProtocolFlowTestFixtures.MESSAGE_ID, result.messageId());
                assertEquals(ProtocolFlowTestFixtures.TIMESTAMP, result.timestamp());
                assertEquals(ProtocolAuthenticationStatus.UNSIGNED,
                        result.authenticationStatus());
            } finally {
                PublicHybridFlowTestFixtures.clear(actualData);
            }
            assertPairOpen(recipient);
        }
    }

    private static void assertPairOpen(PublicHybridFlowTestFixtures.HybridPair pair) {
        byte[] x25519Public = pair.x25519.publicKey();
        byte[] mlkemPublic = pair.mlkem768.publicKey();
        try {
            assertEquals(32, x25519Public.length);
            assertEquals(1184, mlkemPublic.length);
        } finally {
            PublicHybridFlowTestFixtures.clear(x25519Public);
            PublicHybridFlowTestFixtures.clear(mlkemPublic);
        }
    }
}
