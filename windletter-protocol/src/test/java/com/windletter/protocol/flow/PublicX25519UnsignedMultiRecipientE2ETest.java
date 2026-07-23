package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.Test;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.BINARY_PAYLOAD;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.CONTENT_TYPE;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.MESSAGE_ID;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.TIMESTAMP;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicX25519UnsignedMultiRecipientE2ETest {

    @Test
    void eachOfThreeRealRecipientsRestoresTheSameBinaryPayloadFromOnlyTheWireString() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            String wireJson = fixture.send(fixture.binaryPayload());

            for (X25519PrivateKeyHandle recipient : fixture.recipients()) {
                PublicX25519UnsignedReceiver.Result result = fixture.receiver().receive(
                        fixture.receiveRequest(wireJson, recipient)
                );

                assertArrayEquals(BINARY_PAYLOAD, result.payload().data());
                assertEquals(CONTENT_TYPE, result.payload().contentType());
                assertEquals(BINARY_PAYLOAD.length, result.payload().originalSize());
                assertEquals(MESSAGE_ID, result.messageId());
                assertEquals(TIMESTAMP, result.timestamp());
                assertEquals(ProtocolAuthenticationStatus.UNSIGNED, result.authenticationStatus());
                assertEquals(32, recipient.publicKey().length, "receiver must not close borrowed handle");
            }

            assertProtocolCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                    fixture.receiveRequest(wireJson, fixture.unrelatedRecipient)
            ));
        }
    }

    @Test
    void zeroLengthPayloadRoundTripsThroughTheSameRealWireFlow() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ProtocolPayload emptyPayload = new ProtocolPayload(CONTENT_TYPE, new byte[0], 0);
            String wireJson = fixture.send(emptyPayload);

            PublicX25519UnsignedReceiver.Result result = fixture.receiver().receive(
                    fixture.receiveRequest(wireJson, fixture.secondRecipient)
            );

            assertArrayEquals(new byte[0], result.payload().data());
            assertEquals(CONTENT_TYPE, result.payload().contentType());
            assertEquals(0, result.payload().originalSize());
            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.UNSIGNED, result.authenticationStatus());
            assertEquals(32, fixture.secondRecipient.publicKey().length);
        }
    }
}
