package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static com.windletter.protocol.flow.ObfuscationX25519FlowTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class ObfuscationX25519SignedMultiRecipientE2ETest {

    @Test
    void realBouncyCastleThreeRecipientWireHasEightEntriesAndAnyRecipientAuthenticatesBinary() {
        try (Fixture fixture = new Fixture()) {
            String wire = fixture.sendSigned(fixture.binaryPayload());
            ObjectNode root = object(wire);
            assertEquals(8, ((ArrayNode) root.get("recipients")).size());

            for (X25519PrivateKeyHandle handle : List.of(
                    fixture.first, fixture.second, fixture.third)) {
                ObfuscationX25519SignedReceiver.Result result = fixture.signedReceiver().receive(
                        fixture.signedRequest(
                                wire,
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(handle)
                        )
                );
                assertArrayEquals(BINARY, result.payload().data());
                assertEquals(MESSAGE_ID, result.messageId());
                assertEquals(TIMESTAMP, result.timestamp());
                assertEquals(ProtocolAuthenticationStatus.SIGNED_VALID,
                        result.authenticationStatus());
                assertEquals(IDENTITY_ID, result.authenticatedSender().identityId());
                assertEquals(fixture.signingKid, result.authenticatedSender().signingKid());
                assertEquals(32, handle.publicKey().length, "recipient handle is borrowed");
            }
        }
    }

    @Test
    void textAndEmptyRoundTripWhileUnrelatedRecipientAndUnknownSignerReleaseNothing() {
        try (Fixture fixture = new Fixture()) {
            for (ProtocolPayload payload : List.of(fixture.textPayload(), fixture.emptyPayload())) {
                String wire = fixture.sendSigned(payload);
                ObfuscationX25519SignedReceiver.Result result = fixture.signedReceiver().receive(
                        fixture.signedRequest(
                                wire,
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(fixture.third)
                        )
                );
                assertEquals(payload.contentType(), result.payload().contentType());
                assertArrayEquals(payload.data(), result.payload().data());
                assertEquals(payload.originalSize(), result.payload().originalSize());

                assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.signedReceiver().receive(
                        fixture.signedRequest(
                                wire,
                                kid -> Optional.of(fixture.trustedSigningKey()),
                                List.of(fixture.unrelated)
                        )));
                assertCode(ErrorCode.SIGNATURE_INVALID, () -> fixture.signedReceiver().receive(
                        fixture.signedRequest(wire, kid -> Optional.empty(), List.of(fixture.third))
                ));
            }
            assertEquals(32, fixture.unrelated.publicKey().length);
            assertEquals(32, fixture.senderSigning.publicKey().length);
        }
    }
}
