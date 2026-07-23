package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.assertProtocolCode;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.flipEncodedField;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.parseObject;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.recomputeAad;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.reencodeProtectedWithWhitespace;
import static com.windletter.protocol.flow.ProtocolFlowTestFixtures.write;

class PublicX25519UnsignedTamperE2ETest {

    @Test
    void changedRecipientContentWithStaleAadIsRejectedBeforeRouting() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(1);
            flipEncodedField(target, "encrypted_key");

            assertProtocolCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    fixture.receiveRequest(write(root), fixture.secondRecipient)
            ));
        }
    }

    @Test
    void changedRecipientOrderWithStaleAadIsRejectedBeforeRouting() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            ArrayNode recipients = root.withArray("recipients");
            JsonNode first = recipients.get(0).deepCopy();
            recipients.set(0, recipients.get(1).deepCopy());
            recipients.set(1, first);

            assertProtocolCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    fixture.receiveRequest(write(root), fixture.secondRecipient)
            ));
        }
    }

    @Test
    void changedAadIsRejectedBeforeRouting() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            flipEncodedField(root, "aad");

            assertProtocolCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    fixture.receiveRequest(write(root), fixture.secondRecipient)
            ));
        }
    }

    @Test
    void semanticallyIdenticalProtectedWithDifferentLegalJsonBytesFailsGcmAuthentication() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            reencodeProtectedWithWhitespace(root);

            assertProtocolCode(ErrorCode.GCM_AUTH_FAILED, () -> fixture.receiver().receive(
                    fixture.receiveRequest(write(root), fixture.secondRecipient)
            ));
        }
    }

    @Test
    void changedTargetEncryptedKeyWithRecomputedAadFailsKeyUnwrap() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            ObjectNode root = parseObject(fixture.send(fixture.binaryPayload()));
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(1);
            flipEncodedField(target, "encrypted_key");
            recomputeAad(root);

            assertProtocolCode(ErrorCode.KEY_UNWRAP_FAILED, () -> fixture.receiver().receive(
                    fixture.receiveRequest(write(root), fixture.secondRecipient)
            ));
        }
    }

    @Test
    void changedIvCiphertextOrTagFailsGcmAuthenticationAfterRecipientMatch() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            String wireJson = fixture.send(fixture.binaryPayload());
            for (String field : List.of("iv", "ciphertext", "tag")) {
                ObjectNode root = parseObject(wireJson);
                flipEncodedField(root, field);

                assertProtocolCode(ErrorCode.GCM_AUTH_FAILED, () -> fixture.receiver().receive(
                        fixture.receiveRequest(write(root), fixture.secondRecipient)
                ));
            }
        }
    }

    @Test
    void authenticatedInnerWithOnlyProtectedBindingChangedReachesBindingGate() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            String maliciousWire = fixture.authenticatedBindingTamper(
                    ProtocolFlowTestFixtures.BindingTarget.PROTECTED
            );

            assertProtocolCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                    fixture.receiveRequest(maliciousWire, fixture.secondRecipient)
            ));
        }
    }

    @Test
    void authenticatedInnerWithOnlyRecipientsBindingChangedReachesBindingGate() {
        try (ProtocolFlowTestFixtures.RealFixture fixture = ProtocolFlowTestFixtures.realFixture()) {
            String maliciousWire = fixture.authenticatedBindingTamper(
                    ProtocolFlowTestFixtures.BindingTarget.RECIPIENTS
            );

            assertProtocolCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                    fixture.receiveRequest(maliciousWire, fixture.secondRecipient)
            ));
        }
    }
}
