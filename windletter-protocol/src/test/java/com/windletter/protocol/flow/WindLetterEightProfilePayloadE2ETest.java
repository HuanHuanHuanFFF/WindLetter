package com.windletter.protocol.flow;

import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class WindLetterEightProfilePayloadE2ETest {

    @ParameterizedTest(name = "{0} / {1}")
    @MethodSource("allProfilesAndPayloads")
    void everyV1ProfileRoundTripsTextAndArbitraryBinaryPayloads(
            Profile profile,
            PayloadKind payloadKind
    ) {
        ProtocolPayload expected = payloadKind.payload();
        Received actual = profile.roundTrip(expected);

        assertPayload(expected, actual.payload());
        assertEquals(ProtocolFlowTestFixtures.MESSAGE_ID, actual.messageId());
        assertEquals(ProtocolFlowTestFixtures.TIMESTAMP, actual.timestamp());
        assertEquals(profile.expectedStatus(), actual.authenticationStatus());

        if (profile.expectedStatus() == ProtocolAuthenticationStatus.SIGNED_VALID) {
            assertEquals(actual.expectedIdentityId(), actual.authenticatedSender().identityId());
            assertEquals(actual.expectedSigningKid(), actual.authenticatedSender().signingKid());
        } else {
            assertNull(actual.authenticatedSender());
            assertNull(actual.expectedIdentityId());
            assertNull(actual.expectedSigningKid());
        }
    }

    static Stream<Arguments> allProfilesAndPayloads() {
        return Arrays.stream(Profile.values()).flatMap(profile ->
                Arrays.stream(PayloadKind.values()).map(payload ->
                        Arguments.of(profile, payload)
                )
        );
    }

    private static void assertPayload(ProtocolPayload expected, ProtocolPayload actual) {
        byte[] expectedData = expected.data();
        byte[] actualData = actual.data();
        try {
            assertEquals(expected.contentType(), actual.contentType());
            assertArrayEquals(expectedData, actualData);
            assertEquals(expected.originalSize(), actual.originalSize());
        } finally {
            clear(expectedData);
            clear(actualData);
        }
    }

    private enum Profile {
        PUBLIC_X25519_UNSIGNED(ProtocolAuthenticationStatus.UNSIGNED) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (ProtocolFlowTestFixtures.RealFixture fixture =
                             ProtocolFlowTestFixtures.realFixture()) {
                    String wire = fixture.send(payload);
                    PublicX25519UnsignedReceiver.Result result = fixture.receiver().receive(
                            fixture.receiveRequest(wire, fixture.secondRecipient)
                    );
                    return Received.unsigned(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus()
                    );
                }
            }
        },
        PUBLIC_X25519_SIGNED(ProtocolAuthenticationStatus.SIGNED_VALID) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (SignedProtocolFlowTestFixtures fixture =
                             new SignedProtocolFlowTestFixtures()) {
                    String wire = fixture.send(payload);
                    PublicX25519SignedReceiver.Result result = fixture.receiver().receive(
                            fixture.receiveRequest(wire, fixture.secondRecipient)
                    );
                    return Received.signed(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus(), result.authenticatedSender(),
                            SignedProtocolFlowTestFixtures.IDENTITY_ID, fixture.signingKid
                    );
                }
            }
        },
        PUBLIC_HYBRID_UNSIGNED(ProtocolAuthenticationStatus.UNSIGNED) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (PublicHybridFlowTestFixtures fixture =
                             new PublicHybridFlowTestFixtures()) {
                    String wire = fixture.sendUnsigned(payload);
                    PublicHybridUnsignedReceiver.Result result =
                            fixture.unsignedReceiver().receive(
                                    fixture.unsignedRequest(wire, fixture.middle)
                            );
                    return Received.unsigned(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus()
                    );
                }
            }
        },
        PUBLIC_HYBRID_SIGNED(ProtocolAuthenticationStatus.SIGNED_VALID) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (PublicHybridFlowTestFixtures fixture =
                             new PublicHybridFlowTestFixtures()) {
                    String wire = fixture.sendSigned(payload);
                    PublicHybridSignedReceiver.Result result =
                            fixture.signedReceiver().receive(
                                    fixture.signedRequest(wire, fixture.middle)
                            );
                    return Received.signed(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus(), result.authenticatedSender(),
                            PublicHybridFlowTestFixtures.IDENTITY_ID, fixture.signingKid
                    );
                }
            }
        },
        OBFUSCATION_X25519_UNSIGNED(ProtocolAuthenticationStatus.UNSIGNED) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                             new ObfuscationX25519FlowTestFixtures.Fixture()) {
                    String wire = fixture.send(payload);
                    ObfuscationX25519UnsignedReceiver.Result result =
                            fixture.receiver().receive(
                                    fixture.request(wire, List.of(fixture.second))
                            );
                    return Received.unsigned(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus()
                    );
                }
            }
        },
        OBFUSCATION_X25519_SIGNED(ProtocolAuthenticationStatus.SIGNED_VALID) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (ObfuscationX25519FlowTestFixtures.Fixture fixture =
                             new ObfuscationX25519FlowTestFixtures.Fixture()) {
                    String wire = fixture.sendSigned(payload);
                    ObfuscationX25519SignedReceiver.Result result =
                            fixture.signedReceiver().receive(fixture.signedRequest(
                                    wire,
                                    requestedKid -> requestedKid.equals(fixture.signingKid)
                                            ? java.util.Optional.of(fixture.trustedSigningKey())
                                            : java.util.Optional.empty(),
                                    List.of(fixture.second)
                            ));
                    return Received.signed(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus(), result.authenticatedSender(),
                            ObfuscationX25519FlowTestFixtures.IDENTITY_ID,
                            fixture.signingKid
                    );
                }
            }
        },
        OBFUSCATION_HYBRID_UNSIGNED(ProtocolAuthenticationStatus.UNSIGNED) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (ObfuscationHybridFlowTestFixtures fixture =
                             new ObfuscationHybridFlowTestFixtures()) {
                    String wire = fixture.send(payload);
                    ObfuscationHybridUnsignedReceiver.Result result =
                            fixture.receiver().receive(fixture.request(
                                    wire, List.of(fixture.middle.privateKeys())
                            ));
                    return Received.unsigned(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus()
                    );
                }
            }
        },
        OBFUSCATION_HYBRID_SIGNED(ProtocolAuthenticationStatus.SIGNED_VALID) {
            @Override
            Received roundTrip(ProtocolPayload payload) {
                try (ObfuscationHybridFlowTestFixtures fixture =
                             new ObfuscationHybridFlowTestFixtures()) {
                    String wire = fixture.sendSigned(payload);
                    ObfuscationHybridSignedReceiver.Result result =
                            fixture.signedReceiver().receive(fixture.signedRequest(
                                    wire,
                                    fixture.trustedSigningResolver(),
                                    List.of(fixture.middle.privateKeys())
                            ));
                    return Received.signed(
                            result.payload(), result.messageId(), result.timestamp(),
                            result.authenticationStatus(), result.authenticatedSender(),
                            ObfuscationHybridFlowTestFixtures.IDENTITY_ID,
                            fixture.signingKid
                    );
                }
            }
        };

        private final ProtocolAuthenticationStatus expectedStatus;

        Profile(ProtocolAuthenticationStatus expectedStatus) {
            this.expectedStatus = expectedStatus;
        }

        ProtocolAuthenticationStatus expectedStatus() {
            return expectedStatus;
        }

        abstract Received roundTrip(ProtocolPayload payload);
    }

    private enum PayloadKind {
        TEXT {
            @Override
            ProtocolPayload payload() {
                byte[] data = "WindLetter 八组合文本".getBytes(StandardCharsets.UTF_8);
                try {
                    return new ProtocolPayload(
                            "text/plain; charset=utf-8", data, data.length
                    );
                } finally {
                    clear(data);
                }
            }
        },
        BINARY_WITH_ZERO_AND_INVALID_UTF8 {
            @Override
            ProtocolPayload payload() {
                byte[] data = {
                        0x00, 0x42, (byte) 0xc3, 0x28,
                        (byte) 0x80, (byte) 0xff, 0x00
                };
                try {
                    return new ProtocolPayload(
                            "application/vnd.windletter.eight-profile+binary",
                            data,
                            data.length
                    );
                } finally {
                    clear(data);
                }
            }
        };

        abstract ProtocolPayload payload();
    }

    private record Received(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus,
            ProtocolSenderIdentity authenticatedSender,
            String expectedIdentityId,
            String expectedSigningKid
    ) {
        static Received unsigned(
                ProtocolPayload payload,
                String messageId,
                long timestamp,
                ProtocolAuthenticationStatus authenticationStatus
        ) {
            return new Received(
                    payload, messageId, timestamp, authenticationStatus,
                    null, null, null
            );
        }

        static Received signed(
                ProtocolPayload payload,
                String messageId,
                long timestamp,
                ProtocolAuthenticationStatus authenticationStatus,
                ProtocolSenderIdentity authenticatedSender,
                String expectedIdentityId,
                String expectedSigningKid
        ) {
            return new Received(
                    payload, messageId, timestamp, authenticationStatus,
                    authenticatedSender, expectedIdentityId, expectedSigningKid
            );
        }
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
