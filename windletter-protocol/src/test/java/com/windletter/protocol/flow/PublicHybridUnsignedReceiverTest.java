package com.windletter.protocol.flow;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.AeadCiphertext;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.HkdfCrypto;
import com.windletter.crypto.api.MLKem768Crypto;
import com.windletter.crypto.api.MLKem768Encapsulation;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleA256GcmCrypto;
import com.windletter.crypto.bc.BouncyCastleA256KeyWrapCrypto;
import com.windletter.crypto.bc.BouncyCastleHkdfCrypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JacksonOuterWireWriter;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.PublicHybridKekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.recipient.PublicHybridRecipientBuilder;
import com.windletter.protocol.recipient.PublicHybridRecipientKeys;
import com.windletter.protocol.routing.PublicHybridRecipientPrivateKeys;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHybridUnsignedReceiverTest {

    private static final String MESSAGE_ID = "123e4567-e89b-42d3-a456-426614174000";
    private static final long TIMESTAMP = 1_731_800_000L;
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void receivesRealSenderWireForSecondHybridRecipientWithBinaryPayload() {
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, new BouncyCastleHkdfCrypto()
        );
        BouncyCastleA256KeyWrapCrypto keyWrap = new BouncyCastleA256KeyWrapCrypto();
        BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                new PublicHybridRecipientBuilder(deriver, keyWrap), gcm
        );
        PublicHybridUnsignedReceiver receiver = new PublicHybridUnsignedReceiver(
                deriver, keyWrap, gcm
        );
        byte[] data = {0, (byte) 0xff, (byte) 0xc3, 0x28};
        ProtocolPayload payload = new ProtocolPayload(
                "application/octet-stream", data, data.length
        );

        try (X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
             X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
             X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
             MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey()) {
            String wire = sender.send(new PublicHybridUnsignedSender.Request(
                    payload, MESSAGE_ID, TIMESTAMP, senderKey,
                    List.of(
                            new PublicHybridRecipientKeys(firstX.publicKey(), firstPq.publicKey()),
                            new PublicHybridRecipientKeys(secondX.publicKey(), secondPq.publicKey())
                    )
            )).wireJson();

            PublicHybridUnsignedReceiver.Result result = receiver.receive(
                    new PublicHybridUnsignedReceiver.Request(
                            wire,
                            kid -> Optional.of(senderKey.publicKey()),
                            List.of(new PublicHybridRecipientPrivateKeys(secondX, secondPq))
                    )
            );

            assertArrayEquals(data, result.payload().data());
            assertEquals(MESSAGE_ID, result.messageId());
            assertEquals(TIMESTAMP, result.timestamp());
            assertEquals(ProtocolAuthenticationStatus.UNSIGNED, result.authenticationStatus());
        }
    }

    @Test
    void strictProfileAndAadGatesWinBeforeRoutingOrSenderResolution() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            AtomicInteger resolverCalls = new AtomicInteger();
            SenderX25519PublicKeyResolver resolver = kid -> {
                resolverCalls.incrementAndGet();
                return Optional.of(fixture.senderKey.publicKey());
            };
            PublicHybridRecipientPrivateKeys explodingPair = new PublicHybridRecipientPrivateKeys(
                    new ExplodingX25519Handle(), fixture.unrelatedPq
            );

            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request("{", resolver, List.of(explodingPair))
            ));

            ObjectNode aadTampered = (ObjectNode) JSON.readTree(fixture.wire);
            aadTampered.put("aad", Base64Url.encode(new byte[]{1}));
            assertCode(ErrorCode.AAD_MISMATCH, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            aadTampered.toString(), resolver, List.of(explodingPair)
                    )
            ));

            assertCode(ErrorCode.UNSUPPORTED_ALGORITHM, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            withProtectedCty(fixture.wire, "wind+jws"),
                            resolver,
                            List.of(explodingPair)
                    )
            ));

            assertEquals(0, resolverCalls.get());
        }
    }

    @Test
    void unrelatedPairIsNotForMeWithoutSenderResolutionOrDecapsulation() {
        try (RealFixture fixture = new RealFixture()) {
            CountingMlKem768Crypto countingMlkem = new CountingMlKem768Crypto(fixture.mlkem);
            PublicHybridUnsignedReceiver receiver = new PublicHybridUnsignedReceiver(
                    new PublicHybridKekDeriver(
                            fixture.x25519, countingMlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm
            );
            AtomicInteger resolverCalls = new AtomicInteger();

            assertCode(ErrorCode.NOT_FOR_ME, () -> receiver.receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire,
                            kid -> {
                                resolverCalls.incrementAndGet();
                                return Optional.of(fixture.senderKey.publicKey());
                            },
                            List.of(fixture.unrelatedPair())
                    )
            ));

            assertEquals(0, resolverCalls.get());
            assertEquals(0, countingMlkem.decapsulateCalls);
            assertEquals(32, fixture.unrelatedX.publicKey().length);
            assertEquals(1184, fixture.unrelatedPq.publicKey().length);
        }
    }

    @Test
    void unknownWrongOrBrokenSenderResolutionUsesInvalidOrInternalErrors() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.empty(), List.of(fixture.secondPair())
                    )
            ));

            byte[] wrong = fixture.unrelatedX.publicKey();
            byte[] expected = wrong.clone();
            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.of(wrong), List.of(fixture.secondPair())
                    )
            ));
            assertArrayEquals(expected, wrong);

            assertCode(ErrorCode.INVALID_FIELD, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.of(new byte[31]),
                            List.of(fixture.secondPair())
                    )
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire, kid -> null, List.of(fixture.secondPair())
                    )
            ));
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            fixture.wire,
                            kid -> { throw new IllegalStateException("resolver unavailable"); },
                            List.of(fixture.secondPair())
                    )
            ));
            assertEquals(32, fixture.secondX.publicKey().length);
            assertEquals(1184, fixture.secondPq.publicKey().length);
        }
    }

    @Test
    void tamperedEkAndWrappedCekShareExactGenericKeyRecoveryError() throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            for (String field : List.of("ek", "encrypted_key")) {
                ProtocolException failure = assertGenericKeyRecovery(() -> fixture.receiver().receive(
                        fixture.request(tamperRecipientBytes(fixture.wire, 1, field))
                ));
                assertNull(failure.getCause());
                assertEquals(32, fixture.secondX.publicKey().length);
                assertEquals(1184, fixture.secondPq.publicKey().length);
            }
        }
    }

    @Test
    void lowOrderX25519MlkemFailureAndUnwrapFailureShareGenericErrorWithoutCause()
            throws Exception {
        try (RealFixture fixture = new RealFixture()) {
            byte[] lowOrder = new byte[32];
            assertGenericKeyRecovery(() -> fixture.receiver().receive(
                    new PublicHybridUnsignedReceiver.Request(
                            withSenderKid(fixture.wire, X25519KeyId.derive(lowOrder)),
                            kid -> Optional.of(lowOrder),
                            List.of(fixture.secondPair())
                    )
            ));

            CountingMlKem768Crypto failingMlkem = new CountingMlKem768Crypto(
                    fixture.mlkem, new CryptoOperationException("decapsulation failed"), null
            );
            PublicHybridUnsignedReceiver mlkemReceiver = new PublicHybridUnsignedReceiver(
                    new PublicHybridKekDeriver(
                            fixture.x25519, failingMlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm
            );
            assertGenericKeyRecovery(() -> mlkemReceiver.receive(fixture.request(fixture.wire)));
            assertEquals(1, failingMlkem.decapsulateCalls);

            RecordingKeyWrap failingUnwrap = RecordingKeyWrap.throwing(
                    fixture.keyWrap, new CryptoOperationException("unwrap failed")
            );
            PublicHybridUnsignedReceiver unwrapReceiver = new PublicHybridUnsignedReceiver(
                    fixture.deriver, failingUnwrap, fixture.gcm
            );
            assertGenericKeyRecovery(() -> unwrapReceiver.receive(fixture.request(fixture.wire)));
            assertAllZero(failingUnwrap.kek);
        }
    }

    @Test
    void routerInternalAndForeignOrClosedHandleFailuresRemainInternal() {
        try (RealFixture fixture = new RealFixture()) {
            ProtocolException routerFailure = assertFailure(
                    ErrorCode.INTERNAL_ERROR,
                    () -> fixture.receiver().receive(new PublicHybridUnsignedReceiver.Request(
                            fixture.wire,
                            kid -> Optional.of(fixture.senderKey.publicKey()),
                            List.of(new PublicHybridRecipientPrivateKeys(
                                    new ExplodingX25519Handle(), fixture.secondPq
                            ))
                    ))
            );
            assertEquals("failed to inspect local hybrid key handles", routerFailure.getMessage());
            assertInstanceOf(IllegalStateException.class, routerFailure.getCause());

            byte[] targetX = fixture.secondX.publicKey();
            X25519PrivateKeyHandle foreignX = new FixedX25519Handle(targetX);
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.requestWithPairs(List.of(
                            new PublicHybridRecipientPrivateKeys(foreignX, fixture.secondPq)
                    ))
            ));

            byte[] targetPq = fixture.secondPq.publicKey();
            MLKem768PrivateKeyHandle foreignPq = new FixedMlKem768Handle(targetPq);
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.requestWithPairs(List.of(
                            new PublicHybridRecipientPrivateKeys(fixture.secondX, foreignPq)
                    ))
            ));

            X25519PrivateKeyHandle closedX = fixture.x25519.generatePrivateKey();
            MLKem768PrivateKeyHandle closedPq = fixture.mlkem.generatePrivateKey();
            PublicHybridRecipientPrivateKeys closedPair = new PublicHybridRecipientPrivateKeys(
                    closedX, closedPq
            );
            closedX.close();
            assertCode(ErrorCode.INTERNAL_ERROR, () -> fixture.receiver().receive(
                    fixture.requestWithPairs(List.of(closedPair))
            ));
            closedPq.close();

            Arrays.fill(targetX, (byte) 0);
            Arrays.fill(targetPq, (byte) 0);
            assertEquals(32, foreignX.publicKey().length);
            assertEquals(1184, foreignPq.publicKey().length);
        }
    }

    @Test
    void providerOutputAndHkdfContractFailuresAreInternalAndCleared() {
        try (RealFixture fixture = new RealFixture()) {
            OutputX25519Crypto nullX = new OutputX25519Crypto(null);
            PublicHybridUnsignedReceiver nullXReceiver = new PublicHybridUnsignedReceiver(
                    new PublicHybridKekDeriver(
                            nullX, fixture.mlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm
            );
            assertCode(ErrorCode.INTERNAL_ERROR,
                    () -> nullXReceiver.receive(fixture.request(fixture.wire)));

            byte[] wrongPqSecret = filled(31, (byte) 0x44);
            CountingMlKem768Crypto wrongMlkem = new CountingMlKem768Crypto(
                    fixture.mlkem, null, wrongPqSecret
            );
            PublicHybridUnsignedReceiver wrongMlkemReceiver = new PublicHybridUnsignedReceiver(
                    new PublicHybridKekDeriver(
                            fixture.x25519, wrongMlkem, new BouncyCastleHkdfCrypto()
                    ),
                    fixture.keyWrap,
                    fixture.gcm
            );
            assertCode(ErrorCode.INTERNAL_ERROR,
                    () -> wrongMlkemReceiver.receive(fixture.request(fixture.wire)));
            assertTrue(allZero(wrongPqSecret));

            byte[] wrongKek = filled(31, (byte) 0x55);
            OutputHkdfCrypto wrongHkdf = new OutputHkdfCrypto(wrongKek);
            PublicHybridUnsignedReceiver wrongHkdfReceiver = new PublicHybridUnsignedReceiver(
                    new PublicHybridKekDeriver(fixture.x25519, fixture.mlkem, wrongHkdf),
                    fixture.keyWrap,
                    fixture.gcm
            );
            assertCode(ErrorCode.INTERNAL_ERROR,
                    () -> wrongHkdfReceiver.receive(fixture.request(fixture.wire)));
            assertTrue(allZero(wrongKek));
        }
    }

    @Test
    void unwrapNullWrongLengthAndRuntimeContractFailuresAreInternalAndClearOutputs() {
        try (RealFixture fixture = new RealFixture()) {
            List<RecordingKeyWrap> providers = List.of(
                    RecordingKeyWrap.nullOutput(fixture.keyWrap),
                    RecordingKeyWrap.output(fixture.keyWrap, filled(31, (byte) 0x61)),
                    RecordingKeyWrap.throwing(
                            fixture.keyWrap, new IllegalStateException("provider unavailable")
                    )
            );
            for (RecordingKeyWrap provider : providers) {
                PublicHybridUnsignedReceiver receiver = new PublicHybridUnsignedReceiver(
                        fixture.deriver, provider, fixture.gcm
                );
                assertCode(ErrorCode.INTERNAL_ERROR,
                        () -> receiver.receive(fixture.request(fixture.wire)));
                assertAllZero(provider.kek);
                if (provider.output != null) {
                    assertAllZero(provider.output);
                }
            }
        }
    }

    @Test
    void ivCiphertextAndTagTamperAreGcmFailuresAfterSuccessfulKeyRecovery() {
        try (RealFixture fixture = new RealFixture()) {
            for (String field : List.of("iv", "ciphertext", "tag")) {
                assertCode(ErrorCode.GCM_AUTH_FAILED, () -> fixture.receiver().receive(
                        fixture.request(tamperTopLevelBytes(fixture.wire, field))
                ));
                assertEquals(32, fixture.secondX.publicKey().length);
                assertEquals(1184, fixture.secondPq.publicKey().length);
            }
        }
    }

    @Test
    void authenticatedMalformedInnerAndWrongBindingPreserveStrictErrors() {
        try (RealFixture fixture = new RealFixture()) {
            assertCode(ErrorCode.MALFORMED_WIRE, () -> fixture.receiver().receive(
                    fixture.request(fixture.authenticatedWire(
                            "{".getBytes(StandardCharsets.UTF_8)
                    ))
            ));

            byte[] wrongBindingInner = new UnsignedInnerCodec().encode(
                    new UnsignedInnerCodec.Message(
                            MESSAGE_ID,
                            TIMESTAMP,
                            fixture.payload,
                            new OuterBinding.Hashes(new byte[32], new byte[32])
                    )
            );
            try {
                assertCode(ErrorCode.BINDING_FAILED, () -> fixture.receiver().receive(
                        fixture.request(fixture.authenticatedWire(wrongBindingInner))
                ));
            } finally {
                Arrays.fill(wrongBindingInner, (byte) 0);
            }
        }
    }

    @Test
    void successAndInnerFailureClearReceiverOwnedSecretsAndLeaveBorrowedHandlesOpen() {
        try (RealFixture fixture = new RealFixture()) {
            RecordingKeyWrap successKeyWrap = RecordingKeyWrap.delegate(fixture.keyWrap);
            RecordingGcm successGcm = RecordingGcm.delegate(fixture.gcm);
            PublicHybridUnsignedReceiver successReceiver = new PublicHybridUnsignedReceiver(
                    fixture.deriver, successKeyWrap, successGcm
            );

            PublicHybridUnsignedReceiver.Result result = successReceiver.receive(
                    fixture.request(fixture.wire)
            );
            assertArrayEquals(fixture.payload.data(), result.payload().data());
            assertAllZero(
                    successKeyWrap.kek,
                    successKeyWrap.output,
                    successGcm.key,
                    successGcm.aad,
                    successGcm.plaintext
            );

            String malformed = fixture.authenticatedWire("{".getBytes(StandardCharsets.UTF_8));
            RecordingKeyWrap failureKeyWrap = RecordingKeyWrap.delegate(fixture.keyWrap);
            RecordingGcm failureGcm = RecordingGcm.delegate(fixture.gcm);
            PublicHybridUnsignedReceiver failureReceiver = new PublicHybridUnsignedReceiver(
                    fixture.deriver, failureKeyWrap, failureGcm
            );
            assertCode(ErrorCode.MALFORMED_WIRE,
                    () -> failureReceiver.receive(fixture.request(malformed)));
            assertAllZero(
                    failureKeyWrap.kek,
                    failureKeyWrap.output,
                    failureGcm.key,
                    failureGcm.aad,
                    failureGcm.plaintext
            );
            assertEquals(32, fixture.secondX.publicKey().length);
            assertEquals(1184, fixture.secondPq.publicKey().length);
        }
    }

    @Test
    void gcmProviderFailureOrNullOutputClearsRecoveredKeyAndAad() {
        try (RealFixture fixture = new RealFixture()) {
            for (RecordingGcm gcm : List.of(
                    RecordingGcm.throwing(
                            fixture.gcm, new CryptoOperationException("GCM failed")
                    ),
                    RecordingGcm.nullOutput(fixture.gcm)
            )) {
                RecordingKeyWrap keyWrap = RecordingKeyWrap.delegate(fixture.keyWrap);
                PublicHybridUnsignedReceiver receiver = new PublicHybridUnsignedReceiver(
                        fixture.deriver, keyWrap, gcm
                );
                assertCode(ErrorCode.GCM_AUTH_FAILED,
                        () -> receiver.receive(fixture.request(fixture.wire)));
                assertAllZero(keyWrap.kek, keyWrap.output, gcm.key, gcm.aad);
            }
        }
    }

    @Test
    void requestSnapshotsPairsAllowsEmptyForNotForMeAndValidatesDependencies() {
        try (RealFixture fixture = new RealFixture()) {
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver(null, fixture.keyWrap, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver(fixture.deriver, null, fixture.gcm));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver(fixture.deriver, fixture.keyWrap, null));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver.Request(fixture.wire, null, List.of()));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver.Request(
                            fixture.wire, kid -> Optional.empty(), null
                    ));
            assertThrows(IllegalArgumentException.class,
                    () -> new PublicHybridUnsignedReceiver.Request(
                            fixture.wire,
                            kid -> Optional.empty(),
                            Arrays.asList((PublicHybridRecipientPrivateKeys) null)
                    ));
            assertThrows(IllegalArgumentException.class, () -> fixture.receiver().receive(null));

            ArrayList<PublicHybridRecipientPrivateKeys> callerPairs = new ArrayList<>();
            callerPairs.add(fixture.secondPair());
            PublicHybridUnsignedReceiver.Request snapshot = fixture.requestWithPairs(callerPairs);
            callerPairs.clear();
            assertArrayEquals(
                    fixture.payload.data(), fixture.receiver().receive(snapshot).payload().data()
            );
            assertEquals(1, snapshot.recipientPrivateKeys().size());

            assertCode(ErrorCode.NOT_FOR_ME, () -> fixture.receiver().receive(
                    fixture.requestWithPairs(List.of())
            ));
            PublicHybridUnsignedReceiver.Request nullWire = new PublicHybridUnsignedReceiver.Request(
                    null, kid -> Optional.empty(), List.of()
            );
            assertCode(ErrorCode.MALFORMED_WIRE,
                    () -> fixture.receiver().receive(nullWire));
        }
    }

    private static ProtocolException assertGenericKeyRecovery(Runnable operation) {
        ProtocolException failure = assertFailure(ErrorCode.KEY_UNWRAP_FAILED, operation);
        assertEquals("hybrid recipient key recovery failed", failure.getMessage());
        assertNull(failure.getCause());
        return failure;
    }

    private static void assertCode(ErrorCode expected, Runnable operation) {
        assertFailure(expected, operation);
    }

    private static ProtocolException assertFailure(ErrorCode expected, Runnable operation) {
        ProtocolException failure = assertThrows(ProtocolException.class, operation::run);
        assertEquals(expected, failure.errorCode());
        assertFalse(failure.errorCode() == ErrorCode.NOT_FOR_ME
                && expected != ErrorCode.NOT_FOR_ME);
        return failure;
    }

    private static String withProtectedCty(String wire, String cty) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            ObjectNode protectedNode = decodeProtected(root);
            protectedNode.put("cty", cty);
            root.put(
                    "protected",
                    Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode))
            );
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to replace protected cty", e);
        }
    }

    private static String withSenderKid(String wire, String x25519Kid) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            ObjectNode protectedNode = decodeProtected(root);
            ObjectNode kid = (ObjectNode) protectedNode.get("kid");
            kid.put("x25519", x25519Kid);
            root.put(
                    "protected",
                    Base64Url.encode(JcsCanonicalizer.canonicalize(protectedNode))
            );
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to replace sender kid", e);
        }
    }

    private static ObjectNode decodeProtected(ObjectNode root) throws Exception {
        byte[] bytes = Base64Url.decodeCanonical(
                root.get("protected").textValue(), "test.protected"
        );
        try {
            return (ObjectNode) JSON.readTree(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static String tamperRecipientBytes(String wire, int index, String field) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            ObjectNode target = (ObjectNode) root.withArray("recipients").get(index);
            byte[] value = Base64Url.decodeCanonical(
                    target.get(field).textValue(), "test." + field
            );
            value[0] ^= 1;
            target.put(field, Base64Url.encode(value));
            Arrays.fill(value, (byte) 0);
            root.put(
                    "aad",
                    Base64Url.encode(JcsCanonicalizer.canonicalize(root.get("recipients")))
            );
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to tamper recipient field", e);
        }
    }

    private static String tamperTopLevelBytes(String wire, String field) {
        try {
            ObjectNode root = (ObjectNode) JSON.readTree(wire);
            byte[] value = Base64Url.decodeCanonical(
                    root.get(field).textValue(), "test." + field
            );
            value[0] ^= 1;
            root.put(field, Base64Url.encode(value));
            Arrays.fill(value, (byte) 0);
            return root.toString();
        } catch (Exception e) {
            throw new AssertionError("failed to tamper top-level field", e);
        }
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
        int aggregate = 0;
        for (byte current : value) {
            aggregate |= current;
        }
        return aggregate == 0;
    }

    private static void assertAllZero(byte[]... values) {
        for (byte[] value : values) {
            assertNotNull(value);
            assertTrue(allZero(value), "receiver-owned provider array was not cleared");
        }
    }

    private static final class RealFixture implements AutoCloseable {
        private final BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        private final BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        private final BouncyCastleHkdfCrypto hkdf = new BouncyCastleHkdfCrypto();
        private final BouncyCastleA256KeyWrapCrypto keyWrap =
                new BouncyCastleA256KeyWrapCrypto();
        private final BouncyCastleA256GcmCrypto gcm = new BouncyCastleA256GcmCrypto();
        private final PublicHybridKekDeriver deriver = new PublicHybridKekDeriver(
                x25519, mlkem, hkdf
        );
        private final X25519PrivateKeyHandle senderKey = x25519.generatePrivateKey();
        private final X25519PrivateKeyHandle firstX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle firstPq = mlkem.generatePrivateKey();
        private final X25519PrivateKeyHandle secondX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle secondPq = mlkem.generatePrivateKey();
        private final X25519PrivateKeyHandle unrelatedX = x25519.generatePrivateKey();
        private final MLKem768PrivateKeyHandle unrelatedPq = mlkem.generatePrivateKey();
        private final ProtocolPayload payload = new ProtocolPayload(
                "application/octet-stream",
                new byte[]{0, (byte) 0xff, (byte) 0xc3, 0x28},
                4
        );
        private final String wire;

        private RealFixture() {
            PublicHybridUnsignedSender sender = new PublicHybridUnsignedSender(
                    new PublicHybridRecipientBuilder(deriver, keyWrap), gcm
            );
            wire = sender.send(new PublicHybridUnsignedSender.Request(
                    payload,
                    MESSAGE_ID,
                    TIMESTAMP,
                    senderKey,
                    List.of(
                            new PublicHybridRecipientKeys(firstX.publicKey(), firstPq.publicKey()),
                            new PublicHybridRecipientKeys(secondX.publicKey(), secondPq.publicKey())
                    )
            )).wireJson();
        }

        private PublicHybridUnsignedReceiver receiver() {
            return new PublicHybridUnsignedReceiver(deriver, keyWrap, gcm);
        }

        private PublicHybridRecipientPrivateKeys secondPair() {
            return new PublicHybridRecipientPrivateKeys(secondX, secondPq);
        }

        private PublicHybridRecipientPrivateKeys unrelatedPair() {
            return new PublicHybridRecipientPrivateKeys(unrelatedX, unrelatedPq);
        }

        private PublicHybridUnsignedReceiver.Request request(String candidateWire) {
            return new PublicHybridUnsignedReceiver.Request(
                    candidateWire,
                    kid -> Optional.of(senderKey.publicKey()),
                    List.of(secondPair())
            );
        }

        private PublicHybridUnsignedReceiver.Request requestWithPairs(
                List<PublicHybridRecipientPrivateKeys> pairs
        ) {
            return new PublicHybridUnsignedReceiver.Request(
                    wire,
                    kid -> Optional.of(senderKey.publicKey()),
                    pairs
            );
        }

        private String authenticatedWire(byte[] innerBytes) {
            WindLetter parsed = new JacksonOuterWireParser().parse(wire);
            PublicRecipient recipient = (PublicRecipient) parsed.recipients().get(1);
            byte[] senderPublic = senderKey.publicKey();
            byte[] ek = recipient.ek();
            byte[] kek = deriver.deriveForReceiver(secondX, senderPublic, secondPq, ek);
            byte[] cek = keyWrap.unwrap(kek, recipient.encryptedKey());
            byte[] aad = new OuterAad().gcmInput(parsed.protectedValue(), parsed.aad());
            try {
                AeadCiphertext encrypted = gcm.encrypt(
                        cek, parsed.iv(), aad, innerBytes
                );
                WindLetter malicious = new WindLetter(
                        parsed.protectedHeader(),
                        parsed.protectedValue(),
                        parsed.aad(),
                        parsed.recipients(),
                        parsed.iv(),
                        encrypted.ciphertext(),
                        encrypted.tag()
                );
                return new JacksonOuterWireWriter().write(malicious);
            } finally {
                Arrays.fill(senderPublic, (byte) 0);
                Arrays.fill(ek, (byte) 0);
                Arrays.fill(kek, (byte) 0);
                Arrays.fill(cek, (byte) 0);
                Arrays.fill(aad, (byte) 0);
            }
        }

        @Override
        public void close() {
            unrelatedPq.close();
            unrelatedX.close();
            secondPq.close();
            secondX.close();
            firstPq.close();
            firstX.close();
            senderKey.close();
        }
    }

    private static final class ExplodingX25519Handle implements X25519PrivateKeyHandle {
        @Override
        public byte[] publicKey() {
            throw new IllegalStateException("local handle unavailable");
        }

        @Override
        public void close() {
        }
    }

    private static final class FixedX25519Handle implements X25519PrivateKeyHandle {
        private final byte[] publicKey;

        private FixedX25519Handle(byte[] publicKey) {
            this.publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKey() {
            return publicKey.clone();
        }

        @Override
        public void close() {
        }
    }

    private static final class FixedMlKem768Handle implements MLKem768PrivateKeyHandle {
        private final byte[] publicKey;

        private FixedMlKem768Handle(byte[] publicKey) {
            this.publicKey = publicKey.clone();
        }

        @Override
        public byte[] publicKey() {
            return publicKey.clone();
        }

        @Override
        public void close() {
        }
    }

    private static final class OutputX25519Crypto implements X25519Crypto {
        private final byte[] output;

        private OutputX25519Crypto(byte[] output) {
            this.output = output;
        }

        @Override
        public X25519PrivateKeyHandle generatePrivateKey() {
            throw new UnsupportedOperationException();
        }

        @Override
        public X25519PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] deriveSharedSecret(
                X25519PrivateKeyHandle privateKey, byte[] peerPublicKey
        ) {
            return output;
        }
    }

    private static final class CountingMlKem768Crypto implements MLKem768Crypto {
        private final MLKem768Crypto delegate;
        private final RuntimeException failure;
        private final byte[] forcedOutput;
        private int decapsulateCalls;

        private CountingMlKem768Crypto(MLKem768Crypto delegate) {
            this(delegate, null, null);
        }

        private CountingMlKem768Crypto(
                MLKem768Crypto delegate,
                RuntimeException failure,
                byte[] forcedOutput
        ) {
            this.delegate = delegate;
            this.failure = failure;
            this.forcedOutput = forcedOutput;
        }

        @Override
        public MLKem768PrivateKeyHandle generatePrivateKey() {
            return delegate.generatePrivateKey();
        }

        @Override
        public MLKem768PrivateKeyHandle importPrivateKey(byte[] privateKey) {
            return delegate.importPrivateKey(privateKey);
        }

        @Override
        public MLKem768Encapsulation encapsulate(byte[] publicKey) {
            return delegate.encapsulate(publicKey);
        }

        @Override
        public byte[] decapsulate(
                MLKem768PrivateKeyHandle privateKey, byte[] ciphertext
        ) {
            decapsulateCalls++;
            if (failure != null) {
                throw failure;
            }
            if (forcedOutput != null) {
                return forcedOutput;
            }
            return delegate.decapsulate(privateKey, ciphertext);
        }
    }

    private static final class OutputHkdfCrypto implements HkdfCrypto {
        private final byte[] output;

        private OutputHkdfCrypto(byte[] output) {
            this.output = output;
        }

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
            return output;
        }
    }

    private static final class RecordingKeyWrap implements A256KeyWrapCrypto {
        private final A256KeyWrapCrypto delegate;
        private final boolean delegateUnwrap;
        private final RuntimeException failure;
        private final byte[] forcedOutput;
        private byte[] kek;
        private byte[] output;

        private RecordingKeyWrap(
                A256KeyWrapCrypto delegate,
                boolean delegateUnwrap,
                RuntimeException failure,
                byte[] forcedOutput
        ) {
            this.delegate = delegate;
            this.delegateUnwrap = delegateUnwrap;
            this.failure = failure;
            this.forcedOutput = forcedOutput;
        }

        private static RecordingKeyWrap delegate(A256KeyWrapCrypto delegate) {
            return new RecordingKeyWrap(delegate, true, null, null);
        }

        private static RecordingKeyWrap nullOutput(A256KeyWrapCrypto delegate) {
            return new RecordingKeyWrap(delegate, false, null, null);
        }

        private static RecordingKeyWrap output(
                A256KeyWrapCrypto delegate, byte[] output
        ) {
            return new RecordingKeyWrap(delegate, false, null, output);
        }

        private static RecordingKeyWrap throwing(
                A256KeyWrapCrypto delegate, RuntimeException failure
        ) {
            return new RecordingKeyWrap(delegate, false, failure, null);
        }

        @Override
        public byte[] wrap(byte[] kek, byte[] keyToWrap) {
            return delegate.wrap(kek, keyToWrap);
        }

        @Override
        public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
            this.kek = kek;
            if (failure != null) {
                throw failure;
            }
            output = delegateUnwrap
                    ? delegate.unwrap(kek, wrappedKey)
                    : forcedOutput;
            return output;
        }
    }

    private static final class RecordingGcm implements A256GcmCrypto {
        private final A256GcmCrypto delegate;
        private final RuntimeException failure;
        private final boolean returnNull;
        private byte[] key;
        private byte[] aad;
        private byte[] plaintext;

        private RecordingGcm(
                A256GcmCrypto delegate,
                RuntimeException failure,
                boolean returnNull
        ) {
            this.delegate = delegate;
            this.failure = failure;
            this.returnNull = returnNull;
        }

        private static RecordingGcm delegate(A256GcmCrypto delegate) {
            return new RecordingGcm(delegate, null, false);
        }

        private static RecordingGcm throwing(
                A256GcmCrypto delegate, RuntimeException failure
        ) {
            return new RecordingGcm(delegate, failure, false);
        }

        private static RecordingGcm nullOutput(A256GcmCrypto delegate) {
            return new RecordingGcm(delegate, null, true);
        }

        @Override
        public AeadCiphertext encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plaintext) {
            return delegate.encrypt(key, iv, aad, plaintext);
        }

        @Override
        public byte[] decrypt(
                byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag
        ) {
            this.key = key;
            this.aad = aad;
            if (failure != null) {
                throw failure;
            }
            if (returnNull) {
                return null;
            }
            plaintext = delegate.decrypt(key, iv, aad, ciphertext, tag);
            return plaintext;
        }
    }
}
