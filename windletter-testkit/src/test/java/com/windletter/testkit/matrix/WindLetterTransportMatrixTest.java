package com.windletter.testkit.matrix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.windletter.api.WindLetterReceiver;
import com.windletter.api.WindLetterRuntime;
import com.windletter.api.WindLetterSender;
import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.DecryptStatus;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.VerificationPolicy;
import com.windletter.api.enums.VerificationStatus;
import com.windletter.api.enums.WindMode;
import com.windletter.api.model.DecryptRequest;
import com.windletter.api.model.DecryptResult;
import com.windletter.api.model.EncryptAndSignRequest;
import com.windletter.api.model.EncryptRequest;
import com.windletter.api.model.EncryptedMessage;
import com.windletter.api.model.Payload;
import com.windletter.api.model.SenderEncryptionIdentityRef;
import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolLimits;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.testkit.keys.InMemoryDemoKeyRepository;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class WindLetterTransportMatrixTest {

    private static final List<PayloadCase> PAYLOADS = List.of(
        new PayloadCase(
            "text",
            "text/plain;charset=UTF-8",
            "WindLetter 完整传输矩阵".getBytes(StandardCharsets.UTF_8)
        ),
        new PayloadCase(
            "binary",
            "application/octet-stream",
            new byte[] {0, (byte) 0xff, 7, 0, (byte) 0x80}
        )
    );

    @TestFactory
    Stream<DynamicTest> allProfilesAndArmorsRoundTripRealPayloads() {
        return Stream.of(WindMode.values()).flatMap(mode ->
            Stream.of(KeyAlgProfile.values()).flatMap(profile ->
                Stream.of(false, true).flatMap(signed ->
                    Stream.of(ArmorFormat.values()).flatMap(format ->
                        PAYLOADS.stream().map(payload -> DynamicTest.dynamicTest(
                            mode + "/" + profile + "/"
                                + (signed ? "signed" : "unsigned") + "/"
                                + format + "/" + payload.name(),
                            () -> roundTrip(mode, profile, signed, format, payload)
                        ))
                    )
                )
            )
        );
    }

    @TestFactory
    Stream<DynamicTest> allProfilesAndArmorsReturnNotForMeForUnrelatedKeys() {
        return Stream.of(WindMode.values()).flatMap(mode ->
            Stream.of(KeyAlgProfile.values()).flatMap(profile ->
                Stream.of(ArmorFormat.values()).map(format -> DynamicTest.dynamicTest(
                    mode + "/" + profile + "/" + format + "/not-for-me",
                    () -> notForMe(mode, profile, format)
                ))
            )
        );
    }

    @TestFactory
    Stream<DynamicTest> armoredProfilesRejectTruncationBeforeKeyAccess() {
        return Stream.of(WindMode.values()).flatMap(mode ->
            Stream.of(KeyAlgProfile.values()).flatMap(profile ->
                Stream.of(
                    ArmorFormat.BASE64_PEM,
                    ArmorFormat.WIND_BASE_1024F_V1,
                    ArmorFormat.BINARY
                ).map(format -> DynamicTest.dynamicTest(
                    mode + "/" + profile + "/" + format + "/truncated",
                    () -> rejectTruncatedBeforeKeys(mode, profile, format)
                ))
            )
        );
    }

    @TestFactory
    Stream<DynamicTest> armoredProfilesRejectSameLengthTamperBeforeKeyAccess() {
        return Stream.of(WindMode.values()).flatMap(mode ->
            Stream.of(KeyAlgProfile.values()).flatMap(profile ->
                Stream.of(
                    ArmorFormat.BASE64_PEM,
                    ArmorFormat.WIND_BASE_1024F_V1,
                    ArmorFormat.BINARY
                ).map(format -> DynamicTest.dynamicTest(
                    mode + "/" + profile + "/" + format + "/same-length-tamper",
                    () -> rejectSameLengthTamperBeforeKeys(mode, profile, format)
                ))
            )
        );
    }

    @Test
    void oversizedBinaryArmorIsRejectedBeforeKeyAccess() {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(KeyAlgProfile.X25519)) {
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(new DecryptRequest(
                null,
                null,
                new byte[ProtocolLimits.MAX_WIRE_UTF8_BYTES + 13],
                ArmorFormat.BINARY,
                keys.recipientIdentity(),
                VerificationPolicy.AUTO_BY_CTY
            ));

            assertGenericInvalid(result);
            assertEquals(0, keys.recipientLeaseOpens());
        }
    }

    @Test
    void unknownHeaderAndUnsupportedWindVersionFailBeforeKeyAccess() {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(KeyAlgProfile.X25519)) {
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            for (String armor : List.of(
                "not a Wind Letter armor",
                "-----風笺 起-----\n渢𩗍𩘥𬱶䫻凪A\n-----風笺 凪-----"
            )) {
                DecryptResult result = receiver.decrypt(new DecryptRequest(
                    null,
                    armor,
                    null,
                    null,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                ));
                assertGenericInvalid(result);
            }
            assertEquals(0, keys.recipientLeaseOpens());
        }
    }

    @Test
    void explicitTextFormatNeverFallsBackToAnotherCodec() {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(KeyAlgProfile.X25519)) {
            EncryptedMessage encrypted = encryptUnsigned(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.BASE64_PEM,
                keys
            );
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(new DecryptRequest(
                null,
                encrypted.armor(),
                null,
                ArmorFormat.WIND_BASE_1024F_V1,
                keys.recipientIdentity(),
                VerificationPolicy.AUTO_BY_CTY
            ));

            assertGenericInvalid(result);
            assertEquals(0, keys.recipientLeaseOpens());
        }
    }

    private static void roundTrip(
        WindMode mode,
        KeyAlgProfile profile,
        boolean signed,
        ArmorFormat armorFormat,
        PayloadCase payloadCase
    ) {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(profile)) {
            WindLetterSender sender = WindLetterRuntime.sender(keys, keys, keys);
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            Payload payload = new Payload(
                payloadCase.contentType(),
                payloadCase.data(),
                payloadCase.data().length
            );
            SenderEncryptionIdentityRef senderEncryption = mode == WindMode.PUBLIC
                ? keys.senderEncryptionIdentity()
                : null;

            EncryptedMessage encrypted = signed
                ? sender.encryptAndSign(new EncryptAndSignRequest(
                    mode,
                    profile,
                    armorFormat,
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption,
                    keys.signingIdentity()
                ))
                : sender.encrypt(new EncryptRequest(
                    mode,
                    profile,
                    armorFormat,
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption
                ));

            assertRepresentation(encrypted, armorFormat);
            var parsed = new JacksonOuterWireParser().parse(encrypted.wireJson());
            assertEquals(mode == WindMode.PUBLIC ? 2 : 8, parsed.recipients().size());

            DecryptResult result = receiver.decrypt(decryptRequest(encrypted, keys));
            assertEquals(DecryptStatus.SUCCESS, result.status());
            assertEquals(payload.contentType(), result.payload().contentType());
            assertArrayEquals(payload.data(), result.payload().data());
            assertEquals(payload.originalSize(), result.payload().originalSize());
            assertEquals(
                signed ? VerificationStatus.SIGNED_VALID : VerificationStatus.UNSIGNED,
                result.verificationStatus()
            );
            if (signed) {
                assertEquals(keys.trustedSender(), result.senderIdentity());
            } else {
                assertNull(result.senderIdentity());
            }
            assertEquals(1, keys.recipientLeaseOpens());
        }
    }

    private static void notForMe(
        WindMode mode,
        KeyAlgProfile profile,
        ArmorFormat armorFormat
    ) {
        try (
            InMemoryDemoKeyRepository senderKeys = new InMemoryDemoKeyRepository(profile);
            InMemoryDemoKeyRepository unrelatedKeys = new InMemoryDemoKeyRepository(profile)
        ) {
            EncryptedMessage encrypted = encryptUnsigned(mode, profile, armorFormat, senderKeys);
            WindLetterReceiver receiver = WindLetterRuntime.receiver(
                unrelatedKeys,
                senderKeys,
                senderKeys
            );
            DecryptResult result = receiver.decrypt(decryptRequest(encrypted, unrelatedKeys));

            assertEquals(DecryptStatus.NOT_FOR_ME, result.status());
            assertEquals(ErrorCode.NOT_FOR_ME, result.errorCode());
            assertEquals(VerificationStatus.NOT_APPLICABLE, result.verificationStatus());
            assertNull(result.payload());
            assertEquals(1, unrelatedKeys.recipientLeaseOpens());
        }
    }

    private static void rejectTruncatedBeforeKeys(
        WindMode mode,
        KeyAlgProfile profile,
        ArmorFormat armorFormat
    ) {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(profile)) {
            EncryptedMessage encrypted = encryptUnsigned(mode, profile, armorFormat, keys);
            DecryptRequest truncated = switch (armorFormat) {
                case BASE64_PEM -> new DecryptRequest(
                    null,
                    encrypted.armor().substring(0, encrypted.armor().length() - 1),
                    null,
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case WIND_BASE_1024F_V1 -> new DecryptRequest(
                    null,
                    dropLastWindBodyCodePoint(encrypted.armor()),
                    null,
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case BINARY -> new DecryptRequest(
                    null,
                    null,
                    Arrays.copyOf(encrypted.armorBytes(), encrypted.armorBytes().length - 1),
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case NONE -> throw new AssertionError("NONE is not an armored format");
            };

            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(truncated);
            assertGenericInvalid(result);
            assertEquals(0, keys.recipientLeaseOpens());
        }
    }

    private static void rejectSameLengthTamperBeforeKeys(
        WindMode mode,
        KeyAlgProfile profile,
        ArmorFormat armorFormat
    ) {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(profile)) {
            EncryptedMessage encrypted = encryptUnsigned(mode, profile, armorFormat, keys);
            DecryptRequest tampered = switch (armorFormat) {
                case BASE64_PEM -> new DecryptRequest(
                    null,
                    tamperBase64PemFrame(encrypted.armor()),
                    null,
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case WIND_BASE_1024F_V1 -> new DecryptRequest(
                    null,
                    replaceFirstWindCodePoint(encrypted.armor()),
                    null,
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case BINARY -> new DecryptRequest(
                    null,
                    null,
                    tamperBinaryFrame(encrypted.armorBytes()),
                    armorFormat,
                    keys.recipientIdentity(),
                    VerificationPolicy.AUTO_BY_CTY
                );
                case NONE -> throw new AssertionError("NONE is not an armored format");
            };

            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(tampered);
            assertGenericInvalid(result);
            assertEquals(0, keys.recipientLeaseOpens());
        }
    }

    private static EncryptedMessage encryptUnsigned(
        WindMode mode,
        KeyAlgProfile profile,
        ArmorFormat armorFormat,
        InMemoryDemoKeyRepository keys
    ) {
        WindLetterSender sender = WindLetterRuntime.sender(keys, keys, keys);
        return sender.encrypt(new EncryptRequest(
            mode,
            profile,
            armorFormat,
            new Payload("application/octet-stream", new byte[] {0, 1, 2}, 3),
            keys.recipientRefs(),
            Map.of(),
            mode == WindMode.PUBLIC ? keys.senderEncryptionIdentity() : null
        ));
    }

    private static DecryptRequest decryptRequest(
        EncryptedMessage encrypted,
        InMemoryDemoKeyRepository keys
    ) {
        return new DecryptRequest(
            encrypted.armorFormat() == ArmorFormat.NONE ? encrypted.wireJson() : null,
            encrypted.armor(),
            encrypted.armorBytes(),
            encrypted.armorFormat(),
            keys.recipientIdentity(),
            VerificationPolicy.AUTO_BY_CTY
        );
    }

    private static void assertRepresentation(
        EncryptedMessage encrypted,
        ArmorFormat format
    ) {
        assertNotNull(encrypted.wireJson());
        switch (format) {
            case NONE -> {
                assertNull(encrypted.armor());
                assertNull(encrypted.armorBytes());
            }
            case BASE64_PEM, WIND_BASE_1024F_V1 -> {
                assertNotNull(encrypted.armor());
                assertTrue(encrypted.armor().codePointCount(0, encrypted.armor().length()) > 0);
                assertNull(encrypted.armorBytes());
            }
            case BINARY -> {
                assertNull(encrypted.armor());
                assertTrue(encrypted.armorBytes().length > 12);
            }
        }
    }

    private static String dropLastWindBodyCodePoint(String armor) {
        int footerStart = armor.lastIndexOf("\n-----風笺 凪-----");
        int lastBodyStart = armor.offsetByCodePoints(footerStart, -1);
        return armor.substring(0, lastBodyStart) + armor.substring(footerStart);
    }

    private static byte[] tamperBinaryFrame(byte[] frame) {
        byte[] tampered = frame.clone();
        tampered[8] ^= 1;
        return tampered;
    }

    private static String tamperBase64PemFrame(String armor) {
        int headerEnd = armor.indexOf('\n');
        int footerStart = armor.lastIndexOf("\n-----END WIND LETTER-----");
        String body = armor.substring(headerEnd + 1, footerStart).replace("\n", "");
        byte[] frame = java.util.Base64.getDecoder().decode(body);
        frame[8] ^= 1;
        String encoded = java.util.Base64.getEncoder().encodeToString(frame);
        StringBuilder pem = new StringBuilder("-----BEGIN WIND LETTER-----\n");
        for (int offset = 0; offset < encoded.length(); offset += 64) {
            pem.append(encoded, offset, Math.min(offset + 64, encoded.length())).append('\n');
        }
        return pem.append("-----END WIND LETTER-----").toString();
    }

    private static String replaceFirstWindCodePoint(String armor) {
        int bodyStart = armor.indexOf('凪', armor.indexOf('\n') + 1) + 1;
        int first = armor.codePointAt(bodyStart);
        int replacement = first == 0x295ab ? 0x2cc76 : 0x295ab;
        return armor.substring(0, bodyStart)
            + new String(Character.toChars(replacement))
            + armor.substring(bodyStart + Character.charCount(first));
    }

    private static void assertGenericInvalid(DecryptResult result) {
        assertEquals(DecryptStatus.INVALID_MESSAGE, result.status());
        assertEquals(ErrorCode.INVALID_MESSAGE, result.errorCode());
        assertEquals(VerificationStatus.FAILED, result.verificationStatus());
        assertNull(result.payload());
        assertNull(result.senderIdentity());
    }

    private record PayloadCase(String name, String contentType, byte[] data) {
        private PayloadCase {
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }
    }
}
