package com.windletter.testkit.demo;

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
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.testkit.keys.InMemoryDemoKeyRepository;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Runnable end-to-end WindLetter v1.0 demonstration. */
public final class WindLetterDemo {

    private static final byte[] PAYLOAD =
        "WindLetter v1.0 真实收发演示 🌬️".getBytes(StandardCharsets.UTF_8);

    private static final List<DemoCase> SUCCESS_CASES = List.of(
        new DemoCase(
            WindMode.PUBLIC,
            KeyAlgProfile.X25519,
            false,
            ArmorFormat.BASE64URL
        ),
        new DemoCase(
            WindMode.PUBLIC,
            KeyAlgProfile.X25519_ML_KEM_768,
            true,
            ArmorFormat.WIND_BASE_1024F_V1
        ),
        new DemoCase(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519,
            true,
            ArmorFormat.BINARY
        ),
        new DemoCase(
            WindMode.OBFUSCATION,
            KeyAlgProfile.X25519_ML_KEM_768,
            false,
            ArmorFormat.WIND_BASE_1024F_V1
        )
    );

    private WindLetterDemo() {
    }

    public static void main(String[] args) {
        run(System.out);
    }

    static void run(PrintStream output) {
        output.println("WindLetter v1.0 Demo");
        int successes = 0;
        for (DemoCase demoCase : SUCCESS_CASES) {
            runSuccess(output, demoCase);
            successes++;
        }
        runNotForMe(output);
        runInvalidMessage(output);
        output.println("DEMO_OK successes=" + successes);
    }

    private static void runSuccess(PrintStream output, DemoCase demoCase) {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(demoCase.profile())) {
            WindLetterSender sender = WindLetterRuntime.sender(keys, keys, keys);
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            Payload payload = new Payload("text/plain;charset=UTF-8", PAYLOAD, PAYLOAD.length);
            SenderEncryptionIdentityRef senderEncryption = demoCase.mode() == WindMode.PUBLIC
                ? keys.senderEncryptionIdentity()
                : null;
            EncryptedMessage encrypted = demoCase.signed()
                ? sender.encryptAndSign(new EncryptAndSignRequest(
                    demoCase.mode(),
                    demoCase.profile(),
                    demoCase.armorFormat(),
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption,
                    keys.signingIdentity()
                ))
                : sender.encrypt(new EncryptRequest(
                    demoCase.mode(),
                    demoCase.profile(),
                    demoCase.armorFormat(),
                    payload,
                    keys.recipientRefs(),
                    Map.of(),
                    senderEncryption
                ));

            int recipientSlots = new JacksonOuterWireParser()
                .parse(encrypted.wireJson())
                .recipients()
                .size();
            DecryptResult result = receiver.decrypt(decryptRequest(encrypted, keys));
            require(result.status() == DecryptStatus.SUCCESS, "success scenario did not decrypt");
            require(result.payload() != null, "success scenario returned no payload");
            require(
                java.util.Arrays.equals(PAYLOAD, result.payload().data()),
                "success scenario changed payload bytes"
            );
            VerificationStatus expectedAuthentication = demoCase.signed()
                ? VerificationStatus.SIGNED_VALID
                : VerificationStatus.UNSIGNED;
            require(
                result.verificationStatus() == expectedAuthentication,
                "success scenario returned an unexpected authentication result"
            );

            output.printf(
                Locale.ROOT,
                "SUCCESS profile=%s/%s/%s armor=%s recipients=%d wireUtf8Bytes=%d %s status=%s auth=%s payloadBytes=%d%n",
                demoCase.mode().name().toLowerCase(Locale.ROOT),
                demoCase.profile(),
                demoCase.signed() ? "signed" : "unsigned",
                demoCase.armorFormat(),
                recipientSlots,
                encrypted.wireJson().getBytes(StandardCharsets.UTF_8).length,
                transportSize(encrypted),
                result.status(),
                result.verificationStatus(),
                result.payload().data().length
            );
        }
    }

    private static void runNotForMe(PrintStream output) {
        try (
            InMemoryDemoKeyRepository senderKeys = new InMemoryDemoKeyRepository(
                KeyAlgProfile.X25519
            );
            InMemoryDemoKeyRepository unrelatedKeys = new InMemoryDemoKeyRepository(
                KeyAlgProfile.X25519
            )
        ) {
            EncryptedMessage encrypted = encryptUnsigned(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.BASE64URL,
                senderKeys
            );
            WindLetterReceiver receiver = WindLetterRuntime.receiver(
                unrelatedKeys,
                senderKeys,
                senderKeys
            );
            DecryptResult result = receiver.decrypt(decryptRequest(encrypted, unrelatedKeys));
            require(result.status() == DecryptStatus.NOT_FOR_ME, "NOT_FOR_ME scenario failed");
            require(result.errorCode() == ErrorCode.NOT_FOR_ME, "NOT_FOR_ME error was not stable");
            output.printf(
                "NOT_FOR_ME status=%s error=%s%n",
                result.status(),
                result.errorCode()
            );
        }
    }

    private static void runInvalidMessage(PrintStream output) {
        try (InMemoryDemoKeyRepository keys = new InMemoryDemoKeyRepository(KeyAlgProfile.X25519)) {
            EncryptedMessage encrypted = encryptUnsigned(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.WIND_BASE_1024F_V1,
                keys
            );
            String armor = encrypted.armor();
            int codePointCount = armor.codePointCount(0, armor.length());
            String truncated = armor.substring(
                0,
                armor.offsetByCodePoints(0, codePointCount - 1)
            );
            WindLetterReceiver receiver = WindLetterRuntime.receiver(keys, keys, keys);
            DecryptResult result = receiver.decrypt(new DecryptRequest(
                null,
                truncated,
                null,
                ArmorFormat.WIND_BASE_1024F_V1,
                keys.recipientIdentity(),
                VerificationPolicy.AUTO_BY_CTY
            ));
            require(
                result.status() == DecryptStatus.INVALID_MESSAGE,
                "INVALID_MESSAGE scenario failed"
            );
            require(
                result.errorCode() == ErrorCode.INVALID_MESSAGE,
                "INVALID_MESSAGE error was not stable"
            );
            require(
                keys.recipientLeaseOpens() == 0,
                "invalid armor reached the private-key store"
            );
            output.printf(
                "INVALID_MESSAGE status=%s error=%s keyLeases=%d%n",
                result.status(),
                result.errorCode(),
                keys.recipientLeaseOpens()
            );
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
            new Payload("text/plain;charset=UTF-8", PAYLOAD, PAYLOAD.length),
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

    private static String transportSize(EncryptedMessage encrypted) {
        return switch (encrypted.armorFormat()) {
            case NONE -> "rawWire=true";
            case BINARY -> "armorBytes=" + encrypted.armorBytes().length;
            case BASE64URL, WIND_BASE_1024F_V1 -> {
                String armor = encrypted.armor();
                int codePoints = armor.codePointCount(0, armor.length());
                yield "armorCodePoints=" + codePoints + " armorUtf16Units=" + armor.length();
            }
        };
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private record DemoCase(
        WindMode mode,
        KeyAlgProfile profile,
        boolean signed,
        ArmorFormat armorFormat
    ) {
    }
}
