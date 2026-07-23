package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.routing.ObfuscationX25519CekRecovery;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/** Complete receiver flow for the obfuscation/X25519/unsigned profile. */
public final class ObfuscationX25519UnsignedReceiver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int CEK_LENGTH = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final ObfuscationX25519CekRecovery cekRecovery;
    private final A256GcmCrypto gcm;
    private final JacksonOuterWireParser parser = new JacksonOuterWireParser();
    private final OuterAad outerAad = new OuterAad();
    private final UnsignedInnerCodec innerCodec = new UnsignedInnerCodec();
    private final OuterBinding outerBinding = new OuterBinding();

    public ObfuscationX25519UnsignedReceiver(
            ObfuscationX25519CekRecovery cekRecovery,
            A256GcmCrypto gcm
    ) {
        if (cekRecovery == null) {
            throw new IllegalArgumentException("cekRecovery must not be null");
        }
        if (gcm == null) {
            throw new IllegalArgumentException("gcm must not be null");
        }
        this.cekRecovery = cekRecovery;
        this.gcm = gcm;
    }

    public Result receive(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] cek = null;
        byte[] gcmAad = null;
        byte[] decryptedInner = null;
        try {
            WindLetter letter = parser.parse(request.wireJson());
            Epk epk = requireProfile(letter);
            outerAad.verify(letter);

            try {
                cek = cekRecovery.recover(epk, letter.recipients(), request.recipientPrivateKeys());
            } catch (ProtocolException e) {
                throw e;
            } catch (RuntimeException e) {
                throw internal("failed to recover the obfuscation recipient key", e);
            }
            if (cek == null || cek.length != CEK_LENGTH) {
                throw internal("CEK recovery returned a non-32-byte key", null);
            }

            gcmAad = outerAad.gcmInput(letter.protectedValue(), letter.aad());
            try {
                decryptedInner = gcm.decrypt(
                        cek,
                        letter.iv(),
                        gcmAad,
                        letter.ciphertext(),
                        letter.tag()
                );
            } catch (RuntimeException e) {
                throw new ProtocolException(
                        ErrorCode.GCM_AUTH_FAILED,
                        "outer GCM authentication failed",
                        e
                );
            }
            if (decryptedInner == null) {
                throw new ProtocolException(
                        ErrorCode.GCM_AUTH_FAILED,
                        "GCM provider returned no plaintext"
                );
            }

            UnsignedInnerCodec.Message inner = innerCodec.decode(decryptedInner);
            outerBinding.verify(inner.binding(), letter.protectedHeader(), letter.recipients());
            return new Result(
                    inner.payload(),
                    inner.messageId(),
                    inner.timestamp(),
                    ProtocolAuthenticationStatus.UNSIGNED
            );
        } finally {
            clear(cek);
            clear(gcmAad);
            clear(decryptedInner);
        }
    }

    private static Epk requireProfile(WindLetter letter) {
        ProtectedHeader header = letter.protectedHeader();
        boolean profileMatches = "wind+jwe".equals(header.typ())
                && "wind+inner".equals(header.cty())
                && "1.0".equals(header.ver())
                && "obfuscation".equals(header.windMode())
                && "A256GCM".equals(header.enc())
                && "X25519".equals(header.keyAlg())
                && header.senderInfo() instanceof Epk;
        Epk epk = profileMatches ? (Epk) header.senderInfo() : null;
        byte[] epkX = null;
        try {
            if (epk != null) {
                epkX = epk.x();
                profileMatches = "OKP".equals(epk.kty())
                        && "X25519".equals(epk.crv())
                        && epkX.length == X25519_PUBLIC_KEY_LENGTH;
            }
            if (profileMatches) {
                for (RecipientEntry entry : letter.recipients()) {
                    if (!(entry instanceof ObfuscationRecipient recipient)
                            || recipient.ek() != null) {
                        profileMatches = false;
                        break;
                    }
                }
            }
        } finally {
            clear(epkX);
        }
        if (!profileMatches) {
            throw new ProtocolException(
                    ErrorCode.UNSUPPORTED_ALGORITHM,
                    "message does not use the obfuscation/X25519/unsigned profile"
            );
        }
        return epk;
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.INTERNAL_ERROR, message)
                : new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) return false;
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4 && uuid.variant() == 2 && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    public record Request(
            String wireJson,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        public Request {
            if (recipientPrivateKeys == null) {
                throw new IllegalArgumentException("recipientPrivateKeys must not be null");
            }
            recipientPrivateKeys = Collections.unmodifiableList(
                    new ArrayList<>(recipientPrivateKeys)
            );
        }
    }

    public record Result(
            ProtocolPayload payload,
            String messageId,
            long timestamp,
            ProtocolAuthenticationStatus authenticationStatus
    ) {
        public Result {
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException("messageId must be a canonical lowercase UUID v4");
            }
            if (timestamp < 0 || timestamp > MAX_SAFE_JSON_INTEGER) {
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (authenticationStatus == null) {
                throw new IllegalArgumentException("authenticationStatus must not be null");
            }
        }
    }
}
