package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.routing.ObfuscationX25519CekRecovery;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.Epk;
import com.windletter.protocol.wire.ObfuscationRecipient;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/** Complete receiver flow for the obfuscation/X25519/signed profile. */
public final class ObfuscationX25519SignedReceiver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int CEK_LENGTH = 32;
    private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
    private static final Pattern CANONICAL_UUID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    );

    private final ObfuscationX25519CekRecovery cekRecovery;
    private final A256GcmCrypto gcm;
    private final Ed25519Crypto ed25519;
    private final JacksonOuterWireParser parser = new JacksonOuterWireParser();
    private final OuterAad outerAad = new OuterAad();
    private final SignedInnerCodec innerCodec = new SignedInnerCodec();
    private final OuterBinding outerBinding = new OuterBinding();

    public ObfuscationX25519SignedReceiver(
            ObfuscationX25519CekRecovery cekRecovery,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    ) {
        if (cekRecovery == null) {
            throw new IllegalArgumentException("cekRecovery must not be null");
        }
        if (gcm == null) {
            throw new IllegalArgumentException("gcm must not be null");
        }
        if (ed25519 == null) {
            throw new IllegalArgumentException("ed25519 must not be null");
        }
        this.cekRecovery = cekRecovery;
        this.gcm = gcm;
        this.ed25519 = ed25519;
    }

    public Result receive(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] cek = null;
        byte[] gcmAad = null;
        byte[] decryptedInner = null;
        byte[] signingPublicKey = null;
        byte[] signingInput = null;
        byte[] signature = null;
        try {
            WindLetter letter = parser.parse(request.wireJson());
            Epk epk = requireProfile(letter);
            outerAad.verify(letter);

            try {
                cek = cekRecovery.recover(
                        epk, letter.recipients(), request.recipientPrivateKeys()
                );
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

            try (SignedInnerCodec.Decoded decoded = innerCodec.decode(decryptedInner)) {
                SignedInnerCodec.Message inner = decoded.message();
                outerBinding.verify(
                        inner.binding(), letter.protectedHeader(), letter.recipients()
                );

                TrustedEd25519Key trustedKey = resolveSigningKey(
                        request.senderSigningKeys(), inner.signingKid()
                );
                if (!inner.signingKid().equals(trustedKey.signingKid())) {
                    throw internal(
                            "trusted signing-key record does not match requested kid", null
                    );
                }

                signingPublicKey = trustedKey.publicKey();
                String actualKid;
                try {
                    actualKid = Ed25519KeyId.derive(signingPublicKey);
                } catch (RuntimeException e) {
                    throw internal(
                            "trusted Ed25519 key record could not be validated", e
                    );
                }
                if (!inner.signingKid().equals(actualKid)) {
                    throw internal(
                            "trusted Ed25519 public key does not match requested kid", null
                    );
                }

                signingInput = decoded.signingInput();
                signature = decoded.signature();
                boolean verified;
                try {
                    verified = ed25519.verify(
                            signingPublicKey, signingInput, signature
                    );
                } catch (RuntimeException e) {
                    throw internal("Ed25519 verification provider failed", e);
                }
                if (!verified) {
                    throw signatureInvalid("Ed25519 signature is invalid");
                }

                return new Result(
                        inner.payload(),
                        inner.messageId(),
                        inner.timestamp(),
                        ProtocolAuthenticationStatus.SIGNED_VALID,
                        new ProtocolSenderIdentity(
                                trustedKey.identityId(), trustedKey.signingKid()
                        )
                );
            }
        } finally {
            clear(cek);
            clear(gcmAad);
            clear(decryptedInner);
            clear(signingPublicKey);
            clear(signingInput);
            clear(signature);
        }
    }

    private static TrustedEd25519Key resolveSigningKey(
            Ed25519VerificationKeyResolver resolver,
            String expectedKid
    ) {
        Optional<TrustedEd25519Key> resolved;
        try {
            resolved = resolver.resolve(expectedKid);
        } catch (RuntimeException e) {
            throw internal("sender signing-key resolver failed", e);
        }
        if (resolved == null) {
            throw internal("sender signing-key resolver returned null", null);
        }
        if (resolved.isEmpty()) {
            throw signatureInvalid("sender Ed25519 signing key is unknown");
        }
        return resolved.get();
    }

    private static Epk requireProfile(WindLetter letter) {
        ProtectedHeader header = letter.protectedHeader();
        boolean profileMatches = "wind+jwe".equals(header.typ())
                && "wind+jws".equals(header.cty())
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
                    if (!(entry instanceof ObfuscationRecipient recipient)) {
                        profileMatches = false;
                        break;
                    }
                    byte[] ek = recipient.ek();
                    try {
                        if (ek != null) {
                            profileMatches = false;
                            break;
                        }
                    } finally {
                        clear(ek);
                    }
                }
            }
        } finally {
            clear(epkX);
        }
        if (!profileMatches) {
            throw new ProtocolException(
                    ErrorCode.UNSUPPORTED_ALGORITHM,
                    "message does not use the obfuscation/X25519/signed profile"
            );
        }
        return epk;
    }

    private static ProtocolException signatureInvalid(String message) {
        return new ProtocolException(ErrorCode.SIGNATURE_INVALID, message);
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.INTERNAL_ERROR, message)
                : new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static boolean validMessageId(String messageId) {
        if (messageId == null || !CANONICAL_UUID.matcher(messageId).matches()) {
            return false;
        }
        try {
            UUID uuid = UUID.fromString(messageId);
            return uuid.version() == 4 && uuid.variant() == 2
                    && uuid.toString().equals(messageId);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    public record Request(
            String wireJson,
            Ed25519VerificationKeyResolver senderSigningKeys,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        public Request {
            if (senderSigningKeys == null) {
                throw new IllegalArgumentException("senderSigningKeys must not be null");
            }
            if (recipientPrivateKeys == null) {
                throw new IllegalArgumentException(
                        "recipientPrivateKeys must not be null"
                );
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
            ProtocolAuthenticationStatus authenticationStatus,
            ProtocolSenderIdentity authenticatedSender
    ) {
        public Result {
            if (payload == null) {
                throw new IllegalArgumentException("payload must not be null");
            }
            if (!validMessageId(messageId)) {
                throw new IllegalArgumentException(
                        "messageId must be a canonical lowercase UUID v4"
                );
            }
            if (timestamp < 0 || timestamp > MAX_SAFE_JSON_INTEGER) {
                throw new IllegalArgumentException("timestamp is outside the supported range");
            }
            if (authenticationStatus != ProtocolAuthenticationStatus.SIGNED_VALID) {
                throw new IllegalArgumentException(
                        "signed receiver result must be SIGNED_VALID"
                );
            }
            if (authenticatedSender == null) {
                throw new IllegalArgumentException(
                        "authenticatedSender must not be null"
                );
            }
        }
    }
}
