package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.Ed25519Crypto;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.SignedInnerCodec;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.routing.PublicKidRouter;
import com.windletter.protocol.signature.Ed25519VerificationKeyResolver;
import com.windletter.protocol.signature.TrustedEd25519Key;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Complete receiver flow for the public/X25519/signed profile. */
public final class PublicX25519SignedReceiver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int CEK_LENGTH = 32;

    private final PublicX25519KekDeriver kekDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final A256GcmCrypto gcm;
    private final Ed25519Crypto ed25519;
    private final JacksonOuterWireParser parser = new JacksonOuterWireParser();
    private final OuterAad outerAad = new OuterAad();
    private final PublicKidRouter router = new PublicKidRouter();
    private final SignedInnerCodec innerCodec = new SignedInnerCodec();
    private final OuterBinding outerBinding = new OuterBinding();

    public PublicX25519SignedReceiver(
            PublicX25519KekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap,
            A256GcmCrypto gcm,
            Ed25519Crypto ed25519
    ) {
        if (kekDeriver == null) {
            throw new IllegalArgumentException("kekDeriver must not be null");
        }
        if (keyWrap == null) {
            throw new IllegalArgumentException("keyWrap must not be null");
        }
        if (gcm == null) {
            throw new IllegalArgumentException("gcm must not be null");
        }
        if (ed25519 == null) {
            throw new IllegalArgumentException("ed25519 must not be null");
        }
        this.kekDeriver = kekDeriver;
        this.keyWrap = keyWrap;
        this.gcm = gcm;
        this.ed25519 = ed25519;
    }

    public Result receive(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] senderEncryptionPublicKey = null;
        byte[] kek = null;
        byte[] cek = null;
        byte[] gcmAad = null;
        byte[] decryptedInner = null;
        byte[] signingPublicKey = null;
        byte[] signingInput = null;
        byte[] signature = null;
        try {
            WindLetter letter = parser.parse(request.wireJson());
            requireSignedProfile(letter);
            outerAad.verify(letter);

            PublicKidRouter.Match match;
            try {
                match = router.route(letter.recipients(), request.recipientPrivateKeys());
            } catch (ProtocolException e) {
                throw e;
            } catch (IllegalArgumentException | IllegalStateException e) {
                throw internal("failed to inspect local X25519 key handles", e);
            }

            SenderKid senderKid = (SenderKid) letter.protectedHeader().senderInfo();
            senderEncryptionPublicKey = resolveSenderEncryptionPublicKey(
                    request.senderEncryptionKeys(), senderKid.x25519()
            );

            try {
                kek = kekDeriver.derive(match.privateKey(), senderEncryptionPublicKey);
            } catch (CryptoOperationException e) {
                throw keyUnwrap("X25519 shared-secret derivation failed", e);
            } catch (IllegalArgumentException | IllegalStateException e) {
                throw internal("local X25519 key handle could not be used", e);
            }

            try {
                cek = keyWrap.unwrap(kek, match.recipient().encryptedKey());
            } catch (RuntimeException e) {
                throw keyUnwrap("CEK unwrap failed", e);
            }
            if (cek == null || cek.length != CEK_LENGTH) {
                throw keyUnwrap("key-wrap provider returned a non-32-byte CEK", null);
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
                throw new ProtocolException(ErrorCode.GCM_AUTH_FAILED, "outer GCM authentication failed", e);
            }
            if (decryptedInner == null) {
                throw new ProtocolException(
                        ErrorCode.GCM_AUTH_FAILED,
                        "GCM provider returned no plaintext"
                );
            }

            try (SignedInnerCodec.Decoded decoded = innerCodec.decode(decryptedInner)) {
                SignedInnerCodec.Message inner = decoded.message();
                outerBinding.verify(inner.binding(), letter.protectedHeader(), letter.recipients());

                TrustedEd25519Key trustedKey = resolveSigningKey(
                        request.senderSigningKeys(), inner.signingKid()
                );
                if (!inner.signingKid().equals(trustedKey.signingKid())) {
                    throw internal("trusted signing-key record does not match requested kid", null);
                }
                signingPublicKey = trustedKey.publicKey();
                String derivedSigningKid;
                try {
                    derivedSigningKid = Ed25519KeyId.derive(signingPublicKey);
                } catch (RuntimeException e) {
                    throw internal("trusted Ed25519 key record could not be validated", e);
                }
                if (!inner.signingKid().equals(derivedSigningKid)) {
                    throw internal("trusted Ed25519 public key does not match requested kid", null);
                }

                signingInput = decoded.signingInput();
                signature = decoded.signature();
                boolean verified;
                try {
                    verified = ed25519.verify(signingPublicKey, signingInput, signature);
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
                        new ProtocolSenderIdentity(trustedKey.identityId(), trustedKey.signingKid())
                );
            }
        } finally {
            clear(senderEncryptionPublicKey);
            clear(kek);
            clear(cek);
            clear(gcmAad);
            clear(decryptedInner);
            clear(signingPublicKey);
            clear(signingInput);
            clear(signature);
        }
    }

    private static byte[] resolveSenderEncryptionPublicKey(
            SenderX25519PublicKeyResolver resolver,
            String expectedKid
    ) {
        Optional<byte[]> resolved;
        try {
            resolved = resolver.resolve(expectedKid);
        } catch (RuntimeException e) {
            throw internal("sender encryption public-key resolver failed", e);
        }
        if (resolved == null) {
            throw internal("sender encryption public-key resolver returned null", null);
        }
        if (resolved.isEmpty()) {
            throw invalid("sender X25519 public key is unknown");
        }

        byte[] callerValue = resolved.get();
        if (callerValue == null || callerValue.length != X25519_PUBLIC_KEY_LENGTH) {
            throw invalid("resolved sender X25519 public key must contain exactly 32 bytes");
        }
        byte[] snapshot = callerValue.clone();
        if (!expectedKid.equals(X25519KeyId.derive(snapshot))) {
            clear(snapshot);
            throw invalid("resolved sender X25519 public key does not match protected kid");
        }
        return snapshot;
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

    private static void requireSignedProfile(WindLetter letter) {
        ProtectedHeader header = letter.protectedHeader();
        boolean profileMatches = "wind+jwe".equals(header.typ())
                && "wind+jws".equals(header.cty())
                && "1.0".equals(header.ver())
                && "public".equals(header.windMode())
                && "A256GCM".equals(header.enc())
                && "X25519".equals(header.keyAlg())
                && header.senderInfo() instanceof SenderKid;
        if (profileMatches) {
            for (RecipientEntry entry : letter.recipients()) {
                if (!(entry instanceof PublicRecipient recipient)
                        || recipient.kid().mlkem768() != null
                        || recipient.ek() != null) {
                    profileMatches = false;
                    break;
                }
            }
        }
        if (!profileMatches) {
            throw new ProtocolException(
                    ErrorCode.UNSUPPORTED_ALGORITHM,
                    "message does not use the public/X25519/signed profile"
            );
        }
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
    }

    private static ProtocolException signatureInvalid(String message) {
        return new ProtocolException(ErrorCode.SIGNATURE_INVALID, message);
    }

    private static ProtocolException keyUnwrap(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.KEY_UNWRAP_FAILED, message)
                : new ProtocolException(ErrorCode.KEY_UNWRAP_FAILED, message, cause);
    }

    private static ProtocolException internal(String message, Throwable cause) {
        return cause == null
                ? new ProtocolException(ErrorCode.INTERNAL_ERROR, message)
                : new ProtocolException(ErrorCode.INTERNAL_ERROR, message, cause);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    public record Request(
            String wireJson,
            SenderX25519PublicKeyResolver senderEncryptionKeys,
            Ed25519VerificationKeyResolver senderSigningKeys,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        public Request {
            if (senderEncryptionKeys == null) {
                throw new IllegalArgumentException("senderEncryptionKeys must not be null");
            }
            if (senderSigningKeys == null) {
                throw new IllegalArgumentException("senderSigningKeys must not be null");
            }
            if (recipientPrivateKeys == null) {
                throw new IllegalArgumentException("recipientPrivateKeys must not be null");
            }
            for (X25519PrivateKeyHandle privateKey : recipientPrivateKeys) {
                if (privateKey == null) {
                    throw new IllegalArgumentException("recipientPrivateKeys must not contain null");
                }
            }
            recipientPrivateKeys = List.copyOf(new ArrayList<>(recipientPrivateKeys));
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
            if (payload == null || messageId == null || authenticatedSender == null) {
                throw new IllegalArgumentException("receiver result values must not be null");
            }
            if (authenticationStatus != ProtocolAuthenticationStatus.SIGNED_VALID) {
                throw new IllegalArgumentException("signed receiver result must be SIGNED_VALID");
            }
        }
    }
}
