package com.windletter.protocol.flow;

import com.windletter.core.error.ErrorCode;
import com.windletter.crypto.api.A256GcmCrypto;
import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.auth.OuterAad;
import com.windletter.protocol.binding.OuterBinding;
import com.windletter.protocol.inner.UnsignedInnerCodec;
import com.windletter.protocol.key.PublicX25519KekDeriver;
import com.windletter.protocol.key.X25519KeyId;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolPayload;
import com.windletter.protocol.parser.JacksonOuterWireParser;
import com.windletter.protocol.routing.PublicKidRouter;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Complete receiver flow for the stage-one public/X25519/unsigned profile. */
public final class PublicX25519UnsignedReceiver {

    private static final int X25519_PUBLIC_KEY_LENGTH = 32;
    private static final int CEK_LENGTH = 32;

    private final PublicX25519KekDeriver kekDeriver;
    private final A256KeyWrapCrypto keyWrap;
    private final A256GcmCrypto gcm;
    private final JacksonOuterWireParser parser = new JacksonOuterWireParser();
    private final OuterAad outerAad = new OuterAad();
    private final PublicKidRouter router = new PublicKidRouter();
    private final UnsignedInnerCodec innerCodec = new UnsignedInnerCodec();
    private final OuterBinding outerBinding = new OuterBinding();

    public PublicX25519UnsignedReceiver(
            PublicX25519KekDeriver kekDeriver,
            A256KeyWrapCrypto keyWrap,
            A256GcmCrypto gcm
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
        this.kekDeriver = kekDeriver;
        this.keyWrap = keyWrap;
        this.gcm = gcm;
    }

    public Result receive(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        byte[] senderPublicKey = null;
        byte[] kek = null;
        byte[] cek = null;
        byte[] gcmAad = null;
        byte[] decryptedInner = null;
        try {
            WindLetter letter = parser.parse(request.wireJson());
            requireStageOneProfile(letter);
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
            senderPublicKey = resolveSenderPublicKey(request.senderKeys(), senderKid.x25519());

            try {
                kek = kekDeriver.derive(match.privateKey(), senderPublicKey);
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

            UnsignedInnerCodec.Message inner = innerCodec.decode(decryptedInner);
            outerBinding.verify(inner.binding(), letter.protectedHeader(), letter.recipients());
            return new Result(
                    inner.payload(),
                    inner.messageId(),
                    inner.timestamp(),
                    ProtocolAuthenticationStatus.UNSIGNED
            );
        } finally {
            clear(senderPublicKey);
            clear(kek);
            clear(cek);
            clear(gcmAad);
            clear(decryptedInner);
        }
    }

    private static byte[] resolveSenderPublicKey(
            SenderX25519PublicKeyResolver resolver,
            String expectedKid
    ) {
        Optional<byte[]> resolved;
        try {
            resolved = resolver.resolve(expectedKid);
        } catch (RuntimeException e) {
            throw internal("sender public-key resolver failed", e);
        }
        if (resolved == null) {
            throw internal("sender public-key resolver returned null", null);
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

    private static void requireStageOneProfile(WindLetter letter) {
        ProtectedHeader header = letter.protectedHeader();
        boolean profileMatches = "wind+jwe".equals(header.typ())
                && "wind+inner".equals(header.cty())
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
                    "message does not use the public/X25519/unsigned profile"
            );
        }
    }

    private static ProtocolException invalid(String message) {
        return new ProtocolException(ErrorCode.INVALID_FIELD, message);
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
            SenderX25519PublicKeyResolver senderKeys,
            List<X25519PrivateKeyHandle> recipientPrivateKeys
    ) {
        public Request {
            if (senderKeys == null) {
                throw new IllegalArgumentException("senderKeys must not be null");
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
            ProtocolAuthenticationStatus authenticationStatus
    ) {
        public Result {
            if (payload == null || messageId == null || authenticationStatus == null) {
                throw new IllegalArgumentException("receiver result values must not be null");
            }
        }
    }
}
