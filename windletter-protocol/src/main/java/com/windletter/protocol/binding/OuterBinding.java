package com.windletter.protocol.binding;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * Computes and verifies the inner-to-outer semantic binding hashes.
 */
public final class OuterBinding {

    private static final int SHA_256_BYTES = 32;

    public Hashes compute(ProtectedHeader header, List<RecipientEntry> recipients) {
        byte[] protectedHash = sha256(JcsCanonicalizer.canonicalize(
                OuterJsonMapper.toProtectedJson(header)
        ));
        byte[] recipientsHash = sha256(JcsCanonicalizer.canonicalize(
                OuterJsonMapper.toRecipientsJson(recipients)
        ));
        return new Hashes(protectedHash, recipientsHash);
    }

    public void verify(Hashes actual, ProtectedHeader header, List<RecipientEntry> recipients) {
        if (actual == null) {
            throw new IllegalArgumentException("actual must not be null");
        }
        Hashes expected = compute(header, recipients);
        boolean protectedMatches = MessageDigest.isEqual(actual.protectedHash(), expected.protectedHash());
        boolean recipientsMatch = MessageDigest.isEqual(actual.recipientsHash(), expected.recipientsHash());
        if (!protectedMatches | !recipientsMatch) {
            throw new ProtocolException(ErrorCode.BINDING_FAILED, "inner binding does not match outer message");
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new ProtocolException(ErrorCode.INTERNAL_ERROR, "SHA-256 is unavailable", e);
        }
    }

    public record Hashes(byte[] protectedHash, byte[] recipientsHash) {

        public Hashes {
            protectedHash = copyHash(protectedHash, "protectedHash");
            recipientsHash = copyHash(recipientsHash, "recipientsHash");
        }

        @Override
        public byte[] protectedHash() {
            return Arrays.copyOf(protectedHash, protectedHash.length);
        }

        @Override
        public byte[] recipientsHash() {
            return Arrays.copyOf(recipientsHash, recipientsHash.length);
        }

        private static byte[] copyHash(byte[] value, String fieldName) {
            if (value == null || value.length != SHA_256_BYTES) {
                throw new IllegalArgumentException(fieldName + " must contain exactly 32 bytes");
            }
            return Arrays.copyOf(value, value.length);
        }
    }
}
