package com.windletter.protocol.auth;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.codec.JcsCanonicalizer;
import com.windletter.protocol.codec.OuterJsonMapper;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.WindLetter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Computes and verifies the outer recipients AAD and the AES-GCM authentication input.
 */
public final class OuterAad {

    public String compute(List<RecipientEntry> recipients) {
        return Base64Url.encode(JcsCanonicalizer.canonicalize(
                OuterJsonMapper.toRecipientsJson(recipients)
        ));
    }

    public void verify(WindLetter letter) {
        if (letter == null) {
            throw new IllegalArgumentException("letter must not be null");
        }
        byte[] expected = compute(letter.recipients()).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = letter.aad().getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new ProtocolException(ErrorCode.AAD_MISMATCH, "outer aad does not match recipients");
        }
    }

    public byte[] gcmInput(String protectedValue, String aadValue) {
        if (protectedValue == null) {
            throw new IllegalArgumentException("protectedValue must not be null");
        }
        if (aadValue == null) {
            throw new IllegalArgumentException("aadValue must not be null");
        }
        return (protectedValue + "." + aadValue).getBytes(StandardCharsets.US_ASCII);
    }
}
