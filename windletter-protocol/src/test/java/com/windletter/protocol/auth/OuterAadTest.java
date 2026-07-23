package com.windletter.protocol.auth;

import com.windletter.core.error.ErrorCode;
import com.windletter.protocol.ProtocolException;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.PublicRecipient;
import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.RecipientKid;
import com.windletter.protocol.wire.SenderKid;
import com.windletter.protocol.wire.WindLetter;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OuterAadTest {

    private static final String EXPECTED_AAD = "W3siZW5jcnlwdGVkX2tleSI6IkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUkVSRVJFUSIsImtpZCI6eyJ4MjU1MTkiOiJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFQkFRRUJBUUVCQVFFIn19LHsiZW5jcnlwdGVkX2tleSI6IklpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJaUlpSWlJZyIsImtpZCI6eyJ4MjU1MTkiOiJBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJIn19XQ";
    private static final String KID_ONE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    private static final String KID_TWO = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

    private final OuterAad outerAad = new OuterAad();

    @Test
    void computesProtocolAadFromCanonicalFinalRecipientsArray() {
        List<RecipientEntry> recipients = vectorRecipients();

        assertEquals(EXPECTED_AAD, outerAad.compute(recipients));
        assertNotEquals(EXPECTED_AAD, outerAad.compute(List.of(recipients.get(1), recipients.get(0))));
    }

    @Test
    void buildsExactAsciiGcmAuthenticationInputAndRejectsNullParts() {
        assertArrayEquals("abc.def".getBytes(StandardCharsets.US_ASCII), outerAad.gcmInput("abc", "def"));
        assertThrows(IllegalArgumentException.class, () -> outerAad.gcmInput(null, "def"));
        assertThrows(IllegalArgumentException.class, () -> outerAad.gcmInput("abc", null));
    }

    @Test
    void verifiesAadUsingTheFinalRecipientsArray() {
        WindLetter valid = letter(EXPECTED_AAD, vectorRecipients());
        assertDoesNotThrow(() -> outerAad.verify(valid));

        ProtocolException exception = assertThrows(
                ProtocolException.class,
                () -> outerAad.verify(letter("dGFtcGVyZWQ", vectorRecipients()))
        );
        assertEquals(ErrorCode.AAD_MISMATCH, exception.errorCode());
    }

    private static WindLetter letter(String aad, List<RecipientEntry> recipients) {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe", "wind+inner", "1.0", "public", "A256GCM", "X25519",
                new SenderKid(KID_ONE)
        );
        return new WindLetter(
                header, "cHJvdGVjdGVk", aad, recipients,
                filled(12, 0x33), filled(24, 0x44), filled(16, 0x55)
        );
    }

    private static List<RecipientEntry> vectorRecipients() {
        return List.of(
                new PublicRecipient(new RecipientKid(KID_ONE, null), filled(40, 0x11), null),
                new PublicRecipient(new RecipientKid(KID_TWO, null), filled(40, 0x22), null)
        );
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
