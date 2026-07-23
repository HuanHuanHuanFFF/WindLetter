package com.windletter.protocol.wire;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;

class WindLetterTest {

    @Test
    void rejectsEmptyRecipients() {
        ProtectedHeader header = new ProtectedHeader(
                "wind+jwe",
                "wind+inner",
                "1.0",
                "public",
                "A256GCM",
                "X25519",
                new SenderKid("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        );

        assertThrows(IllegalArgumentException.class, () -> new WindLetter(
                header,
                "protected",
                "aad",
                List.of(),
                new byte[12],
                new byte[0],
                new byte[16]
        ));
    }
}
