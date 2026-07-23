package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EncryptRequestTest {

    @Test
    void shouldRejectEmptyRecipients() {
        Payload payload = new Payload("text/plain", new byte[] {1}, 1);
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                payload,
                List.of(),
                Map.of(),
                new SenderEncryptionIdentityRef("sender", null)
            )
        );
    }

    @Test
    void shouldRequireSenderEncryptionIdentity() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.NONE,
                new Payload("text/plain", new byte[] {1}, 1),
                List.of(new RecipientRef("r1", "kid-x", null, Map.of())),
                Map.of(),
                null
            )
        );
    }

    @Test
    void shouldUseImmutableCopiesForRecipientsAndHeaders() {
        List<RecipientRef> recipients = new ArrayList<>();
        recipients.add(new RecipientRef("r1", "kid-x", null, Map.of()));
        Map<String, Object> headers = new HashMap<>();
        headers.put("trace", "x");

        EncryptRequest req = new EncryptRequest(
            WindMode.PUBLIC,
            KeyAlgProfile.X25519,
            null,
            new Payload("text/plain", new byte[] {1}, 1),
            recipients,
            headers,
            new SenderEncryptionIdentityRef("sender", "active")
        );

        recipients.clear();
        headers.clear();
        assertEquals(1, req.recipients().size());
        assertEquals(1, req.customHeaders().size());
        assertEquals(ArmorFormat.NONE, req.armorFormat());
        assertThrows(UnsupportedOperationException.class, () -> req.recipients().add(null));
        assertThrows(UnsupportedOperationException.class, () -> req.customHeaders().put("k", "v"));
    }
}
