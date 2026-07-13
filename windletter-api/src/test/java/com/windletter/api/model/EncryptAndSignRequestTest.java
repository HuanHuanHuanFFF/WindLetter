package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.enums.ArmorFormat;
import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.enums.WindMode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EncryptAndSignRequestTest {

    @Test
    void shouldRequireSigningIdentity() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptAndSignRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.BASE64URL,
                new Payload("text/plain", new byte[] {1}, 1),
                List.of(new RecipientRef("r1", "kid-x", null, Map.of())),
                Map.of(),
                new SenderEncryptionIdentityRef("encryptor", null),
                null
            )
        );
    }

    @Test
    void shouldRequireIndependentEncryptionIdentity() {
        assertThrows(
            IllegalArgumentException.class,
            () -> new EncryptAndSignRequest(
                WindMode.PUBLIC,
                KeyAlgProfile.X25519,
                ArmorFormat.BASE64URL,
                new Payload("text/plain", new byte[] {1}, 1),
                List.of(new RecipientRef("r1", "kid-x", null, Map.of())),
                Map.of(),
                null,
                new SigningIdentityRef("signer", null)
            )
        );
    }

    @Test
    void shouldKeepEncryptionAndSigningIdentitiesSeparate() {
        EncryptAndSignRequest request = new EncryptAndSignRequest(
            WindMode.PUBLIC,
            KeyAlgProfile.X25519,
            ArmorFormat.BASE64URL,
            new Payload("text/plain", new byte[] {1}, 1),
            List.of(new RecipientRef("r1", "kid-x", null, Map.of())),
            Map.of(),
            new SenderEncryptionIdentityRef("encryptor", "enc-current"),
            new SigningIdentityRef("signer", "sig-current")
        );

        org.junit.jupiter.api.Assertions.assertEquals("encryptor", request.senderEncryptionIdentity().identityId());
        org.junit.jupiter.api.Assertions.assertEquals("signer", request.senderSigningIdentity().identityId());
    }
}
