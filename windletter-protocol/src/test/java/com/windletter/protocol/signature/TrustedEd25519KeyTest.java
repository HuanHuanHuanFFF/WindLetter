package com.windletter.protocol.signature;

import com.windletter.protocol.codec.Base64Url;
import com.windletter.protocol.model.ProtocolAuthenticationStatus;
import com.windletter.protocol.model.ProtocolSenderIdentity;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustedEd25519KeyTest {

    private static final String IDENTITY_ID = "sender-identity-1";
    private static final String SIGNING_KID = Base64Url.encode(new byte[32]);

    @Test
    void snapshotsTrustedKeyMaterialAndSupportsFunctionalResolution() {
        byte[] source = new byte[32];
        source[0] = 7;
        TrustedEd25519Key trusted = new TrustedEd25519Key(IDENTITY_ID, SIGNING_KID, source);
        source[0] = 9;

        byte[] firstRead = trusted.publicKey();
        assertEquals(IDENTITY_ID, trusted.identityId());
        assertEquals(SIGNING_KID, trusted.signingKid());
        assertArrayEquals(keyStartingWith(7), firstRead);
        assertNotSame(source, firstRead);

        firstRead[0] = 11;
        assertArrayEquals(keyStartingWith(7), trusted.publicKey());

        Ed25519VerificationKeyResolver resolver = signingKid -> Optional.of(trusted);
        assertSame(trusted, resolver.resolve(SIGNING_KID).orElseThrow());
    }

    @Test
    void rejectsBlankIdentityAndSigningKid() {
        byte[] publicKey = new byte[32];

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(null, SIGNING_KID, publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(" ", SIGNING_KID, publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, null, publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, " ", publicKey));
    }

    @Test
    void rejectsNonCanonicalOrNon32ByteSigningKids() {
        byte[] publicKey = new byte[32];
        String nonCanonicalKid = SIGNING_KID.substring(0, SIGNING_KID.length() - 1) + "B";

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, SIGNING_KID + "=", publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, nonCanonicalKid, publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, Base64Url.encode(new byte[31]), publicKey));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, Base64Url.encode(new byte[33]), publicKey));
    }

    @Test
    void rejectsNullAndNon32BytePublicKeys() {
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, SIGNING_KID, null));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, SIGNING_KID, new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedEd25519Key(IDENTITY_ID, SIGNING_KID, new byte[33]));
    }

    @Test
    void senderIdentityRequiresNonBlankValuesAndAuthenticationStatusesStayOrdered() {
        ProtocolSenderIdentity identity = new ProtocolSenderIdentity(IDENTITY_ID, SIGNING_KID);

        assertEquals(IDENTITY_ID, identity.identityId());
        assertEquals(SIGNING_KID, identity.signingKid());
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolSenderIdentity(null, SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolSenderIdentity(" ", SIGNING_KID));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolSenderIdentity(IDENTITY_ID, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ProtocolSenderIdentity(IDENTITY_ID, " "));
        assertArrayEquals(
                new ProtocolAuthenticationStatus[]{
                        ProtocolAuthenticationStatus.UNSIGNED,
                        ProtocolAuthenticationStatus.SIGNED_VALID
                },
                ProtocolAuthenticationStatus.values()
        );
    }

    private static byte[] keyStartingWith(int value) {
        byte[] key = new byte[32];
        key[0] = (byte) value;
        return key;
    }
}
