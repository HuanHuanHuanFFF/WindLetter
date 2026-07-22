package com.windletter.api;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientKeyStore;
import com.windletter.api.spi.RecipientPublicKeyResolver;
import com.windletter.api.spi.SenderEncryptionKeyStore;
import com.windletter.api.spi.SenderPublicKeyResolver;
import com.windletter.api.spi.SigningIdentityLease;
import com.windletter.api.spi.VerificationKeyMaterial;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class WindLetterRuntimeTest {

    private static final RecipientPublicKeyResolver RECIPIENT_PUBLIC_KEYS =
        recipient -> Optional.empty();
    private static final SenderEncryptionKeyStore SENDER_ENCRYPTION_KEYS =
        identity -> Optional.empty();
    private static final RecipientKeyStore RECIPIENT_PRIVATE_KEYS = identity -> List.of();
    private static final SenderPublicKeyResolver SENDER_PUBLIC_KEYS = kid -> Optional.empty();
    private static final IdentityService IDENTITIES = new IdentityService() {
        @Override
        public Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef identity) {
            return Optional.empty();
        }

        @Override
        public Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String kid) {
            return Optional.empty();
        }

        @Override
        public Optional<SenderIdentity> resolveSenderBySigningKid(String kid) {
            return Optional.empty();
        }
    };

    @Test
    void createsDefaultSenderAndReceiverFromApplicationSpis() {
        assertNotNull(WindLetterRuntime.sender(
            RECIPIENT_PUBLIC_KEYS,
            SENDER_ENCRYPTION_KEYS,
            IDENTITIES
        ));
        assertNotNull(WindLetterRuntime.receiver(
            RECIPIENT_PRIVATE_KEYS,
            SENDER_PUBLIC_KEYS,
            IDENTITIES
        ));
    }

    @Test
    void rejectsMissingDependenciesAtTheCompositionBoundary() {
        assertThrows(IllegalArgumentException.class, () -> WindLetterRuntime.sender(
            null,
            SENDER_ENCRYPTION_KEYS,
            IDENTITIES
        ));
        assertThrows(IllegalArgumentException.class, () -> WindLetterRuntime.receiver(
            RECIPIENT_PRIVATE_KEYS,
            null,
            IDENTITIES
        ));
    }
}
