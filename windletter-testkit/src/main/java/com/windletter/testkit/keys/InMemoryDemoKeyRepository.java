package com.windletter.testkit.keys;

import com.windletter.api.enums.KeyAlgProfile;
import com.windletter.api.model.RecipientIdentityRef;
import com.windletter.api.model.RecipientRef;
import com.windletter.api.model.SenderEncryptionIdentityRef;
import com.windletter.api.model.SenderIdentity;
import com.windletter.api.model.SigningIdentityRef;
import com.windletter.api.spi.DecryptionKeyLease;
import com.windletter.api.spi.IdentityService;
import com.windletter.api.spi.RecipientKeyStore;
import com.windletter.api.spi.RecipientPublicKeyMaterial;
import com.windletter.api.spi.RecipientPublicKeyResolver;
import com.windletter.api.spi.SenderEncryptionKeyLease;
import com.windletter.api.spi.SenderEncryptionKeyStore;
import com.windletter.api.spi.SenderPublicKeyResolver;
import com.windletter.api.spi.SigningIdentityLease;
import com.windletter.api.spi.VerificationKeyMaterial;
import com.windletter.api.spi.X25519PublicKeyMaterial;
import com.windletter.crypto.api.Ed25519PrivateKeyHandle;
import com.windletter.crypto.api.MLKem768PrivateKeyHandle;
import com.windletter.crypto.api.X25519PrivateKeyHandle;
import com.windletter.crypto.bc.BouncyCastleEd25519Crypto;
import com.windletter.crypto.bc.BouncyCastleMLKem768Crypto;
import com.windletter.crypto.bc.BouncyCastleX25519Crypto;
import com.windletter.protocol.key.Ed25519KeyId;
import com.windletter.protocol.key.MLKem768KeyId;
import com.windletter.protocol.key.X25519KeyId;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * One-scenario in-memory key repository for tests and the runnable Demo.
 *
 * <p>It generates real BC private-key handles, exposes only public material through resolver
 * methods, and transfers private-handle ownership through the API lease contracts. Create a fresh
 * repository for each send/receive scenario because successful facade calls close their leases.
 */
public final class InMemoryDemoKeyRepository implements
    RecipientPublicKeyResolver,
    SenderEncryptionKeyStore,
    RecipientKeyStore,
    SenderPublicKeyResolver,
    IdentityService,
    AutoCloseable {

    private static final String SENDER_ID = "demo-sender";
    private static final String SIGNER_ID = "demo-signer";
    private static final String RECIPIENT_1_ID = "demo-recipient-1";
    private static final String RECIPIENT_2_ID = "demo-recipient-2";

    private final KeyAlgProfile profile;
    private final X25519PrivateKeyHandle senderX25519;
    private final X25519PrivateKeyHandle recipient1X25519;
    private final MLKem768PrivateKeyHandle recipient1MlKem;
    private final X25519PrivateKeyHandle recipient2X25519;
    private final MLKem768PrivateKeyHandle recipient2MlKem;
    private final Ed25519PrivateKeyHandle signingKey;
    private final byte[] senderPublic;
    private final byte[] recipient1XPublic;
    private final byte[] recipient1MlPublic;
    private final byte[] recipient2XPublic;
    private final byte[] recipient2MlPublic;
    private final byte[] signingPublic;
    private final String senderKid;
    private final String recipient1XKid;
    private final String recipient1MlKid;
    private final String recipient2XKid;
    private final String recipient2MlKid;
    private final String signingKid;

    private int senderEncryptionOpens;
    private int senderPublicLookups;
    private int recipientLeaseOpens;
    private int verificationLookups;
    private int identityLookups;

    public InMemoryDemoKeyRepository(KeyAlgProfile profile) {
        this.profile = Objects.requireNonNull(profile, "profile");
        BouncyCastleX25519Crypto x25519 = new BouncyCastleX25519Crypto();
        BouncyCastleMLKem768Crypto mlkem = new BouncyCastleMLKem768Crypto();
        BouncyCastleEd25519Crypto ed25519 = new BouncyCastleEd25519Crypto();

        senderX25519 = x25519.generatePrivateKey();
        recipient1X25519 = x25519.generatePrivateKey();
        recipient1MlKem = mlkem.generatePrivateKey();
        recipient2X25519 = x25519.generatePrivateKey();
        recipient2MlKem = mlkem.generatePrivateKey();
        signingKey = ed25519.generatePrivateKey();

        senderPublic = senderX25519.publicKey();
        recipient1XPublic = recipient1X25519.publicKey();
        recipient1MlPublic = recipient1MlKem.publicKey();
        recipient2XPublic = recipient2X25519.publicKey();
        recipient2MlPublic = recipient2MlKem.publicKey();
        signingPublic = signingKey.publicKey();

        senderKid = X25519KeyId.derive(senderPublic);
        recipient1XKid = X25519KeyId.derive(recipient1XPublic);
        recipient1MlKid = MLKem768KeyId.derive(recipient1MlPublic);
        recipient2XKid = X25519KeyId.derive(recipient2XPublic);
        recipient2MlKid = MLKem768KeyId.derive(recipient2MlPublic);
        signingKid = Ed25519KeyId.derive(signingPublic);
    }

    public List<RecipientRef> recipientRefs() {
        if (profile == KeyAlgProfile.X25519) {
            return List.of(
                new RecipientRef(RECIPIENT_1_ID, recipient1XKid, null, Map.of()),
                new RecipientRef(RECIPIENT_2_ID, recipient2XKid, null, Map.of())
            );
        }
        return List.of(
            new RecipientRef(
                RECIPIENT_1_ID,
                recipient1XKid,
                recipient1MlKid,
                Map.of()
            ),
            new RecipientRef(RECIPIENT_2_ID, null, recipient2MlKid, Map.of())
        );
    }

    public RecipientIdentityRef recipientIdentity() {
        return new RecipientIdentityRef(RECIPIENT_2_ID, null);
    }

    public SenderEncryptionIdentityRef senderEncryptionIdentity() {
        return new SenderEncryptionIdentityRef(SENDER_ID, senderKid);
    }

    public SigningIdentityRef signingIdentity() {
        return new SigningIdentityRef(SIGNER_ID, signingKid);
    }

    public SenderIdentity trustedSender() {
        return new SenderIdentity(
            "WindLetter Demo Sender",
            signingKid,
            Map.of("source", "windletter-testkit")
        );
    }

    public int senderEncryptionOpens() {
        return senderEncryptionOpens;
    }

    public int senderPublicLookups() {
        return senderPublicLookups;
    }

    public int recipientLeaseOpens() {
        return recipientLeaseOpens;
    }

    public int verificationLookups() {
        return verificationLookups;
    }

    public int identityLookups() {
        return identityLookups;
    }

    @Override
    public Optional<RecipientPublicKeyMaterial> resolve(RecipientRef recipient) {
        return switch (recipient.recipientId()) {
            case RECIPIENT_1_ID -> Optional.of(new RecipientPublicKeyMaterial(
                recipient1XKid,
                recipient1XPublic,
                recipient1MlKid,
                recipient1MlPublic
            ));
            case RECIPIENT_2_ID -> Optional.of(new RecipientPublicKeyMaterial(
                recipient2XKid,
                recipient2XPublic,
                recipient2MlKid,
                recipient2MlPublic
            ));
            default -> Optional.empty();
        };
    }

    @Override
    public Optional<SenderEncryptionKeyLease> open(SenderEncryptionIdentityRef identity) {
        senderEncryptionOpens++;
        return SENDER_ID.equals(identity.identityId())
            ? Optional.of(SenderEncryptionKeyLease.x25519(senderKid, senderX25519))
            : Optional.empty();
    }

    @Override
    public List<DecryptionKeyLease> openAll(RecipientIdentityRef identity) {
        recipientLeaseOpens++;
        if (!RECIPIENT_2_ID.equals(identity.recipientId())) {
            return List.of();
        }
        return profile == KeyAlgProfile.X25519
            ? List.of(DecryptionKeyLease.x25519(recipient2XKid, recipient2X25519))
            : List.of(DecryptionKeyLease.hybrid(
                recipient2XKid,
                recipient2X25519,
                recipient2MlKid,
                recipient2MlKem
            ));
    }

    @Override
    public Optional<X25519PublicKeyMaterial> resolveX25519ByKid(String kid) {
        senderPublicLookups++;
        return senderKid.equals(kid)
            ? Optional.of(new X25519PublicKeyMaterial(senderKid, senderPublic))
            : Optional.empty();
    }

    @Override
    public Optional<SigningIdentityLease> openSigningIdentity(SigningIdentityRef identity) {
        return SIGNER_ID.equals(identity.identityId())
            ? Optional.of(SigningIdentityLease.ed25519(SIGNER_ID, signingKid, signingKey))
            : Optional.empty();
    }

    @Override
    public Optional<VerificationKeyMaterial> resolveVerificationKeyByKid(String kid) {
        verificationLookups++;
        return signingKid.equals(kid)
            ? Optional.of(new VerificationKeyMaterial(signingKid, signingPublic, Map.of()))
            : Optional.empty();
    }

    @Override
    public Optional<SenderIdentity> resolveSenderBySigningKid(String kid) {
        identityLookups++;
        return signingKid.equals(kid) ? Optional.of(trustedSender()) : Optional.empty();
    }

    @Override
    public void close() {
        signingKey.close();
        recipient2MlKem.close();
        recipient2X25519.close();
        recipient1MlKem.close();
        recipient1X25519.close();
        senderX25519.close();
        clear(signingPublic);
        clear(recipient2MlPublic);
        clear(recipient2XPublic);
        clear(recipient1MlPublic);
        clear(recipient1XPublic);
        clear(senderPublic);
    }

    private static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
