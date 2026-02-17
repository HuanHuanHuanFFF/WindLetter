package com.windletter.api.enums;

/**
 * Key encapsulation algorithm profile.
 */
public enum KeyAlgProfile {
    /** X25519 only. */
    X25519,
    /** X25519 + ML-KEM-768 hybrid profile. */
    X25519_KYBER768
}
