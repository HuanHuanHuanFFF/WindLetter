package com.windletter.crypto.bc;

import com.windletter.crypto.api.A256KeyWrapCrypto;
import com.windletter.crypto.api.CryptoOperationException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * 基于 Bouncy Castle 的 A256KW 实现。
 */
public final class BouncyCastleA256KeyWrapCrypto implements A256KeyWrapCrypto {

    private static AESWrapEngine newWrap() {
        return new AESWrapEngine();
    }

    @Override
    public byte[] wrap(byte[] kek, byte[] keyToWrap) {
        validateKek(kek);
        validatePlaintextKey(keyToWrap);
        AESWrapEngine wrap = newWrap();
        wrap.init(true, new KeyParameter(kek));
        byte[] wrapped = wrap.wrap(keyToWrap, 0, keyToWrap.length);
        return wrapped;
    }

    @Override
    public byte[] unwrap(byte[] kek, byte[] wrappedKey) {
        validateKek(kek);
        validateWrappedKey(wrappedKey);
        AESWrapEngine unwrap = newWrap();
        unwrap.init(false, new KeyParameter(kek));
        try {
            byte[] unwrapped = unwrap.unwrap(wrappedKey, 0, wrappedKey.length);
            return unwrapped;
        } catch (InvalidCipherTextException e) {
            throw new CryptoOperationException("failed to unwrap key", e);
        }
    }

    private static void validateKek(byte[] kek) {
        if (kek == null || kek.length != 32) {
            throw new IllegalArgumentException("kek must be 32 bytes");
        }
    }

    private static void validatePlaintextKey(byte[] keyToWrap) {
        if (keyToWrap == null || keyToWrap.length == 0) {
            throw new IllegalArgumentException("keyToWrap must not be empty");
        }
        if ((keyToWrap.length % 8) != 0) {
            throw new IllegalArgumentException("keyToWrap length must be a multiple of 8");
        }
        if (keyToWrap.length < 16) {
            throw new IllegalArgumentException("keyToWrap is too short");
        }
    }

    private static void validateWrappedKey(byte[] wrappedKey) {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new IllegalArgumentException("wrappedKey must not be empty");
        }
        if ((wrappedKey.length % 8) != 0) {
            throw new IllegalArgumentException("wrappedKey length must be a multiple of 8");
        }
        // RFC 3394: n >= 2，最短包裹结果为 16 + 8 = 24 字节。
        if (wrappedKey.length < 24) {
            throw new IllegalArgumentException("wrappedKey is too short");
        }
    }
}
