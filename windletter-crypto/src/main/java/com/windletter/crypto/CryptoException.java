package com.windletter.crypto;

import com.windletter.core.ErrorCode;
import com.windletter.core.WindLetterException;

/**
 * Wrapper for cryptographic failures.
 * 密码学操作失败时的包装异常。
 */
public class CryptoException extends WindLetterException {
    public CryptoException(String message) {
        super(ErrorCode.CRYPTO_FAILURE, message);
    }

    public CryptoException(String message, Throwable cause) {
        super(ErrorCode.CRYPTO_FAILURE, message, cause);
    }
}
