package com.windletter.crypto.api;

/**
 * 密码学操作失败异常。
 * <p>
 * 用于封装底层密码库抛出的实现细节异常，向上层提供稳定语义。
 */
public class CryptoOperationException extends RuntimeException {

    public CryptoOperationException(String message) {
        super(message);
    }

    public CryptoOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
