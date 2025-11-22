package com.windletter.core;

/**
 * Coarse grained error categories exposed to API callers.
 * 对外暴露的粗粒度错误分类。
 */
public enum ErrorCode {
    INVALID_MESSAGE,
    UNSUPPORTED_ALGORITHM,
    KEY_MISSING,
    CRYPTO_FAILURE,
    ENCODING_ERROR
}
