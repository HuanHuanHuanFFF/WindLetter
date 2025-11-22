package com.windletter.core;

/**
 * Base unchecked exception for all Wind Letter library failures.
 * Wind Letter 库的基础运行时异常。
 */
public class WindLetterException extends RuntimeException {

    private final ErrorCode code;

    public WindLetterException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public WindLetterException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode getCode() {
        return code;
    }
}
