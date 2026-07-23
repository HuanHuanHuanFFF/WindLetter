package com.windletter.armor;

import java.util.Objects;

/** Raised when an armor representation is malformed or unsupported. */
public final class ArmorException extends RuntimeException {

    /** Stable internal failure category; public API callers must not expose this as an oracle. */
    public enum Reason {
        INVALID_INPUT,
        INVALID_TEXT,
        INVALID_MAGIC,
        UNSUPPORTED_VERSION,
        INVALID_LENGTH,
        CHECKSUM_MISMATCH,
        INVALID_UTF8
    }

    private final Reason reason;

    ArmorException(Reason reason, String message) {
        super(message);
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    ArmorException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(reason, "reason");
    }

    public Reason reason() {
        return reason;
    }
}
