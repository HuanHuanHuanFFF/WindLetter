package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class PayloadTest {

    @Test
    void shouldUseDefensiveCopyForInputAndAccessor() {
        byte[] input = new byte[] {1, 2, 3};
        Payload payload = new Payload("text/plain", input, 3);
        input[0] = 9;

        byte[] fromPayload = payload.data();
        assertArrayEquals(new byte[] {1, 2, 3}, fromPayload);
        assertNotSame(fromPayload, payload.data());
    }

    @Test
    void shouldRejectNegativeOriginalSize() {
        assertThrows(IllegalArgumentException.class, () -> new Payload("text/plain", new byte[] {1}, -1));
    }
}
