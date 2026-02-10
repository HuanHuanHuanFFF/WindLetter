package com.windletter.api.model;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class EncryptedMessageTest {

    @Test
    void shouldRejectBlankWireJson() {
        assertThrows(IllegalArgumentException.class, () -> new EncryptedMessage("   ", null));
    }
}
