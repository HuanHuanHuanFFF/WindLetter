package com.windletter.protocol.wire;

import java.util.List;

/**
 * Parsed and validated outer wire data.
 */
public record OuterData(
        OuterShell shell,
        ProtectedHeader header,
        List<RecipientEntry> recipients
) {

    public OuterData {
        shell = WireChecks.requireNonNull(shell, "shell");
        header = WireChecks.requireNonNull(header, "header");
        recipients = WireChecks.copyList(recipients, "recipients");
    }
}

