package com.windletter.protocol.flow;

import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ProtectedHeader;
import com.windletter.protocol.wire.RecipientEntry;
import java.util.List;

/**
 * Outbound wire preparer that computes protected/aad consistently.
 */
public interface OutboundWirePreparer {

    /**
     * Build outbound outer wire message and force recomputation of aad from recipients.
     */
    OuterWireMessage prepare(
            ProtectedHeader header,
            List<RecipientEntry> recipients,
            String ivB64,
            String ciphertextB64,
            String tagB64);
}
