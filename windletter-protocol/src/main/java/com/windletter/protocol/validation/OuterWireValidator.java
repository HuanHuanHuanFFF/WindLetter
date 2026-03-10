package com.windletter.protocol.validation;

import com.windletter.protocol.wire.OuterWireMessage;
import com.windletter.protocol.wire.ParsedOuterWire;
import com.windletter.protocol.wire.ProtectedHeader;

/**
 * Validator for outer wire structure and semantic constraints.
 */
public interface OuterWireValidator {

    /**
     * Validate top-level required fields and protected header whitelist values.
     */
    void validateStructure(OuterWireMessage wire);

    /**
     * Validate decoded protected header against protocol whitelist.
     */
    void validateProtected(ProtectedHeader protectedHeader);

    /**
     * Recompute AAD from raw recipients node and compare with wire aad.
     */
    void validateAadConsistency(ParsedOuterWire parsedWire);
}
