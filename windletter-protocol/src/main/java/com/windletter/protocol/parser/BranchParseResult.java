package com.windletter.protocol.parser;

import com.windletter.protocol.wire.RecipientEntry;
import com.windletter.protocol.wire.SenderInfo;

import java.util.List;

record BranchParseResult(SenderInfo senderInfo, List<RecipientEntry> recipients) {
}

