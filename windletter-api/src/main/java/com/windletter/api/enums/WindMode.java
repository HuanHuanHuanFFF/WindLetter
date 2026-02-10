package com.windletter.api.enums;

/**
 * 传输模式。
 */
public enum WindMode {
    /** 公开模式，收件人标识可见。 */
    PUBLIC,
    /** 混淆模式，使用 rid 与填充减少关系暴露。 */
    OBFUSCATION
}
