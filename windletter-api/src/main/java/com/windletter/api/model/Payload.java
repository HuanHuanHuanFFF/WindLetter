package com.windletter.api.model;

import java.util.Arrays;

/**
 * 业务载荷。
 *
 * @param contentType MIME 类型
 * @param data 原始字节数据
 * @param originalSize 原始长度（>= 0）
 */
public record Payload(String contentType, byte[] data, long originalSize) {

    public Payload {
        contentType = ModelChecks.requireNonBlank(contentType, "contentType");
        ModelChecks.requireNonNull(data, "data");
        if (originalSize < 0) {
            throw new IllegalArgumentException("originalSize must be >= 0");
        }
        data = Arrays.copyOf(data, data.length);
    }

    /**
     * 返回数据副本，避免外部修改内部状态。
     */
    @Override
    public byte[] data() {
        return Arrays.copyOf(data, data.length);
    }
}
