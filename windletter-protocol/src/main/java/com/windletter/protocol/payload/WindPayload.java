package com.windletter.protocol.payload;

/**
 * Business payload holding meta information and body content.
 * 业务载荷，包含元信息与正文内容。
 */
public class WindPayload {
    private Meta meta;
    private Body body;

    public WindPayload() {
    }

    public WindPayload(Meta meta, Body body) {
        this.meta = meta;
        this.body = body;
    }

    public Meta getMeta() {
        return meta;
    }

    public void setMeta(Meta meta) {
        this.meta = meta;
    }

    public Body getBody() {
        return body;
    }

    public void setBody(Body body) {
        this.body = body;
    }

    public static class Meta {
        private String contentType;
        private Long originalSize;

        public Meta() {
        }

        public Meta(String contentType, Long originalSize) {
            this.contentType = contentType;
            this.originalSize = originalSize;
        }

        public String getContentType() {
            return contentType;
        }

        public void setContentType(String contentType) {
            this.contentType = contentType;
        }

        public Long getOriginalSize() {
            return originalSize;
        }

        public void setOriginalSize(Long originalSize) {
            this.originalSize = originalSize;
        }
    }

    public static class Body {
        private String type;
        private String text;

        public Body() {
        }

        public Body(String type, String text) {
            this.type = type;
            this.text = text;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getText() {
            return text;
        }

        public void setText(String text) {
            this.text = text;
        }
    }
}
