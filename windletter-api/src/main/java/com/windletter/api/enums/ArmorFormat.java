package com.windletter.api.enums;

/**
 * 文本封装格式。
 * <p>
 * 说明：
 * <ul>
 *   <li>{@code NONE} 表示未使用文本封装，仅传输 wire JSON。</li>
 *   <li>{@code BASE64URL}/{@code WIND_BASE_1024F_V1} 表示 armor 字符串编码方案。</li>
 *   <li>{@code BINARY} 表示二进制封装通道（不通过 armor 字符串承载）。</li>
 * </ul>
 */
public enum ArmorFormat {
    /** 不使用文本封装。 */
    NONE,
    /** Base64URL 文本封装。 */
    BASE64URL,
    /** WindBase1024F v1 文本封装。 */
    WIND_BASE_1024F_V1,
    /** 二进制封装（例如文件/流式通道）。 */
    BINARY
}
