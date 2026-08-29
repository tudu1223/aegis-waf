package com.aegis.core.sql.lexer;

/**
 * SQL 词法单元。
 *
 * @param type      词法单元类型
 * @param value     原始文本
 * @param upper     大写形式（关键字比对用，避免重复计算）
 * @param position  在源串中的起始下标
 * @param inlineHint 是否来自 MySQL 可执行内联注释 {@code /*!...*}{@code /}
 */
public record Token(
        TokenType type,
        String value,
        String upper,
        int position,
        boolean inlineHint
) {

    public static Token of(TokenType type, String value, int position) {
        return new Token(type, value, value.toUpperCase(), position, false);
    }

    public static Token of(TokenType type, String value, int position, boolean inlineHint) {
        return new Token(type, value, value.toUpperCase(), position, inlineHint);
    }

    /** 是否为指定关键字（忽略大小写）。 */
    public boolean isKeyword(String kw) {
        return type == TokenType.KEYWORD && upper.equals(kw);
    }

    /** 是否为指定标点或运算符。 */
    public boolean is(String text) {
        return value.equalsIgnoreCase(text);
    }

    public boolean isEof() {
        return type == TokenType.EOF;
    }

    @Override
    public String toString() {
        return type + "(" + value + ")";
    }
}
