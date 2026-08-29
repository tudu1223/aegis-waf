package com.aegis.core.sql.lexer;

/**
 * SQL 词法单元类型。
 */
public enum TokenType {

    /** 关键字：SELECT / FROM / WHERE / UNION 等 */
    KEYWORD,

    /** 标识符：表名、列名、别名 */
    IDENTIFIER,

    /** 数值字面量 */
    NUMBER,

    /** 字符串字面量 */
    STRING,

    /** 运算符：= < > + - 等 */
    OPERATOR,

    /** 标点：括号、逗号、分号 */
    PUNCTUATION,

    /** 参数占位符：? 或 :name */
    PLACEHOLDER,

    /** 注释：-- # 或 C 风格 */
    COMMENT,

    /** 十六进制字面量：0x41424344 */
    HEX_LITERAL,

    /** 结束标记 */
    EOF
}
