package com.aegis.core.sql.ast;

/**
 * AST 节点类型。
 *
 * <p>节点类型是结构指纹与结构差分的基本单位：指纹由节点类型序列构成，
 * 差分通过比较节点类型的路径签名集合得出。
 */
public enum NodeType {

    // ---------- 语句级 ----------
    /** SELECT 查询 */
    SELECT_STATEMENT,
    /** INSERT 语句 */
    INSERT_STATEMENT,
    /** UPDATE 语句 */
    UPDATE_STATEMENT,
    /** DELETE 语句 */
    DELETE_STATEMENT,
    /** DDL 语句（CREATE/DROP/ALTER） */
    DDL_STATEMENT,
    /** 集合运算：UNION / INTERSECT / EXCEPT，联合查询注入的标志 */
    SET_OPERATION,
    /** 多语句序列，堆叠查询注入的标志 */
    STATEMENT_LIST,

    // ---------- 子句级 ----------
    /** SELECT 投影列表 */
    SELECT_LIST,
    /** 单个投影项 */
    SELECT_ITEM,
    /** FROM 子句 */
    FROM_CLAUSE,
    /** WHERE 子句 */
    WHERE_CLAUSE,
    /** JOIN 子句 */
    JOIN_CLAUSE,
    /** GROUP BY 子句 */
    GROUP_BY_CLAUSE,
    /** HAVING 子句 */
    HAVING_CLAUSE,
    /** ORDER BY 子句 */
    ORDER_BY_CLAUSE,
    /** LIMIT 子句 */
    LIMIT_CLAUSE,
    /** SET 赋值子句（UPDATE） */
    SET_CLAUSE,
    /** VALUES 子句（INSERT） */
    VALUES_CLAUSE,

    // ---------- 表达式级 ----------
    /** 逻辑与 */
    AND_EXPRESSION,
    /** 逻辑或，注入绕过的核心标志 */
    OR_EXPRESSION,
    /** 逻辑非 */
    NOT_EXPRESSION,
    /** 二元比较：= <> < > <= >= */
    COMPARISON,
    /** 算术运算 */
    ARITHMETIC,
    /** IN 谓词 */
    IN_EXPRESSION,
    /** LIKE 谓词 */
    LIKE_EXPRESSION,
    /** BETWEEN 谓词 */
    BETWEEN_EXPRESSION,
    /** IS NULL / IS NOT NULL 谓词 */
    IS_NULL_EXPRESSION,
    /** EXISTS 谓词 */
    EXISTS_EXPRESSION,
    /** CASE 表达式 */
    CASE_EXPRESSION,
    /** 函数调用，危险函数检测的关键节点 */
    FUNCTION_CALL,
    /** 子查询 */
    SUBQUERY,

    // ---------- 叶子节点 ----------
    /** 列引用 */
    COLUMN_REF,
    /** 表引用 */
    TABLE_REF,
    /** 字面量（归一化后统一为占位符） */
    LITERAL,
    /** 参数占位符 */
    PLACEHOLDER,
    /** 通配符 * */
    WILDCARD,

    /** 无法解析的片段，保证解析器不中断 */
    UNKNOWN
}
