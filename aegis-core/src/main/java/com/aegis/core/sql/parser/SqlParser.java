package com.aegis.core.sql.parser;

import com.aegis.core.sql.ast.AstNode;
import com.aegis.core.sql.ast.NodeType;
import com.aegis.core.sql.lexer.SqlLexer;
import com.aegis.core.sql.lexer.Token;
import com.aegis.core.sql.lexer.TokenType;

import java.util.ArrayList;
import java.util.List;

/**
 * [SEC-SQLI-02] SQL 递归下降语法分析器
 *
 * <p><b>安全原理：</b>
 * 将词法单元序列构建为抽象语法树，把 SQL 从"一串文本"转变为"有结构的语义树"。
 * 这是本系统区别于传统正则型 WAF 的根本所在：正则匹配的对象是文本形态，
 * 而攻击者可通过编码、注释、大小写等手段任意改变文本形态；语法树反映的是
 * SQL 的<b>语义结构</b>，而注入攻击的目的恰恰是改变语义结构，因此必然在
 * 树上留下痕迹。
 *
 * <p><b>关键设计——容错解析：</b>
 * 攻击载荷常常导致 SQL 语法非法（如 {@code ' OR '1'='1' --} 会产生不配对的引号）。
 * 传统解析器遇到语法错误会抛出异常，导致检测失效。本解析器采用<b>容错策略</b>：
 * 无法识别的片段封装为 UNKNOWN 节点并继续解析，保证任何输入都能得到一棵可分析的树。
 * 这对安全检测至关重要——<b>解析失败本身不能成为绕过手段</b>。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入、T-12 检测绕过
 */
public final class SqlParser {

    /** 解析深度上限，防御深度嵌套构造导致的栈溢出（可用性防护）。 */
    private static final int MAX_DEPTH = 64;

    private final List<Token> tokens;
    private int index;
    private int depth;

    public SqlParser(String sql) {
        this.tokens = new SqlLexer(sql).tokenizeEffective();
        this.index = 0;
        this.depth = 0;
    }

    /**
     * 解析入口。
     *
     * <p>若源串包含多条以分号分隔的语句，返回 STATEMENT_LIST 根节点——
     * 这是堆叠查询注入的直接证据。
     *
     * @return 语法树根节点，任何输入均返回非 null 结果
     */
    public AstNode parse() {
        List<AstNode> statements = new ArrayList<>();
        while (!isAtEnd()) {
            skipSemicolons();
            if (isAtEnd()) {
                break;
            }
            int before = index;
            AstNode stmt = parseStatement();
            if (stmt != null) {
                statements.add(stmt);
            }
            // 防御性保护：若一轮解析未消耗任何词法单元，强制前进避免死循环
            if (index == before) {
                index++;
            }
        }

        if (statements.isEmpty()) {
            return new AstNode(NodeType.UNKNOWN);
        }
        if (statements.size() == 1) {
            return statements.get(0);
        }
        // 多条语句 —— 堆叠查询的结构特征
        AstNode list = new AstNode(NodeType.STATEMENT_LIST);
        list.addChildren(statements);
        return list;
    }

    // ==================== 语句级解析 ====================

    private AstNode parseStatement() {
        Token t = peek();
        if (t.isKeyword("SELECT")) {
            return parseSelectWithSetOperations();
        }
        if (t.isKeyword("INSERT")) {
            return parseInsert();
        }
        if (t.isKeyword("UPDATE")) {
            return parseUpdate();
        }
        if (t.isKeyword("DELETE")) {
            return parseDelete();
        }
        if (t.isKeyword("CREATE") || t.isKeyword("DROP") || t.isKeyword("ALTER")) {
            return parseDdl();
        }
        if (t.is("(")) {
            // 括号包围的子查询作为语句
            advance();
            AstNode inner = parseSelectWithSetOperations();
            expect(")");
            return inner;
        }
        return parseUnknownFragment();
    }

    /**
     * 解析 SELECT 及其集合运算。
     *
     * <p>UNION / INTERSECT / EXCEPT 会生成 SET_OPERATION 节点，
     * 这是联合查询注入（TC-02）的核心结构标志。
     */
    private AstNode parseSelectWithSetOperations() {
        AstNode left = parseSimpleSelect();

        while (!isAtEnd() && (peek().isKeyword("UNION") || peek().isKeyword("INTERSECT")
                || peek().isKeyword("EXCEPT") || peek().isKeyword("MINUS"))) {
            Token opToken = advance();
            String op = opToken.upper();
            // UNION ALL 中的 ALL 不改变结构语义，跳过
            if (!isAtEnd() && peek().isKeyword("ALL")) {
                advance();
                op = op + " ALL";
            }
            if (!isAtEnd() && peek().isKeyword("DISTINCT")) {
                advance();
            }

            AstNode setOp = new AstNode(NodeType.SET_OPERATION, op);
            setOp.setFromInlineComment(opToken.inlineHint());
            setOp.setSourcePosition(opToken.position());
            setOp.addChild(left);

            AstNode right;
            if (!isAtEnd() && peek().is("(")) {
                advance();
                right = parseSelectWithSetOperations();
                expect(")");
            } else {
                right = parseSimpleSelect();
            }
            setOp.addChild(right);
            left = setOp;
        }
        return left;
    }

    private AstNode parseSimpleSelect() {
        if (guardDepth()) {
            return new AstNode(NodeType.UNKNOWN);
        }
        depth++;
        try {
            AstNode select = new AstNode(NodeType.SELECT_STATEMENT);
            if (!isAtEnd() && peek().isKeyword("SELECT")) {
                Token kw = advance();
                select.setSourcePosition(kw.position());
                select.setFromInlineComment(kw.inlineHint());
            }
            // DISTINCT / ALL 修饰符
            if (!isAtEnd() && (peek().isKeyword("DISTINCT") || peek().isKeyword("ALL"))) {
                advance();
            }

            select.addChild(parseSelectList());

            if (!isAtEnd() && peek().isKeyword("FROM")) {
                advance();
                select.addChild(parseFromClause());
            }
            // JOIN 子句
            while (!isAtEnd() && isJoinStart()) {
                select.addChild(parseJoinClause());
            }
            if (!isAtEnd() && peek().isKeyword("WHERE")) {
                Token kw = advance();
                AstNode where = new AstNode(NodeType.WHERE_CLAUSE);
                where.setSourcePosition(kw.position());
                where.addChild(parseExpression());
                select.addChild(where);
            }
            if (!isAtEnd() && peek().isKeyword("GROUP")) {
                advance();
                if (!isAtEnd() && peek().isKeyword("BY")) {
                    advance();
                }
                AstNode groupBy = new AstNode(NodeType.GROUP_BY_CLAUSE);
                groupBy.addChildren(parseExpressionList());
                select.addChild(groupBy);
            }
            if (!isAtEnd() && peek().isKeyword("HAVING")) {
                advance();
                AstNode having = new AstNode(NodeType.HAVING_CLAUSE);
                having.addChild(parseExpression());
                select.addChild(having);
            }
            if (!isAtEnd() && peek().isKeyword("ORDER")) {
                advance();
                if (!isAtEnd() && peek().isKeyword("BY")) {
                    advance();
                }
                AstNode orderBy = new AstNode(NodeType.ORDER_BY_CLAUSE);
                orderBy.addChildren(parseOrderByItems());
                select.addChild(orderBy);
            }
            if (!isAtEnd() && (peek().isKeyword("LIMIT") || peek().isKeyword("OFFSET"))) {
                select.addChild(parseLimitClause());
            }
            // INTO OUTFILE / DUMPFILE —— 文件写出，高危
            if (!isAtEnd() && peek().isKeyword("INTO")) {
                advance();
                AstNode into = new AstNode(NodeType.FUNCTION_CALL, "INTO");
                while (!isAtEnd() && !peek().is(";") && !peek().is(")")) {
                    Token tk = advance();
                    into.addChild(new AstNode(NodeType.LITERAL, tk.value()));
                }
                select.addChild(into);
            }
            return select;
        } finally {
            depth--;
        }
    }

    private AstNode parseSelectList() {
        AstNode list = new AstNode(NodeType.SELECT_LIST);
        do {
            if (isAtEnd() || peek().isKeyword("FROM")) {
                break;
            }
            AstNode item = new AstNode(NodeType.SELECT_ITEM);
            if (peek().is("*")) {
                Token star = advance();
                AstNode wc = new AstNode(NodeType.WILDCARD, "*");
                wc.setSourcePosition(star.position());
                item.addChild(wc);
            } else {
                item.addChild(parseExpression());
            }
            // 别名：AS x 或直接 x
            if (!isAtEnd() && peek().isKeyword("AS")) {
                advance();
                if (!isAtEnd() && peek().type() == TokenType.IDENTIFIER) {
                    advance();
                }
            } else if (!isAtEnd() && peek().type() == TokenType.IDENTIFIER
                    && !isClauseBoundary()) {
                advance();
            }
            list.addChild(item);
        } while (matchPunctuation(","));
        return list;
    }

    private AstNode parseFromClause() {
        AstNode from = new AstNode(NodeType.FROM_CLAUSE);
        do {
            if (isAtEnd()) {
                break;
            }
            if (peek().is("(")) {
                advance();
                AstNode sub = new AstNode(NodeType.SUBQUERY);
                sub.addChild(parseSelectWithSetOperations());
                expect(")");
                from.addChild(sub);
            } else {
                from.addChild(parseTableRef());
            }
        } while (matchPunctuation(","));
        return from;
    }

    private AstNode parseTableRef() {
        StringBuilder name = new StringBuilder();
        int position = peek().position();
        boolean inline = peek().inlineHint();
        // 支持 schema.table 形式，information_schema.tables 是注入探测的标志
        while (!isAtEnd() && (peek().type() == TokenType.IDENTIFIER
                || peek().isKeyword("INFORMATION_SCHEMA"))) {
            name.append(advance().value());
            if (!isAtEnd() && peek().is(".")) {
                advance();
                name.append('.');
            } else {
                break;
            }
        }
        AstNode table = new AstNode(NodeType.TABLE_REF, name.toString());
        table.setSourcePosition(position);
        table.setFromInlineComment(inline);
        // 表别名
        if (!isAtEnd() && peek().isKeyword("AS")) {
            advance();
            if (!isAtEnd() && peek().type() == TokenType.IDENTIFIER) {
                advance();
            }
        } else if (!isAtEnd() && peek().type() == TokenType.IDENTIFIER && !isClauseBoundary()) {
            advance();
        }
        return table;
    }

    private boolean isJoinStart() {
        Token t = peek();
        return t.isKeyword("JOIN") || t.isKeyword("INNER") || t.isKeyword("LEFT")
                || t.isKeyword("RIGHT") || t.isKeyword("FULL") || t.isKeyword("CROSS");
    }

    private AstNode parseJoinClause() {
        StringBuilder kind = new StringBuilder();
        while (!isAtEnd() && isJoinStart()) {
            kind.append(advance().upper()).append(' ');
            if (!isAtEnd() && peek().isKeyword("OUTER")) {
                kind.append(advance().upper()).append(' ');
            }
            if (!isAtEnd() && peek().isKeyword("JOIN")) {
                kind.append(advance().upper());
                break;
            }
        }
        AstNode join = new AstNode(NodeType.JOIN_CLAUSE, kind.toString().trim());
        if (!isAtEnd()) {
            if (peek().is("(")) {
                advance();
                AstNode sub = new AstNode(NodeType.SUBQUERY);
                sub.addChild(parseSelectWithSetOperations());
                expect(")");
                join.addChild(sub);
            } else {
                join.addChild(parseTableRef());
            }
        }
        if (!isAtEnd() && peek().isKeyword("ON")) {
            advance();
            join.addChild(parseExpression());
        }
        return join;
    }

    private List<AstNode> parseOrderByItems() {
        List<AstNode> items = new ArrayList<>();
        do {
            if (isAtEnd()) {
                break;
            }
            AstNode expr = parseExpression();
            if (!isAtEnd() && (peek().isKeyword("ASC") || peek().isKeyword("DESC"))) {
                advance();
            }
            items.add(expr);
        } while (matchPunctuation(","));
        return items;
    }

    private AstNode parseLimitClause() {
        AstNode limit = new AstNode(NodeType.LIMIT_CLAUSE);
        advance(); // LIMIT 或 OFFSET
        while (!isAtEnd() && (peek().type() == TokenType.NUMBER
                || peek().type() == TokenType.PLACEHOLDER || peek().is(","))) {
            Token t = advance();
            if (!t.is(",")) {
                limit.addChild(new AstNode(
                        t.type() == TokenType.PLACEHOLDER ? NodeType.PLACEHOLDER : NodeType.LITERAL,
                        t.value()));
            }
        }
        if (!isAtEnd() && peek().isKeyword("OFFSET")) {
            advance();
            if (!isAtEnd()) {
                Token t = advance();
                limit.addChild(new AstNode(NodeType.LITERAL, t.value()));
            }
        }
        return limit;
    }

    private AstNode parseInsert() {
        AstNode insert = new AstNode(NodeType.INSERT_STATEMENT);
        advance(); // INSERT
        if (!isAtEnd() && peek().isKeyword("INTO")) {
            advance();
        }
        if (!isAtEnd()) {
            insert.addChild(parseTableRef());
        }
        // 列清单
        if (!isAtEnd() && peek().is("(")) {
            advance();
            AstNode cols = new AstNode(NodeType.SELECT_LIST);
            do {
                if (isAtEnd() || peek().is(")")) {
                    break;
                }
                Token t = advance();
                cols.addChild(new AstNode(NodeType.COLUMN_REF, t.value()));
            } while (matchPunctuation(","));
            expect(")");
            insert.addChild(cols);
        }
        if (!isAtEnd() && peek().isKeyword("VALUES")) {
            advance();
            AstNode values = new AstNode(NodeType.VALUES_CLAUSE);
            do {
                if (isAtEnd()) {
                    break;
                }
                if (peek().is("(")) {
                    advance();
                    values.addChildren(parseExpressionList());
                    expect(")");
                }
            } while (matchPunctuation(","));
            insert.addChild(values);
        } else if (!isAtEnd() && peek().isKeyword("SELECT")) {
            // INSERT ... SELECT
            insert.addChild(parseSelectWithSetOperations());
        }
        return insert;
    }

    private AstNode parseUpdate() {
        AstNode update = new AstNode(NodeType.UPDATE_STATEMENT);
        advance(); // UPDATE
        if (!isAtEnd()) {
            update.addChild(parseTableRef());
        }
        if (!isAtEnd() && peek().isKeyword("SET")) {
            advance();
            AstNode setClause = new AstNode(NodeType.SET_CLAUSE);
            do {
                if (isAtEnd() || peek().isKeyword("WHERE")) {
                    break;
                }
                setClause.addChild(parseExpression());
            } while (matchPunctuation(","));
            update.addChild(setClause);
        }
        if (!isAtEnd() && peek().isKeyword("WHERE")) {
            advance();
            AstNode where = new AstNode(NodeType.WHERE_CLAUSE);
            where.addChild(parseExpression());
            update.addChild(where);
        }
        return update;
    }

    private AstNode parseDelete() {
        AstNode del = new AstNode(NodeType.DELETE_STATEMENT);
        advance(); // DELETE
        if (!isAtEnd() && peek().isKeyword("FROM")) {
            advance();
        }
        if (!isAtEnd()) {
            del.addChild(parseTableRef());
        }
        if (!isAtEnd() && peek().isKeyword("WHERE")) {
            advance();
            AstNode where = new AstNode(NodeType.WHERE_CLAUSE);
            where.addChild(parseExpression());
            del.addChild(where);
        }
        return del;
    }

    private AstNode parseDdl() {
        Token kw = advance();
        AstNode ddl = new AstNode(NodeType.DDL_STATEMENT, kw.upper());
        ddl.setSourcePosition(kw.position());
        // DDL 的细节结构对注入检测意义有限，仅记录操作对象
        while (!isAtEnd() && !peek().is(";")) {
            Token t = advance();
            if (t.type() == TokenType.IDENTIFIER) {
                ddl.addChild(new AstNode(NodeType.TABLE_REF, t.value()));
            }
        }
        return ddl;
    }

    private AstNode parseUnknownFragment() {
        AstNode unknown = new AstNode(NodeType.UNKNOWN);
        if (!isAtEnd()) {
            Token t = advance();
            unknown.setValue(t.value());
            unknown.setSourcePosition(t.position());
        }
        return unknown;
    }

    // ==================== 表达式解析（按优先级从低到高）====================

    private AstNode parseExpression() {
        return parseOr();
    }

    /**
     * 解析 OR 表达式。
     *
     * <p>[关键安全逻辑] OR 是 SQL 注入最典型的结构特征。
     * {@code ' OR '1'='1} 之所以能绕过认证，正是因为它在 WHERE 子树中
     * 引入了一个新的 OR 节点，使原本的 AND 条件被旁路。
     * 本节点在结构差分中会被标注为 OR_INJECTION。
     */
    private AstNode parseOr() {
        if (guardDepth()) {
            return new AstNode(NodeType.UNKNOWN);
        }
        depth++;
        try {
            AstNode left = parseAnd();
            while (!isAtEnd() && (peek().isKeyword("OR") || peek().is("||"))) {
                Token op = advance();
                AstNode or = new AstNode(NodeType.OR_EXPRESSION, "OR");
                or.setSourcePosition(op.position());
                or.setFromInlineComment(op.inlineHint());
                or.addChild(left);
                or.addChild(parseAnd());
                left = or;
            }
            return left;
        } finally {
            depth--;
        }
    }

    private AstNode parseAnd() {
        AstNode left = parseNot();
        while (!isAtEnd() && (peek().isKeyword("AND") || peek().is("&&"))) {
            Token op = advance();
            AstNode and = new AstNode(NodeType.AND_EXPRESSION, "AND");
            and.setSourcePosition(op.position());
            and.setFromInlineComment(op.inlineHint());
            and.addChild(left);
            and.addChild(parseNot());
            left = and;
        }
        return left;
    }

    private AstNode parseNot() {
        if (!isAtEnd() && (peek().isKeyword("NOT") || peek().is("!"))) {
            Token op = advance();
            AstNode not = new AstNode(NodeType.NOT_EXPRESSION, "NOT");
            not.setSourcePosition(op.position());
            not.addChild(parseNot());
            return not;
        }
        return parsePredicate();
    }

    /** 解析谓词：比较、IN、LIKE、BETWEEN、IS NULL、EXISTS。 */
    private AstNode parsePredicate() {
        if (!isAtEnd() && peek().isKeyword("EXISTS")) {
            Token kw = advance();
            AstNode exists = new AstNode(NodeType.EXISTS_EXPRESSION, "EXISTS");
            exists.setSourcePosition(kw.position());
            if (!isAtEnd() && peek().is("(")) {
                advance();
                AstNode sub = new AstNode(NodeType.SUBQUERY);
                sub.addChild(parseSelectWithSetOperations());
                expect(")");
                exists.addChild(sub);
            }
            return exists;
        }

        AstNode left = parseAdditive();

        if (isAtEnd()) {
            return left;
        }

        Token t = peek();

        // NOT IN / NOT LIKE / NOT BETWEEN
        boolean negated = false;
        if (t.isKeyword("NOT")) {
            Token next = peekAt(1);
            if (next.isKeyword("IN") || next.isKeyword("LIKE") || next.isKeyword("BETWEEN")) {
                advance();
                negated = true;
                t = peek();
            }
        }

        if (t.isKeyword("IN")) {
            Token kw = advance();
            AstNode in = new AstNode(NodeType.IN_EXPRESSION, negated ? "NOT IN" : "IN");
            in.setSourcePosition(kw.position());
            in.addChild(left);
            if (!isAtEnd() && peek().is("(")) {
                advance();
                if (!isAtEnd() && peek().isKeyword("SELECT")) {
                    AstNode sub = new AstNode(NodeType.SUBQUERY);
                    sub.addChild(parseSelectWithSetOperations());
                    in.addChild(sub);
                } else {
                    in.addChildren(parseExpressionList());
                }
                expect(")");
            }
            return in;
        }

        if (t.isKeyword("LIKE")) {
            Token kw = advance();
            AstNode like = new AstNode(NodeType.LIKE_EXPRESSION, negated ? "NOT LIKE" : "LIKE");
            like.setSourcePosition(kw.position());
            like.addChild(left);
            like.addChild(parseAdditive());
            return like;
        }

        if (t.isKeyword("BETWEEN")) {
            Token kw = advance();
            AstNode between = new AstNode(NodeType.BETWEEN_EXPRESSION,
                    negated ? "NOT BETWEEN" : "BETWEEN");
            between.setSourcePosition(kw.position());
            between.addChild(left);
            between.addChild(parseAdditive());
            if (!isAtEnd() && peek().isKeyword("AND")) {
                advance();
                between.addChild(parseAdditive());
            }
            return between;
        }

        if (t.isKeyword("IS")) {
            Token kw = advance();
            boolean isNot = false;
            if (!isAtEnd() && peek().isKeyword("NOT")) {
                advance();
                isNot = true;
            }
            AstNode isNull = new AstNode(NodeType.IS_NULL_EXPRESSION,
                    isNot ? "IS NOT NULL" : "IS NULL");
            isNull.setSourcePosition(kw.position());
            isNull.addChild(left);
            if (!isAtEnd() && (peek().isKeyword("NULL") || peek().isKeyword("TRUE")
                    || peek().isKeyword("FALSE"))) {
                advance();
            }
            return isNull;
        }

        // 二元比较运算符
        if (t.type() == TokenType.OPERATOR && isComparisonOperator(t.value())) {
            Token op = advance();
            AstNode cmp = new AstNode(NodeType.COMPARISON, op.value());
            cmp.setSourcePosition(op.position());
            cmp.setFromInlineComment(op.inlineHint());
            cmp.addChild(left);
            cmp.addChild(parseAdditive());
            return cmp;
        }

        return left;
    }

    private boolean isComparisonOperator(String op) {
        return switch (op) {
            case "=", "!=", "<>", "<", ">", "<=", ">=", "<=>" -> true;
            default -> false;
        };
    }

    private AstNode parseAdditive() {
        AstNode left = parseMultiplicative();
        while (!isAtEnd() && peek().type() == TokenType.OPERATOR
                && (peek().is("+") || peek().is("-") || peek().is("||"))) {
            Token op = advance();
            AstNode arith = new AstNode(NodeType.ARITHMETIC, op.value());
            arith.setSourcePosition(op.position());
            arith.addChild(left);
            arith.addChild(parseMultiplicative());
            left = arith;
        }
        return left;
    }

    private AstNode parseMultiplicative() {
        AstNode left = parseUnary();
        while (!isAtEnd() && peek().type() == TokenType.OPERATOR
                && (peek().is("*") || peek().is("/") || peek().is("%"))) {
            Token op = advance();
            AstNode arith = new AstNode(NodeType.ARITHMETIC, op.value());
            arith.setSourcePosition(op.position());
            arith.addChild(left);
            arith.addChild(parseUnary());
            left = arith;
        }
        return left;
    }

    private AstNode parseUnary() {
        if (!isAtEnd() && peek().type() == TokenType.OPERATOR
                && (peek().is("-") || peek().is("+") || peek().is("~"))) {
            Token op = advance();
            AstNode unary = new AstNode(NodeType.ARITHMETIC, "u" + op.value());
            unary.setSourcePosition(op.position());
            unary.addChild(parseUnary());
            return unary;
        }
        return parsePrimary();
    }

    /** 解析基本单元：字面量、列引用、函数调用、括号表达式、子查询、CASE。 */
    private AstNode parsePrimary() {
        if (isAtEnd()) {
            return new AstNode(NodeType.UNKNOWN);
        }
        if (guardDepth()) {
            return new AstNode(NodeType.UNKNOWN);
        }
        depth++;
        try {
            Token t = peek();

            // 括号：可能是子查询或分组表达式
            if (t.is("(")) {
                advance();
                AstNode node;
                if (!isAtEnd() && peek().isKeyword("SELECT")) {
                    node = new AstNode(NodeType.SUBQUERY);
                    node.addChild(parseSelectWithSetOperations());
                } else {
                    node = parseExpression();
                }
                expect(")");
                return node;
            }

            if (t.isKeyword("CASE")) {
                return parseCase();
            }

            if (t.type() == TokenType.STRING) {
                advance();
                AstNode lit = new AstNode(NodeType.LITERAL, t.value());
                lit.setSourcePosition(t.position());
                lit.setFromInlineComment(t.inlineHint());
                return lit;
            }

            if (t.type() == TokenType.NUMBER || t.type() == TokenType.HEX_LITERAL) {
                advance();
                AstNode lit = new AstNode(NodeType.LITERAL, t.value());
                lit.setSourcePosition(t.position());
                lit.setFromInlineComment(t.inlineHint());
                return lit;
            }

            if (t.type() == TokenType.PLACEHOLDER) {
                advance();
                AstNode ph = new AstNode(NodeType.PLACEHOLDER, "?");
                ph.setSourcePosition(t.position());
                return ph;
            }

            if (t.isKeyword("NULL") || t.isKeyword("TRUE") || t.isKeyword("FALSE")) {
                advance();
                AstNode lit = new AstNode(NodeType.LITERAL, t.upper());
                lit.setSourcePosition(t.position());
                return lit;
            }

            if (t.is("*")) {
                advance();
                return new AstNode(NodeType.WILDCARD, "*");
            }

            if (t.type() == TokenType.IDENTIFIER || t.type() == TokenType.KEYWORD) {
                return parseIdentifierOrFunction();
            }

            // 未识别：消耗一个词法单元，保证解析继续推进
            advance();
            AstNode unknown = new AstNode(NodeType.UNKNOWN, t.value());
            unknown.setSourcePosition(t.position());
            return unknown;
        } finally {
            depth--;
        }
    }

    /**
     * 解析标识符或函数调用。
     *
     * <p>[关键安全逻辑] 函数名在归一化阶段会被<b>完整保留</b>。
     * SLEEP、BENCHMARK、LOAD_FILE、EXTRACTVALUE 等函数是时间盲注与带外注入的
     * 核心标志，若将其一并归一化会造成最危险一类攻击的漏报。
     */
    private AstNode parseIdentifierOrFunction() {
        Token first = advance();
        StringBuilder name = new StringBuilder(first.value());
        int position = first.position();
        boolean inline = first.inlineHint();

        // 限定名：schema.table.column
        while (!isAtEnd() && peek().is(".")) {
            advance();
            if (!isAtEnd() && (peek().type() == TokenType.IDENTIFIER || peek().is("*"))) {
                name.append('.').append(advance().value());
            } else {
                break;
            }
        }

        // 函数调用：标识符后紧跟左括号
        if (!isAtEnd() && peek().is("(")) {
            advance();
            AstNode func = new AstNode(NodeType.FUNCTION_CALL, name.toString().toUpperCase());
            func.setSourcePosition(position);
            func.setFromInlineComment(inline);
            if (!isAtEnd() && !peek().is(")")) {
                if (peek().isKeyword("SELECT")) {
                    AstNode sub = new AstNode(NodeType.SUBQUERY);
                    sub.addChild(parseSelectWithSetOperations());
                    func.addChild(sub);
                } else if (peek().is("*")) {
                    advance();
                    func.addChild(new AstNode(NodeType.WILDCARD, "*"));
                } else {
                    // DISTINCT 修饰（如 COUNT(DISTINCT x)）
                    if (peek().isKeyword("DISTINCT") || peek().isKeyword("ALL")) {
                        advance();
                    }
                    func.addChildren(parseExpressionList());
                }
            }
            expect(")");
            return func;
        }

        AstNode col = new AstNode(NodeType.COLUMN_REF, name.toString());
        col.setSourcePosition(position);
        col.setFromInlineComment(inline);
        return col;
    }

    private AstNode parseCase() {
        Token kw = advance(); // CASE
        AstNode caseNode = new AstNode(NodeType.CASE_EXPRESSION, "CASE");
        caseNode.setSourcePosition(kw.position());
        // 简单 CASE：CASE expr WHEN ...
        if (!isAtEnd() && !peek().isKeyword("WHEN")) {
            caseNode.addChild(parseExpression());
        }
        while (!isAtEnd() && peek().isKeyword("WHEN")) {
            advance();
            caseNode.addChild(parseExpression());
            if (!isAtEnd() && peek().isKeyword("THEN")) {
                advance();
                caseNode.addChild(parseExpression());
            }
        }
        if (!isAtEnd() && peek().isKeyword("ELSE")) {
            advance();
            caseNode.addChild(parseExpression());
        }
        if (!isAtEnd() && peek().isKeyword("END")) {
            advance();
        }
        return caseNode;
    }

    private List<AstNode> parseExpressionList() {
        List<AstNode> list = new ArrayList<>();
        do {
            if (isAtEnd() || peek().is(")")) {
                break;
            }
            list.add(parseExpression());
        } while (matchPunctuation(","));
        return list;
    }

    // ==================== 词法单元游标操作 ====================

    private Token peek() {
        return index < tokens.size() ? tokens.get(index)
                : new Token(TokenType.EOF, "", "", index, false);
    }

    private Token peekAt(int offset) {
        int i = index + offset;
        return i < tokens.size() ? tokens.get(i)
                : new Token(TokenType.EOF, "", "", i, false);
    }

    private Token advance() {
        Token t = peek();
        if (index < tokens.size()) {
            index++;
        }
        return t;
    }

    private boolean isAtEnd() {
        return index >= tokens.size() || peek().isEof();
    }

    private boolean matchPunctuation(String p) {
        if (!isAtEnd() && peek().is(p)) {
            advance();
            return true;
        }
        return false;
    }

    /** 期望某个标点；缺失时不抛异常（容错解析），保证攻击载荷也能被分析。 */
    private void expect(String p) {
        if (!isAtEnd() && peek().is(p)) {
            advance();
        }
    }

    private void skipSemicolons() {
        while (!isAtEnd() && peek().is(";")) {
            advance();
        }
    }

    /** 判断当前词法单元是否为子句边界关键字，用于别名识别时避免误吞。 */
    private boolean isClauseBoundary() {
        Token t = peek();
        return t.isKeyword("FROM") || t.isKeyword("WHERE") || t.isKeyword("GROUP")
                || t.isKeyword("ORDER") || t.isKeyword("HAVING") || t.isKeyword("LIMIT")
                || t.isKeyword("UNION") || t.isKeyword("JOIN") || t.isKeyword("ON")
                || t.isKeyword("SET") || t.isKeyword("VALUES");
    }

    private boolean guardDepth() {
        return depth >= MAX_DEPTH;
    }
}
