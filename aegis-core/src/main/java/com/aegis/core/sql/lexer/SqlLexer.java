package com.aegis.core.sql.lexer;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * [SEC-SQLI-01] SQL 词法分析器
 *
 * <p><b>安全原理：</b>
 * 词法分析是语义检测的第一道关口。攻击者常用注释拆分（{@code UNI/**}{@code /ON}）、
 * MySQL 可执行内联注释（<code>/*!50000UNION*&#47;</code>）、大小写混淆、多余空白等手法
 * 破坏攻击特征串的连续性，从而绕过基于正则的文本匹配。
 *
 * <p>本词法器在切分阶段即消解这些混淆：普通注释被识别为独立词法单元并在后续
 * 过滤中丢弃，使被拆分的关键字重新连接；MySQL 内联注释的<b>内容被保留</b>为正常
 * 词法单元（因为 MySQL 会真实执行其内容，若整体��弃将导致严重漏报），同时打上
 * {@code inlineHint} 标记作为高风险信号。
 *
 * <p>由此，无论攻击者如何在文本层面变形，进入语法分析阶段的词法单元序列都是
 * 规范化的，后续的结构判定不受文本形态影响。
 *
 * <p><b>威胁对应：</b>T-01 SQL 注入（STRIDE: Tampering, DREAD 9.0）、
 * T-12 检测绕过（DREAD 8.0）
 *
 * <p><b>设计说明：</b>本类为自研实现而非直接使用第三方解析器，原因是需要完全掌控
 * 注释处理策略与词法单元的溯源信息（位置、内联标记），这些是结构差分定位与
 * 可视化取证的必要输入。
 */
public final class SqlLexer {

    /** SQL 保留关键字集合。用于区分标识符与关键字，影响语法分析路径。 */
    private static final Set<String> KEYWORDS = Set.of(
            "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "LIKE", "BETWEEN",
            "IS", "NULL", "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET",
            "UNION", "ALL", "DISTINCT", "AS", "JOIN", "INNER", "LEFT", "RIGHT",
            "FULL", "OUTER", "CROSS", "ON", "INSERT", "INTO", "VALUES", "UPDATE",
            "SET", "DELETE", "CREATE", "DROP", "ALTER", "TABLE", "DATABASE",
            "INDEX", "VIEW", "TRUE", "FALSE", "CASE", "WHEN", "THEN", "ELSE",
            "END", "EXISTS", "ASC", "DESC", "INTERSECT", "EXCEPT", "MINUS",
            "PROCEDURE", "FUNCTION", "DECLARE", "IF", "WHILE", "FOR", "LOOP",
            "GRANT", "REVOKE", "COMMIT", "ROLLBACK", "OUTFILE", "DUMPFILE",
            "LOAD_FILE", "INFORMATION_SCHEMA"
    );

    /** 多字符运算符，必须优先于单字符匹配，否则 {@code <=} 会被切成 {@code <} 和 {@code =}。 */
    private static final String[] MULTI_CHAR_OPERATORS = {
            "<=>", "!=", "<>", "<=", ">=", "||", "&&", "<<", ">>", ":="
    };

    private final String source;
    private int pos;

    public SqlLexer(String source) {
        this.source = source == null ? "" : source;
        this.pos = 0;
    }

    /**
     * 执行词法分析，返回全部词法单元（含 EOF）。
     *
     * @return 词法单元列表，注释以 COMMENT 类型保留，由调用方决定是否过滤
     */
    public List<Token> tokenize() {
        List<Token> tokens = new ArrayList<>();
        while (true) {
            skipWhitespace();
            if (pos >= source.length()) {
                tokens.add(Token.of(TokenType.EOF, "", pos));
                break;
            }

            char c = source.charAt(pos);
            int start = pos;

            // 注释处理必须最先进行：注释内可能包含任意字符，
            // 若先按其他规则切分会产生错误的词法单元
            if (c == '-' && peek(1) == '-') {
                tokens.add(readLineComment("--"));
            } else if (c == '#') {
                tokens.add(readLineComment("#"));
            } else if (c == '/' && peek(1) == '*') {
                readBlockComment(tokens);
            } else if (c == '\'' || c == '"' || c == '`') {
                tokens.add(readQuoted(c));
            } else if (Character.isDigit(c)) {
                tokens.add(readNumber());
            } else if (c == '.' && Character.isDigit(peek(1))) {
                tokens.add(readNumber());
            } else if (isIdentifierStart(c)) {
                tokens.add(readWord());
            } else if (c == '?') {
                pos++;
                tokens.add(Token.of(TokenType.PLACEHOLDER, "?", start));
            } else if (c == ':' && isIdentifierStart(peek(1))) {
                tokens.add(readNamedPlaceholder());
            } else if (c == '@') {
                tokens.add(readVariable());
            } else {
                Token op = readOperatorOrPunctuation();
                if (op != null) {
                    tokens.add(op);
                } else {
                    // 无法识别的字符：跳过以保证解析继续，避免因单个异常字符
                    // 导致整条语句无法分析（可用性优先原则）
                    pos++;
                }
            }
        }
        return tokens;
    }

    /**
     * 返回过滤掉普通注释、并完成关键字粘合后的词法单元序列。
     *
     * <p>这是语法分析器的实际输入。
     */
    public List<Token> tokenizeEffective() {
        List<Token> all = tokenize();
        List<Token> effective = new ArrayList<>(all.size());
        for (Token t : all) {
            if (t.type() != TokenType.COMMENT) {
                effective.add(t);
            }
        }
        return weldSplitKeywords(effective, all);
    }

    /**
     * [关键安全逻辑] 注释边界关键字粘合。
     *
     * <p><b>问题背景：</b>攻击载荷 {@code UNI/*}{@code *}{@code /ON} 在词法阶段会被切分为
     * {@code IDENTIFIER(UNI)} 与 {@code KEYWORD(ON)} 两个独立单元——因为注释
     * 中断了单词的连续读取。此时 UNION 语义丢失，注入将被漏报。
     *
     * <p><b>处置策略：</b>安全检测必须采取<b>最保守假设</b>。虽然标准 MySQL 会拒绝
     * 执行这种拆分形式，但不同数据库、连接池、ORM 中间件对注释的预处理行为
     * 存在差异，某些组合会先剥离注释再执行，使 UNION 复原生效。因此本方法
     * 在注释处剥离位置尝试将相邻标识符拼接，若拼接结果构成 SQL 关键字，
     * 则判定攻击者意图为该关键字并完成粘合。
     *
     * <p>该策略遵循"宁可按攻击成功处理，不可假设攻击失败"的安全原则，
     * 与解析失败降级为可疑的思路一致。
     *
     * @param effective 已剔除注释的词法单元序列
     * @param all       含注释的完整序列，用于判定拆分位置
     * @return 完成关键字粘合的词法单元序列
     */
    private List<Token> weldSplitKeywords(List<Token> effective, List<Token> all) {
        // 收集所有被注释中断的位置：注释左右紧邻且中间无空白的词法单元对
        Set<Integer> weldPositions = new java.util.HashSet<>();
        for (int i = 1; i < all.size() - 1; i++) {
            Token comment = all.get(i);
            if (comment.type() != TokenType.COMMENT) {
                continue;
            }
            Token prev = all.get(i - 1);
            Token next = all.get(i + 1);
            // 注释紧贴前一单元的末尾，且紧贴后一单元的开头，说明它切断了一个单词
            boolean tightLeft = prev.position() + prev.value().length() == comment.position();
            boolean tightRight = comment.position() + comment.value().length() == next.position();
            if (tightLeft && tightRight
                    && isWordLike(prev) && isWordLike(next)) {
                weldPositions.add(prev.position());
            }
        }
        if (weldPositions.isEmpty()) {
            return effective;
        }

        List<Token> welded = new ArrayList<>(effective.size());
        int i = 0;
        while (i < effective.size()) {
            Token current = effective.get(i);
            if (weldPositions.contains(current.position()) && i + 1 < effective.size()) {
                Token next = effective.get(i + 1);
                String merged = current.value() + next.value();
                String mergedUpper = merged.toUpperCase();
                if (KEYWORDS.contains(mergedUpper)) {
                    // 拼接后构成关键字，判定为注释拆分混淆，完成粘合
                    welded.add(new Token(TokenType.KEYWORD, merged, mergedUpper,
                            current.position(), true));
                    i += 2;
                    continue;
                }
            }
            welded.add(current);
            i++;
        }
        return welded;
    }

    /** 判断词法单元是否为可参与粘合的单词型单元（标识符或关键字）。 */
    private boolean isWordLike(Token t) {
        return t.type() == TokenType.IDENTIFIER || t.type() == TokenType.KEYWORD;
    }

    // ==================== 各类词法单元的读取 ====================

    private void skipWhitespace() {
        while (pos < source.length() && Character.isWhitespace(source.charAt(pos))) {
            pos++;
        }
    }

    private char peek(int offset) {
        int i = pos + offset;
        return i < source.length() ? source.charAt(i) : '\0';
    }

    private boolean isIdentifierStart(char c) {
        return Character.isLetter(c) || c == '_' || c == '$'
                // 允许非 ASCII 字母，支持中文表名/列名
                || Character.isUnicodeIdentifierStart(c);
    }

    private boolean isIdentifierPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$'
                || Character.isUnicodeIdentifierPart(c);
    }

    /** 读取行注释（-- 或 #），直到行尾。 */
    private Token readLineComment(String prefix) {
        int start = pos;
        pos += prefix.length();
        while (pos < source.length() && source.charAt(pos) != '\n' && source.charAt(pos) != '\r') {
            pos++;
        }
        return Token.of(TokenType.COMMENT, source.substring(start, pos), start);
    }

    /**
     * 读取块注释。
     *
     * <p>[关键安全逻辑] 区分两种块注释：
     * <ul>
     *   <li>普通注释 <code>/*...*&#47;</code>：整体作为 COMMENT 丢弃，使被拆分的关键字复原</li>
     *   <li>MySQL 可执行注释 <code>/*!...*&#47;</code>：其内容<b>会被 MySQL 真实执行</b>，
     *       因此必须递归切分内容并作为正常词法单元加入序列，同时标记 inlineHint。
     *       若此处将其整体丢弃，攻击载荷 <code>/*!50000UNION*&#47;SELECT</code>
     *       将退化为无害文本，造成严重漏报。</li>
     * </ul>
     */
    private void readBlockComment(List<Token> tokens) {
        int start = pos;
        pos += 2; // 跳过 /*

        boolean executable = pos < source.length() && source.charAt(pos) == '!';
        if (executable) {
            pos++; // 跳过 !
            // MySQL 版本号前缀（如 50000）不参与语义，跳过
            while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                pos++;
            }
        }

        int contentStart = pos;
        while (pos < source.length() && !(source.charAt(pos) == '*' && peek(1) == '/')) {
            pos++;
        }
        int contentEnd = pos;
        if (pos < source.length()) {
            pos += 2; // 跳过 */
        }

        if (executable) {
            // 递归切分可执行注释的内容，标记为内联来源
            String content = source.substring(contentStart, contentEnd);
            List<Token> inner = new SqlLexer(content).tokenizeEffective();
            for (Token t : inner) {
                if (!t.isEof()) {
                    tokens.add(new Token(t.type(), t.value(), t.upper(),
                            contentStart + t.position(), true));
                }
            }
        } else {
            tokens.add(Token.of(TokenType.COMMENT, source.substring(start, pos), start));
        }
    }

    /**
     * 读取引号包围的内容。
     *
     * <p>单/双引号为字符串字面量，反引号为标识符（MySQL 风格）。
     * 需处理反斜杠转义与双写引号转义两种形式。
     */
    private Token readQuoted(char quote) {
        int start = pos;
        pos++; // 跳过起始引号
        StringBuilder sb = new StringBuilder();
        while (pos < source.length()) {
            char c = source.charAt(pos);
            if (c == '\\' && pos + 1 < source.length()) {
                // 反斜杠转义：\' \" \\ 等
                sb.append(source.charAt(pos + 1));
                pos += 2;
            } else if (c == quote) {
                if (peek(1) == quote) {
                    // 双写转义：'' 表示一个引号
                    sb.append(quote);
                    pos += 2;
                } else {
                    pos++; // 结束引号
                    break;
                }
            } else {
                sb.append(c);
                pos++;
            }
        }
        TokenType type = (quote == '`') ? TokenType.IDENTIFIER : TokenType.STRING;
        return Token.of(type, sb.toString(), start);
    }

    /** 读取数值字面量，兼容十六进制、小数与科学计数法。 */
    private Token readNumber() {
        int start = pos;
        // 十六进制：0x41424344 常用于绕过字符串过滤
        if (source.charAt(pos) == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
            pos += 2;
            while (pos < source.length() && isHexDigit(source.charAt(pos))) {
                pos++;
            }
            return Token.of(TokenType.HEX_LITERAL, source.substring(start, pos), start);
        }
        while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
            pos++;
        }
        if (pos < source.length() && source.charAt(pos) == '.') {
            pos++;
            while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                pos++;
            }
        }
        // 科学计数法
        if (pos < source.length() && (source.charAt(pos) == 'e' || source.charAt(pos) == 'E')) {
            int save = pos;
            pos++;
            if (pos < source.length() && (source.charAt(pos) == '+' || source.charAt(pos) == '-')) {
                pos++;
            }
            if (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                    pos++;
                }
            } else {
                pos = save; // 回溯：e 不属于数值
            }
        }
        return Token.of(TokenType.NUMBER, source.substring(start, pos), start);
    }

    private boolean isHexDigit(char c) {
        return Character.isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /** 读取单词，并判定其为关键字还是标识符。 */
    private Token readWord() {
        int start = pos;
        while (pos < source.length() && isIdentifierPart(source.charAt(pos))) {
            pos++;
        }
        String word = source.substring(start, pos);
        String upper = word.toUpperCase();
        // 大小写折叠在此完成，uNiOn 与 UNION 归为同一关键字
        TokenType type = KEYWORDS.contains(upper) ? TokenType.KEYWORD : TokenType.IDENTIFIER;
        return Token.of(type, word, start);
    }

    /** 读取具名占位符 :name。 */
    private Token readNamedPlaceholder() {
        int start = pos;
        pos++; // 跳过 :
        while (pos < source.length() && isIdentifierPart(source.charAt(pos))) {
            pos++;
        }
        return Token.of(TokenType.PLACEHOLDER, source.substring(start, pos), start);
    }

    /** 读取系统变量 @@version / 用户变量 @x，常用于数据库指纹探测。 */
    private Token readVariable() {
        int start = pos;
        pos++; // 跳过 @
        if (pos < source.length() && source.charAt(pos) == '@') {
            pos++;
        }
        while (pos < source.length() && isIdentifierPart(source.charAt(pos))) {
            pos++;
        }
        return Token.of(TokenType.IDENTIFIER, source.substring(start, pos), start);
    }

    /** 读取运算符或标点，多字符运算符优先匹配。 */
    private Token readOperatorOrPunctuation() {
        int start = pos;
        for (String op : MULTI_CHAR_OPERATORS) {
            if (source.startsWith(op, pos)) {
                pos += op.length();
                return Token.of(TokenType.OPERATOR, op, start);
            }
        }
        char c = source.charAt(pos);
        if ("=<>+-*/%!~^&|".indexOf(c) >= 0) {
            pos++;
            return Token.of(TokenType.OPERATOR, String.valueOf(c), start);
        }
        if ("(),;.[]{}".indexOf(c) >= 0) {
            pos++;
            return Token.of(TokenType.PUNCTUATION, String.valueOf(c), start);
        }
        return null;
    }
}
