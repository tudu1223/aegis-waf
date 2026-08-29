package com.aegis.core.sql.risk;

/**
 * SQL 风险特征。
 *
 * <p>这些特征作用于<b>已解析的语法树结构</b>，而非原始文本的正则匹配，
 * 这是与传统 WAF 规则集的本质区别。特征用于两个场景：
 * <ul>
 *   <li><b>冷启动兜底</b>：系统刚部署或遇到新接口时基线为空，
 *       此时不能"一律拦截"（会阻断正常业务）也不能"一律放行"（形同虚设），
 *       需要一套不依赖基线的绝对判定规则。</li>
 *   <li><b>风险加权</b>：与结构差分结果共同构成综合风险评分。</li>
 * </ul>
 */
public enum RiskFeature {

    /** R-01 恒真式：比较表达式两侧归一化后恒等 */
    TAUTOLOGY("R-01", "恒真条件", 40,
            "查询中包含恒真比较表达式，是认证绕过的典型特征"),

    /** R-02 UNION 联合查询 */
    UNION_QUERY("R-02", "联合查询", 45,
            "使用 UNION 集合运算，可跨表读取任意数据"),

    /** R-03 堆叠查询 */
    STACKED_QUERY("R-03", "堆叠查询", 50,
            "单次请求包含多条语句，可执行任意 SQL 命令"),

    /** R-04 注释截断 */
    COMMENT_TRUNCATION("R-04", "注释截断", 35,
            "使用注释符截断语句，剥离原有查询条件"),

    /** R-05 时间盲注函数 */
    TIME_BLIND_FUNCTION("R-05", "时间盲注函数", 50,
            "调用 SLEEP/BENCHMARK 等延时函数，用于盲注推断数据"),

    /** R-06 带外与文件操作函数 */
    OUT_OF_BAND_FUNCTION("R-06", "带外/文件函数", 50,
            "调用 LOAD_FILE/EXTRACTVALUE 等函数，用于数据外带或文件读写"),

    /** R-07 系统表访问 */
    SYSTEM_TABLE("R-07", "系统表访问", 45,
            "访问 information_schema 等元数据表，属于注入信息收集阶段"),

    /** R-08 布尔盲注模式 */
    BOOLEAN_BLIND("R-08", "布尔盲注", 35,
            "条件中嵌套子查询比较，用于逐位推断数据"),

    /** R-09 编码绕过：十六进制字面量或 CHAR 拼接 */
    ENCODING_EVASION("R-09", "编码绕过", 25,
            "使用十六进制或字符编码函数构造字符串，规避关键字匹配"),

    /** R-10 过度编码 */
    EXCESSIVE_ENCODING("R-10", "过度编码", 20,
            "载荷经过多重编码，正常业务请求不应出现此特征"),

    /** R-11 逻辑运算符异常增多 */
    EXCESSIVE_LOGIC_OPERATORS("R-11", "逻辑运算异常", 20,
            "布尔运算符数量显著超出正常业务查询水平"),

    /** R-12 版本与数据库指纹探测 */
    VERSION_PROBE("R-12", "指纹探测", 30,
            "查询数据库版本或当前用户，属于攻击前的信息收集"),

    /** R-13 内联注释混淆 */
    INLINE_COMMENT("R-13", "内联注释混淆", 30,
            "使用 MySQL 可执行注释隐藏关键字，规避文本特征匹配"),

    /** R-14 解析失败 */
    PARSE_FAILURE("R-14", "语法解析异常", 20,
            "语句无法完整解析，可能为畸形构造的攻击载荷"),

    /** R-15 DDL 操作 */
    DDL_OPERATION("R-15", "结构变更操作", 45,
            "查询接口中出现 DROP/ALTER 等结构变更语句");

    private final String code;
    private final String displayName;
    private final int weight;
    private final String description;

    RiskFeature(String code, String displayName, int weight, String description) {
        this.code = code;
        this.displayName = displayName;
        this.weight = weight;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getWeight() {
        return weight;
    }

    public String getDescription() {
        return description;
    }
}
