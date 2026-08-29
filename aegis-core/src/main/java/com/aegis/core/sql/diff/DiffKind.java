package com.aegis.core.sql.diff;

/**
 * 结构变异的语义分类。
 *
 * <p>结构差分算法在检出"指纹失配"后，需进一步回答"变在哪里、意味着什么"。
 * 本枚举将新增/缺失的语法节点映射为具有安全语义的攻击手法分类，
 * 既作为取证依据，也是前端可视化的标注来源。
 */
public enum DiffKind {

    /** 恒真式：新增的比较表达式两侧归一化后恒等，如 {@code '1'='1'} */
    TAUTOLOGY("恒真式绕过", "新增恒真比较表达式，使查询条件恒成立", 40),

    /** OR 逻辑注入：WHERE 子树新增 OR 节点，原有条件被旁路 */
    OR_INJECTION("OR 逻辑注入", "WHERE 子句中新增 OR 逻辑运算，原有条件被旁路", 40),

    /** UNION 联合查询注入：用于跨表脱库 */
    UNION_INJECTION("UNION 联合查询", "新增集合运算，可跨表读取任意数据", 40),

    /** 堆叠查询：单次请求执行多条语句 */
    STACKED_QUERY("堆叠查询", "解析出多条语句，可执行任意 SQL 命令", 40),

    /** 注释截断：尾部注释使原有条件失效 */
    COMMENT_TRUNCATION("注释截断", "使用注释截断原有语句结构，剥离后续条件", 25),

    /** 危险函数调用：时间盲注、带外注入、文件读写 */
    DANGEROUS_FUNCTION("危险函数调用", "调用了时间盲注、带外注入或文件操作类函数", 40),

    /** 子查询注入 */
    SUBQUERY_INJECTION("子查询注入", "新增嵌套子查询结构", 25),

    /** 条件被剥离：原有的 WHERE 约束消失，可导致全表数据泄露 */
    CONDITION_REMOVED("条件剥离", "原有查询条件缺失，可能导致全表数据泄露", 25),

    /** 投影列扩展：SELECT 列数增加 */
    COLUMN_EXPANSION("投影列扩展", "查询列数量增加，可能扩大数据暴露范围", 10),

    /** 系统表访问：information_schema 等元数据表 */
    SYSTEM_TABLE_ACCESS("系统表访问", "访问数据库元数据表，属于信息收集行为", 40),

    /** 内联注释混淆：MySQL 可执行注释 */
    INLINE_COMMENT_EVASION("内联注释混淆", "使用 MySQL 可执行注释隐藏攻击载荷", 25),

    /** 结构新增（未归入以上分类的通用变异） */
    STRUCTURE_ADDED("结构新增", "语法树中出现基线之外的结构节点", 10),

    /** 结构缺失 */
    STRUCTURE_REMOVED("结构缺失", "基线中的结构节点在实际语句中缺失", 10);

    private final String displayName;
    private final String description;
    private final int weight;

    DiffKind(String displayName, String description, int weight) {
        this.displayName = displayName;
        this.description = description;
        this.weight = weight;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /** 该变异类型对综合风险评分的贡献权重。 */
    public int getWeight() {
        return weight;
    }

    /** 是否属于确定性的攻击标志（权重达到最高级别）。 */
    public boolean isCritical() {
        return weight >= 40;
    }
}
