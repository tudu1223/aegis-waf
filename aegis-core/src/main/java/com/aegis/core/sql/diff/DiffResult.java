package com.aegis.core.sql.diff;

import java.util.List;

/**
 * 结构差分结果。
 *
 * @param matched       指纹是否与基线一致
 * @param similarity    结构相似度（Jaccard 系数，0–1）
 * @param annotations   变异节点的语义标注列表
 * @param addedPaths    新增的节点路径签名
 * @param removedPaths  缺失的节点路径签名
 * @param hasBaseline   是否存在可比对的基线
 */
public record DiffResult(
        boolean matched,
        double similarity,
        List<DiffAnnotation> annotations,
        List<String> addedPaths,
        List<String> removedPaths,
        boolean hasBaseline
) {

    /** 基线命中，结构完全一致。 */
    public static DiffResult ofMatched() {
        return new DiffResult(true, 1.0, List.of(), List.of(), List.of(), true);
    }

    /** 无基线可比对，仅依赖风险特征判定。 */
    public static DiffResult ofNoBaseline() {
        return new DiffResult(false, 0.0, List.of(), List.of(), List.of(), false);
    }

    /** 是否存在达到严重级别的结构变异。 */
    public boolean hasCriticalAnnotation() {
        return annotations.stream().anyMatch(a -> a.kind().isCritical());
    }

    /** 变异标注对风险评分的累计贡献。 */
    public int annotationScore() {
        return annotations.stream().mapToInt(a -> a.kind().getWeight()).sum();
    }

    /**
     * 单条变异标注。
     *
     * @param kind     变异语义分类
     * @param path     节点在语法树中的路径签名
     * @param snippet  对应的 SQL 片段
     * @param detail   面向用户的说明文字
     */
    public record DiffAnnotation(
            DiffKind kind,
            String path,
            String snippet,
            String detail
    ) {
        public static DiffAnnotation of(DiffKind kind, String path, String snippet) {
            return new DiffAnnotation(kind, path, snippet, kind.getDescription());
        }
    }
}
