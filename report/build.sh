#!/usr/bin/env bash
# ============================================================
#  AEGIS 综合设计报告 · 编译脚本
#
#  用法：
#    ./build.sh          完整编译（含参考文献）
#    ./build.sh quick    快速编译（跳过参考文献处理）
#    ./build.sh clean    清理中间文件
# ============================================================
set -u

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

MODE="${1:-full}"
OUT="build"

case "$MODE" in
  clean)
    rm -rf "$OUT"
    echo "[✓] 已清理构建目录"
    exit 0
    ;;
  quick)
    mkdir -p "$OUT"
    echo "[*] 快速编译..."
    xelatex -interaction=nonstopmode -output-directory="$OUT" main.tex > /dev/null 2>&1
    ;;
  full)
    mkdir -p "$OUT"
    echo "[*] 第一遍编译（生成辅助文件）..."
    xelatex -interaction=nonstopmode -output-directory="$OUT" main.tex > /dev/null 2>&1

    echo "[*] 处理参考文献..."
    biber --output-directory="$OUT" main > /dev/null 2>&1

    echo "[*] 第二遍编译（解析引用）..."
    xelatex -interaction=nonstopmode -output-directory="$OUT" main.tex > /dev/null 2>&1

    echo "[*] 第三遍编译（稳定交叉引用与目录）..."
    xelatex -interaction=nonstopmode -output-directory="$OUT" main.tex > /dev/null 2>&1
    ;;
  *)
    echo "未知参数：$MODE（可选 full / quick / clean）"
    exit 1
    ;;
esac

if [ ! -f "$OUT/main.pdf" ]; then
  echo "[✗] 编译失败，请检查 $OUT/main.log"
  exit 1
fi

# 提取关键信息
PAGES=$(grep -oP 'Output written on .*\((\d+) pages' "$OUT/main.log" 2>/dev/null \
        | grep -oP '\d+(?= pages)' | tail -1)
SIZE=$(du -h "$OUT/main.pdf" | cut -f1)

# 检查未解析的引用与残缺的交叉引用
# 使用 tr 归并多行输出，避免 grep -c 在特定情形下返回多行导致比较失败
UNDEF=$(grep -c "Warning: Citation.*undefined\|Warning: Reference.*undefined" \
        "$OUT/main.log" 2>/dev/null | head -1 | tr -d '[:space:]')
UNDEF=${UNDEF:-0}

echo ""
echo "=========================================="
echo "  编译完成"
echo "=========================================="
echo "  输出文件 : $OUT/main.pdf"
echo "  页数     : ${PAGES:-未知}"
echo "  文件大小 : $SIZE"
if [ "$UNDEF" -gt 0 ]; then
  echo "  ⚠ 未解析引用: $UNDEF 处（建议执行完整编译）"
else
  echo "  引用状态 : 全部解析正常"
fi
echo "=========================================="
