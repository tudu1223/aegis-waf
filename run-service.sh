#!/usr/bin/env bash
# 启动单个 AEGIS 服务（供后台任务调用）
# 用法: ./run-service.sh <console|target|gateway> [标签]
set -u
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE"
JAVA="${AEGIS_JDK17:-C:/Program Files/Eclipse Adoptium/jdk-17.0.19.10-hotspot}/bin/java"
SVC="$1"
TAG="${2:-$(date +%H%M%S)}"
mkdir -p logs

case "$SVC" in
  console)
    exec "$JAVA" -Dfile.encoding=UTF-8 \
      -jar aegis-console/target/aegis-console-1.0.0.jar \
      > "logs/console-$TAG.log" 2>&1
    ;;
  target)
    MODE="${3:-BLOCK}"
    exec "$JAVA" -Dfile.encoding=UTF-8 \
      -javaagent:aegis-agent/target/aegis-agent.jar=console=http://localhost:8080,mode=$MODE \
      -jar vuln-target/target/vuln-target-1.0.0.jar \
      > "logs/target-$TAG.log" 2>&1
    ;;
  gateway)
    exec "$JAVA" -Dfile.encoding=UTF-8 \
      -jar aegis-gateway/target/aegis-gateway-1.0.0.jar \
      > "logs/gateway-$TAG.log" 2>&1
    ;;
  *)
    echo "未知服务: $SVC （可选 console / target / gateway）"
    exit 1
    ;;
esac
