#!/bin/bash
set -e

MATCH_PATTERN=${1:-njs.cve}

TARGET_DIRS=(
  "/usr/local/bin"
  "/src"
  "/testcase"
  "/workspace"
)

echo "🔍 扫描容器镜像中包含: $MATCH_PATTERN"

# 遍历容器
for cid in $(docker ps -a --format '{{.ID}} {{.Image}}' | grep "$MATCH_PATTERN" | awk '{print $1}'); do
    cname=$(docker ps -a --format '{{.ID}} {{.Names}}' | grep "$cid" | awk '{print $2}')
    echo "⚙️ 修复容器: $cname ($cid)"
    docker start "$cid" >/dev/null 2>&1 || true

    for dir in "${TARGET_DIRS[@]}"; do
        echo "  ↪ 修复目录: $dir"
        docker exec "$cid" bash -c "if [ -d '$dir' ]; then find '$dir' -type f -exec sed -i 's/\r\$//' {} +; fi"
    done

    echo "✅ 修复完成: $cname"
done

echo "🎉 所有匹配容器换行符已修复完成"
