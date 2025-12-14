#!/bin/bash
set -e

# -----------------------------
# 1️⃣ 批量拉取 unsure 镜像
# -----------------------------
IMAGES=(
    "njs.cve-2022-32414"
    "njs.cve-2022-28049"
    "njs.cve-2022-38890"
    "njs.cve-2022-31306"
    "njs.cve-2023-27728"
    "njs.cve-2023-27727"
    "njs.cve-2022-34029"
    "njs.cve-2022-29369"
    "njs.cve-2022-29779"
    "njs.cve-2021-46462"
    "njs.cve-2022-31307"
    "njs.cve-2019-13617"
)

echo "开始拉取 unsure 镜像..."
for IMG in "${IMAGES[@]}"; do
    FULL_IMAGE="unsure/secb.eval.x86_64.${IMG}:poc"
    echo "Pulling $FULL_IMAGE"
    docker pull "$FULL_IMAGE"
done
echo "镜像拉取完成！"

# -----------------------------
# 2️⃣ 执行 run_secb.sh
# -----------------------------
echo "开始执行 run_secb.sh..."
./run_secb.sh -m poc -l llm.5-mini -n 100 -i 30
echo "执行完成！"
