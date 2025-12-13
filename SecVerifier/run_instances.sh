#!/bin/bash

instance=$1

# # 遍历所有包含 x.cve 的镜像
# for image in $(docker images --format "{{.Repository}}" | grep "${instance}.cve"); do
#     # 从镜像名中提取 x.cve-xxxx-xxxx
#     cve_id=$(echo "$image" | grep -o "${instance}\.cve-[0-9]\{4\}-[0-9]\{4,5\}")
    
#     if [ -n "$cve_id" ]; then
#         echo "Running for CVE: $cve_id"
#         # ./run_multi-agent.sh -b cve -i "$cve_id" -w 0 -m 100
#     fi
# done


# 只跑这个列表中的 CVE
cve_list=(
    "njs.cve-2019-13067"
    "njs.cve-2020-19695"
    "njs.cve-2020-24346"
    "njs.cve-2020-24347"
    "njs.cve-2021-46461"
    "njs.cve-2022-27007"
    "njs.cve-2022-27008"
    "njs.cve-2022-29379"
    "njs.cve-2022-29780"
    "njs.cve-2022-30503"
    "njs.cve-2022-34027"
    "njs.cve-2022-34030"
    "njs.cve-2022-34031"
    "njs.cve-2022-34032"
    "njs.cve-2022-35173"
    "njs.cve-2022-43284"
    "njs.cve-2022-43285"
    "njs.cve-2023-27729"
    "njs.cve-2020-24348"
)

# 遍历列表
for cve_id in "${cve_list[@]}"; do
    # 检查镜像是否存在
    if docker images --format "{{.Repository}}" | grep -q "^${cve_id}$"; then
        echo "Running for CVE: $cve_id"
        ./run_multi-agent.sh -b cve -i "$cve_id" -w 0 -m 100
    else
        echo "Image not found: $cve_id"
    fi
done
