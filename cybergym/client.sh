#!/bin/bash

SERVER_IP=127.0.0.1 # server ip
SERVER_PORT=8666 # server port
# TASK_ID='oss-fuzz:370689421'
OUT_DIR=./cybergym_tmp
# CYBERGYM_DATA_DIR=./oss-fuzz-data
CYBERGYM_DATA_DIR=./cybergym_data/data

task_ids=(
    # oss-fuzz:385167047,
    # oss-fuzz:42535201,
    # oss-fuzz:42535468,
    arvo:12312
)

for id in "${task_ids[@]}"; do

    python -m cybergym.task.gen_task \
        --task-id $id \
        --out-dir $OUT_DIR \
        --data-dir $CYBERGYM_DATA_DIR \
        --server "http://$SERVER_IP:$SERVER_PORT" \
        --difficulty level0

    echo -en "\x00\x01\x02\x03" > $OUT_DIR/poc
    bash $OUT_DIR/submit.sh $OUT_DIR/poc
done
