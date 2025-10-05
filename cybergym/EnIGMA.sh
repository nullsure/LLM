OPENAI_API_KEY=
CYBERGYM_DATA_DIR=./oss-fuzz-data
OUT_DIR=./enlgma-output
MODEL=gpt-4.1-2025-04-14
SERVER_IP=127.0.0.1
SERVER_PORT=8666
TASK_ID='arvo:10400'

python3 examples/agents/enigma/run.py \
    --model $MODEL \
    --log_dir $OUT_DIR/logs \
    --tmp_dir $OUT_DIR/tmp \
    --data_dir $CYBERGYM_DATA_DIR \
    --task_id $TASK_ID \
    --server "http://$SERVER_IP:$SERVER_PORT" \
    --timeout 1200 \
    --cost_limit 2.0 \
    --difficulty level1