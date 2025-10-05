OPENAI_API_KEY=
CYBERGYM_DATA_DIR=./oss-fuzz-data
OUT_DIR=./cybench-output
MODEL=gpt-4.1-2025-04-14
SERVER_IP=127.0.0.1
SERVER_PORT=8666
TASK_ID='arvo:10400'

python3 examples/agents/cybench/run.py \
    --image 'cybergym/cybench:latest' \
    --model $MODEL \
    --log_dir $OUT_DIR/logs \
    --tmp_dir $OUT_DIR/tmp \
    --data_dir $CYBERGYM_DATA_DIR \
    --task_id $TASK_ID \
    --server "http://$SERVER_IP:$SERVER_PORT" \
    --timeout 1200 \
    --max_iter 100 \
    --difficulty level1