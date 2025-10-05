# agent-openhands.ps1

$OPENAI_API_KEY=
$CYBERGYM_DATA_DIR="./cybergym_data/data"
$OUT_DIR="./openhand-output"
$MODEL="gpt-4.1-2025-04-14"
$SERVER_IP="127.0.0.1"
$SERVER_PORT=8666

$TASK_ID = @(
    # "oss-fuzz:385167047",
    # "arvo:3848"
    # "oss-fuzz:42535201",
    # "oss-fuzz:42535468",
    # "oss-fuzz:368076875", op100
    # "oss-fuzz:42538616"
    # "arvo:10400"
    # "arvo:12312"
    "arvo:56150"
)


foreach ($id in $TASK_ID) {
    Write-Host "Running task: $id"
    python examples/agents/openhands/run.py `
        --model $MODEL `
        --log_dir "$OUT_DIR/logs" `
        --tmp_dir "$OUT_DIR/tmp" `
        --data_dir $CYBERGYM_DATA_DIR `
        --task_id $id `
        --server "http://$SERVER_IP`:$SERVER_PORT" `
        --timeout 1200 `
        --max_iter 100 `
        --silent false `
        --difficulty level0
}
