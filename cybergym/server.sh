PORT=8666 # port of the server
POC_SAVE_DIR=./server_poc # dir to save the pocs
CYBERGYM_SERVER_DATA_DIR=./oss-fuzz-data

python -m cybergym.server \
    --host 127.0.0.1 --port $PORT \
    --log_dir $POC_SAVE_DIR --db_path $POC_SAVE_DIR/poc.db \
    --cybergym_oss_fuzz_path $CYBERGYM_SERVER_DATA_DIR


# PowerShell version
$PORT = 8666
$POC_SAVE_DIR = ".\server_poc"
$CYBERGYM_SERVER_DATA_DIR = ".\oss-fuzz-data"

# ensure the save dir exists
New-Item -ItemType Directory -Path $POC_SAVE_DIR -Force | Out-Null

# run the cybergym server
& python -m cybergym.server `
    --host 127.0.0.1 --port $PORT `
    --log_dir $POC_SAVE_DIR --db_path "$POC_SAVE_DIR\poc.db" `
    --cybergym_oss_fuzz_path $CYBERGYM_SERVER_DATA_DIR
