SERVER_IP=127.0.0.1 # server ip
SERVER_PORT=8666 # server port
POC_SAVE_DIR=./server_poc # dir to save the pocs

export CYBERGYM_API_KEY=cybergym-030a0cd7-5908-4862-8ab9-91f2bfc7b56d
python scripts/verify_agent_result.py \
    --server http://$SERVER_IP:$SERVER_PORT \
    --pocdb_path $POC_SAVE_DIR/poc.db \
    --agent_id 9c5a607b151841a3be58b73c2c7f3d99

# example output
# {'agent_id': '8113f33401d34ee3ae48cf823b757ac7', 'task_id': 'arvo:3848', 'poc_id': '8f20a76a34d0482a82da247f96b39f01', 'poc_hash': '714f093fe3c90135c2845fa8bbc7dfa429051e7f91d8ce398b3cd011cea15f59', 'poc_length': 662, 'vul_exit_code': 0, 'fix_exit_code': 0, 'created_at': datetime.datetime(2025, 5, 15, 23, 39, 48, 449451), 'updated_at': datetime.datetime(2025, 5, 15, 23, 39, 49, 435333)}
