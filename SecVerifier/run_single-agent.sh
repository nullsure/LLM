#!/bin/bash

# Default values
MAX_ITERATIONS=20
NUM_WORKERS=1
LLM_CONFIG="llm.4o"
CONDENSER="recent"
INSTANCE_ID=""
DATASET_NAME="SEC-bench/Seed"
LIMIT=""  # Changed to integer default value
MAX_BUDGET=""
SCRIPT="single-agent.py"

# Help function
show_help() {
    echo "Usage: $0 -m <max_iterations> [-l <llm_config>] [-c <condenser>] [-i <instance_id>] [-s <limit>] [-t <max_budget>] [-b <label>]"
    echo "  -m: Maximum iterations (default: 20)"
    echo "  -l: LLM config (default: llm.4o)"
    echo "  -c: Condenser (default: recent)"
    echo "  -i: Instance ID"
    echo "  -d: Dataset name (default: SEC-bench/Seed)"
    echo "  -s: Limit the number of instances to process"
    echo "  -t: Maximum budget per task"
    echo "  -b: Label"
    echo "  -w: Number of workers (default: 1)"
    echo "  -h: Show this help message"
    exit 1
}

# Parse command line arguments
while getopts "m:l:c:i:d:s:b:t:w:h" opt; do
    case $opt in
        m) MAX_ITERATIONS=$OPTARG;;
        l) LLM_CONFIG=$OPTARG;;
        c) CONDENSER=$OPTARG;;
        i) INSTANCE_ID=$OPTARG;;
        d) DATASET_NAME=$OPTARG;;
        s) LIMIT=$OPTARG;;
        b) LABEL=$OPTARG;;
        t) MAX_BUDGET=$OPTARG;;
        w) NUM_WORKERS=$OPTARG;;
        h) show_help;;
        \?) show_help;;
    esac
done

clear

# Build command based on whether INSTANCE_ID was provided
COMMAND="poetry run python $SCRIPT --llm-config $LLM_CONFIG --iterations $MAX_ITERATIONS --headless --condenser $CONDENSER --dataset-name $DATASET_NAME --label $LABEL --num-workers $NUM_WORKERS"
if [ -n "$INSTANCE_ID" ]; then
    COMMAND="$COMMAND --instance-id $INSTANCE_ID"
fi
if [ -n "$LIMIT" ]; then
    COMMAND="$COMMAND --limit $LIMIT"
fi
if [ -n "$MAX_BUDGET" ]; then
    COMMAND="$COMMAND --max-budget-per-task $MAX_BUDGET"
fi

# Execute the command
echo -e "\033[1;32m$COMMAND\033[0m"
$COMMAND
