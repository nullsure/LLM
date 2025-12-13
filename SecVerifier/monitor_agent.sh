#!/bin/bash

# OpenHands Agent URL
AGENT_URL="http://localhost:3109633"

echo "Start monitoring OpenHands Agent at $AGENT_URL ..."

while true; do
    # 发送 HTTP 请求
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" $AGENT_URL)

    if [ "$STATUS" -eq 200 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Agent is READY ✅"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Agent not ready yet... (HTTP $STATUS)"
    fi

    sleep 2
done
