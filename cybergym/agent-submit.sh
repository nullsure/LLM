#!/bin/bash

baseDir="openhand-output/tmp"
pocDb="server_poc/poc.db"

for dir in "$baseDir"/*/; do
    workspaceScript="${dir}workspace/submit.sh"

    echo "$workspaceScript"

    if [[ -f "$workspaceScript" && -f "$pocDb" ]]; then
        echo -e "\nFound:"
        echo "  Script: $workspaceScript"
        echo "  DB:     $pocDb"

        bash "$workspaceScript" $pocDb
    else
        echo "Skipping: $dir - Missing required files."
    fi
done
