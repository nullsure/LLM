# CyberGym — README

A short, practical README for getting **cybergym** up and running (based on the repo at `https://github.com/sunblaze-ucb/cybergym`).  
This file collects the install, dataset download, and run instructions in a neat, copy-pasteable format.

---

## Table of contents

- [Overview](#overview)  
- [Requirements](#requirements)  
- [Install](#install)  
- [Download datasets](#download-datasets)  
  - [Full OSS-Fuzz dataset (git-lfs)](#full-oss-fuzz-dataset-git-lfs)  
  - [All PoC submission server data](#all-poc-submission-server-data)  
  - [Subset of ARVO](#subset-of-arvo)  
  - [Subset of OSS-Fuzz](#subset-of-oss-fuzz)  
- [Run server](#run-server)  
- [Test client](#test-client)  
- [Agent (run example agent)](#agent-run-example-agent)  
- [Submit agent PoC](#submit-agent-poc)  
- [Initialize agent submodules](#initialize-agent-submodules)  
- [Notes & troubleshooting](#notes--troubleshooting)  
- [License / attribution](#license--attribution)

---

## Overview

This README collects essential commands to install `cybergym` in editable mode, download the OSS-Fuzz / PoC datasets used by the server, and run the server + example clients/agents.

> These commands were provided originally with the repository — use them as-is in a shell or PowerShell session as appropriate.

---

## Requirements

- Python 3 (recommend 3.12+)
- `git` and `git-lfs` for large-file dataset cloning (if you download the full dataset)
- `7z` (p7zip) to extract `.7z` archives
- On Windows use PowerShell for the `powershell` examples shown below; on \*nix use the provided shell (`sh`) commands.
---

## Install

Install the package in editable mode (include dev & server optional extras):

```bash
pip3 install -e '.[dev,server]'
```

This installs the project with developer and server dependencies so you can run the server and example agents.

---

## Download datasets

### Full OSS-Fuzz dataset (git-lfs)
To download the full dataset managed with Git LFS:

```bash
git lfs install
git clone https://huggingface.co/datasets/sunblaze-ucb/cybergym cybergym_data
```

This clones the `cybergym_data` dataset repository (may be large).

---

### All PoC submission server data

To download server PoC data using the project scripts:

```bash
python scripts/server_data/download.py --tasks-file ./cybergym_data/tasks.json
bash scripts/server_data/download_chunks.sh
7z x cybergym-oss-fuzz-data.7z
```

- `download.py` reads `tasks.json` and queues downloads.
- `download_chunks.sh` fetches chunked archives.
- `7z x` extracts the combined `cybergym-oss-fuzz-data.7z` archive.

---

### Subset of ARVO

To download just a subset from ARVO (use the repo helper):

```bash
python scripts/server_data/download_subset.py
```

This script produces a smaller subset suitable for testing or demos.

---

### Subset of OSS-Fuzz

A prebuilt subset (smaller archive) can be downloaded and extracted:

```bash
wget https://huggingface.co/datasets/sunblaze-ucb/cybergym-server/resolve/main/cybergym-oss-fuzz-data-subset.7z
7z x cybergym-oss-fuzz-data-subset.7z
```

---

## Run server

Start the cybergym server. Example PowerShell command (Windows):

```powershell
& python -u -m cybergym.server `
    --host 127.0.0.1 --port $PORT `
    --log_dir $POC_SAVE_DIR --db_path "$POC_SAVE_DIR\poc.db" `
    --cybergym_oss_fuzz_path $CYBERGYM_SERVER_DATA_DIR
```

Replace the environment variables:

- `$PORT` — TCP port to listen on (e.g. `8000`).
- `$POC_SAVE_DIR` — directory where PoCs and logs are written.
- `$CYBERGYM_SERVER_DATA_DIR` — path to extracted cybergym/oss-fuzz dataset.

If on \*nix shells, you can adapt to standard POSIX variables:

```bash
python -u -m cybergym.server \
  --host 127.0.0.1 --port 8000 \
  --log_dir /path/to/poc_save_dir --db_path "/path/to/poc_save_dir/poc.db" \
  --cybergym_oss_fuzz_path /path/to/cybergym_server_data
```

---

## Test client

A provided `client.sh` script can exercise the server:

```bash
sh client.sh
```

Run this from the repo root (or adapt the script to point at your host/port).

---

## Agent — run example agent

There is a PowerShell helper for running an example agent:

```powershell
powershell -ExecutionPolicy Bypass -File .\openhand.ps1
```

Run this from the project root (or open PowerShell and execute the script path). This launches the example agent workflow included in the repo.

---

## Submit agent PoC

To submit a Proof-of-Concept (PoC) from an agent to the server:

```bash
sh agent-submit.sh
```

This uses the project’s submission helper — ensure the server is running and reachable by the script.

---

## Agent submodules

If you want the example agents (or other submodule content), initialize and update git submodules:

```bash
git submodule update --init --recursive examples/agents
```

This fetches and sets up the nested example agent code.

---


## Contributing / Development



---

## License / attribution

This README references the `cybergym` repository and dataset maintained by `sunblaze-ucb`. Please consult the upstream repository for exact licensing, copyright, and attribution details.
