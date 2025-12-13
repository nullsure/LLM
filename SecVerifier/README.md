# Multi-Agent System for Vulnerability Reproduction

This is a multi-agent framework designed to automate the end-to-end process of reproducing security vulnerabilities. It leverages a coordinated system of specialized agents to handle different aspects of the reproduction pipeline.

## Architecture
> [!NOTE]
> The SecVerifier framework is built on the foundation of [OpenHands@0.34.0](https://github.com/All-Hands-AI/OpenHands)

SecVerifier employs a hierarchical multi-agent architecture:

1. **ManagerAgent** - The coordinator agent that orchestrates the full process
2. **BuilderAgent** - Specialized assistant responsible for fixing and optimizing build processes for code repositories
3. **ExploiterAgent** - Specialized assistant responsible for crafting proof-of-concept (PoC) exploits to reproduce vulnerabilities in code repositories
4. **FixerAgent** - Specialized assistant responsible for creating a unified patch file that fixes vulnerabilities in code repositories.

The system uses agent delegation to pass control between specialized agents while maintaining runtime state to preserve the container environment integrity.

## Key Features

- **Coordinated Multi-Agent Workflow**: Specialized agents work together in sequence
- **Maintained Runtime State**: Container state is preserved across agent transitions
- **Vulnerability-Specific Inputs**: Each agent receives vulnerability-specific information
- **Comprehensive Outputs**: Detailed outputs from each phase of reproduction

## Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/SEC-bench/SecVerifier.git
cd SecVerifier

# Install dependencies with Poetry
poetry install
```

### Running SecVerifier

```bash
Usage: ./run_multi-agent.sh -m <max_iterations> [-l <llm_config>] [-c <condenser>] [-i <instance_id>] [-s <limit>] [-t <max_budget>] [-b <label>]
  -m: Maximum iterations (default: 20)
  -l: LLM config (default: llm.4o)
  -c: Condenser (default: recent)
  -i: Instance ID
  -s: Limit the number of instances to process
  -t: Maximum budget per task
  -b: Label
  -w: Number of workers (default: 1)
  -h: Show this help message
```

## Workflow

1. **Initialization**: The system loads vulnerability data from SEC-bench
2. **Builder Phase**: BuilderAgent validates and fixes build scripts
3. **Exploiter Phase**: ExploiterAgent improves helper scripts and creates PoC files
4. **Fixer Phase**: FixerAgent creates a unified patch file that fixes vulnerabilities in code repositories
5. **Evaluation**: The system evaluates the success of the reproduction process
