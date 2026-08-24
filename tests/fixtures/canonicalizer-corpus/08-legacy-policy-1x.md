version: 1.0.0

## tool_calls
allowed: web_fetch, bash
bash.blocked_commands: rm -rf

## evm
max_transaction_eth: 1.0
allowed_actions: wallet.transfer
allowed_chains: 1
