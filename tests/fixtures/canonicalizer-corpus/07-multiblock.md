version: 2.1.0

## evm
max_transaction_eth: 1.25
allowed_actions: wallet.transfer
allowed_chains: 1

## tool_calls
allowed: web_fetch, email.send
email.require_approval: true

## custom
deny_string: "BEGIN RSA PRIVATE KEY"

## soft_limits
daily_evm_limit_eth: 10.0
