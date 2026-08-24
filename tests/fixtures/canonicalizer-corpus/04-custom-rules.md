version: 2.0.0

## custom
allow_only.intent.metadata.job_type: rebalance, risk_check
deny_if.intent.metadata.contract_name contains "unverified"
deny_string: "OPENAI_API_KEY"
deny_string: "PRIVATE_KEY"
