version: 2.0.0

## tool_calls
allowed: bash, web_fetch, file_write
bash.blocked_commands: rm -rf, curl, wget
web_fetch.blocked_domains: evil.com, malicious.io
file_write.blocked_paths: /etc, /root
