<!-- coderabbit-ai-generated:v1 -->

# Security hardening migration

## Source compatibility

The public enums now include `SSHError.knownHostsUnavailable` and `KnownHosts.Verdict.storageFailure`. These additions are source-breaking for consumers with exhaustive switches: add branches for the new cases (or an appropriate default). Treat both as failures to establish host trust; do not accept the host key when persistence fails.

`ExternalBinaryError` also gains `invalidBinaryName`, `invalidChecksum` and `downloadTooLarge`. These are source-breaking for exhaustive switches in the same way: handle the new cases, or add a default.

## Sync links

Push continues to preserve sync-file symlinks and update their regular targets. Each link must be in a directory owned by the current user with no group or other write permission. Links in untrusted directories now fail instead of authorizing their own targets. Relative targets and link chains are resolved from pinned directory descriptors, with a 40-link limit.

## Download authentication

Pass a session whose `delegate` implements `URLSessionDelegate` and/or `URLSessionTaskDelegate` challenge callbacks. Both are forwarded on that session's delegate queue with the supplied session identity; task callbacks receive the actual download task. Certificate-pinning policies should inspect the challenge and task request rather than require that the task appears in the supplied session's task list. Per-task delegates installed on unrelated existing tasks cannot configure this new request.

## PR description compatibility notice

This change adds public error cases `SSHError.knownHostsUnavailable` and `KnownHosts.Verdict.storageFailure`. Consumers with exhaustive switches must handle the new cases. Host-key persistence failures reject the connection.
