# Tasks: issuer-registry-signing

## 1. Agent-side registry signing

- [x] 1.1 Dedicated registry key: `--registry-key` CLI option, P-256 check at startup, refusal on a label identical to the issuance key
- [x] 1.2 `/sign-registry` endpoint in `issuer serve` (P-256 over SHA-256 of the payload bytes); explicit "key not configured" error without the option
- [x] 1.3 Tests: pkcs11 signing round-trip, startup refusals, endpoint errors
