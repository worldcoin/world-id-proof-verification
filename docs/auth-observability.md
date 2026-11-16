# Authentication rejection logs

`POST /api/v4/verify` logs every authentication rejection at `WARN`, visible with
the default `RUST_LOG=info`. The event includes:

- `event=authentication_rejected` and `stage=authentication`.
- `error_kind` and a plain-language `reason` describing the failed check.
- `auth.outcome=rejected` and `auth.error_kind`, also included in the final HTTP
  outcome log for the request.
- `http.status_code=401`, `request_id`, and Datadog trace/span IDs.

HTTP codes use `http.status_code`; Datadog reserves `status` for log severity.
See [Datadog status preprocessing](https://docs.datadoghq.com/logs/guide/logs-show-info-status-for-warnings-or-errors/).

A 401 response can also mean proof/challenge rejection after authentication
succeeded. Such request logs show `auth.outcome=accepted` and no
`auth.error_kind`. Routes without an authentication requirement omit these
fields. Auth failures retain the response body `{"msg":"unauthorized"}`;
proof/challenge rejections return `{"msg":"proof_rejected"}`.

Request logs include `challenge_type` after the service validates the challenge
route parameter or loads the challenge from the nonce store. Earlier failures
omit it; unrecognized path values are never logged.

| `auth.error_kind` / `error_kind` | Meaning |
|---|---|
| `missing_token` | No Authorization header or an empty bearer token. |
| `bad_scheme` | Invalid Authorization header format or a scheme other than Bearer. |
| `malformed` | Invalid JWT structure, base64, or JSON. |
| `bad_alg` | Unsupported algorithm, including `none`; ES256 is required. |
| `missing_sub` | Required `sub` claim is absent. |
| `invalid_claims` | Claims are not an object, or `sub` is not a string. |
| `missing_or_invalid_exp` | `exp` is absent or cannot be parsed as a numeric date. |
| `unknown_sub` | No trusted keys are configured for the claimed service. |
| `bad_signature` | Neither configured key verifies the signature for that service. |
| `expired` | Token expired beyond the 60-second leeway. |
| `not_yet_valid` | `nbf` is more than 60 seconds in the future. |
| `validation_failed` | Unexpected validator error; not classified as a signature mismatch. |

The reason describes the first failed check, not every defect in a token. A
malformed payload is distinguished from a missing subject; a claim validation
failure after a matching key is preserved during key rotation. Tokens, headers,
raw claims, and unverified caller names are never included in these auth logs.

Datadog queries:

```text
service:world-id-proof-verification env:stage @event:authentication_rejected
service:world-id-proof-verification env:stage @stage:http_response @auth.outcome:rejected
service:world-id-proof-verification env:stage @auth.error_kind:expired
service:world-id-proof-verification env:stage @http.status_code:401 @auth.outcome:accepted
```

Use the response's `x-request-id` to find related logs with
`@request_id:<x-request-id>`. Count `authentication_rejected` events when measuring
auth failures, since each rejected request also has a separate HTTP outcome log.

## Nitro-authenticated challenge issuance

With `ENABLE_NITRO_CHALLENGE`, `POST /api/v4/zkp/challenge/enrollment` records
`auth.outcome` for callers authenticated by Nitro capture evidence, and
`auth.error_kind` when that evidence is refused. Callers the proxy verified, and
other challenge types, omit both fields as before. Each refusal logs
`stage=capture_authentication` at `WARN` (`ERROR` for a `503`) and increments
`challenge.nitro.rejected` tagged with `class`; each acceptance increments
`challenge.nitro.accepted`.

| `auth.error_kind` / `class` | Status | Meaning |
|---|---|---|
| `missing_evidence` | 401 | Neither proxy identity headers nor an attestation header. |
| `malformed` | 400 | Attestation header or capture fields are not canonical. |
| `too_large` | 413 | Capture body exceeds 128 KiB. |
| `document` | 401 | The attestation is not a well-formed capture document. |
| `trust` | 401 | Signature or certificate chain does not lead to the AWS Nitro root. |
| `release` | 401 | Enclave measurements are not an approved release. |
| `freshness` | 401 | Document or capture time is outside the accepted window. |
| `binding` | 401 | The document does not cover the presented capture. |
| `rate_limited` | 429 | The capture reached its challenge allowance. |
| `saturated` | 503 | Concurrent verifications are at `NITRO_VERIFY_CONCURRENCY`. |
| `unavailable` | 503 | The issuance counter or the verification task failed. |

A sustained `release` rate after an enclave rollout means the release policy
is behind the deployed enclave. A sustained `trust` rate with no deployment
change is worth treating as probing. Subjects, capture digests and document
contents are never logged or used as metric tags.

```text
service:world-id-proof-verification env:stage @stage:capture_authentication
service:world-id-proof-verification env:stage @stage:capture_authentication @error_kind:release
```
