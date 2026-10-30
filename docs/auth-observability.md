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
service:world-id-proof-verification-service env:stage @event:authentication_rejected
service:world-id-proof-verification-service env:stage @stage:http_response @auth.outcome:rejected
service:world-id-proof-verification-service env:stage @auth.error_kind:expired
service:world-id-proof-verification-service env:stage @http.status_code:401 @auth.outcome:accepted
```

Use the response's `x-request-id` to find related logs with
`@request_id:<x-request-id>`. Count `authentication_rejected` events when measuring
auth failures, since each rejected request also has a separate HTTP outcome log.
