# Proof verification client

`Client::verify()` uses its service JWT provider. `Client::challenge()` instead
requires an integrity token and matching request signer on every call:

```rust,ignore
let client = Client::new(config, service_jwt_provider)?;
let challenge = client
    .challenge(ChallengeType::Enrollment, &integrity_token, signer)
    .await?;
```

`config.host` is the request origin. `signer` is an `Arc<S>` implementing `Signer`;
its key must match the token's `cnf.jwk`. The signer receives a SHA-256 prehash:
Android returns DER-encoded ECDSA, iOS an App Attest assertion. Orb-tools can
reuse its IntegrityForge token and adapt `sign_digest()` to this interface.

Each call signs the URL and empty body using `attested-request` and attaches its headers.
Signing errors propagate before sending. `config.timeout` bounds HTTP; hardware signers
must bound their own operations. Redirects and automatic retries are disabled.

## One-key stage example

The example generates a request key and five-minute integrity token in memory:

```sh
CI_CANONICAL_REQUEST_SIGNING_PRIVATE_KEY_PATH=/path/to/orb-tools/.keys/ag_priv.pem \
  cargo run -p world-id-proof-verification-client --example signed_challenge
```

Alternatively, `CI_CANONICAL_REQUEST_SIGNING_PRIVATE_KEY` supplies PEM contents.
The default file is `.keys/ag_priv.pem` in the working directory. The key must be
an unencrypted PKCS#8 P-256 CI issuer key. Temporary PEM buffers are zeroized.

The example targets `https://app.stage.orb.worldcoin.org`, using issuer
`ci.attestation.worldcoin.dev`, key ID `test-integrity-kid`, and audience
`app.stage.orb.worldcoin.org`. Its public key must already be trusted by the proxy;
private keys stay with the caller. This issuer helper is example-only.

Validated against `attested-request` and test middleware `0.1.1`, and
`worldcoin/attested-proxy@9b42aae0c1818baa03d6189c447af61fa59810d8`.
Proxy replay storage is disabled: request signatures remain reusable within the
configured freshness window.
