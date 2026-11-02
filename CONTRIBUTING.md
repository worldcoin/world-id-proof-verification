# Contributing

Thanks for your interest in contributing to `world-id-proof-verification-service`.

## Getting started

1. Install a Rust toolchain. The project is built and tested against **Rust 1.95.0**; install the
   matching toolchain plus the `rustfmt` and `clippy` components:
   ```bash
   rustup toolchain install 1.95.0 --component rustfmt --component clippy
   ```
2. Install system build dependencies: `build-essential`, `libssl-dev`, `pkg-config`.
3. Build and test:
   ```bash
   cargo build
   cargo test
   ```

## Before opening a pull request

CI runs the following checks and **all must pass**. Run them locally first:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --doc
cargo audit
cargo deny check
```

- `cargo fmt` — code must be formatted.
- `cargo clippy` — must be **warning-free** (`-D warnings`).
- `cargo audit` — no known vulnerable dependencies.
- `cargo deny check` — license, source, and advisory policy in [`deny.toml`](./deny.toml) must pass.

If `cargo deny` flags a new advisory that genuinely cannot be fixed yet, add a documented,
time-bounded waiver to `deny.toml` (with justification and a removal condition) rather than
disabling the check.

## Dependency pinning

`semaphore-rs` performs the cryptographic proof verification and is pinned to an **exact** version
in `Cargo.toml`. Do not relax this to a floating requirement — the verification path must not
change implicitly. Bumping it is a deliberate, reviewed change.

`world-id-proof` and `world-id-primitives` are also pinned exactly. Upgrades can change the
ownership circuit, its Noir compiler requirement, and the ProveKit transcript. Check real
proof compatibility with existing callers as well as the HTTP contract before deployment.
The real-proof regression test lives in `examples/verify_bench.rs` and runs with `--all-targets`.

## Pull request guidelines

- Keep PRs focused and reasonably small.
- Write a clear description of what changed and why.
- Add or update tests for behavior changes, especially anything touching proof verification.
- Reference the relevant issue.

## Code of conduct

This project follows the World [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are
expected to uphold it.
