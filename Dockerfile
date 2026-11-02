FROM public.ecr.aws/docker/library/rust:1.95-slim-bookworm AS builder

# Install dependencies. `git` is needed because the ownership circuit's
# Nargo.toml pulls its Noir libraries from git at compile time.
RUN apt-get update && \
  apt-get install -y --no-install-recommends curl git build-essential libssl-dev pkg-config

# Install the Noir toolchain (nargo). The `world-id-proof` `embed-ownership-verifier`
# build script compiles the bundled ownership circuit with nargo, so it must be
# present at build time. Pinned to the version the crate requires.
ENV PATH="/root/.nargo/bin:${PATH}"
RUN mkdir -p /root/.nargo/bin && \
  curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/7dbe69ccc78877f0200ffa5a40836c953d2cfd8f/noirup -o /tmp/noirup.sh && \
  bash /tmp/noirup.sh --version v1.0.0-beta.26 && \
  rm -f /tmp/noirup.sh

RUN mkdir /code && mkdir /app
COPY ./src /code/src
# Workspace members. The image builds only the service binary; Cargo still
# needs these manifests to load the workspace.
COPY ./api-types /code/api-types
COPY ./client /code/client
COPY Cargo.toml /code
COPY Cargo.lock /code

WORKDIR /code
RUN cargo build --release --locked --bin world-id-proof-verification-service && cp target/release/world-id-proof-verification-service /app/world-id-proof-verification-service && rm -rf /code

#--------------------------------------------------------------------------------------
FROM public.ecr.aws/docker/library/debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/world-id-proof-verification-service /app/world-id-proof-verification-service
# nobody user
USER 65534
CMD ["/app/world-id-proof-verification-service"]
