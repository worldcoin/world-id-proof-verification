use std::num::NonZeroUsize;
use std::time::Duration;

use clap::Parser;

/// A struct representing the configuration options for the proof verification service.
///
/// The `Config` struct contains the following fields:
///
/// * `srv_env`: A `String` representing the environment in which the service is running (e.g. "prod", "staging", "dev").
/// * `srv_name`: A `String` representing the name of the service.
/// * `srv_version`: A `String` representing the version of the service.
/// * `dd_agent_host`: A `String` representing the hostname or IP address of the Datadog agent.
/// * `dd_agent_port`: A `String` representing the Datadog Agent APM trace-intake port.
/// * `dd_statsd_port`: A `String` representing the DogStatsD metrics port.
/// * `response_duration_seconds`: An `i64` representing the maximum accepted age (in seconds) of a challenge timestamp.
/// * `verification_concurrency`: A `NonZeroUsize` bounding how many ZK proof verifications run concurrently.
/// * `rust_log`: A `String` representing the log level for the Rust logging system.
/// * `enable_proof_gen_endpoint`: A `bool` toggling the staging/test-only proof-generation endpoint.
/// * `redis_url`: A `String` Redis connection URL for the single-use nonce store (`redis://` or `rediss://`, optional AUTH).
/// * `redis_command_timeout_ms`: A `u64` bounding each Redis command and the initial connect, in milliseconds.
/// * `challenge_ttl`: A `Duration` challenge lifetime; the Redis key TTL at issuance, humantime-parsed (default "10m").
/// * `gateway_url`: A `String` base URL of the World ID gateway exposing `GET /is-valid-root` (required; no default).
/// * `gateway_timeout`: A `Duration` bounding each gateway request, parsed from a humantime string (e.g. "2s").
/// * `max_body_bytes`: A `bytesize::ByteSize` hard ceiling on request body size, enforced before the body is buffered/parsed.
/// * `verify_timeout`: A `Duration` bounding the CPU-pool ZK verification call, humantime-parsed (default "5s").
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use world_id_proof_verification_service::cfg::config::Config;
///
/// let config = Config {
///     srv_env: "prod".to_string(),
///     srv_name: "world-id-proof-verification-service".to_string(),
///     srv_version: "1.0.0".to_string(),
///     dd_agent_host: "localhost".to_string(),
///     dd_agent_port: "8126".to_string(),
///     dd_statsd_port: "8125".to_string(),
///     response_duration_seconds: 300,
///     verification_concurrency: std::num::NonZeroUsize::new(2).unwrap(),
///     rust_log: "info".to_string(),
///     enable_proof_gen_endpoint: false,
///     redis_url: "redis://127.0.0.1:6379".to_string(),
///     redis_command_timeout_ms: 2000,
///     challenge_ttl: Duration::from_secs(600),
///     gateway_url: "https://gateway.example.com".to_string(),
///     gateway_timeout: Duration::from_secs(2),
///     jwt_trusted_keys: r#"{"svc":{"current":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}}"#.to_string(),
///     max_body_bytes: bytesize::ByteSize::mib(1),
///     verify_timeout: Duration::from_secs(5),
/// };
/// assert_eq!(config.srv_env, "prod");
/// assert_eq!(config.srv_name, "world-id-proof-verification-service");
/// assert_eq!(config.srv_version, "1.0.0");
/// assert_eq!(config.dd_agent_host, "localhost");
/// assert_eq!(config.dd_agent_port, "8126");
/// assert_eq!(config.dd_statsd_port, "8125");
/// assert_eq!(config.response_duration_seconds, 300);
/// assert_eq!(config.verification_concurrency.get(), 2);
/// assert_eq!(config.rust_log, "info");
/// assert_eq!(config.enable_proof_gen_endpoint, false);
/// assert_eq!(config.redis_url, "redis://127.0.0.1:6379");
/// assert_eq!(config.redis_command_timeout_ms, 2000);
/// assert_eq!(config.challenge_ttl, Duration::from_secs(600));
/// assert_eq!(config.gateway_url, "https://gateway.example.com");
/// assert_eq!(config.gateway_timeout, Duration::from_secs(2));
/// assert!(config.jwt_trusted_keys.contains("svc"));
/// ```
#[derive(Clone, Debug, Parser)]
pub struct Config {
    #[arg(long, env, default_value = "prod")]
    pub srv_env: String,
    #[arg(long, env, default_value = option_env!("CARGO_PKG_NAME"))]
    pub srv_name: String,
    #[arg(long, env, default_value = option_env!("CARGO_PKG_VERSION"))]
    pub srv_version: String,
    #[arg(long, env, default_value = "127.0.0.1")]
    pub dd_agent_host: String,
    /// Datadog Agent APM trace-intake port (used for spans/traces).
    #[arg(long, env, default_value = "8126")]
    pub dd_agent_port: String,
    /// DogStatsD metrics port. Metrics go here, not to the trace port.
    #[arg(long, env, default_value = "8125")]
    pub dd_statsd_port: String,
    #[arg(long, env, value_parser = clap::value_parser!(i64).range(1..), default_value = "300")]
    pub response_duration_seconds: i64,
    /// Max concurrent ZK verifications; bounds CPU so a flood can't starve the
    /// runtime. Raise per deployment for higher throughput.
    #[arg(long, env, default_value = "2")]
    pub verification_concurrency: NonZeroUsize,
    #[arg(long, env, default_value = "info")]
    pub rust_log: String,
    #[arg(long, env, default_value = "false")]
    pub enable_proof_gen_endpoint: bool,
    /// Nonce-store Redis URL; carries scheme, optional AUTH and TLS (`rediss://`).
    #[arg(long, env, default_value = "redis://127.0.0.1:6379")]
    pub redis_url: String,
    /// Per-command and connect deadline for Redis, in milliseconds.
    #[arg(long, env, value_parser = clap::value_parser!(u64).range(1..), default_value = "2000")]
    pub redis_command_timeout_ms: u64,
    /// Challenge lifetime, applied as the Redis key TTL at issuance. Parsed from
    /// a humantime string (e.g. "10m", "600s"). The stored `expires_at` is
    /// advisory; this TTL is the authority.
    #[arg(long, env, value_parser = humantime::parse_duration, default_value = "10m")]
    pub challenge_ttl: Duration,
    /// Base URL of the World ID gateway exposing `GET /is-valid-root`, the
    /// source of truth for accepted Merkle roots.
    #[arg(long, env)]
    pub gateway_url: String,
    /// Per-request deadline for the gateway call, as a humantime string (e.g. "2s", "500ms").
    #[arg(long, env, value_parser = humantime::parse_duration, default_value = "2s")]
    pub gateway_timeout: Duration,
    /// Trusted JWT public keys for `POST /api/v4/verify`, as JSON:
    /// `{"svc":{"current":"<PEM SPKI>","previous"?:"<PEM SPKI>"}}`. Required;
    /// validated at startup so the route is never served unauthenticated.
    #[arg(long, env)]
    pub jwt_trusted_keys: String,
    /// Hard ceiling on request body size, enforced before the body is fully
    /// buffered or parsed. A real ownership proof measured on staging is
    /// 760,619 bytes base64, so 1 MiB leaves ~28% headroom. Accepts a plain
    /// byte count or a human-readable size (e.g. "512KiB", "1MB").
    #[arg(long, env, value_parser = clap::value_parser!(bytesize::ByteSize), default_value = "1 MiB")]
    pub max_body_bytes: bytesize::ByteSize,
    /// Deadline for the CPU-pool ZK verification call, humantime-parsed.
    #[arg(long, env, value_parser = humantime::parse_duration, default_value = "5s")]
    pub verify_timeout: Duration,
}

pub const TREE_DEPTH: usize = 30;
