use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use eyre::{Context, Result};
use semaphore_rs::protocol::warmup_for_verification;
use telemetry_batteries::{
    MetricsBackend, MetricsConfig, StatsdConfig, TelemetryConfig, TelemetryGuard, TelemetryPreset,
    TopLevelResultExt,
};
use tracing::Instrument;
use world_id_proof_verification_service::app::{create_app, AppDeps};
use world_id_proof_verification_service::cfg::config;
use world_id_proof_verification_service::cfg::config::TREE_DEPTH;
use world_id_proof_verification_service::clients::gateway::{
    GatewayClient, GatewayClientConfig, HttpGatewayClient,
};
use world_id_proof_verification_service::services::gateway_service::GatewayService;
use world_id_proof_verification_service::services::jwt_auth::JwtKeyStore;
use world_id_proof_verification_service::services::nonce_store::{
    DynNonceStore, RedisConfig, RedisNonceStore,
};
use world_id_proof_verification_service::services::ownership_proof_verifier::{
    DynOwnershipProofVerifier, WorldIdOwnershipVerifier,
};
use world_id_proof_verification_service::services::proof_verifier::{
    DynProofVerifier, SemaphoreVerifier,
};

#[cfg(test)]
mod tests;

fn init_telemetry(
    service_name: String,
    dd_agent_host: String,
    dd_trace_port: u16,
    dd_statsd_port: u16,
) -> Result<TelemetryGuard> {
    let config = TelemetryConfig::builder()
        .preset(TelemetryPreset::Datadog)
        .service_name(service_name)
        // Traces/APM go to the Datadog Agent's trace-intake port (8126).
        .datadog_endpoint(format!("http://{dd_agent_host}:{dd_trace_port}"))
        .metrics(
            MetricsConfig::builder()
                .backend(MetricsBackend::Statsd)
                .statsd(
                    // DogStatsD metrics go to the StatsD port (8125) — NOT the trace port.
                    StatsdConfig::builder()
                        .host(dd_agent_host)
                        .port(dd_statsd_port)
                        .buffer_size(128) // flush metrics more often
                        .build(),
                )
                .build(),
        )
        .build();

    // The guard must be kept alive for the duration of the program, so we
    // return it to the caller instead of dropping it here.
    telemetry_batteries::init_with_config(config).wrap_err("failed to initialize telemetry")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::Config::parse();
    // if the RUST_LOG wasn't provided as env var use the default value from config.
    std::env::set_var("RUST_LOG", &cfg.rust_log);

    let service_name = cfg.srv_name.clone();
    let dd_agent_host = cfg.dd_agent_host.clone();

    let dd_trace_port = cfg.dd_agent_port.parse::<u16>().wrap_err_with(|| {
        format!(
            "invalid Datadog trace port (dd_agent_port): {:?}",
            cfg.dd_agent_port
        )
    })?;
    let dd_statsd_port = cfg.dd_statsd_port.parse::<u16>().wrap_err_with(|| {
        format!(
            "invalid DogStatsD metrics port (dd_statsd_port): {:?}",
            cfg.dd_statsd_port
        )
    })?;

    // Hold the telemetry guard for the lifetime of the process; dropping it
    // would tear down tracing/metrics. Fail fast if telemetry can't start.
    let _telemetry_guard =
        init_telemetry(service_name, dd_agent_host, dd_trace_port, dd_statsd_port)?;

    tracing::info!(stage = "telemetry_init", service = %cfg.srv_name, env = %cfg.srv_env,
        version = %cfg.srv_version, log_output = "stdout", "telemetry initialized");

    // Fatal errors also go to structured stdout; the Agent collects these logs
    // independently of the trace and metrics exporters.
    run(cfg).await.panic_on_top_level_error();
    Ok(())
}

async fn startup_step<T>(
    stage: &'static str,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    async {
        tracing::info!("startup stage started");
        let result = future.await;
        match &result {
            Ok(_) => tracing::info!("startup stage completed"),
            Err(error) => tracing::error!(error = ?error, "startup stage failed"),
        }
        result
    }
    .instrument(tracing::info_span!("startup", stage))
    .await
}

async fn run(cfg: config::Config) -> Result<()> {
    // Built once before serving; fail fast if a critical dependency is unreachable.
    let nonce_store: DynNonceStore = Arc::new(
        startup_step("redis_connect", async {
            RedisNonceStore::connect(&RedisConfig {
                url: cfg.redis_url.clone(),
                command_timeout: Duration::from_millis(cfg.redis_command_timeout_ms),
            })
            .await
            .wrap_err("failed to connect to the nonce-store Redis")
        })
        .await?,
    );
    let gateway_client: Arc<dyn GatewayClient> = Arc::new(
        startup_step("gateway_client_init", async {
            HttpGatewayClient::new(&GatewayClientConfig {
                base_url: cfg.gateway_url.clone(),
                request_timeout: cfg.gateway_timeout,
            })
            .wrap_err("failed to build the gateway client")
        })
        .await?,
    );
    let ownership_verifier: DynOwnershipProofVerifier = Arc::new(WorldIdOwnershipVerifier);
    // Fail fast: never serve the verify route without valid keys.
    let jwt_keys = Arc::new(
        startup_step("jwt_keys_load", async {
            JwtKeyStore::from_json(&cfg.jwt_trusted_keys)
                .wrap_err("failed to load jwt_trusted_keys")
        })
        .await?,
    );
    let deps = AppDeps {
        verifier: Arc::new(SemaphoreVerifier) as DynProofVerifier,
        nonce_store,
        gateway: Arc::new(GatewayService::new(gateway_client)),
        ownership_verifier,
        jwt_keys,
    };

    let app = create_app(cfg, deps);
    let listener = startup_step("listener_bind", async {
        tokio::net::TcpListener::bind(("0.0.0.0", 8080))
            .await
            .wrap_err("failed to bind 0.0.0.0:8080")
    })
    .await?;
    // Warm the verifier before accepting traffic, mirroring the original
    // bind-then-warmup-then-serve ordering.
    startup_step("verifier_warmup", async {
        warmup_for_verification(TREE_DEPTH);
        Ok(())
    })
    .await?;

    tracing::info!("Server is ready to accept connections");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .inspect_err(|error| tracing::error!(stage = "http_serve", %error, "HTTP server failed"))?;
    Ok(())
}

/// Resolves when the process is asked to terminate — SIGTERM (Kubernetes rolling
/// restart) or Ctrl-C. Handing this to `axum::serve(...).with_graceful_shutdown`
/// makes the server stop accepting new connections and drain in-flight
/// verification requests before `main` returns, so the telemetry guard still
/// flushes on exit. This restores actix's default signal handling, which plain
/// `axum::serve` does not provide. Kubernetes' `terminationGracePeriodSeconds`
/// backstops the drain with a SIGKILL, so the wait stays bounded.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received; draining in-flight requests");
}
