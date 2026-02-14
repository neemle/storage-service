use nss_core::util::config::Config;
use nss_core::util::shutdown::shutdown_signal;
use nss_core::util::usage;
use nss_core::{api, meta, obs, storage};
use std::future::Future;
use tracing_subscriber::EnvFilter;

const APP_VERSION: &str = match option_env!("NSS_APP_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if usage::handle_cli_flags(APP_VERSION) {
        return Ok(());
    }

    install_crypto_provider();
    init_tracing();

    let config = Config::load()?;

    let pool = meta::db::connect(&config.postgres_dsn).await?;
    meta::migrate::run_migrations(&pool).await?;

    if is_migrate_only() {
        tracing::info!("migrations completed");
        return Ok(());
    }

    let mode = config.mode.clone();
    let metrics = obs::Metrics::new();
    let chunk_store = storage::chunkstore::ChunkStore::from_runtime(&config)?;
    let state = api::AppState::new(config.clone(), pool, chunk_store, metrics).await?;
    run_mode(mode.as_str(), state).await
}

fn install_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

fn is_migrate_only() -> bool {
    std::env::args().any(|arg| arg == "--migrate-only")
}

async fn run_mode(mode: &str, state: api::AppState) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        "master" => run_master(state).await,
        "replica" => run_replica(state).await,
        _ => Err("NSS_MODE must be master or replica".into()),
    }
}

async fn run_master(state: api::AppState) -> Result<(), Box<dyn std::error::Error>> {
    let servers = api::master::build_servers(state.clone())?;
    nss_core::jobs::start_background_jobs(state);
    wait_for_exit(servers.run_all()).await;
    Ok(())
}

async fn run_replica(state: api::AppState) -> Result<(), Box<dyn std::error::Error>> {
    nss_core::jobs::start_backup_jobs(state.clone());
    let servers = api::replica::build_servers(state).await?;
    wait_for_exit(servers.run_all()).await;
    Ok(())
}

async fn wait_for_exit<F>(run_all: F)
where
    F: Future<Output = ()>,
{
    tokio::select! {
        _ = run_all => {},
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        }
    }
}
