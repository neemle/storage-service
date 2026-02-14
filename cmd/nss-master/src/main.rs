use nss_core::util::config::Config;
use nss_core::util::shutdown::shutdown_signal;
use nss_core::util::usage;
use nss_core::{api, meta, obs, storage};
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

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::load()?;
    if config.mode != "master" {
        return Err("NSS_MODE must be master".into());
    }

    let pool = meta::db::connect(&config.postgres_dsn).await?;
    meta::migrate::run_migrations(&pool).await?;

    if std::env::args().any(|arg| arg == "--migrate-only") {
        tracing::info!("migrations completed");
        return Ok(());
    }

    let metrics = obs::Metrics::new();
    let chunk_store = storage::chunkstore::ChunkStore::from_runtime(&config)?;

    let state = api::AppState::new(config, pool, chunk_store, metrics).await?;

    let servers = api::master::build_servers(state.clone())?;
    nss_core::jobs::start_background_jobs(state.clone());

    tokio::select! {
        _ = servers.run_all() => {},
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        }
    }

    Ok(())
}
