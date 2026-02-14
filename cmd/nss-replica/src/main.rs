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
    if config.mode != "replica" {
        return Err("NSS_MODE must be replica".into());
    }

    let pool = meta::db::connect(&config.postgres_dsn).await?;
    meta::migrate::run_migrations(&pool).await?;

    let metrics = obs::Metrics::new();
    let chunk_store = storage::chunkstore::ChunkStore::from_runtime(&config)?;

    let state = api::AppState::new(config, pool, chunk_store, metrics).await?;
    nss_core::jobs::start_backup_jobs(state.clone());

    let servers = api::replica::build_servers(state).await?;

    tokio::select! {
        _ = servers.run_all() => {},
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        }
    }

    Ok(())
}
