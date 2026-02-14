const USAGE: &str = "\
Neemle Storage Service — S3-compatible object storage

USAGE:
    nss [OPTIONS]

OPTIONS:
    -h, --help           Print this help message and exit
    -v, --version        Print version and exit
        --migrate-only   Run database migrations and exit

REQUIRED ENVIRONMENT VARIABLES:
    NSS_MODE                          Operating mode: \"master\" or \"replica\"
    NSS_POSTGRES_DSN                  PostgreSQL connection string
    NSS_DATA_DIRS                     Comma-separated storage directory paths
    NSS_SECRET_ENCRYPTION_KEY_BASE64  Base64-encoded 32-byte encryption key
    NSS_JWT_SIGNING_KEY_BASE64        Base64-encoded 32-byte JWT signing key (optional)

NETWORK (listen addresses, default shown):
    NSS_S3_LISTEN            S3 API             [:9000]
    NSS_API_LISTEN           Console/Admin API  [:9001]
    NSS_INTERNAL_LISTEN      Internal repl. API [:9003]
    NSS_REPLICA_LISTEN       Replica comms      [:9010]
    NSS_METRICS_LISTEN       Prometheus metrics  [:9100]

IDENTITY & ACCESS:
    NSS_ADMIN_BOOTSTRAP_USER          Initial admin username      [admin]
    NSS_ADMIN_BOOTSTRAP_PASSWORD      Initial admin password      [change-me; blocked unless insecure dev]
    NSS_INTERNAL_SHARED_TOKEN         Inter-node auth token       [change-me; blocked unless insecure dev]

STORAGE:
    NSS_REPLICATION_FACTOR            Target replica count        [1]
    NSS_WRITE_QUORUM                  Write quorum                [=replication_factor]
    NSS_CHUNK_SIZE_BYTES              Fixed chunk size            [auto-detect]
    NSS_CHUNK_MIN_BYTES               Minimum chunk size          [4194304]
    NSS_CHUNK_MAX_BYTES               Maximum chunk size          [67108864]
    NSS_CHECKSUM_ALGO                 crc32c | sha256 | both      [crc32c]
    NSS_CHUNK_ENCRYPTION_ENABLED      Encrypt chunks at rest      [true]
    NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID Active chunk key id        [default]
    NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ Legacy read mode    [true]
    NSS_CHUNK_ENCRYPTION_KEY_BASE64   Optional active 32-byte key [fallback to secret key]
    NSS_CHUNK_ENCRYPTION_KEYS         Optional keyring map        [key_id:base64,...]

BACKGROUND JOBS:
    NSS_SCRUB_INTERVAL_SECONDS        Scrub cycle interval        [3600]
    NSS_REPAIR_WORKERS                Repair worker threads       [4]
    NSS_MULTIPART_TTL_SECONDS         Multipart upload TTL        [86400]
    NSS_GC_INTERVAL_SECONDS           Garbage collection interval [3600]

OPTIONAL SERVICES:
    NSS_REDIS_URL                     Redis URL for caching
    NSS_RABBIT_URL                    RabbitMQ URL for events

CLUSTER (replica mode):
    NSS_MASTER_URL                    Master node endpoint
    NSS_JOIN_TOKEN                    Time-limited join token
    NSS_REPLICA_SUB_MODE              Initial replica sub-mode   [delivery]

OTHER:
    NSS_LOG_LEVEL                     Log level                   [info]
    NSS_INSECURE_DEV                  Dev mode (true/false)       [false]
    NSS_CORS_ALLOW_ORIGINS            Comma-separated CORS origins (* allowed only in insecure dev)
    NSS_S3_PUBLIC_URL                 Public S3 base URL
    NSS_S3_MAX_TIME_SKEW_SECONDS      Max clock skew for S3 auth  [900]
    NSS_UI_DIR                        Path to custom UI build
    NSS_INTERNAL_ADVERTISE            Advertised internal address
    NSS_REPLICA_ADVERTISE             Advertised replica address
";

pub fn print_usage() {
    print!("{USAGE}");
}

pub fn print_version(version: &str) {
    println!("nss {version}");
}

fn handle_cli_flags_from_args(args: &[String], version: &str) -> bool {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return true;
            }
            "-v" | "--version" => {
                print_version(version);
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Check CLI args for --help/-h or --version/-v.
/// Returns `true` if a flag was handled (caller should exit).
pub fn handle_cli_flags(version: &str) -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    handle_cli_flags_from_args(&args, version)
}

#[cfg(test)]
mod tests {
    use super::handle_cli_flags_from_args;

    #[test]
    fn handle_cli_flags_recognizes_help() {
        let args = vec!["--help".to_string()];
        assert!(handle_cli_flags_from_args(&args, "0.1.0"));
    }

    #[test]
    fn handle_cli_flags_recognizes_version() {
        let args = vec!["-v".to_string()];
        assert!(handle_cli_flags_from_args(&args, "0.1.0"));
    }

    #[test]
    fn handle_cli_flags_ignores_unrelated_args() {
        let args = vec!["--migrate-only".to_string()];
        assert!(!handle_cli_flags_from_args(&args, "0.1.0"));
    }

    #[test]
    fn handle_cli_flags_executes_runtime_wrapper() {
        let _ = super::handle_cli_flags("0.1.0");
    }
}
