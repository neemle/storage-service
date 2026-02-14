pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::shutdown_signal;
    use std::sync::Mutex;
    use tokio::time::{sleep, timeout, Duration};

    static SIGNAL_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    #[cfg(unix)]
    async fn shutdown_signal_handles_sigterm() {
        let _guard = SIGNAL_LOCK.lock().expect("lock");
        let handle = tokio::spawn(async { shutdown_signal().await });
        sleep(Duration::from_millis(50)).await;
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        timeout(Duration::from_secs(2), handle)
            .await
            .expect("timeout")
            .expect("join");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn shutdown_signal_handles_sigint() {
        let _guard = SIGNAL_LOCK.lock().expect("lock");
        let handle = tokio::spawn(async { shutdown_signal().await });
        sleep(Duration::from_millis(50)).await;
        unsafe {
            libc::raise(libc::SIGINT);
        }
        timeout(Duration::from_secs(2), handle)
            .await
            .expect("timeout")
            .expect("join");
    }
}
