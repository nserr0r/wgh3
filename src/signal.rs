use anyhow::Result;
use tokio::signal::unix::SignalKind;
use tokio::signal::unix::signal;

pub async fn shutdown() -> Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }

    tracing::info!("получен сигнал завершения");
    Ok(())
}
