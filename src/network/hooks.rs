use tokio::process::Command;

pub async fn run_all(commands: &[String], tun_name: &str, label: &str) {
    for cmd in commands {
        let cmd = cmd.replace("%i", tun_name);
        tracing::info!(%label, %cmd, "выполнение хука");

        let status = Command::new("sh").arg("-c").arg(&cmd).status().await;

        match status {
            Ok(status) if status.success() => {}
            Ok(status) => tracing::warn!(%label, %status, "команда вернула ненулевой код"),
            Err(err) => tracing::warn!(%label, ?err, "не удалось запустить хук"),
        }
    }
}
