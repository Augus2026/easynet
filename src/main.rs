mod client;
mod codec;
mod common;
mod config;
mod server;
mod transport;
mod tun_device;

use anyhow::Result;
use crate::config::AppConfig;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    let app_config = AppConfig::load()?;

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(app_config.runtime.log_level.clone()),
    )
    .init();

    match app_config.runtime.mode.to_lowercase().as_str() {
        "server" => {
            info!("Starting server");
            server::run_server().await
        }
        "client" => {
            info!("Starting client");
            client::run_client().await
        }
        mode => Err(anyhow::anyhow!(
            "Invalid runtime.mode '{}', expected 'client' or 'server'",
            mode
        )),
    }
}
