use anyhow::{Context, Result};
use axum::{ServiceExt, extract::Request};
use clap::Parser;
use registry::router;
use state::RegistryState;
use std::{fmt::Debug, net::SocketAddr, sync::Arc};
use tokio::task::JoinSet;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod context;
mod digest;
mod error;
mod issuer;
mod jwt;
mod registry;
mod state;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opt {
    #[clap(short, long, value_parser)]
    pub config: Vec<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    let options = Opt::parse();

    let config = crate::config::Configuration::config(crate::config::Configuration::figment(
        options.config,
    ))?;

    let mut tasks: JoinSet<Result<()>> = JoinSet::new();

    let state = Arc::new(RegistryState {
        config: config.clone(),
    });

    let app = router(state.clone());
    let app = ServiceExt::<Request>::into_make_service_with_connect_info::<SocketAddr>(app);

    let listen_addr = format!("0.0.0.0:8084");
    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    tasks.spawn(async move {
        axum::serve(listener, app).await?;
        Ok(())
    });

    tasks.spawn(async {
        tokio::signal::ctrl_c()
            .await
            .context("Unable to listen for ctrl+c")?;
        info!("Received ctrl+c and will shutdown...");
        Ok(())
    });

    let res = tasks.join_next().await;

    tasks.shutdown().await;

    if let Some(result) = res {
        result
            .context("Error while waiting for service to complete")?
            .context("Error running service")?;
    }

    Ok(())
}
