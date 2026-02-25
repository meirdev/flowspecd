mod api;
mod bgp;
mod config;
mod flowspec;
mod forwarding;
mod ipfix;
mod router;
mod stats;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "rust-router")]
#[command(about = "Minimal router with BGP FlowSpec and IPFIX support")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/router.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = config::Config::load(&args.config)?;

    // Setup logging
    let log_level = if args.verbose {
        "debug"
    } else {
        &config.router.log_level
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Loaded configuration from {:?}", args.config);

    // Create and run router
    let router = router::Router::new(config);
    router.run().await
}
