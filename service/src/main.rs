use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod dto;
mod error;
mod library;
mod loader;
mod routes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv()?;

    let port = dotenv::var("PORT").unwrap_or("3000".to_string());

    let filter = if cfg!(debug_assertions) {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "service=debug,tower_http=warn".into())
    } else {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "service=info,tower_http=warn".into())
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/", get(|| async { "online" }))
        .route(
            "/libraries/{library_id}",
            get(routes::libraries::get_library),
        )
        .route(
            "/libraries/{library_id}/mapping",
            get(routes::libraries::get_library_mapping),
        )
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    info!("listening on port {}", port);

    axum::serve(listener, app).await?;

    Ok(())
}
