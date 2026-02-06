use axum::{routing::post, Json, Router};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const REGEX_PATTERN: &str = r"/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/";

#[derive(Deserialize)]
struct MatchRequest {
    text: String,
}

#[derive(Serialize)]
struct MatchResponse {
    matched: Option<bool>,
    note: Option<String>,
}

async fn match_handler(Json(req): Json<MatchRequest>) -> Json<MatchResponse> {
    match Regex::new(REGEX_PATTERN) {
        Ok(re) => {
            let matched = re.is_match(&req.text);
            Json(MatchResponse { matched: Some(matched), note: None })
        }
        Err(e) => Json(MatchResponse { matched: None, note: Some(format!("pattern error: {}", e)) }),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start a simple HTTP server with a /match endpoint
    let app = Router::new()
        .route("/match", post(match_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Userspace match endpoint listening on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
