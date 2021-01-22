use warp::{Filter};

use wgman::{handlers::*, filters};
use wgman::dao::{connect};
use wgman_core::config;

#[tokio::main]
async fn main() {
    //db setup
    let db_cfg = match config::get_db_cfg() {
        Ok(cfg) => {cfg}
        Err(err) => {
            dbg!(err);
            std::process::exit(1);
        }
    };

    let pool = match connect(db_cfg).await {
        Ok(u) => {u},
        Err(_) => {
            std::process::exit(1);
        }
    };

    // routes
    let health_route = warp::path("health")
        .and(warp::get())
        .and_then(health);
    let routes = health_route.or(filters::auth(pool));

    println!("Started server at localhost:8000");
    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}

