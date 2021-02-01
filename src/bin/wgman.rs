use warp::{Filter};

use wgman::{handlers::*, filters};
use wgman::dao::{connect, get_interfaces};
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
    let routes = health_route.or(filters::auth(pool.clone()));


    match get_interfaces(&pool).await {
        Ok(_) => {},
        Err(error) => {
            println!("Error making test operation on DB:\n {}", error);
            std::process::exit(1);
        }
    };

    println!("Started server at localhost:8000");
    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}

