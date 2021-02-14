use warp::Filter;

use wgman::{handlers::{health, index, handle_rejection}, filters};
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
    let index_route = warp::get()
    .and(warp::path::end())
    .and_then(index);
    let routes = health_route.or(index_route).or(filters::auth(pool.clone()));


    match get_interfaces(&pool).await {
        Ok(_) => {},
        Err(error) => {
            println!("Error making test operation on DB:\n {}", error);
            std::process::exit(1);
        }
    };

    let api_port: u16 = match config::get_api_cfg() {
        Ok(c) => match str::parse::<u16>(&c.port) {
            Ok(p) => p,
            Err(e) => {
                println!("Error parsing api config port: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            println!("Error loading api cfg: {}", e);
            std::process::exit(1);
        }
    };
    println!("Started server at localhost:{}", &api_port);
    warp::serve(routes.recover(handle_rejection)).run(([0, 0, 0, 0], api_port)).await;
}

