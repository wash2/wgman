use warp::{Filter, Rejection, Reply};

type Result<T> = std::result::Result<T, Rejection>;

#[tokio::main]
async fn main() {
    let set = warp::path!("set" / String).and(warp::post());
    let remove = warp::path!("remove" / String).and(warp::post());
    let list = warp::path!("list" / String).and(warp::post());

    let interface = warp::path("interface");
    let peer = warp::path("peer");
    let endpoint = warp::path("endpoint");

    let interface_set = interface.and(set).and_then(interface_set_handler);
    let interface_remove = interface.and(remove).and_then(interface_remove_handler);
    let interface_list = interface.and(list).and_then(interface_list_handler);
    
    let peer_set = peer.and(set).and_then(peer_set_handler);
    let peer_remove = peer.and(remove).and_then(peer_remove_handler);
    let peer_list = peer.and(list).and_then(peer_list_handler);
    
    let endpoint_set = endpoint.and(set).and_then(endpoint_set_handler);
    let endpoint_remove = endpoint.and(remove).and_then(endpoint_remove_handler);
    let endpoint_list = endpoint.and(list).and_then(endpoint_list_handler);

    let api_routes = (interface_set
            .or(interface_remove)
            .or(interface_list)
            .or(peer_set)
            .or(peer_remove)
            .or(peer_list)
            .or(endpoint_set)
            .or(endpoint_remove)
            .or(endpoint_list)).with(warp::cors().allow_any_origin());

    let health_route = warp::path("health").and(warp::get()
        .and_then(health_handler)
        .with(warp::cors().allow_any_origin())
        );
    let routes = health_route.or(api_routes);

    println!("Started server at localhost:8000");
    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}

async fn health_handler() -> Result<impl Reply> {
    Ok("OK")
}

async fn interface_set_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("interface_set_handler")
}

async fn interface_remove_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("interface_remove_handler")
}

async fn interface_list_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("interface_list_handler")
}

async fn peer_set_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("peer_set_handler")
}

async fn peer_remove_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("peer_remove_handler")
}

async fn peer_list_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("peer_list_handler")
}

async fn endpoint_set_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("endpoint_set_handler")
}

async fn endpoint_remove_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("endpoint_remove_handler")
}

async fn endpoint_list_handler(_auth_type: String) -> Result<impl Reply> {
    Ok("endpoint_list_handler")
}
