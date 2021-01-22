pub mod dao {
    use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
    use wgman_core::types::{ApiInterface, ApiPeerRelation, Interface, InterfacePassword, PeerRelation, User, UserPassword};
    use wgman_core::config::DbCfg;

    pub async fn connect(db_cfg: DbCfg) -> Result<Pool<Postgres>, sqlx::Error> {
        Ok(PgPoolOptions::new()
            .max_connections(20)
            .connect(&format!("postgres://{}:{}@{}:{}/{}", db_cfg.user, db_cfg.pw, db_cfg.host, db_cfg.port, db_cfg.name))
            .await?
        )
    }

    pub async fn get_user_by_name(pool: &Pool<Postgres>, name: String) -> Result<User, sqlx::Error> {
        Ok(sqlx::query_as!(User, "SELECT * FROM public.\"User\" Where name = $1", name).fetch_one(pool).await?)
    }

    pub async fn delete_user_by_name(pool: &Pool<Postgres>, name: String) -> Result<(), sqlx::Error> {
        sqlx::query_as!(User, "DELETE FROM public.\"User\" Where name = $1", name).execute(pool).await?;
        Ok(())
    }

    pub async fn get_interfaces(pool: &Pool<Postgres>) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as!(Interface, "SELECT * FROM public.\"Interface\"").fetch_all(pool).await?)
    }

    pub async fn get_interface_by_name(pool: &Pool<Postgres>, name: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as!(Interface, "SELECT * FROM public.\"Interface\" Where name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_peer_relation_interfaces(pool: &Pool<Postgres>, ApiPeerRelation { peer_name, endpoint_name, .. }: &ApiPeerRelation) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as!(Interface, "SELECT * FROM public.\"Interface\" Where name = $1 OR name = $2", peer_name, endpoint_name).fetch_all(pool).await?)
    }

    pub async fn set_interface(pool: &Pool<Postgres>, ApiInterface { name, public_key, port, ip, fqdn, }: &ApiInterface) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.\"Interface\" (
            name, public_key, port, ip, fqdn
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (name)
            DO UPDATE SET
              name = EXCLUDED.name,
              public_key = EXCLUDED.public_key,
              port = EXCLUDED.port,
              ip = EXCLUDED.ip,
              fqdn = EXCLUDED.fqdn ;
        ")
        .bind(name)
        .bind(public_key)
        .bind(port)
        .bind(ip)
        .bind(fqdn)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn delete_interface(pool: &Pool<Postgres>, name: String) -> Result<(), sqlx::Error> {
        sqlx::query_as!(Interface, "DELETE FROM public.\"Interface\" Where name = $1", name).execute(pool).await?;
        Ok(())
    }

    pub async fn get_user_pw(pool: &Pool<Postgres>, name: String) -> Result<UserPassword, sqlx::Error> {
        Ok(sqlx::query_as!(UserPassword, "SELECT pw.id, password_hash, salt FROM public.\"User\" u INNER JOIN public.\"UserPassword\" pw ON u.id= pw.id WHERE name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_interface_pw(pool: &Pool<Postgres>, name: String) -> Result<InterfacePassword, sqlx::Error> {
        Ok(sqlx::query_as!(InterfacePassword, "SELECT pw.id, password_hash, salt FROM public.\"User\" i INNER JOIN public.\"InterfacePassword\" pw ON i.id= pw.id WHERE name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_peers(pool: &Pool<Postgres>, name: String) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as!(PeerRelation, "SELECT * FROM public.\"PeerRelation\" Where endpoint_name = $1", name).fetch_all(pool).await?)
    }

    pub async fn get_endpoints(pool: &Pool<Postgres>, name: String) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as!(PeerRelation, "SELECT * FROM public.\"PeerRelation\" Where peer_name = $1", name).fetch_all(pool).await?)
    }

    pub async fn delete_peer_relation(pool: &Pool<Postgres>, peer: String, endpoint: String) -> Result<(), sqlx::Error> {
        sqlx::query_as!(PeerRelation, "DELETE FROM public.\"PeerRelation\" Where peer_name = $1 AND endpoint_name = $2", peer, endpoint).execute(pool).await?;
        Ok(())
    }

    pub async fn set_peer_relation(pool: &Pool<Postgres>, ApiPeerRelation { peer_name, peer_allowed_ip, endpoint_name, endpoint_allowed_ip, .. }: &ApiPeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as!(PeerRelation, "INSERT INTO public.\"PeerRelation\" (
            peer_name, endpoint_name, peer_allowed_ip, endpoint_allowed_ip
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              peer_name = EXCLUDED.peer_name,
              peer_allowed_ip = EXCLUDED.peer_allowed_ip,
              endpoint_name = EXCLUDED.endpoint_name,
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ", peer_name, endpoint_name, peer_allowed_ip, endpoint_allowed_ip)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_peer(pool: &Pool<Postgres>, ApiPeerRelation { peer_name, endpoint_name, peer_allowed_ip, .. }: &ApiPeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as!(PeerRelation, "INSERT INTO public.\"PeerRelation\" (
            peer_name, endpoint_name, peer_allowed_ip
            ) VALUES ($1, $2, $3)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ", peer_name, endpoint_name, peer_allowed_ip)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_endpoint(pool: &Pool<Postgres>, ApiPeerRelation { peer_name, endpoint_name, endpoint_allowed_ip, .. }: &ApiPeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as!(PeerRelation, "INSERT INTO public.\"PeerRelation\" (
            peer_name, endpoint_name, endpoint_allowed_ip
            ) VALUES ($1, $2, $3)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ", peer_name, endpoint_name, endpoint_allowed_ip)
        .execute(pool).await?;
        Ok(())
    }
}

pub mod handlers {
    use std::{error::Error, convert::{Infallible, TryInto}};
    use sqlx::{Pool, Postgres};
    use types::{ApiInterface, ApiPeerRelation};
    use warp::{Rejection, Reply, reject};
    use wgman_core::types::{self, AuthKind, BasicAuth, Interface, InterfacePassword, UserPassword};
    use wgman_core::auth::{verify, Hash};
    use crate::dao;

    type WarpResult<T> = std::result::Result<T, Rejection>;

    #[derive(Debug)]
    struct AuthenticationErr;
    impl reject::Reject for AuthenticationErr {}

    #[derive(Debug)]
    struct AuthorizationErr;
    impl reject::Reject for AuthorizationErr {}

    #[derive(Debug)]
    struct DatabaseErr;
    impl reject::Reject for DatabaseErr {}

    #[derive(Debug)]
    struct UnknownErr;
    impl reject::Reject for UnknownErr {}

    async fn authenticate(auth_type: &AuthKind, BasicAuth { name, password } : &BasicAuth, pool: &Pool<Postgres>) -> Result<(), Box<dyn Error>> {
        match auth_type {
            AuthKind::User => {
                let UserPassword { id: _, password_hash, salt }: UserPassword = dao::get_user_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash.as_bytes().try_into()?, salt: salt.as_bytes().try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
            AuthKind::Interface => {
                let InterfacePassword { id: _, password_hash, salt }: InterfacePassword = dao::get_interface_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash.as_bytes().try_into()?, salt: salt.as_bytes().try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
        }
    }

    pub async fn health() -> Result<impl Reply, Infallible> {
        Ok("OK")
    }
    
    pub async fn interface_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, interface: ApiInterface) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::User => Ok(()),
            AuthKind::Interface if bauth.name == interface.name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::set_interface(&pool, &interface).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("interface set")
    }
    
    pub async fn interface_remove(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, interface: ApiInterface) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::User => Ok(()),
            AuthKind::Interface if bauth.name == interface.name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::delete_interface(&pool, interface.name).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("interface removed")
    }
    
    pub async fn interface_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        let interfaces: Vec<ApiInterface> = match dao::get_interfaces(&pool).await {
            Ok(interfaces) => Ok(interfaces.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok(warp::reply::json(&interfaces))
    }
    
    pub async fn peer_relation_interfaces(pool: &Pool<Postgres>, pr: &ApiPeerRelation) -> Result<Vec<Interface>, Rejection> {
        match dao::get_peer_relation_interfaces(pool, pr).await {
            Ok(mut interfaces) if interfaces.len() == 2 => {
                if interfaces[0].name == pr.endpoint_name {
                    interfaces.reverse();
                }
                Ok(interfaces)
            },
            _ => Err(reject::custom(DatabaseErr))
        }
    }

    pub async fn peer_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, pr: ApiPeerRelation) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::User => Ok(()),
            AuthKind::Interface if bauth.name == pr.endpoint_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;

        match dao::set_peer(&pool, &pr).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("peer set")
    }
    
    pub async fn peer_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, interface: ApiInterface) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;

        let peers: Vec<ApiPeerRelation> = match dao::get_peers(&pool, interface.name).await {
            Ok(peers) => Ok(peers.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&peers))
    }
    
    pub async fn endpoint_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, pr: ApiPeerRelation) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::User => Ok(()),
            AuthKind::Interface if bauth.name == pr.peer_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        
        match dao::set_endpoint(&pool, &pr).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("endpoint_set")
    }
    
    pub async fn peer_relation_remove(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, pr: ApiPeerRelation) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::User => Ok(()),
            AuthKind::Interface if bauth.name == pr.peer_name || bauth.name == pr.endpoint_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::delete_peer_relation(&pool, pr.peer_name, pr.endpoint_name).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok("endpoint_remove")
    }
    
    pub async fn endpoint_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, interface: ApiInterface) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;

        let endpoints: Vec<ApiPeerRelation> = match dao::get_endpoints(&pool, interface.name).await {
            Ok(endpoints) => Ok(endpoints.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&endpoints))
    }
}

pub mod filters {
    use sqlx::{Pool, Postgres};
    use warp::Filter;

    use crate::handlers;
    use wgman_core::types::{ApiInterface, ApiPeerRelation, ApiUser, AuthKind, BasicAuth};
        

    pub fn with_auth(auth_kind: AuthKind) -> impl Filter<Extract = (AuthKind,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || auth_kind.clone())
    }

    pub fn with_db(db: Pool<Postgres>) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
    }

    pub fn with_user(user: ApiUser) -> impl Filter<Extract = (ApiUser,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || user.clone())
    }    

    fn with_interface() -> impl Filter<Extract = (ApiInterface,), Error = warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16)
            .and(warp::body::json())
    }

    fn with_peer() -> impl Filter<Extract = (ApiPeerRelation,), Error = warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16)
            .and(warp::body::json())
    }

    pub fn auth(
        pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::any()
        // interface
        .and(warp::path("iauth").and(interface_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(interface_set(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(interface_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(interface_list(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(interface_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(interface_remove(AuthKind::User, pool.clone()))))
        // peers
        .or(warp::path("iauth").and(peer_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(peer_set(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(peer_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(peer_list(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(peer_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(peer_remove(AuthKind::User, pool.clone()))))
        // endpoints
        .or(warp::path("iauth").and(endpoint_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(endpoint_set(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(endpoint_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(endpoint_list(AuthKind::User, pool.clone()))))
        .or(warp::path("iauth").and(endpoint_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("uauth").and(endpoint_remove(AuthKind::User, pool.clone()))))
    }

    fn interface_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::post())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_interface())
        .and_then(handlers::interface_set)
    }

    fn interface_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::get())
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_list)
    }

    fn interface_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::delete())
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_interface())
        .and_then(handlers::interface_remove)
    }

    fn peer_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("peer")
        .and(warp::post())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_peer())
        .and_then(handlers::peer_set)
    }

    fn peer_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("peer")
        .and(warp::get())
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_interface())
        .and_then(handlers::peer_list)
    }

    fn peer_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("peer")
        .and(warp::delete())
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_peer())
        .and_then(handlers::peer_relation_remove)
    }

    fn endpoint_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("endpoint")
        .and(warp::post())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_peer())
        .and_then(handlers::endpoint_set)
    }

    fn endpoint_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("endpoint")
        .and(warp::get())
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_interface())
        .and_then(handlers::endpoint_list)
    }

    fn endpoint_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("endpoint")
        .and(warp::delete())
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_peer())
        .and_then(handlers::peer_relation_remove)
    }
}
