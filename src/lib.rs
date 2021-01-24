pub mod dao {
    use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
    use wgman_core::types::{ApiPeerRelation, Interface, InterfacePassword, PeerRelation, Admin, AdminPassword};
    use wgman_core::config::DbCfg;

    pub async fn connect(db_cfg: DbCfg) -> Result<Pool<Postgres>, sqlx::Error> {
        Ok(PgPoolOptions::new()
            .max_connections(20)
            .connect(&format!("postgres://{}:{}@{}:{}/{}", db_cfg.user, db_cfg.pw, db_cfg.host, db_cfg.port, db_cfg.name))
            .await?
        )
    }

    pub async fn get_admins(pool: &Pool<Postgres>) -> Result<Vec<Admin>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Admin>("SELECT * FROM public.admin")
        .fetch_all(pool)
        .await?)
    }


    pub async fn get_admin(pool: &Pool<Postgres>, u_name: String) -> Result<Admin, sqlx::Error> {
        Ok(sqlx::query_as::<_, Admin>("SELECT * FROM public.admin WHERE u_name = $1")
        .bind(u_name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn delete_admin(pool: &Pool<Postgres>, Admin { u_name, .. }: Admin) -> Result<Vec<Admin>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Admin>( "DELETE FROM public.admin Where u_name = $1")
        .bind(u_name)
        .fetch_all(pool)
        .await?)
        
    }

    pub async fn set_admin(pool: &Pool<Postgres>, Admin { u_name, is_root, .. }: Admin) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, Admin>( "INSERT INTO public.interface (
            u_name, is_root
            ) VALUES ($1, $2)
            ON CONFLICT (u_name)
            DO UPDATE SET
              is_root = EXCLUDED.is_root ;
        ")
        .bind(u_name)
        .bind(is_root)
        .fetch_all(pool)
        .await?;
        Ok(())
    }

    pub async fn get_interfaces(pool: &Pool<Postgres>) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface")
        .fetch_all(pool)
        .await?)
    }

    pub async fn get_interface_by_name(pool: &Pool<Postgres>, name: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where u_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_peer_relation_interfaces(pool: &Pool<Postgres>, ApiPeerRelation { peer_name, endpoint_name, .. }: &ApiPeerRelation) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where u_name = $1 OR u_name = $2")
        .bind(peer_name)
        .bind(endpoint_name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn set_interface(pool: &Pool<Postgres>, Interface { u_name, public_key, port, ip, fqdn, .. }: &Interface) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.interface (
            name, public_key, port, ip, fqdn
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (u_name)
            DO UPDATE SET
              public_key = EXCLUDED.public_key,
              port = EXCLUDED.port,
              ip = EXCLUDED.ip,
              fqdn = EXCLUDED.fqdn ;
        ")
        .bind(u_name)
        .bind(public_key)
        .bind(port)
        .bind(ip)
        .bind(fqdn)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_admin_pw(pool: &Pool<Postgres>, AdminPassword { id, u_name, password_hash, salt }: &AdminPassword) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.admin_password (
            id, u_name, password_hash, salt
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (id)
            DO UPDATE SET
              password_hash = EXCLUDED.password_hash,
              salt = EXCLUDED.salt ;
        ")
        .bind(id)
        .bind(u_name)
        .bind(password_hash)
        .bind(salt)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_interface_pw(pool: &Pool<Postgres>, InterfacePassword { id, u_name, password_hash, salt }: &InterfacePassword) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.interface_password (
            id, u_name, password_hash, salt
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (id)
            DO UPDATE SET
              password_hash = EXCLUDED.password_hash,
              salt = EXCLUDED.salt ;
        ")
        .bind(id)
        .bind(u_name)
        .bind(password_hash)
        .bind(salt)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn delete_interface(pool: &Pool<Postgres>, name: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("DELETE FROM public.interface Where u_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_admin_pw(pool: &Pool<Postgres>, name: String) -> Result<AdminPassword, sqlx::Error> {
        Ok(sqlx::query_as::<_, AdminPassword>("SELECT * FROM public.admin_password WHERE u_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_interface_pw(pool: &Pool<Postgres>, name: String) -> Result<InterfacePassword, sqlx::Error> {
        Ok(sqlx::query_as::<_, InterfacePassword>("SELECT * FROM public.interface_password WHERE u_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_peers(pool: &Pool<Postgres>, name: String) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation Where endpoint_name = $1")
        .bind(name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn get_endpoints(pool: &Pool<Postgres>, name: String) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation Where peer_name = $1")
        .bind(name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn delete_peer_relation(pool: &Pool<Postgres>, peer: String, endpoint: String) -> Result<PeerRelation, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("DELETE FROM public.peer_relation Where peer_name = $1 AND endpoint_name = $2")
        .bind(peer)
        .bind(endpoint)
        .fetch_one(pool)
        .await?)
    }

    pub async fn set_peer_relation(pool: &Pool<Postgres>, PeerRelation { peer_name, peer_allowed_ip, endpoint_name, endpoint_allowed_ip, .. }: &PeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, PeerRelation>("INSERT INTO public.peer_relation (
            peer_name, endpoint_name, peer_allowed_ip, endpoint_allowed_ip
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              peer_name = EXCLUDED.peer_name,
              peer_allowed_ip = EXCLUDED.peer_allowed_ip,
              endpoint_name = EXCLUDED.endpoint_name,
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ")
        .bind(peer_name)
        .bind(endpoint_name)
        .bind(peer_allowed_ip)
        .bind(endpoint_allowed_ip)
        .fetch_all(pool).await?;
        Ok(())
    }

    pub async fn set_peer(pool: &Pool<Postgres>, PeerRelation { peer_name, endpoint_name, peer_allowed_ip, .. }: &PeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, PeerRelation>("INSERT INTO public.peer_relation (
            peer_name, endpoint_name, peer_allowed_ip
            ) VALUES ($1, $2, $3)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ")
        .bind(peer_name)
        .bind(endpoint_name)
        .bind(peer_allowed_ip)
        .fetch_all(pool).await?;
        Ok(())
    }

    pub async fn set_endpoint(pool: &Pool<Postgres>, PeerRelation { peer_name, endpoint_name, endpoint_allowed_ip, .. }: &PeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, PeerRelation>("INSERT INTO public.peer_relation (
            peer_name, endpoint_name, endpoint_allowed_ip
            ) VALUES ($1, $2, $3)
            ON CONFLICT (peer_name, endpoint_name)
            DO UPDATE SET
              endpoint_allowed_ip = EXCLUDED.endpoint_allowed_ip ;
        ")
        .bind(peer_name)
        .bind(endpoint_name)
        .bind(endpoint_allowed_ip)
        .fetch_all(pool).await?;
        Ok(())
    }
}

// TODO better error handling
pub mod handlers {
    use std::{error::Error, convert::{Infallible, TryInto}};
    use sqlx::{Pool, Postgres};
    use types::{ApiInterface, ApiPeerRelation};
    use warp::{Rejection, Reply, reject};
    use wgman_core::types::{self, AdminPassword, ApiAdminPassword, ApiInterfacePassword, AuthKind, BasicAuth, Interface, InterfacePassword};
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

    #[derive(Debug)]
    struct ValidationErr;
    impl reject::Reject for ValidationErr {}
    // TODO refactor authentication

    async fn authenticate(auth_type: &AuthKind, BasicAuth { name, password } : &BasicAuth, pool: &Pool<Postgres>) -> Result<(), Box<dyn Error>> {
        match auth_type {
            AuthKind::Admin => {
                let AdminPassword { id: _, u_name: _, password_hash, salt }: AdminPassword = dao::get_admin_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash[..].try_into()?, salt: salt[..].try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
            AuthKind::Interface => {
                let InterfacePassword { id: _, u_name: _, password_hash, salt }: InterfacePassword = dao::get_interface_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash[..].try_into()?, salt: salt[..].try_into()? }, password) {
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
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == interface.u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        // validation
        let interface: WarpResult<Interface> = match interface.try_into() {
            Ok(i) => Ok(i),
            Err(_) => Err(reject::custom(ValidationErr))
        };

        match dao::set_interface(&pool, &interface?).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("interface set")
    }
    
    pub async fn admin_set_pw(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, pw: ApiAdminPassword) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin if bauth.name == pw.u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        // validation
        let pw: WarpResult<AdminPassword> = match pw.try_into() {
            Ok(i) => Ok(i),
            Err(_) => Err(reject::custom(ValidationErr))
        };

        match dao::set_admin_pw(&pool, &pw?).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("interface set")
    }

    pub async fn interface_set_pw(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, pw: ApiInterfacePassword) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == pw.u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        // validation
        let pw: WarpResult<InterfacePassword> = match pw.try_into() {
            Ok(i) => Ok(i),
            Err(_) => Err(reject::custom(ValidationErr))
        };

        match dao::set_interface_pw(&pool, &pw?).await {
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
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == interface.u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::delete_interface(&pool, interface.u_name).await {
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
                if interfaces[0].u_name == pr.endpoint_name {
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
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == pr.endpoint_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;

        match dao::set_peer(&pool, &pr.into()).await {
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

        let peers: Vec<ApiPeerRelation> = match dao::get_peers(&pool, interface.u_name).await {
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
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == pr.peer_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        
        match dao::set_endpoint(&pool, &pr.into()).await {
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
            AuthKind::Admin => Ok(()),
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

        let endpoints: Vec<ApiPeerRelation> = match dao::get_endpoints(&pool, interface.u_name).await {
            Ok(endpoints) => Ok(endpoints.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&endpoints))
    }
}

pub mod filters {
    use handlers::interface_set_pw;
    use sqlx::{Pool, Postgres};
    use warp::Filter;

    use crate::handlers;
    use wgman_core::types::{ApiAdmin, ApiAdminPassword, ApiInterface, ApiInterfacePassword, ApiPeerRelation, AuthKind, BasicAuth};
        

    pub fn with_auth(auth_kind: AuthKind) -> impl Filter<Extract = (AuthKind,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || auth_kind.clone())
    }

    pub fn with_db(db: Pool<Postgres>) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
    }

    pub fn with_user(user: ApiAdmin) -> impl Filter<Extract = (ApiAdmin,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || user.clone())
    }    

    fn with_interface() -> impl Filter<Extract = (ApiInterface,), Error = warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16)
            .and(warp::body::json())
    }

    fn with_interface_pw() -> impl Filter<Extract = (ApiInterfacePassword,), Error = warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16)
            .and(warp::body::json())
    }


    fn with_admin_pw() -> impl Filter<Extract = (ApiAdminPassword,), Error = warp::Rejection> + Clone {
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
            .or(warp::path("aauth").and(interface_set(AuthKind::Admin, pool.clone()))))

        .or(warp::path("iauth").and(interface_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(interface_list(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(interface_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(interface_remove(AuthKind::Admin, pool.clone()))))
        // peers
        .or(warp::path("iauth").and(peer_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_set(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(peer_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_list(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(peer_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_remove(AuthKind::Admin, pool.clone()))))
        // endpoints
        .or(warp::path("iauth").and(endpoint_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(endpoint_set(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(endpoint_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(endpoint_list(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(endpoint_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(endpoint_remove(AuthKind::Admin, pool.clone()))))
        // admin
        .or(warp::path("iauth").and(admin_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(admin_set(AuthKind::Admin, pool.clone()))))

    }

    fn admin_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("admin")
        .and(warp::post())
        .and(warp::path("pw"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_admin_pw())
        .and_then(handlers::admin_set_pw)
    }

    fn interface_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::post())
        .and(
            (warp::path("pw")
            .and(with_auth(auth_kind.clone()))
            .and(warp::header::<BasicAuth>("authorization"))
            .and(with_db(pool.clone()))
            .and(with_interface_pw())
            .and_then(handlers::interface_set_pw))
            .or(
            with_auth(auth_kind)
            .and(warp::header::<BasicAuth>("authorization"))
            .and(with_db(pool))
            .and(with_interface())
            .and_then(handlers::interface_set)
            )
        )

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

// TODO add unit tests for handlers
#[cfg(test)]
pub mod tests {
    use std::{error::Error, fmt, net::{IpAddr, Ipv4Addr}, panic, vec};

    use ipnetwork::IpNetwork;
    use sqlx::{Pool, Postgres};
    use wgman_core::{auth::encrypt, config, types::{Admin, AdminPassword, Interface, PeerRelation}};
    use futures::executor::block_on;

    use crate::{dao};

    #[derive(Debug)]
    struct FailedValidationErr;
    impl fmt::Display for FailedValidationErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "FailedValidationErr")
        }
    }
    
    impl Error for FailedValidationErr {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            None
        }
    }

    #[tokio::main]
    async fn run_test_with_pool<T>(test: T) -> Result<(), Box<dyn Error>>
    where T: FnOnce(&Pool<Postgres>) -> Result<(), Box<dyn Error>> + panic::UnwindSafe
    {
        let result = panic::catch_unwind(|| {
            let db_cfg = match config::get_db_cfg() {
                Ok(cfg) => {cfg}
                Err(err) => {
                    dbg!(err);
                    std::process::exit(1);
                }
            };
    
            let pool = block_on(dao::connect(db_cfg)).unwrap();  
            test(&pool)
        });    
        // teardown();    
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_set_admin() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let inserted_admin = Admin {
                u_name: String::from("test-admin"), 
                is_root: false, 
                id: Default::default() 
            };
            block_on(
                dao::set_admin(
                    pool, 
                    inserted_admin.clone()
                )
            )?;
            let retrieved_admin = block_on(
                sqlx::query_as::<_, Admin>("SELECT * FROM public.admin WHERE u_name = $1")
                .bind(&inserted_admin.u_name)
                .fetch_one(pool)
            )?;
            assert_eq!(inserted_admin, retrieved_admin);

            let failed_admin = Admin { 
                id: Default::default(),
                u_name: String::from("test::admin"),
                is_root: false,
            };
            match block_on(
                dao::set_admin(
                    pool, 
                    failed_admin
                )
            ) {
                Ok(_) => Err(FailedValidationErr),
                Err(_) => Ok(())
            }?;
            Ok(())
        })
    }

    #[test]
    fn test_set_interface() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            // test normal insertion
            let inserted_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface"),
                public_key: Some(String::from("public key")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,

            };
            block_on(
                dao::set_interface(
                    pool, 
                    &inserted_interface
                )
            )?;
            let retrieved_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&inserted_interface.u_name)
                .fetch_one(pool)
            )?;
            assert_eq!(inserted_interface, retrieved_interface);

            // test insertion with invalid name
            let failed_interface = Interface { 
                id: Default::default(),
                u_name: String::from("test::admin"),
                public_key: Some(String::from("public key")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
            };
            match block_on(
                dao::set_interface(
                    pool, 
                    &failed_interface
                )
            ) {
                Ok(_) => Err(FailedValidationErr),
                Err(_) => Ok(())
            }?;
            Ok(())
        })    
    }

    #[test]
    fn test_set_peer_relation() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let endpoint_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_1"),
                public_key: Some(String::from("public key 1")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,

            };
            block_on(
                dao::set_interface(
                    pool, 
                    &endpoint_interface
                )
            )?;
            let peer_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_2"),
                public_key: Some(String::from("public key 2")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,

            };
            block_on(
                dao::set_interface(
                    pool, 
                    &peer_interface
                )
            )?;
            let endpoint_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&endpoint_interface.u_name)
                .fetch_one(pool)
            )?;
            let peer_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&peer_interface.u_name)
                .fetch_one(pool)
            )?;
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: endpoint_interface.id,
                peer_id: peer_interface.id,
                peer_name: peer_interface.u_name,
                endpoint_name: endpoint_interface.u_name,
                endpoint_allowed_ip: vec![],
                peer_allowed_ip: vec![],
            };

            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            let retrieved_peer_relation = block_on(
                sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation WHERE peer_name = $1 AND endpoint_name = $2")
                .bind(&inserted_peer_relation.peer_name)
                .bind(&inserted_peer_relation.endpoint_name)
                .fetch_one(pool)
            )?;
            assert_eq!(inserted_peer_relation, retrieved_peer_relation);

            Ok(())
        })     
    }

    #[test]
    fn test_set_endpoint() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: Default::default(),
                peer_id: Default::default(),
                peer_name: "test_interface_2".into(),
                endpoint_name: "test_interface_1".into(),
                endpoint_allowed_ip: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192,168,0,0)), 24)?],
                peer_allowed_ip: vec![],
            };

            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            let retrieved_peer_relation = block_on(
                sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation WHERE peer_name = $1 AND endpoint_name = $2")
                .bind(&inserted_peer_relation.peer_name)
                .bind(&inserted_peer_relation.endpoint_name)
                .fetch_one(pool)
            )?;
            assert_eq!(inserted_peer_relation, retrieved_peer_relation);
            Ok(())
        })     
    }

    #[test]
    fn test_get_interface_pw() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: Default::default(),
                peer_id: Default::default(),
                peer_name: "test_interface_2".into(),
                endpoint_name: "test_interface_1".into(),
                endpoint_allowed_ip: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192,168,0,0)), 24)?],
                peer_allowed_ip: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0)?],
            };

            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            let retrieved_peer_relation = block_on(
                sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation WHERE peer_name = $1 AND endpoint_name = $2")
                .bind(&inserted_peer_relation.peer_name)
                .bind(&inserted_peer_relation.endpoint_name)
                .fetch_one(pool)
            )?;
            assert_eq!(inserted_peer_relation, retrieved_peer_relation);

            Ok(())
        })     
    }

    #[test]
    fn test_get_interfaces() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            // test normal insertion
            let inserted_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_get_interfaces"),
                public_key: Some(String::from("public key get interfaces")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,

            };
            block_on(
                dao::set_interface(
                    pool, 
                    &inserted_interface
                )
            )?;
            assert!(block_on(
                dao::get_interfaces(
                    pool, 
                )
            )?.len() > 0);

            Ok(())
        })
    }

    #[test]
    fn test_get_endpoints() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let endpoint_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_1_get_endpoints"),
                public_key: Some(String::from("public key get_endpoints")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &endpoint_interface
                )
            )?;
            let peer_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_2_get_endpoints"),
                public_key: Some(String::from("public key 2 get_endpoints")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &peer_interface
                )
            )?;
            let endpoint_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&endpoint_interface.u_name)
                .fetch_one(pool)
            )?;
            let peer_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&peer_interface.u_name)
                .fetch_one(pool)
            )?;
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: endpoint_interface.id,
                peer_id: peer_interface.id.clone(),
                peer_name: peer_interface.u_name.clone(),
                endpoint_name: endpoint_interface.u_name,
                endpoint_allowed_ip: vec![],
                peer_allowed_ip: vec![],
            };
            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            assert!(block_on(
                dao::get_endpoints(
                    pool,
                    String::from(&peer_interface.u_name), 
                )
            )?.len() > 0);

            Ok(())
        })    
    }

    #[test]
    fn test_get_peers() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let endpoint_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_1_get_peers"),
                public_key: Some(String::from("public key get_peers")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &endpoint_interface
                )
            )?;
            let peer_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_2_get_peers"),
                public_key: Some(String::from("public key 2 get_peers")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &peer_interface
                )
            )?;
            let endpoint_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&endpoint_interface.u_name)
                .fetch_one(pool)
            )?;
            let peer_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&peer_interface.u_name)
                .fetch_one(pool)
            )?;
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: endpoint_interface.id,
                peer_id: peer_interface.id.clone(),
                peer_name: peer_interface.u_name.clone(),
                endpoint_name: endpoint_interface.u_name,
                endpoint_allowed_ip: vec![],
                peer_allowed_ip: vec![],
            };
            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            assert!(block_on(
                dao::get_peers(
                    pool,
                    String::from("test_interface_1"), 
                )
            )?.len() == 1);

            Ok(())
        })    
    }

    #[test]
    fn test_get_admin_pw() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let new_pw_hash = encrypt("password").unwrap();
            let Admin {id, ..} = block_on(
                dao::get_admin(
                    pool,
                    "root".into()
                )
            )?;
            let new_pw  = AdminPassword {
                id,
                u_name: "root".into(),
                password_hash: new_pw_hash.pbkdf2_hash.into(),
                salt: new_pw_hash.salt.into(),
            };
            block_on(
                dao::set_admin_pw(
                    pool,
                    &new_pw
                )
            )?;
            assert_eq!(new_pw, block_on(dao::get_admin_pw(pool, "root".into()))?);
            Ok(())
        })
    }

    #[test]
    fn test_get_admins() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let inserted_admin = Admin {
                u_name: String::from("test-get-admins"), 
                is_root: false, 
                id: Default::default() 
            };
            block_on(
                dao::set_admin(
                    pool, 
                    inserted_admin.clone()
                )
            )?;
            assert!(block_on(
                dao::get_admins(
                    pool, 
                )
            )?.len() > 0);

            Ok(())
        })    
    }
    #[test]
    fn test_remove_endpoint() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let endpoint_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_1_delete_endpoints"),
                public_key: Some(String::from("public key delete_endpoints")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &endpoint_interface
                )
            )?;
            let peer_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_2_delete_endpoints"),
                public_key: Some(String::from("public key 2 delete_endpoints")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,
    
            };
            block_on(
                dao::set_interface(
                    pool, 
                    &peer_interface
                )
            )?;
            let endpoint_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&endpoint_interface.u_name)
                .fetch_one(pool)
            )?;
            let peer_interface = block_on(
                sqlx::query_as::<_, Interface>("SELECT * FROM public.interface WHERE u_name = $1")
                .bind(&peer_interface.u_name)
                .fetch_one(pool)
            )?;
            // test normal insertion
            let inserted_peer_relation = PeerRelation {
                endpoint_id: endpoint_interface.id,
                peer_id: peer_interface.id.clone(),
                peer_name: peer_interface.u_name.clone(),
                endpoint_name: endpoint_interface.u_name.clone(),
                endpoint_allowed_ip: vec![],
                peer_allowed_ip: vec![],
            };
            block_on(
                dao::set_peer_relation(
                    pool, 
                    &inserted_peer_relation
                )
            )?;
            let deleted_peer_relation = block_on(
                dao::delete_peer_relation(
                    pool,
                    peer_interface.u_name.into(),
                    endpoint_interface.u_name.into()
                )
            )?;
            assert!(deleted_peer_relation.peer_name == String::from("test_interface_2"));

            Ok(())
        })
    }

    #[test]
    fn test_remove_interface() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let endpoint_interface = Interface {
                id: Default::default(),
                u_name: String::from("test_interface_delete"),
                public_key: Some(String::from("public key 1")),
                port: Some(6900),
                ip: (Default::default()),
                fqdn: None,

            };
            block_on(
                dao::set_interface(
                    pool, 
                    &endpoint_interface
                )
                )?;
            let deleted_interface = block_on(
                dao::delete_interface(
                    pool,
                    "test_interface_delete".into()
                )
            )?;
            assert!(deleted_interface.u_name == String::from("test_interface_2"));

            Ok(())
        })
    }

    #[test]
    fn test_remove_admin() -> Result<(), Box<dyn Error>> {
        run_test_with_pool(|pool| {
            let deleted_interface = block_on(
                dao::delete_interface(
                    pool,
                    "root".into()
                )
            )?;
            assert!(deleted_interface.u_name == String::from("root"));

            Ok(())
        })    }
}
