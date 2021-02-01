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

    pub async fn get_interface_by_public_key(pool: &Pool<Postgres>, public_key: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where public_key = $1")
        .bind(public_key)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_interface(pool: &Pool<Postgres>, name: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where u_name = $1")
        .bind(name)
        .fetch_one(pool)
        .await?)
    }

    pub async fn get_peer_relation_interfaces(pool: &Pool<Postgres>, ApiPeerRelation { peer_public_key, endpoint_public_key, .. }: &ApiPeerRelation) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where u_name = $1 OR u_name = $2")
        .bind(peer_public_key)
        .bind(endpoint_public_key)
        .fetch_all(pool)
        .await?)
    }

    pub async fn set_interface(pool: &Pool<Postgres>, Interface { u_name, public_key, port, ip, fqdn, .. }: &Interface) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.interface (
            u_name, public_key, port, ip, fqdn
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (u_name)
            DO UPDATE SET
              public_key = COALESCE(EXCLUDED.public_key, public.interface.public_key),
              port = COALESCE(EXCLUDED.port, public.interface.port),
              ip = COALESCE(EXCLUDED.ip, public.interface.ip),
              fqdn = COALESCE(EXCLUDED.fqdn, public.interface.fqdn) ;
        ")
        .bind(u_name)
        .bind(public_key)
        .bind(port)
        .bind(ip)
        .bind(fqdn)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_admin_pw(pool: &Pool<Postgres>, AdminPassword { u_name, password_hash, salt }: &AdminPassword) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.admin_password (
            u_name, password_hash, salt
            ) VALUES ($1, $2, $3)
            ON CONFLICT (u_name)
            DO UPDATE SET
              password_hash = EXCLUDED.password_hash,
              salt = EXCLUDED.salt ;
        ")
        .bind(u_name)
        .bind(password_hash)
        .bind(salt)
        .execute(pool).await?;
        Ok(())
    }

    pub async fn set_interface_pw(pool: &Pool<Postgres>, InterfacePassword { u_name, password_hash, salt }: &InterfacePassword) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO public.interface_password (
            u_name, password_hash, salt
            ) VALUES ($1, $2, $3)
            ON CONFLICT (u_name)
            DO UPDATE SET
              password_hash = EXCLUDED.password_hash,
              salt = EXCLUDED.salt ;
        ")
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
        Ok(sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation Where endpoint_public_key = $1")
        .bind(name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn get_endpoints(pool: &Pool<Postgres>, name: String) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("SELECT * FROM public.peer_relation Where peer_public_key = $1")
        .bind(name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn delete_peer_relation(pool: &Pool<Postgres>, peer: String, endpoint: String) -> Result<PeerRelation, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("DELETE FROM public.peer_relation Where peer_public_key = $1 AND endpoint_public_key = $2")
        .bind(peer)
        .bind(endpoint)
        .fetch_one(pool)
        .await?)
    }

    pub async fn set_peer_relation(pool: &Pool<Postgres>, PeerRelation { peer_public_key, peer_allowed_ip, endpoint_public_key, endpoint_allowed_ip, .. }: &PeerRelation) -> Result<(), sqlx::Error> {
        sqlx::query_as::<_, PeerRelation>("INSERT INTO public.peer_relation (
            peer_public_key, endpoint_public_key, peer_allowed_ip, endpoint_allowed_ip
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (peer_public_key, endpoint_public_key)
            DO UPDATE SET
              peer_public_key = COALESCE(EXCLUDED.peer_public_key, public.peer_relation.peer_public_key),
              peer_allowed_ip = COALESCE(EXCLUDED.peer_allowed_ip, public.peer_relation.peer_allowed_ip),
              endpoint_public_key = COALESCE(EXCLUDED.endpoint_public_key, public.peer_relation.endpoint_public_key),
              endpoint_allowed_ip = COALESCE(EXCLUDED.endpoint_allowed_ip, public.peer_relation.endpoint_allowed_ip) ;
        ")
        .bind(peer_public_key)
        .bind(endpoint_public_key)
        .bind(peer_allowed_ip)
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
    // TODO refactor authentication, add proper error handling

    async fn authenticate(auth_type: &AuthKind, BasicAuth { name, password } : &BasicAuth, pool: &Pool<Postgres>) -> Result<(), Box<dyn Error>> {
        match auth_type {
            AuthKind::Admin => {
                let AdminPassword { u_name: _, password_hash, salt }: AdminPassword = dao::get_admin_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash[..].try_into()?, salt: salt[..].try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
            AuthKind::Interface => {
                let InterfacePassword { u_name: _, password_hash, salt }: InterfacePassword = dao::get_interface_pw(pool, name.clone()).await?;
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
            Err(err) => {
                dbg!(err);
                Err(reject::custom(DatabaseErr))
            }
        }?;

        Ok("interface set")
    }
    
    pub async fn interface_get(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, u_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // no authorization

        let interface: ApiInterface = match dao::get_interface(&pool, u_name).await {
            Ok(interface) => Ok(interface.into()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok(warp::reply::json(&interface))
    }

    pub async fn admin_set_pw(bauth: BasicAuth, pool: Pool<Postgres>, pw: ApiAdminPassword) -> WarpResult<impl Reply> {
        match authenticate(&AuthKind::Admin, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        if bauth.name != pw.u_name {
            return Err(reject::custom(AuthorizationErr));
        }
        // validation
        let pw: WarpResult<AdminPassword> = match pw.try_into() {
            Ok(i) => Ok(i),
            Err(_) => Err(reject::custom(ValidationErr))
        };

        match dao::set_admin_pw(&pool, &pw?).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("admin pw set")
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
            Err(err) => {
                dbg!(err);
                Err(reject::custom(DatabaseErr))
            }
        }?;

        Ok("interface set")
    }

    pub async fn interface_remove(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, if_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == if_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::delete_interface(&pool, if_name).await {
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
        // no authorization
        let interfaces: Vec<ApiInterface> = match dao::get_interfaces(&pool).await {
            Ok(interfaces) => Ok(interfaces.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok(warp::reply::json(&interfaces))
    }
    
    pub async fn peer_relation_interfaces(pool: &Pool<Postgres>, pr: &ApiPeerRelation) -> Result<Vec<Interface>, Rejection> {
        match dao::get_peer_relation_interfaces(pool, pr).await {
            Ok(mut interfaces) if interfaces.len() == 2 => {
                if interfaces[0].u_name == pr.endpoint_public_key {
                    interfaces.reverse();
                }
                Ok(interfaces)
            },
            _ => Err(reject::custom(DatabaseErr))
        }
    }

    pub async fn peer_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, mut pr: ApiPeerRelation, u_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name =>{
                let interface: Result<Interface, _> = match dao::get_interface(&pool, u_name).await {
                    Ok(interface) => Ok(interface.into()),
                    Err(_) => Err(reject::custom(DatabaseErr))
                };
                match interface {
                    Ok(i) => match i.public_key {
                        Some(pk) if pk == pr.endpoint_public_key => Ok(()),
                        _ => Err(reject::custom(AuthorizationErr))
                    }
                    _ => Err(reject::custom(AuthorizationErr))
                }
            },
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        // take existing value by setting to None
        pr.peer_allowed_ip = None;
        match dao::set_peer_relation(&pool, &pr.into()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("peer set")
    }
    
    pub async fn peer_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, u_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        let peers: Vec<ApiPeerRelation> = match dao::get_peers(&pool, u_name).await {
            Ok(peers) => Ok(peers.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&peers))
    }
    
    pub async fn endpoint_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, mut pr: ApiPeerRelation, u_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name =>{
                let interface: Result<Interface, _> = match dao::get_interface(&pool, u_name).await {
                    Ok(interface) => Ok(interface.into()),
                    Err(_) => Err(reject::custom(DatabaseErr))
                };
                match interface {
                    Ok(i) => match i.public_key {
                        Some(pk) if pk == pr.peer_public_key => Ok(()),
                        _ => Err(reject::custom(AuthorizationErr))
                    }
                    _ => Err(reject::custom(AuthorizationErr))
                }
            },
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        pr.endpoint_allowed_ip = None;
        match dao::set_peer_relation(&pool, &pr.into()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("endpoint_set")
    }
    
    pub async fn peer_relation_remove(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, endpoint_public_key: String, peer_public_key: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        match dao::delete_peer_relation(&pool, peer_public_key, endpoint_public_key).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok("endpoint_remove")
    }
    
    pub async fn endpoint_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, u_name: String) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        let endpoints: Vec<ApiPeerRelation> = match dao::get_endpoints(&pool, u_name).await {
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
        .and(warp::path("iauth").and(interface_get(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(interface_get(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(interface_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(interface_set(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(interface_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(interface_remove(AuthKind::Admin, pool.clone()))))
        // peers
        .or(warp::path("iauth").and(peer_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_list(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(peer_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_set(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(peer_relation_remove(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(peer_relation_remove(AuthKind::Admin, pool.clone()))))
        // endpoints
        .or(warp::path("iauth").and(endpoint_list(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(endpoint_list(AuthKind::Admin, pool.clone()))))
        .or(warp::path("iauth").and(endpoint_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(endpoint_set(AuthKind::Admin, pool.clone()))))
        // pw
        .or(warp::path("iauth").and(pw_set(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(pw_set(AuthKind::Admin, pool.clone()))))
        
    }

    fn pw_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("pw")
        .and(warp::post())
        .and(
            warp::path("admin")
            .and(warp::header::<BasicAuth>("authorization"))
            .and(with_db(pool.clone()))
            .and(with_admin_pw())
            .and_then(handlers::admin_set_pw)
        .or(
            warp::path("interface")
            .and(with_auth(auth_kind.clone()))
            .and(warp::header::<BasicAuth>("authorization"))
            .and(with_db(pool.clone()))
            .and(with_interface_pw())
            .and_then(handlers::interface_set_pw)
        ))
    }

    fn interface_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::post())
        .and(with_auth(auth_kind.clone()))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and(with_interface())
        .and_then(handlers::interface_set)
    }

    fn interface_get(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interface")
        .and(warp::get())
        .and(
            (
                warp::path("list")
                .and(with_auth(auth_kind.clone()))
                .and(warp::header::<BasicAuth>("authorization"))
                .and(with_db(pool.clone()))
                .and_then(handlers::interface_list)
            )
            .or(
                with_auth(auth_kind)
                .and(warp::header::<BasicAuth>("authorization"))
                .and(with_db(pool.clone()))
                .and(warp::path!(String))
                .and_then(handlers::interface_get)
            )
        )
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
        .and(warp::path!(String))
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
        .and(warp::path!(String))
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
        .and(warp::path!(String))
        .and_then(handlers::peer_list)
    }

    fn peer_relation_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("pr")
        .and(warp::delete())
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(warp::path!(String / String))
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
        .and(warp::path!(String))
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
        .and(warp::path!(String))
        .and_then(handlers::endpoint_list)
    }
}
