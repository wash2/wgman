pub mod dao {
    use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
    use wgman_core::types::{Admin, AdminPassword, Interface, InterfacePassword, InterfacePeerRelation, PeerRelation};
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

    pub async fn delete_admin(pool: &Pool<Postgres>, Admin { u_name, .. }: Admin) -> Result<Option<Admin>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Admin>( "DELETE FROM public.admin Where u_name = $1 RETURNING *")
        .bind(u_name)
        .fetch_optional(pool)
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

    pub async fn get_interface_by_public_key(pool: &Pool<Postgres>, public_key: String) -> Result<Option<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where public_key = $1")
        .bind(public_key)
        .fetch_optional(pool)
        .await?)
    }

    pub async fn get_interface(pool: &Pool<Postgres>, name: String) -> Result<Option<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("SELECT * FROM public.interface Where u_name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?)
    }

    pub async fn get_peer_relation_interfaces(pool: &Pool<Postgres>, u_name: String) -> Result<Vec<InterfacePeerRelation>, sqlx::Error> {
        // SELECT pw.id, password_hash, salt FROM public.\"User\" u INNER JOIN public.\"UserPassword\" pw ON u.id= pw.id WHERE name = $1"
        Ok(sqlx::query_as::<_, InterfacePeerRelation>("SELECT * FROM public.interface JOIN public.peer_relation ON public_key = endpoint_public_key OR public_key = peer_public_key WHERE u_name = $1;")
        .bind(u_name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn get_interface_peers(pool: &Pool<Postgres>, u_name: String) -> Result<Vec<InterfacePeerRelation>, sqlx::Error> {
        // SELECT pw.id, password_hash, salt FROM public.\"User\" u INNER JOIN public.\"UserPassword\" pw ON u.id= pw.id WHERE name = $1"
        Ok(sqlx::query_as::<_, InterfacePeerRelation>("SELECT * FROM public.interface JOIN public.peer_relation ON public_key = endpoint_public_key WHERE u_name = $1;")
        .bind(u_name)
        .fetch_all(pool)
        .await?)
    }

    pub async fn get_interface_endpoints(pool: &Pool<Postgres>, u_name: String) -> Result<Vec<InterfacePeerRelation>, sqlx::Error> {
        // SELECT pw.id, password_hash, salt FROM public.\"User\" u INNER JOIN public.\"UserPassword\" pw ON u.id= pw.id WHERE name = $1"
        Ok(sqlx::query_as::<_, InterfacePeerRelation>("SELECT * FROM public.interface JOIN public.peer_relation ON public_key = peer_public_key WHERE u_name = $1;")
        .bind(u_name)
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

    pub async fn delete_interface(pool: &Pool<Postgres>, name: String) -> Result<Option<Interface>, sqlx::Error> {
        Ok(sqlx::query_as::<_, Interface>("DELETE FROM public.interface Where u_name = $1 RETURNING *")
        .bind(name)
        .fetch_optional(pool)
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

    pub async fn delete_peer_relation(pool: &Pool<Postgres>, peer: String, endpoint: String) -> Result<Option<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as::<_, PeerRelation>("DELETE FROM public.peer_relation Where peer_public_key = $1 AND endpoint_public_key = $2 RETURNING *")
        .bind(peer)
        .bind(endpoint)
        .fetch_optional(pool)
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
    use types::{ApiInterface, ApiPeerRelation, PeerRelation, ErrorMessage};
    use warp::{Rejection, Reply, hyper::StatusCode, reject};
    use wgman_core::types::{self, AdminPassword, ApiAdminPassword, ApiConfig, ApiInterfacePassword, AuthKind, BasicAuth, Interface, InterfacePassword};
    use wgman_core::auth::{verify, Hash};
    use futures::future::try_join_all;
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
    
    pub async fn index() -> Result<impl Reply, Infallible> {
        Ok("wirguard management API")
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
            Err(_) => {
                Err(reject::custom(DatabaseErr))
            }
        }?;
        dbg!("interface set");
        Ok("interface set")
    }
    
    pub async fn interface_get(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // no authorization

        let interface: ApiInterface = match dao::get_interface(&pool, u_name).await {
            Ok(Some(interface)) => Ok(interface.into()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        dbg!("interface get");
        Ok(warp::reply::json(&interface))
    }

    pub struct PoolIterator {
        pool: Pool<Postgres>
    }

    impl Iterator for PoolIterator {
        type Item = Pool<Postgres>;

        fn next(&mut self) -> Option<Pool<Postgres>> {
            Some(self.pool.clone())
        }
    }

    pub async fn config_list(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // no authorization

        let interfaces: Vec<ApiInterface> = match dao::get_interfaces(&pool).await {
            Ok(interfaces) => Ok(interfaces.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        let configs: Result<Vec<ApiConfig>, Rejection> = try_join_all(interfaces
        .iter()
        .zip(PoolIterator { pool })
        .map(|(i, pool)| async move {
            Ok(ApiConfig {
                interface: i.clone(), 
                peers : match dao::get_peer_relation_interfaces(&pool, i.clone().u_name).await {
                    Ok(peers) => Ok(peers.into_iter().map(|i| i.into()).collect()),
                    Err(_) => Err(reject::custom(DatabaseErr))
                }?
            })
        })
        ).await;
        Ok(warp::reply::json(&configs?))
    }

    pub async fn config_get(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // no authorization

        let interface: ApiInterface = match dao::get_interface(&pool, u_name.clone()).await {
            Ok(Some(interface)) => Ok(interface.into()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        let peers: Vec<ApiPeerRelation> = match dao::get_peer_relation_interfaces(&pool, u_name).await {
            Ok(peers) => Ok(peers.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok(warp::reply::json(&ApiConfig { interface, peers }))
    }

    pub async fn config_set(auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, cfg: ApiConfig) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == cfg.interface.u_name.clone() => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        let interface: Interface = match cfg.interface.clone().try_into() {
            Ok(i) => Ok(i),
            Err(_) => Err(reject::custom(ValidationErr))
        }?;

        dbg!("got interface");

        let peers = cfg.peers
        .iter()
        .map(|p| match p.clone().try_into() {
            Ok(p) => Ok(p),
            Err(_) => Err(reject::custom(ValidationErr))
        });

        if peers.clone().any(|p: WarpResult<PeerRelation>| {
            match p {
                Ok(p) if p.peer_public_key.is_some() && p.endpoint_public_key.is_some() &&
                    p.peer_public_key != cfg.interface.public_key.clone() || p.endpoint_public_key != cfg.interface.public_key.clone() => true,
                Err(_) => true,
                _ => false
            }
        }) {
            return Err(reject::custom(ValidationErr));
        }

        dbg!("validated peers");
        match dao::set_interface(&pool, &interface).await {
            Ok(_) => Ok("interface set"),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        dbg!("set interface");

        for p in peers {
            match dao::set_peer_relation(&pool, &p?).await {
                Ok(_) => Ok("peers set"),
                Err(_) => Err(reject::custom(DatabaseErr))
            }?;
        }
        
        Ok("interface set configuration")
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
            Err(_) => {
                Err(reject::custom(DatabaseErr))
            }
        }?;
        dbg!("interface set pw");
        Ok("interface set pw")
    }

    pub async fn interface_remove(if_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
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
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        dbg!("interface remove");

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
        dbg!("interface list");
        Ok(warp::reply::json(&interfaces))
    }

    pub async fn peer_set(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, mut pr: ApiPeerRelation) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name.clone() &&
                pr.endpoint_name.is_some() && pr.endpoint_name.as_ref().unwrap() == &u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        // take existing value by setting to None
        pr.peer_allowed_ip = None;
        let pr: WarpResult<PeerRelation> = match pr.try_into() {
            Ok(pr) => Ok(pr),
            Err(_) => Err(reject::custom(DatabaseErr))
        };
        match dao::set_peer_relation(&pool, &pr?).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("peer set")
    }
    
    pub async fn peer_list(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
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
        let peers: Vec<ApiPeerRelation> = match dao::get_interface_peers(&pool, u_name).await {
            Ok(peers) => Ok(peers.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&peers))
    }
    
    pub async fn endpoint_set(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>, mut pr: ApiPeerRelation) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            AuthKind::Interface if bauth.name == u_name.clone() &&
                pr.peer_name.is_some() && pr.peer_name.as_ref().unwrap() == &u_name => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;
        
        pr.endpoint_allowed_ip = None;
        let pr: WarpResult<PeerRelation> = match pr.try_into() {
            Ok(pr) => Ok(pr),
            Err(_) => Err(reject::custom(DatabaseErr))
        };

        match dao::set_peer_relation(&pool, &pr?).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        Ok("endpoint_set")
    }
    
    pub async fn peer_relation_remove(endpoint_name: String, peer_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;

        let endpoint_public_key = match dao::get_interface(&pool, endpoint_name).await {
            Ok(Some(interface)) => match interface.public_key {
                Some(pk) => Ok(pk),
                _ => Err(reject::custom(ValidationErr)),
            },
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        let peer_public_key = match dao::get_interface(&pool, peer_name).await {
            Ok(Some(interface)) => match interface.public_key {
                Some(pk) => Ok(pk),
                _ => Err(reject::custom(ValidationErr)),
            },
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        match dao::delete_peer_relation(&pool, peer_public_key, endpoint_public_key).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok("peer relation remove")
    }
    // interface_peer_remove
    pub async fn interface_peer_remove(u_name: String, endpoint_public_key: String, peer_public_key: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;

        match dao::get_interface(&pool, u_name).await {
            Ok(Some(interface)) if interface.u_name == endpoint_public_key => Ok(interface),
            Ok(Some(_)) => Err(reject::custom(ValidationErr)),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;

        match dao::delete_peer_relation(&pool, peer_public_key, endpoint_public_key).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok("endpoint_remove")
    }

    pub async fn interface_endpoint_remove(u_name: String, endpoint_public_key: String, peer_public_key: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        match authenticate(&auth_kind, &bauth, &pool).await {
            Ok(_) => Ok(()),
            Err(_) => Err(reject::custom(AuthenticationErr))
        }?;
        // authorization
        match &auth_kind {
            AuthKind::Admin => Ok(()),
            _ => Err(reject::custom(AuthorizationErr))
        }?;

        match dao::get_interface(&pool, u_name).await {
            Ok(Some(interface)) if interface.u_name == peer_public_key => Ok(interface),
            Ok(Some(_)) => Err(reject::custom(ValidationErr)),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        match dao::delete_peer_relation(&pool, peer_public_key, endpoint_public_key).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(warp::reject::not_found()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        Ok("endpoint_remove")
    }

    pub async fn endpoint_list(u_name: String, auth_kind: AuthKind, bauth: BasicAuth, pool: Pool<Postgres>) -> WarpResult<impl Reply> {
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
        let endpoints: Vec<ApiPeerRelation> = match dao::get_interface_endpoints(&pool, u_name).await {
            Ok(endpoints) => Ok(endpoints.into_iter().map(|i| i.into()).collect()),
            Err(_) => Err(reject::custom(DatabaseErr))
        }?;
        
        Ok(warp::reply::json(&endpoints))
    }

    // This function receives a `Rejection` and tries to return a custom
    // value, otherwise simply passes the rejection along.
    pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
        let code;
        let message;

        if err.is_not_found() {
            code = StatusCode::NOT_FOUND;
            message = "NOT_FOUND";
        } else if let Some(AuthenticationErr) = err.find() {
            code = StatusCode::FORBIDDEN;
            message = "AUTHENTICATION_ERROR";
        }
        else if let Some(AuthorizationErr) = err.find() {
            code = StatusCode::UNAUTHORIZED;
            message = "AUTHORIZATION_ERROR";
        }
        else if let Some(ValidationErr) = err.find() {
            code = StatusCode::BAD_REQUEST;
            message = "VALIDATION_ERROR";
        } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
            // This error happens if the body could not be deserialized correctly
            // We can use the cause to analyze the error and customize the error message
            message = match e.source() {
                Some(cause) => {
                    if cause.to_string().contains("denom") {
                        "FIELD_ERROR: denom"
                    } else {
                        "BAD_REQUEST"
                    }
                }
                None => "BAD_REQUEST",
            };
            code = StatusCode::BAD_REQUEST;
        } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
            // We can handle a specific error, here METHOD_NOT_ALLOWED,
            // and render it however we want
            code = StatusCode::METHOD_NOT_ALLOWED;
            message = "METHOD_NOT_ALLOWED";
        } else if let Some(_) = err.find::<warp::reject::PayloadTooLarge>() {
            code = StatusCode::PAYLOAD_TOO_LARGE;
            message = "PAYLOAD_TOO_LARGE";
        } else {
            // We should have expected this... Just log and say its a 500
            // eprintln!("unhandled rejection: {:?}", err);
            code = StatusCode::INTERNAL_SERVER_ERROR;
            message = "UNHANDLED_REJECTION";
        }

        let json = warp::reply::json(&ErrorMessage {
            code: code.as_u16(),
            message: message.into(),
        });

        Ok(warp::reply::with_status(json, code))
    }
}

pub mod filters {
    use sqlx::{Pool, Postgres};
    use warp::{Filter};
    use serde::de::DeserializeOwned;

    use crate::handlers;
    use wgman_core::types::{AuthKind, BasicAuth};
        

    pub fn with_auth(auth_kind: AuthKind) -> impl Filter<Extract = (AuthKind,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || auth_kind.clone())
    }

    pub fn with_db(db: Pool<Postgres>) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
    }

    fn with_json<T: DeserializeOwned<> + Send>() -> impl Filter<Extract = (T,), Error = warp::Rejection> + Clone {
        warp::body::content_length_limit(1024 * 16)
            .and(warp::body::json())
    }


    pub fn auth(
        pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("iauth").and(routes(AuthKind::Interface, pool.clone()))
            .or(warp::path("aauth").and(routes(AuthKind::Admin, pool.clone())))
    }

    // behind iauth or aauth
    // interfaces/ GET
    // interfaces/ POST
    // interfaces/{} GET
    // interfaces/{} DELETE
    // interfaces/{}/configurations GET
    // interfaces/{}/configurations POST
    // interfaces/{}/peers GET
    //interfaces/{}/peers/{}/{} DELETE
    // interfaces/{}/peers POST
    // interfaces/{}/endpoints GET
    //interfaces/{}/endpoints/{}/{} DELETE
    // interfaces/{}/endpoints POST
    // interfaces/passwords POST


    // behind admin auth only
    //peer_relations/ POST
    // peer_relations/{}/{} DELETE
    //peer_relations/ GET
    //peer_relations/{} GET
    //admins/ POST
    //admins/{} GET
    //admins/{} DELETE
    // admins/passwords POST
    fn routes(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::any()
        // GET
        .and(
            warp::get()
            .and(
                config_list(auth_kind.clone(), pool.clone())
                .or(peer_list(auth_kind.clone(), pool.clone()))
                .or(endpoint_list(auth_kind.clone(), pool.clone()))
                .or(interface_list(auth_kind.clone(), pool.clone()))
                .or(interface_get(auth_kind.clone(), pool.clone()))
                .or(config_get(auth_kind.clone(), pool.clone()))
                .or(config_list(auth_kind.clone(), pool.clone()))
            )
        )
        // POST
        .or(
            warp::post()
            .and(
                interface_set(auth_kind.clone(), pool.clone())
                .or(config_set(auth_kind.clone(), pool.clone()))
                .or(peer_set(auth_kind.clone(), pool.clone()))
                .or(endpoint_set(auth_kind.clone(), pool.clone()))
                .or(admin_pw_set(auth_kind.clone(), pool.clone()))
                .or(interface_pw_set(auth_kind.clone(), pool.clone()))
            )
        )
        // DELETE
        .or(
            warp::delete()
            .and(
                interface_remove(auth_kind.clone(), pool.clone())
                .or(peer_relation_remove(auth_kind.clone(), pool.clone()))
                .or(interface_peer_remove(auth_kind.clone(), pool.clone()))
                .or(interface_endpoint_remove(auth_kind.clone(), pool.clone()))
            )
        )
    }

    fn admin_pw_set(
        _auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("admins"/"passwords")
        .and(warp::path::end())
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and(with_json())
        .and_then(handlers::admin_set_pw)
    }

    fn interface_pw_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / "passwords")
        .and(warp::path::end())
        .and(with_auth(auth_kind.clone()))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and(with_json())
        .and_then(handlers::interface_set_pw)
    }

    fn interface_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interfaces")
        .and(warp::path::end())
        .and(with_auth(auth_kind.clone()))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and(with_json())
        .and_then(handlers::interface_set)
    }

    fn interface_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("interfaces")
        .and(warp::path::end())
        .and(with_auth(auth_kind.clone()))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and_then(handlers::interface_list)
    }

    fn interface_get(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind.clone()))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool.clone()))
        .and_then(handlers::interface_get)
    }

    fn interface_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_remove)
    }

    fn interface_peer_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / String / "peers" / String / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_peer_remove)
    }

    fn interface_endpoint_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / String / "endpoints" / String / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_endpoint_remove)
    }

    fn peer_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("peers" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_json())
        .and_then(handlers::peer_set)
    }

    fn peer_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("peers" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::peer_list)
    }

    fn peer_relation_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("peer_relations" / String / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::peer_relation_remove)
    }

    fn endpoint_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("endpoints" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_json())
        .and_then(handlers::endpoint_set)
    }

    fn endpoint_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("endpoints" / String)
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::endpoint_list)
    }

    fn config_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("configs")
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and(with_json())
        .and_then(handlers::config_set)
    }

    fn config_get(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path!("interfaces" / String / "configs")
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::config_get)
    }

    fn config_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("configs")
        .and(warp::path::end())
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::config_list)
    }
}
