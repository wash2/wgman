pub mod auth {
    use base64::decode;
    use ring::error::Unspecified;
    use ring::rand::SecureRandom;
    use ring::{digest, pbkdf2, rand};
    use sqlx::{Pool, Postgres};
    use std::{convert::TryInto, error::Error, num::NonZeroU32, str::FromStr};

    use crate::{dao::{InterfacePassword, UserPassword, get_interface_pw, get_user_pw}};

    pub struct Hash {
        pub pbkdf2_hash: [u8; digest::SHA512_OUTPUT_LEN],
        pub salt: [u8; digest::SHA512_OUTPUT_LEN],
    }
    
    #[derive(Debug, Default, Clone)]
    pub struct BasicAuth {
        name: String,
        password: String
    }

    #[derive(Debug, Clone)]
    pub enum AuthKind {
        User,
        Interface,
    }

    impl Default for AuthKind {
        fn default() -> Self {
            AuthKind::User
        }
    }

    // Warning:: only intended to be used with base64 authorization header
    impl FromStr for BasicAuth {
        type Err = Box<dyn Error>;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match &s[..5] {
                "Basic" => {
                    let decoded = decode(&s[6..])?;
                    let auth_string = std::str::from_utf8(&decoded[..])?;
                    let colon_indx = match auth_string.find(":") {
                        Some(indx) => {
                            if indx < auth_string.len() - 1 {
                                indx
                            }
                            else {
                                Err("Invalid Login")?
                            }
                        },
                        None => {Err("Invalid Login")?}
                    };

                    Ok(BasicAuth { name: auth_string[..colon_indx].into(), password: auth_string[colon_indx + 1..].into() })
                        
                }
                _ => Err("Invalid Login")?
            }
        }
    }

    #[tokio::main]
    async fn authenticate(auth_type: AuthKind, BasicAuth { name, password } : &BasicAuth, pool: &Pool<Postgres>) -> Result<(), Box<dyn Error>> {
        match auth_type {
            AuthKind::User => {
                let UserPassword { id: _, password_hash, salt }: UserPassword = get_user_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash.as_bytes().try_into()?, salt: salt.as_bytes().try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
            AuthKind::Interface => {
                let InterfacePassword { id: _, password_hash, salt }: InterfacePassword = get_interface_pw(pool, name.clone()).await?;
                match verify(&Hash { pbkdf2_hash: password_hash.as_bytes().try_into()?, salt: salt.as_bytes().try_into()? }, password) {
                    Ok(_) => {Ok(())}
                    Err(_) => {Err("invalid login")?}
                }
            }
        }
    }

    pub fn encrypt(password: &str) -> Result<Hash, Unspecified> {
        const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
        let n_iter = NonZeroU32::new(100_000).unwrap();
        let rng = rand::SystemRandom::new();
    
        let mut salt = [0u8; CREDENTIAL_LEN];
        rng.fill(&mut salt)?;
    
        let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            n_iter,
            &salt,
            password.as_bytes(),
            &mut pbkdf2_hash,
        );
    
        Ok(Hash { salt, pbkdf2_hash })
    }
    
    pub(crate) fn verify(Hash { salt, pbkdf2_hash }: &Hash, password: &str) -> Result<(), Unspecified> {
        let n_iter = NonZeroU32::new(100_000).unwrap();
        const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
    
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA512,
            n_iter,
            salt,
            password.as_bytes(),
            pbkdf2_hash,
        )
    }


}

pub mod config {
    use std::env::{var, VarError};

    #[derive(Debug)]
    pub struct DbCfg {
        pub host: String,
        pub user: String,
        pub pw: String,
        pub port: String,
        pub name: String,
    }

    #[derive(Debug)]
    pub struct ApiCfg {
        pub port: String,
        pub ip: String,
    }

    pub fn get_db_cfg() -> Result<DbCfg, VarError> {
        Ok(DbCfg {
            host: var("WGMAN_DB_HOST")?,
            user: var("WGMAN_DB_USER")?,
            pw: var("WGMAN_DB_PW")?,
            port: var("WGMAN_DB_PORT")?,
            name: var("WGMAN_DB_NAME")?,
        })
    }

    pub fn get_api_cfg() -> Result<ApiCfg, VarError> {
        Ok(ApiCfg {
            port: var("WGMAN_API_PORT")?,
            ip: var("WGMAN_API_IP")?,
        })
    }
}

pub mod dao {
    use ipnetwork::IpNetwork;
    use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
    use uuid::Uuid;
    use crate::config::DbCfg;

    #[derive(Debug, Clone)]
    pub struct User {
        pub id: Uuid,
        pub name: String,
        pub is_admin: bool,
    }

    #[derive(Debug, Clone)]
    pub struct UserPassword {
        pub id: Uuid,
        pub password_hash: String,
        pub salt: String,
    }

    #[derive(Debug, Clone)]
    pub struct Interface {
        pub id: Uuid,
        pub name: String,
        pub public_key: Option<String>,
        pub port: Option<i32>,
        pub ip: Option<IpNetwork>,
        pub fqdn: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct InterfacePassword {
        pub id: Uuid,
        pub password_hash: String,
        pub salt: String,
    }

    #[derive(Debug, Clone)]
    pub struct PeerRelation {
        pub endpoint: Uuid,
        pub peer: Uuid,
        endpoint_allowed_ip: Vec<IpNetwork>,
        peer_allowed_ip: Vec<IpNetwork>,
    }

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

    pub async fn get_interface_by_name(pool: &Pool<Postgres>, name: String) -> Result<Interface, sqlx::Error> {
        Ok(sqlx::query_as!(Interface, "SELECT * FROM public.\"Interface\" Where name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_interfaces(pool: &Pool<Postgres>) -> Result<Vec<Interface>, sqlx::Error> {
        Ok(sqlx::query_as!(Interface, "SELECT * FROM public.\"Interface\"").fetch_all(pool).await?)
    }

    pub async fn get_user_pw(pool: &Pool<Postgres>, name: String) -> Result<UserPassword, sqlx::Error> {
        Ok(sqlx::query_as!(UserPassword, "SELECT pw.id, password_hash, salt FROM public.\"User\" u INNER JOIN public.\"UserPassword\" pw ON u.id= pw.id WHERE name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_interface_pw(pool: &Pool<Postgres>, name: String) -> Result<InterfacePassword, sqlx::Error> {
        Ok(sqlx::query_as!(InterfacePassword, "SELECT pw.id, password_hash, salt FROM public.\"User\" i INNER JOIN public.\"InterfacePassword\" pw ON i.id= pw.id WHERE name = $1", name).fetch_one(pool).await?)
    }

    pub async fn get_peers(pool: &Pool<Postgres>, id: Uuid) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as!(PeerRelation, "SELECT * FROM public.\"PeerRelation\" Where endpoint = $1::UUID", id).fetch_all(pool).await?)
    }

    pub async fn get_(pool: &Pool<Postgres>, id: Uuid) -> Result<Vec<PeerRelation>, sqlx::Error> {
        Ok(sqlx::query_as!(PeerRelation, "SELECT * FROM public.\"PeerRelation\" Where peer = $1::UUID", id).fetch_all(pool).await?)
    }
}

pub mod handlers {
    use std::convert::Infallible;
    use sqlx::{Pool, Postgres};
    use warp::{Reply, Rejection};
    use crate::auth::{AuthKind, BasicAuth};
    
    type WarpResult<T> = std::result::Result<T, Rejection>;

    #[derive(Debug, Default, Clone)]
    pub struct LoginBody {
        auth_type: AuthKind,
        name: String,
        password: String
    }


    pub async fn health() -> Result<impl Reply, Infallible> {
        Ok("OK")
    }
    
    pub async fn interface_set(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("interface_set")
    }
    
    pub async fn interface_remove(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("interface_remove")
    }
    
    pub async fn interface_list(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("interface_list")
    }
    
    pub async fn peer_set(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("peer_set")
    }
    
    pub async fn peer_remove(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("peer_remove")
    }
    
    pub async fn peer_list(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("peer_list")
    }
    
    pub async fn endpoint_set(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("endpoint_set")
    }
    
    pub async fn endpoint_remove(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("endpoint_remove")
    }
    
    pub async fn endpoint_list(auth_kind: AuthKind, bauth: BasicAuth, db_pool: Pool<Postgres>) -> WarpResult<impl Reply> {
        Ok("endpoint_list")
    }
}

pub mod filters {
    use sqlx::{Pool, Postgres};
    use warp::Filter;

    use crate::handlers;
    use crate::auth::{AuthKind, BasicAuth};
        

    pub fn with_auth(auth_kind: AuthKind) -> impl Filter<Extract = (AuthKind,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || auth_kind.clone())
    }

    pub fn with_db(db: Pool<Postgres>) -> impl Filter<Extract = (Pool<Postgres>,), Error = std::convert::Infallible> + Clone {
        warp::any().map(move || db.clone())
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
        warp::post()
        .and(warp::path("interface"))
        .and(warp::path("set"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_set)
    }

    fn interface_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("interface"))
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_list)
    }

    fn interface_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("interface"))
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::interface_remove)
    }

    fn peer_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("peer"))
        .and(warp::path("set"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::peer_set)
    }

    fn peer_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("peer"))
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::peer_list)
    }

    fn peer_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("peer"))
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::peer_remove)
    }

    fn endpoint_set(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("endpoint"))
        .and(warp::path("set"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::endpoint_set)
    }

    fn endpoint_list(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("endpoint"))
        .and(warp::path("list"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::endpoint_list)
    }

    fn endpoint_remove(
        auth_kind: AuthKind, pool: Pool<Postgres>
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path("endpoint"))
        .and(warp::path("remove"))
        .and(with_auth(auth_kind))
        .and(warp::header::<BasicAuth>("authorization"))
        .and(with_db(pool))
        .and_then(handlers::endpoint_remove)
    }
}
