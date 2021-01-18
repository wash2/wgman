pub mod auth {
    use data_encoding::HEXUPPER;
    use ring::error::Unspecified;
    use ring::rand::SecureRandom;
    use ring::{digest, pbkdf2, rand};
    use std::num::NonZeroU32;
    struct Hash {
        pbkdf2_hash: [u8; digest::SHA512_OUTPUT_LEN],
        salt: [u8; digest::SHA512_OUTPUT_LEN],
    }
    
    fn encrypt(password: &str) -> Result<Hash, Unspecified> {
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
    
    fn verify(Hash { salt, pbkdf2_hash }: &Hash, password: &str) -> Result<(), Unspecified> {
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

}
