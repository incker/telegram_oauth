use hmac::crypto_mac::NewMac;
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct TelegramOauth<'a> {
    pub hash: &'a str,
    pub id: i64,
    pub username: Option<&'a str>,
    pub first_name: Option<&'a str>,
    pub last_name: Option<&'a str>,
    pub photo_url: Option<&'a str>,
    pub auth_date: u64,
}

impl<'a> TelegramOauth<'a> {
    pub fn verify(
        &self,
        telegram_token: &str,
        expired_seconds: u64,
    ) -> Result<(), TelegramOauthError> {
        if self.is_expired(expired_seconds) {
            return Err(TelegramOauthError::DataIsOutdated);
        }

        let validation_hash = hex::decode(self.hash).map_err(|_| TelegramOauthError::DataIsFake)?;

        self.create_hmac(telegram_token)
            .verify(&validation_hash)
            .map_err(|_| TelegramOauthError::DataIsFake)
    }

    fn create_hmac(&self, telegram_token: &str) -> Hmac<Sha256> {
        let mut mac = {
            let mut hasher = Sha256::new();
            hasher.update(telegram_token.as_bytes());
            Hmac::<Sha256>::new_varkey(&hasher.finalize()[..])
                .expect("HMAC can take key of any size")
        };

        let mut add_line = |left: &[u8], right: &str| {
            mac.update(left);
            mac.update(right.as_bytes());
        };

        // adding lines in alphabetic order is mandatory
        add_line(b"auth_date=", &self.auth_date.to_string());
        if let Some(first_name) = self.first_name {
            add_line(b"\nfirst_name=", first_name)
        }
        add_line(b"\nid=", &self.id.to_string());
        if let Some(last_name) = self.last_name {
            add_line(b"\nlast_name=", last_name)
        }
        if let Some(photo_url) = self.photo_url {
            add_line(b"\nphoto_url=", photo_url)
        }
        if let Some(username) = self.username {
            add_line(b"\nusername=", username)
        }
        mac
    }

    fn is_expired(&self, expired_seconds: u64) -> bool {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("getting current timestamp should not cause problems")
            .as_secs();
        self.auth_date < timestamp && timestamp - self.auth_date > expired_seconds
    }
}

#[derive(Debug)]
pub enum TelegramOauthError {
    DataIsOutdated,
    DataIsFake,
}

#[cfg(test)]
mod tests {
    use hmac::Mac;

    use crate::TelegramOauth;

    #[test]
    fn test_expired() {
        let test_cases: Vec<(u64, u64, bool)> = vec![
            (u64::MAX, 86400, false),
            (u64::MAX, 0, false),
            (0, 86400, true),
            (0, u64::MAX, false),
        ];

        let mut telegram_oauth = TelegramOauth {
            hash: "5882e9008eb9d8c09ce3afcc881368a291fbf884e160754091d76233cdca4e15",
            id: 123456789,
            username: None,
            first_name: None,
            last_name: None,
            photo_url: None,
            auth_date: u64::MAX,
        };

        for (auth_date, expired_seconds, is_expired) in test_cases {
            telegram_oauth.auth_date = auth_date;
            assert_eq!(
                telegram_oauth.is_expired(expired_seconds),
                is_expired,
                "auth_date: {}, expired_seconds: {}",
                auth_date,
                expired_seconds
            );
        }
    }

    #[test]
    fn test_hashing_verification() {
        let telegram_token = "000000000:DUMMY_A_SUPER_SECRET_TELEGRAM_TOKEN";

        let telegram_oauth = TelegramOauth {
            hash: "334716aa3e904291b6c7d6d464446a5d2b00bc30359fa0afb336e442ed11339e",
            id: 123456789,
            username: Some("username"),
            first_name: Some("DummyName"),
            last_name: Some("DummySecondName"),
            photo_url: Some("https://t.me/i/userpic/000/dummy-your-user-profile-picture-path.jpg"),
            auth_date: u64::MAX,
        };

        let mac = telegram_oauth.create_hmac(telegram_token);
        let generated_hex = hex::encode(&mac.finalize().into_bytes());

        assert_eq!(telegram_oauth.hash, generated_hex);
    }
}
