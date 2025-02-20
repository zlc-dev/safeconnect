use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

use super::{Decryptor, Encrypter};

#[derive(Debug, Clone)]
pub struct RsaEncrypter {
    key: RsaPublicKey
}

#[derive(Debug, Clone)]
pub struct RsaDecryptor {
    key: RsaPrivateKey,
}

pub struct RsaPair {
    pub encrypter: RsaEncrypter,
    pub decrypter: RsaDecryptor
}

impl RsaPair {

    pub fn new(bit_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        let pri_key = RsaPrivateKey::new(&mut rng, bit_size).unwrap();
        let pub_key = RsaPublicKey::from(&pri_key);
        Self {
            encrypter: RsaEncrypter::new(pub_key),
            decrypter: RsaDecryptor::new(pri_key)
        }
    }

    pub fn split(&mut self) -> (&mut RsaEncrypter, &mut RsaDecryptor){
        (&mut self.encrypter, &mut self.decrypter)
    }

    pub fn split_owned(self) -> (RsaEncrypter, RsaDecryptor) {
        (self.encrypter, self.decrypter)
    }

}

impl RsaEncrypter {
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            key,
        }
    }

    pub fn get_pub_key(&self) -> &RsaPublicKey {
        &self.key
    }
}

impl Encrypter for RsaEncrypter {
    fn encrypt(&mut self, in_data: &[u8]) -> Vec<u8> {
        let out = self.key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &in_data).unwrap();
        out
    }
}

impl RsaDecryptor {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }
}

impl Decryptor for RsaDecryptor {
    fn decrypt(&mut self, in_data: &[u8]) -> Option<Vec<u8>> {
        match self.key.decrypt(Pkcs1v15Encrypt, in_data) {
            Ok(ret) => Some(ret),
            Err(_) => None,
        }
    }
}