use std::error::Error;

use base64::{engine, Engine};

pub trait Encrypter {
    fn encrypt(&mut self, in_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

pub trait Decryptor {
    fn decrypt(&mut self, in_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> ;
}

pub trait EncrypterBase64Ext: Encrypter {
    fn encrypt_base64(&mut self, in_data: &[u8], engine: engine::GeneralPurpose) -> Result<String, Box<dyn Error>> {
        let od = self.encrypt(in_data)?;
        Ok(engine.encode(od))
    }
}

pub trait DecryptorBase64Ext: Decryptor {
    fn decrypt_base64(&mut self, in_base64: &str, engine: engine::GeneralPurpose) -> Result<Vec<u8>, Box<dyn Error>>  {
        match engine.decode(in_base64) {
            Ok(in_data) => self.decrypt(&in_data[..]),
            Err(err) => Err(Box::new(err)),
        }
    }
}

impl<T: Encrypter> EncrypterBase64Ext for T {}

impl<T: Decryptor> DecryptorBase64Ext for T {}