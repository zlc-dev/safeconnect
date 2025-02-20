use base64::{engine, Engine};

pub trait Encrypter {
    fn encrypt(&mut self, in_data: &[u8]) -> Vec<u8>;
}

pub trait Decryptor {
    fn decrypt(&mut self, in_data: &[u8]) -> Option<Vec<u8>>;
}

pub trait EncrypterBase64Ext: Encrypter {
    fn encrypt_base64(&mut self, in_data: &[u8], engine: engine::GeneralPurpose) -> String {
        let od = self.encrypt(in_data);
        engine.encode(od)
    }
}

pub trait DecryptorBase64Ext: Decryptor {
    fn decrypt_base64(&mut self, in_base64: &str, engine: engine::GeneralPurpose) -> Option<Vec<u8>> {
        if let Ok(vec) = engine.decode(in_base64) {
            Some(self.decrypt(&vec[..])?)
        } else {
            None
        }
    }
}

impl<T: Encrypter> EncrypterBase64Ext for T {}

impl<T: Decryptor> DecryptorBase64Ext for T {}