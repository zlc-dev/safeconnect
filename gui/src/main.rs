use base64::prelude::BASE64_STANDARD;
use encryption::{encrypt::{DecryptorBase64Ext, EncrypterBase64Ext, RsaDecryptor, RsaEncrypter, RsaPair}, rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, pkcs8::LineEnding, RsaPublicKey}};
use slint::{PlatformError, ToSharedString};

slint::include_modules!();

static mut DECRYPTOR: Option<RsaDecryptor> = None;
static mut ENCRYPTER: Option<RsaEncrypter> = None;

const KEY_BIT_SIZE: usize = 1024;

fn main() -> Result<(), PlatformError> {
    
    let app = App::new().unwrap();

    let app_handle = app.as_weak();
    app.on_gen_key_button_clicked(move || {
        let (enc, dec) = RsaPair::new(KEY_BIT_SIZE).split_owned();
        unsafe {
            DECRYPTOR = Some(dec);
        }
        match enc.get_pub_key().to_pkcs1_pem(LineEnding::CRLF) {
            Ok(pub_key) => app_handle.unwrap().set_self_pub_key(format!("{pub_key}").into()),
            Err(err) => app_handle.unwrap().set_self_pub_key(err.to_shared_string()),
        }
    });

    let app_handle = app.as_weak();
    app.on_decrypt_button_clicked(move || {
        let secret = app_handle.unwrap().get_secret();
        unsafe {
            if let Some(ref mut dec) = DECRYPTOR  {
                if let Some(msg) = dec.decrypt_base64(secret.as_str(), BASE64_STANDARD) {
                    if let Ok(msg_utf8) = std::str::from_utf8(&msg) {
                        app_handle.unwrap().set_decrypted_secret(msg_utf8.into());
                    } else {
                        app_handle.unwrap().set_decrypted_secret("Unsupport encode, need utf8".into());
                    }
                } else {
                    app_handle.unwrap().set_decrypted_secret("Decryption error.".into());
                }
            } else {
                app_handle.unwrap().set_decrypted_secret("Generate your keys and send your public key to the recipient firstly.".into());
            }
        }
    });

    let app_handle = app.as_weak();
    app.on_recv_pub_key_changed(move || {
        let recv_pub_key_pem = app_handle.unwrap().get_recv_pub_key();
        unsafe {
            let recv_pub_key = RsaPublicKey::from_pkcs1_pem(recv_pub_key_pem.as_str());
            match recv_pub_key {
                Ok(pub_key) => ENCRYPTER = Some(RsaEncrypter::new(pub_key)),
                Err(_) => {},
            }
        }
    });

    let app_handle = app.as_weak();
    app.on_encrypt_button_clicked(move || {
        let message = app_handle.unwrap().get_message();
        unsafe {
            if let Some(ref mut encrypter) = ENCRYPTER {
                let encryped_msg = encrypter.encrypt_base64(message.as_bytes(), BASE64_STANDARD);
                app_handle.unwrap().set_encrypted_message(encryped_msg.into());
            } else {
                app_handle.unwrap().set_encrypted_message("Wrong recipient's public key".into());
            }
        }
    });

    app.run()
}
