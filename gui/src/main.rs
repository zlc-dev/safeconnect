#![windows_subsystem = "windows"]

use base64::prelude::BASE64_STANDARD;
use encryption::{encrypt::{DecryptorBase64Ext, EncrypterBase64Ext, RsaDecryptor, RsaEncrypter, RsaPair}, rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, pkcs8::LineEnding, RsaPublicKey}};
use slint::{PlatformError, SharedString, ToSharedString};

slint::include_modules!();

static mut DECRYPTOR: Option<RsaDecryptor> = None;
static mut ENCRYPTER: Option<RsaEncrypter> = None;

const KEY_BIT_SIZE_LIST: [usize; 5] = [256, 512, 1024, 2048, 4096];

fn main() -> Result<(), PlatformError> {
    
    let app = App::new().unwrap();

    app.set_bit_size_list(
        KEY_BIT_SIZE_LIST
        .iter()
        .map(|n| n.to_shared_string())
        .collect::<Vec<SharedString>>()[..]
        .into()
    );

    let app_handle = app.as_weak();
    app.on_gen_key_button_clicked(move || {
        app_handle.unwrap().set_self_pub_key("Generating... ".into());
        let idx = app_handle.unwrap().get_current_bit_size_index() as usize;
        // todo: make it async
        let (enc, dec) = RsaPair::new(KEY_BIT_SIZE_LIST[idx]).split_owned();
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
                match dec.decrypt_base64(secret.as_str(), BASE64_STANDARD) {
                    Ok(msg) => {
                        if let Ok(msg_utf8) = std::str::from_utf8(&msg) {
                            app_handle.unwrap().set_decrypted_secret(msg_utf8.into());
                        } else {
                            app_handle.unwrap().set_decrypted_secret("Unsupport encode, need utf8".into());
                        }
                    },
                    Err(e) =>
                        app_handle.unwrap().set_decrypted_secret(format!("Decryption error: {e}").into()),
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
                match encrypter.encrypt_base64(message.as_bytes(), BASE64_STANDARD) {
                    Ok(encryped_msg) => app_handle.unwrap().set_encrypted_message(encryped_msg.into()),
                    Err(e) => app_handle.unwrap().set_encrypted_message(e.to_shared_string()),
                }
            } else {
                app_handle.unwrap().set_encrypted_message("Wrong recipient's public key".into());
            }
        }
    });

    app.run()
}
