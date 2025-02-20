#![windows_subsystem = "windows"]

use std::{sync::Mutex, thread};

use base64::prelude::BASE64_STANDARD;
use encryption::{encrypt::{DecryptorBase64Ext, EncrypterBase64Ext, RsaDecryptor, RsaEncrypter, RsaPair}, rsa::{pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey}, pkcs8::LineEnding, RsaPublicKey}};
use slint::{PlatformError, SharedString, ToSharedString};

slint::include_modules!();

static DECRYPTOR: Mutex<Option<RsaDecryptor>> = Mutex::new(None);
static ENCRYPTER: Mutex<Option<RsaEncrypter>> = Mutex::new(None);

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
        let app_handle = app_handle.unwrap().as_weak();
        thread::spawn(move || {
            let pair = match RsaPair::new(KEY_BIT_SIZE_LIST[idx]) {
                Ok(p) => p,
                Err(e) => {
                    let _ = app_handle.upgrade_in_event_loop(move |app| {
                        app.set_self_pub_key(e.to_shared_string()); 
                    });
                    return;
                },
            };
            let (enc, dec) = pair.split_owned();
            {
                let mut global_dec = DECRYPTOR.lock().unwrap();
                *global_dec = Some(dec);
            }
            let _ = app_handle.upgrade_in_event_loop( move |app|
                match enc.get_pub_key().to_pkcs1_pem(LineEnding::CRLF) {
                    Ok(pub_key) => app.set_self_pub_key(format!("{pub_key}").into()),
                    Err(e) => app.set_self_pub_key(e.to_shared_string()),
                }
            );
        });
    });

    let app_handle = app.as_weak();
    app.on_decrypt_button_clicked(move || {
        let secret = app_handle.unwrap().get_secret();
        let app_handle = app_handle.unwrap().as_weak();
        thread::spawn(move || {
            let _ = app_handle.upgrade_in_event_loop(move |app| {
                let mut global_dec = DECRYPTOR.lock().unwrap();
                if let Some(ref mut dec) = *global_dec  {
                    match dec.decrypt_base64(secret.as_str(), BASE64_STANDARD) {
                        Ok(msg) => {
                            if let Ok(msg_utf8) = std::str::from_utf8(&msg) {
                                app.set_decrypted_secret(msg_utf8.into());
                            } else {
                                app.set_decrypted_secret("Unsupport encode, need utf8".into());
                            }
                        },
                        Err(e) =>
                            app.set_decrypted_secret(format!("Decryption error: {e}").into()),
                    }
                } else {
                    app.set_decrypted_secret("Generate your keys and send your public key to the recipient firstly.".into());
                }
            });
        });
    });

    let app_handle = app.as_weak();
    app.on_recv_pub_key_changed(move || {
        let recv_pub_key_pem = app_handle.unwrap().get_recv_pub_key();

        let mut global_enc = ENCRYPTER.lock().unwrap();

        let recv_pub_key = RsaPublicKey::from_pkcs1_pem(recv_pub_key_pem.as_str());
        match recv_pub_key {
            Ok(pub_key) => *global_enc = Some(RsaEncrypter::new(pub_key)),
            Err(_) => {},
        }
    });

    let app_handle = app.as_weak();
    app.on_encrypt_button_clicked(move || {
        let message = app_handle.unwrap().get_message();
        let app_handle = app_handle.unwrap().as_weak();
        thread::spawn( move || {
            let _ = app_handle.upgrade_in_event_loop( move |app| {
                let mut global_enc = ENCRYPTER.lock().unwrap();
                if let Some(ref mut encrypter) = *global_enc {
                    match encrypter.encrypt_base64(message.as_bytes(), BASE64_STANDARD) {
                        Ok(encryped_msg) => app.set_encrypted_message(encryped_msg.into()),
                        Err(e) => app.set_encrypted_message(e.to_shared_string()),
                    }
                } else {
                    app.set_encrypted_message("Wrong recipient's public key".into());
                }
            });
        });
    });

    app.run()
}
