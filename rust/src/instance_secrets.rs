// SPDX-License-Identifier: LGPL-3.0-only

use base64::{engine::general_purpose::STANDARD, Engine};
use crypto_secretbox::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Nonce, XSalsa20Poly1305,
};
use std::{
    env,
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
};
use zeroize::Zeroizing;

// Preserve the SQLite envelope used by PHP Crypto and the Python worker:
// base64(nonce || MAC || ciphertext).
pub(crate) fn seal(secret: &[u8]) -> io::Result<String> {
    let cipher = cipher()?;
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret).map_err(|_| unavailable())?;
    let mut payload = nonce.to_vec();
    payload.extend(ciphertext);
    Ok(STANDARD.encode(payload))
}

pub(crate) fn open(encoded: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let data = STANDARD.decode(encoded).map_err(|_| unavailable())?;
    let (nonce, ciphertext) = data.split_at_checked(24).ok_or_else(unavailable)?;
    let plaintext = cipher()?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| unavailable())?;
    Ok(Zeroizing::new(plaintext))
}

fn cipher() -> io::Result<XSalsa20Poly1305> {
    let path = env::var_os("PXE_MASTER_KEY_PATH")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/pxe-tools/master.key"));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| unavailable())?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o027 != 0 {
        return Err(unavailable());
    }
    let mut key = Zeroizing::new(Vec::with_capacity(33));
    file.take(33).read_to_end(&mut key)?;
    XSalsa20Poly1305::new_from_slice(&key).map_err(|_| unavailable())
}

fn unavailable() -> io::Error {
    io::Error::other("Clé maître de l’instance ou chiffrement indisponible")
}
