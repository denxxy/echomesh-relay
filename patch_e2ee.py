import re

with open("/tmp/echomesh/echomesh-mac/echomesh-core/src/e2ee.rs", "r") as f:
    text = f.read()

enc_search = r'''    let cipher = ChaCha20Poly1305::new_from_slice\(&key\)\.map_err\(\|\_\| crypto_error\("invalid AEAD key"\)\)\?;
    let ciphertext = cipher
        \.encrypt\(Nonce::from_slice\(&nonce_bytes\), Payload \{ msg: plaintext, aad: &aad \}\)
        \.map_err\(\|\_\| crypto_error\("authenticated E2EE encryption failed"\)\)\?;'''

enc_replace = r'''    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    
    // V3: Prepend 8-byte timestamp to plaintext for replay protection
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let mut payload = Vec::with_capacity(8 + plaintext.len());
    payload.extend_from_slice(&now.to_be_bytes());
    payload.extend_from_slice(plaintext);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &payload, aad: &aad })
        .map_err(|_| crypto_error("authenticated E2EE encryption failed"))?;'''

text = re.sub(enc_search, enc_replace, text)

dec_search = r'''    let cipher = ChaCha20Poly1305::new_from_slice\(&key\)\.map_err\(\|\_\| crypto_error\("invalid AEAD key"\)\)\?;
    let plaintext = cipher
        \.decrypt\(Nonce::from_slice\(nonce\), Payload \{ msg: ciphertext, aad: &aad \}\)
        \.map_err\(\|\_\| crypto_error\("authenticated E2EE verification failed"\)\)\?;
    Ok\(\(sender_public\.as_bytes\(\)\.to_vec\(\), plaintext\)\)'''

dec_replace = r'''    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| crypto_error("invalid AEAD key"))?;
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| crypto_error("authenticated E2EE verification failed"))?;
        
    if decrypted.len() < 8 {
        return Err(crypto_error("invalid E2EE payload length (missing timestamp)"));
    }
    
    let ts_bytes: [u8; 8] = decrypted[..8].try_into().unwrap();
    let msg_ts = u64::from_be_bytes(ts_bytes);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    
    // Reject messages older than 2 hours or from the future (> 5 min)
    let two_hours = 2 * 60 * 60 * 1000;
    let five_min = 5 * 60 * 1000;
    if now.saturating_sub(msg_ts) > two_hours || msg_ts.saturating_sub(now) > five_min {
        return Err(crypto_error("E2EE payload rejected: timestamp out of bounds (replay protection)"));
    }
    
    let plaintext = decrypted[8..].to_vec();
    Ok((sender_public.as_bytes().to_vec(), plaintext))'''

text = re.sub(dec_search, dec_replace, text)

with open("/tmp/echomesh/echomesh-mac/echomesh-core/src/e2ee.rs", "w") as f:
    f.write(text)

print("E2EE patched successfully!")
