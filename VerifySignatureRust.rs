use std::error::Error;
use openssl::sign::Verifier;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

fn validate_signature(xpayloadsig: &str, payload: &str, pem_key: &str) -> Result<(),Box<dyn Error>> {
    let key: Rsa<openssl::pkey::Public> = Rsa::public_key_from_pem(pem_key.as_bytes()).unwrap();
    let public_key: PKey<openssl::pkey::Public> = PKey::from_rsa(key).unwrap();
    
    let mut t: &str = "";
    let mut v: &str = "";
    for s in xpayloadsig.split(',') {
        if s.len() < 3 {
           return Err("Invalid Signature not valid key value pair".into());
        }
        let (key, value) = s.split_at(1);
        match key {
            "t" => t = &value[1..],
            "v" => v = &value[1..],
            _ => return Err(format!("Invalid signature unexpected key '{}'", key).into()),
        }
    }
    let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
    verifier.update(t.as_bytes())?;
    verifier.update(b".")?;
    verifier.update(payload.as_bytes())?;

    let hash_to_verify = BASE64.decode(v)?;
    let result = verifier.verify(&hash_to_verify)?;
    if !result {
        return Err("Did not pass signature check".into());
    }
    Result::Ok(())
}