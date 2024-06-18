#![no_main]
sp1_zkvm::entrypoint!(main);
use milagro_bls::{PublicKey, SecretKey, Signature};

pub fn main() {
    let sk_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&sk);
    let _msg = sp1_zkvm::io::read::<String>();
    let msg = _msg.as_bytes();

    println!("cycle-tracker-start: sign");
    let sig = Signature::new(msg, &sk);
    println!("cycle-tracker-end: sign");

    sp1_zkvm::io::commit(&pk.as_bytes().to_vec());
    sp1_zkvm::io::commit(&sig.as_bytes().to_vec());
}
