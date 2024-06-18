#![no_main]
sp1_zkvm::entrypoint!(main);
use milagro_bls::{
    AggregatePublicKey, AggregateSignature, Keypair, PublicKey, SecretKey, Signature,
};

const N: usize = 5;

pub fn main() {
    let _msg = sp1_zkvm::io::read::<String>();
    let msg = _msg.as_bytes();

    // Single Signature
    let sk_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk = PublicKey::from_secret_key(&sk);

    println!("cycle-tracker-start: sign");
    let sig = Signature::new(msg, &sk);
    println!("cycle-tracker-end: sign");
    sp1_zkvm::io::commit(&pk.as_bytes().to_vec());
    sp1_zkvm::io::commit(&sig.as_bytes().to_vec());

    // Multiple Signatures
    let mut secret_keys = vec![sk];

    for i in 1..N {
        let sk_bytes = sp1_zkvm::io::read::<[u8; 32]>();
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        secret_keys.push(sk);

        let signing_keypairs: Vec<Keypair> = secret_keys
            .iter()
            .map(|sk| {
                let pk = PublicKey::from_secret_key(sk);
                Keypair { sk: sk.clone(), pk }
            })
            .collect();
        let mut agg_sig = AggregateSignature::new();
        let mut public_keys = vec![];
        println!("{}", format!("cycle-tracker-start: aggregate-{}", i));
        signing_keypairs.iter().for_each(|keypair| {
            let sig = Signature::new(msg, &keypair.sk);
            agg_sig.add(&sig);
            public_keys.push(keypair.pk.clone());
        });
        let agg_sig_bytes = agg_sig.as_bytes().to_vec();
        println!("{}", format!("cycle-tracker-end: aggregate-{}", i));
        sp1_zkvm::io::commit(&agg_sig_bytes);

        let agg_pub_key = AggregatePublicKey::into_aggregate(&public_keys).unwrap();
        let agg_pub_key_hex = agg_pub_key.point.to_hex();
        sp1_zkvm::io::commit(&agg_pub_key_hex);
    }
}
