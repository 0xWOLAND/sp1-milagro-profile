use milagro_bls::BLSCurve::ecp::ECP;
use milagro_bls::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use rand::distributions::{Alphanumeric, DistString};
use rand::random;
use sp1_sdk::utils;
use sp1_sdk::{ProverClient, SP1Stdin};

pub const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");
const N: usize = 5;

fn main() {
    utils::setup_logger();
    let mut stdin = SP1Stdin::new();
    let client = ProverClient::new();

    let msg = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    stdin.write(&msg.as_bytes());

    // Single Signature
    for _ in 0..10 {
        let sk_bytes = vec![0u8; 32]
            .into_iter()
            .map(|_| random::<u8>())
            .collect::<Vec<u8>>();

        stdin.write(&sk_bytes);
    }
    let (mut public_values, _) = client.execute(ELF, stdin).expect("failed to prove");

    let pk = public_values.read::<Vec<u8>>();
    let sig = public_values.read::<Vec<u8>>();

    let signature = Signature::from_bytes(&sig).unwrap();
    let pk = PublicKey::from_bytes(&pk).unwrap();
    assert!(signature.verify(msg.as_bytes(), &pk));

    // Aggregate signatueres
    for _ in 1..N {
        let sig = public_values.read::<Vec<u8>>();
        let agg_pub_key_hex = public_values.read::<String>();

        let agg_pub_key = AggregatePublicKey {
            point: ECP::from_hex(agg_pub_key_hex),
        };
        let agg_sig = AggregateSignature::from_bytes(&sig).unwrap();
        assert!(agg_sig.fast_aggregate_verify_pre_aggregated(msg.as_bytes(), &agg_pub_key));
    }
}
