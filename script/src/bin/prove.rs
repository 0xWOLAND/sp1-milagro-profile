use milagro_bls::{PublicKey, SecretKey, Signature};
use sp1_sdk::utils;
use sp1_sdk::{ProverClient, SP1Stdin};
pub const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();
    let mut stdin = SP1Stdin::new();

    let client = ProverClient::new();

    let sk_bytes = vec![
        78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
        233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
    ];
    let msg = "hello world";

    stdin.write(&sk_bytes);
    stdin.write(&msg.as_bytes());
    let (mut public_values, _) = client.execute(ELF, stdin).expect("failed to prove");

    let pk = public_values.read::<Vec<u8>>();
    let sig = public_values.read::<Vec<u8>>();

    let signature = Signature::from_bytes(&sig).unwrap();
    let pk = PublicKey::from_bytes(&pk).unwrap();
    assert!(signature.verify(msg.as_bytes(), &pk));
}
