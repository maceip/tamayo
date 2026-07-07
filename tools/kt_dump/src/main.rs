use kt_dump::transparency::{verify_consistency, verify_inclusion, verify_log, KeyLog, LogSigner};
use kt_dump::IssuerPublicKey;

fn main() {
    let signer = LogSigner::from_seed([7u8; 32]);
    let keys = [
        IssuerPublicKey { key_version: 1, tkid: [0xA1; 32] },
        IssuerPublicKey { key_version: 2, tkid: [0xB2; 32] },
        IssuerPublicKey { key_version: 3, tkid: [0xC3; 32] },
    ];
    let mut log = KeyLog::new();
    let mut prefix_signed_heads = Vec::new();
    let mut chain_heads_hex = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        log.append(k, (i as u64 + 1) * 1000).unwrap();
        chain_heads_hex.push(hex::encode(log.head()));
        let sth = signer.sign(&log);
        verify_log(&signer.public(), log.records(), &sth).expect("reference verify_log accepts");
        prefix_signed_heads.push(sth);
    }
    assert_eq!(verify_inclusion(log.records(), &[0xB2; 32]).unwrap(), 1);
    verify_consistency(&prefix_signed_heads[0], log.records()).expect("prefix consistency");

    let out = serde_json::json!({
        "source": "eat-pass core/src/transparency.rs compiled verbatim (include!), LogSigner seed = [7u8;32]; every prefix signed head certified by the reference verify_log at dump time",
        "log_public_key_hex": hex::encode(signer.public()),
        "records": log.records(),
        "chain_heads_hex": chain_heads_hex,
        "prefix_signed_heads": prefix_signed_heads,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
