// regenerates the full 100-vector NIST KAT .rsp files for the six FAEST
// parameter sets, replicating the NIST PQCgenKAT_sign harness:
//   - master DRBG seeded with entropy input 00 01 .. 2F
//   - per vector: seed = randombytes(48), mlen = 33*(count+1), msg = randombytes(mlen)
//   - per-vector DRBG reseeded with seed; keypair then sign draw from it
// output is byte-identical in format to the reference .rsp files
// (count/seed/mlen/msg/pk/sk/smlen/sm, uppercase hex)

use std::fmt::Debug;
use std::fs::File;
use std::io::{BufWriter, Write};

use faest::{ByteEncoding, KeypairGenerator};
use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Rng, SeedableRng};
use signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn generate<KP, S>(name: &str, out_path: &str)
where
    KP: KeypairGenerator + RandomizedSigner<Box<S>> + ByteEncoding + Debug,
    KP::VerifyingKey: Verifier<S> + ByteEncoding + Debug,
    S: SignatureEncoding,
{
    let mut entropy = [0u8; 48];
    for (i, e) in entropy.iter_mut().enumerate() {
        *e = i as u8;
    }
    let mut master = NistPqcAes256CtrRng::from_seed(entropy.into());

    let f = File::create(out_path).expect("create rsp");
    let mut w = BufWriter::new(f);
    writeln!(w, "# {name}\n").unwrap();

    for count in 0..100u32 {
        let mut seed = [0u8; 48];
        master.fill_bytes(&mut seed);
        let mlen = 33 * (count as usize + 1);
        let mut msg = vec![0u8; mlen];
        master.fill_bytes(&mut msg);

        let mut rng = NistPqcAes256CtrRng::from_seed(seed.into());
        let kp = KP::generate(&mut rng);
        let vk = kp.verifying_key();
        let signature = kp.sign_with_rng(&mut rng, &msg);
        vk.verify(&msg, &signature).expect("self verify");

        let mut sm = msg.clone();
        sm.extend_from_slice(&signature.to_vec());

        writeln!(w, "count = {count}").unwrap();
        writeln!(w, "seed = {}", hex_upper(&seed)).unwrap();
        writeln!(w, "mlen = {mlen}").unwrap();
        writeln!(w, "msg = {}", hex_upper(&msg)).unwrap();
        writeln!(w, "pk = {}", hex_upper(&vk.to_vec())).unwrap();
        writeln!(w, "sk = {}", hex_upper(&kp.to_vec())).unwrap();
        writeln!(w, "smlen = {}", sm.len()).unwrap();
        writeln!(w, "sm = {}", hex_upper(&sm)).unwrap();
        writeln!(w).unwrap();
    }
    println!("wrote {out_path}");
}

fn main() {
    std::fs::create_dir_all("out").unwrap();
    generate::<faest::FAEST128sSigningKey, faest::FAEST128sSignature>(
        "faest_128s",
        "out/PQCsignKAT_faest_128s.rsp",
    );
    generate::<faest::FAEST128fSigningKey, faest::FAEST128fSignature>(
        "faest_128f",
        "out/PQCsignKAT_faest_128f.rsp",
    );
    generate::<faest::FAEST192sSigningKey, faest::FAEST192sSignature>(
        "faest_192s",
        "out/PQCsignKAT_faest_192s.rsp",
    );
    generate::<faest::FAEST192fSigningKey, faest::FAEST192fSignature>(
        "faest_192f",
        "out/PQCsignKAT_faest_192f.rsp",
    );
    generate::<faest::FAEST256sSigningKey, faest::FAEST256sSignature>(
        "faest_256s",
        "out/PQCsignKAT_faest_256s.rsp",
    );
    generate::<faest::FAEST256fSigningKey, faest::FAEST256fSignature>(
        "faest_256f",
        "out/PQCsignKAT_faest_256f.rsp",
    );
}
