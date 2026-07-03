use rand::RngCore;
use rayon::prelude::*;
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const COMMIT_HEX: &str = "90243a7416f52151a8c6cecf633500dceb366895";
const FIXED_SUFFIX: [u8; 4] = [0x7e, 0xa4, 0x40, 0xbd];

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn check(hash: &[u8]) -> bool {
    hash[0] == 0
        && hash[1] == 0
        && hash[2] == 0
        && hash[3] == 0
        && (hash[4] & 0x80) == 0
}

fn worker(prefix_bytes: [u8; 4], found: Arc<AtomicBool>) {
    let mut rng = rand::thread_rng();

    let mut uuid = [0u8; 16];
    uuid[0..4].copy_from_slice(&prefix_bytes);
    uuid[12..16].copy_from_slice(&FIXED_SUFFIX);

    let mut out = *b"00000000-0000-0000-0000-000000000000";

    hex::encode_to_slice(&uuid[0..4], &mut out[0..8]).unwrap();
    hex::encode_to_slice(&uuid[12..16], &mut out[28..36]).unwrap();

    while !found.load(Ordering::Relaxed) {
        rng.fill_bytes(&mut uuid[4..12]);

        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        
        hex::encode_to_slice(&uuid[4..6], &mut out[9..13]).unwrap();
        hex::encode_to_slice(&uuid[6..8], &mut out[14..18]).unwrap();
        hex::encode_to_slice(&uuid[8..10], &mut out[19..23]).unwrap();
        hex::encode_to_slice(&uuid[10..12], &mut out[24..28]).unwrap();

        let mut hasher = Sha512::new();
        hasher.update(&uuid);
        let result = hasher.finalize();

        if check(&result) {
            if !found.swap(true, Ordering::Relaxed) {
                let answer = std::str::from_utf8(&out).unwrap();
                println!("/answer {}", answer);
            }
            break;
        }
    }
}

fn main() {
    let prefix = &COMMIT_HEX[COMMIT_HEX.len() - 8..];
    let prefix_vec = hex_to_bytes(prefix);
    let prefix_bytes: [u8; 4] = prefix_vec.try_into().unwrap();

    let cores = num_cpus::get();
    println!("[*] Target prefix: {}", prefix);
    println!("[*] Target suffix: 7ea440bd");
    println!("[*] Required PoW : 33 bits leading zero in SHA512");
    println!("[*] Using {} cores for mining...", cores);

    let found = Arc::new(AtomicBool::new(false));

    (0..cores).into_par_iter().for_each(|_| {
        worker(prefix_bytes, found.clone());
    });
}
