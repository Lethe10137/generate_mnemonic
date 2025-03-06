extern crate bip39;
extern crate sha2;

use bip39::Mnemonic;
use sha2::{Digest, Sha256, Sha512};
use std::env;

fn generate_mnemonic_from_entropy(entropy: &[u8]) -> Result<Vec<&'static str>, &'static str> {
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| "Invalid entropy length")?;
    let words = mnemonic.word_iter();
    Ok(words.collect())
}

fn hash(data: &str) -> String {
    let mut hash = Sha256::new_with_prefix("人生得意须尽欢，莫使金樽空对月".as_bytes());
    hash.update(data.as_bytes());
    format!("{:02X}", hash.finalize())
}

fn main() {
    let mut args = env::args().skip(1);

    let mnemonic_len = args
        .next()
        .map(|t| t.parse::<usize>().expect("Invalid mnemonic len"));

    let main = include_str!("../secret/main.txt");

    let words = [
        include_str!("../secret/key1.txt"),
        include_str!("../secret/key2.txt"),
    ];

    println!("Main key digest: \n    {}", hash(main));

    println!("==============================");

    for word in words {
        println!("Sub key digest: \n    {}", hash(word));

        if let Some(mnemonic_len) = mnemonic_len {
            let mut hash = Sha512::new_with_prefix(main.as_bytes());
            hash.update(word.as_bytes());
            let t = hash.finalize();

            match generate_mnemonic_from_entropy(&t[0..(mnemonic_len / 3 * 4)]) {
                Ok(mnemonic) => {
                    println!("Generated Mnemonic: ");
                    mnemonic
                        .iter()
                        .enumerate()
                        .for_each(|(i, &e)| println!("{}:\t {}", i, e));
                }
                Err(e) => eprintln!("Error: {}", e),
            };
        }

        println!("==============================");
    }
}
