use std::env;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

use sha2::{Digest, Sha256, Sha512};

use bip39::Mnemonic;

use ethers::prelude::*;
use ethers::signers::Signer as EthSigner;
use ethers::signers::coins_bip39::English;
use ethers::utils::to_checksum;

use solana_sdk::{
    derivation_path::DerivationPath,
    signer::{Signer, keypair::keypair_from_seed_and_derivation_path},
};

fn generate_mnemonic_from_entropy(
    entropy: &[u8],
) -> Result<(Vec<&'static str>, String, String), &'static str> {
    let mnemonic = Mnemonic::from_entropy(entropy).map_err(|_| "Invalid entropy length")?;

    //Ethereum
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic.to_string().as_str())
        .build()
        .unwrap();
    let eth_address = to_checksum(&wallet.address(), None);

    //Sol
    let seed: [u8; 64] = mnemonic.to_seed_normalized("");
    let derivation_path = DerivationPath::new_bip44(Some(0), Some(0));
    let keypair = keypair_from_seed_and_derivation_path(&seed, Some(derivation_path)).unwrap();
    let pubkey = keypair.pubkey();
    let sol_address = pubkey.to_string();

    Ok((
        mnemonic.words().collect::<Vec<_>>(),
        eth_address,
        sol_address,
    ))
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

    let main = io::BufReader::new(File::open(Path::new("./secret/main.txt")).unwrap())
        .lines()
        .next()
        .unwrap()
        .unwrap();

    let reader = io::BufReader::new(File::open(Path::new("./secret/wallets.txt")).unwrap());

    println!("Main key digest: \n    {}", hash(main.as_str()));

    println!("==============================");

    for word in reader.lines().map_while(Result::ok) {
        println!("Sub key digest: \n    {}", hash(&word));

        if let Some(mnemonic_len) = mnemonic_len {
            let mut hash = Sha512::new_with_prefix(main.as_bytes());
            hash.update(word.as_bytes());
            let t = hash.finalize();

            match generate_mnemonic_from_entropy(&t[0..(mnemonic_len / 3 * 4)]) {
                Ok((mnemonic, eth, sol)) => {
                    println!("Generated Mnemonic: ");
                    let mut output = vec![];
                    mnemonic.iter().enumerate().for_each(|(i, &e)| {
                        print!("{:02}: {:<10}", i + 1, e);
                        if i % 6 == 5 {
                            println!();
                        }
                        output.push(e);
                    });

                    println!("------------------------------");
                    output.iter().for_each(|&e| print!("{} ", e));
                    println!("\n------------------------------");
                    println!("Ethereum: {}", eth);
                    println!("Solana: {}", sol);
                }
                Err(e) => eprintln!("Error: {}", e),
            };
        }

        println!("==============================");
    }
}
