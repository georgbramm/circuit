#![allow(warnings)]
use std::{env, result, io};
use circuit::{decryption, garbled_circuit, generate_random_keys, key_derivation, oblivious_transfer, pad, unpad};

// Protocol
fn main(){
    let args: Vec<String> = env::args().collect();
    if args.len() < 4  {
        eprintln!("Usage: garbler|evaluator <bit> <gate>");
        std::process::exit(1);
    }

    let mut garbler_bit: u8;
    let mut garbled_key = [[[0u8; 16]; 2]; 2];
    let mut evaluator_bit: u8;

    if args[1] == "garbler" {
        garbler_bit = (&args[2]).parse().unwrap();
        println!("Enter four 16-byte keys for garbler");
        for i in 0..4{
            let mut hexkey = String::new();
            io::stdin().read_line(&mut hexkey).expect("Failed to read line");
            let key = hex::decode(hexkey.trim()).unwrap();
            garbled_key[i>>1][i%2] = key.try_into().unwrap();
        }
        let mut buf = [0u8; 1];
        getrandom::fill(&mut buf).expect("getrandom() error");
        evaluator_bit = buf[0];
    } 
    else {
        let mut buf = [0u8; 1];
        getrandom::fill(&mut buf).expect("getrandom() error");
        garbler_bit = buf[0];
        garbled_key = generate_random_keys();
        evaluator_bit = (&args[2]).parse().unwrap();
    }
    
    let garbled_circuit = garbled_circuit(garbled_key, String::from("XOR"));
    let evaluator_key = oblivious_transfer(garbled_key[1], evaluator_bit);
    let encrypt_key = key_derivation(garbled_key[0][garbler_bit as usize], evaluator_key);
    for &encrypted_value in garbled_circuit.iter() {
        let temp = decryption(encrypt_key, encrypted_value);
        let value = unpad(temp);
        if value.is_some() {
            println!("Value: {}", value.unwrap());
        }
    }
}
