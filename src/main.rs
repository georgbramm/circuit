#![allow(warnings)]
use std::{env, result, io};
use circuit::{decryption, garbled_circuit, generate_keys, generate_random_keys, key_derivation, oblivious_transfer, pad, unpad};

// Protocol
fn main(){

    let mut garbler_bit: u8 = 0;
    let mut garbled_key1 = [[[0u8; 16]; 2]; 2];
    let mut garbled_key2 = [[[0u8; 16]; 2]; 2];
    let mut evaluator_bit: u8 = 1;

    let hexkey = vec![
        "110986f8d7e17a790d5b1b125a2bfba9".to_string(),
        "120986f8d7e16b790d5b1b125a2bfba9".to_string(),
        "130986f8d7e15c790d5b1b125a2bfba9".to_string(),
        "140986f8d7e14d790d5b1b125a2bfbc9".to_string()
    ];
    garbled_key1 = generate_keys(hexkey);
    println!("garbled_key1: {:?}", garbled_key1.clone());
    //let mut buf = [0u8; 1];
    //getrandom::fill(&mut buf).expect("getrandom() error");
    //evaluator_bit = buf[0];

    //let mut buf = [0u8; 1];
    //getrandom::fill(&mut buf).expect("getrandom() error");
    //garbler_bit = buf[0];
    garbled_key2 = generate_random_keys();
    //evaluator_bit = (&args[2]).parse().unwrap();

    let garbled_circuit1 = garbled_circuit(garbled_key1, String::from("XOR"));
    let evaluator_key1 = oblivious_transfer(garbled_key1[1], evaluator_bit);
    let garbled_circuit2 = garbled_circuit(garbled_key2, String::from("XOR"));
    let evaluator_key2 = oblivious_transfer(garbled_key2[1], evaluator_bit);

    println!("garbled_circuit: {:?}", garbled_circuit1.clone());
    let encrypt_key1 = key_derivation(garbled_key1[0][garbler_bit as usize % 2], evaluator_key1);
    let encrypt_key2 = key_derivation(garbled_key2[0][garbler_bit as usize % 2], evaluator_key2);

    println!("encrypt_key1: {:?}", encrypt_key1.clone());
    println!("encrypt_key2: {:?}", encrypt_key2.clone());
    for &encrypted_value in garbled_circuit1.iter() {
        let temp = decryption(encrypt_key1, encrypted_value);
        //println!("temp: {:?}", temp.clone());
        let value = unpad(temp);
        if value.is_some() {
            println!("Value: {}", value.unwrap());
        }
    }
    for &encrypted_value in garbled_circuit2.iter() {
        let temp = decryption(encrypt_key2, encrypted_value);
        //println!("temp: {:?}", temp.clone());
        let value = unpad(temp);
        if value.is_some() {
            println!("Value: {}", value.unwrap());
        }
    }
}
