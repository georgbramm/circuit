use crypto::digest::Digest;
use rand::Rng;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use num::{BigUint, FromPrimitive};
use num::bigint::RandomBits;
use crypto::sha3::Sha3;

// Key derivation function
fn key_derivation(key1: [u8; 16], key2: [u8; 16]) -> [u8; 16]{
    assert_eq!(key1.len(), key2.len(), "Key is not equal");
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = key1[i] ^ key2[i];
    }
    result
}

// Encrypt/Decrypt function
fn encryption(key: [u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let aes_key = GenericArray::from(key);
    let mut block = GenericArray::from(plaintext);
    let cipher = Aes128::new(&aes_key);
    cipher.encrypt_block(&mut block);
    let ciphertext = block.try_into().unwrap();
    ciphertext
}

fn decryption(key: [u8; 16], ciphertext: [u8; 16]) -> [u8; 16] {
    let aes_key = GenericArray::from(key);
    let mut block = GenericArray::from(ciphertext);
    let cipher = Aes128::new(&aes_key);
    cipher.decrypt_block(&mut block);
    let plaintext = block.try_into().unwrap();
    plaintext
}

// Hash function
fn hash(message: BigUint) -> [u8; 16]{
    let mut hasher = Sha3::shake_128();
    let message_bytes = message.to_bytes_be();
    hasher.input(&message_bytes);
    let mut hash_message = vec![];
    hasher.result(&mut hash_message);
    let result = hash_message.try_into().unwrap();
    result
}

// Generate truth table for given gate
fn truth_table(gate: String) -> [[u8; 3]; 4] {
    if gate == "AND" {
        return [
                [0, 0, 0],
                [0, 1, 0],
                [1, 0, 0],
                [1, 1, 1]
                ]
    } 
    else if gate == "XOR" {
        return [
                [0, 0, 0],
                [0, 1, 1],
                [1, 0, 1],
                [1, 1, 0]
                ]
    } 
    else 
    {
        unimplemented!("This gate doesn't exist!")
    }
}

// Generate random keys
fn generate_random_keys() -> [[[u8; 16]; 2]; 2] {
    let mut rng = rand::thread_rng();
    let mut keys = [[[0u8; 16]; 2]; 2];
    for row in keys.iter_mut() {
        for key in row.iter_mut() {
            rng.fill(&mut key[..]);
        }
    }
    keys
}

// Oblivious transfer
// From https://eprint.iacr.org/2015/267.pdf
fn oblivious_transfer(keys: [[u8; 16]; 2], bit: bool) -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let p = BigUint::parse_bytes(b"8232614617976856279072317982427644624595758235537723089819576056282601872542631717078779952011141109568991428115823956738415293901639693425529719101034229", 10).unwrap();
    let g = BigUint::from_bytes_be(b"2");
    let a_priv: BigUint = rng.sample(RandomBits::new(512));
    let b_priv: BigUint = rng.sample(RandomBits::new(512));
    let bit_num = if bit {BigUint::from_i8(1).unwrap()} else {BigUint::ZERO};

    let a_pub = g.modpow(&a_priv, &p);
    let b_pub = (g.modpow(&b_priv, &p) * a_pub.modpow(&bit_num, &p)) % &p;
    let a_pub_inverse = a_pub.modpow(&p, &p);

    let keyr = hash(a_pub.modpow(&b_priv, &p));
    
    let key0 = hash(b_pub.modpow(&a_priv, &p));
    let key1 = hash((b_pub.modpow(&a_priv, &p) * a_pub_inverse.modpow(&a_priv, &p)) % p);

    let e0 = encryption(key0, keys[0]);
    let e1 = encryption(key1, keys[1]);
    
    let mr = if bit {decryption(keyr, e1)} else {decryption(keyr, e0)};
    mr
}


fn main() {
    println!("Hello, world!");
}
