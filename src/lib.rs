use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use num::BigUint;
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

// Key derivation function
pub fn key_derivation(key1: [u8; 16], key2: [u8; 16]) -> [u8; 16]{
    assert_eq!(key1.len(), key2.len(), "Key is not equal");
    let mut result = [0u8; 16];

    let mut hasher = Shake128::default();
    let mut key1_vec = key1.to_vec();
    let mut key2_vec = key2.to_vec();
    key1_vec.append(&mut key2_vec);
    hasher.update(&key1_vec);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut result);
    result
}

// Padding function, use for encrypt, decrypt gate
pub fn pad(bit: u8) -> [u8; 16] {
    let mut init = vec![bit];
    let mut pad = vec![15u8; 15];
    init.append(&mut pad);
    let result = init.try_into().unwrap();
    result
}

pub fn unpad(padded_bit: [u8; 16]) -> Option<u8> {
    let mut check = false;
    for i in 1..16 {
        if padded_bit[i] != 15u8 {
            check = true;
        }
    }
    if check {
        None
    } else {
        Some(padded_bit[0])
    }
}

// Encrypt/Decrypt function
pub fn encryption(key: [u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let aes_key = GenericArray::from(key);
    let mut block = GenericArray::from(plaintext);
    let cipher = Aes128::new(&aes_key);
    cipher.encrypt_block(&mut block);
    let ciphertext = block.try_into().unwrap();
    ciphertext
}

pub fn decryption(key: [u8; 16], ciphertext: [u8; 16]) -> [u8; 16] {
    let aes_key = GenericArray::from(key);
    let mut block = GenericArray::from(ciphertext);
    let cipher = Aes128::new(&aes_key);
    cipher.decrypt_block(&mut block);
    let plaintext = block.try_into().unwrap();
    plaintext
}

// Hash function
fn hash_message(message: BigUint) -> [u8; 16]{
    let mut hasher = Shake128::default();
    let message_bytes = message.to_bytes_be();
    hasher.update(&message_bytes);
    let mut reader = hasher.finalize_xof();
    let mut result = [0u8; 16];
    reader.read(&mut result);
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
pub fn generate_random_keys() -> [[[u8; 16]; 2]; 2] {
    //let mut rng = rand::thread_rng();
    let mut keys = [[[0u8; 16]; 2]; 2];
    for row in keys.iter_mut() {
        for key in row.iter_mut() {
            getrandom::fill(&mut key[..]).expect("getrandom() error");
        }
    }
    keys
}

// Oblivious transfer
// From https://eprint.iacr.org/2015/267.pdf
pub fn oblivious_transfer(keys: [[u8; 16]; 2], bit: u8) -> [u8; 16] {
    //let mut rng = rand::thread_rng();
    let p = BigUint::parse_bytes(b"8232614617976856279072317982427644624595758235537723089819576056282601872542631717078779952011141109568991428115823956738415293901639693425529719101034229", 10).unwrap();
    let g = BigUint::from_bytes_be(b"2");
    let mut a_buf = [0u8; 64];
    let mut b_buf = [0u8; 64];
    getrandom::fill(&mut a_buf).expect("getrandom() error");
    getrandom::fill(&mut b_buf).expect("getrandom() error");
    let a_priv: BigUint = BigUint::from_bytes_be(&a_buf);
    let b_priv: BigUint = BigUint::from_bytes_be(&b_buf);
    let bit_num = BigUint::from(bit);

    let a_pub = g.modpow(&a_priv, &p);
    let b_pub = (g.modpow(&b_priv, &p) * a_pub.modpow(&bit_num, &p)) % &p;
    let a_pub_inverse = a_pub.modinv(&p).unwrap();

    let keyr = hash_message(a_pub.modpow(&b_priv, &p));

    let mut hashkey = [[0u8; 16]; 2];
    hashkey[0] = hash_message(b_pub.modpow(&a_priv, &p));
    hashkey[1] = hash_message((b_pub.modpow(&a_priv, &p) * a_pub_inverse.modpow(&a_priv, &p)) % p);

    let mut e = [[0u8; 16]; 2];
    e[0] = encryption(hashkey[0], keys[0]);
    e[1] = encryption(hashkey[1], keys[1]);

    let mr = decryption(keyr, e[bit as usize]);
    mr
}

// Permute garbled circuit
pub fn garbled_circuit(key: [[[u8; 16]; 2]; 2], gate: String) -> [[u8; 16]; 4]{
    let truth_table = truth_table(gate);
    //let mut rng = thread_rng();

    let mut garbled_circuit = [[0u8; 16]; 4];
    for i in 0..4 {
        let encryption_key = key_derivation(key[0][i>>1], key[1][i%2]);
        let padded_bit = pad(truth_table[i][2]);
        garbled_circuit[i] = encryption(encryption_key, padded_bit);
    }
    shuffle(&mut garbled_circuit);
    garbled_circuit
}

pub fn shuffle<T>(vec: &mut [T]) {
    let n: usize = vec.len();
    for i in 0..(n - 1) {
        // Generate random index j, such that: i <= j < n
        // The remainder (`%`) after division is always less than the divisor.
        let rand = getrandom::u32().expect("getrandom() error");
        let j = (rand as usize) % (n - i) + i;
        vec.swap(i, j);
    }
}