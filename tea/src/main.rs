use std::env;
use std::fs::{File, read};
use std::io::{Write, BufWriter};
use std::process;

///
/// Encrypts a 64-bit block (two `u32`s) in-place using TEA.
/// `v`: 2-element array (v[0], v[1]) is the 64-bit block to encrypt.
/// `key`: 4-element array (128-bit key).
///
fn tea_encrypt_block(v: &mut [u32; 2], key: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let delta = 0x9E3779B9u32;
    let mut sum = 0u32;

    // TEA does 32 rounds
    for _ in 0..32 {
        sum = sum.wrapping_add(delta);
        v0 = v0.wrapping_add(
            ((v1 << 4).wrapping_add(key[0])) 
                ^ (v1.wrapping_add(sum)) 
                ^ ((v1 >> 5).wrapping_add(key[1]))
        );
        v1 = v1.wrapping_add(
            ((v0 << 4).wrapping_add(key[2])) 
                ^ (v0.wrapping_add(sum)) 
                ^ ((v0 >> 5).wrapping_add(key[3]))
        );
    }

    v[0] = v0;
    v[1] = v1;
}

///
/// Decrypts a 64-bit block (two `u32`s) in-place using TEA.
///
fn tea_decrypt_block(v: &mut [u32; 2], key: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let delta = 0x9E3779B9u32;
    // sum is delta * 32
    let mut sum = delta.wrapping_mul(32);

    for _ in 0..32 {
        v1 = v1.wrapping_sub(
            ((v0 << 4).wrapping_add(key[2])) 
                ^ (v0.wrapping_add(sum)) 
                ^ ((v0 >> 5).wrapping_add(key[3]))
        );
        v0 = v0.wrapping_sub(
            ((v1 << 4).wrapping_add(key[0])) 
                ^ (v1.wrapping_add(sum)) 
                ^ ((v1 >> 5).wrapping_add(key[1]))
        );
        sum = sum.wrapping_sub(delta);
    }

    v[0] = v0;
    v[1] = v1;
}

///
/// Convert 16 bytes into a 4-element array of u32 (our TEA key).
/// For real usage, you'd derive keys from a password or use random generation.
///
fn bytes_to_key(bytes: &[u8]) -> [u32; 4] {
    // TEA key is 128 bits => 16 bytes => 4 u32
    let mut key = [0u32; 4];
    for i in 0..4 {
        key[i] = u32::from_be_bytes([
            bytes[4*i],
            bytes[4*i + 1],
            bytes[4*i + 2],
            bytes[4*i + 3],
        ]);
    }
    key
}

///
/// Pads the data to a multiple of 8 bytes (size of TEA block).
/// This is a simple zero-padding scheme for demonstration.
///
fn zero_pad_to_block_size(mut data: Vec<u8>) -> Vec<u8> {
    let block_size = 8;
    let pad_len = block_size - (data.len() % block_size);
    if pad_len < block_size {
        data.extend(vec![0u8; pad_len]);
    }
    data
}

///
/// Encrypt the entire buffer in 8-byte blocks using TEA.
///
fn encrypt_data(data: &mut [u8], key: &[u32; 4]) {
    // Operate 8 bytes at a time
    for chunk in data.chunks_mut(8) {
        let mut block = [
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        ];
        tea_encrypt_block(&mut block, key);
        chunk[0..4].copy_from_slice(&block[0].to_be_bytes());
        chunk[4..8].copy_from_slice(&block[1].to_be_bytes());
    }
}

///
/// Decrypt the entire buffer in 8-byte blocks using TEA.
///
fn decrypt_data(data: &mut [u8], key: &[u32; 4]) {
    for chunk in data.chunks_mut(8) {
        let mut block = [
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
        ];
        tea_decrypt_block(&mut block, key);
        chunk[0..4].copy_from_slice(&block[0].to_be_bytes());
        chunk[4..8].copy_from_slice(&block[1].to_be_bytes());
    }
}

fn main() {
    // Very simplistic CLI parsing:
    // Usage: tea-encrypt-cli <encrypt|decrypt> <path-to-file> <16-byte-hex-key>
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <encrypt|decrypt> <filename> <16-byte-hex-key>", args[0]);
        process::exit(1);
    }

    let mode = &args[1];
    let filename = &args[2];
    let key_hex = &args[3];

    // Convert hex key to [u8; 16]
    let key_bytes = match hex_string_to_16_bytes(key_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Invalid 16-byte hex key: {}", e);
            process::exit(1);
        }
    };

    let key = bytes_to_key(&key_bytes);

    // Read file
    let file_data = match read(filename) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read file {}: {}", filename, e);
            process::exit(1);
        }
    };

    // For encryption, zero-pad the data to a multiple of 8 bytes
    let mut data = if mode == "encrypt" {
        zero_pad_to_block_size(file_data)
    } else {
        // For decryption, we assume the file is already padded or is multiple of 8
        file_data
    };

    // Encrypt or decrypt in place
    match mode.as_str() {
        "encrypt" => {
            encrypt_data(&mut data, &key);
        },
        "decrypt" => {
            decrypt_data(&mut data, &key);
        },
        _ => {
            eprintln!("Invalid mode: {}", mode);
            process::exit(1);
        }
    }

    // Write the resulting file (overwrites original in this example)
    let out_file = match File::create(filename) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open output file {}: {}", filename, e);
            process::exit(1);
        }
    };
    let mut writer = BufWriter::new(out_file);
    if let Err(e) = writer.write_all(&data) {
        eprintln!("Failed to write output: {}", e);
        process::exit(1);
    }

    println!("Operation '{}' completed on file '{}'", mode, filename);
}

///
/// Helper that converts a 32-hex-character string into 16 bytes.
/// Expects an exact length of 32 hex characters (128 bits).
///
fn hex_string_to_16_bytes(hex: &str) -> Result<[u8; 16], String> {
    if hex.len() != 32 {
        return Err(format!("Expected 32 hex chars, found {}", hex.len()));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let sub = &hex[2*i..2*i+2];
        bytes[i] = u8::from_str_radix(sub, 16)
            .map_err(|_| format!("Invalid hex at '{}'", sub))?;
    }
    Ok(bytes)
}

