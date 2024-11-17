use std::{
    error,
    io::{self, Write},
};

use cocoon::MiniCocoon;
use rand::Rng;

fn write_message(plaintext: &str, cacoon: &MiniCocoon) {
    let mut data = plaintext.to_owned().into_bytes();
    let detached_prefix = cacoon.encrypt(&mut data).unwrap();
    println!("< {}:{}", hex::encode(detached_prefix), hex::encode(data));
}

fn read_message(cocoon: &MiniCocoon) -> Result<String, Box<dyn error::Error>> {
    print!("> ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    if let Some((detached_prefix, ciphertext)) = input.split_once(':') {
        let detached_prefix =
            hex::decode(detached_prefix.trim()).map_err(|_| "Prefix is invalid hex")?;
        let mut ciphertext =
            hex::decode(ciphertext.trim()).map_err(|_| "Ciphertext is invalid hex")?;

        cocoon
            .decrypt(&mut ciphertext, &detached_prefix)
            .map_err(|_| "Decryption failed")?;
        let data = String::from_utf8(ciphertext).map_err(|_| "Invalid UTF-8")?;

        Ok(data)
    } else {
        Err("Prefix and message must be separated by a colon.")?
    }
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let key = rand::thread_rng().gen::<[u8; 32]>();
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let cocoon = MiniCocoon::from_key(&key, &seed).with_cipher(cocoon::CocoonCipher::Aes256Gcm);

    println!("Conversation:");
    let messages = include_str!("../messages.txt").lines().collect::<Vec<_>>();
    for message in &messages {
        write_message(message, &cocoon);
    }

    println!("\nJoin in on the conversation! Make sure your message is encrypted and uses the same format.");
    let input = read_message(&cocoon)?;
    println!();

    if messages.contains(&input.as_str()) {
        println!("Why did you repeat that message?");
    } else if input.contains("Give me the flag") {
        println!("Since you asked so nicely, here is your flag:");
        write_message(include_str!("../flag.txt"), &cocoon);
    } else {
        println!("You said: {input:?}");
    }

    Ok(())
}
