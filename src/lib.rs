use chrono::{NaiveDate, NaiveDateTime};
use chrono::{TimeZone, Utc};
use cryptonote_account::{Account, Address};
use cryptonote_raw_crypto::{Chacha, ChachaIV, ChachaKey};
use cryptonote_currency::Currency;
use cryptonote_varint as varint;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::rc::Rc;
use ed25519_dalek::{PublicKey, SecretKey, Keypair};

pub struct Wallet {
  account: Option<Account>,
  currency: Currency,
}

impl Wallet {
  pub fn new(currency: Currency) -> Wallet {
    Wallet {
      account: None,
      currency,
    }
  }

  pub fn parseKey(r: & mut Read) -> [u8; 32]{
    let mut key: [u8; 32] = [0; 32];
    r.read_exact(&mut key).unwrap();
    key
  }

  pub fn prase(buffer: &[u8]) {
    let mut buffered = BufReader::new(buffer);
    let createtime: u64 = varint::read(& mut buffered);
    println!("{}", createtime);

    let datetime = NaiveDateTime::from_timestamp(createtime as i64, 0);

    // let cursor = BufReader<Cursor>
    println!("{}", createtime);
    println!("{}", datetime.format("%Y-%m-%d %H:%M:%S"));

    let spend_public_key = Wallet::parseKey(& mut buffered);
    let spend_private_key = Wallet::parseKey(& mut buffered);
    let view_public_key = Wallet::parseKey(& mut buffered);
    let view_private_key = Wallet::parseKey(& mut buffered);
    println!("{:?}", spend_public_key);
    println!("{:?}", spend_private_key);
    println!("{:?}", view_public_key);
    println!("{:?}", view_private_key);
    let spend_prik: SecretKey = SecretKey::from_bytes(&spend_private_key).unwrap();
    let view_prik: SecretKey = SecretKey::from_bytes(&view_private_key).unwrap();
    let spend_pubk: PublicKey = PublicKey::from_bytes(&spend_public_key).unwrap();
    let view_pubk: PublicKey = PublicKey::from_bytes(&view_public_key).unwrap();
    // let into_spend_pubk: PublicKey = (&spend_prik).into();
    // let into_view_pubk: PublicKey = (&view_prik).into();
    // assert!(into_spend_pubk.to_bytes() == spend_public_key);
    // assert!(into_view_pubk.to_bytes() == view_public_key);
    let address = Address::new(0x3d, spend_pubk, view_pubk);
    println!("{}", address.get());
  }

  pub fn load(file: String, password: &str) {
    let input = File::open(file).expect("File not found!");
    let mut buffered = BufReader::new(input);
    let version: u64 = varint::read(&mut buffered);
    let mut iv: [u8; 8] = [0; 8];
    buffered
      .read_exact(&mut iv[..])
      .expect("Failed to read iv!");
    let cipher_len: u64 = varint::read(&mut buffered);
    println!("version is : {}", version);
    println!("iv is : {:?}", iv);
    println!("len is : {}", cipher_len);
    println!("len is : {}", cipher_len as usize);
    let mut cipher = vec![0; cipher_len as usize];
    buffered
      .read_exact(&mut cipher[..])
      .expect("Failed to read cipher!");


    println!("password is : {}", password);

    let key = ChachaKey::generate(password.to_string());

    println!("key is : {:?}", key.data);
    let iv0 = ChachaIV::from(iv);
    let chacha = Chacha::new(key, iv0);
    println!("cipher is : {:x?}", &cipher[0]);
    println!("cipher is : {:x?}", &cipher[cipher.len() - 1]);
    let dec = chacha.encrypt(&cipher);
    println!("dec is : {:x?}", &dec[0]);
    println!("dec is : {:x?}", &dec[dec.len() - 1]);

    Wallet::prase(&dec);
  }
}

#[cfg(test)]
mod tests {
  use super::Wallet;
  #[test]

  fn should_read() {
    Wallet::load(String::from("tests/vig.wallet"), "");
    Wallet::load(String::from("tests/vig-enc.wallet"), "abcd$1234");
  }
}
