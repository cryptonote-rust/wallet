use chrono::{NaiveDate, NaiveDateTime};
use chrono::{TimeZone, Utc};
use cryptonote_account::Account;
use cryptonote_raw_crypto::{Chacha, ChachaIV, ChachaKey};
use cryptonote_currency::Currency;
use cryptonote_varint as varint;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::rc::Rc;

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

  pub fn prase(buffer: &[u8]) {
    let mut buffered = BufReader::new(buffer);
    let createtime: u64 = varint::read(buffered);
    println!("{}", createtime);

    let datetime = NaiveDateTime::from_timestamp(createtime as i64, 0);
    println!("{}", createtime);
    println!("{}", datetime.format("%Y-%m-%d %H:%M:%S"));
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
