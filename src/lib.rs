
use std::rc::Rc;
use std::fs::File;
use std::io::{Write, BufReader, BufRead, Read};
use cryptonote_account::Account;
use cryptonote_currency::Currency;
use cryptonote_varint as varint;

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

  pub fn load(file: String) {
    let input = File::open(file).expect("File not found!");
    let mut buffered = BufReader::new(input);
    let version: u64 = varint::read(&mut buffered);
    let mut iv: [u8;8] = [0;8];
    buffered.read_exact(&mut iv[..]).expect("Failed to read");
    let cipher_len: u64 = varint::read(&mut buffered);
    println!("version is : {}", version);
    println!("iv is : {:x?}", iv);
    println!("len is : {}", cipher_len);
  }
}

#[cfg(test)]
mod tests {
  use super::Wallet;
  #[test]

  fn should_read() {
    Wallet::load(String::from("tests/vig.wallet"));
  }
}
