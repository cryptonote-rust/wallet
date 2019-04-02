use chrono::NaiveDateTime;
use cryptonote_account::Address;
// use cryptonote_currency::Currency;
use cryptonote_raw_crypto::{Chacha, ChachaIV, ChachaKey};
use cryptonote_varint as varint;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
// use std::rc::Rc;
use ed25519_dalek::PublicKey;

type Keys = ([u8; 32], [u8; 32]);
pub struct Wallet {
  version: u64,
  spend_keys: Keys,
  view_keys: Keys,
  createtime: u64,
  iv: [u8; 8],
  password: String,
  loaded: bool,
}

impl Wallet {
  pub fn new() -> Wallet {
    Wallet {
      version: 1,
      spend_keys: ([0; 32], [0; 32]),
      view_keys: ([0; 32], [0; 32]),
      createtime: 0,
      iv: [0; 8],
      password: String::from(""),
      loaded: false,
    }
  }

  pub fn parse_key(r: &mut Read) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    r.read_exact(&mut key).unwrap();
    key
  }

  pub fn to_address(&self) -> Address {
    let spend_pubk: PublicKey = PublicKey::from_bytes(&self.spend_keys.1).unwrap();
    let view_pubk: PublicKey = PublicKey::from_bytes(&self.view_keys.1).unwrap();
    let address = Address::new(0x3d, spend_pubk, view_pubk);
    println!("{}", address.get());
    address
  }

  pub fn prase(&mut self, buffer: &[u8]) {
    let mut buffered = BufReader::new(buffer);
    let createtime: u64 = varint::read(&mut buffered);
    self.createtime = createtime;
    println!("{}", createtime);

    let datetime = NaiveDateTime::from_timestamp(createtime as i64, 0);

    // let cursor = BufReader<Cursor>
    println!("{}", createtime);
    println!("{}", datetime.format("%Y-%m-%d %H:%M:%S"));

    let spend_public_key = Wallet::parse_key(&mut buffered);
    let spend_private_key = Wallet::parse_key(&mut buffered);
    let view_public_key = Wallet::parse_key(&mut buffered);
    let view_private_key = Wallet::parse_key(&mut buffered);

    self.spend_keys = (spend_private_key, spend_public_key);
    self.view_keys = (view_private_key, view_public_key);
    println!("{:?}", spend_public_key);
    println!("{:?}", spend_private_key);
    println!("{:?}", view_public_key);
    println!("{:?}", view_private_key);
    // let spend_prik: SecretKey = SecretKey::from_bytes(&spend_private_key).unwrap();
    // let view_prik: SecretKey = SecretKey::from_bytes(&view_private_key).unwrap();
    // let spend_pubk: PublicKey = PublicKey::from_bytes(&spend_public_key).unwrap();
    // let view_pubk: PublicKey = PublicKey::from_bytes(&view_public_key).unwrap();
    // let into_spend_pubk: PublicKey = (&spend_prik).into();
    // let into_view_pubk: PublicKey = (&view_prik).into();
    // assert!(into_spend_pubk.to_bytes() == spend_public_key);
    // assert!(into_view_pubk.to_bytes() == view_public_key);
    // let address = Address::new(0x3d, spend_pubk, view_pubk);
    // println!("{}", address.get());
  }

  pub fn load(&mut self, file: String, password: &str) {
    let input = File::open(file).expect("File not found!");
    let mut buffered = BufReader::new(input);
    let version: u64 = varint::read(&mut buffered);
    self.version = version;
    let mut iv: [u8; 8] = [0; 8];
    buffered
      .read_exact(&mut iv[..])
      .expect("Failed to read iv!");
    self.iv = iv;
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

    self.prase(&dec);
    self.password = String::from(password);
    self.loaded = true;
  }

  pub fn save(&self, file: String) {
    let output = File::open(file).expect("File not found!");
    let mut buffered = BufWriter::new(output);
    varint::write(&mut buffered, self.version);
  }
}

#[cfg(test)]
mod tests {
  use super::Wallet;

  #[test]

  fn should_read() {
    let mut wallet = Wallet::new();
    wallet.load(String::from("tests/vig.wallet"), "");
    let address = wallet.to_address();
    println!("{}", address.get());
    let mut wallet1 = Wallet::new();
    wallet1.load(String::from("tests/vig-enc.wallet"), "abcd$1234");
    let address1 = wallet1.to_address();
    println!("{}", address1.get());
    assert!(address.get() == address1.get());

    // let mut wallet = Wallet::new();
    // wallet.load(String::from("tests/pool.wallet"), "abcd$1234");
  }
}
