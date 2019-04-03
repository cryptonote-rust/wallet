use cryptonote_account::Address;
use cryptonote_raw_crypto::{Chacha, ChachaIV, ChachaKey};
use cryptonote_varint as varint;
use ed25519_dalek::PublicKey;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

type Keys = ([u8; 32], [u8; 32]);
pub struct Wallet {
  pub version: u64,
  pub spend_keys: Keys,
  pub view_keys: Keys,
  pub createtime: u64,
  pub iv: [u8; 8],
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
    address
  }

  pub fn prase(&mut self, buffer: &[u8]) {
    let mut buffered = BufReader::new(buffer);
    let createtime: u64 = varint::read(&mut buffered);
    self.createtime = createtime;
    let spend_public_key = Wallet::parse_key(&mut buffered);
    let spend_private_key = Wallet::parse_key(&mut buffered);
    let view_public_key = Wallet::parse_key(&mut buffered);
    let view_private_key = Wallet::parse_key(&mut buffered);

    self.spend_keys = (spend_private_key, spend_public_key);
    self.view_keys = (view_private_key, view_public_key);
  }

  pub fn load(&mut self, file: String, password: String) {
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
    let mut cipher = vec![0; cipher_len as usize];
    buffered
      .read_exact(&mut cipher[..])
      .expect("Failed to read cipher!");
    let key = ChachaKey::generate(password.to_string());

    let iv0 = ChachaIV::from(iv);
    let chacha = Chacha::new(key, iv0);
    let dec = chacha.encrypt(&cipher);
    self.prase(&dec);
    self.loaded = true;
  }

  pub fn save(&self, file: String, password: String) {
    let output = File::create(file).expect("Fail to create file!");
    let mut buffered = BufWriter::new(output);
    varint::write(&mut buffered, self.version);
    buffered.write(&self.iv).expect("Error write iv!");
    let mut plain: Vec<u8> = vec![];
    varint::write(&mut plain, self.createtime);
    for item in [
      self.spend_keys.1,
      self.spend_keys.0,
      self.view_keys.1,
      self.view_keys.0,
    ]
    .into_iter()
    {
      plain.extend(item);
    }
    plain.extend(vec![0]);
    varint::write(&mut plain, 0 as u64);
    let key = ChachaKey::generate(password.to_string());
    let iv = ChachaIV::from(self.iv);
    let chacha = Chacha::new(key, iv);
    let cipher = chacha.encrypt(&plain);
    varint::write(&mut buffered, cipher.len() as u64);
    buffered.write(&cipher).expect("Error write cipher!");
  }
}

#[cfg(test)]
mod tests {
  use super::Wallet;

  #[test]

  fn should_read() {
    let mut wallet = Wallet::new();
    wallet.load(String::from("tests/vig.wallet"), String::from(""));
    let address = wallet.to_address();
    let mut wallet1 = Wallet::new();
    wallet1.load(String::from("tests/vig-enc.wallet"), String::from("abcd$1234"));
    let address1 = wallet1.to_address();
    assert!(address.get() == address1.get());

    wallet.save(
      String::from("tests/vig-new.wallet"),
      String::from("abcd$1234"),
    );
    wallet1.save(String::from("tests/vig-enc-new.wallet"), String::from(""));

    let mut wallet2 = Wallet::new();
    wallet2.load(String::from("tests/vig-enc-new.wallet"), String::from(""));

    assert!(wallet.version == wallet2.version);
    assert!(wallet.spend_keys == wallet2.spend_keys);
    assert!(wallet.view_keys == wallet2.view_keys);
    assert!(wallet.createtime == wallet2.createtime);
  }
}
