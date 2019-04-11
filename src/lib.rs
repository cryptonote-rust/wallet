use chrono::{DateTime, Utc};
use cryptonote_account::Address;
use cryptonote_raw_crypto::{secret_to_public, Chacha, ChachaIV, ChachaKey};
use cryptonote_varint as varint;
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use hex;
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

  fn timestamp() -> u64 {
    let now: DateTime<Utc> = Utc::now();
    let now = now.timestamp() as u64;
    now
  }

  pub fn parse_key(r: &mut Read) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    r.read_exact(&mut key).unwrap();
    key
  }

  pub fn check(secret: [u8; 32], public: [u8; 32]) -> bool {
    let generated_pub = secret_to_public(&secret);
    return public == generated_pub;
  }

  pub fn to_key_pair(secret_bytes: [u8; 32], public_bytes: [u8; 32]) -> Keypair {
    let mut pair: Vec<u8> = vec![];
    pair.extend(&public_bytes);
    pair.extend(&secret_bytes);
    let key_pair: Keypair = Keypair::from_bytes(&pair).expect("Error Key Pair");
    key_pair
  }

  pub fn to_address(&self, prefix: u64) -> Address {
    let spend_pubk: PublicKey = PublicKey::from_bytes(&self.spend_keys.1).unwrap();
    let view_pubk: PublicKey = PublicKey::from_bytes(&self.view_keys.1).unwrap();
    let address = Address::new(prefix, spend_pubk, view_pubk);
    address
  }

  pub fn prase(&mut self, buffer: &[u8]) {
    let mut buffered = BufReader::new(buffer);
    let createtime: u64 = varint::read(&mut buffered);
    self.createtime = createtime;
    let spend_public_key = Wallet::parse_key(&mut buffered);
    let spend_private_key = Wallet::parse_key(&mut buffered);
    if !Wallet::check(spend_private_key, spend_public_key) {
      panic!("Wrong spend keys!");
    }

    let view_public_key = Wallet::parse_key(&mut buffered);
    let view_private_key = Wallet::parse_key(&mut buffered);

    if !Wallet::check(spend_private_key, spend_public_key) {
      panic!("Wrong view keys!");
    }

    self.spend_keys = (spend_private_key, spend_public_key);
    self.view_keys = (view_private_key, view_public_key);
  }

  // pub fn from_private_keys()

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

  pub fn from_secret_keys(spend: [u8; 32], view: [u8; 32]) -> Wallet {
    let spend_pub = secret_to_public(&spend);
    let view_pub = secret_to_public(&view);
    Wallet::from_pair((spend, spend_pub), (view, view_pub))
  }

  fn to_fixed_key(bytes: &[u8]) -> [u8; 32] {
    let mut key: [u8; 32] = [0; 32];
    for i in 0..32 {
      key[i] = bytes[i];
    }
    key
  }

  pub fn from_secret_string(spend_str: String, view_str: String) -> Wallet {
    let spend_slice = hex::decode(spend_str).expect("Wrong spend str!");
    let view_slice = hex::decode(view_str).expect("Wrong view str");
    let spend: [u8; 32] = Wallet::to_fixed_key(&spend_slice[..]);
    let view: [u8; 32] = Wallet::to_fixed_key(&view_slice[..]);
    Wallet::from_secret_keys(spend, view)
  }

  pub fn from_pair(spend_keys: Keys, view_keys: Keys) -> Wallet {
    let chacha_iv = ChachaIV::new();
    let iv = chacha_iv.data;
    Wallet {
      version: 1,
      createtime: Wallet::timestamp(),
      loaded: true,
      iv,
      spend_keys,
      view_keys,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::Wallet;
  use ed25519_dalek::{Keypair, PublicKey, SecretKey};

  #[test]
  fn should_read() {
    let prefix: u64 = 0x3d;
    let mut wallet = Wallet::new();
    wallet.load(String::from("tests/vig.wallet"), String::from(""));
    let address = wallet.to_address(prefix);

    let mut wallet1 = Wallet::new();
    wallet1.load(
      String::from("tests/vig-enc.wallet"),
      String::from("abcd$1234"),
    );
    let address1 = wallet1.to_address(prefix);
    assert!(address.get() == address1.get());

    wallet.save(
      String::from("tests/vig-new.wallet"),
      String::from("abcd$1234"),
    );
    wallet1.save(String::from("tests/vig-enc-new.wallet"), String::from(""));

    let mut wallet2 = Wallet::new();
    wallet2.load(String::from("tests/vig-enc-new.wallet"), String::from(""));

    let mut wallet2 = Wallet::new();
    wallet2.load(
      String::from("tests/vig-new.wallet"),
      String::from("abcd$1234"),
    );

    assert!(wallet.version == wallet2.version);
    assert!(wallet.spend_keys == wallet2.spend_keys);
    assert!(wallet.view_keys == wallet2.view_keys);
    assert!(wallet.createtime == wallet2.createtime);

    let spend = wallet.spend_keys.0;
    let view = wallet.view_keys.0;

    let wallet3 = Wallet::from_secret_keys(spend, view);
    let address3 = wallet3.to_address(prefix);
    assert!(address3.get() == address1.get());
    let spend_str = "f644de91c7defae58ff9136dcc8b03a2059fda3294865065f86554d3aaeb310c";
    let view_str = "3dd9d71a6fe2b909e1603c9ac325f13f2c6ac965e7e1ec98e5e666ed84b4d40c";
    println!("before from secret string");
    let wallet = Wallet::from_secret_string(String::from(spend_str), String::from(view_str));
    let address = wallet.to_address(prefix);
    assert!(address.get() == "BM5A1ACoB4Af9ZuaJwTjHE37zowNmSp2nP2FjUZkm4u2LVo2UPXvMnW7xRhf9C7mJcBcLu5n9W3ArU69SKBS6azrMfn6NBH");
  }

  #[test]
  #[should_panic]
  fn test_wrong_load() {
    let prefix: u64 = 0x3d;
    let mut wallet0 = Wallet::new();
    wallet0.load(String::from("tests/vig.wallet"), String::from("aaaa"));
  }

  #[test]
  #[should_panic]
  fn test_wrong_file() {
    let prefix: u64 = 0x3d;
    let mut wallet0 = Wallet::new();
    wallet0.load(String::from("tests/vig1.wallet"), String::from("sssss"));
  }
}
