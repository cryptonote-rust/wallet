# Wallet Library For CryptoNote Based Crypto Currencies


[![](https://travis-ci.com/cryptonote-rust/wallet.svg?branch=master)](https://travis-ci.com/cryptonote-rust/wallet)
[![](https://img.shields.io/crates/v/cryptonote-wallet.svg)](https://crates.io/crates/cryptonote-wallet)
[![codecov](https://codecov.io/gh/cryptonote-rust/wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptonote-rust/wallet)


# Pure Wallet without cache

## Usage

1. load and save

```
    // Create a wallet object
    let mut wallet = Wallet::new();

    // Load wallet from a wallet file with a password.
    wallet.load(String::from("tests/vig.wallet"), String::from(""));

    // Save current wallet to a new file with a new password.
    wallet.save(String::from("tests/vig-new.wallet"), String::from("abcd"));
```

2. to Address
```
    let prefix: u64 = 0x3d;
    let mut wallet = Wallet::new();
    wallet.load(String::from("tests/vig.wallet"), String::from(""));

    // Get an Address object
    let address = wallet.to_address(prefix);
    let addressStr = address.get();
    println!("{}" , addressStr);
    
```
