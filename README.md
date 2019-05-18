# Wallet Library For CryptoNote Based Crypto Currencies


[![](https://travis-ci.com/cryptonote-rust/wallet.svg?branch=master)](https://travis-ci.com/cryptonote-rust/wallet)
[![](https://img.shields.io/crates/v/cryptonote-wallet.svg)](https://crates.io/crates/cryptonote-wallet)
[![codecov](https://codecov.io/gh/cryptonote-rust/wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptonote-rust/wallet)


# Pure Wallet without cache

## Usage

### Wallet creation methods

1. from secret keys

```rust
    let spend = b"f644de91c7defae58ff9136dcc8b03a2059fda3294865065f86554d3aaeb310c";
    let view = b"3dd9d71a6fe2b909e1603c9ac325f13f2c6ac965e7e1ec98e5e666ed84b4d40c";
    let wallet = Wallet::from_secret_keys(spend, view);
```

2. from secret strings

```rust
    let spend_str = "f644de91c7defae58ff9136dcc8b03a2059fda3294865065f86554d3aaeb310c";
    let view_str = "3dd9d71a6fe2b909e1603c9ac325f13f2c6ac965e7e1ec98e5e666ed84b4d40c";
    let wallet = Wallet::from_secret_string(String::from(spend_str), String::from(view_str));
```

### Wallet File processing

1. load and save wallet

```rust
    // Create a wallet object
    let mut wallet = Wallet::new();

    // Load wallet from a wallet file with a password.
    wallet.load(String::from("tests/vig.wallet"), String::from(""));

    // Save current wallet to a new file with a new password.
    wallet.save(String::from("tests/vig-new.wallet"), String::from("abcd"));
```

### Wallet instance functions

#### Wallet Address generation

1. to Address

```rust
    let prefix: u64 = 0x3d;
    let mut wallet = Wallet::new();
    wallet.load(String::from("tests/vig.wallet"), String::from(""));

    // Get an Address object
    let address = wallet.to_address(prefix);
    let addressStr = address.get();
    println!("{}" , addressStr);
```

2. update secret keys

```rust
    let prefix: u64 = 0x3d;
    let mut wallet = Wallet::new();
    let spend_str = "f644de91c7defae58ff9136dcc8b03a2059fda3294865065f86554d3aaeb310c";
    let view_str = "3dd9d71a6fe2b909e1603c9ac325f13f2c6ac965e7e1ec98e5e666ed84b4d40c";
    wallet.update_secret_keys(String::from(spend_str), String::from(view_str));

    // Get an Address object
    let address = wallet.to_address(prefix);
    let addressStr = address.get();
    println!("{}" , addressStr);
```