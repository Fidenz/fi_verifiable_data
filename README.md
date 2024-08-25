# fi-verifiable-data

[![crates.io](https://buildstats.info/crate/fi_verifiable_data)](https://crates.io/crates/fi_verifiable_data)
![Test](https://github.com/Fidenz/fi_verifiable_data/actions/workflows/test.yaml/badge.svg)
![Package publish](https://github.com/Fidenz/fi_verifiable_data/actions/workflows/publish.yaml/badge.svg)
![Doc](https://github.com/Fidenz/fi_verifiable_data/actions/workflows/publish-doc.yaml/badge.svg)

**fi-verifiable-data** library is focused on the representation and validation for **Verifiable Credential** and **Verifiable Presentation**. [fi-digital-signatures]("https://github.com/Fidenz/fi_digital_signatures") crate is used to sign and verify VP and VC proofs. API documentation on [docs.rs](https://docs.rs/fi-verifiable-data/latest/fi_verifiable_data/)

## Verifiable Credential

### Rust

#### Sign

```rust
let mut vc = VC::new(
    id,
    Value::from(issuer),
    Some(Value::from(name)),
    Some(Value::from(description)),
    Some(Value::from(valid_until))
);

let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("Private key hex decode failed"); 

let mut eddsa_doc = VerificationDocument::new(
    String::from("doc_id"),
    Some(private_key_bytes),
    None,
);

let proof = FiProof::new(
    fi_digital_signatures::algorithms::Algorithm::EdDSA,
    String::from("ESig"),
);

match vc.sign(&mut eddsa_doc, proof) {
    Err(error) => {
        eprintln!("{}", error);
        assert!(false);
    }
    Ok(_) => {}
};
```

#### Verify

```rust
let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("Public key hex decode failed");

let mut eddsa_doc = VerificationDocument::new(
    String::from("doc_id"),
    None,
    Some(public_key_bytes),
);

let result = match vc.verify(&mut eddsa_doc) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };
```

### WASM

## Verifiable Presentation

### Rust

#### Sign

```rust
let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("rivate key hex decode failed"); 

let mut eddsa_doc = VerificationDocument::new(
    String::from("doc_id"),
    Some(private_key_bytes),
    None,
);

let mut vp = VP::new(vp_id, Some(String::from(vp_issuer)));
vp.add_verifiable_credentials(vc1);
vp.add_verifiable_credentials(vc2);

let proof = FiProof::new(
    fi_digital_signatures::algorithms::Algorithm::EdDSA,
    String::from("ESig"),
);

match vp.sign(&mut eddsa_doc, proof) {
    Err(error) => {
        eprintln!("{}", error);
        assert!(false);
    }
    Ok(_) => {}
};
```

#### Verify

```rust
let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("Public key hex decode failed");

let mut eddsa_doc = VerificationDocument::new(
    String::from("doc_id"),
    None,
    Some(public_key_bytes),
);

let result = match vp.verify(&mut eddsa_doc) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };
```

### WASM
