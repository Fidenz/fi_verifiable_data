# fi-verifiable-data

[![crates.io](https://buildstats.info/crate/fi_verifiable_data)](https://crates.io/crates/fi_verifiable_data)
![Test](https://github.com/Fidenz/fi_verifiable_data/actions/workflows/test.yaml/badge.svg)
![Package publish](https://github.com/Fidenz/fi_verifiable_data/actions/workflows/publish.yaml/badge.svg) 

**fi-verifiable-data** library is focused on the representation and validation for **Verifiable Credential** and **Verifiable Presentation**. [fi-digital-signatures]("https://github.com/Fidenz/fi_digital_signatures") crate is used to sign and verify VP and VC proofs. API documentation on [docs.rs](https://docs.rs/fi-verifiable-data/latest/fi_verifiable_data/)

CDN - <https://fidenz.github.io/fi_verifiable_data/pkg/fi_verifiable_data.js>

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

#### Sign

```javascript
const fiVerifiableData = await import("fi-verifiable-data");

let vc = new fiVerifiableData.VC("id:1", "issuer", "name", "description", new Date().toString(), [
  "https://www.w3.org/2018/credentials/v1", 
]);
 
const privateKeyBytes = Uint8Array.from(
  Buffer.from(
    "7b6df71975950d5ea15ac090c57d462f73d3a48644fbcf2c6d5db838adf136b5",
    "hex"
  )
);
let verificationDocument = new fiVerifiableData.VerificationDocument(
  "",
  privateKeyBytes,
  null
);

vc.sign(
  fiVerifiableData.Algorithm.EdDSA,
  "purpose",
  verificationDocument,
  fiVerifiableData.ProofType.FiProof
);
console.log(vc.toObject());
```

#### Verify

```javascript
const fiVerifiableData = await import("fi-verifiable-data");
 
const publicKeyBytes = Uint8Array.from(
  Buffer.from(
    "aa7f263d0a1a671a4c06ea22800c1391dd8974174f01d0e5a848fe51bdd1bcf8",
    "hex"
  )
); 
let verificationDocument = new fiVerifiableData.VerificationDocument(
  "",
  null,
  publicKeyBytes
);

let result = vc.verify( 
  verificationDocument
); 
```

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


#### Sign

```javascript
const fiVerifiableData = await import("fi-verifiable-data");

let vp = new fiVerifiableData.VP("id:1", "holder");
vp.addVerifiableCredential(vc1);
vp.addVerifiableCredential(vc2);
 
const privateKeyBytes = Uint8Array.from(
  Buffer.from(
    "7b6df71975950d5ea15ac090c57d462f73d3a48644fbcf2c6d5db838adf136b5",
    "hex"
  )
);
let verificationDocument = new fiVerifiableData.VerificationDocument(
  "",
  privateKeyBytes,
  null
);

vp.sign(
  fiVerifiableData.Algorithm.EdDSA,
  "purpose",
  verificationDocument,
  fiVerifiableData.ProofType.FiProof
);
console.log(vp.toObject());
```

#### Verify

```javascript
const fiVerifiableData = await import("fi-verifiable-data");
 
const publicKeyBytes = Uint8Array.from(
  Buffer.from(
    "aa7f263d0a1a671a4c06ea22800c1391dd8974174f01d0e5a848fe51bdd1bcf8",
    "hex"
  )
); 
let verificationDocument = new fiVerifiableData.VerificationDocument(
  "",
  null,
  publicKeyBytes
);

let result = vp.verify( 
  verificationDocument
); 
``` 