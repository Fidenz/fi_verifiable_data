use serde_json::Value;
use verifiable_data::{document::VerificationDocument, proof::FiProof, vc::VC};

const PRIVATE_KEY_HEX: &'static str =
    "aa7f263d0a1a671a4c06ea22800c1391dd8974174f01d0e5a848fe51bdd1bcf8";
const PUBLIC_KEY_HEX: &'static str =
    "7b6df71975950d5ea15ac090c57d462f73d3a48644fbcf2c6d5db838adf136b5";

#[test]
pub fn vc_basic_test() {
    let id = String::from("id:1");
    let issuer = String::from("id:1#issuer");
    let name = String::from("Test Issuer");

    let mut vc = VC::new(id, Value::from(issuer), Some(Value::from(name)), None, None);

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("rivate key hex decode failed");
    let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("Public key hex decode failed");

    let mut eddsa_doc = VerificationDocument::new(
        String::from("doc_id"),
        Some(private_key_bytes),
        Some(public_key_bytes),
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

    let result = match vc.verify(&mut eddsa_doc) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };
    assert!(result);
}
