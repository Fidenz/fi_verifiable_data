use serde_json::{error, json, Value};
use verifiable_data::{document::VerificationDocument, proof::FiProof, vc::VC, vp::VP};

const PRIVATE_KEY_HEX: &'static str =
    "aa7f263d0a1a671a4c06ea22800c1391dd8974174f01d0e5a848fe51bdd1bcf8";
const PUBLIC_KEY_HEX: &'static str =
    "7b6df71975950d5ea15ac090c57d462f73d3a48644fbcf2c6d5db838adf136b5";

#[test]
pub fn vp_basic_test() {
    let id1 = String::from("id:1");
    let id2 = String::from("id:2");
    let issuer1 = String::from("id:1#issuer");
    let issuer2 = String::from("id:2#issuer");
    let name = String::from("Test Issuer");

    let mut vc1 = VC::new(
        id1,
        Value::from(issuer1),
        Some(Value::from(name.clone())),
        None,
        None,
    );
    let mut vc2 = VC::new(
        id2,
        Value::from(issuer2),
        Some(Value::from(name)),
        None,
        None,
    );

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("rivate key hex decode failed");
    let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("Public key hex decode failed");

    let mut eddsa_doc = VerificationDocument::new(
        String::from("doc_id"),
        Some(private_key_bytes),
        Some(public_key_bytes),
    );

    let proof1 = FiProof::new(
        fi_digital_signatures::algorithms::Algorithm::EdDSA,
        String::from("ESig"),
    );
    let proof2 = FiProof::new(
        fi_digital_signatures::algorithms::Algorithm::EdDSA,
        String::from("ESig"),
    );

    match vc1.sign(&mut eddsa_doc, proof1) {
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
        }
        Ok(_) => {}
    };
    match vc2.sign(&mut eddsa_doc, proof2) {
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
        }
        Ok(_) => {}
    };

    let vp_id = String::from("id");
    let vp_issuer = String::from("id:#issuer");

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

    let result = match vp.verify(&mut eddsa_doc) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    assert!(result);
}

#[test]
pub fn test_vp_from_string() {
    let json_value = json!({
      "@context": [],
      "holder": "id:#issuer",
      "id": "id",
      "proof": {
        "algorithm": "EdDSA",
        "created": "2024-08-22T08:33:13.736780200+00:00",
        "jws": "GO0OdIKNlRqVYkbwq7C0v5KgG1woMvkwsMlXE3pkCNM1qEC-pGyt7rtViZffq8aigekUHq2or3Be5pOrDsLUCQ",
        "proofPurpose": "ESig",
        "type": "FiProof"
      },
      "type": ["VerifiablePresentation"],
      "verifiableCredential": [
        {
          "@context": [],
          "credentialStatus": null,
          "credentialSubject": null,
          "id": "id:1",
          "issuer": "id:1#issuer",
          "name": "Test Issuer",
          "proof": {
            "algorithm": "EdDSA",
            "created": "2024-08-22T08:33:13.735970700+00:00",
            "jws": "FDdaNuqLlggEQainuOQhkiIv4hWKsVVOqLgtATa0S1zgALlPSR4_V9uU9fClw8f_oJ_vVZ1Yuf_-r4sJC7iXAg",
            "proofPurpose": "ESig",
            "type": "FiProof"
          },
          "type": ["VerifiableCredential"],
          "validFrom": "2024-08-22T08:33:13.735475600+00:00"
        },
        {
          "@context": [],
          "credentialStatus": null,
          "credentialSubject": null,
          "id": "id:2",
          "issuer": "id:2#issuer",
          "name": "Test Issuer",
          "proof": {
            "algorithm": "EdDSA",
            "created": "2024-08-22T08:33:13.735980200+00:00",
            "jws": "q-9rfghN4qu6PHh_-53fxX8N8KnMn-zz3xxSJmzMdvOfoP2ksIXvOkeElovoVfa5KW47qL7T2YAAVnZXUba3BQ",
            "proofPurpose": "ESig",
            "type": "FiProof"
          },
          "type": ["VerifiableCredential"],
          "validFrom": "2024-08-22T08:33:13.735924500+00:00"
        }
      ]
    }
    );

    let mut vp = match VP::from(json_value) {
        Ok(val) => val,
        Err(error) => {
            eprintln!("{}", error);
            assert!(false);
            return;
        }
    };

    let private_key_bytes = hex::decode(PRIVATE_KEY_HEX).expect("rivate key hex decode failed");
    let public_key_bytes = hex::decode(PUBLIC_KEY_HEX).expect("Public key hex decode failed");

    let mut eddsa_doc = VerificationDocument::new(
        String::from("doc_id"),
        Some(private_key_bytes),
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

    assert!(result);
}
