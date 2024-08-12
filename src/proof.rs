use chrono::Utc;
use fi_digital_signatures::{
    algorithms::Algorithm, signer::get_signing_key, verifier::get_verifying_key,
};
use serde::{Deserialize, Serialize};

use crate::{document::VerificationDocument, error::Error};

pub trait Proof {
    fn sign(
        doc: VerificationDocument,
        alg: Algorithm,
        content: String,
        purpose: String,
    ) -> Result<Box<Self>, Error>;
    fn verify(&self, doc: VerificationDocument, content: String) -> Result<bool, Error>;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FiProof {
    #[serde(rename = "type")]
    _type: String,
    created: String,
    algorithm: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    jws: String,
}

impl Proof for FiProof {
    fn sign(
        doc: VerificationDocument,
        alg: Algorithm,
        content: String,
        purpose: String,
    ) -> Result<Box<Self>, Error> {
        if doc.private_key.is_none() {}

        let mut key_bytes = match doc.private_key {
            None => {
                return Err(Error::new(
                    "No private key was found in the VerificationDocument",
                ))
            }
            Some(val) => val,
        };

        let signing_key = match get_signing_key(alg, key_bytes.as_mut_slice()) {
            Ok(val) => val,
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Failed to get signing key"));
            }
        };

        let datetime = Utc::now().to_rfc3339();

        match signing_key.sign(content, alg) {
            Ok(val) => Ok(Box::new(FiProof {
                _type: String::from("FiProof"),
                algorithm: String::from(alg.to_str()),
                created: datetime,
                jws: val,
                proof_purpose: purpose,
            })),
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Failed to sign content"));
            }
        }
    }

    fn verify(&self, doc: VerificationDocument, content: String) -> Result<bool, Error> {
        let mut key_bytes = match doc.public_key {
            None => {
                return Err(Error::new(
                    "No publuc key was found in the VerificationDocument",
                ))
            }
            Some(val) => val,
        };

        let alg = match Algorithm::from_str(self.algorithm.as_str()) {
            None => return Err(Error::new("Provided algorithm is no supported")),
            Some(val) => val,
        };

        let verifying_key = match get_verifying_key(alg, key_bytes.as_mut_slice()) {
            Ok(val) => val,
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Failed to get signing key"));
            }
        };

        match verifying_key.verify(content, self.jws.clone(), alg) {
            Ok(val) => Ok(val),
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Failed to verify content"));
            }
        }
    }
}
