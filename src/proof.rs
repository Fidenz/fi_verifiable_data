use chrono::Utc;
use fi_digital_signatures::{
    algorithms::Algorithm, signer::get_signing_key, verifier::get_verifying_key,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use crate::{document::VerificationDocument, error::FiError};

pub trait Proof {
    fn sign(&mut self, doc: &mut VerificationDocument, content: String) -> Result<(), FiError>;
    fn verify(&self, doc: &mut VerificationDocument, content: String) -> Result<bool, FiError>;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FiProof {
    #[serde(rename = "type")]
    _type: String,
    created: String,
    algorithm: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    jws: Option<String>,
}

impl Proof for FiProof {
    fn sign(&mut self, doc: &mut VerificationDocument, content: String) -> Result<(), FiError> {
        let key_bytes = match doc.get_private_key_mut() {
            None => {
                return Err(FiError::new(
                    "No private key was found in the VerificationDocument",
                ))
            }
            Some(val) => val,
        };

        let alg = match Algorithm::from_str(self.algorithm.as_str()) {
            Some(val) => val,
            None => return Err(FiError::new("Algorithm cannot be identified.")),
        };

        let signing_key = match get_signing_key(alg, key_bytes.as_mut_slice()) {
            Ok(val) => val,
            Err(error) => {
                eprintln!("{}", error);
                return Err(FiError::new("Failed to get signing key"));
            }
        };

        match signing_key.sign(content, alg) {
            Ok(val) => {
                self.jws = Some(val);
                Ok(())
            }
            Err(error) => {
                eprintln!("{}", error);
                return Err(FiError::new("Failed to sign content"));
            }
        }
    }

    fn verify(&self, doc: &mut VerificationDocument, content: String) -> Result<bool, FiError> {
        let key_bytes = match doc.get_public_key_mut() {
            None => {
                return Err(FiError::new(
                    "No publuc key was found in the VerificationDocument",
                ))
            }
            Some(val) => val,
        };

        let alg = match Algorithm::from_str(self.algorithm.as_str()) {
            None => return Err(FiError::new("Provided algorithm is no supported")),
            Some(val) => val,
        };

        let verifying_key = match get_verifying_key(alg, key_bytes.as_mut_slice()) {
            Ok(val) => val,
            Err(error) => {
                eprintln!("{}", error);
                return Err(FiError::new("Failed to get signing key"));
            }
        };

        match self.jws.clone() {
            Some(val) => match verifying_key.verify(content, val, alg) {
                Ok(val) => Ok(val),
                Err(error) => {
                    eprintln!("{}", error);
                    return Err(FiError::new("Failed to verify content"));
                }
            },
            None => {
                return Err(FiError::new("Failed to verify content"));
            }
        }
    }
}

impl FiProof {
    pub fn new(alg: Algorithm, purpose: String) -> Self {
        let datetime = Utc::now().to_rfc3339();
        return FiProof {
            _type: String::from("FiProof"),
            algorithm: String::from(alg.to_str()),
            proof_purpose: purpose,
            created: datetime.to_string(),
            jws: None,
        };
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub enum ProofType {
    FiProof,
}

#[cfg(feature = "wasm")]
impl ProofType {
    pub fn sign(
        &self,
        alg: Algorithm,
        purpose: String,
        doc: &mut VerificationDocument,
        content: String,
    ) -> Result<JsValue, FiError> {
        match self {
            ProofType::FiProof => {
                let mut proof = FiProof::new(alg, purpose);
                _ = proof.sign(doc, content);

                match serde_wasm_bindgen::to_value(&proof) {
                    Ok(val) => return Ok(val),
                    Err(err) => return Err(FiError::new(err.to_string().as_str())),
                }
            }
        }
    }

    pub fn verify(
        &self,
        doc: &mut VerificationDocument,
        content: String,
        proof: JsValue,
    ) -> Result<bool, FiError> {
        match self {
            ProofType::FiProof => {
                let fi_proof: FiProof = match serde_wasm_bindgen::from_value(proof) {
                    Err(error) => return Err(FiError::new(error.to_string().as_str())),
                    Ok(val) => val,
                };

                fi_proof.verify(doc, content)
            }
        }
    }
}
