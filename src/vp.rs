use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
};

use fi_digital_signatures::algorithms::Algorithm;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{document::VerificationDocument, error::Error, proof::Proof, vc::VC};

#[derive(Serialize, Deserialize)]
pub struct VP<T>
where
    T: Proof + Serialize,
{
    #[serde(rename = "@context")]
    contexts: Vec<Value>,
    holder: Option<String>,
    id: String,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    proof: Option<T>,
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<VC<T>>,
    #[serde(skip_serializing, skip_deserializing)]
    optional_fields: HashMap<String, Box<Value>>,
}

impl<T: Proof + Serialize + DeserializeOwned> VP<T> {
    pub fn new(id: String, holder: Option<String>) -> Self {
        let mut vp = VP {
            contexts: Vec::new(),
            holder,
            id,
            proof: None,
            types: Vec::new(),
            verifiable_credential: Vec::new(),
            optional_fields: HashMap::new(),
        };

        vp.types.push(String::from("VerifiablePresentation"));

        vp
    }

    pub fn set_holder(&mut self, holder: Option<String>) {
        self.holder = holder;
    }

    pub fn set_context(&mut self, contexts: Vec<Value>) {
        self.contexts = contexts;
    }

    pub fn add_context(&mut self, context: Value) {
        self.contexts.push(context)
    }

    pub fn set_types(&mut self, types: Vec<String>) {
        self.types = types;
    }

    pub fn get_proof(&self) -> &Option<T> {
        self.proof.borrow()
    }

    pub fn get_proof_mut(&mut self) -> &mut Option<T> {
        self.proof.borrow_mut()
    }
    pub fn sign(
        &mut self,
        doc: VerificationDocument,
        alg: Algorithm,
        purpose: String,
    ) -> Result<(), Error> {
        let signable_values = match self.get_signable_content() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        let proof = match T::sign(doc, alg, signable_values.to_string(), purpose) {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        self.proof = Some(*proof);
        return Ok(());
    }

    pub fn verify(&mut self, doc: VerificationDocument) -> Result<bool, Error> {
        let signable_values = match self.get_signable_content() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        let proof = match self.proof.as_mut() {
            None => return Err(Error::new("Cannot get proof as a mutable reference")),
            Some(val) => val,
        };

        proof.verify(doc, signable_values.to_string())
    }

    pub fn to_object(&mut self) -> Result<Value, Error> {
        let mut value = match serde_json::to_value(&self) {
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Cannot create value object from VP"));
            }
            Ok(val) => val,
        };

        let obj = value.as_object_mut().unwrap();

        self.optional_fields.iter_mut().for_each(move |(key, val)| {
            obj.insert(String::from(key), val.take());
        });

        return Ok(value);
    }

    pub fn get_signable_content(&mut self) -> Result<Value, Error> {
        let mut val = match self.to_object() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        val.as_object_mut().unwrap().remove("proof");

        return Ok(val);
    }

    pub fn from(value: Value) -> Result<Self, Error> {
        let mut map: HashMap<String, Box<Value>> = HashMap::new();

        match serde_ignored::deserialize(&value, |path| {
            let _path = path.to_string();
            let value_to_save = value[&_path].clone();
            map.insert(_path, Box::new(value_to_save));
        }) {
            Ok(val) => return Ok(val),
            Err(error) => return Err(Error::new(error.to_string().as_str())),
        };
    }
}
