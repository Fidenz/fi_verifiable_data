use std::collections::HashMap;

use chrono::{DateTime, Utc};
use fi_digital_signatures::algorithms::Algorithm;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{
    constants::FIELD_CASTING_ERROR, document::VerificationDocument, error::Error, proof::Proof,
};

#[derive(Serialize, Deserialize)]
pub struct VC<T>
where
    T: Proof + Serialize,
{
    #[serde(rename = "@context")]
    contexts: Vec<Value>,
    #[serde(rename = "type")]
    types: Vec<String>,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<Value>,
    issuer: Value,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    valid_until: Option<String>,
    #[serde(rename = "credentialSubject")]
    credential_subject: Value,
    #[serde(rename = "credentialStatus")]
    credential_status: Option<Value>,
    #[serde(rename = "credentialSchema", skip_serializing_if = "Option::is_none")]
    credential_schema: Option<Value>,
    #[serde(rename = "refreshService", skip_serializing_if = "Option::is_none")]
    refresh_service: Option<Value>,
    #[serde(rename = "termsOfUse", skip_serializing_if = "Option::is_none")]
    terms_of_use: Option<Value>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    proof: Option<T>,
    #[serde(skip_serializing, skip_deserializing)]
    optional_fields: HashMap<String, Box<Value>>,
}

impl<T: Proof + Serialize + DeserializeOwned> VC<T> {
    pub fn new(
        id: String,
        issuer: Value,
        name: Option<Value>,
        description: Option<Value>,
        valid_until: Option<DateTime<Utc>>,
    ) -> VC<T> {
        let datetime = Utc::now().to_rfc3339();
        let mut vc = VC {
            contexts: Vec::new(),
            types: Vec::new(),
            credential_subject: Value::from("{}"),
            evidence: None,
            id,
            name,
            description,
            issuer,
            valid_from: datetime,
            valid_until: match valid_until {
                Some(val) => Some(val.to_rfc3339()),
                None => None,
            },
            credential_status: None,
            optional_fields: HashMap::new(),
            credential_schema: None,
            proof: None,
            refresh_service: None,
            terms_of_use: None,
        };

        vc.types.push(String::from("VerifiableCredential"));

        vc
    }

    pub fn add_issuer(&mut self, issuer: Value) -> Result<(), Error> {
        if self.issuer.is_array() {
            let arr = match self.issuer.as_array_mut() {
                Some(val) => val,
                None => return Err(Error::new(FIELD_CASTING_ERROR)),
            };

            arr.push(issuer);

            self.issuer = match serde_json::to_value(arr) {
                Ok(val) => val,
                Err(error) => {
                    eprint!("{}", error);
                    return Err(Error::new(FIELD_CASTING_ERROR));
                }
            };
        } else {
            return Err(Error::new(FIELD_CASTING_ERROR));
        }

        return Ok(());
    }

    pub fn set_issuer(&mut self, issuer: Value) {
        self.issuer = issuer;
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

    pub fn set_credential_status(&mut self, credential_status: Option<Value>) {
        self.credential_status = credential_status;
    }

    pub fn set_credential_schemas(&mut self, credential_schema: Option<Value>) {
        self.credential_schema = credential_schema;
    }

    pub fn set_expire(&mut self, expire: Option<String>) {
        self.valid_until = expire;
    }

    pub fn set_terms_of_use(&mut self, terms_of_use: Option<Value>) {
        self.terms_of_use = terms_of_use;
    }

    pub fn set_refresh_service(&mut self, refresh_service: Option<Value>) {
        self.refresh_service = refresh_service;
    }

    pub fn set_evidence(&mut self, evidence: Option<Value>) {
        self.evidence = evidence;
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
            None => return Err(Error::new("message")),
            Some(val) => val,
        };

        proof.verify(doc, signable_values.to_string())
    }

    pub fn to_object(&mut self) -> Result<Value, Error> {
        let mut value = match serde_json::to_value(&self) {
            Err(error) => {
                eprintln!("{}", error);
                return Err(Error::new("Cannot create value object from VC"));
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

        return Ok(val.clone());
    }

    pub fn add_field(&mut self, key: &str, val: Value) {
        self.optional_fields
            .insert(String::from(key), Box::new(val));
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
