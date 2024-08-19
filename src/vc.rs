use std::{
    any::Any,
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
};

use chrono::{DateTime, Utc};
use fi_digital_signatures::algorithms::Algorithm;
use js_sys::{Array, Object};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use wasm_bindgen_struct::wasm_bindgen_struct;

use crate::{
    constants::FIELD_CASTING_ERROR,
    document::VerificationDocument,
    error::Error,
    proof::{Proof, ProofType},
};

#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct VC {
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
    proof: Option<ProofType>,
    #[serde(skip_serializing, skip_deserializing)]
    optional_fields: HashMap<String, Box<Value>>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct VC(HashMap<String, Box<JsValue>>);

#[cfg(not(feature = "wasm"))]
impl VC {
    pub fn new(
        id: String,
        issuer: Value,
        name: Option<Value>,
        description: Option<Value>,
        valid_until: Option<DateTime<Utc>>,
    ) -> VC {
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

    pub fn get_proof(&self) -> &Option<ProofType> {
        self.proof.borrow()
    }

    pub fn get_proof_mut(&mut self) -> &mut Option<ProofType> {
        self.proof.borrow_mut()
    }

    pub fn sign(&mut self, doc: VerificationDocument, mut proof: ProofType) -> Result<(), Error> {
        let signable_values = match self.get_signable_content() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        match proof.sign(doc, signable_values.to_string()) {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        self.proof = Some(proof);
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

        return Ok(val);
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl VC {
    pub fn new(
        id: String,
        issuer: JsValue,
        name: JsValue,
        description: JsValue,
        valid_until: JsValue,
        contexts: Vec<String>,
    ) -> VC {
        let datetime = Utc::now().to_rfc3339();
        let mut vc: HashMap<String, Box<JsValue>> = HashMap::new();

        let types: Vec<JsValue> = Vec::new();
        types.push(JsValue::from_str("VerifiableCredential"));

        vc["type"] = Box::new(JsValue::from(types));
        vc["@context"] = Box::new(JsValue::from_str("{}"));
        vc["credentialSubject"] = Box::new(JsValue::from_str("{}"));
        vc["evidence"] = Box::new(JsValue::from_str("{}"));
        vc["id"] = Box::new(JsValue::from_str("{}"));
        vc["name"] = Box::new(JsValue::from_str("{}"));
        vc["description"] = Box::new(JsValue::from_str("{}"));
        vc["issuer"] = Box::new(JsValue::from_str("{}"));
        vc["validFrom"] = Box::new(JsValue::from_str("{}"));
        vc["validUntil"] = Box::new(valid_until);
        vc["credentialStatus"] = Box::new(JsValue::from_str("{}"));
        vc["credentialSchema"] = Box::new(JsValue::from_str("{}"));
        vc["proof"] = Box::new(JsValue::from_str("{}"));
        vc["termsOfUse"] = Box::new(JsValue::from_str("{}"));
        vc["refreshService"] = Box::new(JsValue::from_str("{}"));

        VC(vc)
    }

    #[wasm_bindgen(js_name = "addIsser")]
    pub fn add_issuer(&mut self, issuer: JsValue) -> Result<(), Error> {
        if self.0["issuer"].is_array() {
            let arr: Array = js_sys::Array::from(&*self.0["issuer"]);

            arr.push(&issuer.clone());

            self.0["issuer"] = Box::new(JsValue::from(arr));
        } else {
            let arr = js_sys::Array::new();
            arr.push(&self.0["issuer"].to_owned());
            arr.push(&issuer.clone());

            self.0["issuer"] = Box::new(JsValue::from(arr));
        }

        return Ok(());
    }

    #[wasm_bindgen(js_name = "setIsser")]
    pub fn set_issuer(&mut self, issuer: JsValue) {
        self.0["issuer"] = Box::new(issuer);
    }

    #[wasm_bindgen(js_name = "setContext")]
    pub fn set_context(&mut self, contexts: JsValue) {
        self.0["@context"] = Box::new(contexts);
    }

    #[wasm_bindgen(js_name = "addContext")]
    pub fn add_context(&mut self, context: JsValue) -> Result<(), Error> {
        if self.0["@context"].is_array() {
            let arr: Array = js_sys::Array::from(&*self.0["@context"]);

            arr.push(&context.clone());

            self.0["@context"] = Box::new(JsValue::from(arr));
        } else {
            let arr = js_sys::Array::new();
            arr.push(&self.0["@context"].to_owned());
            arr.push(&context.clone());

            self.0["@context"] = Box::new(JsValue::from(arr));
        }

        return Ok(());
    }

    #[wasm_bindgen(js_name = "addType")]
    pub fn add_type(&mut self, _type: JsValue) -> Result<(), Error> {
        if self.0["type"].is_array() {
            let arr: Array = js_sys::Array::from(&*self.0["type"]);

            arr.push(&_type.clone());

            self.0["type"] = Box::new(JsValue::from(arr));
        } else {
            let arr = js_sys::Array::new();
            arr.push(&self.0["type"].to_owned());
            arr.push(&_type.clone());

            self.0["type"] = Box::new(JsValue::from(arr));
        }

        return Ok(());
    }

    #[wasm_bindgen(js_name = "setType")]
    pub fn set_type(&mut self, _type: JsValue) {
        self.0["type"] = Box::new(_type);
    }

    #[wasm_bindgen(js_name = "setCredentialStatus")]
    pub fn set_credential_status(&mut self, credential_status: JsValue) {
        self.0["credentialStatus"] = Box::new(credential_status);
    }

    #[wasm_bindgen(js_name = "setCredentialSchemas")]
    pub fn set_credential_schemas(&mut self, credential_schema: JsValue) {
        self.0["credentialSchema"] = Box::new(credential_schema);
    }

    #[wasm_bindgen(js_name = "setExpire")]
    pub fn set_expire(&mut self, expire: JsValue) {
        self.0["expire"] = Box::new(expire);
    }

    #[wasm_bindgen(js_name = "setTermsOfUse")]
    pub fn set_terms_of_use(&mut self, terms_of_use: JsValue) {
        self.0["termsOfUse"] = Box::new(terms_of_use);
    }

    #[wasm_bindgen(js_name = "setRefreshService")]
    pub fn set_refresh_service(&mut self, refresh_service: JsValue) {
        self.0["refreshService"] = Box::new(refresh_service);
    }

    #[wasm_bindgen(js_name = "setEvidence")]
    pub fn set_evidence(&mut self, evidence: JsValue) {
        self.0["issuer"] = Box::new(evidence);
    }

    #[wasm_bindgen(js_name = "getProof")]
    pub fn get_proof(&self) -> JsValue {
        *self.0["proof"]
    }

    #[wasm_bindgen]
    pub fn sign(
        &mut self,
        alg: Algorithm,
        purpose: String,
        doc: VerificationDocument,
        proof_type: ProofType,
    ) -> Result<(), Error> {
        let signable_values = match self.get_signable_content() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        let proof = match proof_type.sign(alg, purpose, doc, signable_values.to_string()) {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        self.0["proof"] = Box::new(proof);
        return Ok(());
    }

    #[wasm_bindgen]
    pub fn verify(
        &mut self,
        doc: VerificationDocument,
        proof_type: ProofType,
    ) -> Result<bool, Error> {
        let signable_values = match self.get_signable_content() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        proof_type.verify(doc, signable_values.to_string(), *self.0["proof"])
    }

    #[wasm_bindgen(js_name = "toObject")]
    pub fn to_object(&mut self) -> Result<Object, Error> {
        let mut value = js_sys::Object::new();
        self.0.iter().for_each(|(key, val)| {
            js_sys::Reflect::set(&value, &JsValue::from_str(key), val);
        });

        return Ok(value);
    }

    #[wasm_bindgen(js_name = "getSignableContent")]
    pub fn get_signable_content(&mut self) -> Result<String, Error> {
        let mut val = match self.to_object() {
            Err(error) => {
                return Err(error);
            }
            Ok(val) => val,
        };

        js_sys::Reflect::delete_property(&val, &JsValue::from_str("proof"));

        return Ok(val.to_string().into());
    }

    #[wasm_bindgen(js_name = "addField")]
    pub fn add_field(&mut self, key: &str, val: JsValue) {
        self.0[key] = Box::new(val);
    }

    #[wasm_bindgen]
    pub fn from(value: JsValue) -> Result<VC, Error> {
        let mut map: HashMap<String, Box<JsValue>> = HashMap::new();

        let keys = match js_sys::Reflect::own_keys(&value) {
            Ok(val) => val,
            Err(error) => return Err(Error::new(error.as_string().unwrap().as_str())),
        };

        let mut new_value: HashMap<String, Box<JsValue>> = HashMap::new();
        keys.iter().for_each(|key| {
            let val = match js_sys::Reflect::get(&value, &key) {
                Err(error) => {
                    eprintln!("{}", error.as_string().unwrap());
                    return;
                }
                Ok(_val) => _val,
            };

            new_value.insert(key.as_string().unwrap(), Box::new(val));
        });

        Ok(VC(new_value))
    }
}
