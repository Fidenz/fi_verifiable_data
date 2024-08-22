use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
};

#[cfg(feature = "wasm")]
use fi_digital_signatures::algorithms::Algorithm;
#[cfg(feature = "wasm")]
use js_sys::{Array, Object};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;
#[cfg(feature = "wasm")]
use wasm_bindgen::JsValue;

use crate::{document::VerificationDocument, error::Error, proof::ProofType, vc::VC};

#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize)]
pub struct VP {
    #[serde(rename = "@context")]
    contexts: Vec<Value>,
    holder: Option<String>,
    id: String,
    #[serde(rename = "type")]
    types: Vec<String>,
    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    proof: Option<ProofType>,
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<VC>,
    #[serde(skip_serializing, skip_deserializing)]
    optional_fields: HashMap<String, Box<Value>>,
}

#[wasm_bindgen]
#[cfg(feature = "wasm")]
pub struct VP(HashMap<String, Box<JsValue>>);

#[cfg(not(feature = "wasm"))]
impl VP {
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

    pub fn add_verifiable_credentials(&mut self, verifiable_credential: VC) {
        self.verifiable_credential.push(verifiable_credential);
    }

    pub fn set_verifiable_credentials(&mut self, verifiable_credentials: Vec<VC>) {
        self.verifiable_credential = verifiable_credentials;
    }

    pub fn set_types(&mut self, types: Vec<String>) {
        self.types = types;
    }

    pub fn get_proof(&self) -> &Option<ProofType> {
        self.proof.borrow()
    }

    pub fn get_proof_mut(&mut self) -> &mut Option<ProofType> {
        self.proof.borrow_mut()
    }

    pub fn sign(
        &mut self,
        doc: &mut VerificationDocument,
        mut proof: ProofType,
    ) -> Result<(), Error> {
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

    pub fn verify(&mut self, doc: &mut VerificationDocument) -> Result<bool, Error> {
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

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl VP {
    #[wasm_bindgen(constructor)]
    pub fn new(id: String, holder: JsValue) -> Self {
        let mut vp: HashMap<String, Box<JsValue>> = HashMap::new();

        let mut types: Vec<JsValue> = Vec::new();
        types.push(JsValue::from_str("VerifiablePresentation"));

        vp.insert(String::from("type"), Box::new(JsValue::from(types)));
        vp.insert(String::from("@context"), Box::new(JsValue::from_str("[]")));
        vp.insert(
            String::from("verifiableCredential"),
            Box::new(JsValue::from_str("[]")),
        );
        vp.insert(String::from("holder"), Box::new(holder));
        vp.insert(String::from("id"), Box::new(JsValue::from_str(id.as_str())));
        vp.insert(String::from("proof"), Box::new(JsValue::null()));

        VP(vp)
    }

    #[wasm_bindgen(js_name = "setHolder")]
    pub fn set_holder(&mut self, holder: JsValue) {
        self.0.insert(String::from("holder"), Box::new(holder));
    }

    #[wasm_bindgen(js_name = "setContext")]
    pub fn set_context(&mut self, contexts: JsValue) {
        self.0.insert(String::from("@context"), Box::new(contexts));
    }

    #[wasm_bindgen(js_name = "addContext")]
    pub fn add_context(&mut self, context: JsValue) -> Result<(), Error> {
        if self.0["@context"].is_array() {
            let arr: Array = js_sys::Array::from(&*self.0["@context"]);

            arr.push(&context.clone());

            self.0
                .insert(String::from("@context"), Box::new(JsValue::from(arr)));
        } else {
            let arr = js_sys::Array::new();
            arr.push(&self.0["@context"].to_owned());
            arr.push(&context.clone());

            self.0
                .insert(String::from("@context"), Box::new(JsValue::from(arr)));
        }

        return Ok(());
    }

    #[wasm_bindgen(js_name = "addType")]
    pub fn add_type(&mut self, _type: JsValue) -> Result<(), Error> {
        if self.0["type"].is_array() {
            let arr: Array = js_sys::Array::from(&*self.0["type"]);

            arr.push(&_type.clone());

            self.0
                .insert(String::from("type"), Box::new(JsValue::from(arr)));
        } else {
            let arr = js_sys::Array::new();
            arr.push(&self.0["type"].to_owned());
            arr.push(&_type.clone());

            self.0
                .insert(String::from("type"), Box::new(JsValue::from(arr)));
        }

        return Ok(());
    }

    #[wasm_bindgen(js_name = "setType")]
    pub fn set_type(&mut self, _type: JsValue) {
        self.0.insert(String::from("type"), Box::new(_type));
    }

    #[wasm_bindgen(js_name = "getProof")]
    pub fn get_proof(&self) -> JsValue {
        *self.0["proof"].clone()
    }

    #[wasm_bindgen(js_name = "addVerifiableCredential")]
    pub fn add_verifiable_credentials(&mut self, verifiable_credential: VC) {
        let arr: Array = js_sys::Array::from(&*self.0["verifiableCredential"]);

        arr.push(&verifiable_credential.clone());

        self.0.insert(
            String::from("verifiableCredential"),
            Box::new(JsValue::from(arr)),
        );
    }

    #[wasm_bindgen(js_name = "setVerifiableCredential")]
    pub fn set_verifiable_credentials(&mut self, verifiable_credentials: Vec<VC>) {
        self.0.insert(
            String::from("verifiableCredential"),
            Box::new(verifiable_credentials),
        );
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

        self.0.insert(String::from("proof"), Box::new(proof));
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

        proof_type.verify(doc, signable_values.to_string(), *self.0["proof"].clone())
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
        self.0.insert(String::from(key), Box::new(val));
    }

    #[wasm_bindgen]
    pub fn from(value: JsValue) -> Result<VP, Error> {
        let map: HashMap<String, Box<JsValue>> = HashMap::new();

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

        Ok(VP(new_value))
    }
}
