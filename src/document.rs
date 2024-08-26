use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::JsValue;

use crate::error::FiError;

pub trait DocResolver {
    fn resolve(&self, url: &str) -> Option<VerificationDocument>;
}

#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct VerificationDocument {
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    id: String,
}

impl VerificationDocument {
    pub fn new(
        id: String,
        private_key: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> VerificationDocument {
        return VerificationDocument {
            id,
            private_key,
            public_key,
        };
    }

    pub fn get_private_key(&self) -> &Option<Vec<u8>> {
        self.private_key.borrow()
    }

    pub fn get_public_key(&self) -> &Option<Vec<u8>> {
        self.public_key.borrow()
    }

    pub fn get_id(&self) -> &String {
        self.id.borrow()
    }

    pub fn get_private_key_mut(&mut self) -> &mut Option<Vec<u8>> {
        self.private_key.borrow_mut()
    }

    pub fn get_public_key_mut(&mut self) -> &mut Option<Vec<u8>> {
        self.public_key.borrow_mut()
    }

    pub fn get_id_mut(&mut self) -> &mut String {
        self.id.borrow_mut()
    }
}

#[wasm_bindgen]
pub struct DocumentLoader {
    docs: HashMap<String, VerificationDocument>,
    doc_resolvers: Vec<Box<dyn DocResolver>>,
}

#[cfg(not(feature = "wasm"))]
impl DocumentLoader {
    pub fn new(docs: Option<HashMap<String, VerificationDocument>>) -> Result<Self, FiError> {
        return Ok(DocumentLoader {
            doc_resolvers: Vec::new(),
            docs: match docs {
                Some(val) => val,
                None => HashMap::new(),
            },
        });
    }

    pub fn get_verification_document(&mut self, url: &str) -> Option<VerificationDocument> {
        get_verification_document(self, url)
    }
}

fn get_verification_document(doc: &mut DocumentLoader, url: &str) -> Option<VerificationDocument> {
    if doc.docs.contains_key(url) {
        let val: VerificationDocument = match doc.docs.get_key_value(url) {
            None => return None,
            Some((_url, _doc)) => _doc.clone(),
        };
        return Some(val);
    }

    let itr = doc.doc_resolvers.iter();
    for resolver in itr {
        let value = resolver.resolve(url);
        if value.is_some() {
            let val = value.clone().unwrap();
            doc.docs.insert(String::from(url), val);
            return Some(value.unwrap());
        }
    }

    return None;
}

#[wasm_bindgen]
#[cfg(feature = "wasm")]
impl DocumentLoader {
    #[wasm_bindgen(constructor)]
    pub fn new(docs: JsValue) -> Result<DocumentLoader, FiError> {
        let mut values: Option<HashMap<String, VerificationDocument>> = None;

        if docs.is_null() || docs.is_undefined() {
            values = match serde_wasm_bindgen::from_value(docs) {
                Ok(val) => val,
                Err(error) => return Err(FiError::new(error.to_string().as_str())),
            };
        }

        return Ok(DocumentLoader {
            doc_resolvers: Vec::new(),
            docs: match values {
                Some(val) => val,
                None => HashMap::new(),
            },
        });
    }

    #[wasm_bindgen(js_name = "getVerificationDocument")]
    pub fn get_verification_document(&mut self, url: &str) -> Option<VerificationDocument> {
        get_verification_document(self, url)
    }
}
