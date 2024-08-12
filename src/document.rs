use std::collections::HashMap;

pub trait DocResolver {
    fn resolve(&self, url: &str) -> Option<VerificationDocument>;
}

#[derive(Clone)]
pub struct VerificationDocument {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub id: String,
}

pub struct DocumentLoader {
    docs: HashMap<String, VerificationDocument>,
    doc_resolvers: Vec<Box<dyn DocResolver>>,
}

impl DocumentLoader {
    pub fn new(docs: Option<HashMap<String, VerificationDocument>>) -> Self {
        return DocumentLoader {
            doc_resolvers: Vec::new(),
            docs: match docs {
                Some(val) => val,
                None => HashMap::new(),
            },
        };
    }

    pub fn get_verification_document(&mut self, url: &str) -> Option<VerificationDocument> {
        if self.docs.contains_key(url) {
            let val: VerificationDocument = match self.docs.get_key_value(url) {
                None => return None,
                Some((_url, _doc)) => _doc.clone(),
            };
            return Some(val);
        }

        let itr = self.doc_resolvers.iter();
        for resolver in itr {
            let value = resolver.resolve(url);
            if value.is_some() {
                let val = value.clone().unwrap();
                self.docs.insert(String::from(url), val);
                return Some(value.unwrap());
            }
        }

        return None;
    }
}
