use core::fmt::Display;

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Debug)]
pub struct FiError {
    message: String,
}

#[wasm_bindgen]
impl FiError {
    #[wasm_bindgen(constructor)]
    pub fn new(message: &str) -> FiError {
        return FiError {
            message: String::from(message),
        };
    }
}

impl Display for FiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = f.write_str(self.message.as_str());
        return Ok(());
    }
}
