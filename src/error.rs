use core::fmt::Display;

pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: &str) -> Error {
        return Error {
            message: String::from(message),
        };
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = f.write_str(self.message.as_str());
        return Ok(());
    }
}
