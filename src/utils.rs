use url::Url;

use crate::Error;

pub trait IntoUrl {
    fn into_url(self) -> Result<Url, Error>;
}

impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self.clone())
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, Error> {
        Ok(Url::parse(self)?)
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> Result<Url, Error> {
        Ok(Url::parse(self)?)
    }
}
