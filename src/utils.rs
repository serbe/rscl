use url::Url;

use crate::Error;

pub trait IntoUrl {
    fn into_url(self) -> Result<Url, Error>;
}

impl<'a> IntoUrl for &'a Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self.clone())
    }
}

impl<'a> IntoUrl for &'a str {
    fn into_url(self) -> Result<Url, Error> {
        Ok(Url::parse(self)?)
    }
}

impl<'a> IntoUrl for &'a String {
    fn into_url(self) -> Result<Url, Error> {
        Ok(Url::parse(self)?)
    }
}
