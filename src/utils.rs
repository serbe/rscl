use crate::{Error, Result};

use percent_encoding::percent_decode_str;
use url::Url;

pub(crate) fn decode(v: &str) -> Option<String> {
    percent_decode_str(v)
        .decode_utf8()
        .map_or(None, |op| Some(op.to_string()))
}

pub(crate) fn parse_url(str: &str) -> Result<Url> {
    let url = Url::parse(str)?;
    if url.has_host() {
        Ok(url)
    } else {
        Err(Error::NoHost)
    }
}
