use thiserror::Error;

#[derive(Debug, Error)]
pub enum PpxError {
    #[error("XML parse error: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("XML attribute error: {0}")]
    XmlAttr(#[from] quick_xml::events::attributes::AttrError),

    #[error("XML encoding error: {0}")]
    XmlEncoding(#[from] quick_xml::encoding::EncodingError),

    #[error("XML escape error: {0}")]
    XmlEscape(#[from] quick_xml::escape::EscapeError),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("invalid integer value for `{field}`: {source}")]
    InvalidInt {
        field: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("invalid boolean value for `{field}`: got `{value}`")]
    InvalidBool { field: &'static str, value: String },

    #[error("missing required element `{0}`")]
    MissingElement(&'static str),

    #[error("missing required attribute `{attr}` on element `{elem}`")]
    MissingAttribute { elem: &'static str, attr: &'static str },

    #[error("unknown action type: `{0}`")]
    UnknownAction(String),

    #[error("unknown proxy type: `{0}`")]
    UnknownProxyType(String),

    #[error("unexpected element `{0}` in context `{1}`")]
    UnexpectedElement(String, &'static str),

    #[error("{0}")]
    Custom(String),
}

pub type PpxResult<T> = Result<T, PpxError>;
