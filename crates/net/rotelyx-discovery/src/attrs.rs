//! Errors for endpoint address parsing.
//!
//! **Rotelyx modification.** This module used to hold the DNS TXT record
//! machinery: the `_iroh` record name and the parser that pulled an endpoint id
//! out of a name like `_iroh.<z32-endpoint-id>.<origin-domain>`. That is how
//! iroh publishes an identity's address to a DNS zone or the Mainline DHT so
//! that strangers can look it up, and it is the one thing Rotelyx exists not to
//! do: a message being encrypted is worth little if `identity X is at address
//! Y` sits in a public directory anybody can query.
//!
//! It was already unreachable, and now it is absent. What remains is the two
//! error types, which the transport still uses for addresses that arrive out of
//! band.

use rotelyx_error::stack_error;


/// Errors encoding endpoint attributes.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum EncodingError {
    #[error("attribute encoding failed")]
    Failed {},
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ParseError {
    #[error("Expected format `key=value`, received `{s}`")]
    UnexpectedFormat { s: String },
    #[error("Could not convert key to Attr")]
    AttrFromString { key: String },
    #[error("Expected 2 labels, received {num_labels}")]
    NumLabels { num_labels: usize },
    #[error("Could not parse labels")]
    Utf8 {
        #[error(std_err)]
        source: std::str::Utf8Error,
    },
    #[error("Record is not an `iroh` record, expected `_iroh`, got `{label}`")]
    NotAnIrohRecord { label: String },
    #[error(transparent)]
    DecodingError { source: rotelyx_transport_base::KeyParsingError },
}
