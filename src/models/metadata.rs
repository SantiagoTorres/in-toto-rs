//! in-toto metadata.
//  Provides a container class `Metablock` for signed metadata and
//  functions for signing, signature verification, de-serialization and
//  serialization from and to JSON.

// use chrono::offset::Utc;
// use chrono::{DateTime, Duration};
use log::{debug, warn};
use serde::de::{Deserialize, DeserializeOwned, Deserializer, Error as DeserializeError};
use serde::ser::Serialize;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display};
use std::marker::PhantomData;
use std::str;

use crate::crypto::{HashValue, KeyId, PrivateKey, PublicKey, Signature};
use crate::error::Error;
use crate::interchange::DataInterchange;
use crate::Result;

use crate::models::safe_path;

pub const FILENAME_FORMAT: &str = "{step_name}.{keyid:.8}.link";

/// Top level trait used for role metadata.
pub trait Metadata: Debug + PartialEq + Serialize + DeserializeOwned {
    /// The version number.
    fn version(&self) -> u32;
}

/// Unverified raw metadata with attached signatures and type information identifying the
/// metadata's type and serialization format.
#[derive(Debug, Clone, PartialEq)]
pub struct RawSignedMetadata<D, M> {
    bytes: Vec<u8>,
    _marker: PhantomData<(D, M)>,
}

impl<D, M> RawSignedMetadata<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new [`RawSignedMetadata`] using the provided `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Access this metadata's inner raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse this metadata.
    pub fn parse(&self) -> Result<Metablock<D, M>> {
        D::from_slice(&self.bytes)
    }
}

/// Helper to construct `Metablock`.
#[derive(Debug, Clone)]
pub struct MetablockBuilder<D, M>
where
    D: DataInterchange,
{
    signatures: HashMap<KeyId, Signature>,
    metadata: D::RawData,
    metadata_bytes: Vec<u8>,
    _marker: PhantomData<M>,
}

impl<D, M> MetablockBuilder<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `MetablockBuilder` from a given `Metadata`.
    pub fn from_metadata(metadata: &M) -> Result<Self> {
        let metadata = D::serialize(metadata)?;
        Self::from_raw_metadata(metadata)
    }

    /// Create a new `MetablockBuilder` from manually serialized metadata to be signed.
    /// Returns an error if `metadata` cannot be parsed into `M`.
    pub fn from_raw_metadata(metadata: D::RawData) -> Result<Self> {
        let _ensure_metadata_parses: M = D::deserialize(&metadata)?;
        let metadata_bytes = D::canonicalize(&metadata)?;
        Ok(Self {
            signatures: HashMap::new(),
            metadata,
            metadata_bytes,
            _marker: PhantomData,
        })
    }

    /// Sign the metadata using the given `private_key`, replacing any existing signatures with the
    /// same `KeyId`.
    ///
    /// **WARNING**: You should never have multiple TUF private keys on the same machine, so if
    /// you're using this to append several signatures at once, you are doing something wrong. The
    /// preferred method is to generate your copy of the metadata locally and use
    /// `Metablock::merge_signatures` to perform the "append" operations.
    pub fn sign(mut self, private_key: &PrivateKey) -> Result<Self> {
        let sig = private_key.sign(&self.metadata_bytes)?;
        let _ = self.signatures.insert(sig.key_id().clone(), sig);
        Ok(self)
    }

    /// Construct a new `Metablock` using the included signatures, sorting the signatures by
    /// `KeyId`.
    pub fn build(self) -> Metablock<D, M> {
        let mut signatures = self
            .signatures
            .into_iter()
            .map(|(_k, v)| v)
            .collect::<Vec<_>>();
        signatures.sort_unstable_by(|a, b| a.key_id().cmp(b.key_id()));

        Metablock {
            signatures,
            metadata: self.metadata,
            _marker: PhantomData,
        }
    }
}

/// Serialized metadata with attached unverified signatures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metablock<D, M>
where
    D: DataInterchange,
{
    signatures: Vec<Signature>,
    #[serde(rename = "signed")]
    metadata: D::RawData,
    #[serde(skip_serializing, skip_deserializing)]
    _marker: PhantomData<M>,
}

impl<D, M> Metablock<D, M>
where
    D: DataInterchange,
    M: Metadata,
{
    /// Create a new `Metablock`. The supplied private key is used to sign the canonicalized
    /// bytes of the provided metadata with the provided scheme.
    ///
    /// ```
    /// # use chrono::prelude::*;
    /// # use in_toto::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use in_toto::interchange::Json;
    /// # use in_toto::models::{Metablock};
    /// #
    /// # fn main() {
    /// # let key: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1.pk8.der");
    /// let key = PrivateKey::from_pkcs8(&key, SignatureScheme::Ed25519).unwrap();
    ///
    /// # }
    /// ```
    pub fn new(metadata: &M, private_key: Option<&PrivateKey>) -> Result<Self> {
        let raw = D::serialize(metadata)?;
        let signatures = match private_key {
            Some(key) => {
                let bytes = D::canonicalize(&raw)?;
                let sig = key.sign(&bytes)?;
                vec![sig]
            }
            None => {
                vec![]
            }
        };

        Ok(Self {
            signatures,
            metadata: raw,
            _marker: PhantomData,
        })
    }

    /// Serialize this metadata to canonical bytes suitable for serialization. Note that this
    /// method is only intended to serialize signed metadata generated by this crate, not to
    /// re-serialize metadata that was originally obtained from a remote source.
    ///
    /// TUF metadata hashes are on the raw bytes of the metadata, so it is not guaranteed that the
    /// hash of the returned bytes will match a hash included in, for example, a snapshot metadata
    /// file, as:
    /// * Parsing metadata removes unknown fields, which would not be included in the returned
    /// bytes,
    /// * DataInterchange implementations only guarantee the bytes are canonical for the purpose of
    /// a signature. Metadata obtained from a remote source may have included different whitespace
    /// or ordered fields in a way that is not preserved when parsing that metadata.
    pub fn to_raw(&self) -> Result<RawSignedMetadata<D, M>> {
        let bytes = D::canonicalize(&D::serialize(self)?)?;
        Ok(RawSignedMetadata::new(bytes))
    }

    /// Merge the singatures from `other` into `self` if and only if
    /// `self.as_ref() == other.as_ref()`. If `self` and `other` contain signatures from the same
    /// key ID, then the signatures from `self` will replace the signatures from `other`.
    pub fn merge_signatures(&mut self, other: &Self) -> Result<()> {
        if self.metadata != other.metadata {
            return Err(Error::IllegalArgument(
                "Attempted to merge unequal metadata".into(),
            ));
        }

        let key_ids = self
            .signatures
            .iter()
            .map(|s| s.key_id().clone())
            .collect::<HashSet<KeyId>>();

        self.signatures.extend(
            other
                .signatures
                .iter()
                .filter(|s| !key_ids.contains(s.key_id()))
                .cloned(),
        );

        Ok(())
    }

    /// An immutable reference to the signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Parse this metadata without verifying signatures.
    ///
    /// This operation is not safe to do with metadata obtained from an untrusted source.
    pub fn assume_valid(&self) -> Result<M> {
        D::deserialize(&self.metadata)
    }

    /// Verify this metadata.
    ///
    /// ```
    /// # use chrono::prelude::*;
    /// # use in_toto::crypto::{PrivateKey, SignatureScheme, HashAlgorithm};
    /// # use in_toto::interchange::Json;
    ///
    /// # fn main() {
    /// let key_1: &[u8] = include_bytes!("../../tests/ed25519/ed25519-1.pk8.der");
    /// let key_1 = PrivateKey::from_pkcs8(&key_1, SignatureScheme::Ed25519).unwrap();
    ///
    /// let key_2: &[u8] = include_bytes!("../../tests/ed25519/ed25519-2.pk8.der");
    /// let key_2 = PrivateKey::from_pkcs8(&key_2, SignatureScheme::Ed25519).unwrap();
    ///
    ///
    /// # }
    pub fn verify<'a, I>(&self, threshold: u32, authorized_keys: I) -> Result<M>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if self.signatures.is_empty() {
            return Err(Error::VerificationFailure(
                "The metadata was not signed with any authorized keys.".into(),
            ));
        }

        if threshold < 1 {
            return Err(Error::VerificationFailure(
                "Threshold must be strictly greater than zero".into(),
            ));
        }

        let authorized_keys = authorized_keys
            .into_iter()
            .map(|k| (k.key_id(), k))
            .collect::<HashMap<&KeyId, &PublicKey>>();

        let canonical_bytes = D::canonicalize(&self.metadata)?;

        let mut signatures_needed = threshold;
        // Create a key_id->signature map to deduplicate the key_ids.
        let signatures = self
            .signatures
            .iter()
            .map(|sig| (sig.key_id(), sig))
            .collect::<HashMap<&KeyId, &Signature>>();
        for (key_id, sig) in signatures {
            match authorized_keys.get(key_id) {
                Some(ref pub_key) => match pub_key.verify(&canonical_bytes, sig) {
                    Ok(()) => {
                        debug!("Good signature from key ID {:?}", pub_key.key_id());
                        signatures_needed -= 1;
                    }
                    Err(e) => {
                        warn!("Bad signature from key ID {:?}: {:?}", pub_key.key_id(), e);
                    }
                },
                None => {
                    warn!(
                        "Key ID {:?} was not found in the set of authorized keys.",
                        sig.key_id()
                    );
                }
            }
            if signatures_needed == 0 {
                break;
            }
        }
        if signatures_needed > 0 {
            return Err(Error::VerificationFailure(format!(
                "Signature threshold not met: {}/{}",
                threshold - signatures_needed,
                threshold
            )));
        }

        // "assume" the metadata is valid because we just verified that it is.
        self.assume_valid()
    }
}
/// Wrapper for a path to metadata.
///
/// Note: This should **not** contain the file extension. This is automatically added by the
/// library depending on what type of data interchange format is being used.
///
/// ```
/// use in_toto::models::MetadataPath;
///
/// // right
/// let _ = MetadataPath::new("root");
///
/// // wrong
/// let _ = MetadataPath::new("root.json");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MetadataPath(String);

impl MetadataPath {
    /// Create a new `MetadataPath` from a `String`.
    ///
    /// ```
    /// # use in_toto::models::MetadataPath;
    /// assert!(MetadataPath::new("foo").is_ok());
    /// assert!(MetadataPath::new("/foo").is_err());
    /// assert!(MetadataPath::new("../foo").is_err());
    /// assert!(MetadataPath::new("foo/..").is_err());
    /// assert!(MetadataPath::new("foo/../bar").is_err());
    /// assert!(MetadataPath::new("..foo").is_ok());
    /// assert!(MetadataPath::new("foo/..bar").is_ok());
    /// assert!(MetadataPath::new("foo/bar..").is_ok());
    /// ```
    pub fn new<P: Into<String>>(path: P) -> Result<Self> {
        let path = path.into();
        safe_path(&path)?;
        Ok(MetadataPath(path))
    }
}

impl Display for MetadataPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MetadataPath {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        MetadataPath::new(s).map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}

/// Wrapper for the real path to a target.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize)]
pub struct TargetPath(String);

impl TargetPath {
    /// Create a new `TargetPath`.
    pub fn new(path: String) -> Result<Self> {
        safe_path(&path)?;
        Ok(TargetPath(path))
    }

    /// Split `TargetPath` into components that can be joined to create URL paths, Unix paths, or
    /// Windows paths.
    ///
    /// ```
    /// # use in_toto::models::TargetPath;
    /// let path = TargetPath::new("foo/bar".into()).unwrap();
    /// assert_eq!(path.components(), ["foo".to_string(), "bar".to_string()]);
    /// ```
    pub fn components(&self) -> Vec<String> {
        self.0.split('/').map(|s| s.to_string()).collect()
    }

    /// The string value of the path.
    pub fn value(&self) -> &str {
        &self.0
    }

    /// Prefix the target path with a hash value to support TUF spec 5.5.2.
    pub fn with_hash_prefix(&self, hash: &HashValue) -> Result<TargetPath> {
        let mut components = self.components();

        // The unwrap here is safe because we checked in `safe_path` that the path is not empty.
        let file_name = components.pop().unwrap();

        components.push(format!("{}.{}", hash, file_name));

        TargetPath::new(components.join("/"))
    }
}
