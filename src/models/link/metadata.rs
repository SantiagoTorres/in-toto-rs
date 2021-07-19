//! in-toto link metadata.

use serde::de::{Deserialize, Deserializer, Error as DeserializeError};
use serde::ser::{Error as SerializeError, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;

use crate::crypto::{self, PrivateKey};
use crate::interchange::DataInterchange;
use crate::Result;

use crate::models::{Link, Metablock, Metadata, TargetDescription, VirtualTargetPath};

/// Helper to construct `LinkMetadata`.
pub struct LinkMetadataBuilder {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,
}

impl LinkMetadataBuilder {
    // This should definitely be improved
    pub fn new() -> Self {
        LinkMetadataBuilder {
            name: String::new(),
            materials: BTreeMap::new(),
            products: BTreeMap::new(),
            env: BTreeMap::new(),
            byproducts: BTreeMap::new(),
        }
    }

    /// Set the name number for this link
    pub fn name(mut self, name: String) -> Self {
        self.name = name;
        self
    }

    /// Set the materials for this metadata
    pub fn materials(mut self, materials: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.materials = materials;
        self
    }

    /// Set the products for this metadata
    pub fn products(mut self, products: BTreeMap<VirtualTargetPath, TargetDescription>) -> Self {
        self.products = products;
        self
    }

    pub fn add_material(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) =
            crypto::calculate_hashes(&mut reader, &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.materials.insert(material_path, hashes);
        self
    }

    pub fn add_product(mut self, material_path: VirtualTargetPath) -> Self {
        let file = File::open(material_path.to_string()).unwrap();
        let mut reader = BufReader::new(file);
        let (_length, hashes) =
            crypto::calculate_hashes(&mut reader, &[crypto::HashAlgorithm::Sha256]).unwrap();
        self.products.insert(material_path, hashes);
        self
    }

    /// Set the products for this metadata
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set the products for this metadata
    pub fn byproducts(mut self, byproducts: BTreeMap<String, String>) -> Self {
        self.byproducts = byproducts;
        self
    }

    pub fn build(self) -> Result<LinkMetadata> {
        LinkMetadata::new(
            self.name,
            self.materials,
            self.products,
            self.env,
            self.byproducts,
        )
    }

    /// Construct a new `Metablock<D, LinkMetadata>`.
    pub fn signed<D>(self, private_key: &PrivateKey) -> Result<Metablock<D, LinkMetadata>>
    where
        D: DataInterchange,
    {
        Metablock::new(&self.build()?, Some(private_key))
    }

    /// Construct a new `Metablock<D, LinkMetadata>`.
    pub fn unsigned<D>(self) -> Result<Metablock<D, LinkMetadata>>
    where
        D: DataInterchange,
    {
        Metablock::new(&self.build()?, None)
    }
}

/// link metadata
#[derive(Debug, Clone, PartialEq)]
pub struct LinkMetadata {
    name: String,
    materials: BTreeMap<VirtualTargetPath, TargetDescription>,
    products: BTreeMap<VirtualTargetPath, TargetDescription>,
    env: BTreeMap<String, String>,
    byproducts: BTreeMap<String, String>,
}

impl LinkMetadata {
    /// Create new `LinkMetadata`.
    pub fn new(
        name: String,
        materials: BTreeMap<VirtualTargetPath, TargetDescription>,
        products: BTreeMap<VirtualTargetPath, TargetDescription>,
        env: BTreeMap<String, String>,
        byproducts: BTreeMap<String, String>,
    ) -> Result<Self> {
        Ok(LinkMetadata {
            name,
            materials,
            products,
            env,
            byproducts,
        })
    }

    // The step this link is associated to
    pub fn name(&self) -> &String {
        &self.name
    }

    // The materials used as inputs
    pub fn materials(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.materials
    }

    // The products used as inputs
    pub fn products(&self) -> &BTreeMap<VirtualTargetPath, TargetDescription> {
        &self.products
    }

    // The Environment where things were built
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    // The Environment where things were built
    pub fn byproducts(&self) -> &BTreeMap<String, String> {
        &self.byproducts
    }
}

impl Metadata for LinkMetadata {
    fn version(&self) -> u32 {
        0u32
    }
}

impl Serialize for LinkMetadata {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Link::from(self)
            .map_err(|e| SerializeError::custom(format!("{:?}", e)))?
            .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for LinkMetadata {
    fn deserialize<D: Deserializer<'de>>(de: D) -> ::std::result::Result<Self, D::Error> {
        let intermediate: Link = Deserialize::deserialize(de)?;
        intermediate
            .try_into()
            .map_err(|e| DeserializeError::custom(format!("{:?}", e)))
    }
}
