//! This crate provides an API for talking to repositories that implements in-toto

//#![deny(missing_docs)]
#![allow(
    clippy::collapsible_if,
    clippy::implicit_hasher,
    clippy::new_ret_no_self,
    clippy::op_ref,
    clippy::too_many_arguments
)]

pub mod crypto;
pub mod error;
pub mod interchange;
pub mod models;
pub mod runlib;
pub mod verifylib;

mod format_hex;

pub use crate::error::*;

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
