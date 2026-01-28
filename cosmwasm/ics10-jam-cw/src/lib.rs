//! ics-10 jam light client for cosmwasm (08-wasm deployment)
//!
//! this contract implements the ibc light client interface for verifying
//! jam chain state on cosmos chains via the 08-wasm client type.
//!
//! follows composable's pattern for ics10-grandpa-cw.

pub mod contract;
pub mod error;
pub mod msg;
pub mod state;
pub mod types;
pub mod verify;

pub use contract::*;
pub use error::*;
pub use msg::*;
