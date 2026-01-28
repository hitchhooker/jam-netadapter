//! contract errors

use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("client is frozen")]
    ClientFrozen,

    #[error("client expired")]
    ClientExpired,

    #[error("invalid proof")]
    InvalidProof,

    #[error("invalid header")]
    InvalidHeader,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("insufficient voting power")]
    InsufficientVotingPower,

    #[error("consensus state not found")]
    ConsensusStateNotFound,

    #[error("height too old")]
    HeightTooOld,

    #[error("not implemented")]
    NotImplemented,
}
