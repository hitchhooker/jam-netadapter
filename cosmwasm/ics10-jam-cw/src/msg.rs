//! contract messages

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

use crate::types::{Height, JamClientState, JamConsensusState};

/// instantiate message
#[cw_serde]
pub struct InstantiateMsg {
    pub client_state: JamClientState,
    pub consensus_state: JamConsensusState,
}

/// execute message (not used)
#[cw_serde]
pub enum ExecuteMsg {}

/// sudo messages (called by ibc module)
#[cw_serde]
pub enum SudoMsg {
    /// update client with new header
    UpdateState {
        client_message: Binary,
    },
    /// freeze client on misbehaviour
    UpdateStateOnMisbehaviour {
        client_message: Binary,
    },
    /// verify client upgrade
    VerifyUpgradeAndUpdateState {
        upgrade_client_state: Binary,
        upgrade_consensus_state: Binary,
        proof_upgrade_client: Binary,
        proof_upgrade_consensus: Binary,
    },
    /// verify membership proof
    VerifyMembership {
        height: Height,
        delay_time_period: u64,
        delay_block_period: u64,
        proof: Binary,
        path: Binary,
        value: Binary,
    },
    /// verify non-membership proof
    VerifyNonMembership {
        height: Height,
        delay_time_period: u64,
        delay_block_period: u64,
        proof: Binary,
        path: Binary,
    },
}

/// query messages
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(JamClientState)]
    ClientState {},

    #[returns(JamConsensusState)]
    ConsensusState { height: Height },

    #[returns(String)]
    Status {},

    #[returns(u64)]
    TimestampAtHeight { height: Height },
}
