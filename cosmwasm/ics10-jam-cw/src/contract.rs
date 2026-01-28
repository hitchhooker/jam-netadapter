//! cosmwasm contract entry points

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, SudoMsg};
use crate::state::{CLIENT_STATE, CONSENSUS_STATES};
use crate::types::{Height, JamConsensusState};
use crate::verify;

/// contract instantiation
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // validate and store initial client state
    let client_state = msg.client_state;
    let consensus_state = msg.consensus_state;

    if client_state.is_frozen() {
        return Err(ContractError::ClientFrozen);
    }

    CLIENT_STATE.save(deps.storage, &client_state)?;

    let height = Height {
        revision_number: 0,
        revision_height: consensus_state.slot as u64,
    };
    CONSENSUS_STATES.save(deps.storage, height.to_key(), &consensus_state)?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("client_type", "10-jam"))
}

/// contract execution (not used for light clients)
#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    Err(ContractError::NotImplemented)
}

/// sudo entry point for ibc module calls
#[entry_point]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::UpdateState { client_message } => {
            sudo_update_state(deps, env, client_message)
        }
        SudoMsg::UpdateStateOnMisbehaviour { client_message } => {
            sudo_update_state_on_misbehaviour(deps, env, client_message)
        }
        SudoMsg::VerifyUpgradeAndUpdateState {
            upgrade_client_state,
            upgrade_consensus_state,
            proof_upgrade_client,
            proof_upgrade_consensus,
        } => sudo_verify_upgrade(
            deps,
            upgrade_client_state,
            upgrade_consensus_state,
            proof_upgrade_client,
            proof_upgrade_consensus,
        ),
        SudoMsg::VerifyMembership {
            height,
            delay_time_period,
            delay_block_period,
            proof,
            path,
            value,
        } => sudo_verify_membership(
            deps,
            height,
            delay_time_period,
            delay_block_period,
            proof,
            path,
            value,
        ),
        SudoMsg::VerifyNonMembership {
            height,
            delay_time_period,
            delay_block_period,
            proof,
            path,
        } => sudo_verify_non_membership(
            deps,
            height,
            delay_time_period,
            delay_block_period,
            proof,
            path,
        ),
    }
}

/// update client state with new header
fn sudo_update_state(
    deps: DepsMut,
    _env: Env,
    client_message: Binary,
) -> Result<Response, ContractError> {
    let header_with_proof: crate::types::JamHeaderWithProof =
        cosmwasm_std::from_json(&client_message)?;

    let client_state = CLIENT_STATE.load(deps.storage)?;

    // get trusted consensus state
    let _trusted_height = Height {
        revision_number: 0,
        revision_height: header_with_proof.header.timeslot as u64 - 1, // TODO: get from ancestry
    };

    // find most recent consensus state
    let trusted_consensus = find_trusted_consensus(deps.as_ref(), &header_with_proof)?;

    // verify header
    let result = verify::verify_jam_header(&client_state, &trusted_consensus, &header_with_proof)?;

    // save new client state if updated
    if let Some(new_client_state) = result.new_client_state {
        CLIENT_STATE.save(deps.storage, &new_client_state)?;
    }

    // save new consensus state
    let new_height = Height {
        revision_number: 0,
        revision_height: result.new_consensus_state.slot as u64,
    };
    CONSENSUS_STATES.save(deps.storage, new_height.to_key(), &result.new_consensus_state)?;

    Ok(Response::new()
        .add_attribute("action", "update_state")
        .add_attribute("height", new_height.revision_height.to_string()))
}

/// freeze client on misbehaviour
fn sudo_update_state_on_misbehaviour(
    deps: DepsMut,
    _env: Env,
    client_message: Binary,
) -> Result<Response, ContractError> {
    let misbehaviour: crate::types::JamMisbehavior =
        cosmwasm_std::from_json(&client_message)?;

    let mut client_state = CLIENT_STATE.load(deps.storage)?;

    // verify misbehaviour
    let freeze_slot = verify::check_misbehavior(&client_state, &misbehaviour)?;

    // freeze client
    client_state.freeze(freeze_slot);
    CLIENT_STATE.save(deps.storage, &client_state)?;

    Ok(Response::new()
        .add_attribute("action", "misbehaviour")
        .add_attribute("frozen_slot", freeze_slot.to_string()))
}

/// verify client upgrade (not yet implemented)
fn sudo_verify_upgrade(
    _deps: DepsMut,
    _upgrade_client_state: Binary,
    _upgrade_consensus_state: Binary,
    _proof_upgrade_client: Binary,
    _proof_upgrade_consensus: Binary,
) -> Result<Response, ContractError> {
    Err(ContractError::NotImplemented)
}

/// verify membership proof
fn sudo_verify_membership(
    deps: DepsMut,
    height: Height,
    _delay_time_period: u64,
    _delay_block_period: u64,
    proof: Binary,
    path: Binary,
    value: Binary,
) -> Result<Response, ContractError> {
    let client_state = CLIENT_STATE.load(deps.storage)?;

    if client_state.is_frozen() {
        return Err(ContractError::ClientFrozen);
    }

    let consensus_state = CONSENSUS_STATES.load(deps.storage, height.to_key())?;

    let state_proof: crate::types::JamStateProof = cosmwasm_std::from_json(&proof)?;

    // verify key matches path
    if state_proof.key != path.to_vec() {
        return Err(ContractError::InvalidProof);
    }

    // verify value matches
    if state_proof.value != value.to_vec() {
        return Err(ContractError::InvalidProof);
    }

    // verify merkle proof
    verify::verify_jam_state_proof(&state_proof, &consensus_state.state_root)?;

    Ok(Response::new().add_attribute("action", "verify_membership"))
}

/// verify non-membership proof
fn sudo_verify_non_membership(
    deps: DepsMut,
    height: Height,
    _delay_time_period: u64,
    _delay_block_period: u64,
    proof: Binary,
    path: Binary,
) -> Result<Response, ContractError> {
    let client_state = CLIENT_STATE.load(deps.storage)?;

    if client_state.is_frozen() {
        return Err(ContractError::ClientFrozen);
    }

    let consensus_state = CONSENSUS_STATES.load(deps.storage, height.to_key())?;

    let state_proof: crate::types::JamStateProof = cosmwasm_std::from_json(&proof)?;

    // verify key matches path
    if state_proof.key != path.to_vec() {
        return Err(ContractError::InvalidProof);
    }

    // for non-membership, value should be empty
    if !state_proof.value.is_empty() {
        return Err(ContractError::InvalidProof);
    }

    // verify merkle proof
    verify::verify_jam_state_proof(&state_proof, &consensus_state.state_root)?;

    Ok(Response::new().add_attribute("action", "verify_non_membership"))
}

/// query entry point
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ClientState {} => {
            let state = CLIENT_STATE.load(deps.storage)?;
            to_json_binary(&state)
        }
        QueryMsg::ConsensusState { height } => {
            let state = CONSENSUS_STATES.load(deps.storage, height.to_key())?;
            to_json_binary(&state)
        }
        QueryMsg::Status {} => {
            let state = CLIENT_STATE.load(deps.storage)?;
            let status = if state.is_frozen() {
                "Frozen"
            } else {
                "Active"
            };
            to_json_binary(&status)
        }
        QueryMsg::TimestampAtHeight { height } => {
            let state = CONSENSUS_STATES.load(deps.storage, height.to_key())?;
            to_json_binary(&state.timestamp)
        }
    }
}

/// find trusted consensus state for verification
fn find_trusted_consensus(
    deps: Deps,
    header_with_proof: &crate::types::JamHeaderWithProof,
) -> Result<JamConsensusState, ContractError> {
    // if ancestry is provided, use the first header's parent as trusted
    if !header_with_proof.ancestry.is_empty() {
        let first_ancestor = &header_with_proof.ancestry[0];
        let height = Height {
            revision_number: 0,
            // parent of first ancestor is the trusted state
            revision_height: (first_ancestor.timeslot - 1) as u64,
        };

        // try to load, if not found try scanning
        if let Ok(cs) = CONSENSUS_STATES.load(deps.storage, height.to_key()) {
            return Ok(cs);
        }
    }

    // fallback: find the highest consensus state we have that's before the target
    let target_slot = header_with_proof.header.timeslot;

    // simple scan - in production would use range queries
    for slot in (0..target_slot).rev() {
        let height = Height {
            revision_number: 0,
            revision_height: slot as u64,
        };
        if let Ok(cs) = CONSENSUS_STATES.load(deps.storage, height.to_key()) {
            return Ok(cs);
        }
    }

    Err(ContractError::ConsensusStateNotFound)
}
