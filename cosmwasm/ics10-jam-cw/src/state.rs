//! contract state

use cw_storage_plus::{Item, Map};

use crate::types::{JamClientState, JamConsensusState};

/// client state (single item)
pub const CLIENT_STATE: Item<JamClientState> = Item::new("client_state");

/// consensus states by height key
pub const CONSENSUS_STATES: Map<Vec<u8>, JamConsensusState> = Map::new("consensus_states");
