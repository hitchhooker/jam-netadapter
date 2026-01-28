# jam-ibc implementation plan

## existing code inventory

### zeratul (~/rotko/zeratul)

| file | contents | reusable |
|------|----------|----------|
| `chain-client/src/ibc.rs` | cosmos rpc client, MsgTransfer, DenomTrace, channel config | yes - client side |
| `penumbra/ibc.rs` | IBCHandler, packet verification, light client integration | yes - proof verification |
| `docs-dev/TODO-IBC-INTEGRATION.md` | pallet-ibc integration plan | reference only |

### composable-ibc (~/rotko/composable-ibc)

| component | location | notes |
|-----------|----------|-------|
| pallet-ibc | contracts/pallet-ibc/ | substrate pallet, heavy runtime deps |
| ics07-tendermint | light-clients/ics07-tendermint/ | tendermint verification logic |
| ics10-grandpa | light-clients/ics10-grandpa/ | grandpa verification (cosmos side) |
| hyperspace | hyperspace/ | forked relayer for substrate |
| ibc-rs types | ibc/ | core ibc types |

### what we need vs what exists

```
                    exists (zeratul)    exists (composable)    need to build
                    ─────────────────   ────────────────────   ─────────────
tendermint header        ✗                     ✓                    port
verification

iavl proof verify        ✗                     ✓                    port

packet types             ✓                     ✓                    adapt

light client state       partial               ✓                    port

channel/connection       ✗                     ✓                    port
state machine

relay task queue         ✗                     ✗                    new

executor network         ✗                     ✗                    new

jam host bindings        ✗                     ✗                    new
```

## architecture decision

**choice: jam service (not polkavm contract)**

rationale:
- light client verification is crypto-heavy (ed25519 batch verify, merkle proofs)
- ibc state is complex (connections, channels, packets, acks)
- gas metering in contracts would kill performance
- jam services have better access to host functions
- fits refine/accumulate model naturally

## phased implementation

### phase 0: extract reusable code (1 week)

pull portable code from composable-ibc into jam-service:

```
composable-ibc/                         jam-service/src/
├── ibc/modules/src/                    ├── ibc/
│   ├── core/                           │   ├── types.rs        (packet, channel, connection)
│   │   ├── ics02_client/              │   ├── client.rs       (client state, consensus state)
│   │   ├── ics03_connection/          │   ├── connection.rs   (connection handshake)
│   │   ├── ics04_channel/             │   ├── channel.rs      (channel handshake)
│   │   └── ics24_host/                │   └── commitment.rs   (ics-023 paths)
│   └── applications/transfer/         │
└── light-clients/ics07-tendermint/    ├── tendermint/
    └── src/                            │   ├── header.rs       (header parsing)
        ├── client_state.rs             │   ├── verify.rs       (signature verification)
        └── consensus_state.rs          │   └── proof.rs        (iavl proof)
```

tasks:
- [ ] extract core ibc types (no substrate deps)
- [ ] extract tendermint header types
- [ ] extract iavl proof verification
- [ ] make everything no_std compatible
- [ ] add to jam-service/Cargo.toml

### phase 1: tendermint light client (2 weeks)

implement light client in jam-service:

```rust
// jam-service/src/ibc/tendermint.rs

pub struct TendermintClientState {
    pub chain_id: Vec<u8>,
    pub trust_threshold: (u64, u64),
    pub trusting_period: u64,
    pub unbonding_period: u64,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
}

pub struct TendermintConsensusState {
    pub timestamp: u64,
    pub root: Hash,  // app_hash for iavl proofs
    pub next_validators_hash: Hash,
}

pub fn verify_header(
    client_state: &TendermintClientState,
    consensus_state: &TendermintConsensusState,
    header: &TendermintHeader,
    commit: &SignedCommit,
    validator_set: &ValidatorSet,
) -> bool {
    // 1. check chain_id matches
    // 2. check header height > latest
    // 3. check within trusting period
    // 4. verify 2/3+ signatures on commit
    // 5. verify validators_hash matches
}
```

tasks:
- [ ] port TendermintHeader parsing (protobuf-free, manual decode)
- [ ] port SignedCommit structure
- [ ] port ValidatorSet with voting power
- [ ] implement ed25519 batch verification (use host::ed25519_verify if available)
- [ ] implement header verification logic
- [ ] implement consensus state updates

### phase 2: iavl proof verification (1 week)

port iavl merkle proof verification:

```rust
// jam-service/src/ibc/proof.rs

pub struct IavlProof {
    pub ops: Vec<ProofOp>,
}

pub struct ProofOp {
    pub op_type: ProofOpType,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
}

pub fn verify_membership(
    proof: &IavlProof,
    root: &Hash,
    path: &[u8],
    value: &[u8],
) -> bool {
    // walk proof ops, verify each step
    // final hash must equal root
}

pub fn verify_non_membership(
    proof: &IavlProof,
    root: &Hash,
    path: &[u8],
) -> bool {
    // verify absence proof
}
```

tasks:
- [ ] port IavlProofOp types
- [ ] port leaf hash computation
- [ ] port inner node hash computation
- [ ] implement membership proof verification
- [ ] implement non-membership proof verification
- [ ] test against known cosmos proofs

### phase 3: ibc core state machine (2 weeks)

implement connection and channel handshakes:

```rust
// jam-service/src/ibc/connection.rs

pub enum ConnectionState {
    Uninitialized,
    Init,
    TryOpen,
    Open,
}

pub struct ConnectionEnd {
    pub state: ConnectionState,
    pub client_id: ClientId,
    pub counterparty: Counterparty,
    pub versions: Vec<Version>,
    pub delay_period: u64,
}

// ICS-003 connection handshake
pub fn conn_open_init(...) -> Result<()>;
pub fn conn_open_try(...) -> Result<()>;
pub fn conn_open_ack(...) -> Result<()>;
pub fn conn_open_confirm(...) -> Result<()>;

// jam-service/src/ibc/channel.rs

pub enum ChannelState {
    Uninitialized,
    Init,
    TryOpen,
    Open,
    Closed,
}

pub struct ChannelEnd {
    pub state: ChannelState,
    pub ordering: Order,
    pub counterparty: ChannelCounterparty,
    pub connection_hops: Vec<ConnectionId>,
    pub version: String,
}

// ICS-004 channel handshake
pub fn chan_open_init(...) -> Result<()>;
pub fn chan_open_try(...) -> Result<()>;
pub fn chan_open_ack(...) -> Result<()>;
pub fn chan_open_confirm(...) -> Result<()>;
```

tasks:
- [ ] implement connection state storage
- [ ] implement connection handshake (4 msgs)
- [ ] implement channel state storage
- [ ] implement channel handshake (4 msgs)
- [ ] implement packet commitment storage
- [ ] implement packet receipt storage (unordered)
- [ ] implement ack commitment storage

### phase 4: packet relay logic (2 weeks)

implement send/receive/ack/timeout:

```rust
// jam-service/src/ibc/packet.rs

pub struct Packet {
    pub sequence: u64,
    pub source_port: PortId,
    pub source_channel: ChannelId,
    pub destination_port: PortId,
    pub destination_channel: ChannelId,
    pub data: Vec<u8>,
    pub timeout_height: Height,
    pub timeout_timestamp: u64,
}

// ICS-004 packet handling
pub fn send_packet(packet: &Packet) -> Result<()> {
    // store commitment = hash(packet)
}

pub fn recv_packet(
    packet: &Packet,
    proof: &IavlProof,
    proof_height: Height,
) -> Result<()> {
    // verify packet was committed on source chain
    // store receipt (unordered) or check sequence (ordered)
}

pub fn acknowledge_packet(
    packet: &Packet,
    ack: &Acknowledgement,
    proof: &IavlProof,
    proof_height: Height,
) -> Result<()> {
    // verify ack was written on dest chain
    // delete commitment
}

pub fn timeout_packet(
    packet: &Packet,
    proof: &IavlProof,
    proof_height: Height,
    next_sequence_recv: u64,
) -> Result<()> {
    // verify packet was not received before timeout
    // delete commitment
}
```

tasks:
- [ ] implement packet commitment computation
- [ ] implement send_packet (store commitment)
- [ ] implement recv_packet (verify proof, store receipt)
- [ ] implement write_acknowledgement
- [ ] implement acknowledge_packet (verify ack proof)
- [ ] implement timeout_packet (verify non-receipt)

### phase 5: relay task queue (1 week)

add executor coordination:

```rust
// jam-service/src/ibc/relay.rs

pub struct RelayTask {
    pub id: Hash,
    pub task_type: RelayTaskType,
    pub source_chain: ChainId,
    pub dest_chain: ChainId,
    pub packet: Packet,
    pub proof: Vec<u8>,
    pub proof_height: Height,
    pub deadline: u32,  // slot
    pub bounty: u64,
    pub claimed_by: Option<PublicKey>,
    pub status: TaskStatus,
}

pub enum RelayTaskType {
    RecvPacket,
    AckPacket,
    TimeoutPacket,
}

pub enum TaskStatus {
    Pending,
    Claimed,
    Executed,
    Failed,
    Expired,
}

// task queue operations
pub fn queue_relay_task(task: RelayTask);
pub fn claim_task(task_id: Hash, executor: PublicKey) -> Result<()>;
pub fn confirm_execution(task_id: Hash, dest_tx: Hash, proof: Vec<u8>) -> Result<()>;
pub fn expire_stale_tasks(current_slot: u32);
```

tasks:
- [ ] implement task queue storage
- [ ] implement task creation on packet events
- [ ] implement task claiming with bond
- [ ] implement execution confirmation
- [ ] implement task expiry and re-queue
- [ ] implement bounty calculation

### phase 6: jam work item integration (1 week)

wire everything into jam refine/accumulate (pattern from romio/jam_abci.jl):

```
refine phase (parallel, stateless):
  - verify ed25519 signatures on tendermint commits
  - verify iavl merkle proofs against known roots
  - validate packet format and timeouts
  - export validated data for accumulate

accumulate phase (sequential, stateful):
  - update light client consensus states
  - store/delete packet commitments
  - update channel/connection state machines
  - queue relay tasks with bounties
  - pay out completed bounties
```

```rust
// jam-service/src/ibc/mod.rs

pub enum IbcWorkItem {
    // client updates
    CreateClient { client_type: ClientType, state: Vec<u8> },
    UpdateClient { client_id: ClientId, header: Vec<u8> },

    // connection handshake
    ConnOpenInit { ... },
    ConnOpenTry { ... },
    ConnOpenAck { ... },
    ConnOpenConfirm { ... },

    // channel handshake
    ChanOpenInit { ... },
    ChanOpenTry { ... },
    ChanOpenAck { ... },
    ChanOpenConfirm { ... },

    // packet relay
    RecvPacket { packet: Packet, proof: Vec<u8>, height: Height },
    AckPacket { packet: Packet, ack: Vec<u8>, proof: Vec<u8>, height: Height },
    TimeoutPacket { packet: Packet, proof: Vec<u8>, height: Height },

    // executor actions
    ClaimRelayTask { task_id: Hash, executor: PublicKey },
    ConfirmExecution { task_id: Hash, dest_tx: Hash, inclusion_proof: Vec<u8> },
}

// refine validates proofs
pub fn refine_ibc(payload: &[u8]) -> RefineOutput {
    let item = IbcWorkItem::decode(payload)?;
    match item {
        IbcWorkItem::UpdateClient { header, .. } => {
            // verify header signatures
        }
        IbcWorkItem::RecvPacket { proof, height, .. } => {
            // verify iavl proof against known root
        }
        // ...
    }
}

// accumulate applies state changes
pub fn accumulate_ibc(payload: &[u8], refined: &RefineOutput, slot: u32) {
    let item = IbcWorkItem::decode(payload)?;
    match item {
        IbcWorkItem::UpdateClient { client_id, header, .. } => {
            // update client state and consensus state
        }
        IbcWorkItem::RecvPacket { packet, .. } => {
            // store receipt, queue ack task
        }
        // ...
    }
}
```

tasks:
- [ ] add IbcWorkItem to WorkItemType enum
- [ ] implement refine_ibc validation
- [ ] implement accumulate_ibc state updates
- [ ] integrate with existing jam-service main.rs
- [ ] add storage prefixes for ibc state

### phase 7: executor binary (2 weeks)

build off-chain executor:

```rust
// jam-ibc-executor/src/main.rs

struct Executor {
    jam_client: JamClient,
    chain_clients: HashMap<ChainId, CosmosClient>,
    keypair: Keypair,
}

impl Executor {
    async fn run(&self) {
        loop {
            // 1. poll jam service for relay tasks
            let tasks = self.jam_client.get_pending_tasks().await?;

            for task in tasks {
                // 2. claim profitable tasks
                if !self.should_claim(&task) {
                    continue;
                }
                self.jam_client.claim_task(task.id, self.keypair.public()).await?;

                // 3. build and submit tx to dest chain
                let tx = self.build_relay_tx(&task);
                let dest = &self.chain_clients[&task.dest_chain];
                let tx_hash = dest.broadcast_tx(tx).await?;

                // 4. wait for inclusion
                let inclusion = dest.wait_for_inclusion(tx_hash).await?;

                // 5. report back to jam
                self.jam_client.confirm_execution(task.id, tx_hash, inclusion.proof).await?;
            }

            sleep(Duration::from_secs(6)).await;
        }
    }
}
```

tasks:
- [ ] create jam-ibc-executor crate
- [ ] implement jam rpc client (work item submission, state queries)
- [ ] implement cosmos rpc client (broadcast_tx, query_tx)
- [ ] implement task selection logic (profitability)
- [ ] implement relay tx construction
- [ ] implement inclusion proof fetching
- [ ] add metrics and monitoring
- [ ] dockerfile for deployment

### phase 8: hermes compatibility (optional, 2 weeks)

translation proxy for hermes:

```
hermes → grpc → translator → jam work items
                          ↓
                    jam service
                          ↓
translator ← jam state queries ← jam rpc
     ↓
   grpc
     ↓
  hermes
```

alternative: fork hermes, add jam chain type directly.

tasks:
- [ ] evaluate effort vs native executor
- [ ] if proceeding: implement grpc translation proxy
- [ ] map hermes rpc calls to jam queries
- [ ] map hermes tx submissions to work items

## jam host functions (from romio)

the ibc service will use these host functions:

| index | function | ibc usage |
|-------|----------|-----------|
| 0 | `gas()` | meter proof verification costs |
| 1 | `fetch(index, ω)` | get work items, entropy for task selection |
| 3 | `read(service, key)` | query light client state, packet commitments |
| 4 | `write(key, value)` | store consensus states, channel state, packets |
| 5 | `info(service)` | get service balance for bounty payouts |
| 7 | `export(data)` | pass validated proofs from refine to accumulate |
| 20 | `transfer(dest, amount, gas, memo)` | pay executor bounties |

note: no native ed25519_verify - must use pure rust (ed25519-dalek with `alloc` feature).

## dependencies

### rust crates needed

```toml
# jam-service/Cargo.toml additions
ed25519-dalek = { version = "2", default-features = false, features = ["alloc"] }
# already have sha2

# jam-ibc-executor/Cargo.toml
tendermint = "0.34"
tendermint-rpc = "0.34"
cosmrs = "0.15"
tokio = { version = "1", features = ["full"] }
```

### external services

- cosmos rpc endpoints (osmosis, cosmoshub, etc)
- jam node rpc (when available)
- optional: hermes for existing relay infra

## testing strategy

### unit tests
- header verification with known cosmos headers
- iavl proof verification with known proofs
- packet commitment computation
- state machine transitions

### integration tests
- local cosmos testnet (gaiad)
- local jam testnet (polkajam-repl)
- end-to-end packet relay

### testnet deployment
- kusama testnet (jam)
- osmosis testnet
- monitor relay latency and success rate

## timeline

| phase | duration | deliverable |
|-------|----------|-------------|
| 0 | 1 week | extracted portable code |
| 1 | 2 weeks | tendermint light client |
| 2 | 1 week | iavl proof verification |
| 3 | 2 weeks | connection/channel state machine |
| 4 | 2 weeks | packet relay logic |
| 5 | 1 week | relay task queue |
| 6 | 1 week | jam work item integration |
| 7 | 2 weeks | executor binary |
| 8 | 2 weeks | hermes compatibility (optional) |

**total: 12-14 weeks**

## risks

| risk | mitigation |
|------|------------|
| composable code too coupled to substrate | extract minimal types, rewrite verification |
| jam host functions missing needed crypto | implement in pure rust (slower) |
| cosmos proof format changes | pin to specific ibc-go version |
| executor incentives don't work | iterate on bounty model |
| hermes incompatible | focus on native executor |

## success criteria

1. tendermint header updates verified on jam
2. ibc packets relayed osmosis → jam
3. ibc packets relayed jam → osmosis
4. relay latency < 30 seconds average
5. executor network has 3+ independent operators
