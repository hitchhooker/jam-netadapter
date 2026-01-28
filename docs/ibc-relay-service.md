# jam-ibc: oraclized ibc relay service

decentralized relay coordination layer for inter-blockchain communication

## problem

current ibc relaying:
- permissionless but practically centralized (few well-funded relayers)
- expensive to run (multi-chain watching, gas on both sides)
- race conditions when relayers compete
- no sla guarantees - packets relay "eventually"
- each chain pair needs dedicated relayer infrastructure

## solution

jam service that coordinates ibc relay as trustless oracle infrastructure.
chains register, service handles packet matching and proof generation.
executors are stateless - just submit what service provides.

```
┌─────────────────────────────────────────────────────────────────┐
│                    cosmos chains                                │
│  osmosis    celestia    neutron    dydx    stride    ...       │
└──────┬─────────┬──────────┬─────────┬────────┬─────────────────┘
       │         │          │         │        │
       │ headers + packet commitments │        │
       ▼         ▼          ▼         ▼        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   jam-ibc service                               │
├─────────────────────────────────────────────────────────────────┤
│ refine (per core):                                              │
│   - verify tendermint headers + signatures                      │
│   - extract packet commitments from state proofs                │
│   - validate iavl merkle proofs                                 │
│                                                                 │
│ accumulate:                                                     │
│   - update light client states                                  │
│   - match SendPacket ↔ RecvPacket across chains                 │
│   - queue relay tasks with proofs                               │
│   - track acks, timeouts, channel state                         │
│   - emit executor instructions                                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ relay tasks (chain, packet, proof)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   executor network                              │
│  stateless submitters that push txs to destination chains       │
│  competitive market - fastest executor earns fee                │
└─────────────────────────────────────────────────────────────────┘
```

## architecture

### work item types

```rust
pub enum IbcWorkItem {
    /// register a new chain with its light client config
    RegisterChain {
        chain_id: Vec<u8>,
        light_client_type: LightClientType,
        genesis_state: Vec<u8>,
        trust_threshold: (u64, u64),  // e.g. 2/3
        trusting_period: u64,          // seconds
        rpc_endpoints: Vec<Vec<u8>>,
    },

    /// submit header update for a chain
    UpdateClient {
        chain_id: Vec<u8>,
        header: Vec<u8>,           // tendermint header
        commit: Vec<u8>,           // signed commit
        validator_set: Vec<u8>,    // if changed
    },

    /// report packet commitment from source chain
    ReportPacket {
        source_chain: Vec<u8>,
        dest_chain: Vec<u8>,
        packet: IbcPacket,
        commitment_proof: Vec<u8>,  // iavl proof
        proof_height: u64,
    },

    /// report acknowledgement
    ReportAck {
        source_chain: Vec<u8>,
        dest_chain: Vec<u8>,
        packet: IbcPacket,
        ack: Vec<u8>,
        ack_proof: Vec<u8>,
        proof_height: u64,
    },

    /// claim relay task (executor)
    ClaimTask {
        task_id: Hash,
        executor: PublicKey,
        bond: u64,
    },

    /// confirm task completion
    ConfirmExecution {
        task_id: Hash,
        dest_tx_hash: Hash,
        inclusion_proof: Vec<u8>,
    },

    /// report timeout
    ReportTimeout {
        source_chain: Vec<u8>,
        packet: IbcPacket,
        proof_unreceived: Vec<u8>,
        proof_height: u64,
    },
}
```

### light client types

```rust
pub enum LightClientType {
    /// tendermint/cometbft consensus (cosmos-sdk chains)
    Tendermint,
    /// grandpa finality (polkadot/kusama parachains)
    Grandpa,
    /// ethereum beacon chain
    Ethereum,
    /// near protocol
    Near,
    /// solana
    Solana,
}
```

### state schema

```
prefix 0x30: chain registry
  - chain_id → ChainConfig (light client type, trust params, status)

prefix 0x31: light client states
  - chain_id → ClientState (latest height, latest header hash, validator set)

prefix 0x32: consensus states (historical)
  - chain_id:height → ConsensusState (timestamp, root, next_validators_hash)

prefix 0x33: connections
  - connection_id → ConnectionEnd (client_id, counterparty, state, versions)

prefix 0x34: channels
  - port_id:channel_id → ChannelEnd (state, ordering, counterparty, connection_hops)

prefix 0x35: packet commitments
  - port:channel:sequence → commitment_hash

prefix 0x36: packet receipts
  - port:channel:sequence → receipt (for unordered channels)

prefix 0x37: ack commitments
  - port:channel:sequence → ack_hash

prefix 0x38: relay task queue
  - task_id → RelayTask (packet, proof, dest_chain, deadline, bounty)

prefix 0x39: executor registry
  - executor_pubkey → ExecutorInfo (stake, reputation, active_tasks)

prefix 0x3A: completed relays
  - packet_hash → RelayRecord (executor, timestamp, dest_tx)
```

### refine phase

validates incoming work items:

```rust
fn refine_ibc(payload: &[u8]) -> RefineOutput {
    let item = IbcWorkItem::decode(payload)?;

    match item {
        IbcWorkItem::UpdateClient { chain_id, header, commit, .. } => {
            // verify tendermint header
            let client_state = get_client_state(&chain_id)?;

            // check header is newer than current
            if header.height <= client_state.latest_height {
                return invalid("header not newer");
            }

            // verify 2/3+ validator signatures on commit
            let validators = get_validator_set(&chain_id, header.height)?;
            if !verify_commit(&header, &commit, &validators, (2, 3)) {
                return invalid("insufficient signatures");
            }

            // check within trusting period
            let chain_config = get_chain_config(&chain_id)?;
            if header.time < now() - chain_config.trusting_period {
                return invalid("header too old");
            }

            valid(/* header hash */)
        }

        IbcWorkItem::ReportPacket { commitment_proof, proof_height, .. } => {
            // verify iavl merkle proof against known state root
            let consensus_state = get_consensus_state(&source_chain, proof_height)?;

            if !verify_iavl_proof(
                &commitment_proof,
                &consensus_state.root,
                &packet_commitment_key(&packet),
                &packet_commitment(&packet),
            ) {
                return invalid("proof verification failed");
            }

            valid(/* packet hash */)
        }

        // ... other cases
    }
}
```

### accumulate phase

applies validated state changes:

```rust
fn accumulate_ibc(payload: &[u8], refined: &RefineOutput, timeslot: u32) {
    let item = IbcWorkItem::decode(payload)?;

    match item {
        IbcWorkItem::UpdateClient { chain_id, header, .. } => {
            // update client state
            let mut client = get_client_state(&chain_id)?;
            client.latest_height = header.height;
            client.latest_header_hash = hash(&header);
            set_client_state(&chain_id, &client);

            // store consensus state for proof verification
            set_consensus_state(&chain_id, header.height, ConsensusState {
                timestamp: header.time,
                root: header.app_hash,
                next_validators_hash: header.next_validators_hash,
            });

            // prune old consensus states beyond trusting period
            prune_old_states(&chain_id);
        }

        IbcWorkItem::ReportPacket { source_chain, dest_chain, packet, .. } => {
            // check not already relayed
            if packet_relayed(&packet) {
                return;
            }

            // create relay task
            let task = RelayTask {
                id: hash(&packet),
                packet: packet.clone(),
                dest_chain,
                proof: commitment_proof,
                proof_height,
                deadline: timeslot + RELAY_DEADLINE_SLOTS,
                bounty: calculate_bounty(&packet),
                status: TaskStatus::Pending,
            };

            queue_relay_task(&task);

            // emit event for executors
            emit_relay_task(&task);
        }

        IbcWorkItem::ConfirmExecution { task_id, dest_tx_hash, inclusion_proof } => {
            let mut task = get_relay_task(&task_id)?;

            // verify tx was included in destination chain
            // (requires light client of dest chain)
            if !verify_tx_inclusion(&task.dest_chain, &dest_tx_hash, &inclusion_proof) {
                return;
            }

            // mark completed, pay executor
            task.status = TaskStatus::Completed;
            set_relay_task(&task);

            let executor = get_executor(&task.claimed_by)?;
            pay_bounty(&executor, task.bounty);
            update_reputation(&executor, true);
        }

        // ... timeout handling, ack processing
    }
}
```

## tendermint light client

core verification logic needed:

### header verification

```rust
pub struct TendermintHeader {
    pub version: Version,
    pub chain_id: String,
    pub height: u64,
    pub time: Timestamp,
    pub last_block_id: BlockId,
    pub last_commit_hash: Hash,
    pub data_hash: Hash,
    pub validators_hash: Hash,
    pub next_validators_hash: Hash,
    pub consensus_hash: Hash,
    pub app_hash: Hash,  // state root for iavl proofs
    pub last_results_hash: Hash,
    pub evidence_hash: Hash,
    pub proposer_address: Address,
}

pub fn verify_header(
    header: &TendermintHeader,
    commit: &Commit,
    validators: &ValidatorSet,
    threshold: (u64, u64),  // numerator, denominator
) -> bool {
    // 1. verify commit is for this header
    if commit.block_id.hash != hash(header) {
        return false;
    }

    // 2. count voting power of valid signatures
    let total_power = validators.total_voting_power();
    let mut signed_power = 0u64;

    for (i, sig) in commit.signatures.iter().enumerate() {
        if sig.is_absent() {
            continue;
        }

        let validator = &validators.validators[i];
        let sign_bytes = vote_sign_bytes(
            &header.chain_id,
            commit.height,
            commit.round,
            &commit.block_id,
        );

        // ed25519 verification
        if verify_signature(&validator.pub_key, &sign_bytes, &sig.signature) {
            signed_power += validator.voting_power;
        }
    }

    // 3. check threshold met
    signed_power * threshold.1 >= total_power * threshold.0
}
```

### iavl proof verification

cosmos chains use iavl (immutable avl tree) for state proofs:

```rust
pub struct IavlProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub leaf: IavlLeafOp,
    pub path: Vec<IavlInnerOp>,
}

pub fn verify_iavl_proof(
    proof: &IavlProof,
    root: &Hash,
    expected_key: &[u8],
    expected_value: &[u8],
) -> bool {
    // verify key/value match
    if proof.key != expected_key || proof.value != expected_value {
        return false;
    }

    // compute leaf hash
    let mut hash = iavl_leaf_hash(&proof.leaf, &proof.key, &proof.value);

    // walk up the tree
    for inner in &proof.path {
        hash = iavl_inner_hash(inner, &hash);
    }

    // compare to root
    hash == *root
}

fn iavl_leaf_hash(leaf: &IavlLeafOp, key: &[u8], value: &[u8]) -> Hash {
    // iavl leaf: 0x00 || length(key) || key || length(value) || value
    let mut preimage = vec![0u8];
    preimage.extend(encode_varint(key.len()));
    preimage.extend(key);
    preimage.extend(encode_varint(value.len()));
    preimage.extend(value);
    sha256(&preimage)
}

fn iavl_inner_hash(inner: &IavlInnerOp, child: &Hash) -> Hash {
    // iavl inner: height || size || version || left || right
    let mut preimage = Vec::new();
    preimage.push(inner.height);
    preimage.extend(&inner.size.to_be_bytes());
    preimage.extend(&inner.version.to_be_bytes());

    if inner.is_left {
        preimage.extend(child);
        preimage.extend(&inner.sibling);
    } else {
        preimage.extend(&inner.sibling);
        preimage.extend(child);
    }

    sha256(&preimage)
}
```

## executor network

executors are off-chain agents that submit relay transactions:

### executor lifecycle

```
1. register with jam-ibc service (stake bond)
2. watch for relay tasks in service state
3. claim task (locks bond)
4. submit tx to destination chain
5. report inclusion proof back to service
6. receive bounty + reputation
```

### executor incentives

```
- bounty = base_fee + packet_size_fee + priority_fee
- fast execution = higher reputation = first pick of tasks
- failed execution = slashed bond + reputation hit
- timeout = partial slash, task goes back to queue
```

### executor client (rust binary)

```rust
// simplified executor loop
async fn run_executor(config: ExecutorConfig) {
    let jam_client = JamClient::new(&config.jam_rpc);
    let chain_clients = init_chain_clients(&config.chains);

    loop {
        // poll for available tasks
        let tasks = jam_client.get_pending_relay_tasks().await?;

        for task in tasks {
            // check if we want this task (profitability, etc)
            if !should_claim(&task, &config) {
                continue;
            }

            // claim task
            let claim = jam_client.claim_task(task.id, config.pubkey).await?;

            // submit to destination chain
            let dest_client = &chain_clients[&task.dest_chain];
            let tx = build_recv_packet_tx(&task.packet, &task.proof);
            let tx_hash = dest_client.broadcast_tx(tx).await?;

            // wait for inclusion
            let inclusion = dest_client.wait_for_inclusion(tx_hash).await?;

            // report completion
            jam_client.confirm_execution(task.id, tx_hash, inclusion.proof).await?;
        }

        sleep(Duration::from_secs(1)).await;
    }
}
```

## hermes compatibility

hermes expects cosmos-sdk rpc. options:

### option 1: translation proxy

```
hermes → grpc/tendermint rpc → translator → jam rpc
```

translator maps:
- `/block` → jam service state query
- `/abci_query` → jam storage read
- `/broadcast_tx` → jam work item submission

problems:
- hermes assumes instant rpc feedback
- jam work items are async
- proof formats differ

### option 2: native jam relayer

build relayer that speaks jam natively:

```rust
// jam-ibc-relayer
pub struct JamRelayer {
    jam_client: JamClient,
    chain_clients: HashMap<ChainId, CosmosClient>,
}

impl JamRelayer {
    async fn relay_loop(&self) {
        loop {
            // for each registered chain pair
            for (src, dst) in self.get_channel_pairs().await {
                // get unreceived packets from source
                let packets = self.chain_clients[&src]
                    .query_unreceived_packets(&channel)
                    .await?;

                // submit to jam service
                for packet in packets {
                    let proof = self.chain_clients[&src]
                        .get_packet_commitment_proof(&packet)
                        .await?;

                    self.jam_client.submit_work_item(IbcWorkItem::ReportPacket {
                        source_chain: src.clone(),
                        dest_chain: dst.clone(),
                        packet,
                        commitment_proof: proof.bytes,
                        proof_height: proof.height,
                    }).await?;
                }
            }

            sleep(Duration::from_secs(6)).await;
        }
    }
}
```

### option 3: hybrid

- use hermes for cosmos↔cosmos relaying (unchanged)
- jam-ibc handles cosmos↔polkadot bridging
- jam service is the polkadot-side light client host

## implementation phases

### phase 1: tendermint light client
- [ ] header parsing and validation
- [ ] ed25519 signature verification (batch)
- [ ] iavl proof verification
- [ ] consensus state tracking

### phase 2: packet relay logic
- [ ] connection handshake (ics-003)
- [ ] channel handshake (ics-004)
- [ ] packet commitment/receipt tracking
- [ ] timeout handling

### phase 3: executor network
- [ ] task queue and claiming
- [ ] bounty calculation and payment
- [ ] execution confirmation
- [ ] slashing for failures

### phase 4: multi-chain support
- [ ] chain registry
- [ ] grandpa light client (for polkadot chains)
- [ ] ethereum beacon light client
- [ ] dynamic light client loading

### phase 5: relayer tooling
- [ ] jam-native relayer binary
- [ ] hermes translation proxy (optional)
- [ ] monitoring and alerting
- [ ] gas estimation

## economics

```
relay fee = base_fee + (packet_size * size_fee) + priority_fee

base_fee:      set by governance, covers service costs
size_fee:      scales with proof/packet size
priority_fee:  user-specified for faster relay

executor cut:  70% of relay fee
service fund:  20% (covers jam core costs)
insurance:     10% (covers failed relay refunds)
```

## comparison

| aspect | current ibc | jam-ibc |
|--------|-------------|---------|
| relayer model | competitive, permissionless | coordinated, staked executors |
| packet matching | each relayer independently | single source of truth |
| proof generation | relayer computes | service provides |
| sla guarantees | none | bounded relay time |
| fee market | gas auction on dest chain | service-level pricing |
| light clients | per-relayer | shared in service |

## references

- [ibc spec](https://github.com/cosmos/ibc)
- [tendermint-rs](https://github.com/informalsystems/tendermint-rs)
- [ibc-rs](https://github.com/cosmos/ibc-rs)
- [hermes](https://github.com/informalsystems/hermes)
- [composable ibc](https://github.com/ComposableFi/composable-ibc)
