# jam-netadapter

decentralized dns and oracle infrastructure for jam chain

## architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           off-chain (auxiliary)                             │
│  ┌──────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐ │
│  │ worker   │  │ aggregator │  │ dns-server │  │ resolver │  │ sla-probe │ │
│  │ (oracle) │→→│ (threshold)│  │ (geodns)   │  │ (.alt)   │  │ (monitor) │ │
│  └──────────┘  └─────┬──────┘  └─────┬──────┘  └────┬─────┘  └─────┬─────┘ │
└──────────────────────┼───────────────┼──────────────┼──────────────┼───────┘
                       │               │              │              │
                       ▼               ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          jam-service (on-chain)                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ refine: validate signatures, merkle proofs, nullifiers              │   │
│  │ accumulate: store oracle data, namespaces, sla results, commitments │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  state: oracles | namespaces | sla contracts | privacy commitments          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## components

### jam-service (on-chain motor)

polkavm service that runs on jam chain. handles six work item types:

| type | description |
|------|-------------|
| `OracleData` | threshold-signed external data (http, dns, timestamp, feeds) |
| `StateUpdate` | key-value storage with ownership and signatures |
| `NamespaceOp` | .alt domain registration, updates, transfers, renewals |
| `SlaOp` | probe registration, measurements, epoch finalization, slashing |
| `PrivateOp` | shielded transactions via poseidon commitments and nullifiers |
| `IbcOp` | cosmos ibc bridge: light clients, packets, relay task queue |

```bash
cd jam-service
just build   # compile to riscv32em
just link    # create .jam binary (~218kb)
```

deploy to jam testnet:
```bash
jamt create-service target/riscv32em-unknown-none-elf/release/netadapter.jam 1000000
```

### worker (off-chain oracle)

fetches external data and signs with ed25519:

- http responses
- dns lookups
- timestamps
- price feeds

```bash
cargo run --bin netadapter-worker -- --port 3000 --key /path/to/key
```

### aggregator (off-chain coordinator)

collects worker signatures until threshold met, packages work items:

```bash
cargo run --bin netadapter-aggregator -- \
  --port 3001 \
  --threshold 2 \
  --workers http://worker1:3000,http://worker2:3000
```

### dns-server (authoritative geodns)

serves zones with geographic routing via maxmind geoip:

```bash
cargo run --bin netadapter-dns -- \
  --dns-port 5353 \
  --api-port 8053 \
  --geoip-db /usr/share/maxmind/GeoLite2-City.mmdb
```

### resolver (recursive + .alt gateway)

anycast recursive resolver with .alt namespace support:

```bash
cargo run --bin netadapter-resolver -- \
  --dns-port 53 \
  --doh-port 443 \
  --anycast-ip 10.x.x.x
```

### sla-probe (monitoring node)

distributed monitoring with commit-reveal measurements:

```bash
# not yet implemented - needs:
# - probe registration with stake
# - periodic measurements of target nodes
# - commit hash, then reveal after deadline
# - reputation tracking
```

## .alt namespace (rfc 8244)

`.alt` is ietf-reserved for alternative namespaces. the resolver acts as
read-only gateway to external naming protocols:

| namespace | source | registration |
|-----------|--------|--------------|
| `*.jam.alt` | jam state | jam service work items |
| `*.dot.alt` | polkadot people chain | people chain extrinsics |
| `*.eth.alt` | ens | ens contracts |
| `*.hs.alt` | handshake | handshake protocol |

examples:
```
rotko.jam.alt          → jam state lookup
validator-01.dot.alt   → people chain lookup
vitalik.eth.alt        → ens lookup
```

## sla monitoring

decentralized uptime/latency monitoring with cryptoeconomic guarantees:

```
┌────────────┐     ┌────────────┐     ┌────────────┐
│  probe A   │     │  probe B   │     │  probe C   │
│  (europe)  │     │  (asia)    │     │  (america) │
└─────┬──────┘     └─────┬──────┘     └─────┬──────┘
      │ measure          │ measure          │ measure
      ▼                  ▼                  ▼
┌─────────────────────────────────────────────────┐
│              target node                        │
└─────────────────────────────────────────────────┘
      │                  │                  │
      │ commit hash      │ commit hash      │ commit hash
      ▼                  ▼                  ▼
┌─────────────────────────────────────────────────┐
│           jam-service (epoch N)                 │
└─────────────────────────────────────────────────┘
      │                  │                  │
      │ reveal           │ reveal           │ reveal
      ▼                  ▼                  ▼
┌─────────────────────────────────────────────────┐
│        jam-service (epoch N+1)                  │
│  → compute consensus (67% threshold)            │
│  → update node stats                            │
│  → adjust probe reputations                     │
│  → check sla contracts                          │
└─────────────────────────────────────────────────┘
```

commit-reveal prevents probes from copying each other's answers.
geographic diversity ensures global coverage.
reputation system penalizes dishonest probes.

## privacy (zeratul-style)

shielded transactions using poseidon hash commitments:

| concept | description |
|---------|-------------|
| note commitment | `poseidon(blinding, amount, asset_id)` - hides value |
| nullifier | `poseidon(nk, position, commitment)` - prevents double-spend |
| merkle tree | incremental tree of commitments for inclusion proofs |
| anchor | historical merkle root (valid for ~10 min window) |

spend flow:
```
1. prover has note at position P with nullifier key NK
2. compute nullifier = poseidon(NK, P, commitment)
3. generate merkle proof for commitment at P
4. submit: { nullifier, anchor, proof }
5. refine: verify nullifier derivation + merkle proof
6. accumulate: mark nullifier spent, reject if seen before
```

## ibc relay (cosmos bridge)

bridge jam to cosmos chains (osmosis, cosmoshub, etc) via ibc protocol:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         cosmos chain (osmosis)                               │
│  packets committed → validators sign blocks → iavl merkle proofs            │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ executors observe
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         off-chain executors                                  │
│  monitor cosmos → build proofs → submit RecvPacket → confirm execution      │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ work items
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         jam-service (ibc module)                             │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ refine: verify tendermint headers, iavl proofs, ed25519 signatures     │ │
│  │ accumulate: update light clients, store packets, manage relay tasks    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│  state: clients | connections | channels | packets | relay tasks            │
└─────────────────────────────────────────────────────────────────────────────┘
```

ibc work item types:

| operation | description |
|-----------|-------------|
| `CreateClient` | register tendermint light client for cosmos chain |
| `UpdateClient` | submit new header with validator signatures |
| `SendPacket` | send packet from jam, creates relay task |
| `RecvPacket` | receive packet from cosmos with merkle proof |
| `AcknowledgePacket` | confirm packet was received on destination |
| `ClaimRelayTask` | executor claims pending relay task |
| `ConfirmExecution` | executor proves tx was included on dest chain |

executor incentives:
- tasks have bounties (base + proof size + urgency bonus)
- first-come-first-served claiming
- deadline for execution (~1 hour)
- bounty paid on successful confirmation
- expired tasks re-queued for new executors

## geodns regions

records can target specific geographic regions:

| format | example | description |
|--------|---------|-------------|
| `*` | `*` | global fallback |
| `continent:XX` | `continent:EU` | eu, na, as, af, oc, sa, an |
| `country:XX` | `country:DE` | iso 3166-1 alpha-2 |
| `asn:NNNNN` | `asn:13335` | autonomous system number |

## state schema

jam-service storage prefixes:

| prefix | contents |
|--------|----------|
| `0x00` | config (threshold, worker keys, finality slots) |
| `0x01` | oracle data by request_id |
| `0x02` | state entries by key |
| `0x03` | namespace domains |
| `0x04` | namespace metadata |
| `0x10` | sla probes |
| `0x11` | sla monitored nodes |
| `0x12` | sla contracts |
| `0x13` | sla commitments |
| `0x14` | sla revealed reports |
| `0x15` | sla epoch results |
| `0x20` | privacy note commitments |
| `0x21` | privacy nullifiers |
| `0x22` | privacy merkle nodes |
| `0x23` | privacy tree metadata |
| `0x24` | privacy anchor history |
| `0x30` | ibc client states |
| `0x31` | ibc consensus states |
| `0x32` | ibc connections |
| `0x33` | ibc channels |
| `0x34` | ibc packet commitments |
| `0x35` | ibc packet receipts |
| `0x36` | ibc packet acknowledgements |
| `0x37` | ibc next sequence send |
| `0x38` | ibc next sequence recv |
| `0x39` | ibc next sequence ack |
| `0x3A` | ibc relay tasks |
| `0x3B` | ibc client counter |
| `0x3C` | ibc connection counter |
| `0x3D` | ibc channel counter |
| `0x3E` | ibc task metrics |
| `0x3F` | ibc pending task index |

## build

```bash
# off-chain binaries
cargo build --release

# on-chain service (requires nightly + riscv target)
cd jam-service
rustup target add riscv32em-unknown-none-elf
just link
```

## deploy

```bash
# start local testnet
polkajam-testnet

# create service
jamt create-service jam-service/target/riscv32em-unknown-none-elf/release/netadapter.jam 1000000

# or download release
wget https://github.com/hitchhooker/jam-netadapter/releases/download/v0.1.0/netadapter.jam
jamt create-service netadapter.jam 1000000
```

## license

mit
