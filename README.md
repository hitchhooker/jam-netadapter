# jam-netadapter

jam network adapter for decentralized dns infrastructure

## architecture overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              JAM Consensus                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ state: zones, .alt namespaces, blocklists, dnssec anchors, config   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌───────────────────┐           ┌───────────────────┐
        │   dns-server      │           │   resolver        │
        │   (authoritative) │           │   (recursive)     │
        │                   │           │                   │
        │ serves zones we   │           │ anycast dns like  │
        │ own with geodns   │           │ 9.9.9.9 + .alt    │
        └───────────────────┘           └───────────────────┘
```

## components

### common
protocol types for:
- oracle requests/responses with ed25519 threshold signatures
- dns zones with geodns regions (continent/country/asn)
- .alt namespace domains and registration
- conflict resolution (serial, nonce, owner signatures)

### worker
oracle worker that fetches external data and signs responses

```bash
cargo run --bin netadapter-worker -- --port 3000
```

### aggregator
collects worker responses, creates threshold-signed work items

```bash
cargo run --bin netadapter-aggregator -- --port 3001 --threshold 2 \
  --workers http://localhost:3000,http://localhost:3002
```

### dns-server (authoritative)
geodns server for zones we own. supports:
- geo-routing by continent/country/asn
- optimistic updates with jam finality
- conflict resolution via serial + owner signatures

```bash
cargo run --bin netadapter-dns -- --dns-port 5353 --api-port 8053 \
  --geoip-db /usr/local/share/maxmind/GeoLite2-City.mmdb \
  --asn-db /usr/local/share/maxmind/GeoLite2-ASN.mmdb
```

### resolver (recursive + .alt)
anycast recursive resolver that:
- resolves normal domains via icann root
- resolves .alt domains from jam state
- supports doh/dot for encrypted dns

```bash
cargo run --bin netadapter-resolver -- --dns-port 53 --doh-port 443 \
  --anycast-ip 10.x.x.x
```

### service
jam service library with refine/accumulate pattern

## .alt namespace gateway (rfc 8244 compliant)

`.alt` is reserved by ietf for alternative namespaces. the resolver acts as
a **read-only gateway** to external naming protocols - no registration happens here.

supported namespaces (synced from authoritative sources):

```
*.dot.alt     - polkadot people chain (authoritative)
*.eth.alt     - ens (ethereum naming service)
*.hs.alt      - handshake domains
*.jam.alt     - jam ecosystem (from jam state)
```

### examples
```
rotko.jam.alt           - resolved from jam state
validator-01.dot.alt    - resolved from polkadot people chain
myapp.dot.alt           - resolved from polkadot people chain
vitalik.eth.alt         - resolved from ens
unstoppable.hs.alt      - resolved from handshake
```

### registration
domains are NOT registered through this resolver. each namespace has its own
authoritative registry:

| namespace | registry | how to register |
|-----------|----------|-----------------|
| `.dot.alt` | polkadot people chain | people chain extrinsics |
| `.eth.alt` | ens | ens app / contracts |
| `.hs.alt` | handshake | handshake protocol |
| `.jam.alt` | jam state | jam service |

the resolver syncs state from these sources and provides unified resolution.

### resolution flow
```
query: example.com      → recurse to icann root → normal answer
query: rotko.jam.alt    → lookup in jam state   → decentralized answer
```

## jam state structure

```
┌────────────────────────────────────────────────────────────────────┐
│ jam state (~3mb baseline, ~50kb/day updates)                       │
├────────────────────────────────────────────────────────────────────┤
│ alt_namespaces: HashMap<String, AltNamespace>                      │
│   - "jam" → { domains: [...], admin: pubkey, policy: open }        │
│   - "eth" → { domains: [...], admin: pubkey, policy: whitelist }   │
│   - "ibp" → { domains: [...], admin: pubkey, policy: open }        │
├────────────────────────────────────────────────────────────────────┤
│ blocklist_root: [u8; 32]  (merkle root, ~1.2mb bloom filter in da) │
├────────────────────────────────────────────────────────────────────┤
│ dnssec_anchors: Vec<DnskeyRecord>  (~50kb)                         │
├────────────────────────────────────────────────────────────────────┤
│ resolver_config: ResolverConfig  (~1kb)                            │
└────────────────────────────────────────────────────────────────────┘
```

## geodns region formats

records can be targeted to specific regions:

| format | example | description |
|--------|---------|-------------|
| `*` | `*` | global fallback |
| `continent:XX` | `continent:EU` | eu, na, as, af, oc, sa, an |
| `country:XX` | `country:DE` | iso 3166-1 alpha-2 |
| `asn:NNNNN` | `asn:13335` | autonomous system number |

## conflict resolution

for distributed participants updating the same zone:

1. **zone ownership** - each zone has owner pubkey
2. **serial-based locking** - updates include expected_serial
3. **nonce replay protection** - prevents duplicate submissions
4. **jam consensus ordering** - deterministic winner after 3 blocks
5. **optimistic rollback** - losers rolled back after finalization

```
participant A → optimistic update (serial=1→2) → local dns serves
participant B → optimistic update (serial=1→2) → conflicts
                              │
jam consensus ────────────────▼
                orders in block (deterministic)
                              │
after 3 blocks ───────────────▼
                finalized, loser rolled back
```

## anycast deployment

multiple ibp providers run resolver instances advertising same ip:

```
                    ┌─────────────────┐
                    │  anycast ip     │
                    │  10.x.x.x       │
                    └────────┬────────┘
                             │ bgp
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │ eu node  │        │ na node  │        │ as node  │
   └──────────┘        └──────────┘        └──────────┘
```

users configure `10.x.x.x` as dns, automatically route to nearest node.

## api endpoints

### dns-server
- `GET /` - server info
- `GET /zones` - list zones
- `POST /zones` - create zone
- `POST /zones/update` - update zone (optimistic or finalized)
- `POST /block` - advance block, trigger finalization

### resolver (gateway)
- `GET /` - resolver info + stats
- `GET /alt` - list supported namespaces
- `GET /alt/{namespace}` - list cached domains in namespace
- `GET /alt/{namespace}/{domain}` - get domain records
- dns queries on port 5354 (udp)

note: no registration endpoints - domains are registered at authoritative sources
