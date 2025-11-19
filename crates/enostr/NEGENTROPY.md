# Negentropy Protocol Implementation (NIP-77)

Efficient set reconciliation for Nostr event synchronization.

## Overview

Negentropy reduces bandwidth by 10-100x compared to traditional REQ/EVENT protocol by identifying differences between client and relay event sets without transferring full events.

## Architecture

### Core Components

1. **NegentropySync** (`src/relay/negentropy.rs`)
   - Manages single sync session
   - Stores event IDs and timestamps
   - Handles initiate/reconcile operations
   - Tracks filter hash for session identity

2. **NegentropyManager** (`src/relay/negentropy.rs`)
   - Manages multiple sync sessions per relay
   - Maps subscription IDs to sync sessions
   - Cleans up stale sessions (>5min)

3. **RelayPool Integration** (`src/relay/pool.rs`)
   - Auto-negotiation: tries NEG-OPEN, falls back to REQ
   - Per-relay negentropy manager
   - Single-filter optimization (multi-filter uses REQ)

4. **Filter Hashing** (`src/filter_hash.rs`)
   - Simple hash for session tracking
   - SHA256 for cryptographic needs

### Protocol Messages (NIP-77 Standard)

**Client → Relay:**
- `["NEG-OPEN", <sub_id>, <filter>, <initial_msg_hex>]` - JSON, initiates sync
- `["NEG-MSG", <sub_id>, <hex_payload>]` - JSON with hex-encoded reconciliation data
- `["NEG-CLOSE", <sub_id>]` - JSON, terminates sync

**Relay → Client:**
- `["NEG-MSG", <sub_id>, <hex_payload>]` - JSON with hex-encoded reconciliation response
- `["NEG-ERR", <sub_id>, <error>]` - JSON error message
- Falls back to standard EVENT/EOSE on errors

All messages use standard JSON format with hex-encoded binary data (strfry compatible).

## Usage

### Basic Subscription (Auto-Negentropy)

```rust
use enostr::{RelayPool, Filter};

let mut pool = RelayPool::new();
// Negentropy enabled by default

let filter = Filter::new().kinds(vec![1]).limit(100);
pool.subscribe("my-sub".to_string(), vec![filter]);
// → Sends NEG-OPEN for single filter
// → Falls back to REQ for multi-filter
```

### Explicit Control

```rust
// Disable globally
pool.set_use_negentropy(false);

// Or per-subscription
pool.subscribe_with_negentropy(
    "my-sub".to_string(),
    vec![filter],
    false // force REQ
);
```

### Direct Negentropy API

```rust
use enostr::{NegentropySync, hash_filter};
use nostrdb::Note;

// Create sync
let filter_hash = hash_filter(&filter);
let mut sync = NegentropySync::new(filter_hash);

// Add local events
for note in local_notes {
    sync.add_note(&note)?;
}

// Initiate
let init_msg = sync.initiate()?;
// → Send as NEG-MSG binary frame

// Reconcile relay response
let (next_msg, have_ids, need_ids) = sync.reconcile_client(&relay_msg)?;
// have_ids: events we have that relay doesn't
// need_ids: events relay has that we don't
// next_msg: continue reconciliation or None if done
```

## Protocol Flow

```
Client                          Relay
  |                              |
  |-- NEG-OPEN <sub> <filter> ->|
  |                              | (relay builds its set)
  |<-------- NEG-MSG <msg> ------|
  |                              |
  | (reconcile, identify diffs)  |
  |                              |
  |-- NEG-MSG <msg> ------------>|
  |                              |
  |<-------- NEG-MSG <msg> ------| (or done)
  |                              |
  | ... iterates until sync ...  |
  |                              |
  |<-------- EOSE ---------------|
  |                              |
  |-- REQ <needed_ids> --------->| (fetch missing)
  |<-------- EVENT --------------|
```

## Implementation Details

### When Negentropy is Used

✅ **Uses NEG-OPEN:**
- Single Filter subscription
- Websocket relay
- Negentropy enabled (default)

❌ **Falls back to REQ:**
- Multiple filters in subscription
- Multicast/WebRTC relay
- Negentropy disabled
- Relay returns NEG-ERR
- Filter too complex (relay decision)

### Message Encoding

- `NEG-OPEN`/`NEG-CLOSE`/`NEG-ERR`: JSON text frames
- `NEG-MSG`: Binary WebSocket frames (protocol version 0x61)

### Storage & Sealing

Events must be sorted by (timestamp, id) before sync:

```rust
sync.add_note(&note)?; // unsealed, mutable
sync.seal()?;          // sorts, deduplicates, seals
sync.initiate()?;      // creates initial message
```

### Error Handling

Relays may respond with:
- `NEG-ERR` if negentropy unsupported → client falls back to REQ
- Standard `EOSE` when sync complete
- `NOTICE` for general errors

## Testing

```bash
# All negentropy tests (7 tests total)
cargo test negentropy

# Unit tests only
cargo test negentropy_test

# Integration tests only
cargo test negentropy_integration

# Check build
cargo check
```

**Test Coverage:**
- ✅ Basic sync creation and sealing
- ✅ Manager multi-session handling
- ✅ Stale session cleanup
- ✅ Message format validation (NEG-OPEN, NEG-CLOSE, NEG-MSG)
- ✅ Filter hashing consistency
- ✅ RelayPool negentropy toggle
- ✅ Explicit negentropy control per subscription

## Performance

**Bandwidth Comparison (1000 events):**
- REQ/EVENT: ~1MB (full event transfer)
- Negentropy: ~10-50KB (only IDs + fingerprints)

**Optimal For:**
- Mobile clients (limited bandwidth)
- Slow networks
- Large event sets
- Periodic resync

**Not Optimal For:**
- Real-time streaming (use REQ)
- Single event fetch (use REQ)
- Initial sync with 0 local events (same as REQ)

## See Also

- [NIP-77: Negentropy Protocol](https://nips.nostr.com/77)
- [rust-negentropy crate](https://crates.io/crates/negentropy)
- TypeScript implementation: `~/src/iris-client/src/lib/ndk/negentropy/`

## Future Work

- [x] Handle binary NEG-MSG responses in RelayPool event loop
- [x] Add RelayPool API for negentropy session management
- [ ] Implement frame size limits for mobile optimization
- [ ] Add metrics (bandwidth saved, sync duration)
- [ ] Cache sealed storage between app restarts
- [ ] Support streaming negentropy (incremental updates)
- [ ] Full end-to-end test with mock relay server
