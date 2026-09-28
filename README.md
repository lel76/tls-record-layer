# TLS Record Layer

Parses and constructs TLS 1.2 and 1.3 record headers (the 5-byte framing layer) and provides a hook for marking 0-RTT early data records.

## Usage

```js
import {
  ContentType,
  ProtocolVersion,
  parseRecordHeader,
  buildRecordHeader,
  parseRecord,
  isEarlyData,
} from 'tls-record-layer';

// Build a header for a 256-byte application_data fragment
const header = buildRecordHeader(ContentType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, 256);
// header is a 5-byte Uint8Array: [23, 0x03, 0x03, 0x01, 0x00]

// Parse a record out of a buffer, marking it as 0-RTT early data
const someBuffer = new Uint8Array([23, 0x03, 0x03, 0x00, 0x01, 0x00]);
const record = parseRecord(someBuffer, { earlyData: true });
if (isEarlyData(record)) {
  // handle early data fragment at record.fragment
}
```

## Why this exists

Network middleboxes, packet capture tools, and TLS-terminating proxies frequently need to inspect the TLS record framing layer without performing a full handshake. This library handles just that 5-byte header and the fragment it bounds — nothing more. It does not decrypt, it does not parse handshake messages, and it does not track session state.

The trade-off: by staying at the record layer we avoid pulling in a full TLS stack, but the caller is responsible for any higher-level context. In particular, 0-RTT early data in TLS 1.3 is carried inside ordinary `application_data` records and has no wire-level marker distinguishing it from post-handshake data. This library therefore exposes an `earlyData` flag on the parsed record that the caller sets based on whether the server's `Finished` has been received yet. We do not guess.

## Edge cases you will hit

- **Fragment length cap.** RFC 8446 limits the fragment to 2^14 (16384) bytes. `buildRecordHeader` enforces this and throws `RangeError` above it. `parseRecordHeader` does not enforce it — it reports whatever is on the wire, because a too-long length on the wire is information the caller may want to log rather than have silently swallowed.
- **Legacy record version.** TLS 1.3 records carry `0x0303` (TLS 1.2) in the `legacy_record_version` field for compatibility, but `0x0301` is also legal. This library reports the on-wire value verbatim and does not normalise it to a "real" protocol version.
- **Fragment is a view, not a copy.** `parseRecord` returns `fragment` as a `subarray` into the input buffer for performance. If you mutate the input, the fragment changes. The `header` field is copied.

## Exports

- `ContentType` — frozen object: `CHANGE_CIPHER_SPEC` (20), `ALERT` (21), `HANDSHAKE` (22), `APPLICATION_DATA` (23).
- `ProtocolVersion` — frozen object: `SSL_3_0` (0x0300), `TLS_1_0` (0x0301), `TLS_1_1` (0x0302), `TLS_1_2` (0x0303), `TLS_1_3` (0x0304).
- `HandshakeType` — frozen object of handshake message type constants, including `END_OF_EARLY_DATA` (5).
- `parseRecordHeader(buffer)` — returns `{ contentType, version, length, headerLength, header }`.
- `buildRecordHeader(contentType, version, length)` — returns a 5-byte `Uint8Array`.
- `parseRecord(buffer, opts?)` — returns `{ ...header fields, fragment, earlyData }`.
- `isEarlyData(record)` — returns `true` only for `application_data` records flagged `earlyData: true`.

## Running the tests

```
node --test
```
