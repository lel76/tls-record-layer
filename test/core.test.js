import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ContentType,
  ProtocolVersion,
  HandshakeType,
  parseRecordHeader,
  buildRecordHeader,
  parseRecord,
  isEarlyData,
} from '../src/index.js';

/**
 * Helper: concatenate a header and a fragment into a single Uint8Array.
 */
function makeRecord(headerBytes, fragmentBytes) {
  const out = new Uint8Array(headerBytes.length + fragmentBytes.length);
  out.set(headerBytes, 0);
  out.set(fragmentBytes, headerBytes.length);
  return out;
}

test('parseRecordHeader reads a standard TLS 1.2 handshake header', () => {
  // ContentType.HANDSHAKE=22, version 0x0303, length 4
  const buf = new Uint8Array([22, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
  const h = parseRecordHeader(buf);
  assert.equal(h.contentType, 22);
  assert.equal(h.version, 0x0303);
  assert.equal(h.length, 4);
  assert.equal(h.headerLength, 5);
  assert.deepEqual(Array.from(h.header), [22, 0x03, 0x03, 0x00, 0x04]);
});

test('parseRecordHeader throws RangeError on fewer than 5 bytes', () => {
  assert.throws(
    () => parseRecordHeader(new Uint8Array([22, 0x03, 0x03])),
    RangeError
  );
});

test('parseRecordHeader throws TypeError on non-Uint8Array input', () => {
  assert.throws(() => parseRecordHeader([1, 2, 3, 4, 5]), TypeError);
  assert.throws(() => parseRecordHeader('hello'), TypeError);
});

test('parseRecordHeader handles a zero-length fragment', () => {
  const buf = new Uint8Array([23, 0x03, 0x03, 0x00, 0x00]);
  const h = parseRecordHeader(buf);
  assert.equal(h.length, 0);
});

test('parseRecordHeader handles the maximum fragment length (16384)', () => {
  const buf = new Uint8Array([23, 0x03, 0x03, 0x40, 0x00]);
  const h = parseRecordHeader(buf);
  assert.equal(h.length, 16384);
});

test('buildRecordHeader produces the correct 5 bytes', () => {
  const h = buildRecordHeader(ContentType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, 256);
  assert.deepEqual(Array.from(h), [23, 0x03, 0x03, 0x01, 0x00]);
});

test('buildRecordHeader round-trips with parseRecordHeader', () => {
  const built = buildRecordHeader(ContentType.ALERT, ProtocolVersion.TLS_1_2, 2);
  const parsed = parseRecordHeader(built);
  assert.equal(parsed.contentType, ContentType.ALERT);
  assert.equal(parsed.version, ProtocolVersion.TLS_1_2);
  assert.equal(parsed.length, 2);
});

test('buildRecordHeader rejects length > 16384', () => {
  assert.throws(
    () => buildRecordHeader(23, 0x0303, 16385),
    RangeError
  );
});

test('buildRecordHeader rejects negative length', () => {
  assert.throws(() => buildRecordHeader(23, 0x0303, -1), RangeError);
});

test('buildRecordHeader rejects non-integer contentType', () => {
  assert.throws(() => buildRecordHeader(22.5, 0x0303, 10), RangeError);
});

test('buildRecordHeader rejects version > 65535', () => {
  assert.throws(() => buildRecordHeader(23, 65536, 0), RangeError);
});

test('buildRecordHeader rejects NaN arguments', () => {
  assert.throws(() => buildRecordHeader(NaN, 0x0303, 0), TypeError);
});

test('parseRecord returns header and fragment view', () => {
  const header = buildRecordHeader(ContentType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, 3);
  const fragment = new Uint8Array([0x01, 0x02, 0x03]);
  const buf = makeRecord(header, fragment);
  const rec = parseRecord(buf);
  assert.equal(rec.contentType, ContentType.APPLICATION_DATA);
  assert.equal(rec.length, 3);
  assert.deepEqual(Array.from(rec.fragment), [1, 2, 3]);
  // fragment is a view: mutating the source mutates the fragment.
  buf[5] = 0xff;
  assert.equal(rec.fragment[0], 0xff);
});

test('parseRecord throws RangeError when fragment is truncated', () => {
  // Declares 10 bytes of fragment but only provides 2.
  const buf = new Uint8Array([23, 0x03, 0x03, 0x00, 0x0a, 0x01, 0x02]);
  assert.throws(() => parseRecord(buf), RangeError);
});

test('parseRecord accepts earlyData flag', () => {
  const header = buildRecordHeader(ContentType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, 1);
  const buf = makeRecord(header, new Uint8Array([0x00]));
  const rec = parseRecord(buf, { earlyData: true });
  assert.equal(rec.earlyData, true);
  assert.equal(isEarlyData(rec), true);
});

test('isEarlyData returns false for a non-early-data application_data record', () => {
  const header = buildRecordHeader(ContentType.APPLICATION_DATA, ProtocolVersion.TLS_1_2, 1);
  const buf = makeRecord(header, new Uint8Array([0x00]));
  const rec = parseRecord(buf);
  assert.equal(isEarlyData(rec), false);
});

test('isEarlyData returns false for a handshake record even if flagged', () => {
  const header = buildRecordHeader(ContentType.HANDSHAKE, ProtocolVersion.TLS_1_2, 1);
  const buf = makeRecord(header, new Uint8Array([0x00]));
  const rec = parseRecord(buf, { earlyData: true });
  // Early data is only carried in application_data records.
  assert.equal(isEarlyData(rec), false);
});

test('isEarlyData returns false for null or non-object input', () => {
  assert.equal(isEarlyData(null), false);
  assert.equal(isEarlyData(undefined), false);
  assert.equal(isEarlyData('hello'), false);
});

test('parseRecordHeader preserves legacy version 0x0301 on a TLS 1.3-style record', () => {
  // TLS 1.3 records may carry 0x0301 or 0x0303 in legacy_record_version.
  // We report the on-wire value faithfully rather than normalising.
  const buf = new Uint8Array([23, 0x03, 0x01, 0x00, 0x01, 0xaa]);
  const h = parseRecordHeader(buf);
  assert.equal(h.version, 0x0301);
});

test('HandshakeType exposes END_OF_EARLY_DATA', () => {
  // Sanity check that the constant we expose matches RFC 8446 §4.
  assert.equal(HandshakeType.END_OF_EARLY_DATA, 5);
});

test('ContentType and ProtocolVersion are frozen', () => {
  assert.throws(() => { ContentType.ALERT = 99; }, TypeError);
  assert.throws(() => { ProtocolVersion.TLS_1_3 = 99; }, TypeError);
});
