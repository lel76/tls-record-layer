/**
 * TLS record layer parser and constructor for TLS 1.2 and TLS 1.3.
 *
 * Design decisions (stated plainly so the tests and the reader share one mind):
 *
 * 1. We only handle the 5-byte TLS record header and the fragment it carries.
 *    We do NOT parse the inner handshake, alert, or application-data payloads
 *    beyond what is needed to identify 0-RTT early data. Early data is signalled
 *    in TLS 1.3 by an application_data record (type 0x17) that arrives before
 *    the handshake completes; we expose isEarlyData(record) which returns true
 *    for application_data records flagged as early. The flag is carried on the
 *    parsed record object so callers can mark it after inspecting context.
 *
 * 2. ContentType and ProtocolVersion are exposed as plain numeric constants
 *    (frozen objects), not TypeScript enums. This keeps the library runtime-free
 *    and lets callers compare with === against raw bytes if they want.
 *
 * 3. TLS 1.3 uses the legacy_record_version field (0x0303) for backwards
 *    compatibility. We preserve whatever value is on the wire rather than
 *    normalising — a 1.3 record with 0x0301 is legal on the wire and we report
 *    it faithfully. The caller decides what to enforce.
 */

/**
 * TLS record content types, per RFC 8446 §5.1 and RFC 5246 §6.2.1.
 */
export const ContentType = Object.freeze({
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23,
});

/**
 * Protocol versions as they appear in the record header.
 * TLS 1.2 = 0x0303, TLS 1.0 = 0x0301. TLS 1.3 records carry 0x0303
 * in the legacy_record_version field for middlebox compatibility.
 */
export const ProtocolVersion = Object.freeze({
  SSL_3_0: 0x0300,
  TLS_1_0: 0x0301,
  TLS_1_1: 0x0302,
  TLS_1_2: 0x0303,
  TLS_1_3: 0x0304, // appears in supported_versions extension, not in record header
});

/**
 * TLS handshake message types, per RFC 8446 §4 and RFC 5246 §7.4.
 * Included because early-data detection in TLS 1.3 requires knowing that a
 * ClientHello (type 1) has already been seen.
 */
export const HandshakeType = Object.freeze({
  HELLO_REQUEST: 0,
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  NEW_SESSION_TICKET: 4,
  END_OF_EARLY_DATA: 5,
  ENCRYPTED_EXTENSIONS: 8,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_HELLO_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
});

/**
 * @typedef {Object} ParsedRecordHeader
 * @property {number} contentType    - The 1-byte content type (see ContentType).
 * @property {number} version        - The 2-byte legacy_record_version (big-endian).
 * @property {number} length         - The 2-byte fragment length (big-endian).
 * @property {number} headerLength   - Always 5 for a standard TLS record header.
 * @property {Uint8Array} header     - The 5 header bytes (a copy).
 */

/**
 * @typedef {Object} ParsedRecord
 * @property {number} contentType
 * @property {number} version
 * @property {number} length
 * @property {number} headerLength
 * @property {Uint8Array} header
 * @property {Uint8Array} fragment   - The fragment bytes (a view into the input).
 * @property {boolean}  earlyData   - True if this record is 0-RTT early data.
 */

/**
 * Parse a 5-byte TLS record header from the start of a buffer.
 *
 * We deliberately do NOT consume the fragment here — the caller may want to
 * inspect how many bytes remain. Use parseRecord() to also slice the fragment.
 *
 * @param {Uint8Array} buffer - Buffer containing at least 5 bytes of a record header.
 * @returns {ParsedRecordHeader}
 * @throws {TypeError} if buffer is not a Uint8Array.
 * @throws {RangeError} if fewer than 5 bytes are available.
 */
export function parseRecordHeader(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('buffer must be a Uint8Array');
  }
  if (buffer.length < 5) {
    throw new RangeError(
      `need at least 5 bytes for a TLS record header, got ${buffer.length}`
    );
  }
  const contentType = buffer[0];
  // Record version is big-endian: high byte first.
  const version = (buffer[1] << 8) | buffer[2];
  const length = (buffer[3] << 8) | buffer[4];
  return {
    contentType,
    version,
    length,
    headerLength: 5,
    // Copy so the caller can't mutate our view of the header by accident.
    header: buffer.slice(0, 5),
  };
}

/**
 * Build a 5-byte TLS record header.
 *
 * @param {number} contentType - Must be 0–255.
 * @param {number} version     - Must be 0–65535.
 * @param {number} length      - Fragment length, must be 0–16384 (2^14) per RFC 8446 §5.1.
 *                               We enforce the cap because exceeding it is a protocol
 *                               violation that middleboxes will reject; better to fail
 *                               here than on the wire.
 * @returns {Uint8Array} A new 5-byte header.
 * @throws {TypeError} if arguments are not finite numbers.
 * @throws {RangeError} if any value is out of its valid range.
 */
export function buildRecordHeader(contentType, version, length) {
  if (
    !Number.isFinite(contentType) ||
    !Number.isFinite(version) ||
    !Number.isFinite(length)
  ) {
    throw new TypeError('contentType, version, and length must be finite numbers');
  }
  if (contentType < 0 || contentType > 255 || !Number.isInteger(contentType)) {
    throw new RangeError(`contentType must be an integer in [0, 255], got ${contentType}`);
  }
  if (version < 0 || version > 65535 || !Number.isInteger(version)) {
    throw new RangeError(`version must be an integer in [0, 65535], got ${version}`);
  }
  // RFC 8446 §5.1: The length MUST NOT exceed 2^14 bytes. We use a strict cap.
  if (length < 0 || length > 16384 || !Number.isInteger(length)) {
    throw new RangeError(
      `length must be an integer in [0, 16384], got ${length}`
    );
  }
  const out = new Uint8Array(5);
  out[0] = contentType;
  out[1] = (version >>> 8) & 0xff;
  out[2] = version & 0xff;
  out[3] = (length >>> 8) & 0xff;
  out[4] = length & 0xff;
  return out;
}

/**
 * Parse a complete TLS record (header + fragment) from the start of a buffer.
 *
 * The fragment is returned as a subarray (view) into the input buffer to avoid
 * a copy; the header is copied because callers frequently log or store it.
 *
 * @param {Uint8Array} buffer - Buffer containing a full record (header + fragment).
 * @param {Object} [opts]
 * @param {boolean} [opts.earlyData=false] - Mark this record as 0-RTT early data.
 *     The library does not track handshake state; the caller sets this based on
 *     whether a Finished message has been received yet.
 * @returns {ParsedRecord}
 * @throws {TypeError} if buffer is not a Uint8Array.
 * @throws {RangeError} if the buffer does not contain a full record.
 */
export function parseRecord(buffer, opts) {
  const earlyData = opts ? opts.earlyData === true : false;
  const header = parseRecordHeader(buffer);
  const total = header.headerLength + header.length;
  if (buffer.length < total) {
    throw new RangeError(
      `record declares ${header.length} fragment bytes but only ${
        buffer.length - header.headerLength
      } are available`
    );
  }
  return {
    contentType: header.contentType,
    version: header.version,
    length: header.length,
    headerLength: header.headerLength,
    header: header.header,
    fragment: buffer.subarray(header.headerLength, total),
    earlyData,
  };
}

/**
 * Determine whether a parsed record carries 0-RTT early data.
 *
 * In TLS 1.3, early data is sent as application_data records (type 0x17)
 * before the server's Finished. Because the record layer itself has no marker
 * for "this is early data", detection requires context: the caller must know
 * whether the handshake has completed. This function therefore returns true
 * only when the record is application_data AND the caller has flagged it as
 * early via parseRecord(buffer, { earlyData: true }) or by setting
 * record.earlyData = true.
 *
 * We do NOT guess based on position in the stream — that would be unreliable
 * and would invent a contract the record layer does not actually provide.
 *
 * @param {ParsedRecord} record
 * @returns {boolean}
 */
export function isEarlyData(record) {
  if (!record || typeof record !== 'object') {
    return false;
  }
  return (
    record.contentType === ContentType.APPLICATION_DATA &&
    record.earlyData === true
  );
}
