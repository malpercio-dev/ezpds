import { describe, it, expect } from 'vitest';
import { parsePairingPayload } from './pairing-payload';

describe('parsePairingPayload', () => {
  it('accepts a valid payload', () => {
    expect(parsePairingPayload('{"relayUrl":"https://relay.ezpds.com","pairingCode":"abc123"}')).toEqual({
      relayUrl: 'https://relay.ezpds.com',
      pairingCode: 'abc123',
    });
  });

  it('trims surrounding whitespace from both fields', () => {
    expect(
      parsePairingPayload('{"relayUrl":"  https://relay.ezpds.com  ","pairingCode":"  abc123  "}'),
    ).toEqual({
      relayUrl: 'https://relay.ezpds.com',
      pairingCode: 'abc123',
    });
  });

  it('rejects a payload with an extra key', () => {
    expect(
      parsePairingPayload('{"relayUrl":"https://relay.ezpds.com","pairingCode":"abc123","debug":true}'),
    ).toBeNull();
  });

  it('rejects a payload with only one of the two keys', () => {
    expect(parsePairingPayload('{"relayUrl":"https://relay.ezpds.com"}')).toBeNull();
    expect(parsePairingPayload('{"pairingCode":"abc123"}')).toBeNull();
  });

  it('rejects a payload with no keys', () => {
    expect(parsePairingPayload('{}')).toBeNull();
  });

  it('rejects a payload where a value is the wrong type (number)', () => {
    expect(parsePairingPayload('{"relayUrl":123,"pairingCode":"abc123"}')).toBeNull();
  });

  it('rejects a payload where a value is the wrong type (null)', () => {
    expect(parsePairingPayload('{"relayUrl":null,"pairingCode":"abc123"}')).toBeNull();
  });

  it('rejects a payload where both values are the wrong type', () => {
    expect(parsePairingPayload('{"relayUrl":null,"pairingCode":42}')).toBeNull();
  });

  it('rejects an empty-string relayUrl', () => {
    expect(parsePairingPayload('{"relayUrl":"","pairingCode":"abc123"}')).toBeNull();
  });

  it('rejects an empty-string pairingCode', () => {
    expect(parsePairingPayload('{"relayUrl":"https://relay.ezpds.com","pairingCode":""}')).toBeNull();
  });

  it('rejects a value that is whitespace-only after trimming', () => {
    expect(parsePairingPayload('{"relayUrl":"   ","pairingCode":"abc123"}')).toBeNull();
  });

  it('rejects malformed JSON', () => {
    expect(parsePairingPayload('not json at all')).toBeNull();
    expect(parsePairingPayload('{relayUrl: "https://relay.ezpds.com"')).toBeNull();
  });

  it('rejects an empty string', () => {
    expect(parsePairingPayload('')).toBeNull();
  });

  it('rejects a JSON array', () => {
    expect(parsePairingPayload('["https://relay.ezpds.com","abc123"]')).toBeNull();
  });

  it('rejects a bare JSON string', () => {
    expect(parsePairingPayload('"https://relay.ezpds.com"')).toBeNull();
  });

  it('rejects a bare JSON number', () => {
    expect(parsePairingPayload('42')).toBeNull();
  });

  it('rejects JSON null', () => {
    expect(parsePairingPayload('null')).toBeNull();
  });
});
