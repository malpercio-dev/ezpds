import { describe, it, expect } from 'vitest';
import { hasPdsCapability, type PdsCapabilities } from './account';

/**
 * The capability gate's whole job is to be safe when it does not know. Every "no answer"
 * shape — a host that sent no `custos` extension, a probe that has not run, an unreachable
 * host — must read as "do not offer the feature", never as "offer it anyway".
 */
describe('hasPdsCapability', () => {
  const custos: PdsCapabilities = {
    version: '0.8.1',
    reached: true,
    capabilities: ['createCeremony', 'escrow', 'sovereignSessions'],
  };

  it('reports an advertised capability', () => {
    expect(hasPdsCapability(custos, 'createCeremony')).toBe(true);
    expect(hasPdsCapability(custos, 'escrow')).toBe(true);
  });

  it('does not infer unadvertised capabilities from advertised ones', () => {
    expect(hasPdsCapability(custos, 'agents')).toBe(false);
    expect(hasPdsCapability(custos, 'didWebHosting')).toBe(false);
  });

  it('reads a non-Custos host as offering nothing', () => {
    // What a reference PDS, rsky-pds, or millipds response yields: no `custos` object.
    const referencePds: PdsCapabilities = { version: null, reached: true, capabilities: [] };
    expect(hasPdsCapability(referencePds, 'createCeremony')).toBe(false);
    expect(hasPdsCapability(referencePds, 'sovereignSessions')).toBe(false);
  });

  it('reads an unprobed or failed probe as offering nothing', () => {
    expect(hasPdsCapability(null, 'escrow')).toBe(false);
    expect(hasPdsCapability(undefined, 'escrow')).toBe(false);
  });

  it('distinguishes a host that advertises nothing from one that was never asked', () => {
    // Both withhold every capability, so `hasPdsCapability` agrees on them — that is the
    // safe default. The difference lives in `reached`, and only a gate that states a fact
    // about the user's server ("this one can't create identities") may read it: saying
    // that about an unreachable host would be a false accusation.
    const reachedAndEmpty: PdsCapabilities = { version: null, reached: true, capabilities: [] };
    const neverAsked: PdsCapabilities = { version: null, reached: false, capabilities: [] };

    expect(hasPdsCapability(reachedAndEmpty, 'createCeremony')).toBe(false);
    expect(hasPdsCapability(neverAsked, 'createCeremony')).toBe(false);
    expect(reachedAndEmpty.reached).toBe(true);
    expect(neverAsked.reached).toBe(false);
  });

  it('answers for a capability name this build does not know', () => {
    const newer: PdsCapabilities = { version: '9.9.9', reached: true, capabilities: ['someFutureThing'] };
    expect(hasPdsCapability(newer, 'someFutureThing')).toBe(true);
    expect(hasPdsCapability(newer, 'escrow')).toBe(false);
  });
});
