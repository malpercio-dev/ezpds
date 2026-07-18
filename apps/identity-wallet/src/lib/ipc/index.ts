/**
 * Typed wrappers for all Tauri IPC commands, split into per-domain modules.
 *
 * The "`invoke()` lives only here" invariant holds at directory granularity: every
 * module under `$lib/ipc/` may call `invoke()`, and page components import the wrappers
 * from `$lib/ipc` (this barrel) instead of calling `invoke()` directly. Pure helpers that
 * are policy gates rather than command wrappers live outside this directory (the biometric
 * gate is `$lib/biometric.ts`); `isCodedError` (a generic IPC error guard) is the one pure
 * helper kept here, in `./errors`, because it is used to narrow the errors these commands reject with.
 */
export * from './account';
export * from './oauth';
export * from './appearance';
export * from './claim';
export * from './identity';
export * from './monitor';
export * from './recovery';
export * from './removal';
export * from './migration';
export * from './handle-change';
export * from './rotation';
export * from './rekey';
export * from './agents';
export * from './app-passwords';
export { isCodedError } from './errors';
