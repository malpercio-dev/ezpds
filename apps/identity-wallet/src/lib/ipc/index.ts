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
export * from './diagnostics';
export * from './claim';
export * from './identity';
export * from './password-unlock';
export * from './monitor';
export * from './recovery';
export * from './share-recovery';
export * from './removal';
export * from './migration';
export * from './disaster-recovery';
export * from './endpoint-repair';
export * from './handle-change';
export * from './rotation';
export * from './rekey';
export * from './self-held-kit';
export * from './agents';
export * from './oauth-consent';
export * from './qr-scan';
export * from './app-passwords';
export * from './blob-backup';
export * from './repo-backup';
export * from './notifications';
export * from './notification-routes';
export { isCodedError } from './errors';
