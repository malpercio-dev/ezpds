/**
 * Type guard for Tauri IPC error objects with a `code` field.
 * Use in catch blocks to distinguish typed IPC errors from generic JS errors.
 */
export function isCodedError(raw: unknown): raw is { code: string } {
  return (
    typeof raw === 'object' &&
    raw !== null &&
    'code' in raw &&
    typeof (raw as { code: unknown }).code === 'string'
  );
}
