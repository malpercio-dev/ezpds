// pattern: Functional Core
//
// Shared between get_preferences.rs and put_preferences.rs: which `app.bsky` preference
// $types are gated to a full access-scope token, matching the reference PDS
// (`packages/pds/src/actor-store/preference/util.ts`'s `isFullAccessOnlyPref`). An
// app-password token — privileged or not — never reads or writes these; declaring a
// preference type here only ever narrows what an app password can see or manage, never what
// a full access-scope token can.

/// A preference `$type` may carry data a client authenticated with an app password should
/// never see or overwrite (e.g. `personalDetailsPref` can hold a birth date).
pub fn is_full_access_only_pref(ty: &str) -> bool {
    ty == "app.bsky.actor.defs#personalDetailsPref"
}
