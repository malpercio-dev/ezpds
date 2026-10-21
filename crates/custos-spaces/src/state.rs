// pattern: Imperative Shell

use std::ops::Deref;

use axum::extract::FromRef;
use custos_core::CoreState;

use crate::consent::{new_space_type_cache, SpaceTypeCache};

/// The state every Spaces handler extracts: the shared [`CoreState`] plus the Spaces feature's own
/// fields. Core helpers take `&CoreState`; a `&SpacesState` reaches them through [`Deref`].
#[derive(Clone)]
pub struct SpacesState {
    pub core: CoreState,
    /// TTL cache of resolved space type declarations, shared by the consent page and the
    /// collection fallback of a bare `space:` grant.
    pub space_type_cache: SpaceTypeCache,
}

impl SpacesState {
    pub fn new(core: CoreState) -> Self {
        Self {
            core,
            space_type_cache: new_space_type_cache(),
        }
    }
}

// Field access only, not a smart pointer: lets `state.db` and `helper(&state)` compile where a
// helper takes `&CoreState`. Writes go through `state.core`.
impl Deref for SpacesState {
    type Target = CoreState;

    fn deref(&self) -> &CoreState {
        &self.core
    }
}

impl FromRef<SpacesState> for CoreState {
    fn from_ref(state: &SpacesState) -> CoreState {
        state.core.clone()
    }
}
