// pattern: Imperative Shell

use std::ops::Deref;

use axum::extract::FromRef;
use custos_core::CoreState;

/// The state every Spaces handler extracts: the shared [`CoreState`] plus the Spaces feature's own
/// fields (none today; the space type cache is core, since the consent page reads it too). Core
/// helpers take `&CoreState`; a `&SpacesState` reaches them through [`Deref`].
#[derive(Clone)]
pub struct SpacesState {
    pub core: CoreState,
}

impl SpacesState {
    pub fn new(core: CoreState) -> Self {
        Self { core }
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
