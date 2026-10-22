// pattern: Functional Core (the cursor) behind an Imperative Shell seam (`JournalStore`)

//! The shape every resumable ceremony shares: a typed step, a persisted cursor, idempotent step
//! work, and a resume entry point.
//!
//! A ceremony is resumable rather than atomic when one of its steps cannot join the transaction
//! that records it (a plc.directory publish, a remote PDS call). The journal makes the rule
//! explicit: each step's work runs only while the cursor is short of it, and the cursor advances
//! only after the work succeeded. A crash between the two re-runs that step on resume, so step work
//! must be idempotent; a crash anywhere else resumes at the recorded step.
//!
//! A step whose work commits its own cursor write in the same transaction (the strongest form)
//! makes its store's `save` for that step a no-op. That is the store's business, not the
//! journal's.

use std::future::Future;

/// One step of a ceremony. Variants are declared in execution order, so `Ord` is that order.
pub trait Step: Copy + Ord + std::fmt::Debug + Send + Sync {}

/// Where one ceremony instance's cursor lives. A store is bound to its instance (a child DID, a
/// migrating DID), so neither method takes a key.
pub trait JournalStore<S: Step>: Sync {
    type Error;
    /// The last recorded step, or `None` when the ceremony has not started.
    fn load(&self) -> impl Future<Output = Result<Option<S>, Self::Error>> + Send;
    /// Record that `step`'s work has completed.
    fn save(&self, step: S) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

pub struct Journal<S, St> {
    store: St,
    cursor: Option<S>,
}

impl<S: Step, St: JournalStore<S>> Journal<S, St> {
    /// Load the instance's cursor: the resume entry point, and the start of a fresh ceremony.
    pub async fn resume(store: St) -> Result<Self, St::Error> {
        let cursor = store.load().await?;
        Ok(Self { store, cursor })
    }

    pub fn cursor(&self) -> Option<S> {
        self.cursor
    }

    pub fn reached(&self, step: S) -> bool {
        self.cursor.is_some_and(|cursor| cursor >= step)
    }

    /// Record `step` as done. A step already reached is not re-recorded, and the cursor never
    /// moves backwards.
    pub async fn advance(&mut self, step: S) -> Result<(), St::Error> {
        if self.reached(step) {
            return Ok(());
        }
        self.store.save(step).await?;
        self.cursor = Some(step);
        Ok(())
    }

    /// Run `step`'s work unless the cursor has already reached it, then record it.
    pub async fn run<E, Fut>(&mut self, step: S, work: impl FnOnce() -> Fut) -> Result<(), E>
    where
        Fut: Future<Output = Result<(), E>>,
        E: From<St::Error>,
    {
        if self.reached(step) {
            return Ok(());
        }
        work().await?;
        self.advance(step).await.map_err(E::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Demo {
        One,
        Two,
        Three,
    }
    impl Step for Demo {}

    #[derive(Default)]
    struct Memory {
        cursor: Mutex<Option<Demo>>,
        saves: Mutex<Vec<Demo>>,
    }

    impl JournalStore<Demo> for &Memory {
        type Error = String;
        async fn load(&self) -> Result<Option<Demo>, String> {
            Ok(*self.cursor.lock().unwrap_or_else(|e| e.into_inner()))
        }
        async fn save(&self, step: Demo) -> Result<(), String> {
            *self.cursor.lock().unwrap_or_else(|e| e.into_inner()) = Some(step);
            self.saves
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(step);
            Ok(())
        }
    }

    async fn ceremony(
        store: &Memory,
        fail_at: Option<Demo>,
        ran: &Mutex<Vec<Demo>>,
    ) -> Result<(), String> {
        let mut journal = Journal::resume(store).await?;
        for step in [Demo::One, Demo::Two, Demo::Three] {
            journal
                .run(step, || async {
                    if fail_at == Some(step) {
                        return Err(format!("crash at {step:?}"));
                    }
                    ran.lock().unwrap_or_else(|e| e.into_inner()).push(step);
                    Ok(())
                })
                .await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_crash_resumes_at_the_recorded_step() {
        let store = Memory::default();
        let ran = Mutex::new(Vec::new());

        assert!(ceremony(&store, Some(Demo::Three), &ran).await.is_err());
        assert_eq!(
            *store.cursor.lock().unwrap_or_else(|e| e.into_inner()),
            Some(Demo::Two)
        );

        ceremony(&store, None, &ran)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Steps One and Two ran once; the resume picked up at Three.
        assert_eq!(
            *ran.lock().unwrap_or_else(|e| e.into_inner()),
            [Demo::One, Demo::Two, Demo::Three]
        );
        assert_eq!(
            *store.saves.lock().unwrap_or_else(|e| e.into_inner()),
            [Demo::One, Demo::Two, Demo::Three]
        );
    }

    #[tokio::test]
    async fn advance_never_moves_backwards() {
        let store = Memory::default();
        let mut journal = Journal::resume(&store)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        journal
            .advance(Demo::Two)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        journal
            .advance(Demo::One)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(journal.cursor(), Some(Demo::Two));
        assert!(journal.reached(Demo::One));
        assert!(!journal.reached(Demo::Three));
    }
}
