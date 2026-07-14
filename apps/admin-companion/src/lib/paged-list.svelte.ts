// pattern: Imperative Shell (reactive controller)
//
// A cursor-paged relay list, shared by Codes and Transfers. Both fetch a first page,
// then append older pages via the relay's opaque cursor with a "Load more" button, and
// both keep a failed *page* fetch from clobbering the rows already shown — the paging
// error renders inline next to the button instead.
//
// The controller owns the list state machine (loading / error / ready-with-cursor) and
// the separate paging-error slot; the caller supplies one `fetchPage(cursor?)` adapter
// that maps its relay call's page shape onto `{ items, cursor }`.

import { classifyRelayError, type ErrorView } from './errors';

export type PagedListState<T> =
  | { kind: 'loading' }
  | { kind: 'error'; view: ErrorView }
  | { kind: 'ready'; items: T[]; cursor?: string; paging: boolean };

export interface PagedList<T> {
  /** The list state, for switching on `.kind` in the template. */
  readonly state: PagedListState<T>;
  /** The current kind, narrowed once so the template needn't re-narrow the getter. */
  readonly kind: PagedListState<T>['kind'];
  /** The rows so far (empty until ready). */
  readonly items: T[];
  /** The next-page cursor, or `undefined` when the list is exhausted / not ready. */
  readonly cursor: string | undefined;
  /** Whether a "Load more" fetch is in flight. */
  readonly paging: boolean;
  /** The whole-list failure (the `error` state's view), if any. */
  readonly errorView: ErrorView | undefined;
  /** A failed *page* fetch that left the shown rows intact, if any. */
  readonly pagingError: ErrorView | undefined;
  /** (Re)load the first page from scratch. */
  load(): Promise<void>;
  /** Fetch the next page and append it, newest-first order preserved. */
  loadMore(): Promise<void>;
}

export function createPagedList<T>(
  fetchPage: (cursor?: string) => Promise<{ items: T[]; cursor?: string }>,
): PagedList<T> {
  let state = $state<PagedListState<T>>({ kind: 'loading' });
  // A failed page fetch never clobbers the rows already shown — it renders inline next
  // to the paging button instead.
  let pagingError = $state<ErrorView | undefined>(undefined);

  async function load(): Promise<void> {
    state = { kind: 'loading' };
    pagingError = undefined;
    try {
      const first = await fetchPage();
      state = { kind: 'ready', items: first.items, cursor: first.cursor, paging: false };
    } catch (e) {
      state = { kind: 'error', view: classifyRelayError(e) };
    }
  }

  async function loadMore(): Promise<void> {
    if (state.kind !== 'ready' || !state.cursor || state.paging) return;
    state = { ...state, paging: true };
    pagingError = undefined;
    try {
      const next = await fetchPage(state.cursor);
      // A concurrent reload (Refresh) can move the list out of `ready` mid-flight; only
      // append when it is still the ready list this page was fetched for.
      if (state.kind !== 'ready') return;
      state = {
        kind: 'ready',
        items: [...state.items, ...next.items],
        cursor: next.cursor,
        paging: false,
      };
    } catch (e) {
      // A failed page keeps what is already shown; the error renders by the button.
      pagingError = classifyRelayError(e);
      if (state.kind === 'ready') state = { ...state, paging: false };
    }
  }

  return {
    get state() {
      return state;
    },
    get kind() {
      return state.kind;
    },
    get items() {
      return state.kind === 'ready' ? state.items : [];
    },
    get cursor() {
      return state.kind === 'ready' ? state.cursor : undefined;
    },
    get paging() {
      return state.kind === 'ready' ? state.paging : false;
    },
    get errorView() {
      return state.kind === 'error' ? state.view : undefined;
    },
    get pagingError() {
      return pagingError;
    },
    load,
    loadMore,
  };
}
