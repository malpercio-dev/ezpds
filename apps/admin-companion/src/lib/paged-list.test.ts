import { describe, it, expect, vi } from 'vitest';
import { createPagedList } from './paged-list.svelte';

interface Row {
  id: string;
}

describe('createPagedList', () => {
  it('loads the first page into a ready state', async () => {
    const fetchPage = vi.fn().mockResolvedValue({ items: [{ id: 'a' }, { id: 'b' }], cursor: 'c1' });
    const list = createPagedList<Row>(fetchPage);

    await list.load();

    expect(list.kind).toBe('ready');
    expect(list.items.map((r) => r.id)).toEqual(['a', 'b']);
    expect(list.cursor).toBe('c1');
    expect(list.paging).toBe(false);
    expect(fetchPage).toHaveBeenCalledWith();
  });

  it('surfaces a first-page failure as the error state', async () => {
    const list = createPagedList<Row>(vi.fn().mockRejectedValue({ code: 'UNREACHABLE' }));

    await list.load();

    expect(list.kind).toBe('error');
    expect(list.errorView?.chipLabel).toBe('unreachable');
    expect(list.items).toEqual([]);
  });

  it('appends the next page and advances the cursor', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: [{ id: 'a' }], cursor: 'c1' })
      .mockResolvedValueOnce({ items: [{ id: 'b' }], cursor: 'c2' });
    const list = createPagedList<Row>(fetchPage);

    await list.load();
    await list.loadMore();

    expect(list.items.map((r) => r.id)).toEqual(['a', 'b']);
    expect(list.cursor).toBe('c2');
    expect(fetchPage).toHaveBeenLastCalledWith('c1');
  });

  it('exhausts the list when the last page has no cursor', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: [{ id: 'a' }], cursor: 'c1' })
      .mockResolvedValueOnce({ items: [{ id: 'b' }], cursor: undefined });
    const list = createPagedList<Row>(fetchPage);

    await list.load();
    await list.loadMore();
    expect(list.cursor).toBeUndefined();

    // No cursor → loadMore is a no-op (does not fetch again).
    await list.loadMore();
    expect(fetchPage).toHaveBeenCalledTimes(2);
  });

  it('keeps shown rows and records a paging error when a page fetch fails', async () => {
    const fetchPage = vi
      .fn()
      .mockResolvedValueOnce({ items: [{ id: 'a' }], cursor: 'c1' })
      .mockRejectedValueOnce({ code: 'UNREACHABLE' });
    const list = createPagedList<Row>(fetchPage);

    await list.load();
    await list.loadMore();

    expect(list.kind).toBe('ready');
    expect(list.items.map((r) => r.id)).toEqual(['a']);
    expect(list.paging).toBe(false);
    expect(list.pagingError?.chipLabel).toBe('unreachable');
  });

  it('does not page while not ready', async () => {
    const fetchPage = vi.fn().mockRejectedValue({ code: 'UNREACHABLE' });
    const list = createPagedList<Row>(fetchPage);
    await list.load(); // → error
    await list.loadMore();
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });
});
