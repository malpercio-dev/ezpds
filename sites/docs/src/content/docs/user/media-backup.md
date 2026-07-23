---
title: Backing up your content
description: Keep your own verified copy of your posts and media in iCloud — the one backup that survives your server failing.
---

Your server holds two kinds of thing for you: your **posts** — the records, every
post, like, follow, and profile edit — and your **media** — the photos and video
attached to them, plus your avatar and banner. Obsign can keep a second copy of
**both**, held by **you** in your own iCloud Drive, so a server that loses them —
or goes away entirely — isn't the end of the story.

Both are opt-in, per identity, and live side by side on the **Media backup**
screen (reached from an identity's detail view).

:::note[This is a different backup from your recovery key]
The [2-of-3 Shamir backup](/user/backup/) protects the **key that proves who you
are** — your way back in if you lose your phone. This page is about backing up
**your content**. They defend different things: one protects *access*, the other
protects *content*. You want both.
:::

## Why hold your own copy

Your server already backs its data up off-box (operators can read how in
[Backups &amp; restore](/operator/backups/)). That protects you if a *file* goes
bad. It does not protect you if the *server itself* goes away — a host that shuts
down, a volume that's lost with no restore point, an operator you no longer
trust.

A media backup you hold is the layer underneath all of that. Because it lives in
your iCloud Drive, it survives the server entirely. And because your posts
reference media by its **content address** — a hash of the bytes themselves —
your copy is either exactly the file the post points at or it isn't; there is no
"close enough."

## Backing up your media

Open an identity and choose **Back up media**. The backup is:

- **Opt-in, per identity** — nothing is copied anywhere until you ask, and each
  identity is backed up on its own.
- **Incremental** — the first run copies everything; later runs only fetch what's
  new, so keeping it current is cheap.
- **Verified as it goes** — every file is checked against its content address
  before it's written to the mirror, so a corrupted download is never stored as
  if it were good.

The current mirror size is always shown, and the copy is a normal folder you can
see in the **Files** app — nothing hidden, nothing you can't inspect.

## Keeping it fresh

Media you post keeps arriving after the first backup, so Obsign tops the mirror
up on its own. On iOS a scheduled background task refreshes each opted-in
identity's mirror without you opening the app — the same incremental,
content-verified pass as **Back up now** — so a photo posted days ago doesn't sit
unprotected until the next time you happen to launch Obsign. Each identity is
handled independently, so one account's failure never stops the others.

You stay in control of when that happens. A **Media backup** section in Settings
lets you:

- turn background backups **off** entirely (leaving only the manual **Back up
  now**),
- restrict them to **while charging**, or
- **skip cellular data**, so top-ups wait for Wi-Fi.

## Restoring to your server

If your server loses the originals, open the identity and choose **Restore to
server**. Obsign uploads your mirrored files back **byte-for-byte**. Because media
is content-addressed, the restored files carry the same addresses they had
before, so every post keeps pointing at the same media — nothing in your posts is
rewritten.

iOS sometimes offloads files from a full device to save space, leaving only a
placeholder. A restore handles that for you: when a backed-up file isn't actually
on the phone, Obsign asks iCloud to download it, waits for it to arrive (within a
time limit), verifies it still matches its content address, and uploads it — so a
restore on a device where most of the mirror has been evicted just works instead
of handing you a list of files to fetch by hand. The summary tells you how many
files it pulled from iCloud first, so a slower restore explains itself. A file
that's genuinely gone — with no iCloud copy left to download — is reported on its
own, and the restore continues past it.

## During a migration

Your media backup also protects a **move**. When you
[migrate your identity](/user/migration/) away from a server that has already
lost some of your media, that media would normally have to be left behind. If
you've backed it up, Obsign instead falls back to your own copy: it verifies the
backed-up file still matches its content address and uploads *that* to your new
server. The substitution is exact, so a blob your old server dropped shrinks — and
ideally empties — the move's loss list instead of forcing you to skip it.

## Backing up your posts

Your **posts** — the records themselves, every post, like, follow, and profile
edit — are the one part of your account that otherwise lives only on your server.
The same **Media backup** screen has a **Back up your posts** section that mirrors
a full snapshot of your repository into your iCloud Drive.

- **A snapshot, not a stream** — each backup captures your whole repository as it
  stands, so the copy you hold is always a complete, self-contained record rather
  than a pile of fragments.
- **Integrity-checked before it's kept** — a snapshot is verified before it
  replaces the last one, and if a freshly fetched copy fails the check the previous
  good snapshot is left untouched. You are never left holding a corrupt backup.
- **Yours to keep and to move** — the snapshot is a standard repository export you
  can hold, inspect, and carry to another server, so the record of what you've
  written stays with you no matter what happens to the server that hosted it.

Together with your media backup, this means your whole presence — what you wrote
and the images you attached — has a copy that you control.
