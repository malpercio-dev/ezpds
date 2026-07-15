# Changelog fragments

Every pull request that changes a shipped surface must add a short Markdown fragment:

```text
changelog.d/<id>.<type>.md
```

- `<id>` is the Linear issue identifier in lowercase (for example, `mm-358`). If a
  change has no Linear issue, use the pull request number (for example, `271`).
- `<type>` is one of `added`, `changed`, `fixed`, `removed`, or `security`.
- The file contains one concise, user- or operator-facing Markdown statement. Do not
  include a heading or bullet marker; the release script supplies both.
- Use more than one fragment when a change belongs in more than one category.

Example (`changelog.d/mm-358.added.md`):

```markdown
Release notes now collect user-visible changes from pull requests automatically.
```

The CI gate requires a fragment when a pull request changes a deployable surface:

- server or shared runtime source under `crates/*/src/`, plus PDS runtime assets;
- either mobile app's frontend, native runtime source, static assets, or Tauri config;
- the public marketing site;
- workspace runtime dependency manifests, the production image/config, or the NixOS
  runtime module.

Documentation, tests, design files, CI configuration, scripts, developer tooling, and
other repository-internal changes do not trigger the presence requirement. Any fragment
that is present is still checked for a valid name and non-empty content.

`just set-version X.Y.Z` groups all fragments into a dated Keep a Changelog release
section in `CHANGELOG.md`, then deletes the consumed fragments. This README remains.
