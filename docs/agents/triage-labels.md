# Triage Labels

The skills speak in terms of five state roles and two category roles. This file
maps those roles to what the `MM` team in Linear actually uses.

## State roles

| Role in mattpocock/skills | In Linear                     | Meaning                                  |
| ------------------------- | ----------------------------- | ---------------------------------------- |
| `needs-triage`            | label `needs-triage`          | Maintainer needs to evaluate this issue  |
| `needs-info`              | label `needs-info`            | Waiting on reporter for more information |
| `ready-for-agent`         | label `ready-for-agent`       | Fully specified, ready for an AFK agent  |
| `ready-for-human`         | label `ready-for-human`       | Requires human implementation            |
| `wontfix`                 | **status** `Canceled`         | Will not be actioned                     |

`wontfix` is a status, not a label: moving an issue to `Canceled` is the
transition, and a canceled issue carries no state label. The four labels are
team-scoped to `MM` and already exist.

## Category roles

| Role in mattpocock/skills | In Linear                              |
| ------------------------- | -------------------------------------- |
| `bug`                     | label `Bug`                            |
| `enhancement`             | label `Feature` (new) or `Improvement` (existing surface) |

Every triaged issue carries one category label and, unless canceled, one state
label. Wave labels (`Wave N: ...`) are orthogonal and stay on.
