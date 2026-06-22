# Issue tracker: GitHub

Issues and PRDs for this repository live in GitHub Issues at `GrandpaNiuu/cn-direct-rules`. Use the GitHub app when available and the `gh` CLI as the local fallback.

## Conventions

- Create, read, comment on, label, and close work through GitHub Issues.
- Infer the repository from `git remote -v` when operating in this checkout.
- When a skill says to publish work to the issue tracker, create a GitHub issue.
- When a skill says to fetch a ticket, read the issue and its comments and labels.

## Pull requests as a triage surface

External pull requests are a request surface: **yes**.

Triage external PRs with the same roles as issues when the author's association is `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE`. Do not pull owner, member, or collaborator work-in-progress PRs into the external request queue.

GitHub shares one number space across issues and pull requests. Resolve an ambiguous `#N` as a PR first, then fall back to an issue.
