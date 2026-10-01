# 0011. verify includes build and dist check; no committed dist/

**Status:** Accepted

## Context

Green unit tests say nothing about whether the extension loads. Gmail UI cannot be previewed on a Vite
dev server ([0001](0001-esbuild-not-vite.md)). List-mark density is not assertable by unit tests alone.

## Decision

- `npm run verify` = lint + typecheck + test + build + `check-dist`. CI runs lint, typecheck and test on
  both the engines floor and the current LTS, then build and `check-dist` once, on the current LTS, and
  uploads that package. The build is not repeated on the floor because the artifact Chrome loads is the
  same bytes whichever Node produced it; what the floor can break is the toolchain, which the first three
  steps already exercise. The release workflow runs the full `verify`, on the current LTS.
- `check-dist` derives required files from the manifest, and also pins the advertised permissions and
  checks every bundle for sourcemap references and HTML sinks. Release refuses a tag that does not match
  `package.json`.
- **No committed `dist/`.** The harness mounts real Badge/Panel/engine on fixtures; screenshots and
  list-density checks come from that page.

## Consequences

- Packaging drift (renamed bundle, stale manifest reference) fails in seconds.
- README assets track the shipping UI.
- Reviewers get installable artifacts from CI.

## Rejected alternatives

- **Hardcoded dist file lists** — drift when the manifest grows.
- **Dev-server preview of the badge** — meaningless outside Gmail; the harness replaces it.
- **Committing `dist/`** — stale binaries and review noise.
