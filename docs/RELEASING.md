# Releasing

How a change reaches users, and which Docker tag means what.

## Channels

| Docker tag | What it is | When it moves |
|---|---|---|
| `:edge` | Staging / beta channel, built from every push to `main` | Every merge to `main` |
| `:latest` | The release channel most users run | Only when a `vX.Y.Z` git tag is pushed |
| `:X.Y.Z` | Immutable per-release tags | Created alongside `:latest` on a version tag |

A push to `main` ships **nothing** to `:latest` users. Merging is staging;
tagging is releasing.

## Cutting a release

1. Make sure the version is bumped **in all three files** (they must match):
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `app/__init__.py` → `__version__ = "X.Y.Z"`
   - `app/main.py` → `version="X.Y.Z"` (FastAPI constructor)
2. Update `CHANGELOG.md` with the release section.
3. Tag and push:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
   The Docker workflow builds from the tagged commit and stamps
   `:latest` + `:X.Y.Z`.
4. Verify the deploy before announcing: pull `:latest` and confirm the app
   version and that the dashboard returns 200. A green build is not the same
   as a working image.
5. **Create a GitHub Release for the tag** (`gh release create vX.Y.Z`), with
   user-facing notes from the changelog. The dashboard's update badge reads
   the *latest GitHub Release*, so this is what tells existing installs an
   update exists. The badge compares versions numerically, so a patch release
   for an older line (e.g. v1.11.3 while `main` is on 1.13.0) never prompts
   `:edge` testers to "upgrade" backwards.

## Fixing a bad release

Version tags are protected: they cannot be moved or deleted. Never roll
back — fix forward with a new patch tag (`vX.Y.Z+1`).

For a patch to an older line (hotfix while `main` carries unreleased work):
branch from the last commit of that line, apply the minimal fix, bump the
patch version, make sure the branch carries the current tag-driven
`docker-publish.yml`, then tag from that branch. The tag builds from the
tagged commit, not from `main`.

## History

- Until 2026-09-17, `:latest` was rebuilt on every push to `main`. That is
  how a docs-only push rebuilt the 1.11.2 image with unpinned dependencies
  and broke every fresh pull (#123, fixed by v1.11.3). The tag-driven scheme
  above exists so that cannot happen again.
