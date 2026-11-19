# Releasing RIFT

A release is a version tag `vX.Y.Z` on `main`. Pushing it builds the images `weneten/rift:X.Y.Z` for amd64 and arm64 (`image.yml`) and creates the GitHub release with that version's notes from `CHANGELOG.md` (`release.yml`). `latest` keeps following `main`.

## Steps

1. **Notes.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z]` and start a new, empty `## [Unreleased]` above it. Update the compare links at the bottom (`[Unreleased]: .../compare/vX.Y.Z...HEAD`, `[X.Y.Z]: .../compare/vPREVIOUS...vX.Y.Z`). Check the notes with `sh deploy/release-notes X.Y.Z`.
2. **Version.** Set `version = "X.Y.Z"` in `Cargo.toml` and run `cargo build` so `Cargo.lock` follows. If dependencies changed, regenerate the third-party licenses: `cargo about generate --locked --fail about.hbs -o THIRD_PARTY_LICENSES.md`.
3. **Compatibility.** If the release changes the control or enrollment protocol, raise `VERSION` in `src/protocol.rs`, keep `MIN_PEER_VERSION` at the previous protocol for this release, and leave out in `daemon::downgrade` what older agents cannot read. If it changes what is stored, add a migration and a fixture (see `docs/architecture.md`).
4. **Checks.** Commit, push to `main` and wait until CI is green, including `linux-netns`.
5. **Tag.**

   ```sh
   git tag -a vX.Y.Z -m "RIFT X.Y.Z"
   git push origin vX.Y.Z
   ```

   `image.yml` refuses a tag that does not match `Cargo.toml`, and so does `release.yml`.
6. **Afterwards.** Check that `weneten/rift:X.Y.Z` exists for both platforms and that the release page shows the notes. Users pin it with `RIFT_VERSION=X.Y.Z` in `.env` and the matching checkout (`git checkout vX.Y.Z`); they update the server first, then the agents.
