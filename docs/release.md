# Releasing RIFT

A release is a version tag `vX.Y.Z` on `main`. Pushing it builds the images `weneten/rift:X.Y.Z` for amd64 and arm64 (`image.yml`) and creates the GitHub release with that version's notes from `CHANGELOG.md` (`release.yml`). `latest` keeps following `main`.

## Steps

1. **Notes.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z]` and start a new, empty `## [Unreleased]` above it. Update the compare links at the bottom (`[Unreleased]: .../compare/vX.Y.Z...HEAD`, `[X.Y.Z]: .../compare/vPREVIOUS...vX.Y.Z`). Check the notes with `sh deploy/release-notes X.Y.Z`.
2. **Version.** Set `version = "X.Y.Z"` in `Cargo.toml` and run `cargo build` so `Cargo.lock` follows. If dependencies changed, regenerate the third-party licenses: `cargo about generate --locked --fail about.hbs -o THIRD_PARTY_LICENSES.md`.
3. **Compatibility.** If the release changes the control or enrollment protocol, raise `VERSION` in `src/protocol.rs`, keep `MIN_PEER_VERSION` at the previous protocol for this release, and leave out in `daemon::downgrade` what older agents cannot read. If it changes what is stored, add a migration and a fixture (see `docs/architecture.md`).
4. **Checks.** Commit, push to `main` and wait until CI is green, including `linux-netns` and `docker-bridge`, which run only with a disposable runner (see below); without one, run them by hand on a throwaway VM.
5. **Tag.**

   ```sh
   git tag -a vX.Y.Z -m "RIFT X.Y.Z"
   git push origin vX.Y.Z
   ```

   `image.yml` refuses a tag that does not match `Cargo.toml`, and so does `release.yml`.
6. **Afterwards.** Check that `weneten/rift:X.Y.Z` exists for both platforms and that the release page shows the notes. Users pin it with `RIFT_VERSION=X.Y.Z` in `.env` and the matching checkout (`git checkout vX.Y.Z`); they update the server first, then the agents.

## CI runners

All workflows run on self-hosted runners. Register them under Settings → Actions → Runners of the repository with these labels (the runner adds `self-hosted`, `linux` and the architecture itself):

| Labels | Runs | Needs on the machine |
| --- | --- | --- |
| `self-hosted, linux, x64` | `rust`, `licenses`, `site-helper` (CI); `build-amd64`, `merge` (image); `release` | `git`, a C compiler (`build-essential`), `curl`, `python3`, Docker Engine with the buildx plugin and the runner user in the `docker` group, the GitHub CLI `gh`. Rust comes from `dtolnay/rust-toolchain` into the runner user's home. |
| `self-hosted, linux, arm64` | `build-arm64` (image) | Docker Engine with buildx, runner user in the `docker` group. Without an arm64 runner, the image workflow waits for one and `merge` never runs. |
| `self-hosted, linux, x64, disposable` | `linux-netns`, `docker-bridge` (CI) | Everything of the x64 runner plus passwordless `sudo` (the jobs install `iproute2`, `wireguard-tools`, `nftables`, `iptables`, `iperf3`, `conntrack`, `openssh-client` with `apt-get`). A **throwaway VM** reset after each run: these tests change sysctls, nftables and Docker's firewall rules of the host. Set the repository variable `RIFT_DISPOSABLE_RUNNER=true` once such a runner exists; until then both jobs are skipped. |

Pull requests from forks do not run on these machines: CI starts only for pull requests whose branch is in this repository. To check a fork's pull request, push its branch here. In addition, keep Settings → Actions → General → "Require approval for all external contributors" on.

Self-hosted runners keep their state between runs: Cargo's caches, Docker images and build cache grow. Clean them now and then (`docker system prune`, `docker buildx prune`), or use ephemeral runners (`./config.sh --ephemeral`) that are recreated after every job. The image jobs use the GitHub Actions cache (`type=gha`) as before; it needs network access to GitHub, nothing on the machine.

