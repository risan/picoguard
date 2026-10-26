# Releasing picoguard

A release starts when you push a version tag. The workflow `.github/workflows/release.yml` then
tests the commit, builds the three binaries, signs `SHA256SUMS` with the release key, publishes
the GitHub release and publishes the crate to crates.io. Nothing else starts it: not a branch
push, a pull request, a schedule or a manual run.

The release public key is `dist/release-key.der`. Its SHA-256 fingerprint, which the README also
shows, is:

```
5724aad59c1a5c73be060aaffe293b0b56e5092b71ebb0073e19b1c4238656cf
```

Check it any time with `sha256sum dist/release-key.der`.

## What each release holds

Seven files: `picoguard-x86_64-unknown-linux-musl`, `picoguard-aarch64-unknown-linux-musl`,
`picoguard-armv7-unknown-linux-musleabihf`, `install.sh`, `proxmox-lxc.sh`, `SHA256SUMS` and
`SHA256SUMS.sig`. `SHA256SUMS` is the `sha256sum` output over the five other files. The signature
is the raw 64-byte Ed25519 signature over the exact bytes of `SHA256SUMS`.

## One-time setup

### 1. The signing key

Make the key pair in a temporary directory in memory, never in the repository, and never keep the
private half anywhere except the secret and the offline backup below:

```sh
umask 077
d=$(mktemp -d /dev/shm/pgkey.XXXXXX)
openssl genpkey -algorithm ed25519 -outform DER -out "$d/key.der"
openssl pkey -inform DER -in "$d/key.der" -pubout -outform DER -out dist/release-key.der
base64 -w0 "$d/key.der" | gh secret set RELEASE_SIGNING_KEY -R risan/picoguard
base64 -w0 "$d/key.der"          # write this one line down for the offline backup
shred -u "$d/key.der"; rmdir "$d"
```

`dist/release-key.der` must be exactly 44 bytes and start with the bytes `302a300506032b6570032100`
(`stat -c %s` and `xxd -p -l 12` show it). Commit it, and put its new fingerprint in the README and
in this file.

The secret `RELEASE_SIGNING_KEY` is the base64 of the private key on one line, so GitHub masks it
reliably in logs.

### 2. The offline backup

Keep the one line printed above somewhere that is offline only: for example on paper in a safe
place, or on an encrypted USB drive that stays disconnected. Never put it in a password manager
that syncs, a cloud drive, a chat, an email or any other online copy. If the repository secret is
lost, this backup is the only way to sign with the same key again.

### 3. The crates.io token

On crates.io, create a token limited to the crate `picoguard` with the scopes `publish-new` and
`publish-update`, and give it an expiry. Then store it as a secret:

```sh
gh secret set CARGO_REGISTRY_TOKEN -R risan/picoguard
```

Paste the token when asked. The first publish of a crate needs `publish-new`. After the first
stable release, replace the token with one that has only `publish-update`. The token reaches only
the last step of the `crate` job, and only for stable tags.

Instead of letting CI make the first publish, you can run `cargo publish --locked` by hand on the
release commit before you push the tag. The workflow then sees the version on crates.io and
skips the publish. Do this only after "Before the first stable release" below: publishing to
crates.io also makes the source public.

### 4. Recommended repository settings

The workflow does not need them, but they protect the releases:

- A tag ruleset for `v*` that blocks deleting and moving tags.
- Immutable releases.

## Cutting a release

1. Set `version` in `Cargo.toml` and refresh the lock file: `cargo update -p picoguard`.
2. Run `scripts/check.sh` and commit.
3. Write the release notes to a file. They become the GitHub release notes word for word.
4. Create an annotated tag whose message is the notes, then push the tag:

   ```sh
   git tag -a v0.3.0 -F notes.md
   git push origin v0.3.0
   ```

   The tag must be annotated (`-a`) and must be exactly `v` plus the version in `Cargo.toml`.
   A prerelease version such as `0.3.0-rc.1` makes a GitHub prerelease.

The workflow has four jobs:

- `preflight` reads the tag through the API and fails unless it is annotated, points to the
  commit being built and matches `Cargo.toml`.
- `build` runs `scripts/check.sh` and `scripts/build-release.sh` with pinned Rust, zig and
  `cargo-zigbuild`, and fails if the build would change `Cargo.lock` or the ARMv7 binary is over
  4 MiB. It uploads the files as an artifact.
- `release` downloads the artifact, signs `SHA256SUMS` (only this job sees the key), checks the
  signature and creates the release as a draft. It publishes the draft only when all seven assets
  are attached, so `releases/latest` never shows a half-made release.
- `crate` checks the package and, for a stable tag, publishes it to crates.io, unless that
  version is already there.

If a run fails before the release is published, nothing is public: fix the cause and use "Re-run
failed jobs". A leftover draft is deleted and made again. Never publish a draft by hand. If a
release is already published, a re-run fails on purpose and changes nothing.

## Rehearsal with a prerelease tag

Before the first real release, and after changing the workflow, prove the pipeline on a
throwaway branch with a prerelease tag:

```sh
git switch -c rehearsal
# set version = "0.3.0-rc.1" in Cargo.toml
cargo update -p picoguard
git commit -am "Rehearsal version"
git tag -a v0.3.0-rc.1 -m 'picoguard v0.3.0-rc.1' -m 'Rehearsal of the signed release workflow.'
git push origin v0.3.0-rc.1
```

The release is marked prerelease and the crate job only checks the package. Download it and
verify it as below. Afterwards delete the prerelease and its tag:

```sh
gh release delete v0.3.0-rc.1 --cleanup-tag --yes
```

## Before the first stable release

A stable tag publishes the crate, and crates.io shows the source, so the repository must be ready
to be public first. In this order:

1. The rehearsal above has passed, and you have checked its release by hand.
2. Audit the whole history. The report names private query names, so keep it outside the
   repository, and keep the names file there too:

   ```sh
   scripts/audit-history.sh --names ~/private/queries.txt \
       --report ~/private/audit-report.md --summary ~/private/audit-summary.md
   ```

   It needs `gitleaks`, `jq` and `git`. It exits 1 on an unexplained query name or a secret.
   Read the report. Fix real findings, and list names that are public in a file for
   `--known-public`. Findings that are only about personal details are for you to accept or act on.
3. Look at the report once more and confirm in that moment that the repository may be public.
   Then make it public: `gh repo edit risan/picoguard --visibility public
   --accept-visibility-change-consequences`.
4. Check that an unauthenticated download works:
   `curl -fsSLO https://github.com/risan/picoguard/releases/latest/download/SHA256SUMS`.
5. Make sure the `CARGO_REGISTRY_TOKEN` secret is set, then cut the stable release.

## Verify a release by hand

```sh
mkdir check && cd check
curl -fsSLO https://github.com/risan/picoguard/releases/download/v0.3.0/SHA256SUMS
curl -fsSLO https://github.com/risan/picoguard/releases/download/v0.3.0/SHA256SUMS.sig
cp ../dist/release-key.der .
sha256sum release-key.der
openssl pkeyutl -verify -pubin -inkey release-key.der -keyform DER \
    -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

To check the binaries too, download them next to `SHA256SUMS` and run `sha256sum -c
--ignore-missing SHA256SUMS`.

The fingerprint must match the one at the top. The openssl command must print
`Signature Verified Successfully`.

## Sign by hand in an emergency

If CI is unavailable, build and sign on a trusted machine with the backup key:

```sh
scripts/build-release.sh
RELEASE_SIGNING_KEY=<the base64 line from the backup> scripts/sign-release.sh dist/release
```

The script refuses a key that does not match `dist/release-key.der`, checks the signature, and
leaves no signature behind when anything fails. Put the key in the shell only for that command,
for example by reading it with `read -rs`, and do not leave it in the shell history.

Then push the annotated tag if it is not pushed yet, and publish with the same script CI uses. It
creates a draft, attaches the seven files, checks them and only then publishes, with the notes of
the tag, and it refuses to touch a release that is already published:

```sh
export GITHUB_REPOSITORY=risan/picoguard
tag_object=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/v0.3.0" --jq .object.sha)
scripts/publish-github-release.sh v0.3.0 "$tag_object" false dist/release
```

Use `true` instead of `false` for a prerelease tag. The crate is not published by this; run
`scripts/publish-crate.sh 0.3.0 false` with `CARGO_REGISTRY_TOKEN` set, or `cargo publish --locked`.

## A lost key

If both the secret and the backup are gone, you cannot sign with that key again.

1. Make a new key pair as in "The signing key", set the new secret and commit the new
   `dist/release-key.der` with its new fingerprint in the README and this file.
2. Cut a new release. Older releases keep their old signatures, which verify only with the old
   public key.
3. Devices that trust the old key need one manual `install.sh` run to learn the new key. Tell
   users to run it themselves.

## A leaked key

If the private key may have been seen by anyone else:

1. Delete the secret `RELEASE_SIGNING_KEY` at once, so no run can sign.
2. Make a new key pair as above, replace the secret and the public key file, and cut a new
   release.
3. Edit the notes of every release signed with the leaked key to say that its signature must not
   be trusted. Devices that trust the old key need one manual `install.sh` run.
4. Find out how the key leaked and fix that.
