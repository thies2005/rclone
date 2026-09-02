# AGENTS.md

Guide for AI agents (and humans) working on this repository. Read this first.

## What this repo is

This is **`thies2005/rclone`**, a downstream fork of upstream
[`rclone/rclone`](https://github.com/rclone/rclone). It exists to ship a
set of **custom enhancements to the `internxt` backend** that are not (yet)
in upstream, while otherwise staying in lock-step with upstream releases.

Everything outside `backend/internxt/` is intended to be byte-for-byte
identical to an upstream release tag (the only other fork-owned files are
this `AGENTS.md` and the `--internxt-totp-secret` section of
`docs/content/internxt.md`; upstream ships its own AGENTS.md which ours
replaces). **Do not modify non-internxt code** unless you are pulling it
in from upstream.

## Remotes

| remote   | URL                                          | purpose              |
| -------- | -------------------------------------------- | -------------------- |
| `origin` | `https://github.com/thies2005/rclone.git`    | this fork (push here)|
| `upstream` | `https://github.com/rclone/rclone.git`     | official rclone      |

`upstream` is **not** configured by default. Set it up before upgrading:

```
git remote add upstream https://github.com/rclone/rclone.git
git fetch upstream --tags
```

## The internxt fork customizations (preserve on every upgrade)

All fork-specific code lives in **`backend/internxt/`**, plus one docs
page (`docs/content/internxt.md`, the `--internxt-totp-secret` section)
and this file. As of the v1.75.0 merge the fork differs from upstream by
**+598 / -57 lines** across these files:

| file                          | fork-only? | what it does |
| ----------------------------- | ---------- | ------------ |
| `dns_resolver.go`             | **new**    | Overrides Go's default resolver with real DNS servers read from the `RCLONE_DNS_SERVERS` env var (comma-separated). Fixes DNS resolution failing on Android when CGO is disabled (`/etc/resolv.conf` points at `[::1]:53`). Tries UDP then TCP per server. |
| `totp.go`                     | **new**    | `generateTOTPCode`, plus `revealTOTPSecret` / `isBase32Secret` which auto-detect whether the stored `totp_secret` is a legacy plaintext base32 seed or an obscured rclone value (see big comment in the file — do not "simplify" this logic, it guards against silent corruption of plaintext seeds by `obscure.Reveal`). |
| `totp_test.go`                | **new**    | tests for the above |
| `internxt_internal_test.go`   | **new**    | internal tests |
| `internxt.go`                 | modified   | Adds the `totp_secret` config option, `renewerOAuthConfig`, `doBootstrapLogin` (auto-login when `mnemonic` missing), `initTokenRenewer` (proactive token renewal via `oauthutil.NewRenew`), and removes the old `authFailed` one-shot flag so `shouldRetry` always re-authorizes on 401. |
| `auth.go`                     | modified   | `getUserInfo` now also returns the refreshed JWT so it can be persisted; `reLogin` generates a TOTP code automatically when `totp_secret` is set instead of erroring out on 2FA accounts. |

### Fork config options / env vars to keep working

- `totp_secret` (config option, `IsPassword: true`, `Sensitive: true`,
  `Advanced: true`) — base32 TOTP seed for automatic 2FA. May be stored
  plaintext (legacy) or obscured; both are accepted.
- `RCLONE_DNS_SERVERS` (env var) — comma-separated DNS servers, e.g.
  `1.1.1.1,8.8.8.8`. Optional port, defaults to `:53`.

### Things that are intentional — do not "fix"

- `dns_resolver.go` is **not** named `dns_android.go`. The previous
  `_android.go` suffix added a Go build constraint that excluded the file
  when cross-compiling with `GOOS=linux` (which is what the consuming app,
  CloudBridge, does). Keep the non-suffixed name.
- `revealTOTPSecret`'s base32 pre-check is load-bearing. A plaintext base32
  seed is also valid base64url, so a naive `obscure.Reveal()` would silently
  "decrypt" it into garbage. See commit `1db5dd5d2`.
- The `authFailed` one-shot flag was deliberately removed; 401s should
  always attempt re-authorization. See commit `fd054ea2c`.

## Upgrading to a new upstream release

This is the canonical workflow. Note: **upstream started actively modifying
`backend/internxt/` as of v1.75.0** (Move/DirMove, upload size-limit
handling), so expect internxt itself to change between releases.

1. **Fetch upstream and find the newest tag:**
   ```
   git fetch upstream --tags
   git tag --sort=-v:refname | head   # newest first, e.g. v1.75.0
   ```
2. **Sanity-check whether upstream touched internxt** (warns about conflicts):
   ```
   git log --oneline <OLD_TAG>..<NEW_TAG> -- backend/internxt/
   git diff --stat <OLD_TAG> <NEW_TAG> -- backend/internxt/
   ```
   Empty output = the merge will not touch internxt and the fork diff is
   preserved automatically.
3. **Merge the release tag** (follow the existing commit style — a merge
   commit titled `Merge tag 'vX.Y.Z'`):
   ```
   git merge --no-ff <NEW_TAG> -m "Merge tag 'vX.Y.Z'

   Merge upstream vX.Y.Z (<one-line summary of highlights>).

   Internxt fork functionality (TOTP re-auth, proactive token renewer,
   Android DNS resolver override) preserved unchanged."
   ```
4. **Verify the internxt diff is unchanged** (should match the table above):
   ```
   git diff --stat <NEW_TAG> HEAD -- backend/internxt/
   ```
5. **Build + test:**
   ```
   go build ./...
   go vet ./backend/internxt/...
   go test ./backend/internxt/...
   ```
6. Confirm `VERSION` now reflects the new release, then push.

### Stable-branch point releases are not ancestors of the next minor tag

The v1.74.x point-release tags live on upstream's `v1.74-stable` branch
and are **not ancestors** of `v1.75.0` (check with
`git merge-base --is-ancestor <OLD> <NEW>`). Merging v1.75.0 after having
merged v1.74.3 therefore has a merge base of v1.74.0 and re-applies the
stable-line changes, producing ~20 conflicts in files the fork never
touched (`VERSION`, `MANUAL.*`, `go.mod`, `go.sum`, changelog, CI yml,
`cmd/gui/dist.zip`, ...).

Resolution recipe (used for the v1.75.0 merge):

- Take the upstream side for every conflicted file except `AGENTS.md`,
  `docs/content/internxt.md`, and `backend/internxt/`:
  `git checkout --theirs -- <files> && git add <files>`
- `AGENTS.md`: keep ours (`git checkout --ours -- AGENTS.md`). Upstream
  ships its own AGENTS.md since v1.75.0; ours describes this fork and
  replaces it.
- `docs/content/internxt.md`: keep the fork's `--internxt-totp-secret`
  block. Upstream also dropped the `--internxt-mnemonic` docs entry
  because the option is `Hide: fs.OptionHideBoth` — follow upstream there.
- Then verify the invariant before committing:
  ```
  git diff <NEW_TAG> -- . ':(exclude)backend/internxt' \
    ':(exclude)AGENTS.md' ':(exclude)docs/content/internxt.md'
  ```
  must be empty.

### If upstream *does* modify internxt

Resolve conflicts in favor of keeping the fork's behavior, then re-apply
each fork feature on top of the upstream changes file by file. The fork's
features are isolated enough that this is usually a per-file reconcile.

## Build / test commands

```
go build ./...                          # build everything
go vet ./backend/internxt/...           # vet the fork code
go test ./backend/internxt/...          # internxt unit tests
make rclone                             # build the rclone binary
make check                              # alias for `make rclone`
```

`golangci-lint` is **not** installed in this environment; rely on
`go vet` + `go build` + `go test`.

## Conventions

- **Commit messages** follow the existing pattern for fork-only work:
  `type(internxt): <summary>` where `type` is `feat` / `fix` / `docs` /
  `refactor`. See `git log --oneline master --not v1.74.0` for examples.
- Upstream merges are **merge commits** (`--no-ff`) titled
  `Merge tag 'vX.Y.Z'`, matching upstream's own style.
- Do not add code comments unless asked (repo convention).
- Do not commit unless explicitly asked. Do not push unless explicitly
  asked.
