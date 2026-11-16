# Security audit — injection / SSRF / path traversal (2026-11-16)

Scope: command injection, SQL injection, path traversal, SSRF (including
git-remote), header/template injection, unsafe deserialization. Attacker
input traced from MCP/HTTP ops and skillpack/source URLs to sinks.

Repo version at audit tip: `9a4ae096` / `v0.37.2.0` lineage on
`cursor/vulnerability-findings-persistence-dd80`.

---

## HIGH-1 — `parseRemoteUrl` / `cloneRepo` SSRF via DNS-to-private hostnames

### Severity
**HIGH**

### Attack chain

1. Attacker obtains or uses an OAuth client with `sources_admin` **or**
   `admin` (admin implies sources_admin per `src/core/scope.ts`).
2. Over HTTP MCP (`serve-http.ts` exposes all non-`localOnly` ops;
   `sources_add` is not `localOnly`), call `sources_add` with:
   ```json
   { "id": "x", "url": "https://10.0.0.5.nip.io/repo.git" }
   ```
   Equivalent bypass hosts: `*.sslip.io`, any attacker DNS whose A/AAAA
   record is RFC1918 / loopback / link-local / CGNAT / IMDS.
3. `sources_add` → `addSource` → `parseRemoteUrl(url)` → `cloneRepo(url)`.
4. `parseRemoteUrl` only calls static `isInternalUrl()` (`url-safety.ts`),
   which never resolves DNS. Hostnames like `10.0.0.5.nip.io` are treated
   as **public** (verified during this audit).
5. `cloneRepo` runs `execFileSync('git', [...GIT_SSRF_FLAGS, 'clone', url, dest], { env: { ...process.env, ...GIT_ENV } })`.
   Git connects to the private IP. The same gap exists for
   `gbrain skillpack scaffold https://…nip.io/…` (CLI) and for
   `recloneIfMissing` / sync pull of an already-registered poisoned URL.

### Evidence

| Location | Role |
|---|---|
| `src/core/git-remote.ts:85-124` | `parseRemoteUrl` — https-only + `isInternalUrl`, **no DNS** |
| `src/core/url-safety.ts:74-133` | Static hostname/IP classifier only |
| `src/core/ssrf-validate.ts:1-23` | Explicitly documents that `isInternalUrl` leaves DNS rebinding open; image path uses this module, git path does not |
| `src/core/operations.ts:2730-2800` | `sources_add` MCP op, `scope: 'sources_admin'`, accepts `url`, not `localOnly` |
| `src/core/sources-ops.ts:257-299` | Validates via `parseRemoteUrl` then `cloneRepo` |
| `src/core/git-remote.ts:188-191` | Full `process.env` inherited into git (including `GIT_SSL_NO_VERIFY` if set) |
| `src/commands/serve-http.ts:1054` | `operations.filter(op => !op.localOnly)` — sources_add exposed |

Empirical check (this audit): `isInternalUrl('https://10.0.0.5.nip.io/repo.git') === false`;
same for `127.0.0.1.nip.io` and `169.254.169.254.nip.io`. Literal
`https://192.168.1.1/…` is correctly blocked.

### Why controls fail

- `GIT_SSRF_FLAGS` (`http.followRedirects=false`, `protocol.file.allow=never`,
  `protocol.ext.allow=never`, `--no-recurse-submodules`) stop **redirect**
  and **non-https schemes**, not “hostname that resolves to private IP”.
- Image loading (`search_by_image` → `fetchWithSSRFGuard`) correctly
  resolves DNS and rejects private A/AAAA records. Git remotes never
  call that helper.
- TLS verification mitigates some classic IMDS theft over HTTPS, but:
  - TCP/TLS ClientHello to internal:443 still occurs (recon / port scan).
  - Inherited `GIT_SSL_NO_VERIFY=true` (spread via `...process.env`) disables
    that mitigation and turns the sink into full request SSRF.
  - Internal HTTPS services with usable certs remain in scope.

### Impact

Server-side reachability of private/link-local/IMDS-adjacent addresses
from the gbrain host via MCP `sources_add` / skillpack clone; plant
attacker-controlled tree under `$GBRAIN_HOME/clones/<id>/`.

### Fix direction

Reuse `validateAndResolveUrl` (or equivalent DNS+private check) inside
`parseRemoteUrl` before clone/ls-remote; refuse when any A/AAAA is
internal; pin or reject rather than trusting hostname alone. Scrub
`GIT_SSL_NO_VERIFY` / `GIT_CONFIG_*` overrides in `GIT_ENV`. Re-validate
URL on `recloneIfMissing` / pull paths.

---

## MEDIUM-1 — `url_reachable` DNS check then fetch-by-hostname (TOCTOU rebinding)

### Severity
**MEDIUM**

### Attack chain

1. Attacker places a citation URL in brain content whose DNS is attacker-
   controlled (short TTL): first answer = public IP, later answer = private.
2. `gbrain integrity` (or any caller of `urlReachableResolver`) invokes
   `url_reachable`.
3. `checkDnsRebinding` (`url-reachable.ts:263-303`) sees only public
   records → allows.
4. `fetch(currentUrl)` (`url-reachable.ts:128`) looks up the hostname
   again (no IP pin, unlike `fetchWithSSRFGuard` which rebuilds the URL
   with the resolved IP and sets `Host`).
5. Second lookup returns private IP → request hits internal network.

### Evidence

| Location | Role |
|---|---|
| `src/core/resolvers/builtin/url-reachable.ts:100-128` | DNS check then `fetch(currentUrl)` by name |
| `src/core/ssrf-validate.ts:196-248` | Correct pattern: fetch by resolved IP + Host header |
| `src/commands/integrity.ts` | Consumes `url_reachable` on page URLs |

### Why controls fail

Per-hop `isInternalUrl` + one-shot DNS check close static and
“always-private” cases (including nip.io **at check time**) but do not
defeat TTL-flip rebinding. The hardened helper already exists and is
unused here.

### Impact

Integrity/cron-driven SSRF to internal HTTP(S) services when citation
URLs are attacker-influenced. Lower than HIGH-1 because it is not an
MCP tool by default and needs a cooperating DNS flip.

### Fix direction

Route through `fetchWithSSRFGuard` (or fetch by pinned IP with Host).

---

## Discarded near-misses (below MEDIUM or controls hold)

| Area | Why discarded |
|---|---|
| `submit_job` / shell RCE over MCP | `ctx.remote !== false` + `PROTECTED_JOB_NAMES`; fail-closed after prior HTTP context bug. Intentional RCE only for local trusted + `GBRAIN_ALLOW_SHELL_JOBS=1`. |
| SQL via sort / slug / source_id / language | `PAGE_SORT_SQL` whitelist; params bound; `validateSourceId` / `COLUMN_NAME_REGEX` + `quoteIdentifier` on embedding columns; `sql-ranking` escapes LIKE + SQL literals. |
| `exclude_slug_prefixes` into CASE/LIKE | Escaped in `buildLikePrefixLiteral`; factors require `Number.isFinite`. |
| `file_upload` path traversal | `localOnly` + `validateUploadPath` realpath confinement when `remote !== false`. |
| `validatePageSlug` / export restore `join(outDir, slug)` | Slug charset rejects `.` / `..`. |
| Tarball extract traversal | Type allowlist, path normalize, caps; GNU tar list preflight. |
| Harvest / copy path escape | `confineRealpath` + symlink reject on skill tree; CLI-only. |
| Archive crawler | Refuses without explicit `scan_paths`; rejects `..` and relatives. |
| `search_by_image` URL SSRF | Uses `fetchWithSSRFGuard` (DNS + redirect revalidation). `image_path` blocked when `remote === true`; dispatch defaults `remote ?? true`. |
| `drift-watch` `execSync(\`git ${args}\`)` | Shell interpolation latent bug, but doctor calls without user `commitSha`; not MCP-reachable today. |
| `cli.ts` smoke-test `execSync(bash scriptPath)` | Path from `import.meta.url`, not attacker input. |
| `toPgVectorLiteral` + `sql.unsafe` (postgres facts path) | Numeric join only; pglite parameterizes. No string breakout from Float32Array. |
| `yaml-lite` / redirect YAML | Flat key:value only; no JS deserialize. `resolveFile` barely wired; LocalStorage confines paths. |
| `protocol.allow=user` missing vs docs | `protocol.file.allow` / `protocol.ext.allow` work on git 2.43; https-only gate remains. Doc drift, not a bypass by itself. |
| Registry `fetch(registry_url)` | Operator config / defaults to GitHub raw; not MCP attacker URL. |

---

## Summary

| ID | Severity | Title |
|---|---|---|
| HIGH-1 | HIGH | Git remote / `sources_add` SSRF via DNS-to-private hostnames (nip.io class) |
| MEDIUM-1 | MEDIUM | `url_reachable` TOCTOU DNS rebinding (fetch-by-name after check) |
