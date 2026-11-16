# GBrain remote-trust security audit (2026-11-16)

Scope: logic flaws, secrets, crypto, API exposure, infrastructure — focused on
complete attack chains from **less-trusted remote MCP / OAuth clients** into
confidentiality or integrity impact. Local CLI (`remote: false`, same uid) is
out of scope unless it escalates from remote.

Trust model checked: CLI trusted; HTTP/stdio MCP untrusted (`remote: true`);
OAuth scopes `read|write|admin|sources_admin|users_admin`; `localOnly` ops
must be rejected over HTTP.

## Verdict

No CRITICAL issue in **default** deploy posture (`bind 127.0.0.1`, DCR off,
bearer required). Several **HIGH** issues allow an already-authenticated
read-scoped remote client to bypass source isolation or privacy fences.
One **HIGH** chain becomes full unauthenticated takeover if an operator
enables `--enable-dcr`.

---

## HIGH-1 — Cross-source isolation bypass via caller-controlled `source_id`

**Severity:** HIGH  
**Impact:** Confidentiality — OAuth client scoped to source A reads pages /
code from source B (or all sources).

**Attack path**

1. Operator registers an OAuth client with `--source dept-x` (and
   `federated_read` limited to `dept-x`).
2. Attacker (or over-privileged agent) holds a `read` token for that client.
3. Call MCP `query` with `source_id: "__all__"` (or `source_id: "dept-y"` /
   another neighbor source).
4. Handler prefers the request param over `sourceScopeOpts(ctx)` and drops
   the auth-bound filter.

**Evidence**

```1186:1194:src/core/operations.ts
    const sourceIdParam = typeof p.source_id === 'string' ? p.source_id : undefined;
    const querySourceScope =
      sourceIdParam !== undefined
        ? sourceIdParam === '__all__'
          ? {}
          : { sourceId: sourceIdParam }
        : sourceScopeOpts(ctx);
```

Same pattern on `code_callers` / `code_callees`:

```3134:3146:src/core/operations.ts
    const allSourcesParam = p.all_sources === true;
    const sourceIdParam = typeof p.source_id === 'string' ? p.source_id : undefined;
    const allSources = allSourcesParam || sourceIdParam === '__all__';
    const sourceId = allSources
      ? undefined
      : sourceIdParam !== undefined
        ? sourceIdParam
        : ctx.sourceId;
    const edges = await ctx.engine.getCallersOf(symbol, {
      limit,
      allSources,
      sourceId,
    });
```

`sourceScopeOpts` correctly prefers `ctx.auth.allowedSources` — but these
handlers never call it when the client supplies a param.

**Contrast (correct):** `search` always spreads `sourceScopeOpts(ctx)` and
has no override param (`operations.ts:1057-1061`).

**Fix direction:** For `ctx.remote === true`, ignore `__all__` / foreign
`source_id` / `all_sources` unless the requested id is ⊆ `allowedSources`
(or equals scalar `sourceId`). Prefer intersecting with `sourceScopeOpts`.

---

## HIGH-2 — `get_versions` leaks private facts fence to remote callers

**Severity:** HIGH  
**Impact:** Confidentiality — private facts recoverable via history after
`get_page` was hardened.

**Attack path**

1. Remote MCP / OAuth `read` client cannot see private facts via `get_page`
   (strips takes + keeps only `world` facts when `ctx.remote === true`).
2. Same client calls `get_versions` / `history` on the same slug.
3. Response maps only `stripTakesFence` — **private facts rows remain**.

**Evidence**

```1791:1800:src/core/operations.ts
    const versions = await ctx.engine.getVersions(p.slug as string, sourceOpts);
    // Same takes-allow-list privacy boundary as get_page. Snapshots persist
    // historical compiled_truth verbatim, including the takes fence, so
    // a remote token bypassing get_page via /history would re-introduce
    // the same leak across every prior version.
    if (!ctx.takesHoldersAllowList) return versions;
    return versions.map(v => ({ ...v, compiled_truth: stripTakesFence(v.compiled_truth) }));
```

`get_page` (fixed posture the history path should match):

```516:525:src/core/operations.ts
    const isUntrustedReader = ctx.remote === true;
    const visibleBody = isUntrustedReader
      ? {
          ...page,
          compiled_truth: stripFactsFence(
            stripTakesFence(page.compiled_truth),
            { keepVisibility: ['world'] },
          ),
        }
      : page;
```

**Fix direction:** Gate on `ctx.remote === true` (not allow-list presence)
and apply the same `stripFactsFence({ keepVisibility: ['world'] })` +
`stripTakesFence` pair.

---

## HIGH-3 — `recall --supersessions` skips visibility filter

**Severity:** HIGH  
**Impact:** Confidentiality — remote callers read private superseded facts.

**Attack path**

1. Remote MCP client calls `recall` with `supersessions: true`.
2. Handler invokes `listSupersessions` with **no** `visibility` argument.
3. Engine SQL returns all superseded rows regardless of `visibility`.

**Evidence**

```2959:2971:src/core/operations.ts
    const visibility =
      ctx.remote === false
        ? undefined
        : ['world'] as ('private' | 'world')[];
    ...
    if (p.supersessions === true) {
      const since = parseSinceParam(p.since);
      rows = await ctx.engine.listSupersessions(sourceId, { since: since ?? undefined, limit });
```

```2825:2833:src/core/postgres-engine.ts
      SELECT * FROM facts
      WHERE source_id = ${source_id}
        AND expired_at IS NOT NULL
        AND superseded_by IS NOT NULL
        ${since ? sql`AND expired_at >= ${since}` : sql``}
      ORDER BY expired_at DESC, id DESC
      LIMIT ${limit}
```

Other recall branches correctly pass `visibility`. `find_trajectory`
correctly threads `remote: ctx.remote === true` into SQL.

**Fix direction:** Add `visibility` to `listSupersessions` (both engines)
and pass the remote world-only filter from the op handler.

---

## HIGH-4 — `--enable-dcr` allows unauthenticated admin client registration

**Severity:** HIGH (CRITICAL if DCR is enabled on an internet-reachable
listener; default deploy has DCR **off**)  
**Impact:** Full brain compromise (read/write/admin ops, job admin surface).

**Attack path**

1. Operator runs `gbrain serve --http --enable-dcr --bind 0.0.0.0` (or
   tunnels a DCR-enabled server).
2. Attacker `POST /register` with `scope: "admin"`,
   `grant_types: ["client_credentials"]` — `assertAllowedScopes` permits
   `admin` (`scope.ts:27-33`, `oauth-provider.ts:173-177`).
3. Attacker exchanges `client_credentials` for an admin access token
   (`serve-http.ts:350-367`, `oauth-provider.ts:629-684`).
4. Attacker calls any non-`localOnly` admin op (`submit_job` for non-
   protected names, `run_doctor`, etc.). Protected cycle/shell names remain
   blocked by `remote !== false` (`operations.ts:2115-2117`).

Additionally, `/authorize` auto-issues codes with **no resource-owner
login or consent** (`oauth-provider.ts:311-347`), so authorization_code
public clients registered via DCR are equally automatic.

**Default posture (not vulnerable alone):** DCR off unless `--enable-dcr`
(`serve.ts:88`, `serve-http.ts:266`); bind defaults to `127.0.0.1`
(`serve-http.ts:237`).

**Fix direction:** Cap DCR-registrable scopes to `read` (or require an
operator secret); never allow `admin`/`write` via unauthenticated DCR.
Require authenticated consent on `/authorize`.

---

## MEDIUM-1 — OAuth HTTP CORS is reflect-any-origin

**Severity:** MEDIUM  
**Impact:** Browser origin with a stolen/leaked bearer token can call MCP
APIs and read responses. Contradicts `SECURITY.md` “default-deny” docs
(which describe the legacy `http-transport.ts` path).

**Evidence**

```319:323:src/commands/serve-http.ts
  app.use('/mcp', cors());
  app.use('/token', cors());
  app.use('/authorize', cors());
  app.use('/register', cors());
  app.use('/revoke', cors());
```

Legacy transport correctly default-denies via `GBRAIN_HTTP_CORS_ORIGIN`
(`src/mcp/http-transport.ts:50-54`, `140-147`).

**Fix direction:** Mirror allowlist CORS from `http-transport.ts` on the
OAuth server; default deny.

---

## MEDIUM-2 — OAuth `/mcp` missing IP/token rate limits

**Severity:** MEDIUM  
**Impact:** Unauthenticated bearer-bruteforce load and runaway authenticated
clients (DB / embedding cost). Legacy transport has dual buckets; OAuth
path only rate-limits `/token` client_credentials and admin magic-link.

**Evidence:** `serve-http.ts` `/mcp` handler (`1054+`) has no
`buildDefaultLimiters()` / express rate limit. Contrast
`src/mcp/http-transport.ts:248-291` and `src/mcp/rate-limit.ts`.

---

## MEDIUM-3 — `sources_list` exposes all source `remote_url`s to any `read` token

**Severity:** MEDIUM  
**Impact:** Source topology + private git HTTPS URLs leak to narrowly
scoped OAuth clients.

**Evidence:** `sources_list` is `scope: 'read'` and returns
`listSources(engine)` unfiltered (`operations.ts:2805-2821`).

**Fix direction:** Filter to `sourceScopeOpts` / `allowedSources` for
remote callers; redact credentials in URLs (if any).

---

## Checked and not filed (no complete remote chain)

| Area | Result |
|------|--------|
| Protected jobs (`shell`/`synthesize`/`patterns`/`consolidate`/`subagent*`) over HTTP | Rejected when `ctx.remote !== false` (`operations.ts:2115`) + queue `allowProtectedSubmit` (`protected-names.ts`, `queue.ts:81`) |
| `file_url` / `file_upload` / `file_list` / `sync_brain` secret/path ops | `localOnly: true`; filtered from HTTP tool list (`serve-http.ts:1054`) |
| MCP `config get` / secret return | No config-get op; `whoami` returns identity only; remote doctor thin-set does not emit key material |
| Hardcoded production credentials (`sk-`, live tokens) | None in src/CI (test fixtures use `gbrain_at_xxx` placeholders; workflows use `${{ secrets.* }}`) |
| Insecure default HTTP exposure | Bind `127.0.0.1`, DCR off, bearer required |
| `put_page` outside `allowedSlugPrefixes` for OAuth write | By design — allow-list is subagent/dream-cycle only (`viaSubagent`); OAuth `write` may write within its `sourceId` |
| Job claim races | `FOR UPDATE SKIP LOCKED` (`queue.ts:542+`) |
| `find_trajectory` / normal `recall` / `get_page` visibility | Remote filters present |
| Gateway fetch shims | Provider base URLs from config/recipe defaults; image URL path SSRF-guarded (`ssrf-validate.ts`) |
| `~/.gbrain/config.json` perms + gitignore | `0o600` + `ensureGitignore()` (`config.ts:323-378`) — local FS, not remote MCP |

---

## Suggested priority

1. HIGH-1 source_id override (multi-source / team brains)
2. HIGH-2 get_versions facts strip
3. HIGH-3 recall supersessions visibility
4. HIGH-4 DCR scope ceiling + authorize consent (before any `--enable-dcr` prod use)
5. MEDIUM CORS + MCP rate limits + sources_list scoping
